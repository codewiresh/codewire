//! Synthetic reconnect and write-only key import at the real isolated RPC mount.

use super::*;
use codewire_access::CredentialAuthKind;
use codewire_platform_credentials::CredentialRegistration;
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::AddApiKeyCredentialRequest;

fn replacement(record: &codewire_platform_credentials::CredentialRecord) -> Value {
    json!({"name":record.metadata.display_name,"credentialId":record.metadata.id.as_str(),
        "expectedRevocationGeneration":record.version.revocation_generation.to_string()})
}

async fn existing(
    h: &Harness,
    name: &str,
    kind: CredentialAuthKind,
) -> Result<codewire_platform_credentials::CredentialRecord> {
    Ok(h.store
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            CredentialRegistration {
                provider: codewire_access::ProviderId::parse("openai")?,
                authentication_kind: kind,
                display_name: name.into(),
                account_hint: Some("previous-account".into()),
                expires_at_unix: Some(4_000_000_000),
            },
            &ProtectedValue::from_slice(b"synthetic-previous-credential")?,
        )
        .await?)
}

#[test]
fn replacement_selector_and_api_key_grammar_are_bounded_without_kind_guessing() {
    assert!(replacement_selector(None, None).unwrap().is_none());
    for pair in [
        (Some("id".into()), None),
        (None, Some(1)),
        (Some("id".into()), Some(0)),
        (Some("id".into()), Some(u64::MAX)),
    ] {
        assert!(replacement_selector(pair.0, pair.1).is_err());
    }
    assert!(
        replacement_selector(Some("id".into()), Some(1))
            .unwrap()
            .is_some()
    );
    for provider in ["openai", "anthropic"] {
        assert!(validate_api_key(provider, "key", API_KEY_MATERIAL.as_bytes(), None).is_ok());
        for value in [
            Vec::new(),
            vec![b'x'; 1025],
            b"invalid\nkey".to_vec(),
            b"invalid key".to_vec(),
            vec![0xff],
        ] {
            assert!(validate_api_key(provider, "key", &value, None).is_err());
        }
        assert!(validate_api_key(provider, "key", b"valid-key", Some(u64::MAX)).is_err());
    }
    assert!(validate_api_key("github", "key", b"valid-key", None).is_err());
    assert!(validate_api_key("openai", "key", b"a=b", None).is_err());
    assert!(validate_api_key("openai", "key", b"abc==", None).is_ok());
    let request = AddApiKeyCredentialRequest {
        provider: "openai".into(),
        name: "key".into(),
        value: API_KEY_MATERIAL.as_bytes().to_vec(),
        ..Default::default()
    };
    let debug = format!("{request:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(API_KEY_MATERIAL));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_reconnect_validates_before_challenge_and_preserves_named_identity() -> Result<()>
{
    let h = Harness::new().await?;
    let result = async {
        let original = existing(&h, "Canonical Work", CredentialAuthKind::OAuth).await?;
        let wrong_kind = existing(&h, "API key", CredentialAuthKind::ApiKey).await?;
        let mut wrong_name = replacement(&original);
        wrong_name["name"] = json!("renamed-work");
        let mut stale = replacement(&original);
        stale["expectedRevocationGeneration"] = json!("2");
        for (auth, request, code) in [
            (Auth::Bob, replacement(&original), "not_found"),
            (Auth::Alice, wrong_name, "invalid_argument"),
            (Auth::Alice, replacement(&wrong_kind), "invalid_argument"),
            (Auth::Alice, stale, "failed_precondition"),
            (
                Auth::Alice,
                json!({"name":"Canonical Work","credentialId":original.metadata.id.as_str()}),
                "invalid_argument",
            ),
        ] {
            h.rpc
                .enroll_request(auth, request)
                .await?
                .error(code)
                .await?;
            h.drained().await?;
            ensure!(
                !h.control("native.pid").exists(),
                "rejected replacement started provider login"
            );
        }
        let mut response = h
            .rpc
            .enroll_request(Auth::Alice, replacement(&original))
            .await?;
        response.challenge().await?;
        h.release()?;
        let metadata = response.committed().await?;
        h.drained().await?;
        ensure!(
            metadata["id"] == original.metadata.id.as_str() && metadata["name"] == "Canonical Work"
        );
        ensure!(metadata["expiresAtUnix"] == "4000000000");
        ensure!(
            metadata["accountHint"] == "person@example.test"
                && metadata["revocationGeneration"] == "2"
        );
        ensure!(h.count().await? == 2 && !h.logged_out());
        let stored = h
            .store
            .record(&original.metadata.owner, &original.metadata.id)
            .await?;
        ensure!(stored.version.material_generation == 2);
        let material = h
            .store
            .read_for_broker(&stored.metadata.owner, &stored.metadata.id, stored.version)
            .await?;
        ensure!(
            material
                .expose_secret()
                .windows(ACCESS.len())
                .any(|bytes| bytes == ACCESS.as_bytes())
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_reconnect_cannot_overwrite_a_revoke_during_device_login() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let original = existing(&h, "work", CredentialAuthKind::OAuth).await?;
        let mut response = h
            .rpc
            .enroll_request(Auth::Alice, replacement(&original))
            .await?;
        response.challenge().await?;
        let revoked = h
            .store
            .revoke(
                &original.metadata.owner,
                &original.metadata.id,
                original.version,
            )
            .await?;
        h.release()?;
        response.error("failed_precondition").await?;
        h.drained().await?;
        ensure!(h.logged_out());
        ensure!(
            h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?
                == revoked
        );
        ensure!(revoked.metadata.account_hint == original.metadata.account_hint);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_reconnect_cancellation_preserves_the_exact_publication_boundary() -> Result<()> {
    for after_issue in [false, true] {
        let h = Harness::new().await?;
        let result = async {
            let original = existing(&h, "work", CredentialAuthKind::OAuth).await?;
            let mut blocker = h.db.pool.begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker)
                .await?;
            if after_issue {
                install_commit_barrier(&h.db.pool, 4191904).await?;
                sqlx::query("SELECT pg_advisory_xact_lock(4191904)")
                    .execute(&mut *blocker)
                    .await?;
            } else {
                sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                    .bind(ALICE)
                    .execute(&mut *blocker)
                    .await?;
            }
            let mut response = h
                .rpc
                .enroll_request(Auth::Alice, replacement(&original))
                .await?;
            response.challenge().await?;
            h.release()?;
            let pid = blocked_by(&h.db.pool, blocker_pid).await?;
            let query: String =
                sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid)
                    .fetch_one(&h.db.pool)
                    .await?;
            ensure!((query == "COMMIT") == after_issue);
            drop(response);
            let owner = h.owner.clone();
            let mut shutdown = tokio::spawn(async move { owner.shutdown().await });
            tokio::time::timeout(TIMEOUT, h.owner.stop.cancelled()).await?;
            ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS - 1);
            blocker.rollback().await?;
            tokio::time::timeout(TIMEOUT, &mut shutdown)
                .await??
                .map_err(|error| anyhow::anyhow!("closed mutation shutdown: {error:?}"))?;
            let stored = h
                .store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
            if after_issue {
                ensure!(
                    stored.version.revocation_generation == 2
                        && stored.version.material_generation == 2
                );
                ensure!(stored.metadata.account_hint.as_deref() == Some("person@example.test"));
            } else {
                ensure!(stored == original);
            }
            ensure!(stored.metadata.display_name == original.metadata.display_name);
            ensure!(stored.metadata.expires_at_unix == original.metadata.expires_at_unix);
            ensure!(
                h.count().await? == 1
                    && material_count(&h.db.pool, original.metadata.id.as_str()).await? == 1
            );
            ensure!(h.logged_out() != after_issue);
            ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS);
            Ok(())
        }
        .await;
        h.finish(result).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_api_key_import_rechecks_original_oauth_after_envelope_preparation() -> Result<()>
{
    let h = Harness::new().await?;
    let result = async {
        h.provider.generate_gate.arm();
        let rpc = h.rpc.clone();
        let request = tokio::spawn(async move {
            rpc.add_api_key(
                Auth::Alice,
                "openai",
                "work",
                API_KEY_MATERIAL.as_bytes(),
                None,
            )
            .await
        });
        h.provider.generate_gate.wait().await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE)))
            .execute(&h.db.pool)
            .await?;
        h.provider.generate_gate.release();
        let (status, response) = tokio::time::timeout(TIMEOUT, request).await???;
        ensure!(!status.is_success() && response["code"] == "unauthenticated");
        h.drained().await?;
        ensure!(h.count().await? == 0 && !h.control("native.pid").exists());
        ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_api_key_import_is_oauth_only_write_only_and_create_only() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        for auth in [Auth::Missing, Auth::CookieWrongOrigin, Auth::ApiKey] {
            let (status, response) = h
                .rpc
                .add_api_key(
                    auth,
                    "openai",
                    "must-not-store",
                    API_KEY_MATERIAL.as_bytes(),
                    None,
                )
                .await?;
            ensure!(!status.is_success() && response["code"] == auth.denial_code());
        }
        for (provider, material) in [
            ("github", b"valid-key".to_vec()),
            ("openai", b"invalid\nkey".to_vec()),
            ("anthropic", vec![b'x'; 1025]),
        ] {
            let (status, response) = h
                .rpc
                .add_api_key(Auth::Alice, provider, "invalid", &material, None)
                .await?;
            ensure!(!status.is_success() && response["code"] == "invalid_argument");
        }
        ensure!(h.count().await? == 0 && h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        for provider in ["openai", "anthropic"] {
            let (status, response) = h
                .rpc
                .add_api_key(
                    Auth::Alice,
                    provider,
                    provider,
                    API_KEY_MATERIAL.as_bytes(),
                    Some(4_000_000_000),
                )
                .await?;
            ensure!(status.is_success());
            let metadata = &response["credential"];
            ensure!(
                metadata["provider"] == provider
                    && metadata["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_API_KEY"
            );
            ensure!(
                metadata["revocationGeneration"] == "1"
                    && metadata["expiresAtUnix"] == "4000000000"
            );
            ensure!(metadata.get("accountHint").is_none() && metadata.get("value").is_none());
            let owner = Owner::User(OwnerId::parse(ALICE)?);
            let record = h
                .store
                .record(&owner, &CredentialId::parse(id(metadata)?)?)
                .await?;
            let material = h
                .store
                .read_for_broker(&owner, &record.metadata.id, record.version)
                .await?;
            ensure!(material.expose_secret() == API_KEY_MATERIAL.as_bytes());
            let (status, duplicate) = h
                .rpc
                .add_api_key(Auth::Alice, provider, provider, b"different-key", None)
                .await?;
            ensure!(!status.is_success() && duplicate["code"] == "already_exists");
            ensure!(h.store.record(&owner, &record.metadata.id).await? == record);
        }
        h.drained().await?;
        ensure!(h.count().await? == 2 && !h.control("native.pid").exists());
        Ok(())
    }
    .await;
    h.finish(result).await
}
