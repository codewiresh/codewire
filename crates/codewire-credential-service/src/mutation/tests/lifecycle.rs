//! Existing named CLI lifecycle through the real OAuth-only generated mount.

use super::*;
use base64::Engine as _;
use codewire_access::CredentialAuthKind;
use codewire_platform_credentials::{CredentialRecord, CredentialRegistration};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{CodexDeviceChallenge, RotateApiKeyCredentialRequest};

async fn existing(
    h: &Harness,
    provider: &str,
    kind: CredentialAuthKind,
) -> Result<CredentialRecord> {
    Ok(h.store
        .create(
            &Owner::User(OwnerId::parse(ALICE)?),
            CredentialRegistration {
                provider: ProviderId::parse(provider)?,
                authentication_kind: kind,
                display_name: provider.into(),
                account_hint: Some("kept-account".into()),
                expires_at_unix: Some(4_000_000_000),
            },
            &ProtectedValue::from_slice(b"synthetic-previous-credential")?,
        )
        .await?)
}

fn rename(record: &CredentialRecord) -> Value {
    json!({"credentialId":record.metadata.id.as_str(),
        "expectedRevocationGeneration":record.metadata.revocation_generation.to_string(),
        "expectedName":record.metadata.display_name, "name":"renamed-work"})
}

fn rotation(record: &CredentialRecord) -> Value {
    json!({"credentialId":record.metadata.id.as_str(),
        "expectedRevocationGeneration":record.metadata.revocation_generation.to_string(),
        "value":base64::engine::general_purpose::STANDARD.encode(API_KEY_MATERIAL)})
}

#[test]
fn rotation_and_device_codes_do_not_enter_generated_debug() {
    let request = RotateApiKeyCredentialRequest {
        value: API_KEY_MATERIAL.as_bytes().to_vec(),
        ..Default::default()
    };
    let challenge = CodexDeviceChallenge {
        user_code: "SYNTHETIC-CODE".into(),
        ..Default::default()
    };
    for (debug, canary) in [
        (format!("{request:?}"), API_KEY_MATERIAL),
        (format!("{challenge:?}"), "SYNTHETIC-CODE"),
    ] {
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(canary));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_rename_is_oauth_only_exact_name_and_revision_metadata_only() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let original = existing(&h, "openai", CredentialAuthKind::ApiKey).await?;
        for auth in [
            Auth::Missing,
            Auth::CookieWrongOrigin,
            Auth::ApiKey,
            Auth::Bob,
        ] {
            let (status, response) = h
                .rpc
                .update("RenameCredential", auth, rename(&original))
                .await?;
            ensure!(!status.is_success());
            ensure!(
                response["code"]
                    == if matches!(auth, Auth::Bob) {
                        "not_found"
                    } else {
                        auth.denial_code()
                    }
            );
        }
        let calls = h.provider.generate_calls.load(Ordering::SeqCst);
        let before = envelope_bytes(&h.db.pool, original.metadata.id.as_str()).await?;
        for (field, value, code) in [
            ("expectedRevocationGeneration", "2", "failed_precondition"),
            ("expectedName", "OPENAI", "failed_precondition"),
            ("name", "\ninvalid", "invalid_argument"),
        ] {
            let mut body = rename(&original);
            body[field] = json!(value);
            let (status, response) = h.rpc.update("RenameCredential", Auth::Alice, body).await?;
            ensure!(!status.is_success() && response["code"] == code);
        }
        let (status, response) = h
            .rpc
            .update("RenameCredential", Auth::Alice, rename(&original))
            .await?;
        ensure!(status.is_success() && response["credential"]["name"] == "renamed-work");
        let mut expected = original.clone();
        expected.metadata.display_name = "renamed-work".into();
        ensure!(
            h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?
                == expected
        );
        ensure!(envelope_bytes(&h.db.pool, original.metadata.id.as_str()).await? == before);
        ensure!(
            h.provider.generate_calls.load(Ordering::SeqCst) == calls
                && h.provider.unwrap_calls.load(Ordering::SeqCst) == 0
        );
        let (status, response) = h
            .rpc
            .update("RenameCredential", Auth::Alice, rename(&original))
            .await?;
        ensure!(!status.is_success() && response["code"] == "failed_precondition");
        h.drained().await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_rotation_is_explicit_write_only_exact_identity_and_revision() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        for provider in ["openai", "anthropic"] {
            let original = existing(&h, provider, CredentialAuthKind::ApiKey).await?;
            for auth in [
                Auth::Missing,
                Auth::CookieWrongOrigin,
                Auth::ApiKey,
                Auth::Bob,
            ] {
                let (status, response) = h
                    .rpc
                    .update("RotateApiKeyCredential", auth, rotation(&original))
                    .await?;
                ensure!(!status.is_success());
                ensure!(
                    response["code"]
                        == if matches!(auth, Auth::Bob) {
                            "not_found"
                        } else {
                            auth.denial_code()
                        }
                );
            }
            let calls = h.provider.generate_calls.load(Ordering::SeqCst);
            for (field, value, code) in [
                ("expectedRevocationGeneration", "2", "failed_precondition"),
                ("expiresAtUnix", "1", "invalid_argument"),
                ("expiresAtUnix", "18446744073709551615", "invalid_argument"),
                ("value", "aW52YWxpZCBrZXk=", "invalid_argument"),
            ] {
                let mut body = rotation(&original);
                body[field] = json!(value);
                let (status, response) = h
                    .rpc
                    .update("RotateApiKeyCredential", Auth::Alice, body)
                    .await?;
                ensure!(!status.is_success() && response["code"] == code);
            }
            ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == calls);
            let revoked = h
                .store
                .revoke(
                    &original.metadata.owner,
                    &original.metadata.id,
                    original.version,
                )
                .await?;
            let (status, response) = h
                .rpc
                .update("RotateApiKeyCredential", Auth::Alice, rotation(&revoked))
                .await?;
            ensure!(status.is_success());
            let next = h
                .store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?;
            let mut expected = revoked.clone();
            expected.version.revocation_generation += 1;
            expected.version.material_generation += 1;
            expected.metadata.revocation_generation = expected.version.revocation_generation;
            expected.metadata.status = codewire_access::CredentialStatus::Active;
            expected.metadata.expires_at_unix = None;
            ensure!(next == expected);
            ensure!(
                response["credential"]["id"] == original.metadata.id.as_str()
                    && response["credential"]["status"] == "CREDENTIAL_STATUS_ACTIVE"
                    && response["credential"].get("expiresAtUnix").is_none()
            );
            ensure!(
                h.store
                    .read_for_broker(&next.metadata.owner, &next.metadata.id, next.version)
                    .await?
                    .expose_secret()
                    == API_KEY_MATERIAL.as_bytes()
            );
        }
        let oauth = existing(&h, "github", CredentialAuthKind::OAuth).await?;
        let calls = h.provider.generate_calls.load(Ordering::SeqCst);
        let (status, response) = h
            .rpc
            .update("RotateApiKeyCredential", Auth::Alice, rotation(&oauth))
            .await?;
        ensure!(!status.is_success() && response["code"] == "invalid_argument");
        ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == calls);
        h.drained().await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_rotation_rechecks_original_oauth_and_concurrent_revocation() -> Result<()> {
    for revoke_oauth in [false, true] {
        let h = Harness::new().await?;
        let result = async {
            let original = existing(&h, "openai", CredentialAuthKind::ApiKey).await?;
            h.provider.generate_gate.arm();
            let rpc = h.rpc.clone();
            let body = rotation(&original);
            let request = tokio::spawn(async move {
                rpc.update("RotateApiKeyCredential", Auth::Alice, body)
                    .await
            });
            h.provider.generate_gate.wait().await?;
            let expected = if revoke_oauth {
                sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
                    .bind(hash_oauth_token(&oauth(ALICE)))
                    .execute(&h.db.pool)
                    .await?;
                original
            } else {
                h.store
                    .revoke(
                        &original.metadata.owner,
                        &original.metadata.id,
                        original.version,
                    )
                    .await?
            };
            h.provider.generate_gate.release();
            let (status, response) = tokio::time::timeout(HANG_GUARD, request).await???;
            ensure!(
                !status.is_success()
                    && response["code"]
                        == if revoke_oauth {
                            "unauthenticated"
                        } else {
                            "failed_precondition"
                        }
            );
            h.drained().await?;
            ensure!(
                h.store
                    .record(&expected.metadata.owner, &expected.metadata.id)
                    .await?
                    == expected
            );
            ensure!(h.provider.unwrap_calls.load(Ordering::SeqCst) == 0 && h.count().await? == 1);
            Ok(())
        }
        .await;
        h.finish(result).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_rename_rechecks_original_oauth_before_publication() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let original = existing(&h, "openai", CredentialAuthKind::ApiKey).await?;
        let mut blocker = h.db.pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(ALICE)
            .execute(&mut *blocker)
            .await?;
        let rpc = h.rpc.clone();
        let body = rename(&original);
        let request =
            tokio::spawn(async move { rpc.update("RenameCredential", Auth::Alice, body).await });
        blocked_by(&h.db.pool, blocker_pid).await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE)))
            .execute(&h.db.pool)
            .await?;
        blocker.rollback().await?;
        let (status, response) = tokio::time::timeout(HANG_GUARD, request).await???;
        ensure!(!status.is_success() && response["code"] == "unauthenticated");
        h.drained().await?;
        ensure!(
            h.store
                .record(&original.metadata.owner, &original.metadata.id)
                .await?
                == original
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}
