//! Real restricted mutation mount with a synthetic, isolated official-gh flow.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_app_missing_configuration_is_definite_and_never_publishes() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        ensure!(h.owner.shared.github_app_authorization.is_none());
        let (status, value) = h
            .rpc
            .update(
                "CompleteGithubAppAuthorization",
                Auth::Cookie,
                json!({"code": "c3ludGhldGljLWNvZGU="}),
            )
            .await?;
        ensure!(!status.is_success());
        ensure!(value["code"] == "failed_precondition");
        ensure!(
            value["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no credential was changed")
        );
        ensure!(!value.to_string().contains("may have completed"));
        h.drained().await?;
        ensure!(h.count().await? == 0);
        ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        ensure!(!h.control("version.pid").exists());
        Ok(())
    }
    .await;
    h.finish(result).await
}

async fn github_challenge(stream: &mut ConnectStream) -> Result<()> {
    let frame = stream.next().await?.context("missing GitHub challenge")?;
    ensure!(frame["challenge"]["verificationUrl"] == "https://github.com/login/device");
    ensure!(frame["challenge"]["userCode"] == "ABCD-EFGH");
    ensure!(frame.get("credential").is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_create_and_reconnect_use_protected_storage_and_exact_identity() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        for auth in [Auth::Missing, Auth::CookieWrongOrigin, Auth::ApiKey] {
            // Connect streaming rejection is an END_STREAM error, not an
            // HTTP failure. No challenge or credential may precede it.
            h.rpc
                .enroll_github_request(auth, json!({"name":"no-login"}))
                .await?
                .error(auth.denial_code())
                .await?;
        }
        ensure!(!h.control("version.pid").exists());
        ensure!(h.count().await? == 0);
        ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        let mut stream = h.rpc.enroll_github_request(Auth::Alice, json!({})).await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let metadata = stream.committed().await?;
        h.drained().await?;
        ensure!(metadata["provider"] == "github" && metadata["accountHint"] == "synthetic-user");
        ensure!(metadata["name"] == "synthetic-user");
        ensure!(metadata["revocationGeneration"] == "1");
        let credential_id = CredentialId::parse(id(&metadata)?)?;
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let original = h.store.record(&owner, &credential_id).await?;
        let material = h
            .store
            .read_for_broker(&owner, &credential_id, original.version)
            .await?;
        ensure!(material.expose_secret() == GITHUB_TOKEN.as_bytes());
        let (wrapped, ciphertext, _) = envelope_bytes(&h.db.pool, credential_id.as_str()).await?;
        for bytes in [&wrapped, &ciphertext] {
            ensure!(
                !bytes
                    .windows(GITHUB_TOKEN.len())
                    .any(|value| value == GITHUB_TOKEN.as_bytes())
            );
        }
        // GitHub is one account-level connection. A second connection fails
        // closed before any provider challenge, never as an implicit upsert.
        h.reset_login().await?;
        let mut duplicate = h.rpc.enroll_github_request(Auth::Alice, json!({})).await?;
        duplicate.error("already_exists").await?;
        h.drained().await?;
        ensure!(h.count().await? == 1 && !h.logged_out());
        ensure!(h.store.record(&owner, &credential_id).await? == original);
        // A legacy named create is still a second connection.
        let mut legacy = h
            .rpc
            .enroll_github_request(Auth::Alice, json!({"name":"work-github"}))
            .await?;
        legacy.error("already_exists").await?;
        h.drained().await?;
        ensure!(h.count().await? == 1 && !h.logged_out());
        // Reconnect replaces the one connection in place.
        h.reset_login().await?;
        let mut stream = h
            .rpc
            .enroll_github_request(
                Auth::Alice,
                json!({
                    "name":"synthetic-user", "credentialId":credential_id.as_str(),
                    "expectedRevocationGeneration":"1"
                }),
            )
            .await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let replaced = stream.committed().await?;
        h.drained().await?;
        ensure!(replaced["id"] == metadata["id"] && replaced["revocationGeneration"] == "2");
        ensure!(replaced["name"] == metadata["name"]);
        ensure!(h.count().await? == 1 && !h.logged_out());
        let stored = h.store.record(&owner, &credential_id).await?;
        ensure!(stored.version.material_generation == original.version.material_generation + 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_reconnect_rejects_wrong_provider_and_original_oauth_revocation() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let codex = enrolled(&h, "codex-work").await?;
        h.reset_login().await?;
        let mut stream = h.rpc.enroll_github_request(Auth::Alice, json!({
            "name":"codex-work", "credentialId":id(&codex)?, "expectedRevocationGeneration":"1"
        })).await?;
        stream.error("invalid_argument").await?;
        h.drained().await?;
        ensure!(!h.control("version.pid").exists());
        let mut stream = h
            .rpc
            .enroll_github_request(Auth::Alice, json!({"name":"revoked-login"}))
            .await?;
        github_challenge(&mut stream).await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE)))
            .execute(&h.db.pool)
            .await?;
        h.release()?;
        // The exact original authority was rejected before publication, so
        // this is a definite no-store terminal rather than a post-COMMIT
        // acknowledgement ambiguity.
        stream.error("failed_precondition").await?;
        h.drained().await?;
        ensure!(h.count().await? == 1 && !h.logged_out());
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn github_delete_is_direct_keeps_profiles_and_reconnect_restores_use() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let mut stream = h.rpc.enroll_github_request(Auth::Alice, json!({})).await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let metadata = stream.committed().await?;
        h.drained().await?;
        let first = id(&metadata)?.to_owned();
        let manager =
            PlatformAccessProfileStore::new(h.db.pool.clone(), builtin_provider_catalog());
        let profile = manager
            .create(&owner, AccessProfileName::parse("work")?, BTreeMap::new())
            .await?;
        ensure!(
            codewire_platform_credentials::active_github_connection(&h.db.pool, &owner)
                .await?
                .map(|id| id.to_string())
                == Some(first.clone())
        );

        // GitHub has no user-visible revoke step: Delete removes the active
        // connection and its protected material in one mutation.
        let (status, value) = h
            .rpc
            .lifecycle("DeleteCredential", Auth::Cookie, &first, 1)
            .await?;
        ensure!(status.is_success(), "direct GitHub delete failed: {value}");
        ensure!(h.count().await? == 0 && !h.logged_out());
        ensure!(material_count(&h.db.pool, &first).await? == 0);
        let kept = manager.get(&owner, &profile.id).await?;
        ensure!(kept.revision == profile.revision && kept.includes_github());
        ensure!(
            codewire_platform_credentials::active_github_connection(&h.db.pool, &owner)
                .await?
                .is_none()
        );

        // Reconnect creates the one connection again; every profile that
        // includes GitHub resolves it without a new revision.
        h.reset_login().await?;
        let mut stream = h.rpc.enroll_github_request(Auth::Alice, json!({})).await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let reconnected = stream.committed().await?;
        h.drained().await?;
        let second = id(&reconnected)?.to_owned();
        ensure!(second != first);
        ensure!(
            codewire_platform_credentials::active_github_connection(&h.db.pool, &owner)
                .await?
                .map(|id| id.to_string())
                == Some(second)
        );
        let restored = manager.get(&owner, &profile.id).await?;
        ensure!(restored.revision == profile.revision && restored.includes_github());
        Ok(())
    }
    .await;
    h.finish(result).await
}
