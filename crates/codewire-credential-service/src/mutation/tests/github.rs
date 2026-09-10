//! Real restricted mutation mount with a synthetic, isolated official-gh flow.

use super::*;

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
        let mut stream = h
            .rpc
            .enroll_github_request(Auth::Alice, json!({"name":"work-github"}))
            .await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let metadata = stream.committed().await?;
        h.drained().await?;
        ensure!(metadata["provider"] == "github" && metadata["accountHint"] == "synthetic-user");
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
        h.reset_login().await?;
        let mut stream = h
            .rpc
            .enroll_github_request(
                Auth::Alice,
                json!({
                    "name":"work-github", "credentialId":credential_id.as_str(),
                    "expectedRevocationGeneration":"1"
                }),
            )
            .await?;
        github_challenge(&mut stream).await?;
        h.release()?;
        let replaced = stream.committed().await?;
        h.drained().await?;
        ensure!(replaced["id"] == metadata["id"] && replaced["revocationGeneration"] == "2");
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
        stream.error("unauthenticated").await?;
        h.drained().await?;
        ensure!(h.count().await? == 1 && !h.logged_out());
        Ok(())
    }
    .await;
    h.finish(result).await
}
