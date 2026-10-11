//! Real isolated OAuth mutation mount, synthetic key generation/import only.
use super::*;
use base64::Engine as _;
use codewire_protected_store::ssh_material::{decode_protected_material, generate_ed25519};

#[test]
fn ssh_generated_import_debug_redacts_key_and_passphrase() {
    let request = codewire_proto::codewire::v1::AddSshCredentialRequest {
        name: "synthetic-ssh".into(),
        private_key: b"private-ssh-key-canary".to_vec(),
        passphrase: Some(b"private-ssh-passphrase-canary".to_vec()),
        ..Default::default()
    };
    let debug = format!("{request:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("private-ssh-key-canary"));
    assert!(!debug.contains("private-ssh-passphrase-canary"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn ssh_rpc_is_oauth_only_create_only_and_returns_only_derived_public_identity() -> Result<()>
{
    let h = Harness::new().await?;
    let result = async {
        for method in ["GenerateSshCredential", "AddSshCredential"] {
            for auth in [Auth::Missing, Auth::CookieWrongOrigin, Auth::ApiKey] {
                let (status, response) = h.rpc.ssh(method, auth, json!({"name":"must-not-store"})).await?;
                ensure!(!status.is_success() && response["code"] == auth.denial_code());
            }
        }
        for body in [json!({"name":"bad","privateKey":""}),
            json!({"name":"bad","privateKey":base64::engine::general_purpose::STANDARD.encode(b"private-invalid-ssh-canary")}),
            json!({"name":"bad","privateKey":"eA==","passphrase":""})] {
            let (status, response) = h.rpc.ssh("AddSshCredential", Auth::Alice, body).await?;
            ensure!(!status.is_success() && response["code"] == "invalid_argument");
            ensure!(!response.to_string().contains("private-invalid-ssh-canary"));
        }
        for expiry in ["0", "1", "18446744073709551615"] {
            let (status, response) = h.rpc.ssh("GenerateSshCredential", Auth::Alice,
                json!({"name":"invalid-expiry","expiresAtUnix":expiry})).await?;
            ensure!(!status.is_success() && response["code"] == "invalid_argument");
        }
        ensure!(h.count().await? == 0 && h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        let (status, generated) = h.rpc.ssh("GenerateSshCredential", Auth::Alice,
            json!({"name":"Work SSH","expiresAtUnix":"4000000000"})).await?;
        ensure!(status.is_success());
        let metadata = &generated["credential"];
        ensure!(metadata["provider"] == "ssh" && metadata["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY");
        ensure!(metadata["revocationGeneration"] == "1" && metadata["expiresAtUnix"] == "4000000000");
        ensure!(metadata.get("accountHint").is_none() && metadata.get("privateKey").is_none() && metadata.get("passphrase").is_none());
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let record = h.store.record(&owner, &CredentialId::parse(id(metadata)?)?).await?;
        let key = decode_protected_material(h.store.read_for_broker(&owner, &record.metadata.id, record.version).await?)?;
        ensure!(metadata["sshPublicKey"]["openssh"] == key.public_key().openssh());
        ensure!(metadata["sshPublicKey"]["fingerprint"] == key.public_key().fingerprint());
        let (status, duplicate) = h.rpc.ssh("GenerateSshCredential", Auth::Alice, json!({"name":"work ssh"})).await?;
        ensure!(!status.is_success() && duplicate["code"] == "already_exists");
        ensure!(h.store.record(&owner, &record.metadata.id).await? == record);

        let (public, bundle) = generate_ed25519()?.into_parts();
        let (private_key, _) = decode_protected_material(bundle)?.into_parts();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&*private_key);
        let (status, imported) = h.rpc.ssh("AddSshCredential", Auth::Alice,
            json!({"name":"Imported SSH","privateKey":encoded})).await?;
        ensure!(status.is_success());
        ensure!(imported["credential"]["sshPublicKey"]["openssh"] == public.openssh());
        ensure!(imported["credential"]["sshPublicKey"]["fingerprint"] == public.fingerprint());
        ensure!(!imported.to_string().contains(&encoded));
        ensure!(!imported.to_string().contains("BEGIN OPENSSH PRIVATE KEY"));
        h.drained().await?;
        ensure!(h.count().await? == 2);
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn ssh_publication_rechecks_original_oauth_after_preparation() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        h.provider.generate_gate.arm();
        let rpc = h.rpc.clone();
        let task = tokio::spawn(async move {
            rpc.ssh(
                "GenerateSshCredential",
                Auth::Alice,
                json!({"name":"Revoked OAuth SSH"}),
            )
            .await
        });
        h.provider.generate_gate.wait().await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE)))
            .execute(&h.db.pool)
            .await?;
        h.provider.generate_gate.release();
        let (status, response) = tokio::time::timeout(TIMEOUT, task).await???;
        ensure!(!status.is_success() && response["code"] == "unauthenticated");
        h.drained().await?;
        ensure!(h.count().await? == 0 && h.owner.capacity.available_permits() == MAX_OPERATIONS);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn ssh_cancel_keeps_public_metadata_and_material_at_the_same_commit_boundary() -> Result<()> {
    for commit_issued in [false, true] {
        let h = Harness::new().await?;
        let result = async {
            let mut blocker = h.db.pool.begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await?;
            if commit_issued {
                install_commit_barrier(&h.db.pool, 4191905).await?;
                sqlx::query("SELECT pg_advisory_xact_lock(4191905)").execute(&mut *blocker).await?;
            } else {
                sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE").bind(ALICE).execute(&mut *blocker).await?;
            }
            let rpc = h.rpc.clone();
            let request = tokio::spawn(async move {
                rpc.ssh("GenerateSshCredential", Auth::Alice, json!({"name":"Commit-fenced SSH"})).await
            });
            let pid = blocked_by(&h.db.pool, blocker_pid).await?;
            let query: String = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1").bind(pid).fetch_one(&h.db.pool).await?;
            ensure!((query == "COMMIT") == commit_issued);
            request.abort();
            let _ = request.await;
            h.owner.start_shutdown();
            ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS - 1);
            blocker.rollback().await?;
            tokio::time::timeout(TIMEOUT, h.owner.shutdown()).await?
                .map_err(|e| anyhow::anyhow!("closed SSH shutdown: {e:?}"))?;
            let rows: Vec<(bool, bool)> = sqlx::query_as("SELECT c.ssh_public_key IS NOT NULL AND c.ssh_fingerprint IS NOT NULL, m.credential_id IS NOT NULL FROM platform_credentials c LEFT JOIN platform_credential_material m ON m.credential_id=c.id")
                .fetch_all(&h.db.pool).await?;
            ensure!(rows == if commit_issued { vec![(true,true)] } else { vec![] });
            ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS);
            Ok(())
        }.await;
        h.finish(result).await?;
    }
    Ok(())
}
