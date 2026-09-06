//! Generated OAuth-only mutation boundary over exact synthetic PostgreSQL.
//! Seven cases exercise the actual network mount; the last explicitly tests
//! the owner's bounded event queue using real shared OAuth authentication.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, ensure};
use codewire_access::{AccessProfileName, CapabilitySlot, builtin_provider_catalog};
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_server_core::auth::{AuthState, authenticate_headers_with_context, hash_oauth_token};
use serde_json::{Value, json};

use crate::platform_test_support as platform_support;
use platform_support::{
    SyntheticKek, TIMEOUT, TestDatabase, envelope_bytes, material_count, quote_ident,
};

pub(crate) mod support;
use support::*;

async fn enrolled(h: &Harness, name: &str) -> Result<Value> {
    let mut response = h.rpc.enroll(Auth::Alice, name).await?;
    response.challenge().await?;
    h.release()?;
    let credential = response.committed().await?;
    h.drained().await?;
    Ok(credential)
}

fn id(metadata: &Value) -> Result<&str> {
    metadata["id"]
        .as_str()
        .context("committed credential identifier")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_enrollment_oauth_only_commits_metadata_without_material_leaks() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let identity: (String, String) =
            sqlx::query_as("SELECT current_user::text,session_user::text")
                .fetch_one(&h.pool)
                .await?;
        ensure!(identity == (h.role.clone(), h.role.clone()));
        for auth in [Auth::Missing, Auth::Cookie, Auth::ApiKey] {
            h.rpc.denied_enrollment(auth).await?;
        }
        ensure!(!h.control("before-challenge.pid").exists() && h.count().await? == 0);
        ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == 0);
        for statement in [
            "SELECT secret FROM public.oidc_clients LIMIT 0",
            "SELECT * FROM public.sessions LIMIT 0",
            "SELECT * FROM public.api_keys LIMIT 0",
            "SELECT * FROM public.oidc_refresh_tokens LIMIT 0",
            "SELECT * FROM public.tenant_secrets LIMIT 0",
            "UPDATE public.users SET is_admin=true WHERE false",
            "UPDATE public.oidc_access_tokens SET expires_at=now() WHERE false",
            "UPDATE public.oidc_clients SET disabled=false WHERE false",
            "UPDATE public.environments SET state='running' WHERE false",
            "UPDATE public.platform_access_profiles SET current_revision=2 WHERE false",
        ] {
            denied(&h.pool, statement).await?;
        }
        let administrator: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&h.db.pool)
            .await?;
        denied(
            &h.pool,
            &format!("SET ROLE {}", quote_ident(&administrator)),
        )
        .await?;

        let metadata = enrolled(&h, "work").await?;
        ensure!(metadata["name"] == "work" && metadata["provider"] == "openai");
        ensure!(metadata["authenticationKind"] == "CREDENTIAL_AUTHENTICATION_KIND_OAUTH");
        ensure!(
            metadata["status"] == "CREDENTIAL_STATUS_ACTIVE"
                && metadata["revocationGeneration"] == "1"
        );
        ensure!(metadata["accountHint"] == "person@example.test");
        ensure!(metadata.get("expiresAtUnix").is_none());
        for name in [
            "owner",
            "materialGeneration",
            "material",
            "ciphertext",
            "wrappedDek",
            "protectedRef",
            "accessToken",
            "refreshToken",
        ] {
            ensure!(metadata.get(name).is_none());
        }
        let credential_id = CredentialId::parse(id(&metadata)?)?;
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let record = h.owner.shared.store.record(&owner, &credential_id).await?;
        let material = h
            .owner
            .shared
            .store
            .read_for_broker(&owner, &credential_id, record.version)
            .await?;
        for canary in [ACCESS, REFRESH] {
            ensure!(
                material
                    .expose_secret()
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes())
            );
        }
        let (wrapped, ciphertext, nonce) =
            envelope_bytes(&h.db.pool, credential_id.as_str()).await?;
        ensure!(!wrapped.is_empty() && !ciphertext.is_empty() && nonce.len() == 12);
        for bytes in [&wrapped, &ciphertext] {
            for canary in [ACCESS, REFRESH] {
                ensure!(
                    !bytes
                        .windows(canary.len())
                        .any(|window| window == canary.as_bytes())
                );
            }
        }
        ensure!(
            h.count().await? == 1 && material_count(&h.db.pool, credential_id.as_str()).await? == 1
        );
        ensure!(
            !h.logged_out(),
            "success revoked the imported provider credential"
        );
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_disconnect_before_challenge_and_during_envelope_preparation_drains() -> Result<()>
{
    let h = Harness::new().await?;
    let result = async {
        h.hold_challenge()?;
        let rpc = h.rpc.clone();
        let mut request =
            tokio::spawn(async move { rpc.enroll(Auth::Alice, "before-challenge").await });
        h.wait_file("before-challenge.pid").await?;
        request.abort();
        match tokio::time::timeout(TIMEOUT, &mut request).await? {
            Ok(response) => drop(response?),
            Err(error) => ensure!(error.is_cancelled()),
        }
        h.drained().await?;
        ensure!(h.count().await? == 0 && !h.logged_out());

        h.reset_login().await?;
        h.provider.generate_gate.arm();
        let mut response = h.rpc.enroll(Auth::Alice, "during-envelope").await?;
        response.challenge().await?;
        h.release()?;
        h.provider.generate_gate.wait().await?;
        drop(response);
        h.drained().await?;
        ensure!(h.count().await? == 0 && h.logged_out());
        ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_login_cannot_outlive_original_oauth_revocation_or_expiry() -> Result<()> {
    let h = Harness::new().await?;
    let result=async {
        let mut response=h.rpc.enroll(Auth::Alice,"revoked-during-login").await?;
        response.challenge().await?;
        sqlx::query("DELETE FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE))).execute(&h.db.pool).await?;
        h.release()?;
        response.error("unauthenticated").await?;
        h.drained().await?;
        ensure!(h.count().await?==0 && h.logged_out());

        h.reset_login().await?;
        sqlx::query("INSERT INTO oidc_access_tokens(token_hash,client_id,user_id,scopes,expires_at) \
            VALUES ($1,$2,$3,ARRAY['codewire.api'],clock_timestamp()+interval '3 seconds')")
            .bind(hash_oauth_token(&oauth(ALICE))).bind(CLIENT).bind(ALICE).execute(&h.db.pool).await?;
        let mut response=h.rpc.enroll(Auth::Alice,"original-expiry").await?;
        let challenge=response.challenge().await?;
        let original:i64=sqlx::query_scalar("SELECT floor(extract(epoch from expires_at))::bigint FROM oidc_access_tokens WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE))).fetch_one(&h.db.pool).await?;
        ensure!(challenge["expiresAtUnix"].as_str().context("challenge expiry")?.parse::<i64>()?<=original);
        // Replacing the database expiry with a later value must not extend
        // the already-authenticated request's original monotonic lifetime.
        sqlx::query("UPDATE oidc_access_tokens SET expires_at=clock_timestamp()+interval '1 hour' WHERE token_hash=$1")
            .bind(hash_oauth_token(&oauth(ALICE))).execute(&h.db.pool).await?;
        response.error("deadline_exceeded").await?;
        h.drained().await?;
        ensure!(h.count().await?==0 && !h.logged_out());
        Ok(())
    }.await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_duplicate_name_rolls_back_only_new_publication() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let original = enrolled(&h, "work").await?;
        let before = envelope_bytes(&h.db.pool, id(&original)?).await?;
        h.reset_login().await?;
        let mut response = h.rpc.enroll(Auth::Alice, "WORK").await?;
        response.challenge().await?;
        h.release()?;
        response.error("already_exists").await?;
        h.drained().await?;
        ensure!(h.count().await? == 1 && h.logged_out());
        ensure!(envelope_bytes(&h.db.pool, id(&original)?).await? == before);
        let state: (String, i64) = sqlx::query_as(
            "SELECT status,revocation_generation FROM platform_credentials WHERE id=$1",
        )
        .bind(id(&original)?)
        .fetch_one(&h.db.pool)
        .await?;
        ensure!(state == ("active".into(), 1));
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_lifecycle_requires_owner_current_revision_and_revoked_unreferenced_record()
-> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        let metadata = enrolled(&h, "lifecycle").await?;
        let identifier = id(&metadata)?;
        for method in ["RevokeCredential", "DeleteCredential"] {
            h.rpc
                .lifecycle_error(method, Auth::Bob, identifier, 1, "not_found")
                .await?;
            h.rpc
                .lifecycle_error(method, Auth::Cookie, identifier, 1, "unauthenticated")
                .await?;
            h.rpc
                .lifecycle_error(method, Auth::ApiKey, identifier, 1, "unauthenticated")
                .await?;
            for invalid in [0, u64::MAX] {
                h.rpc
                    .lifecycle_error(method, Auth::Alice, identifier, invalid, "invalid_argument")
                    .await?;
            }
        }
        h.rpc
            .lifecycle_error(
                "RevokeCredential",
                Auth::Alice,
                identifier,
                2,
                "failed_precondition",
            )
            .await?;
        h.rpc
            .lifecycle_error(
                "DeleteCredential",
                Auth::Alice,
                identifier,
                1,
                "failed_precondition",
            )
            .await?;
        let manager =
            PlatformAccessProfileStore::new(h.db.pool.clone(), builtin_provider_catalog());
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let profile = manager
            .create(
                &owner,
                AccessProfileName::parse("selected")?,
                BTreeMap::from([(CapabilitySlot::codex(), CredentialId::parse(identifier)?)]),
            )
            .await?;
        let (status, value) = h
            .rpc
            .lifecycle("RevokeCredential", Auth::Alice, identifier, 1)
            .await?;
        ensure!(status.is_success() && value["credential"]["revocationGeneration"] == "2");
        ensure!(value["credential"]["status"] == "CREDENTIAL_STATUS_REVOKED");
        ensure!(material_count(&h.db.pool, identifier).await? == 0 && !h.logged_out());
        h.rpc
            .lifecycle_error(
                "DeleteCredential",
                Auth::Alice,
                identifier,
                1,
                "failed_precondition",
            )
            .await?;
        h.rpc
            .lifecycle_error(
                "DeleteCredential",
                Auth::Alice,
                identifier,
                2,
                "failed_precondition",
            )
            .await?;
        manager
            .delete(&owner, &profile.id, profile.revision)
            .await?;
        let (status, value) = h
            .rpc
            .lifecycle("DeleteCredential", Auth::Alice, identifier, 2)
            .await?;
        ensure!(status.is_success() && value == json!({}) && h.count().await? == 0);
        h.rpc
            .lifecycle_error("RevokeCredential", Auth::Alice, identifier, 2, "not_found")
            .await?;
        Ok(())
    }
    .await;
    h.finish(result).await
}

pub(crate) async fn install_commit_barrier(pool: &PgPool, key: i32) -> Result<()> {
    // A deferred constraint trigger runs only when PostgreSQL executes COMMIT.
    // It is confined to the generated disposable fixture DB; no source hook,
    // wire proxy, migration edit, or production schema assertion is involved.
    sqlx::raw_sql(&format!("CREATE FUNCTION public.mutation_commit_barrier() RETURNS trigger \
        LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_advisory_xact_lock({key}); RETURN NEW; END $$; \
        CREATE CONSTRAINT TRIGGER mutation_commit_barrier AFTER INSERT ON public.platform_credential_material \
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.mutation_commit_barrier();"))
        .execute(pool).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn generated_publication_cancellation_before_commit_rolls_back_after_issue_retains()
-> Result<()> {
    // Each half has its own owner because explicit shutdown is irreversible.
    for after_issue in [false, true] {
        let h = Harness::new().await?;
        let result = async {
            let mut blocker = h.db.pool.begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker)
                .await?;
            if after_issue {
                install_commit_barrier(&h.db.pool, 4191902).await?;
                sqlx::query("SELECT pg_advisory_xact_lock(4191902)")
                    .execute(&mut *blocker)
                    .await?;
            } else {
                sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                    .bind(ALICE)
                    .execute(&mut *blocker)
                    .await?;
            }
            let mut response = h.rpc.enroll(Auth::Alice, "cancel-publication").await?;
            response.challenge().await?;
            h.release()?;
            let pid = blocked_by(&h.db.pool, blocker_pid).await?;
            let query: String =
                sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid)
                    .fetch_one(&h.db.pool)
                    .await?;
            ensure!(
                (query == "COMMIT") == after_issue,
                "barrier does not prove the intended publication phase"
            );
            drop(response);
            // Explicit owner cancellation makes the pre-/post-COMMIT boundary
            // deterministic; response loss alone is not an instant TCP ACK.
            let owner = h.owner.clone();
            let mut shutdown = tokio::spawn(async move { owner.shutdown().await });
            tokio::time::timeout(TIMEOUT, h.owner.stop.cancelled()).await?;
            ensure!(
                h.owner.capacity.available_permits() == MAX_OPERATIONS - 1,
                "SQL cleanup released its admission permit early"
            );
            blocker.rollback().await?;
            tokio::time::timeout(TIMEOUT, &mut shutdown)
                .await??
                .map_err(|error| anyhow::anyhow!("closed mutation shutdown: {error:?}"))?;
            ensure!(h.count().await? == i64::from(after_issue));
            ensure!(
                h.logged_out() != after_issue,
                "publication disposition revoked a potentially committed login"
            );
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
async fn generated_late_commit_preserves_unknown_disposition_and_disposes_original_connection()
-> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        // The pinned PostgreSQL fixture does not poll disconnected clients
        // during COMMIT. Observe its default; do not alter connection behavior.
        let connection_check: String =
            sqlx::query_scalar("SELECT current_setting('client_connection_check_interval')")
                .fetch_one(&h.pool)
                .await?;
        ensure!(connection_check == "0");
        install_commit_barrier(&h.db.pool, 4191903).await?;
        let mut blocker = h.db.pool.begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(4191903)")
            .execute(&mut *blocker)
            .await?;
        let mut response = h.rpc.enroll(Auth::Alice, "late-commit").await?;
        response.challenge().await?;
        h.release()?;
        let pid = blocked_by(&h.db.pool, blocker_pid).await?;
        let query: String = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
            .bind(pid)
            .fetch_one(&h.db.pool)
            .await?;
        ensure!(query == "COMMIT");
        response.error("unknown").await?;
        h.drained().await?;
        ensure!(
            !h.logged_out(),
            "unknown COMMIT outcome triggered provider logout"
        );
        ensure!(h.owner.capacity.available_permits() == MAX_OPERATIONS);

        // Hold every pool slot simultaneously, not just one spare connection.
        // The original connection must be locally disposed even though its
        // remote backend can still finish the already-issued COMMIT later.
        let capacity = h.pool.options().get_max_connections();
        let replacements = tokio::time::timeout(TIMEOUT, async {
            let mut connections = Vec::new();
            let mut pids = BTreeSet::new();
            for _ in 0..capacity {
                let mut connection = h.pool.acquire().await?;
                let replacement: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *connection)
                    .await?;
                ensure!(replacement != pid && pids.insert(replacement));
                connections.push(connection);
            }
            Ok::<_, anyhow::Error>(connections)
        })
        .await
        .context("issued COMMIT connection retained pool capacity")??;
        let still_blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 \
             AND query='COMMIT' AND $2=ANY(pg_blocking_pids(pid)))",
        )
        .bind(pid)
        .bind(blocker_pid)
        .fetch_one(&h.db.pool)
        .await?;
        ensure!(still_blocked && h.count().await? == 0);
        ensure!(h.provider.generate_calls.load(Ordering::SeqCst) == 1);
        drop(replacements);

        // PostgreSQL may commit after the local timeout. Release the exact
        // deferred-trigger barrier, then prove that this late durable result
        // remains encrypted and usable instead of being logged out or replayed.
        blocker.rollback().await?;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                )
                .bind(pid)
                .fetch_one(&h.db.pool)
                .await?;
                if !exists {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("late COMMIT backend did not finish after barrier release")??;
        ensure!(h.count().await? == 1);
        let stored_id: String = sqlx::query_scalar(
            "SELECT id FROM public.platform_credentials WHERE user_id=$1 AND display_name='late-commit'",
        )
        .bind(ALICE)
        .fetch_one(&h.db.pool)
        .await?;
        let credential_id = CredentialId::parse(stored_id)?;
        let owner = Owner::User(OwnerId::parse(ALICE)?);
        let record = h.owner.shared.store.record(&owner, &credential_id).await?;
        ensure!(record.metadata.owner == owner);
        ensure!(record.metadata.status == codewire_access::CredentialStatus::Active);
        ensure!(record.version.revocation_generation == 1 && record.version.material_generation == 1);
        ensure!(material_count(&h.db.pool, credential_id.as_str()).await? == 1);
        let material = h
            .owner
            .shared
            .store
            .read_for_broker(&owner, &credential_id, record.version)
            .await?;
        let (wrapped, ciphertext, nonce) = envelope_bytes(&h.db.pool, credential_id.as_str()).await?;
        ensure!(!wrapped.is_empty() && !ciphertext.is_empty() && nonce.len() == 12);
        for canary in [ACCESS, REFRESH] {
            ensure!(material.expose_secret().windows(canary.len()).any(|window| window == canary.as_bytes()));
            for bytes in [&wrapped, &ciphertext] {
                ensure!(!bytes.windows(canary.len()).any(|window| window == canary.as_bytes()));
            }
        }
        ensure!(!h.logged_out() && h.provider.generate_calls.load(Ordering::SeqCst) == 1);
        Ok(())
    }
    .await;
    h.finish(result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL, executable TMPDIR and owned Linux tmpfs"]
async fn owner_queue_preserves_terminal_failure_behind_unconsumed_challenge() -> Result<()> {
    let h = Harness::new().await?;
    let result = async {
        // Supplemental owner-level queue proof, not a network backpressure
        // claim. The opaque authority still comes from real shared OAuth/SQL
        // authentication; no authority fields or test constructors are used.
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", oauth(ALICE)).parse()?);
        let auth = authenticate_headers_with_context(
            &AuthState {
                pool: h.pool.clone(),
            },
            &headers,
        )
        .await?;
        let authority = auth
            .oauth_bearer_authority()
            .context("original OAuth authority")?
            .clone();
        let mut events = h
            .owner
            .enroll(authority, "buffered-failure".into())
            .map_err(|error| anyhow::anyhow!("closed enrollment error: {error:?}"))?;
        h.wait_file("native.pid").await?;
        tokio::time::timeout(TIMEOUT, async {
            while events.receiver.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        h.provider.fail_generate.store(true, Ordering::SeqCst);
        h.release()?;
        h.drained().await?;
        let challenge = tokio::time::timeout(TIMEOUT, events.receiver.recv())
            .await?
            .context("missing buffered challenge")?
            .map_err(|error| anyhow::anyhow!("unexpected challenge failure: {error:?}"))?;
        ensure!(matches!(
            challenge.event,
            Some(enroll_codex_response::Event::Challenge(_))
        ));
        let terminal = tokio::time::timeout(TIMEOUT, events.receiver.recv())
            .await?
            .context("buffered challenge swallowed terminal failure")?;
        ensure!(matches!(terminal, Err(Error::Unavailable)));
        ensure!(
            tokio::time::timeout(TIMEOUT, events.receiver.recv())
                .await?
                .is_none()
        );
        ensure!(h.count().await? == 0 && h.logged_out());
        Ok(())
    }
    .await;
    h.finish(result).await
}
