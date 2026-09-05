//! Synthetic PostgreSQL coordination proof. These tests use separate replica
//! pools, not a process mutex, and never contact a real OAuth/KEK provider.
//! Explicit --ignored execution requires TEST_DATABASE_URL and cleans the exact
//! generated database. No claim of exactly-once external delivery follows.

#[allow(dead_code)]
mod support;

use std::error::Error as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use codewire_access::{
    CredentialAuthKind as Kind, CredentialId, CredentialStatus, Owner, builtin_provider_catalog,
};
use codewire_platform_credentials::{
    CredentialMetadataReader, CredentialRecord, CredentialVersion, OAuthRefreshState as State,
    PlatformCredentialError as Error, PlatformCredentialStore, StartedOAuthRefresh,
};
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, GeneratedDek, KekProvider, KekProviderKind, SecretEnvelopeError,
    TestKekProvider, WrappedDek,
};
use codewire_server_core::org_deletion::begin_organization_deletion;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use zeroize::Zeroizing;

use support::*;

#[derive(Default)]
struct SyntheticOAuthProvider {
    consumed_old_token: AtomicBool,
    requests: AtomicUsize,
}

impl SyntheticOAuthProvider {
    fn exchange(
        &self,
        _permit: &StartedOAuthRefresh,
    ) -> Result<codewire_protected_store::ProtectedValue> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        ensure!(
            !self.consumed_old_token.swap(true, Ordering::SeqCst),
            "synthetic provider received a consumed refresh token"
        );
        Ok(value(NEW_VALUE))
    }
}

async fn replica(
    db: &TestDatabase,
    provider: Arc<dyn KekProvider>,
) -> Result<(PgPool, Arc<PlatformCredentialStore>)> {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(db.pool.connect_options().as_ref().clone())
        .await?;
    let store = Arc::new(PlatformCredentialStore::new(
        pool.clone(),
        provider,
        builtin_provider_catalog(),
    ));
    Ok((pool, store))
}

async fn create(
    store: &PlatformCredentialStore,
    owner: &Owner,
    name: &str,
) -> Result<CredentialRecord> {
    let mut input = registration(name, Kind::OAuth);
    input.expires_at_unix = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 3_600,
    );
    Ok(store.create(owner, input, &value(OLD_VALUE)).await?)
}

async fn started(
    store: &PlatformCredentialStore,
    owner: &Owner,
    record: &CredentialRecord,
) -> Result<(Uuid, StartedOAuthRefresh)> {
    let attempt = Uuid::new_v4();
    let prepared = store
        .begin_oauth_refresh(owner, &record.metadata.id, record.version, attempt)
        .await?;
    Ok((attempt, store.start_oauth_refresh(prepared).await?))
}

fn promoted(version: CredentialVersion) -> CredentialVersion {
    CredentialVersion {
        revocation_generation: version.revocation_generation + 1,
        material_generation: version.material_generation + 1,
    }
}

async fn counts(pool: &PgPool, id: &CredentialId) -> Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT \
        (SELECT count(*) FROM platform_credential_refresh_attempts WHERE credential_id=$1), \
        (SELECT count(*) FROM platform_credential_refresh_material m JOIN platform_credential_refresh_attempts a USING(attempt_id) WHERE a.credential_id=$1)")
        .bind(id.as_str()).fetch_one(pool).await?)
}

async fn expire(pool: &PgPool, id: &CredentialId) -> Result<()> {
    sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn two_replicas_reserve_one_provider_operation_and_publish_one_exact_version() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("two-replicas").await?;
        let provider = Arc::new(SyntheticKek::default());
        let first = db.store(provider.clone());
        let (second_pool, second) = replica(&db, provider.clone()).await?;
        let record = create(&first, &owner, "Concurrent").await?;
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let (a, b) = tokio::join!(
            first.begin_oauth_refresh(&owner, &record.metadata.id, record.version, first_id),
            second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, second_id),
        );
        let (attempt, prepared) = match (a, b) {
            (Ok(permit), Err(Error::RefreshInProgress)) => (first_id, permit),
            (Err(Error::RefreshInProgress), Ok(permit)) => (second_id, permit),
            _ => anyhow::bail!("independent replicas did not select exactly one refresh owner"),
        };
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
        let permit = second.start_oauth_refresh(prepared).await?;
        let oauth = SyntheticOAuthProvider::default();
        let encrypted = permit.prepare_result(&oauth.exchange(&permit)?)?;
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        first.stage_oauth_refresh(&encrypted).await?;
        second.stage_oauth_refresh(&encrypted).await?;
        ensure!(
            first
                .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?
                == promoted(record.version)
        );
        ensure!(
            second
                .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?
                == promoted(record.version)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated);
        ensure!(oauth.requests.load(Ordering::SeqCst) == 1);
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 0));
        let current = second.record(&owner, &record.metadata.id).await?;
        ensure!(current.version == promoted(record.version));
        ensure!(current.metadata.expires_at_unix == record.metadata.expires_at_unix);
        ensure!(
            second
                .read_for_broker(&owner, &record.metadata.id, current.version)
                .await?
                .expose_secret()
                == NEW_VALUE
        );
        second_pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn only_expired_unstarted_reservations_can_be_reclaimed_and_old_permits_fail() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("reserved-recovery").await?;
        let provider = Arc::new(SyntheticKek::default());
        let first = db.store(provider.clone());
        let (second_pool, second) = replica(&db, provider).await?;
        let record = create(&first, &owner, "Reclaim").await?;
        let old_id = Uuid::new_v4();
        let old = first.begin_oauth_refresh(&owner, &record.metadata.id, record.version, old_id).await?;
        ensure!(matches!(second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, old_id).await, Err(Error::StaleRefresh)));
        sqlx::query("UPDATE platform_credential_refresh_attempts SET reserved_until=clock_timestamp()-interval '1 second' WHERE credential_id=$1")
            .bind(record.metadata.id.as_str()).execute(&db.pool).await?;
        let new_id = Uuid::new_v4();
        let new = second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        ensure!(matches!(first.start_oauth_refresh(old).await, Err(Error::StaleRefresh)));
        ensure!(first.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, old_id).await == Err(Error::StaleRefresh));
        second.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        first.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        ensure!(matches!(second.start_oauth_refresh(new).await, Err(Error::StaleRefresh)));
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 0));
        ensure!(first.read_for_broker(&owner, &record.metadata.id, record.version).await?.expose_secret() == OLD_VALUE);
        second_pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn ambiguous_start_and_provider_acceptance_never_allow_timeout_replay() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("unknown-recovery").await?;
        let provider = Arc::new(SyntheticKek::default());
        let first = db.store(provider.clone());
        let (second_pool, second) = replica(&db, provider).await?;
        for accepted in [false, true] {
            let record = create(&first, &owner, if accepted { "Provider accepted" } else { "Start ACK lost" }).await?;
            let (attempt, permit) = started(&first, &owner, &record).await?;
            let oauth = SyntheticOAuthProvider::default();
            if accepted {
                // The fake provider consumed the old token; lose the returned
                // replacement before any result reaches durable staging.
                drop(oauth.exchange(&permit)?);
            }
            // Losing the successful start result before sending and crashing
            // after provider acceptance are indistinguishable in durable state.
            drop(permit);
            sqlx::query("UPDATE platform_credential_refresh_attempts SET reserved_until=clock_timestamp()-interval '1 hour' WHERE credential_id=$1")
                .bind(record.metadata.id.as_str()).execute(&db.pool).await?;
            ensure!(second.oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt).await? == State::Started);
            ensure!(matches!(second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4()).await, Err(Error::RefreshInProgress)));
            ensure!(second.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::RefreshOutcomeUnknown));
            second.mark_oauth_refresh_unknown(&owner, &record.metadata.id, record.version, attempt).await?;
            first.mark_oauth_refresh_unknown(&owner, &record.metadata.id, record.version, attempt).await?;
            ensure!(oauth.requests.load(Ordering::SeqCst) == usize::from(accepted));
            ensure!(second.oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt).await? == State::Unknown);
            let failed = second.record(&owner, &record.metadata.id).await?;
            ensure!(failed.metadata.status == CredentialStatus::RefreshFailed);
            ensure!(failed.version.revocation_generation == record.version.revocation_generation + 1);
            ensure!(failed.version.material_generation == record.version.material_generation);
            ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
            ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 0));
            ensure!(matches!(first.read_for_broker(&owner, &record.metadata.id, failed.version).await, Err(Error::Inactive)));
            ensure!(first.publish_oauth_refresh(&owner, &record.metadata.id, failed.version, &value(NEW_VALUE)).await == Err(Error::Inactive));
            let replaced = first.replace(&owner, &record.metadata.id, failed.version, &value(NEW_VALUE), record.metadata.expires_at_unix).await?;
            ensure!(replaced.metadata.status == CredentialStatus::Active);
            ensure!(counts(&db.pool, &record.metadata.id).await? == (0, 0));
            ensure!(second.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
        }
        second_pool.close().await;
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn staged_result_and_lost_promotion_ack_recover_on_an_independent_replica() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("stage-recovery").await?;
        let provider = Arc::new(SyntheticKek::default());
        let (first_pool, first) = replica(&db, provider.clone()).await?;
        let record = create(&first, &owner, "Durable result").await?;
        let (attempt, permit) = started(&first, &owner, &record).await?;
        let encrypted = permit.prepare_result(&value(NEW_VALUE))?;
        first.stage_oauth_refresh(&encrypted).await?;
        drop(encrypted);
        drop(permit);
        drop(first);
        first_pool.close().await;
        let (second_pool, second) = replica(&db, provider.clone()).await?;
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        ensure!(
            second
                .oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt)
                .await?
                == State::Staged
        );
        let _lost_ack = second
            .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
            .await?;
        let third = db.store(provider.clone());
        ensure!(
            third
                .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?
                == promoted(record.version)
        );
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated);
        ensure!(
            third
                .cancel_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await
                .is_err()
        );
        // Receipt success after hard expiry still grants no use authority.
        expire(&db.pool, &record.metadata.id).await?;
        ensure!(
            third
                .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?
                == promoted(record.version)
        );
        ensure!(matches!(
            third
                .read_for_broker(&owner, &record.metadata.id, promoted(record.version))
                .await,
            Err(Error::Expired)
        ));
        let current = third.record(&owner, &record.metadata.id).await?;
        let replacement = third
            .replace(
                &owner,
                &record.metadata.id,
                current.version,
                &value(OLD_VALUE),
                None,
            )
            .await?;
        ensure!(
            third
                .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await
                == Err(Error::StaleRefresh)
        );
        ensure!(third.record(&owner, &record.metadata.id).await? == replacement);
        second_pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn stage_failure_is_atomic_and_only_identical_result_retries_are_accepted() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("stage-failure").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let record = create(&store, &owner, "Stage failure").await?;
        let (attempt, permit) = started(&store, &owner, &record).await?;
        let result = permit.prepare_result(&value(NEW_VALUE))?;
        sqlx::raw_sql("CREATE FUNCTION reject_refresh_stage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic refresh stage failure never public'; END $$; \
            CREATE TRIGGER reject_refresh_stage BEFORE UPDATE ON platform_credential_refresh_material FOR EACH ROW EXECUTE FUNCTION reject_refresh_stage()")
            .execute(&db.pool).await?;
        ensure!(store.stage_oauth_refresh(&result).await == Err(Error::DatabaseUnavailable));
        ensure!(store.oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt).await? == State::Started);
        ensure!(store.read_for_broker(&owner, &record.metadata.id, record.version).await?.expose_secret() == OLD_VALUE);
        sqlx::query("DROP TRIGGER reject_refresh_stage ON platform_credential_refresh_material").execute(&db.pool).await?;
        store.stage_oauth_refresh(&result).await?;
        store.stage_oauth_refresh(&result).await?;
        let conflicting = permit.prepare_result(&value(b"synthetic-conflicting-result"))?;
        ensure!(store.stage_oauth_refresh(&conflicting).await == Err(Error::StaleRefresh));
        ensure!(store.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
        ensure!(store.mark_oauth_refresh_unknown(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
        store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
        ensure!(store.read_for_broker(&owner, &record.metadata.id, promoted(record.version)).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn publication_failure_retains_the_old_value_and_the_durable_staged_result() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("publication-failure").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let record = create(&store, &owner, "Publication failure").await?;
        let original = envelope_bytes(&db.pool, record.metadata.id.as_str()).await?;
        let (attempt, permit) = started(&store, &owner, &record).await?;
        store.stage_oauth_refresh(&permit.prepare_result(&value(NEW_VALUE))?).await?;
        sqlx::raw_sql("CREATE FUNCTION reject_refresh_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic refresh publication failure never public'; END $$; \
            CREATE TRIGGER reject_refresh_publication BEFORE INSERT ON platform_credential_material FOR EACH ROW EXECUTE FUNCTION reject_refresh_publication()")
            .execute(&db.pool).await?;
        ensure!(store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::DatabaseUnavailable));
        ensure!(store.record(&owner, &record.metadata.id).await? == record);
        ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == original);
        ensure!(store.oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt).await? == State::Staged);
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
        sqlx::query("DROP TRIGGER reject_refresh_publication ON platform_credential_material").execute(&db.pool).await?;
        store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
        ensure!(store.read_for_broker(&owner, &record.metadata.id, promoted(record.version)).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn live_attempts_fence_replacement_but_revoke_and_delete_win_in_every_phase() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("mutation-fences").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let unrelated = create(&store, &owner, "Unrelated").await?;
        for phase in [State::Reserved, State::Started, State::Staged] {
            let record = create(&store, &owner, &format!("Phase {phase:?}")).await?;
            let attempt = Uuid::new_v4();
            let reserved = store
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?;
            let staged = if phase == State::Reserved {
                drop(reserved);
                None
            } else {
                let permit = store.start_oauth_refresh(reserved).await?;
                let result = permit.prepare_result(&value(NEW_VALUE))?;
                if phase == State::Staged {
                    store.stage_oauth_refresh(&result).await?;
                }
                Some(result)
            };
            ensure!(
                store
                    .replace(
                        &owner,
                        &record.metadata.id,
                        record.version,
                        &value(NEW_VALUE),
                        None
                    )
                    .await
                    == Err(Error::RefreshInProgress)
            );
            ensure!(
                store
                    .publish_oauth_refresh(
                        &owner,
                        &record.metadata.id,
                        record.version,
                        &value(NEW_VALUE)
                    )
                    .await
                    == Err(Error::RefreshInProgress)
            );
            ensure!(
                store
                    .oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt)
                    .await?
                    == phase
            );
            let revoked = store
                .revoke(&owner, &record.metadata.id, record.version)
                .await?;
            ensure!(counts(&db.pool, &record.metadata.id).await? == (0, 0));
            ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
            if let Some(staged) = staged {
                ensure!(store.stage_oauth_refresh(&staged).await.is_err());
            }
            ensure!(
                store
                    .promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                    .await
                    .is_err()
            );
            store
                .delete_revoked(&owner, &record.metadata.id, revoked.version)
                .await?;
            ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));
        }
        ensure!(
            store
                .read_for_broker(&owner, &unrelated.metadata.id, unrelated.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn hard_expiry_fences_prepare_start_stage_and_promotion_without_extending_deadline()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("hard-expiry").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let preparing = create(&store, &owner, "Preparing").await?;
        provider.generate_gate.arm();
        let task = {
            let store = store.clone();
            let owner = owner.clone();
            let record = preparing.clone();
            tokio::spawn(async move {
                store
                    .begin_oauth_refresh(
                        &owner,
                        &record.metadata.id,
                        record.version,
                        Uuid::new_v4(),
                    )
                    .await
            })
        };
        provider.generate_gate.wait().await?;
        expire(&db.pool, &preparing.metadata.id).await?;
        provider.generate_gate.release();
        ensure!(matches!(
            tokio::time::timeout(TIMEOUT, task).await??,
            Err(Error::Expired)
        ));
        ensure!(counts(&db.pool, &preparing.metadata.id).await? == (0, 0));
        for phase in [State::Reserved, State::Started, State::Staged] {
            let record = create(&store, &owner, &format!("Expiry {phase:?}")).await?;
            let original = envelope_bytes(&db.pool, record.metadata.id.as_str()).await?;
            let attempt = Uuid::new_v4();
            let reserved = store
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
                .await?;
            if phase == State::Reserved {
                expire(&db.pool, &record.metadata.id).await?;
                ensure!(matches!(
                    store.start_oauth_refresh(reserved).await,
                    Err(Error::Expired)
                ));
            } else {
                let permit = store.start_oauth_refresh(reserved).await?;
                let encrypted = permit.prepare_result(&value(NEW_VALUE))?;
                if phase == State::Staged {
                    store.stage_oauth_refresh(&encrypted).await?;
                }
                expire(&db.pool, &record.metadata.id).await?;
                if phase == State::Started {
                    ensure!(store.stage_oauth_refresh(&encrypted).await == Err(Error::Expired));
                } else {
                    ensure!(
                        store
                            .promote_oauth_refresh(
                                &owner,
                                &record.metadata.id,
                                record.version,
                                attempt
                            )
                            .await
                            == Err(Error::Expired)
                    );
                }
            }
            ensure!(
                store
                    .record(&owner, &record.metadata.id)
                    .await?
                    .metadata
                    .expires_at_unix
                    == Some(0)
            );
            ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == original);
            ensure!(
                store
                    .oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt)
                    .await?
                    == phase
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_deletion_during_wrapped_dek_preparation_prevents_reservation() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.organization("prepare-delete-org").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let record = create(&store, &owner, "Never reserved").await?;
        provider.generate_gate.arm();
        let task = {
            let store = store.clone();
            let owner = owner.clone();
            let record = record.clone();
            tokio::spawn(async move {
                store
                    .begin_oauth_refresh(
                        &owner,
                        &record.metadata.id,
                        record.version,
                        Uuid::new_v4(),
                    )
                    .await
            })
        };
        provider.generate_gate.wait().await?;
        tokio::time::timeout(
            TIMEOUT,
            begin_organization_deletion(&db.pool, &admin_user(), owner.id().as_str()),
        )
        .await??;
        provider.generate_gate.release();
        ensure!(matches!(
            tokio::time::timeout(TIMEOUT, task).await??,
            Err(Error::NotFound)
        ));
        ensure!(counts(&db.pool, &record.metadata.id).await? == (0, 0));
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn reservation_owner_lock_precedes_deletion_and_exact_cascades_preserve_other_owners()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        const BARRIER: i32 = 19_220_020;
        let org = db.organization("same-owner-text").await?;
        let user = db.user("same-owner-text").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let record = create(&store, &org, "Organization").await?;
        let unrelated = create(&store, &user, "Personal").await?;
        let (unrelated_attempt, unrelated_permit) = started(&store, &user, &unrelated).await?;
        store.stage_oauth_refresh(&unrelated_permit.prepare_result(&value(NEW_VALUE))?).await?;
        sqlx::raw_sql(&format!("CREATE FUNCTION pause_refresh_reservation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({BARRIER}::bigint); RETURN NEW; END $$; \
            CREATE TRIGGER pause_refresh_reservation BEFORE INSERT ON platform_credential_refresh_attempts FOR EACH ROW EXECUTE FUNCTION pause_refresh_reservation()"))
            .execute(&db.pool).await?;
        let mut blocker = db.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)").bind(i64::from(BARRIER)).execute(&mut *blocker).await?;
        let reservation = {
            let store = store.clone(); let org = org.clone(); let record = record.clone();
            tokio::spawn(async move { store.begin_oauth_refresh(&org, &record.metadata.id, record.version, Uuid::new_v4()).await })
        };
        wait_for_advisory_waiter(&db.pool, BARRIER).await?;
        let mut deletion = {
            let pool = db.pool.clone(); let org = org.clone();
            tokio::spawn(async move { begin_organization_deletion(&pool, &admin_user(), org.id().as_str()).await })
        };
        ensure!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut deletion).await.is_err());
        blocker.commit().await?;
        let prepared = tokio::time::timeout(TIMEOUT, reservation).await???;
        tokio::time::timeout(TIMEOUT, deletion).await???;
        ensure!(matches!(store.start_oauth_refresh(prepared).await, Err(Error::NotFound)));
        sqlx::query("DELETE FROM organizations WHERE id=$1").bind(org.id().as_str()).execute(&db.pool).await?;
        ensure!(counts(&db.pool, &record.metadata.id).await? == (0, 0));
        ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
        ensure!(counts(&db.pool, &unrelated.metadata.id).await? == (1, 1));
        store.promote_oauth_refresh(&user, &unrelated.metadata.id, unrelated.version, unrelated_attempt).await?;
        ensure!(store.read_for_broker(&user, &unrelated.metadata.id, promoted(unrelated.version)).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn refresh_identity_scope_and_private_material_are_not_metadata_reader_capabilities()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("scope-owner").await?;
        let other_kind = db.organization("scope-owner").await?;
        let provider = Arc::new(SyntheticKek::default());
        let store = db.store(provider.clone());
        let record = create(&store, &owner, "Private refresh").await?;
        let attempt = Uuid::new_v4();
        ensure!(matches!(
            store
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::nil())
                .await,
            Err(Error::InvalidInput)
        ));
        ensure!(matches!(
            store
                .begin_oauth_refresh(&other_kind, &record.metadata.id, record.version, attempt)
                .await,
            Err(Error::NotFound)
        ));
        let api_key = store
            .create(
                &owner,
                registration("Wrong kind", Kind::ApiKey),
                &value(OLD_VALUE),
            )
            .await?;
        ensure!(matches!(
            store
                .begin_oauth_refresh(&owner, &api_key.metadata.id, api_key.version, attempt)
                .await,
            Err(Error::UnsupportedCredential)
        ));
        let reserved = store
            .begin_oauth_refresh(&owner, &record.metadata.id, record.version, attempt)
            .await?;
        ensure!(format!("{reserved:?}") == "PreparedOAuthRefresh([REDACTED])");
        let permit = store.start_oauth_refresh(reserved).await?;
        let encrypted = permit.prepare_result(&value(NEW_VALUE))?;
        ensure!(format!("{permit:?}") == "StartedOAuthRefresh([REDACTED])");
        ensure!(format!("{encrypted:?}") == "PreparedOAuthRefreshResult([REDACTED])");
        store.stage_oauth_refresh(&encrypted).await?;
        ensure!(
            store
                .oauth_refresh_state(&owner, &record.metadata.id, record.version, Uuid::new_v4())
                .await
                == Err(Error::StaleRefresh)
        );
        ensure!(
            store
                .oauth_refresh_state(
                    &owner,
                    &record.metadata.id,
                    promoted(record.version),
                    attempt
                )
                .await
                == Err(Error::StaleRefresh)
        );
        ensure!(
            store
                .oauth_refresh_state(&other_kind, &record.metadata.id, record.version, attempt)
                .await
                == Err(Error::NotFound)
        );
        let (pool, _) = db.metadata_pool().await?;
        let reader = CredentialMetadataReader::new(pool.clone(), builtin_provider_catalog());
        ensure!(reader.get(&owner, &record.metadata.id).await? == record.metadata);
        let unwraps = provider.unwrap_calls.load(Ordering::SeqCst);
        for table in [
            "platform_credential_refresh_attempts",
            "platform_credential_refresh_material",
        ] {
            let error = sqlx::query(&format!("SELECT * FROM {table}"))
                .execute(&pool)
                .await
                .err()
                .context("metadata role read refresh authority state")?;
            ensure!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref()
                    == Some("42501")
            );
        }
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == unwraps);
        for error in [
            Error::RefreshInProgress,
            Error::StaleRefresh,
            Error::RefreshOutcomeUnknown,
        ] {
            ensure!(error.source().is_none());
            let rendered = format!("{error} {error:?}");
            for forbidden in [b"scope-owner".as_slice(), OLD_VALUE, NEW_VALUE] {
                ensure!(
                    !rendered
                        .as_bytes()
                        .windows(forbidden.len())
                        .any(|part| part == forbidden)
                );
            }
        }
        pool.close().await;
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[derive(Default)]
struct RecoverableKek {
    inner: SyntheticKek,
    unavailable: AtomicBool,
}

#[async_trait::async_trait]
impl KekProvider for RecoverableKek {
    fn kind(&self) -> KekProviderKind {
        self.inner.kind()
    }
    async fn generate(&self, context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError> {
        self.inner.generate(context).await
    }
    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        if self.unavailable.load(Ordering::SeqCst) {
            let mut invalid = wrapped.clone();
            invalid.ciphertext = b"synthetic-temporary-kek-outage-never-public".to_vec();
            return TestKekProvider.unwrap(context, &invalid).await;
        }
        self.inner.unwrap(context, wrapped).await
    }
    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        self.inner.rewrap(context, wrapped).await
    }
    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError> {
        self.inner.authority_id().await
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn staged_integrity_and_kek_recovery_preserve_old_material_and_recheck_final_fences()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("integrity-recovery").await?;
        let provider = Arc::new(RecoverableKek::default());
        let store = db.store(provider.clone());
        let record = create(&store, &owner, "Integrity").await?;
        let old_envelope = envelope_bytes(&db.pool, record.metadata.id.as_str()).await?;
        let (attempt, permit) = started(&store, &owner, &record).await?;
        store.stage_oauth_refresh(&permit.prepare_result(&value(NEW_VALUE))?).await?;
        provider.unavailable.store(true, Ordering::SeqCst);
        ensure!(store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::ProviderUnavailable));
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
        ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == old_envelope);
        provider.unavailable.store(false, Ordering::SeqCst);
        let ciphertext: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM platform_credential_refresh_material WHERE attempt_id=$1").bind(attempt).fetch_one(&db.pool).await?;
        sqlx::query("UPDATE platform_credential_refresh_material SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0) # 1) WHERE attempt_id=$1").bind(attempt).execute(&db.pool).await?;
        ensure!(store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::CorruptRecord));
        ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == old_envelope);
        sqlx::query("UPDATE platform_credential_refresh_material SET ciphertext=$2 WHERE attempt_id=$1").bind(attempt).bind(&ciphertext).execute(&db.pool).await?;
        store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
        ensure!(store.read_for_broker(&owner, &record.metadata.id, promoted(record.version)).await?.expose_secret() == NEW_VALUE);

        for mutation in ["revoke", "expiry", "envelope"] {
            let record = create(&store, &owner, mutation).await?;
            let (attempt, permit) = started(&store, &owner, &record).await?;
            store.stage_oauth_refresh(&permit.prepare_result(&value(NEW_VALUE))?).await?;
            provider.inner.unwrap_gate.arm();
            let task = {
                let store = store.clone(); let owner = owner.clone(); let record = record.clone();
                tokio::spawn(async move { store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await })
            };
            provider.inner.unwrap_gate.wait().await?;
            match mutation {
                "revoke" => { store.revoke(&owner, &record.metadata.id, record.version).await?; }
                "expiry" => expire(&db.pool, &record.metadata.id).await?,
                "envelope" => {
                    sqlx::query("UPDATE platform_credential_refresh_material SET nonce=set_byte(nonce,0,get_byte(nonce,0) # 1) WHERE attempt_id=$1")
                        .bind(attempt).execute(&db.pool).await?;
                }
                _ => unreachable!(),
            }
            provider.inner.unwrap_gate.release();
            let outcome = tokio::time::timeout(TIMEOUT, task).await??;
            match mutation {
                "revoke" => ensure!(outcome.is_err()),
                "expiry" => ensure!(outcome == Err(Error::Expired)),
                "envelope" => ensure!(outcome == Err(Error::CorruptRecord)),
                _ => unreachable!(),
            }
            ensure!(store.record(&owner, &record.metadata.id).await?.version.material_generation == record.version.material_generation);
        }
        Ok(())
    }.await;
    db.finish(result).await
}
