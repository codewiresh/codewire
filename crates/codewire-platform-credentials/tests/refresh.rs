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
    CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS, CredentialAuthKind as Kind, CredentialId,
    CredentialStatus, Owner, builtin_provider_catalog,
};
use codewire_platform_credentials::{
    CredentialMetadataReader, CredentialRecord, CredentialRegistration, CredentialVersion,
    OAuthKeepAliveForm, OAuthRefreshAttemptInfo, OAuthRefreshState as State,
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

fn expiring_oauth(name: &str) -> Result<CredentialRegistration> {
    let mut input = registration(name, Kind::OAuth);
    input.expires_at_unix = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 3_600,
    );
    Ok(input)
}

async fn create(
    store: &PlatformCredentialStore,
    owner: &Owner,
    name: &str,
) -> Result<CredentialRecord> {
    Ok(store
        .create(owner, expiring_oauth(name)?, &value(OLD_VALUE))
        .await?)
}

/// Organizations can no longer register an OAuth login. This stands in for a
/// row written before that rule: registered as an API key, then relabelled.
/// Its material is never read here; only reservation and deletion fences are.
async fn legacy_organization_oauth(
    db: &TestDatabase,
    store: &PlatformCredentialStore,
    organization: &Owner,
    mut input: CredentialRegistration,
) -> Result<CredentialRecord> {
    ensure!(organization.is_organization() && input.authentication_kind == Kind::OAuth);
    input.authentication_kind = Kind::ApiKey;
    let record = store.create(organization, input, &value(OLD_VALUE)).await?;
    sqlx::query("UPDATE platform_credentials SET authentication_kind='oauth' WHERE id=$1")
        .bind(record.metadata.id.as_str())
        .execute(&db.pool)
        .await?;
    Ok(store.record(organization, &record.metadata.id).await?)
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

async fn expire_execution(pool: &PgPool, id: &CredentialId) -> Result<()> {
    // Move only this synthetic attempt's clock coordinates. Preserve the
    // schema's strict started_at < started_until invariant and exact duration.
    sqlx::query("WITH expired AS (SELECT clock_timestamp()-interval '1 second' AS at) \
        UPDATE platform_credential_refresh_attempts SET started_until=expired.at, \
        started_at=expired.at-($2::bigint * interval '1 second') FROM expired WHERE credential_id=$1")
        .bind(id.as_str())
        .bind(i64::try_from(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS)?)
        .execute(pool).await?;
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
        ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.is_none());
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
        ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
            attempt_id: attempt, expected: record.version, state: State::Reserved,
            reservation_live: true, execution_live: false,
        }));
        let permit = second.start_oauth_refresh(prepared).await?;
        ensure!(first.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
            attempt_id: attempt, expected: record.version, state: State::Started,
            reservation_live: false, execution_live: true,
        }));
        let duration: i64 = sqlx::query_scalar("SELECT extract(epoch FROM started_until-started_at)::bigint FROM platform_credential_refresh_attempts WHERE credential_id=$1")
            .bind(record.metadata.id.as_str()).fetch_one(&db.pool).await?;
        ensure!(duration == i64::try_from(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS)?);
        ensure!(duration == 90, "the durable abandonment horizon is part of the shared contract");
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
        ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
            attempt_id: old_id, expected: record.version, state: State::Reserved,
            reservation_live: false, execution_live: false,
        }));
        let new_id = Uuid::new_v4();
        let new = second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        ensure!(matches!(first.start_oauth_refresh(old).await, Err(Error::StaleRefresh)));
        ensure!(first.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, old_id).await == Err(Error::StaleRefresh));
        second.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        first.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, new_id).await?;
        ensure!(first.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
            attempt_id: new_id, expected: record.version, state: State::Cancelled,
            reservation_live: false, execution_live: false,
        }));
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
        for outcome in ["Start ACK lost", "Provider accepted", "Owner reports failure", "Failure SQL rollback"] {
            let record = create(&first, &owner, outcome).await?;
            let original = envelope_bytes(&db.pool, record.metadata.id.as_str()).await?;
            let (attempt, permit) = started(&first, &owner, &record).await?;
            let oauth = SyntheticOAuthProvider::default();
            let accepted = outcome != "Start ACK lost";
            if accepted {
                // The fake provider consumed the old token; lose the returned
                // replacement before any result reaches durable staging.
                drop(oauth.exchange(&permit)?);
            }
            sqlx::query("UPDATE platform_credential_refresh_attempts SET reserved_until=clock_timestamp()-interval '1 hour' WHERE credential_id=$1")
                .bind(record.metadata.id.as_str()).execute(&db.pool).await?;
            let discovered = second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.context("replica failed to discover started attempt")?;
            ensure!(discovered.attempt_id == attempt && discovered.expected == record.version);
            ensure!(discovered.state == State::Started && discovered.execution_live && !discovered.reservation_live);
            ensure!(matches!(second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4()).await, Err(Error::RefreshInProgress)));
            ensure!(second.cancel_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::RefreshOutcomeUnknown));
            ensure!(second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, discovered.expected, discovered.attempt_id).await == Err(Error::RefreshInProgress));
            ensure!(first.record(&owner, &record.metadata.id).await? == record);
            ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == original);

            match outcome {
                "Owner reports failure" => first.fail_oauth_refresh(permit).await?,
                "Failure SQL rollback" => {
                    sqlx::raw_sql("CREATE FUNCTION reject_refresh_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='refresh_failed' THEN RAISE EXCEPTION 'synthetic refresh failure never public'; END IF; RETURN NEW; END $$; \
                        CREATE TRIGGER reject_refresh_failure BEFORE UPDATE ON platform_credentials FOR EACH ROW EXECUTE FUNCTION reject_refresh_failure()")
                        .execute(&db.pool).await?;
                    ensure!(first.fail_oauth_refresh(permit).await == Err(Error::DatabaseUnavailable));
                    ensure!(first.record(&owner, &record.metadata.id).await? == record);
                    ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
                    ensure!(envelope_bytes(&db.pool, record.metadata.id.as_str()).await? == original);
                    ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(discovered));
                    ensure!(second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, discovered.expected, discovered.attempt_id).await == Err(Error::RefreshInProgress));
                    sqlx::query("DROP TRIGGER reject_refresh_failure ON platform_credentials").execute(&db.pool).await?;
                    expire_execution(&db.pool, &record.metadata.id).await?;
                }
                _ => {
                    // Lost start ACK and lost provider result leave no send
                    // permit on a new replica. A reserved timeout is not enough.
                    drop(permit);
                    expire_execution(&db.pool, &record.metadata.id).await?;
                }
            }
            second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, discovered.expected, discovered.attempt_id).await?;
            first.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, discovered.expected, discovered.attempt_id).await?;
            ensure!(oauth.requests.load(Ordering::SeqCst) == usize::from(accepted));
            ensure!(second.oauth_refresh_state(&owner, &record.metadata.id, record.version, attempt).await? == State::Unknown);
            ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
                state: State::Unknown, execution_live: false, ..discovered
            }));
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
            ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.is_none());
            ensure!(second.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
        }

        // An alive sender cannot stage late. The execution horizon does not
        // detect process death; another replica can safely close only the
        // unknown result, never claim another provider-send permit.
        let record = create(&first, &owner, "Alive beyond deadline").await?;
        let (attempt, permit) = started(&first, &owner, &record).await?;
        let encrypted = permit.prepare_result(&value(NEW_VALUE))?;
        expire_execution(&db.pool, &record.metadata.id).await?;
        ensure!(first.stage_oauth_refresh(&encrypted).await == Err(Error::StaleRefresh));
        ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await? == Some(OAuthRefreshAttemptInfo {
            attempt_id: attempt, expected: record.version, state: State::Started,
            reservation_live: false, execution_live: false,
        }));
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
        ensure!(first.read_for_broker(&owner, &record.metadata.id, record.version).await?.expose_secret() == OLD_VALUE);
        ensure!(matches!(second.begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4()).await, Err(Error::RefreshInProgress)));
        // Hard expiry must not prevent terminal fail-closed cleanup either.
        expire(&db.pool, &record.metadata.id).await?;
        second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
        first.fail_oauth_refresh(permit).await?;
        ensure!(first.stage_oauth_refresh(&encrypted).await.is_err());
        ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 0));
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
        expire_execution(&db.pool, &record.metadata.id).await?;
        // A durable stage is a recovery asset, not a timed-out reservation.
        first.stage_oauth_refresh(&encrypted).await?;
        drop(encrypted);
        drop(permit);
        drop(first);
        first_pool.close().await;
        let (second_pool, second) = replica(&db, provider.clone()).await?;
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        let unwraps = provider.unwrap_calls.load(Ordering::SeqCst);
        // Recovery supplies only trusted owner + credential identity. The
        // failed replica's process-local UUID/version are not required inputs.
        let recovered = second
            .current_oauth_refresh_attempt(&owner, &record.metadata.id)
            .await?
            .context("missing durable stage")?;
        ensure!(
            recovered
                == OAuthRefreshAttemptInfo {
                    attempt_id: attempt,
                    expected: record.version,
                    state: State::Staged,
                    reservation_live: false,
                    execution_live: false,
                }
        );
        ensure!(provider.unwrap_calls.load(Ordering::SeqCst) == unwraps);
        ensure!(
            second
                .fail_abandoned_oauth_refresh(
                    &owner,
                    &record.metadata.id,
                    recovered.expected,
                    recovered.attempt_id
                )
                .await
                == Err(Error::StaleRefresh)
        );
        ensure!(matches!(
            second
                .begin_oauth_refresh(&owner, &record.metadata.id, record.version, Uuid::new_v4())
                .await,
            Err(Error::RefreshInProgress)
        ));
        // Reservation preparation intentionally happens before DB locks; the
        // denied new attempt therefore prepares one DEK but publishes nothing.
        ensure!(provider.generate_calls.load(Ordering::SeqCst) == generated + 1);
        let generated = provider.generate_calls.load(Ordering::SeqCst);
        let _lost_ack = second
            .promote_oauth_refresh(
                &owner,
                &record.metadata.id,
                recovered.expected,
                recovered.attempt_id,
            )
            .await?;
        let third = db.store(provider.clone());
        let receipt = third
            .current_oauth_refresh_attempt(&owner, &record.metadata.id)
            .await?
            .context("missing publication receipt")?;
        ensure!(
            receipt
                == OAuthRefreshAttemptInfo {
                    state: State::Committed,
                    ..recovered
                }
        );
        ensure!(
            third
                .promote_oauth_refresh(
                    &owner,
                    &record.metadata.id,
                    receipt.expected,
                    receipt.attempt_id
                )
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
        ensure!(store.fail_oauth_refresh(permit).await == Err(Error::StaleRefresh));
        expire_execution(&db.pool, &record.metadata.id).await?;
        ensure!(store.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
        store.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
        ensure!(store.read_for_broker(&owner, &record.metadata.id, promoted(record.version)).await?.expose_secret() == NEW_VALUE);
        Ok(())
    }.await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn stage_and_abandonment_serialize_and_execution_deadline_is_rechecked_after_sql_wait()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        const BARRIER: i32 = 19_220_021;
        let owner = db.user("stage-abandonment-fence").await?;
        let provider = Arc::new(SyntheticKek::default());
        let first = db.store(provider.clone());
        let (second_pool, second) = replica(&db, provider).await?;
        sqlx::raw_sql(&format!("CREATE FUNCTION pause_refresh_staging() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({BARRIER}::bigint); RETURN NEW; END $$; \
            CREATE TRIGGER pause_refresh_staging BEFORE UPDATE ON platform_credential_refresh_material FOR EACH ROW EXECUTE FUNCTION pause_refresh_staging()"))
            .execute(&db.pool).await?;

        for deadline_passes in [false, true] {
            let record = create(&first, &owner, if deadline_passes { "Expired during staging" } else { "Durable stage wins" }).await?;
            let (attempt, permit) = started(&first, &owner, &record).await?;
            let oauth = SyntheticOAuthProvider::default();
            let encrypted = permit.prepare_result(&oauth.exchange(&permit)?)?;
            if deadline_passes {
                // Keep the exact 90-second durable interval, but advance only
                // this fixture's start to leave one second for the SQL gate.
                sqlx::query("WITH shortened AS (SELECT clock_timestamp()+interval '1 second' AS at) \
                    UPDATE platform_credential_refresh_attempts SET started_until=shortened.at, \
                    started_at=shortened.at-($2::bigint * interval '1 second') FROM shortened WHERE credential_id=$1")
                    .bind(record.metadata.id.as_str())
                    .bind(i64::try_from(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS)?)
                    .execute(&db.pool).await?;
            }
            let mut blocker = db.pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)")
                .bind(i64::from(BARRIER)).execute(&mut *blocker).await?;
            let staging = {
                let first = first.clone();
                tokio::spawn(async move { first.stage_oauth_refresh(&encrypted).await })
            };
            wait_for_advisory_waiter(&db.pool, BARRIER).await?;
            let mut abandonment = {
                let second = second.clone(); let owner = owner.clone(); let record = record.clone();
                tokio::spawn(async move { second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await })
            };
            ensure!(tokio::time::timeout(std::time::Duration::from_millis(50), &mut abandonment).await.is_err(), "abandonment bypassed the credential fence");
            if deadline_passes {
                tokio::time::timeout(HANG_GUARD, async {
                    loop {
                        let expired: bool = sqlx::query_scalar("SELECT started_until<=clock_timestamp() FROM platform_credential_refresh_attempts WHERE credential_id=$1")
                            .bind(record.metadata.id.as_str()).fetch_one(&db.pool).await?;
                        if expired {
                            break Ok::<_, anyhow::Error>(());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await??;
            }
            blocker.commit().await?;
            let staged = tokio::time::timeout(HANG_GUARD, staging).await??;
            let abandoned = tokio::time::timeout(HANG_GUARD, abandonment).await??;
            ensure!(oauth.requests.load(Ordering::SeqCst) == 1);
            if deadline_passes {
                ensure!(staged == Err(Error::StaleRefresh));
                ensure!(abandoned == Ok(()));
                ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 0));
                ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
                ensure!(second.current_oauth_refresh_attempt(&owner, &record.metadata.id).await?.context("missing failed attempt")?.state == State::Unknown);
                first.fail_oauth_refresh(permit).await?;
            } else {
                ensure!(staged == Ok(()));
                ensure!(abandoned == Err(Error::StaleRefresh));
                ensure!(counts(&db.pool, &record.metadata.id).await? == (1, 1));
                ensure!(first.fail_oauth_refresh(permit).await == Err(Error::StaleRefresh));
                expire_execution(&db.pool, &record.metadata.id).await?;
                ensure!(second.fail_abandoned_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await == Err(Error::StaleRefresh));
                second.promote_oauth_refresh(&owner, &record.metadata.id, record.version, attempt).await?;
                ensure!(second.read_for_broker(&owner, &record.metadata.id, promoted(record.version)).await?.expose_secret() == NEW_VALUE);
            }
        }
        second_pool.close().await;
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
            ensure!(
                store
                    .current_oauth_refresh_attempt(&owner, &record.metadata.id)
                    .await?
                    .is_none()
            );
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
            tokio::time::timeout(HANG_GUARD, task).await??,
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
        let record = create(&store, &owner, "Expired send owner").await?;
        let (_, permit) = started(&store, &owner, &record).await?;
        expire(&db.pool, &record.metadata.id).await?;
        store.fail_oauth_refresh(permit).await?;
        let failed = store.record(&owner, &record.metadata.id).await?;
        ensure!(failed.metadata.status == CredentialStatus::RefreshFailed);
        ensure!(failed.metadata.expires_at_unix == Some(0));
        ensure!(material_count(&db.pool, record.metadata.id.as_str()).await? == 0);
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
        let record =
            legacy_organization_oauth(&db, &store, &owner, expiring_oauth("Never reserved")?)
                .await?;
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
            HANG_GUARD,
            begin_organization_deletion(&db.pool, &admin_user(), owner.id().as_str()),
        )
        .await??;
        provider.generate_gate.release();
        ensure!(matches!(
            tokio::time::timeout(HANG_GUARD, task).await??,
            Err(Error::NotFound)
        ));
        ensure!(counts(&db.pool, &record.metadata.id).await? == (0, 0));
        ensure!(store.record(&owner, &record.metadata.id).await == Err(Error::NotFound));
        ensure!(
            store
                .current_oauth_refresh_attempt(&owner, &record.metadata.id)
                .await
                == Err(Error::NotFound)
        );
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
        let record =
            legacy_organization_oauth(&db, &store, &org, expiring_oauth("Organization")?).await?;
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
        let prepared = tokio::time::timeout(HANG_GUARD, reservation).await???;
        tokio::time::timeout(HANG_GUARD, deletion).await???;
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
        ensure!(
            store
                .current_oauth_refresh_attempt(&owner, &record.metadata.id)
                .await?
                .is_none()
        );
        ensure!(
            store
                .current_oauth_refresh_attempt(&other_kind, &record.metadata.id)
                .await
                == Err(Error::NotFound)
        );
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
        ensure!(
            store
                .fail_abandoned_oauth_refresh(
                    &owner,
                    &record.metadata.id,
                    record.version,
                    Uuid::new_v4()
                )
                .await
                == Err(Error::StaleRefresh)
        );
        ensure!(
            store
                .fail_abandoned_oauth_refresh(
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
                .fail_abandoned_oauth_refresh(
                    &other_kind,
                    &record.metadata.id,
                    record.version,
                    attempt
                )
                .await
                == Err(Error::NotFound)
        );
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
        let discovery = store
            .current_oauth_refresh_attempt(&owner, &record.metadata.id)
            .await?
            .context("missing metadata-only discovery")?;
        ensure!(discovery.state == State::Staged);
        let restricted_store = PlatformCredentialStore::new(
            pool.clone(),
            provider.clone(),
            builtin_provider_catalog(),
        );
        ensure!(
            restricted_store
                .current_oauth_refresh_attempt(&owner, &record.metadata.id)
                .await
                == Err(Error::DatabaseUnavailable)
        );
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
            let outcome = tokio::time::timeout(HANG_GUARD, task).await??;
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

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn keepalive_candidates_are_idle_active_oauth_without_an_owned_attempt() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        // The restricted broker login proves the existing grants suffice.
        let (pool, _) = db.broker_pool().await?;
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            Arc::new(SyntheticKek::default()),
            builtin_provider_catalog(),
        ));
        let user = db.user("keepalive-user").await?;
        let org = db.organization("keepalive-org").await?;
        let deleting = db.organization("keepalive-deleting").await?;
        let oauth = |name: &str| {
            let mut input = registration(name, Kind::OAuth);
            input.expires_at_unix = None;
            input
        };
        let new = |owner: Owner, input: codewire_platform_credentials::CredentialRegistration| {
            let store = store.clone();
            async move { store.create(&owner, input, &value(OLD_VALUE)).await }
        };
        let age = |id: CredentialId| {
            let pool = db.pool.clone();
            async move {
                sqlx::query(
                    "UPDATE platform_credentials SET created_at=now()-interval '10 days' WHERE id=$1",
                )
                .bind(id.as_str())
                .execute(&pool)
                .await
            }
        };
        let mut expected = Vec::new();
        let mut aged = |record: CredentialRecord, selected: bool| {
            if selected {
                expected.push(record.metadata.id.clone());
            }
            record
        };

        let idle = aged(new(user.clone(), oauth("Idle")).await?, true);
        age(idle.metadata.id.clone()).await?;
        // Fresh material is never a candidate.
        let fresh = aged(new(user.clone(), oauth("Fresh")).await?, false);
        let key = aged(new(user.clone(), registration("Key", Kind::ApiKey)).await?, false);
        age(key.metadata.id.clone()).await?;
        let failed = aged(new(user.clone(), oauth("Failed")).await?, false);
        age(failed.metadata.id.clone()).await?;
        sqlx::query("UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1")
            .bind(failed.metadata.id.as_str())
            .execute(&db.pool)
            .await?;
        let revoked = aged(new(user.clone(), oauth("Revoked")).await?, false);
        age(revoked.metadata.id.clone()).await?;
        store
            .revoke(&user, &revoked.metadata.id, revoked.version)
            .await?;
        let expired = aged(new(user.clone(), oauth("Expired")).await?, false);
        age(expired.metadata.id.clone()).await?;
        sqlx::query("UPDATE platform_credentials SET expires_at_unix=1 WHERE id=$1")
            .bind(expired.metadata.id.as_str())
            .execute(&db.pool)
            .await?;
        // A live reservation, a started and a staged attempt belong to their
        // owner or to recovery. An expired, never-started reservation does not.
        let reserved = aged(new(user.clone(), oauth("Reserved")).await?, false);
        age(reserved.metadata.id.clone()).await?;
        store
            .begin_oauth_refresh(&user, &reserved.metadata.id, reserved.version, Uuid::new_v4())
            .await?;
        let abandoned = aged(new(user.clone(), oauth("Abandoned")).await?, true);
        age(abandoned.metadata.id.clone()).await?;
        store
            .begin_oauth_refresh(&user, &abandoned.metadata.id, abandoned.version, Uuid::new_v4())
            .await?;
        sqlx::query(
            "UPDATE platform_credential_refresh_attempts \
             SET reserved_until=clock_timestamp()-interval '1 second' WHERE credential_id=$1",
        )
        .bind(abandoned.metadata.id.as_str())
        .execute(&db.pool)
        .await?;
        let running = aged(new(user.clone(), oauth("Running")).await?, false);
        age(running.metadata.id.clone()).await?;
        let (_, _running_permit) = started(&store, &user, &running).await?;
        let staged = aged(new(user.clone(), oauth("Staged")).await?, false);
        age(staged.metadata.id.clone()).await?;
        let (_, staged_permit) = started(&store, &user, &staged).await?;
        store
            .stage_oauth_refresh(&staged_permit.prepare_result(&value(NEW_VALUE))?)
            .await?;
        // A commit receipt for the current generation dates the material even
        // though the record itself was created long ago.
        let rotated = aged(new(user.clone(), oauth("Rotated")).await?, false);
        age(rotated.metadata.id.clone()).await?;
        let (rotated_attempt, rotated_permit) = started(&store, &user, &rotated).await?;
        store
            .stage_oauth_refresh(&rotated_permit.prepare_result(&value(NEW_VALUE))?)
            .await?;
        store
            .promote_oauth_refresh(&user, &rotated.metadata.id, rotated.version, rotated_attempt)
            .await?;
        // A legacy organization OAuth row counts only while its organization
        // is live.
        let shared = aged(
            legacy_organization_oauth(&db, &store, &org, oauth("Shared")).await?,
            true,
        );
        age(shared.metadata.id.clone()).await?;
        let orphaned = aged(
            legacy_organization_oauth(&db, &store, &deleting, oauth("Orphaned")).await?,
            false,
        );
        age(orphaned.metadata.id.clone()).await?;
        begin_organization_deletion(&db.pool, &admin_user(), deleting.id().as_str()).await?;
        let _ = fresh;
        // An aged Claude subscription token (Anthropic's OAuth kind) and an
        // aged Claude sign-in: each form selects exactly its own kind.
        let anthropic = |name: &str, kind: Kind| {
            let mut input = registration(name, kind);
            input.provider = codewire_access::ProviderId::parse("anthropic").unwrap();
            input.account_hint = None;
            input
        };
        let setup_token = new(user.clone(), anthropic("Setup token", Kind::OAuth)).await?;
        age(setup_token.metadata.id.clone()).await?;
        let sign_in = new(user.clone(), anthropic("Sign-in", Kind::ClaudeSignIn)).await?;
        age(sign_in.metadata.id.clone()).await?;

        let form = |provider: &str, kind: Kind, age: u64| OAuthKeepAliveForm {
            provider: codewire_access::ProviderId::parse(provider).unwrap(),
            authentication_kind: kind,
            min_age_seconds: age,
        };
        let providers = [form("openai", Kind::OAuth, 7 * 86_400)];
        let page = |after: Option<CredentialId>, limit: u32| {
            let store = store.clone();
            let providers = providers.clone();
            async move {
                store
                    .oauth_keepalive_candidates(&providers, after.as_ref(), limit)
                    .await
            }
        };
        expected.sort();
        let all = page(None, 100).await?;
        let ids: Vec<_> = all.iter().map(|candidate| candidate.id.clone()).collect();
        ensure!(ids == expected, "selected {ids:?}, expected {expected:?}");
        let first = all.first().context("candidate")?;
        ensure!(
            first.provider.as_str() == "openai"
                && first.authentication_kind == Kind::OAuth
                && first.version.material_generation == 1
        );
        // ID-ordered pages resume after the cursor without repeating a row.
        let mut paged = Vec::new();
        let mut after = None;
        loop {
            let next = page(after.clone(), 1).await?;
            let Some(candidate) = next.first() else { break };
            paged.push(candidate.id.clone());
            after = Some(candidate.id.clone());
        }
        ensure!(paged == expected);
        // The age is per form: nothing here is 11 days old.
        let older = [form("openai", Kind::OAuth, 11 * 86_400)];
        ensure!(store.oauth_keepalive_candidates(&older, None, 100).await?.is_empty());
        // Once the receipt itself is old, the rotated credential is due.
        sqlx::query(
            "UPDATE platform_credential_refresh_attempts \
             SET created_at=now()-interval '8 days' WHERE credential_id=$1",
        )
        .bind(rotated.metadata.id.as_str())
        .execute(&db.pool)
        .await?;
        let all = page(None, 100).await?;
        let rotated_candidate = all
            .iter()
            .find(|candidate| candidate.id == rotated.metadata.id)
            .context("aged commit receipt was not selected")?;
        ensure!(rotated_candidate.version == promoted(rotated.version));
        // A provider outside the list is never selected.
        let other = [form("github", Kind::OAuth, 0)];
        ensure!(store.oauth_keepalive_candidates(&other, None, 100).await?.is_empty());
        // The Anthropic sign-in form selects the sign-in and never the
        // subscription token, which has no refresh; naming Anthropic's OAuth
        // kind would select only the token.
        let claude = [form("anthropic", Kind::ClaudeSignIn, 7 * 86_400)];
        let selected = store.oauth_keepalive_candidates(&claude, None, 100).await?;
        ensure!(
            selected.len() == 1
                && selected[0].id == sign_in.metadata.id
                && selected[0].authentication_kind == Kind::ClaudeSignIn
        );
        let tokens = [form("anthropic", Kind::OAuth, 7 * 86_400)];
        let selected = store.oauth_keepalive_candidates(&tokens, None, 100).await?;
        ensure!(selected.len() == 1 && selected[0].id == setup_token.metadata.id);
        for (providers, limit) in [
            (Vec::new(), 10),
            (providers.to_vec(), 0),
            (providers.to_vec(), 1001),
            ([providers[0].clone(), providers[0].clone()].to_vec(), 10),
            ([form("openai", Kind::ApiKey, 60)].to_vec(), 10),
        ] {
            ensure!(matches!(
                store.oauth_keepalive_candidates(&providers, None, limit).await,
                Err(Error::InvalidInput)
            ));
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
