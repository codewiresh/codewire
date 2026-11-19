//! A refresh the provider rate-limited (#4975; docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "A refresh the provider rate-limited"), against synthetic PostgreSQL with
//! two replicas. Explicit --ignored execution requires TEST_DATABASE_URL.

use std::sync::Arc;

use anyhow::{Result, ensure};
use codewire_access::{CredentialAuthKind as Kind, CredentialStatus, Owner};
use codewire_platform_credentials::{
    CredentialRecord, OAuthKeepAliveForm, OAuthRefreshState as State,
    PlatformCredentialError as Error, PlatformCredentialStore, RevocationFence,
    StartedOAuthRefresh,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::support::*;

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
) -> Result<StartedOAuthRefresh, Error> {
    let prepared = store
        .begin_oauth_refresh(owner, &record.metadata.id, record.version, Uuid::new_v4())
        .await?;
    store.start_oauth_refresh(prepared).await
}

/// End the credential's rate-limit wait now, on the database clock.
async fn end_wait(pool: &PgPool, record: &CredentialRecord) -> Result<()> {
    sqlx::query(
        "UPDATE platform_credential_refresh_attempts \
         SET started_at=clock_timestamp()-interval '2 seconds', \
         rate_limited_until=clock_timestamp()-interval '1 second' WHERE credential_id=$1",
    )
    .bind(record.metadata.id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

fn due() -> Result<[OAuthKeepAliveForm; 1]> {
    Ok([OAuthKeepAliveForm {
        provider: codewire_access::ProviderId::parse("openai")?,
        authentication_kind: Kind::OAuth,
        min_age_seconds: 0,
    }])
}

/// One wait, then one retry whose failure is terminal: the wait is the
/// credential's, so a second replica keeps it, and the attempt after it
/// cannot be rate-limited again.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_rate_limited_refresh_waits_once_and_its_retry_cannot_wait_again() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rate-limited").await?;
        let first = db.store(Arc::new(SyntheticKek::default()));
        let second = db.store(Arc::new(SyntheticKek::default()));
        let record = create(&first, &owner, "Rate limited").await?;
        let id = &record.metadata.id;

        let permit = started(&first, &owner, &record).await?;
        first.rate_limit_oauth_refresh(&permit, 120).await?;
        drop(permit);
        let attempt = second.current_oauth_refresh_attempt(&owner, id).await?;
        ensure!(attempt.map(|attempt| attempt.state) == Some(State::RateLimited));
        // The sign-in is kept as it was, material included.
        let kept = second.record(&owner, id).await?;
        ensure!(kept.version == record.version && kept.metadata.status == CredentialStatus::Active);
        ensure!(
            second
                .read_for_broker(&owner, id, record.version)
                .await?
                .expose_secret()
                == OLD_VALUE
        );
        ensure!(material_count(&db.pool, id.as_str()).await? == 1);

        // No replica begins a refresh, nor selects it for keep-alive, while
        // the wait runs.
        match second
            .begin_oauth_refresh(&owner, id, record.version, Uuid::new_v4())
            .await
        {
            Err(Error::RefreshRateLimited {
                retry_after_seconds,
            }) => {
                ensure!(
                    (118..=120).contains(&retry_after_seconds),
                    "{retry_after_seconds} s left"
                );
            }
            other => anyhow::bail!("begin during the wait: {other:?}"),
        }
        ensure!(
            second
                .oauth_keepalive_candidates(&due()?, None, 10)
                .await?
                .is_empty()
        );

        end_wait(&db.pool, &record).await?;
        ensure!(
            second
                .oauth_keepalive_candidates(&due()?, None, 10)
                .await?
                .len()
                == 1
        );
        let retry = started(&second, &owner, &record).await?;
        ensure!(second.rate_limit_oauth_refresh(&retry, 120).await == Err(Error::StaleRefresh));
        ensure!(first.rate_limit_oauth_refresh(&retry, 120).await == Err(Error::StaleRefresh));
        second.fail_oauth_refresh(retry).await?;
        let failed = first.record(&owner, id).await?;
        ensure!(failed.metadata.status == CredentialStatus::RefreshFailed);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The wait is bounded whatever the provider asked, and only the exact
/// started attempt can be rate-limited, once.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn only_a_started_attempt_is_rate_limited_within_its_bounds() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rate-limit-bounds").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let record = create(&store, &owner, "Rate limited").await?;
        let id = &record.metadata.id;

        let permit = started(&store, &owner, &record).await?;
        for seconds in [0, 59, 601, u64::MAX] {
            ensure!(
                store.rate_limit_oauth_refresh(&permit, seconds).await == Err(Error::InvalidInput),
                "{seconds} s"
            );
        }
        store.rate_limit_oauth_refresh(&permit, 60).await?;
        // A second answer for the same attempt changes nothing.
        ensure!(store.rate_limit_oauth_refresh(&permit, 60).await == Err(Error::StaleRefresh));
        // Nor can the permit then fail the sign-in.
        ensure!(store.fail_oauth_refresh(permit).await == Err(Error::StaleRefresh));
        ensure!(store.record(&owner, id).await?.metadata.status == CredentialStatus::Active);
        ensure!(
            store
                .current_oauth_refresh_attempt(&owner, id)
                .await?
                .map(|attempt| attempt.state)
                == Some(State::RateLimited)
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The retry's mark survives every way the retry can end before it starts:
/// cancelled, its reservation lapsed, or a revocation fence that replaced the
/// waiting attempt and did not commit. Each next attempt is still the retry.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_retry_mark_survives_a_retry_that_never_started() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let owner = db.user("rate-limit-mark").await?;
        let store = db.store(Arc::new(SyntheticKek::default()));
        let cancelled = create(&store, &owner, "Cancelled retry").await?;
        let lapsed = create(&store, &owner, "Lapsed retry").await?;
        let fenced = create(&store, &owner, "Fenced wait").await?;
        for record in [&cancelled, &lapsed, &fenced] {
            let wait = if std::ptr::eq(record, &fenced) {
                600
            } else {
                60
            };
            let permit = started(&store, &owner, record).await?;
            store.rate_limit_oauth_refresh(&permit, wait).await?;
        }

        // The retry is cancelled before it starts.
        end_wait(&db.pool, &cancelled).await?;
        let attempt = Uuid::new_v4();
        let id = &cancelled.metadata.id;
        store
            .begin_oauth_refresh(&owner, id, cancelled.version, attempt)
            .await?;
        store
            .cancel_oauth_refresh(&owner, id, cancelled.version, attempt)
            .await?;
        let permit = started(&store, &owner, &cancelled).await?;
        ensure!(store.rate_limit_oauth_refresh(&permit, 60).await == Err(Error::StaleRefresh));

        // The retry's reservation lapses.
        end_wait(&db.pool, &lapsed).await?;
        let id = &lapsed.metadata.id;
        store
            .begin_oauth_refresh(&owner, id, lapsed.version, Uuid::new_v4())
            .await?;
        sqlx::query(
            "UPDATE platform_credential_refresh_attempts \
             SET reserved_until=clock_timestamp()-interval '1 second' WHERE credential_id=$1",
        )
        .bind(id.as_str())
        .execute(&db.pool)
        .await?;
        let permit = started(&store, &owner, &lapsed).await?;
        ensure!(store.rate_limit_oauth_refresh(&permit, 60).await == Err(Error::StaleRefresh));

        // A revocation fence replaces the waiting attempt and is cancelled:
        // the wait ends early, and the next refresh is still the retry.
        let id = &fenced.metadata.id;
        let fence = store
            .fence_oauth_refresh_for_revocation(&owner, id, fenced.version)
            .await?;
        let RevocationFence::Fenced { attempt_id } = fence else {
            anyhow::bail!("a waiting attempt is fenced: {fence:?}");
        };
        store
            .cancel_oauth_refresh(&owner, id, fenced.version, attempt_id)
            .await?;
        let permit = started(&store, &owner, &fenced).await?;
        ensure!(store.rate_limit_oauth_refresh(&permit, 60).await == Err(Error::StaleRefresh));
        Ok(())
    }
    .await;
    db.finish(result).await
}
