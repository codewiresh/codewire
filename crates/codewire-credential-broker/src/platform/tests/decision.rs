//! A hosted epoch's authority decision against real restricted PostgreSQL
//! and a synthetic runtime authority and KEK. A lease reuses the decision for
//! at most a minute and rereads only its credential's record; a credential
//! change applies to the very next lease, and any other authority change
//! within the minute. Time is advanced on Tokio's paused clock, which the
//! decision's age is measured on; database I/O runs on the real clock.

use std::future::Future;

use codewire_access::ProviderId;
use codewire_platform_credentials::CredentialRegistration;

use crate::timing::{self, AuthorityUse, MaterialCacheUse, Timings};

use super::material_cache::{retained, steps, unwraps};
use super::*;

/// Advance the Tokio clock the decision's age is measured on.
async fn age(by: Duration) {
    tokio::time::pause();
    tokio::time::advance(by).await;
    tokio::time::resume();
}

async fn measured<T>(future: impl Future<Output = T>) -> (T, Timings) {
    timing::measure(future).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_lease_within_sixty_seconds_makes_no_resolve_or_grant_call_and_one_record_read()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let adapter = f.epoch().await?;
        let calls = f.authority.calls();
        let (first, timings) = measured(lease(&adapter)).await;
        first?;
        ensure!(
            steps(&timings) == (0, 0, 1, 1),
            "first {:?}",
            steps(&timings)
        );
        ensure!(timings.authority_decision == AuthorityUse::Reused);
        for elapsed in [
            Duration::ZERO,
            Duration::from_secs(30),
            Duration::from_secs(29),
        ] {
            age(elapsed).await;
            let (leased, timings) = measured(lease(&adapter)).await;
            leased?;
            ensure!(
                steps(&timings) == (0, 0, 1, 0),
                "reuse {:?}",
                steps(&timings)
            );
            ensure!(timings.authority_decision == AuthorityUse::Reused);
            ensure!(timings.material_cache == MaterialCacheUse::Hit);
        }
        ensure!(
            f.authority.calls() == calls,
            "a lease inside the window resolved"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Lease `count` times at once while the authority holds the first resolve,
/// so that every other lease is waiting when it completes.
async fn concurrent_leases(
    f: &Fixture,
    adapter: &Arc<Adapter>,
    count: usize,
) -> Result<Vec<(Result<PlatformCredentialLease, BrokerLeaseError>, Timings)>> {
    f.authority.gate.arm(1);
    let tasks: Vec<_> = (0..count)
        .map(|_| {
            let adapter = adapter.clone();
            spawn(async move { measured(lease(&adapter)).await })
        })
        .collect();
    f.authority.gate.wait().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.authority.gate.release();
    let mut results = Vec::with_capacity(count);
    for task in tasks {
        results.push(finish_task(task).await?);
    }
    Ok(results)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn after_sixty_seconds_one_evaluation_serves_every_concurrent_lease() -> Result<()> {
    const LEASES: usize = 8;
    let f = Fixture::create().await?;
    let result = async {
        let adapter = f.epoch().await?;
        lease(&adapter).await?;
        age(AUTHORITY_DECISION_REUSE).await;
        let calls = f.authority.calls();
        let results = concurrent_leases(&f, &adapter, LEASES).await?;
        let mut grants = 0;
        for (leased, timings) in results {
            leased?;
            grants += timings.grants.count;
        }
        ensure!(
            f.authority.calls() == calls + 1,
            "{} resolves",
            f.authority.calls() - calls
        );
        ensure!(grants == 1, "{grants} grant evaluations");
        // The new decision is reused again.
        let (leased, timings) = measured(lease(&adapter)).await;
        leased?;
        ensure!(steps(&timings) == (0, 0, 1, 0));
        // Concurrent leases that see one rotation each present it.
        mutate(&f, "replace").await?;
        for (leased, _) in concurrent_leases(&f, &adapter, LEASES).await? {
            ensure!(refresh_token(leased?)? == "synthetic-refresh-replacement");
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_credential_change_applies_to_the_very_next_lease() -> Result<()> {
    for change in [
        "rotation",
        "reconnect",
        "refresh",
        "refresh by another replica",
        "revoke",
        "expiry",
        "refresh failed",
        "owner deletion",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let adapter = f.epoch().await?;
            ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-old");
            lease(&adapter).await?;
            ensure!(retained(&adapter) == 1);
            let current = f.store.record(&f.owner, &f.record.metadata.id).await?;
            let reconnect = async |label: &str| {
                let prepared = f
                    .store
                    .prepare_replacement(
                        &f.owner,
                        &f.store.record(&f.owner, &f.record.metadata.id).await?,
                        &value(bundle(false, label).as_bytes()),
                        Some("synthetic-account".into()),
                    )
                    .await?;
                let mut tx = f.pool.begin().await?;
                f.store
                    .replace_prepared_in(&mut tx, &f.owner, prepared)
                    .await?;
                tx.commit().await?;
                anyhow::Ok(())
            };
            let expected = match change {
                "rotation" => {
                    mutate(&f, "replace").await?;
                    Ok("synthetic-refresh-replacement")
                }
                "reconnect" => {
                    reconnect("new").await?;
                    Ok("synthetic-refresh-new")
                }
                "refresh" | "refresh by another replica" => {
                    let (_pool, other) = f.second().await?;
                    let owner = if change == "refresh" {
                        &*adapter
                    } else {
                        &other
                    };
                    let started = owner
                        .start_credential_refresh(reserve(owner, request(owner).await?).await?)
                        .await?;
                    owner
                        .commit_credential_refresh(started, bundle(false, "new"))
                        .await?;
                    Ok("synthetic-refresh-new")
                }
                "revoke" => {
                    mutate(&f, "revoke").await?;
                    Err(BrokerLeaseError::ReconnectRequired)
                }
                "expiry" => {
                    mutate(&f, "expiry").await?;
                    Err(BrokerLeaseError::ReconnectRequired)
                }
                "refresh failed" => {
                    sqlx::query(
                        "UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1",
                    )
                    .bind(f.record.metadata.id.as_str())
                    .execute(&f.db.pool)
                    .await?;
                    Err(BrokerLeaseError::ReconnectRequired)
                }
                // The owner's lifecycle removes the environment it created,
                // then the owner, whose credential rows cascade with it.
                "owner deletion" => {
                    let mut tx = f.db.pool.begin().await?;
                    sqlx::query("DELETE FROM environments WHERE id=$1")
                        .bind(f.context.environment_id.as_str())
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM users WHERE id=$1")
                        .bind(f.owner.id().as_str())
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                    Err(BrokerLeaseError::Denied)
                }
                _ => unreachable!(),
            };
            let calls = f.authority.calls();
            let initial = unwraps(&f);
            let (next, timings) = measured(lease(&adapter)).await;
            ensure!(
                timings.authority_decision == AuthorityUse::Evaluated,
                "{change}: the next lease reused the decision"
            );
            ensure!(f.authority.calls() == calls + 1);
            match expected {
                Ok(token) => {
                    let next = next?;
                    ensure!(next.material_generation() > current.version.material_generation);
                    ensure!(refresh_token(next)? == token, "{change}: old value");
                    ensure!(timings.material_cache == MaterialCacheUse::Miss);
                    ensure!(unwraps(&f) == initial + 1);
                }
                Err(denial) => {
                    ensure!(
                        next.as_ref().err() == Some(&denial),
                        "{change}: {:?}",
                        next.err()
                    );
                    ensure!(unwraps(&f) == initial, "{change}: a denial unwrapped");
                    ensure!(retained(&adapter) == 0, "{change}: a denial kept its value");
                }
            }
            // Reconnect restores a withheld capability on the very next
            // lease too, though the decision granted that slot nothing.
            if matches!(change, "revoke" | "expiry" | "refresh failed") {
                if change == "expiry" {
                    sqlx::query("UPDATE platform_credentials SET expires_at_unix=NULL WHERE id=$1")
                        .bind(f.record.metadata.id.as_str())
                        .execute(&f.db.pool)
                        .await?;
                }
                reconnect("reconnected").await?;
                ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-reconnected");
            }
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_authority_change_is_served_until_sixty_seconds_then_denied() -> Result<()> {
    for change in [
        "membership or role",
        "gateway",
        "workspace",
        "policy",
        "personal-policy",
        "stop",
        "generation",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let adapter = f.epoch().await?;
            lease(&adapter).await?;
            ensure!(retained(&adapter) == 1);
            match change {
                "membership or role" => f.authority.deny.store(true, Ordering::SeqCst),
                "stop" | "generation" => mutate(&f, change).await?,
                _ => f
                    .authority
                    .change(|session| change_authority(session, change)),
            }
            let calls = f.authority.calls();
            for elapsed in [Duration::ZERO, Duration::from_secs(59)] {
                age(elapsed).await;
                let (leased, timings) = measured(lease(&adapter)).await;
                ensure!(leased.is_ok(), "{change}: not served inside the window");
                ensure!(timings.authority_decision == AuthorityUse::Reused);
            }
            ensure!(f.authority.calls() == calls);
            age(Duration::from_secs(1)).await;
            let (leased, timings) = measured(lease(&adapter)).await;
            ensure!(
                matches!(leased, Err(BrokerLeaseError::Denied)),
                "{change}: {:?}",
                leased.err()
            );
            ensure!(timings.authority_decision == AuthorityUse::Evaluated);
            ensure!(f.authority.calls() == calls + 1);
            // A denied evaluation installs nothing and clears the epoch's
            // material cache; the next lease evaluates again.
            ensure!(retained(&adapter) == 0, "{change}: a denial kept a value");
            ensure!(matches!(
                lease(&adapter).await,
                Err(BrokerLeaseError::Denied)
            ));
            ensure!(f.authority.calls() == calls + 2);
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn an_evaluation_only_narrows_the_connected_identity_deadline() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let adapter = f.epoch().await?;
        let connected = adapter.session.identity_expires_at_unix;
        ensure!(lease(&adapter).await?.grant().expires_at_unix == Some(connected));
        // A later identity expiry never extends the connected one; an
        // earlier one narrows it from the next evaluation on.
        for (expiry, expected) in [
            (connected + 600, connected),
            (connected - 600, connected - 600),
        ] {
            f.authority
                .change(|session| session.identity_expires_at_unix = expiry);
            // Inside the window the decision's deadline stands.
            ensure!(lease(&adapter).await?.grant().expires_at_unix == Some(connected));
            age(AUTHORITY_DECISION_REUSE).await;
            ensure!(
                lease(&adapter).await?.grant().expires_at_unix == Some(expected),
                "expiry {expiry}"
            );
        }
        Ok(())
    }
    .await;
    f.finish(result).await
}

async fn lease_slot(
    adapter: &Adapter,
    slot: CapabilitySlot,
    operation: &str,
    route: &str,
) -> Result<PlatformCredentialLease, BrokerLeaseError> {
    adapter
        .lease_operation(
            Uuid::new_v4(),
            slot,
            BrokerOperationId::parse(operation).unwrap(),
            BrokerRouteId::parse(route).unwrap(),
        )
        .await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn requests_to_an_unselected_slot_make_no_evaluation() -> Result<()> {
    const REQUESTS: usize = 20;
    let f = Fixture::create().await?;
    let result = async {
        let adapter = f.epoch().await?;
        let calls = f.authority.calls();
        let anthropic = || {
            lease_slot(
                &adapter,
                CapabilitySlot::anthropic(),
                "messages",
                "anthropic-api",
            )
        };
        let github = || {
            lease_slot(
                &adapter,
                CapabilitySlot::github(),
                "git-push",
                "github-https",
            )
        };
        for _ in 0..REQUESTS {
            // A slot the profile does not select is refused from the decision.
            let (leased, timings) = measured(anthropic()).await;
            ensure!(matches!(leased, Err(BrokerLeaseError::Denied)));
            ensure!(
                steps(&timings) == (0, 0, 0, 0),
                "anthropic {:?}",
                steps(&timings)
            );
            ensure!(timings.authority_decision == AuthorityUse::Reused);
            // An ungranted GitHub slot rereads only the account's connection.
            let (leased, timings) = measured(github()).await;
            ensure!(matches!(leased, Err(BrokerLeaseError::Denied)));
            ensure!(
                steps(&timings) == (0, 0, 1, 0),
                "github {:?}",
                steps(&timings)
            );
        }
        ensure!(f.authority.calls() == calls, "a refused slot evaluated");
        // A GitHub connection made since the decision is a credential change:
        // the very next GitHub request evaluates once. This runtime does not
        // authorize it, so later requests are refused from the new decision.
        f.store
            .create(
                &f.owner,
                CredentialRegistration {
                    provider: ProviderId::parse("github")?,
                    ..registration("GitHub", CredentialAuthKind::OAuth)
                },
                &value(b"synthetic-github-connection-never-leased"),
            )
            .await?;
        let (leased, timings) = measured(github()).await;
        ensure!(matches!(leased, Err(BrokerLeaseError::Denied)));
        ensure!(timings.authority_decision == AuthorityUse::Evaluated);
        ensure!(f.authority.calls() == calls + 1);
        for _ in 0..REQUESTS {
            ensure!(matches!(github().await, Err(BrokerLeaseError::Denied)));
            ensure!(matches!(anthropic().await, Err(BrokerLeaseError::Denied)));
        }
        ensure!(f.authority.calls() == calls + 1, "a refused slot evaluated");
        // The selected slot is still served.
        lease(&adapter).await?;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_withheld_slot_is_refused_without_evaluation_until_its_reconnect() -> Result<()> {
    const REQUESTS: usize = 10;
    let f = Fixture::create().await?;
    let result = async {
        let adapter = f.epoch().await?;
        lease(&adapter).await?;
        sqlx::query("UPDATE platform_credentials SET status='refresh_failed' WHERE id=$1")
            .bind(f.record.metadata.id.as_str())
            .execute(&f.db.pool)
            .await?;
        // The changed record evaluates once, which withholds the slot.
        let calls = f.authority.calls();
        ensure!(matches!(
            lease(&adapter).await,
            Err(BrokerLeaseError::ReconnectRequired)
        ));
        ensure!(f.authority.calls() == calls + 1);
        // Until Reconnect, each request rereads only that credential's record.
        for _ in 0..REQUESTS {
            let (leased, timings) = measured(lease(&adapter)).await;
            ensure!(matches!(leased, Err(BrokerLeaseError::ReconnectRequired)));
            ensure!(
                steps(&timings) == (0, 0, 1, 0),
                "withheld {:?}",
                steps(&timings)
            );
        }
        ensure!(
            f.authority.calls() == calls + 1,
            "a withheld slot evaluated"
        );
        // Reconnect is served on the very next request.
        let current = f.store.record(&f.owner, &f.record.metadata.id).await?;
        let prepared = f
            .store
            .prepare_replacement(
                &f.owner,
                &current,
                &value(bundle(false, "reconnected").as_bytes()),
                Some("synthetic-account".into()),
            )
            .await?;
        let mut tx = f.pool.begin().await?;
        f.store
            .replace_prepared_in(&mut tx, &f.owner, prepared)
            .await?;
        tx.commit().await?;
        let (next, timings) = measured(lease(&adapter)).await;
        ensure!(refresh_token(next?)? == "synthetic-refresh-reconnected");
        ensure!(timings.authority_decision == AuthorityUse::Evaluated);
        ensure!(f.authority.calls() == calls + 2);
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Nothing is released under a decision older than its window. A lease takes
/// the decision just inside it, then reads material slowly: before releasing
/// it evaluates again, so a member removed meanwhile is refused.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_lease_releases_material_only_under_a_decision_inside_its_window() -> Result<()> {
    for removed in [false, true] {
        let f = Fixture::create().await?;
        let result = async {
            let adapter = f.epoch().await?;
            // Half a second inside the window, a margin for real time spent here.
            age(AUTHORITY_DECISION_REUSE - Duration::from_millis(500)).await;
            let calls = f.authority.calls();
            // The epoch's first lease misses its cache and waits at the unwrap.
            f.provider.unwrap_gate.arm();
            let operation = spawn({
                let adapter = adapter.clone();
                async move { measured(lease(&adapter)).await }
            });
            f.provider.unwrap_gate.wait().await?;
            ensure!(
                f.authority.calls() == calls,
                "the lease did not take the decision inside its window"
            );
            age(Duration::from_secs(1)).await;
            if removed {
                f.authority.deny.store(true, Ordering::SeqCst);
            }
            f.provider.unwrap_gate.release();
            let (leased, timings) = finish_task(operation).await?;
            ensure!(
                f.authority.calls() == calls + 1,
                "the aged decision was not evaluated again before release"
            );
            ensure!(timings.authority_decision == AuthorityUse::Evaluated);
            if removed {
                ensure!(
                    matches!(leased, Err(BrokerLeaseError::Denied)),
                    "material was released under an aged decision ({:?})",
                    leased.err()
                );
                ensure!(
                    retained(&adapter) == 0,
                    "a refused release filled the cache"
                );
            } else {
                ensure!(refresh_token(leased?)? == "synthetic-refresh-old");
                ensure!(retained(&adapter) == 1);
            }
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}
