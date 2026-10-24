//! Leases with full per-request checks (`lease_checked`): Codex login
//! delivery, owner-local delegation epochs, and any provider without a hosted
//! epoch's authority decision. Two runtime authority checks bracket each
//! lease, its grant and record reads repeat after the material read, and the
//! final check only narrows the deadline. Real restricted PostgreSQL, with a
//! synthetic runtime authority and KEK.

use crate::timing::{self, MaterialCacheUse};

use super::material_cache::{retained, unwraps};
use super::*;

/// A provider without an epoch decision, so that every lease runs the full
/// checks. With `cache` it also holds an epoch material cache, as an
/// owner-local delegation epoch does.
async fn checked(f: &Fixture, cache: bool) -> Result<(PgPool, Arc<Adapter>)> {
    let (pool, adapter) = f.second().await?;
    let adapter = Adapter {
        material: cache.then(EpochMaterialCache::new),
        ..adapter
    };
    Ok((pool, Arc::new(adapter)))
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn unwrap_rechecks_replacement_revocation_rebinding_stop_generation_and_hard_expiry()
-> Result<()> {
    for mutation in [
        "replace",
        "revoke",
        "rebind",
        "stop",
        "generation",
        "expiry",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let (pool, adapter) = checked(&f, false).await?;
            let replacement = bundle(false, "replacement");
            f.provider.unwrap_gate.arm();
            let operation = spawn({
                let adapter = adapter.clone();
                async move { lease(&adapter).await }
            });
            f.provider.unwrap_gate.wait().await?;
            match mutation {
                "replace" => {
                    f.store
                        .replace(
                            &f.owner,
                            &f.record.metadata.id,
                            f.record.version,
                            &value(replacement.as_bytes()),
                            None,
                        )
                        .await?;
                }
                "revoke" => {
                    f.store
                        .revoke(&f.owner, &f.record.metadata.id, f.record.version)
                        .await?;
                }
                "rebind" => f.rebind().await?,
                "stop" => f.stop().await?,
                "generation" => {
                    sqlx::query(
                        "UPDATE environments SET environment_operation_generation=8 WHERE id=$1",
                    )
                    .bind(f.context.environment_id.as_str())
                    .execute(&f.db.pool)
                    .await?;
                }
                "expiry" => {
                    sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
                        .bind(f.record.metadata.id.as_str())
                        .execute(&f.db.pool)
                        .await?;
                }
                _ => unreachable!(),
            }
            f.provider.unwrap_gate.release();
            let leased = finish_task(operation).await?;
            if mutation == "replace" {
                // The record moved under the lease, which evaluates again
                // once and releases the replacement, never the replaced
                // material (owner, 2026-10-24).
                let leased = leased.map_err(|error| anyhow::anyhow!("replace: {error:?}"))?;
                leased.with_material(|material| {
                    let released = crate::codex_oauth::CodexOAuthCredential::parse(material)?;
                    ensure!(
                        released.refresh_token() != "synthetic-refresh-old",
                        "replace exposed stale material"
                    );
                    ensure!(material == replacement.as_bytes());
                    Ok(())
                })?;
            } else {
                ensure!(
                    matches!(leased, Err(BrokerLeaseError::Denied)),
                    "{mutation} exposed stale material"
                );
            }
            pool.close().await;
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn unwrap_rechecks_authenticated_gateway_workspace_policy_and_identity_expiry() -> Result<()>
{
    for mutation in [
        "relay",
        "workspace",
        "policy",
        "authorized set replaced",
        "personal-policy",
        "expiry",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let (pool, adapter) = checked(&f, false).await?;
            f.provider.unwrap_gate.arm();
            let operation = spawn({
                let adapter = adapter.clone();
                async move { lease(&adapter).await }
            });
            f.provider.unwrap_gate.wait().await?;
            f.authority
                .change(|session| change_authority(session, mutation));
            f.provider.unwrap_gate.release();
            ensure!(
                matches!(finish_task(operation).await?, Err(BrokerLeaseError::Denied)),
                "{mutation} exposed stale material"
            );
            pool.close().await;
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn lease_denies_authority_changed_before_its_first_grant_evaluation() -> Result<()> {
    for mutation in [
        "relay",
        "workspace",
        "policy",
        "authorized set replaced",
        "expiry",
        "personal-policy",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let (pool, adapter) = checked(&f, false).await?;
            // Hold the environment row: the lease's first grant evaluation
            // waits for it after the lease's first runtime authority check.
            let mut holder = f.db.pool.begin().await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *holder)
                .await?;
            sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE")
                .bind(f.context.environment_id.as_str())
                .fetch_one(&mut *holder)
                .await?;
            let unwraps = f.provider.unwrap_calls.load(Ordering::SeqCst);
            let operation = spawn({
                let adapter = adapter.clone();
                async move { lease(&adapter).await }
            });
            wait_for_database_blocker(&f.db.pool, pid).await?;
            f.authority
                .change(|session| change_authority(session, mutation));
            holder.commit().await?;
            ensure!(
                matches!(finish_task(operation).await?, Err(BrokerLeaseError::Denied)),
                "{mutation} released material for a changed authority"
            );
            // Both grant evaluations use the first response, so only the final
            // check sees the change. Material was unwrapped once and withheld.
            ensure!(
                f.provider.unwrap_calls.load(Ordering::SeqCst) == unwraps + 1,
                "{mutation}: the lease did not reach its final authority check"
            );
            pool.close().await;
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn final_lease_authority_denies_any_change_and_only_narrows_expiry() -> Result<()> {
    for mutation in [
        "relay",
        "workspace",
        "policy",
        "authorized set replaced",
        "expiry",
        "shorter expiry",
        "longer expiry",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let (pool, adapter) = checked(&f, false).await?;
            let connected = adapter.session.identity_expires_at_unix;
            let unwraps = f.provider.unwrap_calls.load(Ordering::SeqCst);
            // The lease's second runtime authority check is its last: it
            // follows both grant evaluations and the only unwrap.
            f.authority.gate.arm(2);
            let operation = spawn({
                let adapter = adapter.clone();
                async move { lease(&adapter).await }
            });
            f.authority.gate.wait().await?;
            ensure!(f.provider.unwrap_calls.load(Ordering::SeqCst) == unwraps + 1);
            f.authority.change(|session| match mutation {
                "shorter expiry" => session.identity_expires_at_unix = connected - 600,
                "longer expiry" => session.identity_expires_at_unix = connected + 600,
                _ => change_authority(session, mutation),
            });
            f.authority.gate.release();
            let leased = finish_task(operation).await?;
            match mutation {
                "shorter expiry" => ensure!(
                    leased?.grant().expires_at_unix == Some(connected - 600),
                    "a shorter final expiry did not narrow the lease"
                ),
                "longer expiry" => ensure!(
                    leased?.grant().expires_at_unix == Some(connected),
                    "a longer final expiry extended the lease"
                ),
                _ => ensure!(
                    matches!(leased, Err(BrokerLeaseError::Denied)),
                    "{mutation} released material for a changed authority"
                ),
            }
            pool.close().await;
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

/// Warm `adapter`'s cache, then pause its next lease between its record reads
/// and apply `mutation` there. That lease must be a reuse, must fail with
/// exactly `denial`, and must drop its credential's value.
async fn deny_mutated_hit(
    f: &Fixture,
    mutation: &str,
    denial: BrokerLeaseError,
    mutate: impl AsyncFnOnce() -> Result<()>,
) -> Result<()> {
    let (pool, adapter) = checked(f, true).await?;
    lease(&adapter).await?;
    ensure!(retained(&adapter) == 1);
    let initial = unwraps(f);
    let gate = Arc::new(SessionGate::default());
    gate.arm(1);
    let operation = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), {
        let adapter = adapter.clone();
        async move { timing::measure(lease(&adapter)).await }
    }));
    gate.wait().await?;
    mutate().await?;
    gate.release();
    let (leased, timings) = finish_task(operation).await?;
    ensure!(
        timings.material_cache == MaterialCacheUse::Hit,
        "{mutation}: the gated lease was not a reuse"
    );
    ensure!(
        leased.as_ref().err() == Some(&denial),
        "{mutation} released reused material ({:?})",
        leased.err()
    );
    ensure!(unwraps(f) == initial, "{mutation}: a reuse unwrapped");
    ensure!(
        retained(&adapter) == 0,
        "{mutation}: a denied lease kept its value"
    );
    pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn cache_hit_rechecks_replacement_revocation_rebinding_stop_generation_expiry_and_owner_deletion()
-> Result<()> {
    for mutation in [
        "replace",
        "revoke",
        "rebind",
        "stop",
        "generation",
        "expiry",
        "owner deletion",
    ] {
        let f = Fixture::create().await?;
        // A revoked or expired credential withholds only its own capability:
        // the second grant evaluation reports Reconnect instead of a grant.
        let denial = if matches!(mutation, "revoke" | "expiry") {
            BrokerLeaseError::ReconnectRequired
        } else {
            BrokerLeaseError::Denied
        };
        let mutated = async || {
            match mutation {
                "replace" => {
                    f.store
                        .replace(
                            &f.owner,
                            &f.record.metadata.id,
                            f.record.version,
                            &value(bundle(false, "replacement").as_bytes()),
                            None,
                        )
                        .await?;
                }
                "revoke" => {
                    f.store
                        .revoke(&f.owner, &f.record.metadata.id, f.record.version)
                        .await?;
                }
                "rebind" => f.rebind().await?,
                "stop" => f.stop().await?,
                "generation" => {
                    sqlx::query(
                        "UPDATE environments SET environment_operation_generation=8 WHERE id=$1",
                    )
                    .bind(f.context.environment_id.as_str())
                    .execute(&f.db.pool)
                    .await?;
                }
                "expiry" => {
                    sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
                        .bind(f.record.metadata.id.as_str())
                        .execute(&f.db.pool)
                        .await?;
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
                }
                _ => unreachable!(),
            }
            Ok(())
        };
        let result = if mutation == "replace" {
            reevaluate_replaced_hit(&f, mutated).await
        } else {
            deny_mutated_hit(&f, mutation, denial, mutated).await
        };
        f.finish(result).await?;
    }
    Ok(())
}

/// A cache-hit lease whose credential is replaced between its two record
/// reads: the record moved, so the lease evaluates again once and releases
/// the replacement, read through the store, never the value it held for the
/// replaced record (owner, 2026-10-24).
async fn reevaluate_replaced_hit(
    f: &Fixture,
    replace: impl AsyncFnOnce() -> Result<()>,
) -> Result<()> {
    let (pool, adapter) = checked(f, true).await?;
    lease(&adapter).await?;
    ensure!(retained(&adapter) == 1);
    let initial = unwraps(f);
    let gate = Arc::new(SessionGate::default());
    gate.arm(1);
    let operation = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), {
        let adapter = adapter.clone();
        async move { lease(&adapter).await }
    }));
    gate.wait().await?;
    ensure!(
        unwraps(f) == initial,
        "replace: the gated lease was not a reuse"
    );
    replace().await?;
    gate.release();
    let leased = finish_task(operation)
        .await?
        .map_err(|error| anyhow::anyhow!("replace: {error:?}"))?;
    leased.with_material(|material| {
        let released = crate::codex_oauth::CodexOAuthCredential::parse(material)?;
        ensure!(
            released.refresh_token() != "synthetic-refresh-old",
            "replace released reused material"
        );
        ensure!(released.refresh_token() == "synthetic-refresh-replacement");
        Ok(())
    })?;
    // One read, for the replacement, which the cache now holds instead.
    ensure!(unwraps(f) == initial + 1);
    ensure!(retained(&adapter) == 1);
    pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn cache_hit_rechecks_authenticated_gateway_workspace_policy_and_identity_expiry()
-> Result<()> {
    for mutation in [
        "relay",
        "workspace",
        "policy",
        "authorized set replaced",
        "personal-policy",
        "expiry",
    ] {
        let f = Fixture::create().await?;
        let result = deny_mutated_hit(&f, mutation, BrokerLeaseError::Denied, async || {
            f.authority
                .change(|session| change_authority(session, mutation));
            Ok(())
        })
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn final_lease_rechecks_pod_identity_after_sql_lock_waits() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (pool, adapter) = checked(&f, false).await?;
        // Pause at the unwrap, before the lease's second grant evaluation.
        f.provider.unwrap_gate.arm();
        let operation = spawn({
            let adapter = adapter.clone();
            async move {
                lease(&adapter)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}"))
            }
        });
        f.provider.unwrap_gate.wait().await?;
        let mut holder = f.db.pool.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *holder)
            .await?;
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE")
            .bind(f.context.environment_id.as_str())
            .fetch_one(&mut *holder)
            .await?;
        f.provider.unwrap_gate.release();
        wait_for_database_blocker(&f.db.pool, pid).await?;
        f.authority
            .change(|session| session.workspace_mut().uid = Uuid::new_v4());
        holder.commit().await?;
        ensure!(
            finish_task(operation).await? == Err("Denied".into()),
            "the lease retained identity across a SQL wait"
        );
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// A hosted epoch delivers the Codex login through the full checks, while its
/// authority decision keeps serving proxied leases within its window.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_codex_login_on_a_hosted_epoch_rechecks_authority_after_its_unwrap() -> Result<()> {
    for mutation in ["relay", "workspace", "personal-policy"] {
        let f = Fixture::create_for_bridge().await?;
        let result = async {
            let adapter = f.epoch().await?;
            f.provider.unwrap_gate.arm();
            let login = spawn({
                let adapter = adapter.clone();
                async move { adapter.lease_codex_login(Uuid::new_v4()).await.map(|_| ()) }
            });
            f.provider.unwrap_gate.wait().await?;
            f.authority
                .change(|session| change_authority(session, mutation));
            f.provider.unwrap_gate.release();
            ensure!(
                matches!(finish_task(login).await?, Err(BrokerLeaseError::Denied)),
                "{mutation}: a Codex login survived an authority change"
            );
            ensure!(
                lease(&adapter).await.is_ok(),
                "{mutation}: the epoch's decision stopped serving within its window"
            );
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}
