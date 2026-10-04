//! Reuse of decrypted material within one bridge epoch, against real
//! restricted PostgreSQL and a synthetic runtime authority and KEK. A reuse
//! skips only the protected-material read; every authority, grant and record
//! check still runs and still denies.

use crate::codex_oauth::CodexOAuthCredential;
use crate::timing::{self, MaterialCacheUse, Timings};

use super::*;

/// A provider as one admitted bridge epoch holds it: its own empty cache.
async fn epoch(f: &Fixture) -> Result<Arc<Adapter>> {
    Ok(Arc::new(Adapter {
        material: Some(EpochMaterialCache::new()),
        ..Adapter::connect(
            f.authority.clone(),
            f.store.clone(),
            PlatformAccessProfileStore::new(f.pool.clone(), builtin_provider_catalog()),
        )
        .await?
    }))
}

fn retained(adapter: &Adapter) -> usize {
    adapter.material.as_ref().map_or(0, EpochMaterialCache::len)
}

fn unwraps(f: &Fixture) -> usize {
    f.provider.unwrap_calls.load(Ordering::SeqCst)
}

fn refresh_token(lease: PlatformCredentialLease) -> Result<String> {
    lease.with_material(|bytes| {
        Ok(CodexOAuthCredential::parse(bytes)?
            .refresh_token()
            .to_owned())
    })
}

/// Authority checks, grant evaluations, record reads and material reads.
fn steps(timings: &Timings) -> (u32, u32, u32, u32) {
    (
        timings.authority.count,
        timings.grants.count,
        timings.record.count,
        timings.material_read.count,
    )
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_second_lease_in_an_epoch_reuses_material_without_a_material_read() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let adapter = epoch(&f).await?;
        let initial = unwraps(&f);
        let (first, miss) = timing::measure(lease(&adapter)).await;
        let first = first?;
        // The miss path is today's lease: two authority checks bracket two
        // grant evaluations and record reads around one material read.
        ensure!(
            steps(&miss) == (2, 2, 2, 1),
            "miss steps {:?}",
            steps(&miss)
        );
        ensure!(miss.material_cache == MaterialCacheUse::Miss);
        ensure!(unwraps(&f) == initial + 1);
        ensure!(retained(&adapter) == 1);
        let (second, hit) = timing::measure(lease(&adapter)).await;
        let second = second?;
        // The hit path skips only the material read: its two SQL reads, the
        // unwrap and the final fence transaction.
        ensure!(steps(&hit) == (2, 2, 2, 0), "hit steps {:?}", steps(&hit));
        ensure!(hit.material_read.elapsed == Duration::ZERO);
        ensure!(hit.material_cache == MaterialCacheUse::Hit);
        ensure!(unwraps(&f) == initial + 1, "a reuse unwrapped again");
        ensure!(second.grant() == first.grant());
        ensure!(second.material_generation() == first.material_generation());
        ensure!(refresh_token(first)? == refresh_token(second)?);
        ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-old");
        ensure!(unwraps(&f) == initial + 1);
        // A provider outside a bridge epoch has no cache and reads through.
        let (_, bypass) = timing::measure(lease(&f.adapter)).await;
        ensure!(steps(&bypass) == (2, 2, 2, 1));
        ensure!(bypass.material_cache == MaterialCacheUse::Bypass);
        ensure!(unwraps(&f) == initial + 2);
        Ok(())
    }
    .await;
    f.finish(result).await
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
    let adapter = epoch(f).await?;
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
        let result = deny_mutated_hit(&f, mutation, denial, async || {
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
        })
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn cache_hit_rechecks_authenticated_gateway_workspace_policy_and_identity_expiry()
-> Result<()> {
    for mutation in [
        "gateway",
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
async fn replacement_refresh_and_reconnect_make_the_next_lease_read_the_new_value() -> Result<()> {
    for change in ["replace", "refresh", "reconnect"] {
        let f = Fixture::create().await?;
        let result = async {
            let adapter = epoch(&f).await?;
            let warm = lease(&adapter).await?;
            ensure!(refresh_token(warm)? == "synthetic-refresh-old");
            ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-old");
            let current = f.store.record(&f.owner, &f.record.metadata.id).await?;
            match change {
                "replace" => {
                    f.store
                        .replace(
                            &f.owner,
                            &current.metadata.id,
                            current.version,
                            &value(bundle(false, "new").as_bytes()),
                            None,
                        )
                        .await?;
                }
                // A refresh committed in this same epoch drops its value.
                "refresh" => {
                    let started = adapter
                        .start_credential_refresh(
                            reserve(&adapter, request(&adapter).await?).await?,
                        )
                        .await?;
                    adapter
                        .commit_credential_refresh(started, bundle(false, "new"))
                        .await?;
                    ensure!(
                        retained(&adapter) == 0,
                        "a refresh commit kept the old value"
                    );
                }
                // Reconnect publishes a newly enrolled login for the same
                // identity, as the public enrollment path does.
                "reconnect" => {
                    let prepared = f
                        .store
                        .prepare_replacement(
                            &f.owner,
                            &current,
                            &value(bundle(false, "new").as_bytes()),
                            Some("synthetic-account".into()),
                        )
                        .await?;
                    let mut tx = f.pool.begin().await?;
                    f.store
                        .replace_prepared_in(&mut tx, &f.owner, prepared)
                        .await?;
                    tx.commit().await?;
                }
                _ => unreachable!(),
            }
            let initial = unwraps(&f);
            let (next, timings) = timing::measure(lease(&adapter)).await;
            let next = next?;
            ensure!(
                timings.material_cache == MaterialCacheUse::Miss,
                "{change}: the next lease reused the old value"
            );
            ensure!(unwraps(&f) == initial + 1);
            ensure!(next.material_generation() == current.version.material_generation + 1);
            ensure!(
                refresh_token(next)? == "synthetic-refresh-new",
                "{change}: the next lease did not return the new value"
            );
            ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-new");
            ensure!(
                unwraps(&f) == initial + 1,
                "{change}: the new value was not reused"
            );
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_denied_lease_never_fills_its_cache() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let adapter = epoch(&f).await?;
        let admitted = f.authority.session.lock().unwrap().clone();
        let initial = unwraps(&f);
        // The lease's last authority check follows its only unwrap.
        f.authority.gate.arm(2);
        let operation = spawn({
            let adapter = adapter.clone();
            async move { lease(&adapter).await }
        });
        f.authority.gate.wait().await?;
        ensure!(unwraps(&f) == initial + 1);
        f.authority
            .change(|session| session.workspace_mut().uid = Uuid::new_v4());
        f.authority.gate.release();
        ensure!(matches!(
            finish_task(operation).await?,
            Err(BrokerLeaseError::Denied)
        ));
        ensure!(retained(&adapter) == 0, "a denied lease filled the cache");
        // Restored authority admits again, and the lease must read through:
        // the denied lease left nothing to reuse.
        f.authority.change(|session| *session = admitted);
        let (leased, timings) = timing::measure(lease(&adapter)).await;
        leased?;
        ensure!(timings.material_cache == MaterialCacheUse::Miss);
        ensure!(unwraps(&f) == initial + 2);
        ensure!(retained(&adapter) == 1);
        // A denial before any material step also drops the credential's value.
        f.store
            .revoke(&f.owner, &f.record.metadata.id, f.record.version)
            .await?;
        ensure!(lease(&adapter).await.is_err());
        ensure!(
            retained(&adapter) == 0,
            "a revoked credential kept its value"
        );
        ensure!(unwraps(&f) == initial + 2);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn every_codex_login_reads_through_and_fills_nothing() -> Result<()> {
    let f = Fixture::create_for_bridge().await?;
    let result = async {
        let adapter = epoch(&f).await?;
        let initial = unwraps(&f);
        const LOGINS: usize = 3;
        for login in 1..=LOGINS {
            let (leased, timings) =
                timing::measure(adapter.lease_codex_login(Uuid::new_v4())).await;
            leased?;
            ensure!(timings.material_cache == MaterialCacheUse::Bypass);
            ensure!(timings.material_read.count == 1);
            ensure!(unwraps(&f) == initial + login);
            ensure!(retained(&adapter) == 0, "a Codex login filled the cache");
        }
        // A proxied lease of the same credential fills the cache; the login
        // still neither reuses nor replaces that value.
        lease(&adapter).await?;
        ensure!(retained(&adapter) == 1);
        ensure!(unwraps(&f) == initial + LOGINS + 1);
        adapter.lease_codex_login(Uuid::new_v4()).await?;
        ensure!(
            unwraps(&f) == initial + LOGINS + 2,
            "a Codex login reused material"
        );
        lease(&adapter).await?;
        ensure!(unwraps(&f) == initial + LOGINS + 2);
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// An owner-local delegation authority: one explicit selection whose grant
/// evaluation can be switched to deny.
struct OwnerLocalAuthority {
    session: PlatformRuntimeSession,
    grant: DerivedGrant,
    deny: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl PlatformRuntimeAuthority for OwnerLocalAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        Ok(self.session.clone())
    }

    async fn owner_local_grants(
        &self,
        expected: &PlatformRuntimeSession,
    ) -> Result<Vec<DerivedGrant>, PlatformRuntimeError> {
        if self.deny.load(Ordering::SeqCst) || !expected.same_binding(&self.session) {
            return Err(PlatformRuntimeError::Denied);
        }
        Ok(vec![self.grant.clone()])
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn owner_local_cache_hit_rechecks_grants_and_drops_its_value_when_denied() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let profile = EnvironmentAccessBinding {
            environment_id: EnvironmentId::parse(Uuid::new_v4().to_string())?,
            profile_id: codewire_access::AccessProfileId::parse(Uuid::new_v4().to_string())?,
            profile_revision: 3,
        };
        let context = GrantContext {
            environment_id: profile.environment_id.clone(),
            environment_generation: 7,
            placement: GrantPlacement::PlatformToLocal,
            user_id: OwnerId::parse("synthetic-owner")?,
            organization_id: Some(OwnerId::parse("synthetic-org")?),
            allow_personal_credentials: true,
            authorized_credentials: [f.record.metadata.id.clone()].into(),
        };
        let session = PlatformRuntimeSession::owner_local(
            context.clone(),
            f.owner.clone(),
            Some(profile.clone()),
            [7; 32],
            unix_now()? + 3_600,
        )?;
        let authority = Arc::new(OwnerLocalAuthority {
            grant: DerivedGrant {
                environment_id: context.environment_id.clone(),
                environment_generation: context.environment_generation,
                profile: Some(codewire_access::GrantProfile {
                    id: profile.profile_id.clone(),
                    revision: profile.profile_revision,
                }),
                capability_slot: CapabilitySlot::codex(),
                credential_id: f.record.metadata.id.clone(),
                credential_revocation_generation: f.record.version.revocation_generation,
                expires_at_unix: Some(session.identity_expires_at_unix),
                permissions: [permission()].into(),
            },
            session,
            deny: Default::default(),
        });
        // An owner-local delegation stream is admitted through the same bridge
        // admission, so it holds its own epoch cache.
        let adapter = Arc::new(PlatformBrokerLeaseProvider {
            material: Some(EpochMaterialCache::new()),
            ..PlatformBrokerLeaseProvider::connect(
                authority.clone(),
                f.store.clone(),
                PlatformAccessProfileStore::new(f.pool.clone(), builtin_provider_catalog()),
            )
            .await?
        });
        let lease = |adapter: Arc<PlatformBrokerLeaseProvider<OwnerLocalAuthority>>| async move {
            let permission = permission();
            adapter
                .lease_operation(
                    Uuid::new_v4(),
                    CapabilitySlot::codex(),
                    permission.operation,
                    permission.route,
                )
                .await
        };
        let initial = unwraps(&f);
        let (first, miss) = timing::measure(lease(adapter.clone())).await;
        ensure!(refresh_token(first?)? == "synthetic-refresh-old");
        ensure!(miss.material_cache == MaterialCacheUse::Miss);
        ensure!(unwraps(&f) == initial + 1);
        let (second, hit) = timing::measure(lease(adapter.clone())).await;
        second?;
        ensure!(hit.material_cache == MaterialCacheUse::Hit);
        ensure!(unwraps(&f) == initial + 1);
        // The next reuse pauses between its record reads, where the
        // delegation's grant evaluation starts to deny.
        let gate = Arc::new(SessionGate::default());
        gate.arm(1);
        let operation = spawn(BETWEEN_RECORD_READS.scope(gate.clone(), {
            let adapter = adapter.clone();
            async move { timing::measure(lease(adapter)).await }
        }));
        gate.wait().await?;
        authority.deny.store(true, Ordering::SeqCst);
        gate.release();
        let (denied, timings) = finish_task(operation).await?;
        ensure!(timings.material_cache == MaterialCacheUse::Hit);
        ensure!(
            matches!(denied, Err(BrokerLeaseError::Denied)),
            "an owner-local reuse survived a grant denial"
        );
        ensure!(unwraps(&f) == initial + 1);
        ensure!(
            adapter
                .material
                .as_ref()
                .is_some_and(EpochMaterialCache::is_empty),
            "a denied owner-local runtime kept its value"
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}
