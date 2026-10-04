//! Reuse of decrypted material within one bridge epoch, against real
//! restricted PostgreSQL and a synthetic runtime authority and KEK. A reuse
//! skips only the protected-material read. A hosted lease still rereads its
//! credential's record and reuses a value only for exactly that record; a
//! lease with full per-request checks still runs every check around it.

use crate::timing::{self, AuthorityUse, MaterialCacheUse, Timings};

use super::*;

pub(super) fn retained(adapter: &Adapter) -> usize {
    adapter.material.as_ref().map_or(0, EpochMaterialCache::len)
}

pub(super) fn unwraps(f: &Fixture) -> usize {
    f.provider.unwrap_calls.load(Ordering::SeqCst)
}

/// Authority checks, grant evaluations, record reads and material reads.
pub(super) fn steps(timings: &Timings) -> (u32, u32, u32, u32) {
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
        let adapter = f.epoch().await?;
        let initial = unwraps(&f);
        let (first, miss) = timing::measure(lease(&adapter)).await;
        let first = first?;
        // The epoch's admission evaluated authority: the first lease rereads
        // its credential's record and reads the material through the store.
        ensure!(
            steps(&miss) == (0, 0, 1, 1),
            "miss steps {:?}",
            steps(&miss)
        );
        ensure!(miss.material_cache == MaterialCacheUse::Miss);
        ensure!(miss.authority_decision == AuthorityUse::Reused);
        ensure!(unwraps(&f) == initial + 1);
        ensure!(retained(&adapter) == 1);
        let (second, hit) = timing::measure(lease(&adapter)).await;
        let second = second?;
        // The hit path skips the material read too: its two SQL reads, the
        // unwrap and the final fence transaction.
        ensure!(steps(&hit) == (0, 0, 1, 0), "hit steps {:?}", steps(&hit));
        ensure!(hit.material_read.elapsed == Duration::ZERO);
        ensure!(hit.material_cache == MaterialCacheUse::Hit);
        ensure!(hit.authority_decision == AuthorityUse::Reused);
        ensure!(unwraps(&f) == initial + 1, "a reuse unwrapped again");
        ensure!(second.grant() == first.grant());
        ensure!(second.material_generation() == first.material_generation());
        ensure!(refresh_token(first)? == refresh_token(second)?);
        ensure!(refresh_token(lease(&adapter).await?)? == "synthetic-refresh-old");
        ensure!(unwraps(&f) == initial + 1);
        // A provider outside a bridge epoch has no cache and no decision: it
        // runs the full per-request checks and reads through.
        let (_pool, outside) = f.second().await?;
        let (_, bypass) = timing::measure(lease(&outside)).await;
        ensure!(steps(&bypass) == (2, 2, 2, 1));
        ensure!(bypass.material_cache == MaterialCacheUse::Bypass);
        ensure!(bypass.authority_decision == AuthorityUse::Evaluated);
        ensure!(unwraps(&f) == initial + 2);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn replacement_refresh_and_reconnect_make_the_next_lease_read_the_new_value() -> Result<()> {
    for change in ["replace", "refresh", "reconnect"] {
        let f = Fixture::create().await?;
        let result = async {
            let adapter = f.epoch().await?;
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
            // The changed record made this very lease evaluate again.
            ensure!(timings.authority_decision == AuthorityUse::Evaluated);
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
        let adapter = f.epoch().await?;
        let initial = unwraps(&f);
        // A replacement during each of the lease's two unwraps fails the
        // store's version fence twice: the lease evaluates and retries once,
        // then fails, never filling a value it read.
        f.provider.unwrap_gate.arm();
        let operation = spawn({
            let adapter = adapter.clone();
            async move { lease(&adapter).await }
        });
        for _ in 0..2 {
            f.provider.unwrap_gate.wait().await?;
            mutate(&f, "replace").await?;
            f.provider.unwrap_gate.release();
            // Re-armed before this task yields, so the retry's unwrap waits.
            f.provider.unwrap_gate.arm();
        }
        ensure!(matches!(
            finish_task(operation).await?,
            Err(BrokerLeaseError::Denied)
        ));
        ensure!(unwraps(&f) == initial + 2);
        ensure!(retained(&adapter) == 0, "a denied lease filled the cache");
        // The gate is still armed: let the next lease's single unwrap pass.
        let operation = spawn({
            let adapter = adapter.clone();
            async move { timing::measure(lease(&adapter)).await }
        });
        f.provider.unwrap_gate.wait().await?;
        f.provider.unwrap_gate.release();
        let (leased, timings) = finish_task(operation).await?;
        ensure!(leased?.material_generation() == 3);
        ensure!(timings.material_cache == MaterialCacheUse::Miss);
        ensure!(unwraps(&f) == initial + 3);
        ensure!(retained(&adapter) == 1);
        // A denial before any material step also drops the credential's value.
        mutate(&f, "revoke").await?;
        ensure!(lease(&adapter).await.is_err());
        ensure!(
            retained(&adapter) == 0,
            "a revoked credential kept its value"
        );
        ensure!(unwraps(&f) == initial + 3);
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
        let adapter = f.epoch().await?;
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
