//! Real restricted PostgreSQL plus synthetic, process-local runtime identity.
//! No Kubernetes, provider network, ambient configuration or real credentials.

mod checked;
mod codex_login;
mod decision;
mod keepalive;
mod material_cache;
#[cfg(all(feature = "ssh-agent", target_os = "linux"))]
mod ssh;
mod subscription;

#[path = "../../../codewire-platform-credentials/tests/support/mod.rs"]
#[allow(dead_code)]
pub(super) mod support;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use codewire_access::{
    AccessProfile, AccessProfileName, CredentialStatus, EnvironmentAccessBinding, EnvironmentId,
    GrantPlacement, OwnerId, builtin_provider_catalog,
};
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

use super::*;
use support::{SyntheticKek, TIMEOUT, TestDatabase, registration, value};

fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> AbortOnDropHandle<T> {
    AbortOnDropHandle::new(tokio::spawn(future))
}

async fn finish_task<T>(task: AbortOnDropHandle<T>) -> Result<T> {
    Ok(tokio::time::timeout(TIMEOUT, task)
        .await
        .context("synthetic broker operation did not finish")??)
}

#[derive(Default)]
struct SessionGate {
    remaining: AtomicUsize,
    entered: Notify,
    released: Notify,
}

impl SessionGate {
    fn arm(&self, calls: usize) {
        self.remaining.store(calls, Ordering::SeqCst);
    }
    async fn pass(&self) {
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .ok()
            == Some(1)
        {
            self.entered.notify_one();
            self.released.notified().await;
        }
    }
    async fn wait(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, self.entered.notified())
            .await
            .context("runtime authority did not reach its exact synthetic barrier")?;
        Ok(())
    }
    fn release(&self) {
        self.released.notify_one();
    }
}

tokio::task_local! {
    /// Armed by a test to pause one lease between its two record reads.
    static BETWEEN_RECORD_READS: Arc<SessionGate>;
}

/// A lease's test-only barrier between its two record reads: after the unwrap
/// of a read through the store, or where that unwrap would be on a reuse.
/// Outside a test's scope it does nothing.
pub(super) async fn between_record_reads() {
    if let Ok(gate) = BETWEEN_RECORD_READS.try_with(Arc::clone) {
        gate.pass().await;
    }
}

pub(super) struct SyntheticAuthority {
    session: Mutex<PlatformRuntimeSession>,
    gate: SessionGate,
    /// Every `current_session` call: one runtime authority resolve.
    calls: AtomicUsize,
    /// Deny every resolve, as the hosted authority does once the creator's
    /// membership or role, the organization, or the Pod lineage changed.
    deny: AtomicBool,
}

#[async_trait]
impl PlatformRuntimeAuthority for SyntheticAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.gate.pass().await;
        if self.deny.load(Ordering::SeqCst) {
            return Err(PlatformRuntimeError::Denied);
        }
        Ok(self.session.lock().expect("synthetic session").clone())
    }
}

impl SyntheticAuthority {
    pub(super) fn new(session: PlatformRuntimeSession) -> Self {
        Self {
            session: Mutex::new(session),
            gate: SessionGate::default(),
            calls: AtomicUsize::new(0),
            deny: AtomicBool::new(false),
        }
    }

    fn change(&self, change: impl FnOnce(&mut PlatformRuntimeSession)) {
        change(&mut self.session.lock().expect("synthetic session"));
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

type Adapter = PlatformBrokerLeaseProvider<SyntheticAuthority>;

pub(super) struct Fixture {
    db: TestDatabase,
    pub(super) pool: PgPool,
    pub(super) provider: Arc<SyntheticKek>,
    pub(super) store: Arc<PlatformCredentialStore>,
    pub(super) authority: Arc<SyntheticAuthority>,
    adapter: Arc<Adapter>,
    pub(super) record: CredentialRecord,
    profile: AccessProfile,
    pub(super) context: GrantContext,
    pub(super) owner: Owner,
}

fn pod(name: &str) -> PlatformPodIdentity {
    PlatformPodIdentity {
        namespace: "synthetic-workloads".into(),
        name: name.into(),
        uid: Uuid::new_v4(),
    }
}

fn context() -> GrantContext {
    GrantContext {
        environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
        environment_generation: 7,
        placement: GrantPlacement::Platform,
        user_id: OwnerId::parse("synthetic-owner").unwrap(),
        organization_id: Some(OwnerId::parse("synthetic-org").unwrap()),
        allow_personal_credentials: true,
        authorized_credentials: Default::default(),
    }
}

fn session() -> PlatformRuntimeSession {
    PlatformRuntimeSession::new(
        pod("relay"),
        pod("workspace"),
        context(),
        Owner::User(context().user_id),
        unix_now().unwrap() + 3_600,
    )
    .unwrap()
}

pub(super) fn token(claims: serde_json::Value) -> String {
    format!(
        "e30.{}.synthetic-signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap())
    )
}

fn id_token() -> String {
    token(
        serde_json::json!({"https://api.openai.com/auth": {"chatgpt_account_id": "synthetic-account"}}),
    )
}

pub(super) fn bundle(access_expired: bool, label: &str) -> CanonicalCodexOAuthBundle {
    let access = token(
        serde_json::json!({"exp": if access_expired {1} else {unix_now().unwrap()+7_200}, "synthetic":label}),
    );
    crate::import_codex_auth_json(
        &serde_json::to_vec(&serde_json::json!({
            "auth_mode":"chatgpt", "tokens": {"access_token":access,
                "refresh_token":format!("synthetic-refresh-{label}"), "id_token":id_token(),
                "account_id":"synthetic-account"}
        }))
        .unwrap(),
    )
    .unwrap()
    .into_parts()
    .0
}

fn permission() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse("responses").unwrap(),
        route: BrokerRouteId::parse("openai-api").unwrap(),
    }
}

async fn lease(adapter: &Adapter) -> Result<PlatformCredentialLease, BrokerLeaseError> {
    let permission = permission();
    adapter
        .lease_operation(
            Uuid::new_v4(),
            CapabilitySlot::codex(),
            permission.operation,
            permission.route,
        )
        .await
}

async fn request(adapter: &Adapter) -> Result<BrokerCredentialRefreshRequest> {
    let admitted = lease(adapter).await?;
    Ok(BrokerCredentialRefreshRequest {
        refresh_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        kind: BrokerCredentialRefreshKind::CodexOAuth,
        grant: admitted.grant().clone(),
        operation: admitted.permission().operation.clone(),
        route: admitted.permission().route.clone(),
        material_generation: admitted.material_generation(),
    })
}

async fn reserve(
    adapter: &Adapter,
    request: BrokerCredentialRefreshRequest,
) -> Result<PlatformRefreshReservation> {
    match adapter.begin_credential_refresh(request).await? {
        BrokerRefreshAdmission::Reserved(reserved) => Ok(reserved),
        BrokerRefreshAdmission::Recovered => anyhow::bail!("expected a new synthetic reservation"),
    }
}

impl Fixture {
    async fn create() -> Result<Self> {
        Self::create_with_environment_id(context().environment_id).await
    }

    /// The private bridge uses the existing UUID wire coordinate; retain the
    /// original adapter fixture's text ID for all existing SQL race tests.
    pub(super) async fn create_for_bridge() -> Result<Self> {
        Self::create_with_environment_id(EnvironmentId::parse(Uuid::new_v4().to_string())?).await
    }

    async fn create_with_environment_id(environment_id: EnvironmentId) -> Result<Self> {
        let db = TestDatabase::create().await?;
        let setup = async {
            let owner = db.user("synthetic-owner").await?;
            let org = db.organization("synthetic-org").await?;
            let provider = Arc::new(SyntheticKek::default());
            let (pool, _) = db.broker_pool().await?;
            let store = Arc::new(PlatformCredentialStore::new(pool.clone(), provider.clone(), builtin_provider_catalog()));
            let record = store.create(&owner, registration("Codex", CredentialAuthKind::OAuth),
                &value(bundle(true, "old").as_bytes())).await?;
            sqlx::query("INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
                VALUES ('synthetic-preset',$1,'Synthetic','synthetic','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
                .bind(org.id().as_str()).execute(&db.pool).await?;
            sqlx::query("INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
                VALUES ($3,$1,$2,'sandbox','synthetic-preset','running','started',7,'{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)")
                .bind(org.id().as_str()).bind(owner.id().as_str()).bind(environment_id.as_str()).execute(&db.pool).await?;
            let mut context = context();
            context.environment_id = environment_id;
            context.authorized_credentials.insert(record.metadata.id.clone());
            let manager = PlatformAccessProfileStore::new(db.pool.clone(), builtin_provider_catalog());
            let profile = manager.create(&owner, AccessProfileName::parse("work")?,
                BTreeMap::from([(CapabilitySlot::codex(), record.metadata.id.clone())])).await?;
            manager.create_binding(&context, EnvironmentAccessBinding {
                environment_id: context.environment_id.clone(), profile_id: profile.id.clone(), profile_revision: profile.revision,
            }, Some(&context.user_id)).await?;
            let mut session = session();
            session.context = context.clone();
            let authority = Arc::new(SyntheticAuthority::new(session));
            let adapter = epoch(&authority, &store, &pool).await?;
            Ok::<_, anyhow::Error>((pool, provider, store, authority, adapter, record, profile, context, owner))
        }.await;
        match setup {
            Ok((pool, provider, store, authority, adapter, record, profile, context, owner)) => {
                Ok(Self {
                    db,
                    pool,
                    provider,
                    store,
                    authority,
                    adapter,
                    record,
                    profile,
                    context,
                    owner,
                })
            }
            Err(error) => {
                db.finish(Err(error)).await?;
                unreachable!("failed setup always returns its error")
            }
        }
    }

    /// Another hosted epoch of this fixture's runtime, admitted as the bridge
    /// admits one: its own empty material cache and its first authority
    /// decision, evaluated at admission.
    pub(super) async fn epoch(&self) -> Result<Arc<Adapter>> {
        epoch(&self.authority, &self.store, &self.pool).await
    }

    /// Another replica's provider outside any hosted bridge epoch: no
    /// material cache and no authority decision, so every lease runs the
    /// full per-request checks.
    async fn second(&self) -> Result<(PgPool, Adapter)> {
        let (pool, _) = self.db.broker_pool().await?;
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            self.provider.clone(),
            builtin_provider_catalog(),
        ));
        let adapter = Adapter::connect(
            self.authority.clone(),
            store,
            PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
        )
        .await?;
        Ok((pool, adapter))
    }

    pub(super) async fn state(&self) -> Result<OAuthRefreshState> {
        Ok(self
            .store
            .current_oauth_refresh_attempt(&self.owner, &self.record.metadata.id)
            .await?
            .context("synthetic refresh attempt missing")?
            .state)
    }

    async fn rebind(&self) -> Result<()> {
        let manager =
            PlatformAccessProfileStore::new(self.db.pool.clone(), builtin_provider_catalog());
        let changed = manager
            .update(
                &self.owner,
                &self.profile.id,
                self.profile.revision,
                self.profile.entries.clone(),
            )
            .await?;
        manager
            .replace_binding(
                &self.context,
                &EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: self.profile.id.clone(),
                    profile_revision: self.profile.revision,
                },
                EnvironmentAccessBinding {
                    environment_id: self.context.environment_id.clone(),
                    profile_id: changed.id,
                    profile_revision: changed.revision,
                },
                Some(&self.context.user_id),
            )
            .await?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        sqlx::query("UPDATE environments SET desired_state='stopped' WHERE id=$1")
            .bind(self.context.environment_id.as_str())
            .execute(&self.db.pool)
            .await?;
        Ok(())
    }

    async fn expire_started(&self) -> Result<()> {
        sqlx::query(
            "WITH expired AS (SELECT clock_timestamp()-interval '1 second' AS at) \
            UPDATE platform_credential_refresh_attempts SET started_until=expired.at, \
            started_at=expired.at-interval '90 seconds' FROM expired WHERE credential_id=$1",
        )
        .bind(self.record.metadata.id.as_str())
        .execute(&self.db.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn finish(self, result: Result<()>) -> Result<()> {
        self.pool.close().await;
        self.db.finish(result).await
    }
}

/// A hosted bridge epoch as `admit` in `platform/bridge.rs` builds one.
async fn epoch(
    authority: &Arc<SyntheticAuthority>,
    store: &Arc<PlatformCredentialStore>,
    pool: &PgPool,
) -> Result<Arc<Adapter>> {
    let adapter = Adapter {
        material: Some(EpochMaterialCache::new()),
        decision: Some(EpochDecision::new()),
        ..Adapter::connect(
            authority.clone(),
            store.clone(),
            PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
        )
        .await?
    };
    adapter.admit_authority().await?;
    Ok(Arc::new(adapter))
}

#[test]
fn session_shape_requires_two_exact_pods_platform_scope_and_finite_live_identity() {
    let valid = session();
    for attack in [
        "nil relay",
        "nil workspace",
        "same pod",
        "local",
        "generation",
        "organization",
        "owner",
        "expiry",
    ] {
        let mut invalid = valid.clone();
        match attack {
            "nil relay" => invalid.relay_mut().uid = Uuid::nil(),
            "nil workspace" => invalid.workspace_mut().uid = Uuid::nil(),
            "same pod" => *invalid.workspace_mut() = invalid.relay_mut().clone(),
            "local" => invalid.context.placement = GrantPlacement::Local,
            "generation" => invalid.context.environment_generation = 0,
            "organization" => invalid.context.organization_id = None,
            "owner" => {
                invalid.credential_owner = Owner::User(OwnerId::parse("another-user").unwrap())
            }
            "expiry" => invalid.identity_expires_at_unix = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            invalid.validate(),
            Err(PlatformRuntimeError::Denied),
            "{attack}"
        );
    }
}

#[test]
fn runtime_binding_includes_both_pod_uids_and_exact_owner_policy() {
    let valid = session();
    for attack in ["relay", "workspace", "generation", "user", "policy"] {
        let mut changed = valid.clone();
        match attack {
            "relay" => changed.relay_mut().uid = Uuid::new_v4(),
            "workspace" => changed.workspace_mut().uid = Uuid::new_v4(),
            "generation" => changed.context.environment_generation += 1,
            "user" => changed.context.user_id = OwnerId::parse("another-user").unwrap(),
            "policy" => changed.context.allow_personal_credentials = false,
            _ => unreachable!(),
        }
        assert!(!valid.same_binding(&changed), "{attack}");
    }
    let mut extended = valid.clone();
    extended.identity_expires_at_unix += 100;
    assert!(
        valid.same_binding(&extended),
        "expiry is separately attenuated, never extended"
    );
}

#[test]
fn runtime_errors_are_closed_and_have_no_upstream_source() {
    use std::error::Error;
    for error in [
        PlatformRuntimeError::Denied,
        PlatformRuntimeError::Unavailable,
    ] {
        assert!(error.source().is_none());
        assert!(
            !format!("{error:?}: {error}").contains("synthetic-provider-error-input-never-public")
        );
    }
    assert_eq!(
        published(CredentialVersion {
            revocation_generation: u64::MAX,
            material_generation: 1
        }),
        None
    );
    assert!(has_provider_budget(Duration::ZERO));
    assert!(has_provider_budget(Duration::from_secs(59)));
    assert!(!has_provider_budget(Duration::from_secs(60)));
    assert!(!has_provider_budget(Duration::from_secs(90)));
    assert!(!has_provider_budget(Duration::MAX));
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn restricted_role_leases_refreshes_and_admits_only_the_published_generation() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (initial, timings) = crate::timing::measure(lease(&f.adapter)).await;
        let initial = initial?;
        // The epoch's admission evaluated authority. The lease reuses that
        // decision, rereads only its credential's record, then reads the
        // material.
        ensure!(
            (
                timings.authority.count,
                timings.grants.count,
                timings.record.count,
                timings.material_read.count
            ) == (0, 0, 1, 1)
        );
        ensure!(timings.authority_decision == crate::timing::AuthorityUse::Reused);
        ensure!(
            initial.grant().expires_at_unix == Some(f.adapter.session.identity_expires_at_unix)
        );
        ensure!(initial.material_generation() == 1);
        initial.with_material(|bytes| {
            ensure!(
                crate::codex_oauth::CodexOAuthCredential::parse(bytes)?.refresh_token()
                    == "synthetic-refresh-old"
            );
            Ok(())
        })?;
        let request = request(&f.adapter).await?;
        let started = f
            .adapter
            .start_credential_refresh(reserve(&f.adapter, request).await?)
            .await?;
        ensure!(f.state().await? == OAuthRefreshState::Started);
        f.adapter
            .commit_credential_refresh(started, bundle(false, "new"))
            .await?;
        // The published generation changed the record: the very next lease
        // evaluates again and reads the new value.
        let (current, timings) = crate::timing::measure(lease(&f.adapter)).await;
        let current = current?;
        ensure!(timings.authority_decision == crate::timing::AuthorityUse::Evaluated);
        ensure!(current.material_generation() == 2);
        ensure!(current.grant().credential_revocation_generation == 2);
        current.with_material(|bytes| {
            ensure!(
                crate::codex_oauth::CodexOAuthCredential::parse(bytes)?.refresh_token()
                    == "synthetic-refresh-new"
            );
            Ok(())
        })?;
        let denied = sqlx::query("UPDATE environments SET state=state")
            .execute(&f.pool)
            .await
            .unwrap_err();
        ensure!(
            denied
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("42501")
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

/// Apply one credential or runtime state change through the database.
pub(super) async fn mutate(f: &Fixture, mutation: &str) -> Result<()> {
    match mutation {
        // A rotation: new material for the same credential.
        "replace" => {
            let current = f.store.record(&f.owner, &f.record.metadata.id).await?;
            f.store
                .replace(
                    &f.owner,
                    &current.metadata.id,
                    current.version,
                    &value(bundle(false, "replacement").as_bytes()),
                    None,
                )
                .await?;
        }
        "revoke" => {
            let current = f.store.record(&f.owner, &f.record.metadata.id).await?;
            f.store
                .revoke(&f.owner, &f.record.metadata.id, current.version)
                .await?;
        }
        "expiry" => {
            sqlx::query("UPDATE platform_credentials SET expires_at_unix=0 WHERE id=$1")
                .bind(f.record.metadata.id.as_str())
                .execute(&f.db.pool)
                .await?;
        }
        "rebind" => f.rebind().await?,
        "stop" => f.stop().await?,
        "generation" => {
            sqlx::query("UPDATE environments SET environment_operation_generation=8 WHERE id=$1")
                .bind(f.context.environment_id.as_str())
                .execute(&f.db.pool)
                .await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(super) fn refresh_token(lease: PlatformCredentialLease) -> Result<String> {
    lease.with_material(|bytes| {
        Ok(crate::codex_oauth::CodexOAuthCredential::parse(bytes)?
            .refresh_token()
            .to_owned())
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn the_material_fence_follows_replacement_and_rejects_revocation_and_expiry_during_unwrap()
-> Result<()> {
    for mutation in [
        "replace",
        "revoke",
        "expiry",
        "rebind",
        "stop",
        "generation",
    ] {
        let f = Fixture::create().await?;
        let result = async {
            let calls = f.authority.calls();
            f.provider.unwrap_gate.arm();
            let operation = spawn({
                let adapter = f.adapter.clone();
                async move { crate::timing::measure(lease(&adapter)).await }
            });
            f.provider.unwrap_gate.wait().await?;
            mutate(&f, mutation).await?;
            f.provider.unwrap_gate.release();
            let (leased, timings) = finish_task(operation).await?;
            match mutation {
                // The store's final fence fails the stale version; the lease
                // evaluates once and retries with the replacement.
                "replace" => {
                    let leased = leased?;
                    ensure!(leased.material_generation() == 2);
                    ensure!(refresh_token(leased)? == "synthetic-refresh-replacement");
                    ensure!((timings.grants.count, timings.material_read.count) == (1, 2));
                    ensure!(f.authority.calls() == calls + 1);
                }
                // Revocation withholds only this capability until Reconnect.
                "revoke" => ensure!(
                    matches!(leased, Err(BrokerLeaseError::ReconnectRequired)),
                    "revoke exposed stale material ({:?})",
                    leased.err()
                ),
                "expiry" => ensure!(
                    matches!(leased, Err(BrokerLeaseError::Denied)),
                    "expiry exposed stale material ({:?})",
                    leased.err()
                ),
                // Runtime and environment authority may take up to a minute
                // to apply: the epoch's decision still stands for this lease.
                _ => {
                    ensure!(
                        leased.is_ok(),
                        "{mutation} was not served from the decision ({:?})",
                        leased.err()
                    );
                    ensure!(f.authority.calls() == calls);
                }
            }
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

/// Change one coordinate of the synthetic runtime authority's responses.
fn change_authority(session: &mut PlatformRuntimeSession, mutation: &str) {
    match mutation {
        "relay" => session.relay_mut().uid = Uuid::new_v4(),
        "workspace" => session.workspace_mut().uid = Uuid::new_v4(),
        "policy" => session.context.authorized_credentials.clear(),
        // As after the account deletes and reconnects a credential: the hosted
        // binding is unchanged, but a different credential is authorized.
        "authorized set replaced" => {
            session.context.authorized_credentials =
                [CredentialId::parse(Uuid::new_v4().to_string()).unwrap()].into()
        }
        "personal-policy" => session.context.allow_personal_credentials = false,
        "expiry" => session.identity_expires_at_unix = 0,
        _ => unreachable!(),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn start_rechecks_original_binding_after_reservation_and_cancels_only_reserved() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        let reserved = reserve(&f.adapter, request(&f.adapter).await?).await?;
        f.rebind().await?;
        ensure!(matches!(
            f.adapter.start_credential_refresh(reserved).await,
            Err(BrokerRefreshError::Denied)
        ));
        ensure!(f.state().await? == OAuthRefreshState::Cancelled);
        ensure!(
            f.store
                .record(&f.owner, &f.record.metadata.id)
                .await?
                .version
                == f.record.version
        );
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn start_rechecks_runtime_and_profile_after_durable_transition_before_returning_send_permit()
-> Result<()> {
    for mutation in ["rebind", "stop", "workspace", "expiry"] {
        let f = Fixture::create().await?;
        let result = async {
            let reserved = reserve(&f.adapter, request(&f.adapter).await?).await?;
            f.authority.gate.arm(3); // two pre-Start checks, then post-commit admission
            let start = spawn({
                let adapter = f.adapter.clone();
                async move { adapter.start_credential_refresh(reserved).await }
            });
            f.authority.gate.wait().await?;
            ensure!(f.state().await? == OAuthRefreshState::Started);
            match mutation {
                "rebind" => f.rebind().await?,
                "stop" => f.stop().await?,
                "workspace" => f
                    .authority
                    .change(|session| session.workspace_mut().uid = Uuid::new_v4()),
                "expiry" => f
                    .authority
                    .change(|session| session.identity_expires_at_unix = 0),
                _ => unreachable!(),
            }
            f.authority.gate.release();
            ensure!(matches!(
                finish_task(start).await?,
                Err(BrokerRefreshError::Denied)
            ));
            ensure!(f.state().await? == OAuthRefreshState::Unknown);
            ensure!(
                f.store
                    .record(&f.owner, &f.record.metadata.id)
                    .await?
                    .metadata
                    .status
                    == CredentialStatus::RefreshFailed
            );
            Ok(())
        }
        .await;
        f.finish(result).await?;
    }
    Ok(())
}

async fn wait_for_database_blocker(pool: &PgPool, holder: i32) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity a \
                WHERE a.datname=current_database() AND $1::integer=ANY(pg_catalog.pg_blocking_pids(a.pid)))")
                .bind(holder).fetch_one(pool).await?;
            if blocked { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("final admission never reached the exact synthetic SQL blocker")?
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn started_admission_rechecks_pod_identity_after_sql_lock_waits() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let reservation = reserve(&f.adapter, request(&f.adapter).await?).await?;
        // Pause immediately before the final admission's first runtime read.
        f.authority.gate.arm(3);
        let operation = spawn({
            let adapter = f.adapter.clone();
            async move {
                adapter
                    .start_credential_refresh(reservation)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}"))
            }
        });
        f.authority.gate.wait().await?;
        let mut holder = f.db.pool.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *holder)
            .await?;
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE")
            .bind(f.context.environment_id.as_str())
            .fetch_one(&mut *holder)
            .await?;
        f.authority.gate.release();
        wait_for_database_blocker(&f.db.pool, pid).await?;
        f.authority
            .change(|session| session.workspace_mut().uid = Uuid::new_v4());
        holder.commit().await?;
        ensure!(
            finish_task(operation).await? == Err("Denied".into()),
            "start retained identity across a SQL wait"
        );
        ensure!(f.state().await? == OAuthRefreshState::Unknown);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn started_execution_must_still_be_live_after_post_start_admission_waits() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let reserved = reserve(&f.adapter, request(&f.adapter).await?).await?;
        f.authority.gate.arm(3);
        let start = spawn({
            let adapter = f.adapter.clone();
            async move { adapter.start_credential_refresh(reserved).await }
        });
        f.authority.gate.wait().await?;
        ensure!(f.state().await? == OAuthRefreshState::Started);
        f.expire_started().await?;
        f.authority.gate.release();
        ensure!(matches!(
            finish_task(start).await?,
            Err(BrokerRefreshError::Denied)
        ));
        ensure!(f.state().await? == OAuthRefreshState::Unknown);
        // The failed refresh withholds this capability until Reconnect.
        ensure!(matches!(
            lease(&f.adapter).await,
            Err(BrokerLeaseError::ReconnectRequired)
        ));
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn independent_replicas_share_reserved_and_started_exclusion_without_sharing_send_permits()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (pool, second) = f.second().await?;
        let first_request = request(&f.adapter).await?;
        let mut second_request = first_request.clone();
        second_request.refresh_id = Uuid::new_v4();
        let (first, other) = tokio::join!(
            f.adapter.begin_credential_refresh(first_request),
            second.begin_credential_refresh(second_request.clone())
        );
        let (owner, reserved) = match (first, other) {
            (
                Ok(BrokerRefreshAdmission::Reserved(reserved)),
                Err(BrokerRefreshError::InProgress),
            ) => (&*f.adapter, reserved),
            (
                Err(BrokerRefreshError::InProgress),
                Ok(BrokerRefreshAdmission::Reserved(reserved)),
            ) => (&second, reserved),
            _ => anyhow::bail!("two replicas did not select exactly one reservation owner"),
        };
        let started = owner.start_credential_refresh(reserved).await?;
        ensure!(matches!(
            f.adapter.begin_credential_refresh(second_request).await,
            Err(BrokerRefreshError::InProgress)
        ));
        owner.fail_credential_refresh(started).await?;
        ensure!(f.state().await? == OAuthRefreshState::Unknown);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn expired_reserved_attempt_can_be_replaced_but_its_original_permit_cannot_start()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let old = reserve(&f.adapter, request(&f.adapter).await?).await?;
        sqlx::query("UPDATE platform_credential_refresh_attempts SET reserved_until=clock_timestamp()-interval '1 second' WHERE credential_id=$1")
            .bind(f.record.metadata.id.as_str()).execute(&f.db.pool).await?;
        let (pool, second) = f.second().await?;
        let fresh = reserve(&second, request(&second).await?).await?;
        ensure!(matches!(f.adapter.start_credential_refresh(old).await, Err(BrokerRefreshError::Unavailable)));
        let started = second.start_credential_refresh(fresh).await?;
        second.fail_credential_refresh(started).await?;
        pool.close().await;
        Ok(())
    }.await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn lost_start_ack_is_not_a_second_send_permit_and_expired_started_fails_closed() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        let original = request(&f.adapter).await?;
        let reserved = reserve(&f.adapter, original.clone()).await?;
        f.authority.gate.arm(3);
        let start = spawn({
            let adapter = f.adapter.clone();
            async move { adapter.start_credential_refresh(reserved).await }
        });
        f.authority.gate.wait().await?;
        ensure!(f.state().await? == OAuthRefreshState::Started);
        // The database committed, but the caller never received its send permit.
        start.abort();
        ensure!(matches!(tokio::time::timeout(TIMEOUT, start).await?, Err(error) if error.is_cancelled()));
        let (pool, second) = f.second().await?;
        let mut retry = original;
        retry.refresh_id = Uuid::new_v4();
        ensure!(matches!(
            second.begin_credential_refresh(retry.clone()).await,
            Err(BrokerRefreshError::InProgress)
        ));
        f.expire_started().await?;
        ensure!(matches!(
            second.begin_credential_refresh(retry).await,
            Err(BrokerRefreshError::Denied)
        ));
        ensure!(f.state().await? == OAuthRefreshState::Unknown);
        ensure!(matches!(
            lease(&second).await,
            Err(BrokerLeaseError::ReconnectRequired)
        ));
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn two_replicas_recover_exact_staged_output_even_after_the_execution_deadline() -> Result<()>
{
    let f = Fixture::create().await?;
    let result = async {
        let original = request(&f.adapter).await?;
        let started = f
            .adapter
            .start_credential_refresh(reserve(&f.adapter, original.clone()).await?)
            .await?;
        let result = started
            .started
            .prepare_result(&value(bundle(false, "recovered").as_bytes()))?;
        f.store.stage_oauth_refresh(&result).await?;
        drop(started);
        f.expire_started().await?;
        let (pool, second) = f.second().await?;
        let mut a = original.clone();
        a.refresh_id = Uuid::new_v4();
        let mut b = original;
        b.refresh_id = Uuid::new_v4();
        let (a, b) = tokio::join!(
            f.adapter.begin_credential_refresh(a),
            second.begin_credential_refresh(b)
        );
        // A racing reader can observe the publication between its profile and
        // record reads and safely ask the shared runtime for another admission.
        ensure!(matches!(
            a,
            Ok(BrokerRefreshAdmission::Recovered)
                | Err(BrokerRefreshError::Stale)
                | Err(BrokerRefreshError::Denied)
        ));
        ensure!(matches!(
            b,
            Ok(BrokerRefreshAdmission::Recovered)
                | Err(BrokerRefreshError::Stale)
                | Err(BrokerRefreshError::Denied)
        ));
        ensure!(f.state().await? == OAuthRefreshState::Committed);
        ensure!(lease(&second).await?.material_generation() == 2);
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn committed_receipt_recovers_only_its_predecessor_and_does_not_block_a_new_refresh()
-> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let predecessor = request(&f.adapter).await?;
        let started = f
            .adapter
            .start_credential_refresh(reserve(&f.adapter, predecessor.clone()).await?)
            .await?;
        f.adapter
            .commit_credential_refresh(started, bundle(false, "published"))
            .await?;
        ensure!(matches!(
            f.adapter
                .begin_credential_refresh(predecessor.clone())
                .await?,
            BrokerRefreshAdmission::Recovered
        ));
        let mut unrelated = predecessor;
        unrelated.material_generation += 40;
        ensure!(matches!(
            f.adapter.begin_credential_refresh(unrelated).await,
            Err(BrokerRefreshError::Stale)
        ));
        let current = request(&f.adapter).await?;
        ensure!(current.material_generation == 2);
        let reserved = reserve(&f.adapter, current).await?;
        f.adapter.abort_credential_refresh(reserved).await?;
        ensure!(f.state().await? == OAuthRefreshState::Cancelled);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn original_request_and_connected_identity_deadlines_can_only_be_attenuated() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let mut original = request(&f.adapter).await?;
        let connected_deadline = original
            .grant
            .expires_at_unix
            .context("finite identity deadline")?;
        f.authority
            .change(|session| session.identity_expires_at_unix += 10_000);
        ensure!(lease(&f.adapter).await?.grant().expires_at_unix == Some(connected_deadline));
        let mut invalid = original.clone();
        invalid.grant.expires_at_unix = None;
        ensure!(matches!(
            f.adapter.begin_credential_refresh(invalid).await,
            Err(BrokerRefreshError::Denied)
        ));
        let mut invalid = original.clone();
        invalid.grant.expires_at_unix = Some(connected_deadline + 1);
        ensure!(matches!(
            f.adapter.begin_credential_refresh(invalid).await,
            Err(BrokerRefreshError::Denied)
        ));
        original.grant.expires_at_unix = Some(unix_now()? + 2);
        let reserved = reserve(&f.adapter, original.clone()).await?;
        tokio::time::timeout(Duration::from_secs(4), async {
            while unix_now().unwrap() < original.grant.expires_at_unix.unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        ensure!(matches!(
            f.adapter.start_credential_refresh(reserved).await,
            Err(BrokerRefreshError::Denied)
        ));
        ensure!(f.state().await? == OAuthRefreshState::Cancelled);
        Ok(())
    }
    .await;
    f.finish(result).await
}

#[derive(Clone, Default)]
struct SyntheticTransport {
    gate: Arc<SessionGate>,
    refresh_calls: Arc<AtomicUsize>,
    provider_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl crate::BrokerUpstreamTransport for SyntheticTransport {
    async fn execute(
        &self,
        request: crate::BrokerUpstreamRequest,
    ) -> Result<crate::BrokerUpstreamResponse, crate::BrokerUpstreamError> {
        let (_, url, _, _) = request.into_parts();
        let body = if url.as_str() == "https://auth.openai.com/oauth/token" {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            self.gate.pass().await;
            serde_json::to_vec(&serde_json::json!({"access_token":token(serde_json::json!({"exp":unix_now().unwrap()+7_200})),
                "refresh_token":"synthetic-refresh-shutdown", "id_token":id_token()})).unwrap()
        } else if url.as_str() == "https://chatgpt.com/backend-api/codex/responses" {
            self.provider_calls.fetch_add(1, Ordering::SeqCst);
            b"data: {}\n\n".to_vec()
        } else {
            return Err(crate::BrokerUpstreamError::Protocol);
        };
        Ok(crate::BrokerUpstreamResponse::new(
            http::StatusCode::OK,
            http::HeaderMap::new(),
            Box::pin(futures::stream::iter([Ok(bytes::Bytes::from(body))])),
        ))
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn shared_shutdown_drains_platform_publication_after_guest_and_session_loss() -> Result<()> {
    let f = Fixture::create().await?;
    let result = async {
        let (pool, adapter) = f.second().await?;
        let transport = SyntheticTransport::default();
        transport.gate.arm(1);
        let broker = Arc::new(crate::OpenAiBroker::new(adapter, transport.clone())?);
        let operation = spawn({
            let broker = broker.clone();
            async move {
                broker
                    .execute(
                        codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeRequest {
                            capability_slot: "codex".into(),
                            route: "openai-api".into(),
                            request_id: Uuid::new_v4().to_string(),
                            method: "POST".into(),
                            path: "/responses".into(),
                            headers: vec![
                                codewire_gateway_proto::codewire::bridge::v1::CredentialHttpHeader {
                                    name: "content-type".into(),
                                    value: b"application/json".to_vec(),
                                },
                            ],
                            body: br#"{"model":"gpt-5","input":"synthetic"}"#.to_vec(),
                            ..Default::default()
                        },
                    )
                    .await
            }
        });
        transport.gate.wait().await?;
        ensure!(f.state().await? == OAuthRefreshState::Started);
        operation.abort();
        ensure!(matches!(tokio::time::timeout(TIMEOUT, operation).await?, Err(error) if error.is_cancelled()));
        f.authority
            .change(|session| session.identity_expires_at_unix = 0);
        f.provider.unwrap_gate.arm();
        transport.gate.release();
        f.provider.unwrap_gate.wait().await?; // staged output, promotion's OpenBao fence
        let mut shutdown = spawn({
            let broker = broker.clone();
            async move { broker.wait_for_active_operations().await }
        });
        ensure!(
            tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown abandoned durable publication"
        );
        f.provider.unwrap_gate.release();
        finish_task(shutdown).await??;
        ensure!(f.state().await? == OAuthRefreshState::Committed);
        ensure!(transport.refresh_calls.load(Ordering::SeqCst) == 1);
        ensure!(transport.provider_calls.load(Ordering::SeqCst) == 0);
        ensure!(matches!(
            lease(&f.adapter).await,
            Err(BrokerLeaseError::Denied)
        ));
        pool.close().await;
        Ok(())
    }
    .await;
    f.finish(result).await
}
