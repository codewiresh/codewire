use super::*;
use codewire_access::{AccessProfileId, CredentialId, EnvironmentId, GrantProfile, OwnerId};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sqlx::{PgPool, postgres::PgPoolOptions};

use super::tests::support::SyntheticKek;

fn owner_local(profile_selected: bool) -> PlatformRuntimeSession {
    let context = GrantContext {
        environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
        environment_generation: 7,
        placement: GrantPlacement::PlatformToLocal,
        user_id: OwnerId::parse("synthetic-owner").unwrap(),
        organization_id: Some(OwnerId::parse("synthetic-org").unwrap()),
        allow_personal_credentials: profile_selected,
        authorized_credentials: if profile_selected {
            [CredentialId::parse(Uuid::new_v4().to_string()).unwrap()].into()
        } else {
            Default::default()
        },
    };
    let profile = profile_selected.then(|| EnvironmentAccessBinding {
        environment_id: context.environment_id.clone(),
        profile_id: AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap(),
        profile_revision: 3,
    });
    PlatformRuntimeSession::owner_local(
        context.clone(),
        Owner::User(context.user_id),
        profile,
        [7; 32],
        unix_now().unwrap() + 60,
    )
    .unwrap()
}

#[test]
fn owner_local_profile_and_projection_only_are_distinct_closed_bindings() {
    for selected in [false, true] {
        let session = owner_local(selected);
        assert!(session.validate().is_ok());
        let RuntimeIdentity::OwnerLocal { profile, .. } = &session.identity else {
            panic!("owner-local session acquired a Pod identity");
        };
        assert_eq!(profile.is_some(), selected);
        assert_eq!(
            session.context.placement.credential_storage(),
            Placement::Platform
        );
        assert_eq!(
            session.context.placement.execution_target(),
            Placement::Local
        );
        let mut invalid = session.clone();
        invalid.context.placement = GrantPlacement::Platform;
        assert_eq!(invalid.validate(), Err(PlatformRuntimeError::Denied));
        invalid.context.placement = GrantPlacement::Local;
        assert_eq!(invalid.validate(), Err(PlatformRuntimeError::Denied));
    }
}

#[test]
fn owner_local_session_rejects_unbound_or_invalid_runtime_selection() {
    for attack in [
        "zero generation",
        "huge generation",
        "noncanonical environment",
        "nil environment",
        "missing org",
        "wrong owner",
        "expired",
        "wrong profile environment",
        "zero revision",
        "huge revision",
        "noncanonical profile",
        "empty hash",
        "missing profile",
    ] {
        let mut invalid = owner_local(true);
        match attack {
            "zero generation" => invalid.context.environment_generation = 0,
            "huge generation" => invalid.context.environment_generation = u64::MAX,
            "noncanonical environment" => {
                invalid.context.environment_id = EnvironmentId::parse("host-label").unwrap()
            }
            "nil environment" => {
                invalid.context.environment_id =
                    EnvironmentId::parse(Uuid::nil().to_string()).unwrap()
            }
            "missing org" => invalid.context.organization_id = None,
            "wrong owner" => {
                invalid.credential_owner = Owner::User(OwnerId::parse("another-owner").unwrap())
            }
            "expired" => invalid.identity_expires_at_unix = unix_now().unwrap(),
            _ => {
                let RuntimeIdentity::OwnerLocal {
                    profile,
                    selection_sha256,
                } = &mut invalid.identity
                else {
                    unreachable!()
                };
                match attack {
                    "wrong profile environment" => {
                        profile.as_mut().unwrap().environment_id =
                            EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap()
                    }
                    "zero revision" => profile.as_mut().unwrap().profile_revision = 0,
                    "huge revision" => profile.as_mut().unwrap().profile_revision = u64::MAX,
                    "noncanonical profile" => {
                        profile.as_mut().unwrap().profile_id =
                            AccessProfileId::parse("profile-label").unwrap()
                    }
                    "empty hash" => *selection_sha256 = [0; 32],
                    "missing profile" => *profile = None,
                    _ => unreachable!(),
                }
            }
        }
        assert_eq!(
            invalid.validate(),
            Err(PlatformRuntimeError::Denied),
            "{attack}"
        );
    }
}

#[test]
fn owner_local_same_binding_fences_selection_and_identity_kind() {
    let session = owner_local(true);
    for attack in [
        "environment",
        "generation",
        "user",
        "organization",
        "profile",
        "revision",
        "hash",
        "placement",
        "hosted",
    ] {
        let mut changed = session.clone();
        match attack {
            "environment" => {
                changed.context.environment_id =
                    EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            "generation" => changed.context.environment_generation += 1,
            "user" => changed.context.user_id = OwnerId::parse("changed-owner").unwrap(),
            "organization" => {
                changed.context.organization_id = Some(OwnerId::parse("changed-org").unwrap())
            }
            "placement" => changed.context.placement = GrantPlacement::Platform,
            "hosted" => {
                changed.identity = RuntimeIdentity::Hosted {
                    gateway: PlatformPodIdentity {
                        namespace: "synthetic".into(),
                        name: "gateway".into(),
                        uid: Uuid::new_v4(),
                    },
                    workspace: PlatformPodIdentity {
                        namespace: "synthetic".into(),
                        name: "workspace".into(),
                        uid: Uuid::new_v4(),
                    },
                }
            }
            _ => {
                let RuntimeIdentity::OwnerLocal {
                    profile,
                    selection_sha256,
                } = &mut changed.identity
                else {
                    unreachable!()
                };
                match attack {
                    "profile" => {
                        profile.as_mut().unwrap().profile_id =
                            AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap()
                    }
                    "revision" => profile.as_mut().unwrap().profile_revision += 1,
                    "hash" => selection_sha256[0] ^= 1,
                    _ => unreachable!(),
                }
            }
        }
        assert!(!session.same_binding(&changed), "{attack}");
    }
    let mut renewed = session.clone();
    renewed.identity_expires_at_unix += 1;
    assert!(session.same_binding(&renewed));
    // Expiry is not binding equality: the provider separately clamps the
    // returned session to its original deadline on every admission.
}

struct IdentityOnly(PlatformRuntimeSession);

#[async_trait]
impl PlatformRuntimeAuthority for IdentityOnly {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn owner_local_identity_alone_cannot_issue_grant_descriptions() {
    let authority = IdentityOnly(owner_local(true));
    assert_eq!(
        authority.owner_local_grants(&authority.0).await,
        Err(PlatformRuntimeError::Denied)
    );
}

fn hosted_pods() -> (PlatformPodIdentity, PlatformPodIdentity) {
    let pod = |name: &str| PlatformPodIdentity {
        namespace: "synthetic-workloads".into(),
        name: name.into(),
        uid: Uuid::new_v4(),
    };
    (pod("gateway"), pod("workspace"))
}

#[test]
fn hosted_constructor_rejects_owner_local_context_even_with_valid_pods() {
    let local = owner_local(true);
    let (gateway, workspace) = hosted_pods();
    assert_eq!(
        PlatformRuntimeSession::new(
            gateway,
            workspace,
            local.context,
            local.credential_owner,
            local.identity_expires_at_unix,
        ),
        Err(PlatformRuntimeError::Denied),
    );
}

fn permission() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse("responses").unwrap(),
        route: BrokerRouteId::parse("openai-api").unwrap(),
    }
}

fn description(session: &PlatformRuntimeSession) -> DerivedGrant {
    let RuntimeIdentity::OwnerLocal {
        profile: Some(profile),
        ..
    } = &session.identity
    else {
        panic!("synthetic grant requires an explicit selected profile");
    };
    DerivedGrant {
        environment_id: session.context.environment_id.clone(),
        environment_generation: session.context.environment_generation,
        profile: Some(GrantProfile {
            id: profile.profile_id.clone(),
            revision: profile.profile_revision,
        }),
        capability_slot: CapabilitySlot::codex(),
        credential_id: session
            .context
            .authorized_credentials
            .first()
            .unwrap()
            .clone(),
        credential_revocation_generation: 1,
        expires_at_unix: Some(session.identity_expires_at_unix),
        permissions: [permission()].into(),
    }
}

struct DescriptionsAuthority {
    session: Mutex<PlatformRuntimeSession>,
    descriptions: Mutex<Vec<DerivedGrant>>,
    description_calls: AtomicUsize,
    /// When set, each grant evaluation waits for one `gate` permit, so a test
    /// can hold leases inside their authority work.
    gated: AtomicBool,
    gate: tokio::sync::Semaphore,
    inside: AtomicUsize,
    most_inside: AtomicUsize,
}

#[async_trait]
impl PlatformRuntimeAuthority for DescriptionsAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        Ok(self.session.lock().unwrap().clone())
    }

    async fn owner_local_grants(
        &self,
        expected: &PlatformRuntimeSession,
    ) -> Result<Vec<DerivedGrant>, PlatformRuntimeError> {
        self.description_calls.fetch_add(1, Ordering::SeqCst);
        assert!(expected.same_binding(&self.session.lock().unwrap()));
        if self.gated.load(Ordering::SeqCst) {
            let inside = self.inside.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_inside.fetch_max(inside, Ordering::SeqCst);
            self.gate.acquire().await.unwrap().forget();
            self.inside.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(self.descriptions.lock().unwrap().clone())
    }
}

struct ClosedDatabaseFixture {
    adapter: PlatformBrokerLeaseProvider<DescriptionsAuthority>,
    authority: Arc<DescriptionsAuthority>,
    kek: Arc<SyntheticKek>,
    pool: PgPool,
}

impl ClosedDatabaseFixture {
    async fn new(session: PlatformRuntimeSession, descriptions: Vec<DerivedGrant>) -> Self {
        // Reuse the existing synthetic lazy-pool boundary. Close before any
        // consumer can acquire a connection: no network or SQL can execute.
        // PoolClosed maps to Unavailable, distinguishable from pre-read Denied.
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic?sslmode=disable")
            .unwrap();
        pool.close().await;
        assert!(matches!(pool.acquire().await, Err(sqlx::Error::PoolClosed)));
        let kek = Arc::new(SyntheticKek::default());
        let catalog = codewire_access::builtin_provider_catalog();
        let credentials = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            kek.clone(),
            catalog.clone(),
        ));
        let profiles = PlatformAccessProfileStore::new(pool.clone(), catalog);
        let authority = Arc::new(DescriptionsAuthority {
            session: Mutex::new(session),
            descriptions: Mutex::new(descriptions),
            description_calls: AtomicUsize::new(0),
            gated: AtomicBool::new(false),
            gate: tokio::sync::Semaphore::new(0),
            inside: AtomicUsize::new(0),
            most_inside: AtomicUsize::new(0),
        });
        let adapter =
            PlatformBrokerLeaseProvider::connect(authority.clone(), credentials, profiles)
                .await
                .unwrap();
        Self {
            adapter,
            authority,
            kek,
            pool,
        }
    }

    async fn assert_admit_error(&self, expected: BrokerLeaseError) {
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            self.adapter.admit(&CapabilitySlot::codex(), permission()),
        )
        .await
        .expect("synthetic denial tried to wait for a database or upstream");
        assert!(matches!(result, Err(error) if error == expected));
        assert_eq!(self.kek.generate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.kek.unwrap_calls.load(Ordering::SeqCst), 0);
        assert!(self.pool.is_closed());
    }
}

#[tokio::test]
async fn owner_local_admit_rejects_malformed_grants_before_credential_lookup() {
    let session = owner_local(true);
    let valid = description(&session);
    let fixture = ClosedDatabaseFixture::new(session, vec![valid.clone()]).await;
    // Positive discriminator: a well-bound description reaches record lookup
    // and the deliberately closed pool, not an accidental policy denial.
    fixture
        .assert_admit_error(BrokerLeaseError::Unavailable)
        .await;
    let mut expected_calls = 1;
    for attack in [
        "environment",
        "generation",
        "profile",
        "revision",
        "credential",
        "slot",
        "permission",
        "empty",
        "bad trailing grant",
    ] {
        let mut invalid = valid.clone();
        match attack {
            "environment" => {
                invalid.environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            "generation" => invalid.environment_generation += 1,
            "profile" => {
                invalid.profile.as_mut().unwrap().id =
                    AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            "revision" => invalid.profile.as_mut().unwrap().revision += 1,
            "credential" => {
                invalid.credential_id = CredentialId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            "slot" => invalid.capability_slot = CapabilitySlot::github(),
            "permission" => invalid.permissions.clear(),
            "bad trailing grant" => invalid.profile.as_mut().unwrap().revision += 1,
            "empty" => {}
            _ => unreachable!(),
        }
        *fixture.authority.descriptions.lock().unwrap() = match attack {
            "empty" => vec![],
            "bad trailing grant" => vec![valid.clone(), invalid],
            _ => vec![invalid],
        };
        fixture.assert_admit_error(BrokerLeaseError::Denied).await;
        expected_calls += 1;
        assert_eq!(
            fixture.authority.description_calls.load(Ordering::SeqCst),
            expected_calls,
            "{attack}"
        );
    }
}

#[tokio::test]
async fn admission_timing_counts_each_authority_grant_and_record_call() {
    let session = owner_local(true);
    let valid = description(&session);
    let fixture = ClosedDatabaseFixture::new(session, vec![valid]).await;
    let counts = |timings: &crate::timing::Timings| {
        (
            timings.authority.count,
            timings.grants.count,
            timings.record.count,
            timings.material_read.count,
        )
    };
    // One authority check, one grant evaluation and one record read, which
    // fails on the closed pool before a second check or any material read.
    let (admitted, timings) = crate::timing::measure(
        fixture
            .adapter
            .admit(&CapabilitySlot::codex(), permission()),
    )
    .await;
    assert!(matches!(admitted, Err(BrokerLeaseError::Unavailable)));
    assert_eq!(counts(&timings), (1, 1, 1, 0));
    let (leased, timings) = crate::timing::measure(fixture.adapter.lease_operation(
        Uuid::new_v4(),
        CapabilitySlot::codex(),
        permission().operation,
        permission().route,
    ))
    .await;
    assert!(matches!(leased, Err(BrokerLeaseError::Unavailable)));
    assert_eq!(counts(&timings), (1, 1, 1, 0));
    assert_eq!(timings.resolve.count, 0);
    assert_eq!(
        fixture.authority.description_calls.load(Ordering::SeqCst),
        2
    );
}

fn lease_operation(
    adapter: &PlatformBrokerLeaseProvider<DescriptionsAuthority>,
) -> impl Future<Output = Result<PlatformCredentialLease, BrokerLeaseError>> + '_ {
    adapter.lease_operation(
        Uuid::new_v4(),
        CapabilitySlot::codex(),
        permission().operation,
        permission().route,
    )
}

#[tokio::test]
async fn lease_budget_bounds_concurrent_leases_and_queues_the_rest() {
    const CAPACITY: usize = 2;
    const LEASES: usize = 5;
    let session = owner_local(true);
    let valid = description(&session);
    let mut fixture = ClosedDatabaseFixture::new(session, vec![valid]).await;
    let budget = LeaseBudget::new(CAPACITY);
    fixture.adapter.leases = Some(budget.clone());
    let authority = fixture.authority.clone();
    authority.gated.store(true, Ordering::SeqCst);
    let leases = futures::future::join_all((0..LEASES).map(|_| lease_operation(&fixture.adapter)));
    let release = async {
        for released in 0..LEASES {
            // Quiescent: the budget is full of leases inside authority work
            // and every other lease is queued for a slot, not failed.
            let inside = CAPACITY.min(LEASES - released);
            tokio::time::timeout(Duration::from_secs(1), async {
                while authority.inside.load(Ordering::SeqCst) != inside
                    || budget.available() != CAPACITY - inside
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("leases did not settle inside the budget");
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert_eq!(authority.inside.load(Ordering::SeqCst), inside);
            assert_eq!(
                authority.description_calls.load(Ordering::SeqCst),
                released + inside
            );
            authority.gate.add_permits(1);
        }
    };
    let (results, ()) = tokio::join!(leases, release);
    // Every lease ran its authority work, then failed only on the closed pool.
    assert!(
        results
            .iter()
            .all(|result| matches!(result, Err(BrokerLeaseError::Unavailable)))
    );
    assert_eq!(authority.description_calls.load(Ordering::SeqCst), LEASES);
    assert_eq!(authority.most_inside.load(Ordering::SeqCst), CAPACITY);
    assert_eq!(budget.available(), CAPACITY);
}

#[tokio::test]
async fn a_queued_lease_waits_until_its_identity_expiry_and_no_longer() {
    let (log, _guard) = crate::timing::tests::TimingLog::install();
    let session = owner_local(true);
    let expires_in = session.identity_expires_at_unix - unix_now().unwrap();
    let valid = description(&session);
    let mut fixture = ClosedDatabaseFixture::new(session, vec![valid]).await;
    let budget = LeaseBudget::new(1);
    let held = Arc::clone(&budget.permits).try_acquire_owned().unwrap();
    fixture.adapter.leases = Some(budget.clone());
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let (leased, timings) = crate::timing::measure(lease_operation(&fixture.adapter)).await;
    let waited = started.elapsed();
    assert!(matches!(leased, Err(BrokerLeaseError::Unavailable)));
    assert!(waited > Duration::from_secs(expires_in.saturating_sub(2)));
    assert!(waited <= Duration::from_secs(expires_in));
    // Timing uses wall-clock time, which this paused test does not advance.
    assert_eq!(timings.lease_wait.count, 1);
    // It never started authority, database or KEK work.
    assert_eq!(timings.authority.count, 0);
    assert_eq!(
        fixture.authority.description_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(fixture.kek.unwrap_calls.load(Ordering::SeqCst), 0);
    let rejected: Vec<_> = log
        .lines()
        .into_iter()
        .inspect(crate::timing::tests::assert_secret_free)
        .filter(|line| line["fields"]["event"] == "capacity_rejected")
        .map(|line| line["fields"].clone())
        .collect();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["limit"], "broker_leases");
    assert_eq!(rejected[0]["operation"], "lease");
    assert_eq!(rejected[0]["capacity"], 1);
    assert_eq!(rejected[0]["in_use"], 1);
    // A closed budget (service shutdown) fails a lease at once.
    budget.close();
    let started = tokio::time::Instant::now();
    assert!(matches!(
        lease_operation(&fixture.adapter).await,
        Err(BrokerLeaseError::Unavailable)
    ));
    assert_eq!(started.elapsed(), Duration::ZERO);
    drop(held);
}

#[tokio::test]
async fn owner_local_app_only_admit_never_asks_for_profile_grants_or_material() {
    let fixture =
        ClosedDatabaseFixture::new(owner_local(false), vec![description(&owner_local(true))]).await;
    fixture.assert_admit_error(BrokerLeaseError::Denied).await;
    assert_eq!(
        fixture.authority.description_calls.load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn connected_owner_local_session_rejects_rebinding_before_grant_dispatch() {
    let original = owner_local(true);
    let fixture = ClosedDatabaseFixture::new(original.clone(), vec![description(&original)]).await;
    for attack in [
        "environment",
        "generation",
        "user",
        "organization",
        "profile",
        "revision",
        "hash",
        "authorized credentials",
        "personal policy",
        "hosted",
    ] {
        let mut changed = original.clone();
        match attack {
            "environment" => {
                changed.context.environment_id =
                    EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
                let RuntimeIdentity::OwnerLocal {
                    profile: Some(profile),
                    ..
                } = &mut changed.identity
                else {
                    unreachable!()
                };
                profile.environment_id = changed.context.environment_id.clone();
            }
            "generation" => changed.context.environment_generation += 1,
            "user" => {
                changed.context.user_id = OwnerId::parse("changed-owner").unwrap();
                changed.credential_owner = Owner::User(changed.context.user_id.clone());
            }
            "organization" => {
                changed.context.organization_id = Some(OwnerId::parse("changed-org").unwrap())
            }
            "authorized credentials" => {
                changed.context.authorized_credentials =
                    [CredentialId::parse(Uuid::new_v4().to_string()).unwrap()].into()
            }
            "personal policy" => changed.context.allow_personal_credentials = false,
            "hosted" => {
                let (gateway, workspace) = hosted_pods();
                changed.identity = RuntimeIdentity::Hosted { gateway, workspace };
                changed.context.placement = GrantPlacement::Platform;
            }
            _ => {
                let RuntimeIdentity::OwnerLocal {
                    profile: Some(profile),
                    selection_sha256,
                } = &mut changed.identity
                else {
                    unreachable!()
                };
                match attack {
                    "profile" => {
                        profile.profile_id =
                            AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap()
                    }
                    "revision" => profile.profile_revision += 1,
                    "hash" => selection_sha256[0] ^= 1,
                    _ => unreachable!(),
                }
            }
        }
        // Each replacement is independently valid. The connected original
        // binding, not malformed-shape rejection, must stop its adoption.
        assert!(changed.validate().is_ok(), "{attack}");
        *fixture.authority.session.lock().unwrap() = changed;
        assert_eq!(
            fixture.adapter.session().await,
            Err(BrokerLeaseError::Denied),
            "{attack}"
        );
        fixture.assert_admit_error(BrokerLeaseError::Denied).await;
        assert_eq!(
            fixture.authority.description_calls.load(Ordering::SeqCst),
            0,
            "{attack}"
        );
    }
}

#[tokio::test]
async fn connected_owner_local_session_clamps_original_and_newly_shorter_expiry() {
    let original = owner_local(true);
    let original_expiry = original.identity_expires_at_unix;
    let mut fixture =
        ClosedDatabaseFixture::new(original.clone(), vec![description(&original)]).await;
    fixture
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix = original_expiry + 3_600;
    assert_eq!(
        fixture
            .adapter
            .session()
            .await
            .unwrap()
            .identity_expires_at_unix,
        original_expiry
    );
    fixture
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix = original_expiry - 10;
    assert_eq!(
        fixture
            .adapter
            .session()
            .await
            .unwrap()
            .identity_expires_at_unix,
        original_expiry - 10
    );
    fixture
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix = unix_now().unwrap();
    assert_eq!(
        fixture.adapter.session().await,
        Err(BrokerLeaseError::Denied)
    );
    // Simulate the connected deadline elapsing without a real-time sleep: a
    // fresh authority response cannot revive that already-connected instance.
    fixture.adapter.session.identity_expires_at_unix = unix_now().unwrap();
    fixture
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix = original_expiry + 3_600;
    assert_eq!(
        fixture.adapter.session().await,
        Err(BrokerLeaseError::Denied)
    );
    assert_eq!(
        fixture.authority.description_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(fixture.kek.unwrap_calls.load(Ordering::SeqCst), 0);
    assert!(fixture.pool.is_closed());
}

#[test]
fn hosted_binding_follows_current_authorization_but_fences_every_coordinate() {
    let local = owner_local(true);
    let (gateway, workspace) = hosted_pods();
    let context = GrantContext {
        placement: GrantPlacement::Platform,
        ..local.context.clone()
    };
    let session = PlatformRuntimeSession::new(
        gateway,
        workspace,
        context,
        local.credential_owner.clone(),
        local.identity_expires_at_unix,
    )
    .unwrap();
    // Deleting and reconnecting GitHub changes only the authorized set.
    let mut reconnected = session.clone();
    reconnected.context.authorized_credentials =
        [CredentialId::parse(Uuid::new_v4().to_string()).unwrap()]
            .into_iter()
            .collect();
    assert!(session.same_authority(&reconnected));
    let mut deleted = session.clone();
    deleted.context.authorized_credentials.clear();
    assert!(session.same_authority(&deleted));
    for attack in [
        "environment",
        "generation",
        "user",
        "organization",
        "personal",
        "gateway",
        "owner",
    ] {
        let mut changed = session.clone();
        match attack {
            "environment" => {
                changed.context.environment_id =
                    EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            "generation" => changed.context.environment_generation += 1,
            "user" => changed.context.user_id = OwnerId::parse("changed-owner").unwrap(),
            "organization" => {
                changed.context.organization_id = Some(OwnerId::parse("changed-org").unwrap())
            }
            "personal" => {
                changed.context.allow_personal_credentials =
                    !changed.context.allow_personal_credentials
            }
            "gateway" => changed.gateway_mut().uid = Uuid::new_v4(),
            "owner" => changed.credential_owner = Owner::User(OwnerId::parse("other").unwrap()),
            _ => unreachable!(),
        }
        assert!(!session.same_authority(&changed), "{attack}");
    }
}
