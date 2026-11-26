//! Platform credential storage adapter for an isolated broker, not a listener.
//!
//! The runtime authority is a trusted, process-local dependency. Its eventual
//! implementation must authenticate either the exact relay/workload Pods or
//! the original owner OAuth session delegating to a local runtime, and resolve
//! current owner/policy from platform authority. The identity variants cannot
//! substitute for one another. Guest coordinates, a configured token lifetime,
//! or an unverified JWT do not establish authority. This module authenticates
//! nobody and does not activate a listener.
//!
//! PostgreSQL serializes refresh across replicas. Only durable Start returns a
//! send permit. A staged result is recoverable bookkeeping, never permission to
//! use material. The shared broker owns the 30-second provider timeout and
//! tracks Start through terminal publication; storage owns the 90-second
//! abandonment fence. This adapter creates no detached placement work.

pub mod bridge;
mod decision;
mod grant_checks;
use grant_checks::{Checked, ensure_live, record_matches, same_grant_binding, select_grant};
mod login_admission;
use login_admission::{DeliveryPredicate, claude_login_admissible, codex_login_admissible};
pub mod keepalive;
mod lease;
pub use lease::PlatformCredentialLease;
mod placeholders;
mod refresh_errors;
mod runtime_errors;
use crate::RateLimitClose;
use refresh_errors::{refresh_lease_error, refresh_store_error};
pub use runtime_errors::PlatformRuntimeError;
use runtime_errors::runtime_error;
#[cfg(all(feature = "ssh-agent", target_os = "linux"))]
mod ssh;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_access::{
    AvailableGrants, BrokerOperationId, BrokerRouteId,
    CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS, CapabilitySlot, CredentialAuthKind,
    CredentialId, CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentAccessBinding,
    GrantContext, GrantPermission, GrantPlacement, Owner, PROVIDER_REFRESH_TIMEOUT_SECONDS,
    Placement, WithheldReason, claude_login_permission, codex_login_permission,
};
use codewire_platform_credentials::{
    CredentialRecord, CredentialVersion, EpochMaterialCache, OAuthRefreshState,
    PlatformAccessProfileStore, PlatformCredentialError, PlatformCredentialStore,
    PlatformProfileError, PreparedOAuthRefresh, StartedOAuthRefresh,
};
use codewire_protected_store::ProtectedValue;
use uuid::Uuid;

use crate::commit_failure::{taken_bundle, valid_bundle};
use crate::timing::{self, AuthorityUse, MaterialCacheUse, Phase};
use crate::{
    BrokerCredentialRefreshKind, BrokerCredentialRefreshRequest, BrokerLeaseError,
    BrokerLeaseProvider, BrokerRefreshAdmission, BrokerRefreshError, CanonicalClaudeOAuthBundle,
    CanonicalCodexOAuthBundle, CommitFailure, GitHubAppUserOAuthBundle,
};
pub use decision::AUTHORITY_DECISION_REUSE;
use decision::EpochDecision;
pub(crate) use placeholders::EpochPlaceholders;

/// Exact Pod identity established by a trusted runtime authenticator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformPodIdentity {
    pub namespace: String,
    pub name: String,
    pub uid: Uuid,
}

/// Material-free authenticated session. Construction validates shape, not
/// authentication. Only a trusted [`PlatformRuntimeAuthority`] may supply it.
/// This deliberately has no wire deserializer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformRuntimeSession {
    identity: RuntimeIdentity,
    context: GrantContext,
    credential_owner: Owner,
    identity_expires_at_unix: u64,
}

/// Closed process-local authentication bindings. Local coordinates are an
/// authenticated owner's assertion, never a purported Kubernetes identity.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RuntimeIdentity {
    /// The credential relay (orchestration) Pod that carries the bound
    /// workspace's bridge, and that workspace Pod.
    Hosted {
        relay: PlatformPodIdentity,
        workspace: PlatformPodIdentity,
    },
    OwnerLocal {
        profile: Option<EnvironmentAccessBinding>,
        selection_sha256: [u8; 32],
    },
}

impl PlatformRuntimeSession {
    /// Bind current server-authorized scope to already-authenticated identities.
    /// The finite deadline must come from the exact successfully authenticated
    /// identity, not `now + projected_token_lifetime`. Token rotation may create
    /// a new session; it cannot extend an already connected broker's authority.
    pub fn new(
        relay: PlatformPodIdentity,
        workspace: PlatformPodIdentity,
        context: GrantContext,
        credential_owner: Owner,
        identity_expires_at_unix: u64,
    ) -> Result<Self, PlatformRuntimeError> {
        let session = Self {
            identity: RuntimeIdentity::Hosted { relay, workspace },
            context,
            credential_owner,
            identity_expires_at_unix,
        };
        session.validate()?;
        Ok(session)
    }

    /// Bind a trusted owner's explicit platform selection to one local runtime
    /// operation. Only the owner-OAuth authority may establish this session; the
    /// constructor checks shape, not authentication, consent or live membership.
    /// No platform environment row, synthetic Pod, stored grant or second
    /// lifecycle generation is created. Absence of a profile permits projection
    /// only, not provider credential access.
    pub fn owner_local(
        context: GrantContext,
        credential_owner: Owner,
        profile: Option<EnvironmentAccessBinding>,
        selection_sha256: [u8; 32],
        identity_expires_at_unix: u64,
    ) -> Result<Self, PlatformRuntimeError> {
        let session = Self {
            identity: RuntimeIdentity::OwnerLocal {
                profile,
                selection_sha256,
            },
            context,
            credential_owner,
            identity_expires_at_unix,
        };
        session.validate()?;
        Ok(session)
    }

    fn validate(&self) -> Result<(), PlatformRuntimeError> {
        match &self.identity {
            RuntimeIdentity::Hosted { relay, workspace } => {
                if relay == workspace || self.context.placement != GrantPlacement::Platform {
                    return Err(PlatformRuntimeError::Denied);
                }
                for pod in [relay, workspace] {
                    for value in [&pod.namespace, &pod.name] {
                        if value.is_empty()
                            || value.len() > 253
                            || !value
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
                        {
                            return Err(PlatformRuntimeError::Denied);
                        }
                    }
                    if pod.uid.is_nil() {
                        return Err(PlatformRuntimeError::Denied);
                    }
                }
            }
            RuntimeIdentity::OwnerLocal {
                profile,
                selection_sha256,
            } => {
                let canonical_uuid = |value: &str| {
                    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
                };
                if self.context.placement != GrantPlacement::PlatformToLocal
                    || !canonical_uuid(self.context.environment_id.as_str())
                    || self.context.environment_generation > i64::MAX as u64
                    || *selection_sha256 == [0; 32]
                {
                    return Err(PlatformRuntimeError::Denied);
                }
                match profile {
                    Some(profile)
                        if profile.environment_id == self.context.environment_id
                            && canonical_uuid(profile.profile_id.as_str())
                            && profile.profile_revision > 0
                            && profile.profile_revision <= i64::MAX as u64 => {}
                    None if self.context.authorized_credentials.is_empty() => {}
                    _ => return Err(PlatformRuntimeError::Denied),
                }
            }
        }
        let owner_matches = match &self.credential_owner {
            Owner::User(id) => id == &self.context.user_id,
            Owner::Organization(id) => self.context.organization_id.as_ref() == Some(id),
        };
        if self.context.environment_generation == 0
            || self.context.organization_id.is_none()
            || !owner_matches
            || self.identity_expires_at_unix <= unix_now()?
        {
            return Err(PlatformRuntimeError::Denied);
        }
        Ok(())
    }

    /// Every coordinate of the admitted binding is fixed. For a hosted
    /// environment the authorized credentials are not: launch authority
    /// recomputes them from current state on every admission, so deleting or
    /// reconnecting the account's GitHub connection applies to a running
    /// sandbox without a new bridge, and a removed credential is never granted.
    /// An owner-local selection keeps its exact authorized set.
    fn same_binding(&self, other: &Self) -> bool {
        let GrantContext {
            environment_id,
            environment_generation,
            placement,
            user_id,
            organization_id,
            allow_personal_credentials,
            authorized_credentials,
        } = &self.context;
        let hosted = matches!(self.identity, RuntimeIdentity::Hosted { .. });
        self.identity == other.identity
            && *environment_id == other.context.environment_id
            && *environment_generation == other.context.environment_generation
            && *placement == other.context.placement
            && *user_id == other.context.user_id
            && *organization_id == other.context.organization_id
            && *allow_personal_credentials == other.context.allow_personal_credentials
            && (hosted || *authorized_credentials == other.context.authorized_credentials)
            && self.credential_owner == other.credential_owner
    }

    /// Whether `current` is still this admitted session's exact binding, as
    /// [`Self::same_binding`] defines it, for a runtime authority to recheck.
    pub fn same_authority(&self, current: &Self) -> bool {
        self.same_binding(current)
    }

    /// Whether `other` is this exact response apart from its expiry: the same
    /// authenticated identity, credential owner and whole grant context,
    /// including the authorized credentials that [`Self::same_binding`]
    /// deliberately lets a hosted session follow. A lease evaluates both of its
    /// grant reads against one response, so the response read after them must
    /// still authorize exactly that context. Expiry is attenuated separately.
    fn same_except_expiry(&self, other: &Self) -> bool {
        let Self {
            identity,
            context,
            credential_owner,
            identity_expires_at_unix: _,
        } = self;
        *identity == other.identity
            && *context == other.context
            && *credential_owner == other.credential_owner
    }

    #[cfg(test)]
    fn relay_mut(&mut self) -> &mut PlatformPodIdentity {
        let RuntimeIdentity::Hosted { relay, .. } = &mut self.identity else {
            panic!("test requires a hosted session");
        };
        relay
    }

    #[cfg(test)]
    fn workspace_mut(&mut self) -> &mut PlatformPodIdentity {
        let RuntimeIdentity::Hosted { workspace, .. } = &mut self.identity else {
            panic!("test requires a hosted session");
        };
        workspace
    }
}

/// Trusted runtime authority, not an adapter for guest-provided coordinates.
/// Revalidate live Pod UIDs/deletion, environment generation, owner/policy and
/// the verified identity's deadline on every call. No implementation is supplied
/// here; a caller cannot activate platform brokerage with storage context alone.
#[async_trait]
pub trait PlatformRuntimeAuthority: Send + Sync {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError>;

    /// Reevaluate an owner's exact explicit profile selection without a hosted
    /// environment row. The owner-OAuth implementation must compare the entire
    /// expected session binding and compose the original OAuth token and current
    /// source authority fences with profile/credential evaluation in one SQL
    /// transaction. These material-free descriptions are not transferable
    /// authorization. Hosted authenticators cannot use this path by default.
    /// A capability withheld for its credential's lifecycle comes back in
    /// `reconnect_required`, never as a grant (#4909).
    async fn owner_local_grants(
        &self,
        _expected: &PlatformRuntimeSession,
    ) -> Result<AvailableGrants, PlatformRuntimeError> {
        Err(PlatformRuntimeError::Denied)
    }

    /// Only recipient ciphertext for the sources already bound by the trusted
    /// authority. An identity-only test adapter remains explicitly deny-only.
    async fn project_environment(
        &self,
        _request: codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, PlatformRuntimeError> {
        Err(PlatformRuntimeError::Denied)
    }

    /// Fixed-Platform fragment for an authenticated native owner's mixed
    /// launch. Hosted authorities stay deny-only; this never selects a remote
    /// source outside the channel's immutable platform selection.
    async fn project_environment_fragment(
        &self,
        _request: codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<
        codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionComposition,
        PlatformRuntimeError,
    > {
        Err(PlatformRuntimeError::Denied)
    }
}

/// One connected runtime identity and its isolated, least-authority stores.
pub struct PlatformBrokerLeaseProvider<A> {
    authority: Arc<A>,
    session: PlatformRuntimeSession,
    instance_id: Uuid,
    credentials: Arc<PlatformCredentialStore>,
    profiles: PlatformAccessProfileStore,
    /// The bridge service's shared concurrent-lease budget, if any.
    leases: Option<LeaseBudget>,
    /// This epoch's reusable decrypted values. Only a bridge epoch has one;
    /// it is created at admission and dropped with the epoch, and is never
    /// shared with another epoch or the SSH signer.
    material: Option<EpochMaterialCache>,
    /// This hosted epoch's reusable authority decision. Only a hosted bridge
    /// epoch has one; it is created at admission and dropped with the epoch.
    /// Without one, every lease runs full per-request checks.
    decision: Option<EpochDecision>,
    /// This hosted epoch's derived placeholders (#4001). Only a hosted epoch
    /// has them, and only while the credential service's hosted placeholders
    /// setting is on; created at admission and dropped with the epoch.
    placeholders: Option<EpochPlaceholders>,
    /// Where this hosted epoch's credential uses fold, under its workspace
    /// binding (#6189). Only a hosted epoch of a service that reports them.
    uses: Option<crate::credential_uses::EpochUses>,
    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    ssh: Option<ssh::Epoch>,
}

/// One process-wide budget of concurrent leases, shared by every epoch of one
/// bridge service. A slot covers exactly one lease: its record read, any
/// authority evaluation it runs or waits for (or its full per-request checks),
/// and its protected-material read (SQL and the KEK unwrap) or reuse from its
/// epoch's material cache; never provider I/O, a refresh or a response body.
/// A lease waits for a slot in arrival order until its connected
/// identity's original expiry, the deadline that already bounds that lease, so
/// a burst queues instead of failing.
#[derive(Clone)]
pub(crate) struct LeaseBudget {
    permits: Arc<tokio::sync::Semaphore>,
    capacity: usize,
}

impl LeaseBudget {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            capacity,
        }
    }

    /// Fail every waiting and later lease; held slots finish normally.
    pub(crate) fn close(&self) {
        self.permits.close();
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.permits.available_permits()
    }

    async fn acquire(
        &self,
        expires_at_unix: u64,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, BrokerLeaseError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let deadline = Duration::from_secs(expires_at_unix)
            .checked_sub(now)
            .and_then(|remaining| tokio::time::Instant::now().checked_add(remaining))
            .ok_or(BrokerLeaseError::Denied)?;
        let acquired = timing::timed(
            Phase::LeaseWait,
            tokio::time::timeout_at(deadline, Arc::clone(&self.permits).acquire_owned()),
        )
        .await;
        match acquired {
            Ok(Ok(permit)) => Ok(permit),
            // Closed by shutdown.
            Ok(Err(_)) => Err(BrokerLeaseError::Unavailable),
            Err(_) => {
                timing::capacity_rejected(
                    "broker_leases",
                    "lease",
                    self.capacity,
                    self.capacity
                        .saturating_sub(self.permits.available_permits()),
                );
                Err(BrokerLeaseError::Unavailable)
            }
        }
    }
}

/// Private process-local reservation. Possession does not authorize sending.
pub struct PlatformRefreshReservation {
    instance_id: Uuid,
    request: BrokerCredentialRefreshRequest,
    prepared: PreparedOAuthRefresh,
}

/// Private process-local proof of a successful durable Start and final runtime
/// admission. It cannot be reconstructed from a database receipt.
pub struct PlatformStartedRefresh {
    instance_id: Uuid,
    request: BrokerCredentialRefreshRequest,
    started: StartedOAuthRefresh,
}

struct Admission {
    record: CredentialRecord,
    grant: DerivedGrant,
    permission: GrantPermission,
}

impl<A: PlatformRuntimeAuthority> PlatformBrokerLeaseProvider<A> {
    /// Capture an authenticated session inside the isolated broker. These
    /// handles must never be installed in a relay, daemon or metadata service.
    pub async fn connect(
        authority: Arc<A>,
        credentials: Arc<PlatformCredentialStore>,
        profiles: PlatformAccessProfileStore,
    ) -> Result<Self, PlatformRuntimeError> {
        let session = timing::timed(Phase::Authority, authority.current_session()).await?;
        session.validate()?;
        Ok(Self {
            authority,
            session,
            instance_id: Uuid::new_v4(),
            credentials,
            profiles,
            leases: None,
            material: None,
            decision: None,
            placeholders: None,
            uses: None,
            #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
            ssh: None,
        })
    }

    /// Drop any value this epoch reuses for `credential`.
    fn forget_material(&self, credential: &CredentialId) {
        if let Some(material) = &self.material {
            material.evict(credential);
        }
    }

    /// A runtime that authority or grant evaluation denies may reuse nothing.
    fn forget_material_on_denial<T>(
        &self,
        result: Result<T, BrokerLeaseError>,
    ) -> Result<T, BrokerLeaseError> {
        if let (Err(error), Some(material)) = (&result, &self.material)
            && error.is_denial()
        {
            material.clear();
        }
        result
    }

    async fn session(&self) -> Result<PlatformRuntimeSession, BrokerLeaseError> {
        let mut current = timing::timed(Phase::Authority, self.authority.current_session())
            .await
            .map_err(runtime_error)?;
        current.validate().map_err(runtime_error)?;
        if !self.session.same_binding(&current) {
            return Err(BrokerLeaseError::Denied);
        }
        current.identity_expires_at_unix = current
            .identity_expires_at_unix
            .min(self.session.identity_expires_at_unix);
        current.validate().map_err(runtime_error)?;
        Ok(current)
    }

    /// One runtime authority check, the grant and record reads, then a second
    /// check that attenuates the deadline. Refresh and SSH admissions use this.
    async fn admit(
        &self,
        slot: &CapabilitySlot,
        permission: GrantPermission,
    ) -> Result<Admission, BrokerLeaseError> {
        let session = self.session().await?;
        let mut admission = self
            .grant_and_record(&session, slot, permission)
            .await
            .map_err(Checked::refused)?;
        // The profile/record reads can wait for SQL locks. Their completion
        // cannot preserve runtime authority that was revoked during that wait.
        let current = self.session().await?;
        admission.grant.expires_at_unix = admission
            .grant
            .expires_at_unix
            .map(|deadline| deadline.min(current.identity_expires_at_unix));
        ensure_live(&admission.record.metadata, &admission.grant)?;
        Ok(admission)
    }

    /// Evaluate the slot's grant for `session` and read its credential record.
    /// This performs no runtime authority check of its own: every caller reads
    /// the authority again after it, before releasing anything it admits.
    async fn grant_and_record(
        &self,
        session: &PlatformRuntimeSession,
        slot: &CapabilitySlot,
        permission: GrantPermission,
    ) -> Result<Admission, Checked> {
        let available = self.available_grants(session).await?;
        let grant = select_grant(&available, session, slot, &permission)?;
        let record = match self
            .read_record(&session.credential_owner, &grant.credential_id)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                self.forget_material(&grant.credential_id);
                return Err(error.into());
            }
        };
        if !record_matches(&record, &grant, &session.credential_owner) {
            self.forget_material(&grant.credential_id);
            return Err(Checked::moved(&grant, &session.credential_owner, &record));
        }
        Ok(Admission {
            record,
            grant,
            permission,
        })
    }

    /// One grant evaluation for `session`. A denial drops every value this
    /// epoch retains; otherwise only values of credentials that no current
    /// grant names are dropped.
    async fn available_grants(
        &self,
        session: &PlatformRuntimeSession,
    ) -> Result<AvailableGrants, BrokerLeaseError> {
        let available = async {
            match &session.identity {
                RuntimeIdentity::Hosted { .. } => timing::timed(
                    Phase::Grants,
                    self.profiles.evaluate_grants(&session.context),
                )
                .await
                .map_err(profile_error),
                RuntimeIdentity::OwnerLocal {
                    profile: Some(profile),
                    ..
                } => {
                    let available =
                        timing::timed(Phase::Grants, self.authority.owner_local_grants(session))
                            .await
                            .map_err(runtime_error)?;
                    if available.grants.iter().any(|grant| {
                        grant.environment_id != session.context.environment_id
                            || grant.environment_generation
                                != session.context.environment_generation
                            || grant.profile.as_ref().is_none_or(|granted| {
                                granted.id != profile.profile_id
                                    || granted.revision != profile.profile_revision
                            })
                            || !session
                                .context
                                .authorized_credentials
                                .contains(&grant.credential_id)
                    }) {
                        return Err(BrokerLeaseError::Denied);
                    }
                    // A capability withheld for its lifecycle answers
                    // Reconnect for its own slot only (#4909).
                    Ok(available)
                }
                RuntimeIdentity::OwnerLocal { profile: None, .. } => Err(BrokerLeaseError::Denied),
            }
        }
        .await;
        let available = self.forget_material_on_denial(available)?;
        // A value whose credential no current grant names, such as one that
        // was revoked, rebound or now needs Reconnect, is never reused again.
        if let Some(material) = &self.material {
            material.retain_credentials(|id| {
                available
                    .grants
                    .iter()
                    .any(|grant| grant.credential_id == *id)
            });
        }
        Ok(available)
    }

    /// One read of a credential's current record: a single indexed
    /// statement by id and exact owner.
    async fn read_record(
        &self,
        owner: &Owner,
        credential: &CredentialId,
    ) -> Result<CredentialRecord, BrokerLeaseError> {
        timing::timed(Phase::Record, self.credentials.record(owner, credential))
            .await
            .map_err(credential_error)
    }

    /// The value this epoch retains for exactly `record`, when the lease may
    /// reuse one (never for SSH keys), and the cache a successful read fills.
    /// Records the lease's material cache use.
    fn reusable(
        &self,
        record: &CredentialRecord,
        allowed: bool,
    ) -> (Option<&EpochMaterialCache>, Option<ProtectedValue>) {
        let cache = self.material.as_ref().filter(|_| {
            allowed && record.metadata.authentication_kind != CredentialAuthKind::SshKey
        });
        let reused = cache.and_then(|cache| cache.get(record));
        timing::material_cache(match (cache, &reused) {
            (None, _) => MaterialCacheUse::Bypass,
            (Some(_), Some(_)) => MaterialCacheUse::Hit,
            (Some(_), None) => MaterialCacheUse::Miss,
        });
        (cache, reused)
    }

    /// One protected-material read for exactly `record`'s version.
    async fn read_material(
        &self,
        record: &CredentialRecord,
    ) -> Result<ProtectedValue, PlatformCredentialError> {
        timing::timed(
            Phase::MaterialRead,
            self.credentials.read_for_broker(
                &record.metadata.owner,
                &record.metadata.id,
                record.version,
            ),
        )
        .await
    }

    /// One lease. A hosted bridge epoch serves it from its authority decision
    /// (`decision.rs`); a Codex login delivery, an owner-local delegation
    /// epoch, and a provider that no hosted epoch admitted run the full
    /// per-request checks of [`Self::lease_checked`].
    async fn lease(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
        permission: GrantPermission,
        admissible: Option<DeliveryPredicate>,
    ) -> Result<PlatformCredentialLease, BrokerLeaseError> {
        if request_id.is_nil() {
            return Err(BrokerLeaseError::InvalidRequest);
        }
        // Held until this lease returns: many epochs cannot stampede SQL,
        // Kubernetes or the KEK with more than the service's lease budget.
        let _budget = match &self.leases {
            Some(leases) => Some(
                leases
                    .acquire(self.session.identity_expires_at_unix)
                    .await?,
            ),
            None => None,
        };
        let mut lease = match (&self.decision, admissible) {
            (Some(epoch), None) => self.lease_decided(epoch, &slot, &permission).await,
            _ => self.lease_checked(slot, permission, admissible).await,
        }?;
        lease.uses = self.uses.clone();
        if let Some(placeholders) = &self.placeholders
            && placeholders::leases_carry_placeholders(&self.session.identity)
        {
            match self.placeholder(placeholders, &lease.grant).await {
                Some(placeholder) => lease.placeholder = Some(placeholder),
                None => lease.placeholder_failed = true,
            }
        }
        Ok(lease)
    }

    /// One lease with full per-request checks: two runtime authority checks
    /// bracket grant and record reads, the protected-material read, and a
    /// second grant and record read. `admissible`, when present, is a
    /// delivery predicate applied to the session and to both record reads.
    ///
    /// In a bridge epoch, a value this epoch read for exactly the record the
    /// first read returns may replace the protected-material read, and only
    /// that read. Every other step still runs, and the unchanged check that
    /// both record reads are equal is the version fence around the reuse. A
    /// value is retained only at the end of a lease that succeeded. A lease
    /// that fails after selecting a credential drops that credential's value;
    /// a runtime authority or grant denial, or a credential no longer granted,
    /// drops what it can no longer use. Direct delivery (a lease with a
    /// delivery predicate) and SSH keys never reuse or retain material.
    ///
    /// A record that moved to another revocation generation while the lease
    /// read it (a refresh, replacement or Reconnect committed in between)
    /// evaluates the whole lease again once, as the next request would. If
    /// that evaluation refuses too, the lease is denied, as it was before the
    /// record moved. Nothing read for the moved record is released.
    async fn lease_checked(
        &self,
        slot: CapabilitySlot,
        permission: GrantPermission,
        admissible: Option<DeliveryPredicate>,
    ) -> Result<PlatformCredentialLease, BrokerLeaseError> {
        match self
            .lease_checked_once(slot.clone(), permission.clone(), admissible)
            .await
        {
            // A second move is a denial; a departed or disabled creator keeps
            // its name (#6406).
            Err(Checked::Moved) => self
                .lease_checked_once(slot, permission, admissible)
                .await
                .map_err(|checked| match checked {
                    Checked::Refused(
                        error @ (BrokerLeaseError::CreatorDeparted
                        | BrokerLeaseError::CreatorDisabled),
                    ) => error,
                    _ => BrokerLeaseError::Denied,
                }),
            leased => leased.map_err(Checked::refused),
        }
    }

    /// One evaluation of [`Self::lease_checked`].
    async fn lease_checked_once(
        &self,
        slot: CapabilitySlot,
        permission: GrantPermission,
        admissible: Option<DeliveryPredicate>,
    ) -> Result<PlatformCredentialLease, Checked> {
        timing::authority(AuthorityUse::Evaluated);
        // Two runtime authority checks bracket the whole lease. Both grant
        // evaluations use the first response, and the last response must be
        // exactly that one apart from its expiry, so nothing either evaluation
        // relied on can have changed without denying the lease. The response is
        // never kept beyond this lease.
        let initial = self.forget_material_on_denial(self.session().await)?;
        // A delivery predicate refuses before any grant, record or material
        // read it cannot pass, and again for each record read.
        if let Some(admissible) = admissible {
            admissible(&initial, None)?;
        }
        let before = self
            .grant_and_record(&initial, &slot, permission.clone())
            .await?;
        let credential = before.record.metadata.id.clone();
        let leased = async {
            ensure_live(&before.record.metadata, &before.grant)?;
            if let Some(admissible) = admissible {
                admissible(&initial, Some(&before))?;
            }
            // Reuse only a value read for exactly this record: owner, id,
            // provider, kind, status, expiry and both generations.
            let (cache, reused) = self.reusable(&before.record, admissible.is_none());
            let read = reused.is_none();
            let material = match reused {
                Some(material) => material,
                None => self
                    .read_material(&before.record)
                    .await
                    .map_err(|error| match error {
                        PlatformCredentialError::StaleVersion => Checked::Moved,
                        error => credential_error(error).into(),
                    })?,
            };
            #[cfg(test)]
            tests::between_record_reads().await;
            // OpenBao unwrap and SQL lock waits may outlive the original
            // authority. Recheck the exact profile selection and current
            // record, then runtime authority last. Nothing below awaits, so no
            // wait follows that check. A reused value passes this same fence:
            // the record read now must equal the record it was retained for.
            let mut after = self.grant_and_record(&initial, &slot, permission).await?;
            let current = self.forget_material_on_denial(self.session().await)?;
            if !initial.same_except_expiry(&current)
                || before.permission != after.permission
                || !same_grant_binding(&before.grant, &after.grant)
            {
                return Err(BrokerLeaseError::Denied.into());
            }
            if before.record != after.record {
                return Err(Checked::moved(
                    &before.grant,
                    &initial.credential_owner,
                    &after.record,
                ));
            }
            after.grant.expires_at_unix = before
                .grant
                .expires_at_unix
                .min(after.grant.expires_at_unix)
                .map(|deadline| deadline.min(current.identity_expires_at_unix));
            ensure_live(&after.record.metadata, &after.grant)?;
            if let Some(admissible) = admissible {
                admissible(&current, Some(&after))?;
            }
            // Retain only a value this successful lease read itself.
            if let Some(cache) = cache.filter(|_| read) {
                cache.fill(&after.record, &material);
            }
            Ok(PlatformCredentialLease {
                record: after.record,
                grant: after.grant,
                permission: after.permission,
                material,
                placeholder: None,
                placeholder_failed: false,
                uses: None,
            })
        }
        .await;
        if leased.is_err() {
            self.forget_material(&credential);
        }
        leased
    }

    async fn admit_request(
        &self,
        request: &BrokerCredentialRefreshRequest,
    ) -> Result<Admission, BrokerRefreshError> {
        if request.request_id.is_nil()
            || request.refresh_id.is_nil()
            || request.material_generation == 0
            || request.grant.credential_revocation_generation == 0
        {
            return Err(BrokerRefreshError::InvalidRequest);
        }
        let mut admission = self
            .admit(
                &request.grant.capability_slot,
                GrantPermission {
                    operation: request.operation.clone(),
                    route: request.route.clone(),
                },
            )
            .await
            .map_err(refresh_lease_error)?;
        let metadata = &admission.record.metadata;
        let expected_form = match request.kind {
            BrokerCredentialRefreshKind::CodexOAuth => {
                metadata.provider.as_str() == "openai"
                    && metadata.authentication_kind == CredentialAuthKind::OAuth
                    && request.grant.capability_slot.as_str() == "codex"
            }
            BrokerCredentialRefreshKind::GitHubAppUserOAuth => {
                metadata.provider.as_str() == "github"
                    && metadata.authentication_kind == CredentialAuthKind::OAuth
                    && request.grant.capability_slot.as_str() == "github"
            }
            // Never a Claude subscription token, which is the provider's
            // OAuth kind and has no refresh.
            BrokerCredentialRefreshKind::ClaudeOAuth => {
                metadata.provider.as_str() == "anthropic"
                    && metadata.authentication_kind == CredentialAuthKind::ClaudeSignIn
                    && request.grant.capability_slot.as_str() == "anthropic"
            }
        };
        if !expected_form || !same_grant_binding(&admission.grant, &request.grant) {
            return Err(BrokerRefreshError::Denied);
        }
        // A refresh started for login delivery keeps that delivery's whole
        // predicate. Its session facts are fixed by `same_binding`, which
        // every authority check in `admit` enforced against this session.
        if admission.permission == codex_login_permission() {
            codex_login_admissible(&self.session, Some(&admission)).map_err(refresh_lease_error)?;
        }
        if admission.permission == claude_login_permission() {
            claude_login_admissible(&self.session, Some(&admission))
                .map_err(refresh_lease_error)?;
        }
        let requested_deadline = request
            .grant
            .expires_at_unix
            .ok_or(BrokerRefreshError::Denied)?;
        if requested_deadline <= unix_now().map_err(|_| BrokerRefreshError::Unavailable)?
            || admission
                .grant
                .expires_at_unix
                .is_none_or(|current| requested_deadline > current)
        {
            return Err(BrokerRefreshError::Denied);
        }
        admission.grant.expires_at_unix = Some(requested_deadline);
        Ok(admission)
    }

    async fn exact_request(
        &self,
        request: &BrokerCredentialRefreshRequest,
    ) -> Result<(), BrokerRefreshError> {
        let admission = self.admit_request(request).await?;
        if admission.record.version != expected(request) {
            return Err(BrokerRefreshError::Stale);
        }
        Ok(())
    }

    async fn cancel(
        &self,
        request: &BrokerCredentialRefreshRequest,
    ) -> Result<(), BrokerRefreshError> {
        self.credentials
            .cancel_oauth_refresh(
                &self.session.credential_owner,
                &request.grant.credential_id,
                expected(request),
                request.refresh_id,
            )
            .await
            .map_err(refresh_store_error)
    }

    async fn promote(
        &self,
        request: &BrokerCredentialRefreshRequest,
        attempt_id: Uuid,
    ) -> Result<(), BrokerRefreshError> {
        self.credentials
            .promote_oauth_refresh(
                &self.session.credential_owner,
                &request.grant.credential_id,
                expected(request),
                attempt_id,
            )
            .await
            .map(|_| ())
            .map_err(refresh_store_error)
    }

    async fn commit_refresh_value(
        &self,
        permit: PlatformStartedRefresh,
        value: ProtectedValue,
    ) -> Result<(), BrokerRefreshError> {
        if permit.instance_id != self.instance_id {
            return Err(BrokerRefreshError::Denied);
        }
        // Do not discard rotated output merely because a guest disconnected or
        // its grant expired. Publication preserves storage's hard deadline; the
        // shared runtime separately obtains fresh authority before consuming it.
        let published = publish_started_refresh(
            &self.credentials,
            &self.session.credential_owner,
            &permit.request.grant.credential_id,
            expected(&permit.request),
            permit.request.refresh_id,
            permit.started,
            value,
        )
        .await;
        // The published generation no longer matches the retained value's
        // record; drop it now rather than at its expiry.
        self.forget_material(&permit.request.grant.credential_id);
        published
    }
}

/// Durably stage one exact started attempt's rotated material, then promote
/// it. A stage ACK can be lost: discover only this exact immutable attempt as
/// staged or committed; absence of staged output never permits another
/// provider exchange. Shared by on-demand refresh and the keep-alive owner.
pub(crate) async fn publish_started_refresh(
    store: &PlatformCredentialStore,
    owner: &Owner,
    credential_id: &CredentialId,
    expected: CredentialVersion,
    attempt_id: Uuid,
    started: StartedOAuthRefresh,
    value: ProtectedValue,
) -> Result<(), BrokerRefreshError> {
    let result = started
        .prepare_result(&value)
        .map_err(refresh_store_error)?;
    drop(value);
    drop(started);
    if let Err(error) = store.stage_oauth_refresh(&result).await {
        let current = store
            .current_oauth_refresh_attempt(owner, credential_id)
            .await
            .map_err(refresh_store_error)?;
        if !current.is_some_and(|attempt| {
            attempt.attempt_id == attempt_id
                && attempt.expected == expected
                && matches!(
                    attempt.state,
                    OAuthRefreshState::Staged | OAuthRefreshState::Committed
                )
        }) {
            return Err(refresh_store_error(error));
        }
    }
    store
        .promote_oauth_refresh(owner, credential_id, expected, attempt_id)
        .await
        .map(|_| ())
        .map_err(refresh_store_error)
}

#[async_trait]
impl<A: PlatformRuntimeAuthority + 'static> BrokerLeaseProvider for PlatformBrokerLeaseProvider<A> {
    type Lease = PlatformCredentialLease;
    type RefreshReservation = PlatformRefreshReservation;
    type StartedRefresh = PlatformStartedRefresh;

    async fn project_environment_fragment(
        &self,
        request: codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<
        codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionComposition,
        BrokerLeaseError,
    > {
        self.session().await?;
        let deadline = request.deadline_unix_ms;
        let result = self
            .authority
            .project_environment_fragment(request)
            .await
            .map_err(runtime_error)?;
        self.session().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerLeaseError::Unavailable)?
            .as_millis();
        if now >= u128::from(deadline) {
            return Err(BrokerLeaseError::Denied);
        }
        Ok(result)
    }

    async fn project_environment(
        &self,
        request: codewire_daemon_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerLeaseError> {
        self.session().await?;
        let deadline = request.deadline_unix_ms;
        let sealed = self
            .authority
            .project_environment(request)
            .await
            .map_err(runtime_error)?;
        self.session().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerLeaseError::Unavailable)?
            .as_millis();
        if now >= u128::from(deadline) {
            return Err(BrokerLeaseError::Denied);
        }
        Ok(sealed)
    }

    async fn lease_operation(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Self::Lease, BrokerLeaseError> {
        let permission = GrantPermission { operation, route };
        // A login permission is leased only with its delivery predicate.
        if permission == codex_login_permission() || permission == claude_login_permission() {
            return Err(BrokerLeaseError::Denied);
        }
        self.lease(request_id, slot, permission, None).await
    }

    /// A listed direct delivery exception; see [`codex_login_admissible`].
    async fn lease_codex_login(&self, request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        self.lease(
            request_id,
            CapabilitySlot::codex(),
            codex_login_permission(),
            Some(codex_login_admissible),
        )
        .await
    }

    /// The other listed direct delivery exception; see
    /// [`claude_login_admissible`].
    async fn lease_claude_login(&self, request_id: Uuid) -> Result<Self::Lease, BrokerLeaseError> {
        self.lease(
            request_id,
            CapabilitySlot::anthropic(),
            claude_login_permission(),
            Some(claude_login_admissible),
        )
        .await
    }

    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    async fn ssh_operation(
        &self,
        request: codewire_daemon_proto::codewire::bridge::v1::CredentialSshRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<
        codewire_daemon_proto::codewire::bridge::v1::credential_ssh_response::Result,
        BrokerLeaseError,
    > {
        self.retained_ssh_operation(request, cancellation).await
    }

    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<Self::RefreshReservation>, BrokerRefreshError> {
        let admission = self.admit_request(&request).await?;
        let version = expected(&request);
        let attempt = self
            .credentials
            .current_oauth_refresh_attempt(
                &self.session.credential_owner,
                &request.grant.credential_id,
            )
            .await
            .map_err(refresh_store_error)?;
        if let Some(attempt) = attempt {
            // An old committed receipt is irrelevant to a request admitted for
            // the already-published generation; it must not cause a recovery loop.
            if attempt.state == OAuthRefreshState::Committed
                && attempt.expected == version
                && published(version) == Some(admission.record.version)
            {
                return Ok(BrokerRefreshAdmission::Recovered);
            }
            if admission.record.version != version {
                return Err(BrokerRefreshError::Stale);
            }
            match attempt.state {
                OAuthRefreshState::Reserved if attempt.reservation_live => {
                    return Err(BrokerRefreshError::InProgress);
                }
                OAuthRefreshState::Started if attempt.execution_live => {
                    return Err(BrokerRefreshError::InProgress);
                }
                OAuthRefreshState::Staged if attempt.expected == version => {
                    self.promote(&request, attempt.attempt_id).await?;
                    return Ok(BrokerRefreshAdmission::Recovered);
                }
                OAuthRefreshState::Started if attempt.expected == version => {
                    // The send owner neither staged nor failed it before the
                    // durable deadline, for example after process loss.
                    tracing::warn!(
                        provider = match request.kind {
                            BrokerCredentialRefreshKind::CodexOAuth => "openai",
                            BrokerCredentialRefreshKind::GitHubAppUserOAuth => "github",
                            BrokerCredentialRefreshKind::ClaudeOAuth => "anthropic",
                        },
                        failure = "abandoned",
                        "started credential refresh passed its execution deadline without an outcome"
                    );
                    self.credentials
                        .fail_abandoned_oauth_refresh(
                            &self.session.credential_owner,
                            &request.grant.credential_id,
                            version,
                            attempt.attempt_id,
                        )
                        .await
                        .map_err(refresh_store_error)?;
                    return Err(BrokerRefreshError::Denied);
                }
                OAuthRefreshState::Unknown => return Err(BrokerRefreshError::Denied),
                OAuthRefreshState::Staged | OAuthRefreshState::Started => {
                    return Err(BrokerRefreshError::Stale);
                }
                // A rate-limit wait still running is refused by the begin below.
                OAuthRefreshState::Reserved
                | OAuthRefreshState::Committed
                | OAuthRefreshState::Cancelled
                | OAuthRefreshState::RateLimited => {}
            }
        }
        if admission.record.version != version {
            return Err(BrokerRefreshError::Stale);
        }
        let prepared = refresh_errors::begin(
            &self.credentials,
            &self.session.credential_owner,
            (&request.grant.credential_id, version, request.refresh_id),
            self.instance_id,
        )
        .await?;
        Ok(BrokerRefreshAdmission::Reserved(
            PlatformRefreshReservation {
                instance_id: self.instance_id,
                request,
                prepared,
            },
        ))
    }

    async fn start_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<Self::StartedRefresh, BrokerRefreshError> {
        if reservation.instance_id != self.instance_id {
            return Err(BrokerRefreshError::Denied);
        }
        let PlatformRefreshReservation {
            request, prepared, ..
        } = reservation;
        if let Err(error) = self.exact_request(&request).await {
            self.cancel(&request).await?;
            return Err(error);
        }
        // An uncertain Start ACK destroys the only prepared permit. Never cancel
        // or reconstruct it from Started; another replica observes the deadline.
        // This is earlier than the durable Start admission. Its monotonic
        // elapsed time conservatively reserves the entire shared provider budget
        // even when Start's SQL work or later authority checks are slow.
        let earliest_start = Instant::now();
        let started = self
            .credentials
            .start_oauth_refresh(prepared)
            .await
            .map_err(|_| BrokerRefreshError::Unavailable)?;
        let final_admission = async {
            self.exact_request(&request).await?;
            let attempt = self
                .credentials
                .current_oauth_refresh_attempt(
                    &self.session.credential_owner,
                    &request.grant.credential_id,
                )
                .await
                .map_err(refresh_store_error)?;
            if !attempt.is_some_and(|attempt| {
                attempt.attempt_id == request.refresh_id
                    && attempt.expected == expected(&request)
                    && attempt.state == OAuthRefreshState::Started
                    && attempt.execution_live
            }) {
                return Err(BrokerRefreshError::Denied);
            }
            // Discovery can itself wait for a database lock. Runtime identity
            // and the original deadline must still hold after the last await.
            let current = self.session().await.map_err(refresh_lease_error)?;
            let now = unix_now().map_err(|_| BrokerRefreshError::Unavailable)?;
            if request.grant.expires_at_unix.is_none_or(|deadline| {
                deadline <= now || deadline > current.identity_expires_at_unix
            }) || !has_provider_budget(earliest_start.elapsed())
            {
                return Err(BrokerRefreshError::Denied);
            }
            Ok(())
        }
        .await;
        if let Err(error) = final_admission {
            self.credentials
                .fail_oauth_refresh(started)
                .await
                .map_err(refresh_store_error)?;
            return Err(error);
        }
        Ok(PlatformStartedRefresh {
            instance_id: self.instance_id,
            request,
            started,
        })
    }

    async fn commit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        if permit.request.kind != BrokerCredentialRefreshKind::CodexOAuth {
            return Err(CommitFailure::returned(permit, BrokerRefreshError::Denied));
        }
        let (permit, value) =
            valid_bundle(permit, ProtectedValue::from_slice(material.as_bytes()))?;
        drop(material);
        Ok(self.commit_refresh_value(permit, value).await?)
    }

    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: GitHubAppUserOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        if permit.request.kind != BrokerCredentialRefreshKind::GitHubAppUserOAuth {
            return Err(CommitFailure::returned(permit, BrokerRefreshError::Denied));
        }
        let mut bytes = material.into_bytes();
        let (permit, value) = taken_bundle(permit, &mut bytes)?;
        Ok(self.commit_refresh_value(permit, value).await?)
    }

    async fn commit_claude_oauth_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        if permit.request.kind != BrokerCredentialRefreshKind::ClaudeOAuth {
            return Err(CommitFailure::returned(permit, BrokerRefreshError::Denied));
        }
        let mut bytes = material.into_bytes();
        let (permit, value) = taken_bundle(permit, &mut bytes)?;
        Ok(self.commit_refresh_value(permit, value).await?)
    }

    async fn abort_credential_refresh(
        &self,
        reservation: Self::RefreshReservation,
    ) -> Result<(), BrokerRefreshError> {
        if reservation.instance_id != self.instance_id {
            return Err(BrokerRefreshError::Denied);
        }
        self.cancel(&reservation.request).await
    }

    async fn fail_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
    ) -> Result<(), BrokerRefreshError> {
        if permit.instance_id != self.instance_id {
            return Err(BrokerRefreshError::Denied);
        }
        self.credentials
            .fail_oauth_refresh(permit.started)
            .await
            .map_err(refresh_store_error)
    }

    async fn rate_limit_credential_refresh(
        &self,
        permit: Self::StartedRefresh,
        wait_seconds: u64,
    ) -> Result<RateLimitClose, BrokerRefreshError> {
        if permit.instance_id != self.instance_id {
            return Err(BrokerRefreshError::Denied);
        }
        refresh_errors::rate_limit(&self.credentials, permit.started, wait_seconds).await
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
        if let Some(ssh) = &self.ssh {
            ssh.drain().await.map_err(refresh_lease_error)?;
        }
        // SQL/OpenBao futures are awaited directly. The shared refresh tracker
        // drains Start, provider exchange and terminal publication before here.
        Ok(())
    }
}

fn expected(request: &BrokerCredentialRefreshRequest) -> CredentialVersion {
    CredentialVersion {
        revocation_generation: request.grant.credential_revocation_generation,
        material_generation: request.material_generation,
    }
}

fn published(version: CredentialVersion) -> Option<CredentialVersion> {
    Some(CredentialVersion {
        revocation_generation: version.revocation_generation.checked_add(1)?,
        material_generation: version.material_generation.checked_add(1)?,
    })
}

fn has_provider_budget(elapsed: Duration) -> bool {
    elapsed
        .checked_add(Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS))
        .is_some_and(|needed| {
            needed < Duration::from_secs(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS)
        })
}

fn unix_now() -> Result<u64, PlatformRuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PlatformRuntimeError::Unavailable)
}

fn credential_error(error: PlatformCredentialError) -> BrokerLeaseError {
    match error {
        PlatformCredentialError::DatabaseUnavailable
        | PlatformCredentialError::ProviderUnavailable
        | PlatformCredentialError::ProviderTimedOut
        | PlatformCredentialError::ClockUnavailable => BrokerLeaseError::Unavailable,
        PlatformCredentialError::CorruptRecord => BrokerLeaseError::InvalidResponse,
        _ => BrokerLeaseError::Denied,
    }
}

fn profile_error(error: PlatformProfileError) -> BrokerLeaseError {
    match error {
        PlatformProfileError::DatabaseUnavailable | PlatformProfileError::ClockUnavailable => {
            BrokerLeaseError::Unavailable
        }
        PlatformProfileError::CorruptRecord => BrokerLeaseError::InvalidResponse,
        _ => BrokerLeaseError::Denied,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod session_tests;
