//! Platform credential storage adapter for an isolated broker, not a listener.
//!
//! The runtime authority is a trusted, process-local dependency. Its eventual
//! implementation must authenticate either the exact gateway/workload Pods or
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
#[cfg(all(feature = "ssh-agent", target_os = "linux"))]
mod ssh;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS,
    CapabilitySlot, CredentialAuthKind, CredentialMetadata, DerivedGrant, EnvironmentAccessBinding,
    GrantContext, GrantPermission, GrantPlacement, Owner, PROVIDER_REFRESH_TIMEOUT_SECONDS,
    Placement,
};
use codewire_platform_credentials::{
    CredentialRecord, CredentialVersion, OAuthRefreshState, PlatformAccessProfileStore,
    PlatformCredentialError, PlatformCredentialStore, PlatformProfileError, PreparedOAuthRefresh,
    StartedOAuthRefresh,
};
use codewire_protected_store::ProtectedValue;
use uuid::Uuid;

use crate::{
    BrokerCredentialLease, BrokerCredentialRefreshKind, BrokerCredentialRefreshRequest,
    BrokerLeaseError, BrokerLeaseProvider, BrokerRefreshAdmission, BrokerRefreshError,
    CanonicalCodexOAuthBundle, GitHubAppUserOAuthBundle,
};

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
    Hosted {
        gateway: PlatformPodIdentity,
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
        gateway: PlatformPodIdentity,
        workspace: PlatformPodIdentity,
        context: GrantContext,
        credential_owner: Owner,
        identity_expires_at_unix: u64,
    ) -> Result<Self, PlatformRuntimeError> {
        let session = Self {
            identity: RuntimeIdentity::Hosted { gateway, workspace },
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
            RuntimeIdentity::Hosted { gateway, workspace } => {
                if gateway == workspace || self.context.placement != GrantPlacement::Platform {
                    return Err(PlatformRuntimeError::Denied);
                }
                for pod in [gateway, workspace] {
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

    #[cfg(test)]
    fn gateway_mut(&mut self) -> &mut PlatformPodIdentity {
        let RuntimeIdentity::Hosted { gateway, .. } = &mut self.identity else {
            panic!("test requires a hosted session");
        };
        gateway
    }

    #[cfg(test)]
    fn workspace_mut(&mut self) -> &mut PlatformPodIdentity {
        let RuntimeIdentity::Hosted { workspace, .. } = &mut self.identity else {
            panic!("test requires a hosted session");
        };
        workspace
    }
}

/// Closed failures: authenticators must discard Kubernetes, SQL, transport and
/// token parser text rather than retaining upstream messages or error sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformRuntimeError {
    #[error("platform runtime authority denied the session")]
    Denied,
    #[error("platform runtime authority is unavailable")]
    Unavailable,
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
    async fn owner_local_grants(
        &self,
        _expected: &PlatformRuntimeSession,
    ) -> Result<Vec<DerivedGrant>, PlatformRuntimeError> {
        Err(PlatformRuntimeError::Denied)
    }

    /// Only recipient ciphertext for the sources already bound by the trusted
    /// authority. An identity-only test adapter remains explicitly deny-only.
    async fn project_environment(
        &self,
        _request: codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, PlatformRuntimeError> {
        Err(PlatformRuntimeError::Denied)
    }

    /// Fixed-Platform fragment for an authenticated native owner's mixed
    /// launch. Hosted authorities stay deny-only; this never selects a remote
    /// source outside the channel's immutable platform selection.
    async fn project_environment_fragment(
        &self,
        _request: codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<
        codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionComposition,
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
    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    ssh: Option<ssh::Epoch>,
}

/// Non-cloneable, non-serializable, zeroizing operation material.
pub struct PlatformCredentialLease {
    record: CredentialRecord,
    grant: DerivedGrant,
    permission: GrantPermission,
    material: ProtectedValue,
}

impl BrokerCredentialLease for PlatformCredentialLease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        &self.record.metadata
    }
    fn grant(&self) -> &DerivedGrant {
        &self.grant
    }
    fn permission(&self) -> &GrantPermission {
        &self.permission
    }
    fn material_generation(&self) -> u64 {
        self.record.version.material_generation
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(self.material.expose_secret())
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
    /// handles must never be installed in a gateway, daemon or metadata service.
    pub async fn connect(
        authority: Arc<A>,
        credentials: Arc<PlatformCredentialStore>,
        profiles: PlatformAccessProfileStore,
    ) -> Result<Self, PlatformRuntimeError> {
        let session = authority.current_session().await?;
        session.validate()?;
        Ok(Self {
            authority,
            session,
            instance_id: Uuid::new_v4(),
            credentials,
            profiles,
            #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
            ssh: None,
        })
    }

    async fn session(&self) -> Result<PlatformRuntimeSession, BrokerLeaseError> {
        let mut current = self
            .authority
            .current_session()
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

    async fn admit(
        &self,
        slot: &CapabilitySlot,
        permission: GrantPermission,
    ) -> Result<Admission, BrokerLeaseError> {
        let session = self.session().await?;
        let grants = match &session.identity {
            RuntimeIdentity::Hosted { .. } => self
                .profiles
                .evaluate_grants(&session.context)
                .await
                .map_err(profile_error)?,
            RuntimeIdentity::OwnerLocal {
                profile: Some(profile),
                ..
            } => {
                let grants = self
                    .authority
                    .owner_local_grants(&session)
                    .await
                    .map_err(runtime_error)?;
                if grants.iter().any(|grant| {
                    grant.environment_id != session.context.environment_id
                        || grant.environment_generation != session.context.environment_generation
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
                grants
            }
            RuntimeIdentity::OwnerLocal { profile: None, .. } => {
                return Err(BrokerLeaseError::Denied);
            }
        };
        let mut grant = grants
            .into_iter()
            .find(|grant| &grant.capability_slot == slot)
            .ok_or(BrokerLeaseError::Denied)?;
        if !grant.permissions.contains(&permission) {
            return Err(BrokerLeaseError::Denied);
        }
        grant.expires_at_unix = Some(
            grant
                .expires_at_unix
                .unwrap_or(session.identity_expires_at_unix)
                .min(session.identity_expires_at_unix),
        );
        let record = self
            .credentials
            .record(&session.credential_owner, &grant.credential_id)
            .await
            .map_err(credential_error)?;
        if record.metadata.placement != Placement::Platform
            || record.metadata.owner != session.credential_owner
            || record.version.revocation_generation == 0
            || record.version.material_generation == 0
            || record.metadata.revocation_generation != grant.credential_revocation_generation
            || record.version.revocation_generation != grant.credential_revocation_generation
        {
            return Err(BrokerLeaseError::Denied);
        }
        // The profile/record reads can wait for SQL locks. Their completion
        // cannot preserve runtime authority that was revoked during that wait.
        let current = self.session().await?;
        grant.expires_at_unix = grant
            .expires_at_unix
            .map(|deadline| deadline.min(current.identity_expires_at_unix));
        ensure_live(&record.metadata, &grant)?;
        Ok(Admission {
            record,
            grant,
            permission,
        })
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
        let expected_form = match request.kind {
            BrokerCredentialRefreshKind::CodexOAuth => {
                admission.record.metadata.provider.as_str() == "openai"
                    && request.grant.capability_slot.as_str() == "codex"
            }
            BrokerCredentialRefreshKind::GitHubAppUserOAuth => {
                admission.record.metadata.provider.as_str() == "github"
                    && request.grant.capability_slot.as_str() == "github"
            }
        };
        if !expected_form
            || admission.record.metadata.authentication_kind != CredentialAuthKind::OAuth
            || !same_grant_binding(&admission.grant, &request.grant)
        {
            return Err(BrokerRefreshError::Denied);
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
        let result = permit
            .started
            .prepare_result(&value)
            .map_err(refresh_store_error)?;
        drop(value);
        if let Err(error) = self.credentials.stage_oauth_refresh(&result).await {
            // A stage ACK can be lost. Discover only this exact immutable result's
            // attempt; absence of staged output never permits another exchange.
            let current = self
                .credentials
                .current_oauth_refresh_attempt(
                    &self.session.credential_owner,
                    &permit.request.grant.credential_id,
                )
                .await
                .map_err(refresh_store_error)?;
            if !current.is_some_and(|attempt| {
                attempt.attempt_id == permit.request.refresh_id
                    && attempt.expected == expected(&permit.request)
                    && matches!(
                        attempt.state,
                        OAuthRefreshState::Staged | OAuthRefreshState::Committed
                    )
            }) {
                return Err(refresh_store_error(error));
            }
        }
        // Do not discard rotated output merely because a guest disconnected or
        // its grant expired. Publication preserves storage's hard deadline; the
        // shared runtime separately obtains fresh authority before consuming it.
        self.promote(&permit.request, permit.request.refresh_id)
            .await
    }
}

#[async_trait]
impl<A: PlatformRuntimeAuthority + 'static> BrokerLeaseProvider for PlatformBrokerLeaseProvider<A> {
    type Lease = PlatformCredentialLease;
    type RefreshReservation = PlatformRefreshReservation;
    type StartedRefresh = PlatformStartedRefresh;

    async fn project_environment_fragment(
        &self,
        request: codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<
        codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionComposition,
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
        request: codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
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
        if request_id.is_nil() {
            return Err(BrokerLeaseError::InvalidRequest);
        }
        let permission = GrantPermission { operation, route };
        let before = self.admit(&slot, permission.clone()).await?;
        let material = self
            .credentials
            .read_for_broker(
                &before.record.metadata.owner,
                &before.record.metadata.id,
                before.record.version,
            )
            .await
            .map_err(credential_error)?;
        // OpenBao unwrap and SQL lock waits may outlive the original authority.
        // Recheck runtime, exact profile selection, current record and deadline.
        let mut after = self.admit(&slot, permission).await?;
        if before.record != after.record || !same_grant_binding(&before.grant, &after.grant) {
            return Err(BrokerLeaseError::Denied);
        }
        after.grant.expires_at_unix = before
            .grant
            .expires_at_unix
            .min(after.grant.expires_at_unix);
        ensure_live(&after.record.metadata, &after.grant)?;
        Ok(PlatformCredentialLease {
            record: after.record,
            grant: after.grant,
            permission: after.permission,
            material,
        })
    }

    #[cfg(all(feature = "ssh-agent", target_os = "linux"))]
    async fn ssh_operation(
        &self,
        request: codewire_gateway_proto::codewire::bridge::v1::CredentialSshRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<
        codewire_gateway_proto::codewire::bridge::v1::credential_ssh_response::Result,
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
                OAuthRefreshState::Reserved
                | OAuthRefreshState::Committed
                | OAuthRefreshState::Cancelled => {}
            }
        }
        if admission.record.version != version {
            return Err(BrokerRefreshError::Stale);
        }
        let prepared = self
            .credentials
            .begin_oauth_refresh(
                &self.session.credential_owner,
                &request.grant.credential_id,
                version,
                request.refresh_id,
            )
            .await
            .map_err(refresh_store_error)?;
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
    ) -> Result<(), BrokerRefreshError> {
        if permit.request.kind != BrokerCredentialRefreshKind::CodexOAuth {
            return Err(BrokerRefreshError::Denied);
        }
        let value = ProtectedValue::from_slice(material.as_bytes())
            .map_err(|_| BrokerRefreshError::InvalidResponse)?;
        drop(material);
        self.commit_refresh_value(permit, value).await
    }

    async fn commit_github_app_refresh(
        &self,
        permit: Self::StartedRefresh,
        material: GitHubAppUserOAuthBundle,
    ) -> Result<(), BrokerRefreshError> {
        if permit.request.kind != BrokerCredentialRefreshKind::GitHubAppUserOAuth {
            return Err(BrokerRefreshError::Denied);
        }
        let mut bytes = material.into_bytes();
        let value = ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| BrokerRefreshError::InvalidResponse)?;
        self.commit_refresh_value(permit, value).await
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

fn same_grant_binding(a: &DerivedGrant, b: &DerivedGrant) -> bool {
    a.environment_id == b.environment_id
        && a.environment_generation == b.environment_generation
        && a.profile == b.profile
        && a.capability_slot == b.capability_slot
        && a.credential_id == b.credential_id
        && a.permissions == b.permissions
}

fn ensure_live(
    metadata: &CredentialMetadata,
    grant: &DerivedGrant,
) -> Result<(), BrokerLeaseError> {
    let now = unix_now().map_err(runtime_error)?;
    if metadata.status != codewire_access::CredentialStatus::Active
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_none_or(|expiry| expiry <= now)
    {
        return Err(BrokerLeaseError::Denied);
    }
    Ok(())
}

fn unix_now() -> Result<u64, PlatformRuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PlatformRuntimeError::Unavailable)
}

fn runtime_error(error: PlatformRuntimeError) -> BrokerLeaseError {
    match error {
        PlatformRuntimeError::Denied => BrokerLeaseError::Denied,
        PlatformRuntimeError::Unavailable => BrokerLeaseError::Unavailable,
    }
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

fn refresh_lease_error(error: BrokerLeaseError) -> BrokerRefreshError {
    match error {
        BrokerLeaseError::InvalidRequest => BrokerRefreshError::InvalidRequest,
        BrokerLeaseError::Denied => BrokerRefreshError::Denied,
        BrokerLeaseError::Unavailable => BrokerRefreshError::Unavailable,
        BrokerLeaseError::InvalidResponse => BrokerRefreshError::InvalidResponse,
    }
}

fn refresh_store_error(error: PlatformCredentialError) -> BrokerRefreshError {
    match error {
        PlatformCredentialError::RefreshInProgress => BrokerRefreshError::InProgress,
        PlatformCredentialError::StaleVersion | PlatformCredentialError::StaleRefresh => {
            BrokerRefreshError::Stale
        }
        other => refresh_lease_error(credential_error(other)),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod session_tests;
