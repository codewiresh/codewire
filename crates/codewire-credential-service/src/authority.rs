use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_access::{
    AccessProfile, EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId, Placement,
    builtin_provider_catalog,
};
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator,
};
use codewire_credential_broker::platform::{
    PlatformPodIdentity, PlatformRuntimeAuthority, PlatformRuntimeError, PlatformRuntimeSession,
};
#[cfg(feature = "enrollment")]
use codewire_platform_credentials::PlatformCredentialStore;
use codewire_platform_credentials::{
    PlatformAccessProfileStore, PlatformBindingMetadata, PlatformProfileError,
};
use codewire_project::PlatformProjectionSelection;
use codewire_protected_store::secret_envelope::KekProvider;
use codewire_server_core::pod_identity::{
    KubernetesPodIdentityVerifier, PodIdentityError, PodIdentityPurpose, VerifiedPodIdentity,
};
use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use sqlx::PgPool;
use tokio::time::Instant;
use tonic::metadata::MetadataMap;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::objects::{Lineage, gateway_environment, live_pod, validate_lineage, verified_shape};
use crate::projection::{self, ProjectionMetadata};

pub(crate) const WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";
const ASCII_WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
type Error = PlatformRuntimeError;

/// One explicit authority assignment for the three runtime consumers. Keeping
/// these constructors together prevents normal composition from silently
/// reusing the credential-material authority for application values.
#[cfg(any(feature = "enrollment", test))]
pub(crate) struct RuntimeKekAuthorities {
    #[cfg(feature = "enrollment")]
    credential: Arc<dyn KekProvider>,
    application: Arc<dyn KekProvider>,
}

#[cfg(any(feature = "enrollment", test))]
impl RuntimeKekAuthorities {
    pub(crate) fn new(
        _credential: Arc<dyn KekProvider>,
        application: Arc<dyn KekProvider>,
    ) -> Self {
        Self {
            #[cfg(feature = "enrollment")]
            credential: _credential,
            application,
        }
    }

    #[cfg(feature = "enrollment")]
    pub(crate) fn credential_store(&self, pool: PgPool) -> Arc<PlatformCredentialStore> {
        Arc::new(PlatformCredentialStore::new(
            pool,
            self.credential.clone(),
            builtin_provider_catalog(),
        ))
    }

    pub(crate) fn kubernetes_authenticator(
        &self,
        client: Client,
        pool: PgPool,
    ) -> KubernetesPlatformBridgeAuthenticator {
        KubernetesPlatformBridgeAuthenticator::new(client, pool, self.application.clone())
    }

    #[cfg(feature = "enrollment")]
    pub(crate) fn delegation_provider(&self) -> Arc<dyn KekProvider> {
        self.application.clone()
    }
}

/// Production-only construction: callers cannot inject purported verified IDs.
///
/// Private metadata is exactly one ordinary authorization bearer for the
/// gateway and one binary x-codewire-workspace-authorization-bin whose decoded
/// bytes are canonical "Bearer ..." for the workspace. The gateway producer
/// must mark that binary metadata value sensitive. The ASCII lookalike is
/// rejected, not treated as a fallback. Only fixed purpose TokenReviews
/// establish identity; no cookie, public user bearer or guest scope is accepted.
pub struct KubernetesPlatformBridgeAuthenticator {
    client: Client,
    pool: PgPool,
    gateway_verifier: KubernetesPodIdentityVerifier,
    workspace_verifier: KubernetesPodIdentityVerifier,
    provider: Arc<dyn KekProvider>,
}

impl KubernetesPlatformBridgeAuthenticator {
    pub fn new(client: Client, pool: PgPool, provider: Arc<dyn KekProvider>) -> Self {
        Self {
            gateway_verifier: KubernetesPodIdentityVerifier::new(
                Some(client.clone()),
                PodIdentityPurpose::CredentialGateway,
            ),
            workspace_verifier: KubernetesPodIdentityVerifier::new(
                Some(client.clone()),
                PodIdentityPurpose::CredentialWorkspace,
            ),
            client,
            pool,
            provider,
        }
    }
}

#[async_trait]
impl PlatformBridgeAuthenticator for KubernetesPlatformBridgeAuthenticator {
    type Authority = KubernetesPlatformRuntimeAuthority;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Arc<Self::Authority>, PlatformBridgeAuthenticationError> {
        // Validate both complete inputs before either verifier/network call.
        let (gateway_headers, workspace_headers) = authentication_headers(metadata)?;
        tokio::time::timeout(AUTHORITY_TIMEOUT, async {
            let (gateway, workspace) = tokio::try_join!(
                self.gateway_verifier.authenticate(&gateway_headers),
                self.workspace_verifier.authenticate(&workspace_headers),
            )
            .map_err(authentication_error)?;
            // Only these metadata-only opaque verifier results are retained.
            let identities = Identities::new(gateway, workspace).map_err(runtime_auth_error)?;
            let authority = AuthoritySource {
                client: self.client.clone(),
                pool: self.pool.clone(),
                provider: self.provider.clone(),
                profiles: PlatformAccessProfileStore::new(
                    self.pool.clone(),
                    builtin_provider_catalog(),
                ),
            };
            let initial = identities
                .bounded(authority.resolve(&identities))
                .await
                .map_err(runtime_auth_error)?;
            Ok(Arc::new(KubernetesPlatformRuntimeAuthority {
                authority,
                identities,
                initial,
            }))
        })
        .await
        .map_err(|_| PlatformBridgeAuthenticationError::Unavailable)?
    }
}

/// Captures the original verified Pod identities, finite deadline and exact
/// initial database/profile/controller selection. No public constructor, wire
/// deserializer, credential value or protected-material cache exists.
pub struct KubernetesPlatformRuntimeAuthority {
    pub(crate) authority: AuthoritySource,
    pub(crate) identities: Identities,
    pub(crate) initial: Resolved,
}

#[async_trait]
impl PlatformRuntimeAuthority for KubernetesPlatformRuntimeAuthority {
    async fn project_environment(
        &self,
        request: codewire_gateway_proto::codewire::bridge::v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, Error> {
        self.project(request).await
    }

    async fn current_session(&self) -> Result<PlatformRuntimeSession, Error> {
        let current = self
            .identities
            .bounded(self.authority.resolve(&self.identities))
            .await?;
        if !self.initial.same_authority(&current) {
            return Err(Error::Denied);
        }
        self.identities.ensure_live()?;
        Ok(current.session)
    }
}

pub(crate) struct Identities {
    gateway: VerifiedPodIdentity,
    workspace: VerifiedPodIdentity,
    expires_at_unix: u64,
    deadline: Instant,
}

impl Identities {
    fn new(gateway: VerifiedPodIdentity, workspace: VerifiedPodIdentity) -> Result<Self, Error> {
        verified_shape(&gateway)?;
        verified_shape(&workspace)?;
        if gateway.purpose() != PodIdentityPurpose::CredentialGateway
            || workspace.purpose() != PodIdentityPurpose::CredentialWorkspace
            || gateway.namespace() != workspace.namespace()
            || gateway.pod_uid() == workspace.pod_uid()
        {
            return Err(Error::Denied);
        }
        let expires_at_unix = gateway.expires_at_unix().min(workspace.expires_at_unix());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?;
        let remaining = Duration::from_secs(expires_at_unix)
            .checked_sub(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Error::Denied)?;
        let deadline = Instant::now().checked_add(remaining).ok_or(Error::Denied)?;
        Ok(Self {
            gateway,
            workspace,
            expires_at_unix,
            deadline,
        })
    }

    pub(crate) fn ensure_live(&self) -> Result<(), Error> {
        if Instant::now() >= self.deadline || unix_now()? >= self.expires_at_unix {
            return Err(Error::Denied);
        }
        Ok(())
    }

    pub(crate) async fn bounded<T>(
        &self,
        work: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        self.ensure_live()?;
        let deadline = self.deadline.min(Instant::now() + AUTHORITY_TIMEOUT);
        let result = tokio::time::timeout_at(deadline, work).await;
        self.ensure_live()?;
        result.map_err(|_| Error::Unavailable)?
    }
}

pub(crate) struct AuthoritySource {
    client: Client,
    pub(crate) pool: PgPool,
    pub(crate) provider: Arc<dyn KekProvider>,
    profiles: PlatformAccessProfileStore,
}

#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct Scope {
    pub(crate) environment_id: String,
    pub(crate) creator: String,
    pub(crate) organization: String,
    pub(crate) generation: i64,
    pub(crate) namespace: String,
    pub(crate) claim_name: String,
    pub(crate) claim_uid: String,
    pub(crate) pod_name: String,
    pub(crate) member_id: String,
    pub(crate) member_role: String,
    pub(crate) profile_id: Option<String>,
    pub(crate) profile_revision: Option<i64>,
    pub(crate) confirmed_by: Option<String>,
    pub(crate) profile_user: Option<String>,
    pub(crate) profile_organization: Option<String>,
}

impl Scope {
    fn context(&self) -> Result<GrantContext, Error> {
        if self.generation <= 0 || self.member_id.is_empty() || self.member_role.is_empty() {
            return Err(Error::Denied);
        }
        Ok(GrantContext {
            environment_id: EnvironmentId::parse(&self.environment_id)
                .map_err(|_| Error::Denied)?,
            environment_generation: self.generation as u64,
            placement: GrantPlacement::Platform,
            user_id: OwnerId::parse(&self.creator).map_err(|_| Error::Denied)?,
            organization_id: Some(OwnerId::parse(&self.organization).map_err(|_| Error::Denied)?),
            allow_personal_credentials: self.profile_user.as_deref() == Some(&self.creator)
                && self.confirmed_by.as_deref() == Some(&self.creator),
            authorized_credentials: BTreeSet::new(),
        })
    }

    fn owner(&self) -> Result<Owner, Error> {
        match (
            &self.profile_id,
            self.profile_revision,
            &self.profile_user,
            &self.profile_organization,
            &self.confirmed_by,
        ) {
            (None, None, None, None, None) => Ok(Owner::User(
                OwnerId::parse(&self.creator).map_err(|_| Error::Denied)?,
            )),
            (Some(_), Some(revision), Some(user), None, Some(confirmed))
                if revision > 0 && user == &self.creator && confirmed == &self.creator =>
            {
                Ok(Owner::User(
                    OwnerId::parse(user).map_err(|_| Error::Denied)?,
                ))
            }
            (Some(_), Some(revision), None, Some(org), None)
                if revision > 0 && org == &self.organization =>
            {
                Ok(Owner::Organization(
                    OwnerId::parse(org).map_err(|_| Error::Denied)?,
                ))
            }
            _ => Err(Error::Denied),
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct Resolved {
    session: PlatformRuntimeSession,
    pub(crate) scope: Scope,
    pub(crate) metadata: ProjectionMetadata,
    pub(crate) selection: PlatformProjectionSelection,
    binding: Option<PlatformBindingMetadata>,
    profile: Option<AccessProfile>,
    lineage: Lineage,
}

impl Resolved {
    /// Everything resolved at admission stays fixed except the authorized
    /// credentials, which follow the owner's current connections.
    fn same_authority(&self, current: &Self) -> bool {
        let Self {
            session,
            scope,
            metadata,
            selection,
            binding,
            profile,
            lineage,
        } = self;
        session.same_authority(&current.session)
            && *scope == current.scope
            && *metadata == current.metadata
            && *selection == current.selection
            && *binding == current.binding
            && *profile == current.profile
            && *lineage == current.lineage
    }
}

// The exact same scope query is used inside projection capture/final locks.
// Membership remains mandatory even for the creator. Optional provider binding
// does not relax environment state, generation or backend/Pod identity.
pub(crate) const SCOPE_QUERY: &str = "SELECT e.id AS environment_id,e.created_by AS creator,e.org_id AS organization, \
     e.environment_operation_generation AS generation,s.namespace,s.sandbox_claim_name AS claim_name, \
     s.sandbox_claim_uid AS claim_uid,s.pod_name,m.id AS member_id,m.role AS member_role, \
     b.profile_id,b.profile_revision,b.personal_owner_confirmed_by AS confirmed_by, \
     p.user_id AS profile_user,p.organization_id AS profile_organization \
     FROM public.environments e \
     JOIN public.users u ON u.id=e.created_by \
     JOIN public.organizations o ON o.id=e.org_id AND o.deletion_state='active' \
     JOIN public.org_members m ON m.org_id=e.org_id AND m.user_id=e.created_by \
     JOIN public.sandbox_environment_backend s ON s.environment_id=e.id \
     LEFT JOIN public.platform_environment_access_bindings b ON b.environment_id=e.id \
     LEFT JOIN public.platform_access_profiles p ON p.id=b.profile_id \
     WHERE e.id=$1 AND e.type='sandbox' AND e.state='running' AND e.desired_state='started' \
     AND e.deletion_requested_at IS NULL AND e.environment_operation_generation>0 \
     AND s.sandbox_claim_name IS NOT NULL AND s.sandbox_claim_uid IS NOT NULL AND s.pod_name IS NOT NULL";

impl AuthoritySource {
    async fn scope(&self, environment: &str) -> Result<Scope, Error> {
        // Membership is an INNER JOIN, never the public environment API's
        // creator shortcut. Incomplete backend or consent never infers scope.
        sqlx::query_as(SCOPE_QUERY)
            .bind(environment)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Denied)
    }

    async fn resolve(&self, identities: &Identities) -> Result<Resolved, Error> {
        identities.ensure_live()?;
        let gateway: Pod = Api::namespaced(self.client.clone(), identities.gateway.namespace())
            .get(identities.gateway.pod_name())
            .await
            .map_err(kube_error)?;
        live_pod(&gateway, &identities.gateway)?;
        let environment = gateway_environment(&gateway)?;
        let scope = self.scope(&environment).await?;
        if scope.namespace != identities.gateway.namespace() {
            return Err(Error::Denied);
        }
        let mut context = scope.context()?;
        let owner = scope.owner()?;
        let metadata = projection::metadata(&self.pool, &environment).await?;
        let (binding, profile) = if scope.profile_id.is_some() {
            let binding = self
                .profiles
                .get_binding_metadata(&context)
                .await
                .map_err(profile_error)?;
            if Some(binding.binding.profile_id.as_str()) != scope.profile_id.as_deref()
                || Some(binding.binding.profile_revision as i64) != scope.profile_revision
                || binding
                    .personal_owner_confirmed_by
                    .as_ref()
                    .map(OwnerId::as_str)
                    != scope.confirmed_by.as_deref()
            {
                return Err(Error::Denied);
            }
            let profile = self
                .profiles
                .get_revision(
                    &owner,
                    &binding.binding.profile_id,
                    binding.binding.profile_revision,
                )
                .await
                .map_err(profile_error)?;
            if profile.owner != owner
                || profile.placement != Placement::Platform
                || profile.entries.is_empty() && !profile.includes_github()
                || profile.entries.len() > 64
            {
                return Err(Error::Denied);
            }
            let mut authorized: BTreeSet<codewire_access::CredentialId> =
                profile.entries.values().cloned().collect();
            // Every personal profile includes the account's current GitHub
            // connection. When it is missing, GitHub is omitted, not fabricated.
            if profile.includes_github()
                && let Some(github) =
                    codewire_platform_credentials::active_github_connection(&self.pool, &owner)
                        .await
                        .map_err(|_| Error::Unavailable)?
            {
                authorized.insert(github);
            }
            // Every selected credential must still exist and belong to the
            // profile owner, or nothing is admitted. Its lifecycle is not an
            // environment fence: one that needs Reconnect (refresh failed,
            // revoked or expired) withholds only its own capability, at each
            // broker admission, so sessions and the projection still launch.
            let ids: Vec<String> = authorized.iter().map(ToString::to_string).collect();
            let owned: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM public.platform_credentials WHERE \
             ((user_id=$1 AND organization_id IS NULL) OR (organization_id=$2 AND user_id IS NULL)) \
             AND id=ANY($3)",
        )
        .bind(match &owner { Owner::User(id) => Some(id.as_str()), _ => None })
        .bind(match &owner { Owner::Organization(id) => Some(id.as_str()), _ => None })
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
            if owned.into_iter().collect::<BTreeSet<_>>() != ids.into_iter().collect() {
                return Err(Error::Denied);
            }
            context.authorized_credentials = authorized;
            (Some(binding), Some(profile))
        } else {
            (None, None)
        };
        // The selection digest was captured when the environment was created
        // and binds reserved names, not connection state: connecting or
        // deleting GitHub later changes only the authorized credentials above.
        let reserved_keys = codewire_project::platform_projection_reserved_keys(
            profile.iter().flat_map(|profile| profile.reserved_slots()),
        )
        .map_err(|_| Error::Denied)?;
        let selection = metadata.selection(&scope, reserved_keys)?;
        let lineage =
            validate_lineage(&self.client, &scope, &gateway, &identities.workspace).await?;
        // Selecting a GitHub repository needs no profile. Orchestration records
        // that choice once, when it renders the verified workspace Pod with the
        // GitHub client; only then is the creator's active connection
        // authorized. A missing connection is omitted, never fabricated.
        if profile.is_none()
            && lineage.managed_github()
            && let Some(github) =
                codewire_platform_credentials::active_github_connection(&self.pool, &owner)
                    .await
                    .map_err(|_| Error::Unavailable)?
        {
            context.authorized_credentials.insert(github);
        }
        // No profile/Kube await follows the final database scope reread. A
        // different binding with identical entry IDs still changes Scope.
        if self.scope(&environment).await? != scope
            || projection::metadata(&self.pool, &environment).await? != metadata
        {
            return Err(Error::Denied);
        }
        identities.ensure_live()?;
        let session = PlatformRuntimeSession::new(
            platform_pod(&identities.gateway)?,
            platform_pod(&identities.workspace)?,
            context,
            owner,
            identities.expires_at_unix,
        )?;
        Ok(Resolved {
            session,
            scope,
            metadata,
            selection,
            binding,
            profile,
            lineage,
        })
    }
}

fn platform_pod(identity: &VerifiedPodIdentity) -> Result<PlatformPodIdentity, Error> {
    let uid = Uuid::parse_str(identity.pod_uid()).map_err(|_| Error::Denied)?;
    if uid.is_nil() {
        return Err(Error::Denied);
    }
    Ok(PlatformPodIdentity {
        namespace: identity.namespace().into(),
        name: identity.pod_name().into(),
        uid,
    })
}

fn authentication_headers(
    metadata: &MetadataMap,
) -> Result<(HeaderMap, HeaderMap), PlatformBridgeAuthenticationError> {
    let denied = PlatformBridgeAuthenticationError::Unauthenticated;
    if metadata.contains_key(ASCII_WORKSPACE_AUTHORIZATION) {
        return Err(denied);
    }
    let mut gateway = metadata.get_all("authorization").iter();
    let gateway = match (gateway.next(), gateway.next()) {
        (Some(value), None) => value,
        _ => return Err(denied),
    };
    let mut workspace = metadata.get_all_bin(WORKSPACE_AUTHORIZATION).iter();
    let workspace = match (workspace.next(), workspace.next()) {
        (Some(value), None) => value,
        _ => return Err(denied),
    };
    if workspace.as_encoded_bytes().len() > (MAX_TOKEN_BYTES + 7).div_ceil(3) * 4 {
        return Err(denied);
    }
    let workspace = Zeroizing::new(workspace.to_bytes().map_err(|_| denied)?.to_vec());
    Ok((
        canonical_headers(gateway.as_encoded_bytes())?,
        canonical_headers(&workspace)?,
    ))
}

fn canonical_headers(bytes: &[u8]) -> Result<HeaderMap, PlatformBridgeAuthenticationError> {
    let denied = PlatformBridgeAuthenticationError::Unauthenticated;
    let token = bytes.strip_prefix(b"Bearer ").ok_or(denied)?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(denied);
    }
    let parts: Vec<&[u8]> = token.split(|byte| *byte == b'.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(denied);
    }
    let mut value = HeaderValue::from_bytes(bytes).map_err(|_| denied)?;
    value.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, value);
    Ok(headers)
}

pub(crate) fn kube_error(error: kube::Error) -> Error {
    match error {
        kube::Error::Api(response) if response.code == 404 => Error::Denied,
        _ => Error::Unavailable,
    }
}

fn profile_error(error: PlatformProfileError) -> Error {
    match error {
        PlatformProfileError::DatabaseUnavailable | PlatformProfileError::ClockUnavailable => {
            Error::Unavailable
        }
        _ => Error::Denied,
    }
}

fn authentication_error(error: PodIdentityError) -> PlatformBridgeAuthenticationError {
    match error {
        PodIdentityError::Unauthenticated => PlatformBridgeAuthenticationError::Unauthenticated,
        PodIdentityError::PermissionDenied => PlatformBridgeAuthenticationError::Denied,
        PodIdentityError::Unavailable => PlatformBridgeAuthenticationError::Unavailable,
    }
}

fn runtime_auth_error(error: Error) -> PlatformBridgeAuthenticationError {
    match error {
        Error::Denied => PlatformBridgeAuthenticationError::Denied,
        Error::Unavailable => PlatformBridgeAuthenticationError::Unavailable,
    }
}

pub(crate) fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Unavailable)
}
