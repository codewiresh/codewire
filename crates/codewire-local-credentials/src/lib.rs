#![forbid(unsafe_code)]

//! Private metadata and protected-value lifecycle for the local credential
//! authority.
//!
//! SQLite contains metadata and exact protected-store entry references only.
//! Provider material is accepted as [`ProtectedValue`], written to one exact
//! entry, and never serialized, formatted, or exposed through metadata APIs.
//! The synchronous persistence kernel is served by a separate owner-only local
//! RPC process on bounded blocking workers. The VM supervisor does not link or
//! own that material-bearing authority.

mod broker_channel;
mod broker_log;
mod broker_process;
mod client;
mod control;
mod platform;
mod repository;
mod service;
mod store_backend;
mod transport;
mod workload_secret;

pub use broker_channel::{
    BrokerCredentialRefreshAdmission, BrokerCredentialRefreshReservation, BrokerLeaseAuditDecision,
    BrokerLeaseAuditEvent, BrokerLeaseChannelError, LocalCredentialBrokerLeaseClient,
    LocalCredentialDelegationClient, LocalCredentialDelegationOutput,
    LocalEnvironmentProjectionBinding, LocalSshSignError, LocalSshSignRequest, LocalSshSigner,
    StartedBrokerCredentialRefresh, serve_broker_lease_channel,
};
pub use broker_process::{
    EnvironmentBrokerRuntime, EnvironmentBrokerSelection, LocalBrokerProcessConfig,
    LocalBrokerProcessSpawner, LocalBrokerSpawnError,
};
pub use client::{
    AuthorityInfo, LocalCredentialClient, LocalCredentialControlClient, PreparedGitRepository,
    SpawnedAuthority,
};
pub use platform::{
    PlatformCredentialBinding, PlatformCredentialConnector, PlatformCredentialInput,
    PlatformCredentialOutput,
};
pub use repository::{
    GitHubLoginRenewer, GitHubLoginState, LocalCredentialRepositoryLeaseClient, LocalRepositoryGit,
    LocalRepositoryGitProcessSpawner, LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner,
    LocalRepositorySpawnError, LocalRepositoryTransport, MAX_GIT_BUNDLE_BYTES,
    REPOSITORY_SSH_RUNTIME_PREFIX, RepositoryCredentialLease, RepositoryExecutorError,
    RepositoryLeaseChannelError, RepositoryPlatformAccess, RepositorySshCheckoutIntent,
    SSH_HELPER_BASENAME, SSH_HELPER_HOST_ENV, SSH_HELPER_OWNER_ENV, SSH_HELPER_PORT_ENV,
    SSH_HELPER_RUNTIME_ENV, run_git_credential_helper, run_git_credential_helper_for_endpoint,
    run_local_repository_executor, run_local_ssh_repository_executor,
    run_platform_repository_executor, validate_github_https_source,
    validate_repository_ssh_runtime_path,
};
pub use service::serve_local_credential_authority;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use service::serve_os_local_credential_authority_with_process_spawners;
pub use transport::{
    AuthorityRuntimeConfig, AuthorityRuntimeError, MAXIMUM_SOCKET_PATH_BYTES, authority_exit_code,
    check_socket_path,
};
pub use workload_secret::{
    LocalLaunchSecretSelection, LocalSecretProject, ResolvedWorkloadSecretMetadata,
    WorkloadSecretMetadata, WorkloadSecretSelection, WorkloadSecretSource,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessError, AccessProfile, AccessProfileId, AccessProfileName, AccessProfileReference,
    AccessProfileScope, BrokerOperationId, BrokerRouteId,
    CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS, CapabilitySlot, CredentialAuthKind,
    CredentialId, CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentAccessBinding,
    EnvironmentId, GrantContext, GrantPermission, GrantPlacement, Owner, OwnerId, Placement,
    ProviderCatalog, ProviderId, SshPublicKeyMetadata, derive_grants, validate_profile_entries,
};
use codewire_protected_store::ProtectedStoreBackend;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use codewire_protected_store::SelectedProtectedStore;
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
    ssh_material::{PreparedSshCredential, SshAgentMaterial, decode_protected_material},
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

pub const DATABASE_FILE: &str = "credentials.db";
/// The file backend's owner-only entry directory inside the authority root.
pub const FILE_STORE_DIRECTORY: &str = "protected-v1";
pub const LOCAL_OWNER_ID: &str = "local-user";
/// The complete environment inherited by the detached Linux authority.
///
/// These variables locate the user session bus used by Secret Service. The
/// launcher clears every other ambient variable before exec.
pub const AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES: [&str; 2] =
    ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"];

const AUTHORITY_LOCK_FILE: &str = "authority.lock";
const DATABASE_APPLICATION_ID: i64 = 0x4357_4352; // "CWCR"
const DATABASE_SCHEMA_VERSION: i64 = 5;
/// Adds typed SSH public-key metadata.
const SSH_DATABASE_SCHEMA_VERSION: i64 = 4;
const PREVIOUS_DATABASE_SCHEMA_VERSION: i64 = 3;
/// GitHub is one connection per local store. Every profile includes it and
/// never stores a GitHub credential ID.
const GITHUB_SINGLETON_SCHEMA: &str = "
    CREATE UNIQUE INDEX credentials_github_oauth_singleton
      ON credentials(provider, authentication_kind)
      WHERE provider = 'github' AND authentication_kind = 'oauth' AND status = 'active';
    CREATE TRIGGER profile_entries_github_insert BEFORE INSERT ON profile_entries
      WHEN NEW.capability_slot = 'github'
      BEGIN SELECT RAISE(ABORT, 'GitHub is always included, never an entry'); END;
    CREATE TRIGGER profile_entries_github_update BEFORE UPDATE OF capability_slot ON profile_entries
      WHEN NEW.capability_slot = 'github'
      BEGIN SELECT RAISE(ABORT, 'GitHub is always included, never an entry'); END;";
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCredential {
    pub provider: ProviderId,
    pub authentication_kind: CredentialAuthKind,
    pub display_name: String,
    pub account_hint: Option<String>,
    pub expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub metadata: CredentialMetadata,
    pub persistence: ProtectedStorePersistence,
    /// A retired or uncommitted protected entry still needs exact deletion.
    /// The active material remains usable while this is true.
    pub protected_store_cleanup_pending: bool,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessProfileRecord {
    pub profile: AccessProfile,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessProfileRevisionRecord {
    pub profile: AccessProfile,
    pub profile_created_at_unix_ms: u64,
    pub revision_created_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentAccessBindingRecord {
    pub binding: EnvironmentAccessBinding,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

/// One exact credential operation admitted for the co-located local broker.
///
/// This value is deliberately non-cloneable and non-serializable. It is
/// created only after the authority rederives the environment's current grant
/// and checks the requested capability, operation, and route. Debug output
/// never renders protected material.
pub struct CredentialOperationLease {
    pub credential: CredentialRecord,
    pub grant: DerivedGrant,
    pub permission: GrantPermission,
    material_generation: u64,
    value: ProtectedValue,
}

/// Authority-private admission descriptor sent only over the inherited
/// authority-to-broker channel. It deliberately contains an integer material
/// generation rather than protected material or a protected-store reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CredentialOperationAdmission {
    credential: CredentialRecord,
    grant: DerivedGrant,
    permission: GrantPermission,
    material_generation: u64,
}

impl CredentialOperationLease {
    /// Consume this lease while performing its one authorized operation.
    /// Protected material is borrowed only for the duration of the callback
    /// and is zeroized when the consumed lease is dropped.
    pub fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(self.value.expose_secret())
    }

    /// Return the exact protected-value generation admitted for this operation.
    /// The generation is metadata only and never identifies a store entry on
    /// its own.
    pub fn material_generation(&self) -> u64 {
        self.material_generation
    }
}

impl fmt::Debug for CredentialOperationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialOperationLease")
            .field("credential", &self.credential)
            .field("grant", &self.grant)
            .field("permission", &self.permission)
            .field("material_generation", &self.material_generation)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Material-free request from the authenticated broker boundary.
///
/// The broker is responsible for authenticating the environment generation;
/// the authority binds the resulting material to that exact generation and
/// admits only the capability selected by the environment's current profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOperationLeaseRequest {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub capability_slot: CapabilitySlot,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
}

/// Material-free authorization for one pre-create repository fetch.
///
/// This is deliberately separate from an environment grant: repository
/// resolution happens before the create intent has allocated and durably
/// bound an environment ID. The exact local profile revision still selects
/// the only credential and capability that the one-shot executor may borrow.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryCredentialLeaseRequest {
    pub request_id: Uuid,
    pub profile_id: AccessProfileId,
    pub profile_revision: u64,
    pub source: String,
    pub branch: String,
    pub revision: String,
    pub known_hosts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepositoryGitHubCredentialAdmission {
    credential: CredentialRecord,
    profile_id: AccessProfileId,
    profile_revision: u64,
    permission: GrantPermission,
    material_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepositorySshCredentialAdmission {
    credential: CredentialRecord,
    profile_id: AccessProfileId,
    profile_revision: u64,
    material_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RepositoryCredentialAdmission {
    GitHubOAuth(RepositoryGitHubCredentialAdmission),
    Ssh(RepositorySshCredentialAdmission),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialState {
    PendingWrite,
    Ready,
    PendingDelete,
}

impl MaterialState {
    fn as_str(self) -> &'static str {
        match self {
            Self::PendingWrite => "pending_write",
            Self::Ready => "ready",
            Self::PendingDelete => "pending_delete",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalCredentialError> {
        match value {
            "pending_write" => Ok(Self::PendingWrite),
            "ready" => Ok(Self::Ready),
            "pending_delete" => Ok(Self::PendingDelete),
            _ => Err(LocalCredentialError::CorruptMetadata),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalOperation {
    RollbackWrite,
    DeleteRetired,
}

impl JournalOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::RollbackWrite => "rollback_write",
            Self::DeleteRetired => "delete_retired",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalCredentialError> {
        match value {
            "rollback_write" => Ok(Self::RollbackWrite),
            "delete_retired" => Ok(Self::DeleteRetired),
            _ => Err(LocalCredentialError::CorruptMetadata),
        }
    }
}

struct ProtectedEntryJournal {
    operation: JournalOperation,
    protected_entry_id: ProtectedEntryId,
}

impl fmt::Debug for ProtectedEntryJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedEntryJournal")
            .field("operation", &self.operation)
            .field("protected_entry_id", &"[REDACTED]")
            .finish()
    }
}

struct InternalCredentialRecord {
    public: CredentialRecord,
    material_generation: u64,
    protected_entry_id: ProtectedEntryId,
    material_state: MaterialState,
}

/// Process and durable ownership of one OAuth refresh. An environment's
/// broker refreshes for its grant; a pre-create repository executor refreshes
/// the GitHub connection it was admitted to. Both serialize through the same
/// per-credential owner map and marker, so one refresh token is never spent
/// twice. Untagged: a marker written before repository refresh existed still
/// parses as the environment form.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum CredentialRefreshPermit {
    Environment(EnvironmentRefreshPermit),
    Repository(RepositoryRefreshPermit),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentRefreshPermit {
    channel_id: Uuid,
    refresh_id: Uuid,
    request_id: Uuid,
    grant: Box<DerivedGrant>,
    permission: GrantPermission,
    current_material_generation: u64,
    next_material_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryRefreshPermit {
    channel_id: Uuid,
    refresh_id: Uuid,
    request_id: Uuid,
    /// Re-admitted at reservation and start, exactly as the lease was.
    repository: Box<RepositoryCredentialLeaseRequest>,
    credential_id: CredentialId,
    credential_revocation_generation: u64,
    current_material_generation: u64,
    next_material_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CredentialRefreshAdmission {
    Reserved(CredentialRefreshPermit),
    Recovered,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CredentialRefreshJournal {
    permit: CredentialRefreshPermit,
    phase: CredentialRefreshPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum CredentialRefreshPhase {
    Reserved,
    Started { execution_deadline_unix_ms: u64 },
}

impl EnvironmentRefreshPermit {
    fn request(&self) -> CredentialOperationLeaseRequest {
        CredentialOperationLeaseRequest {
            environment_id: self.grant.environment_id.clone(),
            environment_generation: self.grant.environment_generation,
            capability_slot: self.grant.capability_slot.clone(),
            operation: self.permission.operation.clone(),
            route: self.permission.route.clone(),
        }
    }
}

impl CredentialRefreshPermit {
    pub(crate) fn channel_id(&self) -> Uuid {
        match self {
            Self::Environment(permit) => permit.channel_id,
            Self::Repository(permit) => permit.channel_id,
        }
    }

    pub(crate) fn refresh_id(&self) -> Uuid {
        match self {
            Self::Environment(permit) => permit.refresh_id,
            Self::Repository(permit) => permit.refresh_id,
        }
    }

    pub(crate) fn request_id(&self) -> Uuid {
        match self {
            Self::Environment(permit) => permit.request_id,
            Self::Repository(permit) => permit.request_id,
        }
    }

    pub(crate) fn credential_id(&self) -> &CredentialId {
        match self {
            Self::Environment(permit) => &permit.grant.credential_id,
            Self::Repository(permit) => &permit.credential_id,
        }
    }

    pub(crate) fn credential_revocation_generation(&self) -> u64 {
        match self {
            Self::Environment(permit) => permit.grant.credential_revocation_generation,
            Self::Repository(permit) => permit.credential_revocation_generation,
        }
    }

    pub(crate) fn current_material_generation(&self) -> u64 {
        match self {
            Self::Environment(permit) => permit.current_material_generation,
            Self::Repository(permit) => permit.current_material_generation,
        }
    }

    pub(crate) fn next_material_generation(&self) -> u64 {
        match self {
            Self::Environment(permit) => permit.next_material_generation,
            Self::Repository(permit) => permit.next_material_generation,
        }
    }
}

impl fmt::Debug for InternalCredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalCredentialRecord")
            .field("public", &self.public)
            .field("material_generation", &self.material_generation)
            .field("protected_entry_id", &"[REDACTED]")
            .field("material_state", &self.material_state)
            .finish()
    }
}

/// Single-process local authority state. The mutex serializes SQLite and OS
/// protected-store transitions so callers cannot interleave one credential's
/// journal with another operation.
pub struct LocalCredentialAuthority<S: ProtectedStore> {
    /// The recorded store this authority selected, when opened by selection.
    protected_store_identity: Option<AuthorityProtectedStore>,
    _authority_lock: AuthorityLock,
    connection: Mutex<Connection>,
    protected_store: S,
    catalog: ProviderCatalog,
    owner_id: OwnerId,
    active_refreshes: Mutex<BTreeMap<CredentialId, CredentialRefreshPermit>>,
}

impl<S: ProtectedStore> fmt::Debug for LocalCredentialAuthority<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCredentialAuthority")
            .field("protected_store", &"[REDACTED]")
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

/// The persistent store a production authority serves from and records:
/// a backend plus, for the Keychain backend only, an explicit keychain file
/// (tests and synthetic acceptance; production uses the login keychain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityProtectedStore {
    pub backend: ProtectedStoreBackend,
    pub keychain: Option<PathBuf>,
}

impl AuthorityProtectedStore {
    pub fn platform_default() -> Option<Self> {
        ProtectedStoreBackend::platform_default().map(|backend| Self {
            backend,
            keychain: None,
        })
    }

    /// An explicit keychain belongs only to the Keychain backend and must be
    /// an absolute path.
    pub fn is_valid(&self) -> bool {
        match &self.keychain {
            None => true,
            Some(path) => {
                self.backend == ProtectedStoreBackend::Keychain
                    && path.is_absolute()
                    && path.to_str().is_some()
            }
        }
    }

    /// `secret-service`, `keychain`, `file` or `keychain:/absolute/path`.
    pub fn to_record(&self) -> String {
        match &self.keychain {
            None => self.backend.as_str().to_owned(),
            Some(path) => format!("{}:{}", self.backend.as_str(), path.display()),
        }
    }

    pub fn from_record(value: &str) -> Option<Self> {
        let (backend, keychain) = match value.split_once(':') {
            Some((backend, path)) => (backend, Some(PathBuf::from(path))),
            None => (value, None),
        };
        let store = Self {
            backend: ProtectedStoreBackend::parse(backend)?,
            keychain,
        };
        store.is_valid().then_some(store)
    }
}

impl fmt::Display for AuthorityProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.keychain {
            None => write!(formatter, "{}", self.backend),
            Some(path) => write!(formatter, "{} at {}", self.backend, path.display()),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl LocalCredentialAuthority<SelectedProtectedStore> {
    /// Open the authority on its configured backend, moving values recorded
    /// under another backend first. See `store_backend` for the guarantees.
    pub fn open_selected(
        root: &Path,
        selection: &AuthorityProtectedStore,
        catalog: ProviderCatalog,
    ) -> Result<Self, LocalCredentialError> {
        if !selection.is_valid() {
            return Err(LocalCredentialError::ProtectedStoreSwitch(
                ProtectedStoreError::Unavailable,
            ));
        }
        let file_directory = root.join(FILE_STORE_DIRECTORY);
        // Every store, including a previous one being emptied, is opened at
        // its own recorded location, never at the configured one.
        let open = |store: &AuthorityProtectedStore| {
            SelectedProtectedStore::open(store.backend, &file_directory, store.keychain.as_deref())
                .map(|store| Box::new(store) as Box<dyn ProtectedStore>)
        };
        let store = SelectedProtectedStore::open(
            selection.backend,
            &file_directory,
            selection.keychain.as_deref(),
        )
        .map_err(LocalCredentialError::ProtectedStoreSwitch)?;
        Self::open_inner(root, store, catalog, Some((selection, &open)))
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    pub fn open(
        root: &Path,
        protected_store: S,
        catalog: ProviderCatalog,
    ) -> Result<Self, LocalCredentialError> {
        Self::open_inner(root, protected_store, catalog, None)
    }

    #[cfg(test)]
    pub(crate) fn open_with_backend(
        root: &Path,
        protected_store: S,
        catalog: ProviderCatalog,
        selection: &AuthorityProtectedStore,
        open: store_backend::OpenProtectedStore<'_>,
    ) -> Result<Self, LocalCredentialError> {
        Self::open_inner(root, protected_store, catalog, Some((selection, open)))
    }

    fn open_inner(
        root: &Path,
        protected_store: S,
        catalog: ProviderCatalog,
        selection: Option<(
            &AuthorityProtectedStore,
            store_backend::OpenProtectedStore<'_>,
        )>,
    ) -> Result<Self, LocalCredentialError> {
        let owner_id = OwnerId::parse(LOCAL_OWNER_ID)?;
        #[cfg(unix)]
        ensure_private_root(root)?;
        let authority_lock = AuthorityLock::acquire(root)?;
        let connection = open_database(root)?;
        ensure_authority_identity(&connection, &owner_id, protected_store.persistence())?;
        if let Some((selected, open)) = selection {
            store_backend::select_protected_store(&connection, selected, &protected_store, open)?;
        }
        let authority = Self {
            protected_store_identity: selection.map(|(selected, _)| selected.clone()),
            _authority_lock: authority_lock,
            connection: Mutex::new(connection),
            protected_store,
            catalog,
            owner_id,
            active_refreshes: Mutex::new(BTreeMap::new()),
        };
        authority.reconcile()?;
        authority.reconcile_workload_secrets()?;
        Ok(authority)
    }

    pub fn owner_id(&self) -> &OwnerId {
        &self.owner_id
    }

    pub fn protected_store_persistence(&self) -> ProtectedStorePersistence {
        self.protected_store.persistence()
    }

    pub fn protected_store_identity(&self) -> Option<&AuthorityProtectedStore> {
        self.protected_store_identity.as_ref()
    }

    pub(crate) fn validate_ssh_enrollment_name(
        &self,
        display_name: &str,
    ) -> Result<(), AccessError> {
        if display_name.is_empty()
            || display_name.len() > 256
            || display_name.trim() != display_name
            || display_name.chars().any(char::is_control)
        {
            return Err(AccessError::InvalidField {
                field: "credential display name",
            });
        }
        let provider = ProviderId::parse("ssh")?;
        let definition =
            self.catalog
                .get(&provider)
                .ok_or_else(|| AccessError::ProviderUnavailable {
                    provider: provider.clone(),
                })?;
        if !definition.supports_authentication_kind(CredentialAuthKind::SshKey) {
            return Err(AccessError::UnsupportedAuthenticationKind {
                provider,
                kind: CredentialAuthKind::SshKey,
            });
        }
        Ok(())
    }

    pub fn add_credential(
        &self,
        input: NewCredential,
        material: ProtectedValue,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        if input.provider.as_str() == "ssh"
            || input.authentication_kind == CredentialAuthKind::SshKey
        {
            return Err(LocalCredentialError::SshCredentialRequiresEnrollment);
        }
        self.add_credential_inner(input, material, None, || Ok(()))
    }

    pub(crate) fn add_ssh_credential(
        &self,
        display_name: String,
        expires_at_unix: Option<u64>,
        prepared: PreparedSshCredential,
        publication_check: impl FnOnce() -> Result<(), LocalCredentialError>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let (public_key, material) = prepared.into_parts();
        self.add_credential_inner(
            NewCredential {
                provider: ProviderId::parse("ssh")?,
                authentication_kind: CredentialAuthKind::SshKey,
                display_name,
                account_hint: None,
                expires_at_unix,
            },
            material,
            Some(SshPublicKeyMetadata {
                openssh: public_key.openssh().to_string(),
                fingerprint: public_key.fingerprint().to_string(),
            }),
            publication_check,
        )
    }

    fn add_credential_inner(
        &self,
        input: NewCredential,
        material: ProtectedValue,
        ssh_public_key: Option<SshPublicKeyMetadata>,
        publication_check: impl FnOnce() -> Result<(), LocalCredentialError>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let provider =
            self.catalog
                .get(&input.provider)
                .ok_or_else(|| AccessError::ProviderUnavailable {
                    provider: input.provider.clone(),
                })?;
        // A Claude subscription token (Anthropic OAuth) is a platform
        // credential only, whatever the shared catalog admits. The native
        // client projection has no subscription form.
        // TODO(native-claude-subscription-form): admit it locally once native
        // VMs project Claude Code's subscription mode.
        if !provider.supports_authentication_kind(input.authentication_kind)
            || (input.provider.as_str() == "anthropic"
                && input.authentication_kind == CredentialAuthKind::OAuth)
        {
            return Err(AccessError::UnsupportedAuthenticationKind {
                provider: input.provider,
                kind: input.authentication_kind,
            }
            .into());
        }

        let id = CredentialId::parse(Uuid::new_v4().to_string())?;
        let metadata = CredentialMetadata {
            id: id.clone(),
            placement: Placement::Local,
            owner: Owner::User(self.owner_id.clone()),
            provider: input.provider,
            authentication_kind: input.authentication_kind,
            display_name: input.display_name,
            account_hint: input.account_hint,
            ssh_public_key,
            status: CredentialStatus::Active,
            expires_at_unix: input.expires_at_unix,
            revocation_generation: 1,
        };
        metadata.validate()?;
        let entry_id = protected_entry_id(&id, 1)?;
        let persistence = self.protected_store.persistence();
        let now = unix_millis()?;
        let expires_at = optional_u64_to_i64(metadata.expires_at_unix)?;

        let connection = self.connection()?;
        match self.protected_store.get(&entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        // This is the publication boundary. Enrollment admission, shutdown,
        // and the original RPC deadline are rechecked while the SQLite
        // serialization lock is held. Once the pending row exists, journal
        // disposition must finish even if the RPC waiter disappears.
        publication_check()?;
        // GitHub is one connection per store. A second one fails closed; the
        // existing connection is reconnected in place or deleted first.
        if metadata.provider.as_str() == "github"
            && metadata.authentication_kind == CredentialAuthKind::OAuth
            && github_connection_exists(&connection)?
        {
            return Err(LocalCredentialError::GitHubAlreadyConnected);
        }
        let inserted = connection.execute(
            "INSERT INTO credentials(
               id, provider, authentication_kind, display_name, account_hint,
               ssh_public_key_openssh, ssh_public_key_fingerprint,
               status, expires_at_unix, revocation_generation,
               material_generation, protected_entry_id, store_persistence, material_state,
               created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?12, ?13, ?14, ?14)",
            params![
                id.as_str(),
                metadata.provider.as_str(),
                auth_kind_to_str(metadata.authentication_kind),
                metadata.display_name,
                metadata.account_hint,
                metadata
                    .ssh_public_key
                    .as_ref()
                    .map(|key| key.openssh.as_str()),
                metadata
                    .ssh_public_key
                    .as_ref()
                    .map(|key| key.fingerprint.as_str()),
                status_to_str(metadata.status),
                expires_at,
                i64::try_from(metadata.revocation_generation)
                    .map_err(|_| LocalCredentialError::InvalidTime)?,
                entry_id.expose_reference(),
                persistence_to_str(persistence),
                MaterialState::PendingWrite.as_str(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
            ],
        );
        if let Err(error) = inserted {
            return Err(map_insert_error(error));
        }

        if let Err(error) = self.protected_store.put(&entry_id, &material) {
            if self.protected_store.delete(&entry_id).is_ok() {
                delete_pending_write(&connection, &id)?;
            }
            return Err(error.into());
        }

        let changed = connection
            .execute(
                "UPDATE credentials
                 SET material_state = 'ready', updated_at_unix_ms = ?2
                 WHERE id = ?1 AND material_state = 'pending_write'",
                params![
                    id.as_str(),
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id FROM credentials
                 WHERE material_state = 'ready'
                 ORDER BY display_name COLLATE NOCASE, id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        let ids = rows
            .map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id =
                    CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
                load_internal_credential(&connection, &id, Some(MaterialState::Ready))
                    .map(|record| record.public)
            })
            .collect()
    }

    pub fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn resolve_credential(
        &self,
        display_name: &str,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let id = connection
            .query_row(
                "SELECT id FROM credentials
                 WHERE display_name = ?1 COLLATE NOCASE AND material_state = 'ready'",
                [display_name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(LocalCredentialError::CredentialNotFound)?;
        let id = CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn rename_credential(
        &self,
        id: &CredentialId,
        display_name: String,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        let mut metadata = current.public.metadata;
        metadata.display_name = display_name;
        metadata.validate()?;
        let changed = connection.execute(
            "UPDATE credentials SET display_name = ?2, updated_at_unix_ms = ?3
             WHERE id = ?1 AND material_state = 'ready'",
            params![
                id.as_str(),
                metadata.display_name,
                i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        );
        match changed {
            Ok(1) => load_internal_credential(&connection, id, Some(MaterialState::Ready))
                .map(|record| record.public),
            Ok(_) => Err(LocalCredentialError::CorruptMetadata),
            Err(error) => Err(map_insert_error(error)),
        }
    }

    /// Atomically make a new protected value active behind the same credential
    /// ID. The old value remains active until the new entry and metadata commit
    /// are durable. Failure to delete the retired entry is journaled and
    /// reported through metadata without making the new value unavailable.
    /// The caller must supply the exact observed revision. An absent account
    /// hint clears the previous hint; callers preserving it must pass it back.
    pub fn rotate_credential_material(
        &self,
        id: &CredentialId,
        expected_revocation_generation: u64,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
        account_hint: Option<String>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        // Hold the refresh-owner lock through every journal and protected-store
        // mutation. A check-then-unlock here would let a broker begin a refresh
        // against the same next material generation while a manual rotation is
        // still in flight.
        let active_refreshes = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        if active_refreshes.contains_key(id) {
            return Err(LocalCredentialError::CredentialRefreshInProgress);
        }
        let mut connection = self.connection()?;
        let mut current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.provider.as_str() == "ssh"
            || current.public.metadata.authentication_kind == CredentialAuthKind::SshKey
        {
            return Err(LocalCredentialError::SshCredentialRequiresEnrollment);
        }
        if expected_revocation_generation == 0
            || current.public.metadata.revocation_generation != expected_revocation_generation
        {
            // Even journal reconciliation can delete or promote protected
            // material. A stale caller has no authority to initiate it.
            return Err(LocalCredentialError::StaleCredentialRevision);
        }
        let mut replacement_metadata = current.public.metadata.clone();
        replacement_metadata.account_hint = account_hint;
        replacement_metadata.expires_at_unix = expires_at_unix;
        replacement_metadata.status = CredentialStatus::Active;
        replacement_metadata.validate()?;
        let expires_at = optional_u64_to_i64(expires_at_unix)?;
        reconcile_ready_journal(&connection, &self.protected_store, &current)?;
        current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.revocation_generation != expected_revocation_generation {
            // Recovery may have promoted an abandoned OAuth refresh. Do not
            // replace that newer result using an earlier confirmation.
            return Err(LocalCredentialError::StaleCredentialRevision);
        }

        let generation = current
            .public
            .metadata
            .revocation_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let material_generation = current
            .material_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let next_entry_id = protected_entry_id(id, material_generation)?;
        match self.protected_store.get(&next_entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        let now = unix_millis()?;
        insert_protected_entry_journal(
            &connection,
            id,
            JournalOperation::RollbackWrite,
            &next_entry_id,
            now,
        )?;

        if let Err(error) = self.protected_store.put(&next_entry_id, &material) {
            if self.protected_store.delete(&next_entry_id).is_ok() {
                delete_protected_entry_journal(&connection, id)?;
            }
            return Err(error.into());
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE credentials
                 SET protected_entry_id = ?2, status = 'active', expires_at_unix = ?3,
                     revocation_generation = ?4, material_generation = ?5,
                     updated_at_unix_ms = ?6, account_hint = ?7
                 WHERE id = ?1 AND material_state = 'ready' AND revocation_generation = ?8",
                params![
                    id.as_str(),
                    next_entry_id.expose_reference(),
                    expires_at,
                    i64::try_from(generation).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(material_generation)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
                    replacement_metadata.account_hint,
                    i64::try_from(expected_revocation_generation)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        let journal_changed = transaction
            .execute(
                "UPDATE protected_entry_journal
                 SET operation = 'delete_retired', protected_entry_id = ?2
                 WHERE credential_id = ?1 AND operation = 'rollback_write'",
                params![id.as_str(), current.protected_entry_id.expose_reference()],
            )
            .map_err(database_error)?;
        if journal_changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        transaction.commit().map_err(database_error)?;

        if self
            .protected_store
            .delete(&current.protected_entry_id)
            .is_ok()
        {
            delete_protected_entry_journal(&connection, id)?;
        }
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
        request: &CredentialOperationLeaseRequest,
        grant: &DerivedGrant,
        material_generation: u64,
    ) -> Result<CredentialRefreshAdmission, LocalCredentialError> {
        if channel_id.is_nil()
            || refresh_id.is_nil()
            || request_id.is_nil()
            || material_generation == 0
            || grant.credential_revocation_generation == 0
        {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        let permit = EnvironmentRefreshPermit {
            channel_id,
            refresh_id,
            request_id,
            grant: Box::new(grant.clone()),
            permission: GrantPermission {
                operation: request.operation.clone(),
                route: request.route.clone(),
            },
            current_material_generation: material_generation,
            next_material_generation: material_generation
                .checked_add(1)
                .ok_or(LocalCredentialError::CorruptMetadata)?,
        };
        if permit.request() != *request {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        self.reserve_credential_refresh(CredentialRefreshPermit::Environment(permit))
    }

    /// Reserve a refresh of the GitHub connection a pre-create repository
    /// executor was admitted to, before any environment exists. The same
    /// owner map and marker as environment refreshes serialize it, so a
    /// broker and a checkout never spend one refresh token twice.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_repository_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
        repository: &RepositoryCredentialLeaseRequest,
        credential_id: &CredentialId,
        revocation_generation: u64,
        material_generation: u64,
    ) -> Result<CredentialRefreshAdmission, LocalCredentialError> {
        if channel_id.is_nil()
            || refresh_id.is_nil()
            || request_id.is_nil()
            || material_generation == 0
            || revocation_generation == 0
        {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        let permit = RepositoryRefreshPermit {
            channel_id,
            refresh_id,
            request_id,
            repository: Box::new(repository.clone()),
            credential_id: credential_id.clone(),
            credential_revocation_generation: revocation_generation,
            current_material_generation: material_generation,
            next_material_generation: material_generation
                .checked_add(1)
                .ok_or(LocalCredentialError::CorruptMetadata)?,
        };
        self.reserve_credential_refresh(CredentialRefreshPermit::Repository(permit))
    }

    fn reserve_credential_refresh(
        &self,
        permit: CredentialRefreshPermit,
    ) -> Result<CredentialRefreshAdmission, LocalCredentialError> {
        // Reserve process ownership before any blocking protected-store call.
        // Manual replacement and deletion use this same lock. The durable
        // reservation is then written under the SQLite serialization boundary.
        {
            let mut active = self
                .active_refreshes
                .lock()
                .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
            if active.contains_key(permit.credential_id()) {
                return Err(LocalCredentialError::CredentialRefreshInProgress);
            }
            if active
                .values()
                .any(|owner| owner.refresh_id() == permit.refresh_id())
            {
                return Err(LocalCredentialError::StaleCredentialRefresh);
            }
            active.insert(permit.credential_id().clone(), permit.clone());
        }
        let result = self.prepare_credential_refresh(&permit);
        if !matches!(result, Ok(CredentialRefreshAdmission::Reserved(_))) {
            self.release_credential_refresh(
                permit.credential_id(),
                permit.channel_id(),
                permit.refresh_id(),
            )?;
        }
        result
    }

    /// Re-admit a refresh's owner now: the same credential, still OAuth and
    /// still selected by the same environment grant or repository request.
    /// The revocation generation is not compared here; callers compare it.
    /// Returns the admitted material and revocation generations.
    fn readmit_refresh(
        &self,
        connection: &Connection,
        permit: &CredentialRefreshPermit,
    ) -> Result<(u64, u64), LocalCredentialError> {
        match permit {
            CredentialRefreshPermit::Environment(permit) => {
                let admission =
                    self.admit_environment_credential_operation_at(connection, &permit.request())?;
                let mut expected_grant = permit.grant.clone();
                expected_grant.credential_revocation_generation =
                    admission.grant.credential_revocation_generation;
                if !refresh_grant_matches(&admission.grant, &expected_grant)?
                    || admission.credential.metadata.authentication_kind
                        != CredentialAuthKind::OAuth
                {
                    return Err(LocalCredentialError::StaleCredentialRefresh);
                }
                Ok((
                    admission.material_generation,
                    admission.grant.credential_revocation_generation,
                ))
            }
            CredentialRefreshPermit::Repository(permit) => {
                let RepositoryCredentialAdmission::GitHubOAuth(admission) =
                    self.admit_repository_credential_operation_at(connection, &permit.repository)?
                else {
                    return Err(LocalCredentialError::StaleCredentialRefresh);
                };
                if admission.credential.metadata.id != permit.credential_id
                    || admission.credential.metadata.authentication_kind
                        != CredentialAuthKind::OAuth
                {
                    return Err(LocalCredentialError::StaleCredentialRefresh);
                }
                Ok((
                    admission.material_generation,
                    admission.credential.metadata.revocation_generation,
                ))
            }
        }
    }

    /// Persist Started before the broker may send a provider request. This
    /// transition is deliberately not idempotent: a lost acknowledgement must
    /// never authorize replay of a possibly consumed provider refresh token.
    pub(crate) fn start_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<u64, LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let connection = self.connection()?;
        let marker = load_credential_refresh_marker(&connection, permit.credential_id())?
            .filter(|marker| {
                marker.permit == permit && marker.phase == CredentialRefreshPhase::Reserved
            })
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        let (material_generation, revocation_generation) =
            self.readmit_refresh(&connection, &permit)?;
        if material_generation != permit.current_material_generation()
            || revocation_generation != permit.credential_revocation_generation()
        {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        let execution_deadline_unix_ms = unix_millis()?
            .checked_add(CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS * 1_000)
            .ok_or(LocalCredentialError::InvalidTime)?;
        let started = CredentialRefreshJournal {
            phase: CredentialRefreshPhase::Started {
                execution_deadline_unix_ms,
            },
            ..marker
        };
        let changed = connection
            .execute(
                "UPDATE authority_metadata SET value = ?2 WHERE key = ?1",
                params![
                    credential_refresh_marker_key(permit.credential_id()),
                    serde_json::to_string(&started)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        Ok(execution_deadline_unix_ms)
    }

    pub(crate) fn commit_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<(CredentialRecord, u64), LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let connection = self.connection()?;
        let current = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?;
        let marker = load_credential_refresh_marker(&connection, permit.credential_id())?
            .filter(|marker| {
                marker.permit == permit
                    && matches!(marker.phase, CredentialRefreshPhase::Started { .. })
            })
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        validate_refresh_current(&current, &marker)?;
        let journal = load_validated_protected_entry_journal(&connection, &current)?
            .filter(|journal| journal.operation == JournalOperation::RollbackWrite)
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        // Publication is durable bookkeeping, not fresh request authority.
        // The shared broker obtains a new operation lease after this commit.
        // A completed blocking write remains recoverable after its deadline.
        promote_oauth_refresh(&connection, &self.protected_store, &current, &journal)?;
        let record = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?
        .public;
        drop(connection);
        self.release_credential_refresh(permit.credential_id(), channel_id, refresh_id)?;
        Ok((record, permit.next_material_generation()))
    }

    /// Cancellation is valid only while no provider request has been started.
    pub(crate) fn abort_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let connection = self.connection()?;
        let marker = load_credential_refresh_marker(&connection, permit.credential_id())?
            .filter(|marker| {
                marker.permit == permit && marker.phase == CredentialRefreshPhase::Reserved
            })
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        let current = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?;
        validate_refresh_current(&current, &marker)?;
        let journal = load_validated_protected_entry_journal(&connection, &current)?
            .filter(|journal| journal.operation == JournalOperation::RollbackWrite)
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        if self
            .protected_store
            .get(&journal.protected_entry_id)?
            .is_some()
        {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        delete_credential_refresh_journal(&connection, permit.credential_id())?;
        drop(connection);
        self.release_credential_refresh(permit.credential_id(), channel_id, refresh_id)
    }

    /// Invalidate an unsuccessful or ambiguous Started attempt. Neither a
    /// provider response nor an opaque transport error is retained.
    pub(crate) fn fail_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let connection = self.connection()?;
        let marker = load_credential_refresh_marker(&connection, permit.credential_id())?
            .filter(|marker| {
                marker.permit == permit
                    && matches!(marker.phase, CredentialRefreshPhase::Started { .. })
            })
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        let current = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?;
        validate_refresh_current(&current, &marker)?;
        let journal = load_validated_protected_entry_journal(&connection, &current)?
            .filter(|journal| journal.operation == JournalOperation::RollbackWrite)
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        if self
            .protected_store
            .get(&journal.protected_entry_id)?
            .is_some()
        {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        fail_oauth_refresh(&connection, &current)?;
        let record = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?
        .public;
        drop(connection);
        self.release_credential_refresh(permit.credential_id(), channel_id, refresh_id)?;
        Ok(record)
    }

    pub(crate) fn release_channel_credential_refreshes(
        &self,
        channel_id: Uuid,
    ) -> Result<(), LocalCredentialError> {
        let mut active = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        // This is called only after the channel's blocking operations drain.
        // Its journal is reconciled by the next admission or authority restart.
        // Elapsed time alone never removes an owner from this map.
        active.retain(|_, owner| owner.channel_id() != channel_id);
        Ok(())
    }

    fn prepare_credential_refresh(
        &self,
        permit: &CredentialRefreshPermit,
    ) -> Result<CredentialRefreshAdmission, LocalCredentialError> {
        let connection = self.connection()?;
        let id = permit.credential_id();
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        // An abandoned Started attempt may already have a durable output.
        // Promote that output before evaluating this request's current grant.
        // A Started attempt without output invalidates the old token instead.
        reconcile_ready_journal(&connection, &self.protected_store, &current)?;
        let (material_generation, revocation_generation) =
            self.readmit_refresh(&connection, permit)?;
        if material_generation != permit.current_material_generation()
            || revocation_generation != permit.credential_revocation_generation()
        {
            // Only discovery of this exact staged predecessor is recovery.
            // Unrelated rotation or a changed request identity is stale.
            if current.material_generation == permit.current_material_generation()
                && current.public.metadata.revocation_generation
                    == permit.credential_revocation_generation()
                && material_generation == permit.next_material_generation()
                && revocation_generation
                    == permit
                        .credential_revocation_generation()
                        .checked_add(1)
                        .ok_or(LocalCredentialError::CorruptMetadata)?
            {
                return Ok(CredentialRefreshAdmission::Recovered);
            }
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        let next_entry_id = protected_entry_id(id, permit.next_material_generation())?;
        match self.protected_store.get(&next_entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        insert_credential_refresh_journal(
            &connection,
            id,
            &next_entry_id,
            &CredentialRefreshJournal {
                permit: permit.clone(),
                phase: CredentialRefreshPhase::Reserved,
            },
            unix_millis()?,
        )?;
        Ok(CredentialRefreshAdmission::Reserved(permit.clone()))
    }

    fn active_refresh_permit(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<CredentialRefreshPermit, LocalCredentialError> {
        let active = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        active
            .values()
            .find(|owner| {
                owner.channel_id() == channel_id
                    && owner.refresh_id() == refresh_id
                    && owner.request_id() == request_id
            })
            .cloned()
            .ok_or(LocalCredentialError::StaleCredentialRefresh)
    }

    fn release_credential_refresh(
        &self,
        id: &CredentialId,
        channel_id: Uuid,
        refresh_id: Uuid,
    ) -> Result<(), LocalCredentialError> {
        let mut active = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        match active.get(id) {
            Some(owner) if owner.channel_id() == channel_id && owner.refresh_id() == refresh_id => {
                active.remove(id);
                Ok(())
            }
            _ => Err(LocalCredentialError::StaleCredentialRefresh),
        }
    }

    pub fn revoke_credential(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.status == CredentialStatus::Revoked {
            return Ok(current.public);
        }
        let generation = current
            .public
            .metadata
            .revocation_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let changed = connection
            .execute(
                "UPDATE credentials
                 SET status = 'revoked', revocation_generation = ?2, updated_at_unix_ms = ?3
                 WHERE id = ?1 AND material_state = 'ready'",
                params![
                    id.as_str(),
                    i64::try_from(generation).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn delete_credential(&self, id: &CredentialId) -> Result<(), LocalCredentialError> {
        // Keep refresh admission excluded until both metadata and protected
        // entries have reached the delete outcome. Otherwise a refresh could
        // install its rollback journal after this initial check.
        let active_refreshes = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        if active_refreshes.contains_key(id) {
            return Err(LocalCredentialError::CredentialRefreshInProgress);
        }
        let connection = self.connection()?;
        if profile_or_binding_references_credential(&connection, id)? {
            return Err(LocalCredentialError::CredentialInUse);
        }
        let mut record = load_internal_credential(&connection, id, None)?;
        if record.material_state == MaterialState::PendingWrite {
            return Err(LocalCredentialError::CredentialUnavailable);
        }
        if record.material_state == MaterialState::Ready {
            reconcile_ready_journal(&connection, &self.protected_store, &record)?;
            record = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        }
        let journal = load_validated_protected_entry_journal(&connection, &record)?;
        if record.material_state == MaterialState::Ready {
            let changed = connection
                .execute(
                    "UPDATE credentials SET material_state = 'pending_delete', updated_at_unix_ms = ?2
                     WHERE id = ?1 AND material_state = 'ready'",
                    params![
                        id.as_str(),
                        i64::try_from(unix_millis()?)
                            .map_err(|_| LocalCredentialError::InvalidTime)?
                    ],
                )
                .map_err(database_error)?;
            if changed != 1 {
                return Err(LocalCredentialError::CorruptMetadata);
            }
        }
        self.protected_store
            .delete(&record.protected_entry_id)
            .map_err(LocalCredentialError::from)?;
        if let Some(journal) = journal {
            self.protected_store
                .delete(&journal.protected_entry_id)
                .map_err(LocalCredentialError::from)?;
        }
        delete_pending_delete(&connection, id)
    }

    pub fn lease_environment_credential_operation(
        &self,
        request: &CredentialOperationLeaseRequest,
    ) -> Result<CredentialOperationLease, LocalCredentialError> {
        let admission = self.admit_environment_credential_operation(request)?;
        deny_generic_ssh_lease(&admission.credential.metadata)?;
        let entry_id = protected_entry_id(
            &admission.credential.metadata.id,
            admission.material_generation,
        )?;
        let value = self
            .protected_store
            .get(&entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)?;
        Ok(CredentialOperationLease {
            credential: admission.credential,
            grant: admission.grant,
            permission: admission.permission,
            material_generation: admission.material_generation,
            value,
        })
    }

    pub(crate) fn admit_environment_credential_operation(
        &self,
        request: &CredentialOperationLeaseRequest,
    ) -> Result<CredentialOperationAdmission, LocalCredentialError> {
        let connection = self.connection()?;
        self.admit_environment_credential_operation_at(&connection, request)
    }

    /// The inherited channel selects one exact profile, including explicit
    /// absence. Binding comparison and grant derivation share the authority
    /// lock so a concurrent replacement cannot select a different credential.
    pub(crate) fn admit_selected_environment_credential_operation(
        &self,
        request: &CredentialOperationLeaseRequest,
        expected: Option<&EnvironmentAccessBinding>,
    ) -> Result<CredentialOperationAdmission, LocalCredentialError> {
        let connection = self.connection()?;
        check_selected_environment_binding(&connection, &request.environment_id, expected)?;
        self.admit_environment_credential_operation_at(&connection, request)
    }

    pub(crate) fn read_admitted_credential_material(
        &self,
        admission: &CredentialOperationAdmission,
    ) -> Result<ProtectedValue, LocalCredentialError> {
        let entry_id = protected_entry_id(
            &admission.credential.metadata.id,
            admission.material_generation,
        )?;
        self.protected_store
            .get(&entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)
    }

    pub(crate) fn revalidate_credential_operation(
        &self,
        request: &CredentialOperationLeaseRequest,
        captured: &CredentialOperationAdmission,
    ) -> Result<(), LocalCredentialError> {
        if self.admit_environment_credential_operation(request)? != *captured {
            return Err(LocalCredentialError::CredentialOperationLeaseDenied);
        }
        Ok(())
    }

    fn admit_environment_credential_operation_at(
        &self,
        connection: &Connection,
        request: &CredentialOperationLeaseRequest,
    ) -> Result<CredentialOperationAdmission, LocalCredentialError> {
        let binding = load_environment_access_binding(connection, &request.environment_id)?.binding;
        let grant = derive_local_environment_grants(
            connection,
            &binding,
            request.environment_generation,
            &self.owner_id,
            &self.catalog,
        )?
        .into_iter()
        .find(|grant| grant.capability_slot == request.capability_slot)
        .ok_or(LocalCredentialError::CredentialOperationLeaseDenied)?;
        let permission = GrantPermission {
            operation: request.operation.clone(),
            route: request.route.clone(),
        };
        if !grant.permissions.contains(&permission) {
            return Err(LocalCredentialError::CredentialOperationLeaseDenied);
        }
        let record =
            load_internal_credential(connection, &grant.credential_id, Some(MaterialState::Ready))?;
        if record.public.metadata.revocation_generation != grant.credential_revocation_generation {
            return Err(LocalCredentialError::CredentialOperationLeaseDenied);
        }
        if record.public.metadata.status != CredentialStatus::Active {
            return Err(LocalCredentialError::CredentialInactive);
        }
        if let Some(expires_at) = record.public.metadata.expires_at_unix
            && expires_at <= unix_seconds()?
        {
            return Err(LocalCredentialError::CredentialInactive);
        }
        Ok(CredentialOperationAdmission {
            credential: record.public,
            grant,
            permission,
            material_generation: record.material_generation,
        })
    }

    pub(crate) fn admit_repository_credential_operation(
        &self,
        request: &RepositoryCredentialLeaseRequest,
    ) -> Result<RepositoryCredentialAdmission, LocalCredentialError> {
        let connection = self.connection()?;
        self.admit_repository_credential_operation_at(&connection, request)
    }

    /// Repository admission under a connection the caller already holds,
    /// such as a refresh journal transition.
    fn admit_repository_credential_operation_at(
        &self,
        connection: &Connection,
        request: &RepositoryCredentialLeaseRequest,
    ) -> Result<RepositoryCredentialAdmission, LocalCredentialError> {
        let transport = crate::repository::validate_repository_lease_request(request)
            .map_err(|_| LocalCredentialError::CredentialOperationLeaseDenied)?;
        let profile =
            load_profile_revision(connection, &request.profile_id, request.profile_revision)?
                .profile;
        let capability_slot = match transport {
            crate::repository::LocalRepositoryTransport::GitHubOAuth => CapabilitySlot::github(),
            crate::repository::LocalRepositoryTransport::Ssh => {
                CapabilitySlot::parse("ssh").expect("canonical SSH capability slot")
            }
        };
        // GitHub checkout uses the store's one current connection, which every
        // profile includes; it never falls back to another credential. Other
        // transports use the revision's exact entry.
        let credential_id = match transport {
            crate::repository::LocalRepositoryTransport::GitHubOAuth => {
                match active_github_connection(connection)? {
                    Some(id) => id,
                    // An inactive connection needs reconnecting.
                    None if github_connection_exists(connection)? => {
                        return Err(LocalCredentialError::CredentialInactive);
                    }
                    None => return Err(LocalCredentialError::CredentialOperationLeaseDenied),
                }
            }
            crate::repository::LocalRepositoryTransport::Ssh => profile
                .entries
                .get(&capability_slot)
                .cloned()
                .ok_or(LocalCredentialError::CredentialOperationLeaseDenied)?,
        };
        let record =
            load_internal_credential(connection, &credential_id, Some(MaterialState::Ready))?;
        let permissions = match transport {
            crate::repository::LocalRepositoryTransport::GitHubOAuth => vec![GrantPermission {
                operation: BrokerOperationId::parse("git-fetch")
                    .expect("canonical Git fetch operation ID"),
                route: BrokerRouteId::parse("github-https")
                    .expect("canonical GitHub HTTPS route ID"),
            }],
            crate::repository::LocalRepositoryTransport::Ssh => ["ssh-identities", "ssh-sign"]
                .into_iter()
                .map(|operation| GrantPermission {
                    operation: BrokerOperationId::parse(operation)
                        .expect("canonical SSH operation ID"),
                    route: BrokerRouteId::parse("ssh-agent").expect("canonical SSH agent route ID"),
                })
                .collect(),
        };
        let capability = self
            .catalog
            .get(&record.public.metadata.provider)
            .and_then(|provider| provider.capabilities.get(&capability_slot))
            .filter(|capability| {
                capability
                    .authentication_kinds
                    .contains(&record.public.metadata.authentication_kind)
                    && permissions
                        .iter()
                        .all(|permission| capability.permissions.contains(permission))
            })
            .ok_or(LocalCredentialError::CredentialOperationLeaseDenied)?;
        debug_assert!(
            permissions
                .iter()
                .all(|permission| capability.permissions.contains(permission))
        );
        let exact_credential_kind = match transport {
            crate::repository::LocalRepositoryTransport::GitHubOAuth => {
                record.public.metadata.provider.as_str() == "github"
                    && record.public.metadata.authentication_kind == CredentialAuthKind::OAuth
            }
            crate::repository::LocalRepositoryTransport::Ssh => {
                record.public.metadata.provider.as_str() == "ssh"
                    && record.public.metadata.authentication_kind == CredentialAuthKind::SshKey
                    && record.public.metadata.ssh_public_key.is_some()
            }
        };
        if !exact_credential_kind || record.public.metadata.status != CredentialStatus::Active {
            return Err(LocalCredentialError::CredentialInactive);
        }
        if let Some(expires_at) = record.public.metadata.expires_at_unix
            && expires_at <= unix_seconds()?
        {
            return Err(LocalCredentialError::CredentialInactive);
        }
        Ok(match transport {
            crate::repository::LocalRepositoryTransport::GitHubOAuth => {
                RepositoryCredentialAdmission::GitHubOAuth(RepositoryGitHubCredentialAdmission {
                    credential: record.public,
                    profile_id: request.profile_id.clone(),
                    profile_revision: request.profile_revision,
                    permission: permissions
                        .into_iter()
                        .next()
                        .expect("GitHub admission has one permission"),
                    material_generation: record.material_generation,
                })
            }
            crate::repository::LocalRepositoryTransport::Ssh => {
                RepositoryCredentialAdmission::Ssh(RepositorySshCredentialAdmission {
                    credential: record.public,
                    profile_id: request.profile_id.clone(),
                    profile_revision: request.profile_revision,
                    material_generation: record.material_generation,
                })
            }
        })
    }

    pub(crate) fn revalidate_repository_credential_operation(
        &self,
        request: &RepositoryCredentialLeaseRequest,
        captured: &RepositoryCredentialAdmission,
    ) -> Result<(), LocalCredentialError> {
        if self.admit_repository_credential_operation(request)? != *captured {
            return Err(LocalCredentialError::CredentialOperationLeaseDenied);
        }
        Ok(())
    }

    pub(crate) fn read_repository_ssh_material(
        &self,
        admission: &RepositorySshCredentialAdmission,
    ) -> Result<SshAgentMaterial, LocalCredentialError> {
        let entry_id = protected_entry_id(
            &admission.credential.metadata.id,
            admission.material_generation,
        )?;
        let value = self
            .protected_store
            .get(&entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)?;
        decode_protected_material(value).map_err(|_| LocalCredentialError::CredentialUnavailable)
    }

    #[cfg(test)]
    fn credential_material_for_test(
        &self,
        id: &CredentialId,
    ) -> Result<ProtectedValue, LocalCredentialError> {
        let connection = self.connection()?;
        let record = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if record.public.metadata.status != CredentialStatus::Active {
            return Err(LocalCredentialError::CredentialInactive);
        }
        if let Some(expires_at) = record.public.metadata.expires_at_unix
            && expires_at <= unix_seconds()?
        {
            return Err(LocalCredentialError::CredentialInactive);
        }
        self.protected_store
            .get(&record.protected_entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)
    }

    /// Publish a profile's complete entry set. GitHub is never an entry: every
    /// profile includes the store's one connection.
    pub fn create_profile(
        &self,
        name: AccessProfileName,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let profile = AccessProfile {
            id: AccessProfileId::parse(Uuid::new_v4().to_string())?,
            placement: Placement::Local,
            owner: Owner::User(self.owner_id.clone()),
            name,
            revision: 1,
            entries,
        };
        validate_profile_entries(
            &profile,
            &load_ready_credential_metadata(&connection)?,
            &self.catalog,
        )?;
        let now = unix_millis()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Err(error) = transaction.execute(
            "INSERT INTO profiles(id, owner_id, name, current_revision, created_at_unix_ms, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            params![
                profile.id.as_str(),
                self.owner_id.as_str(),
                profile.name.as_str(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        ) {
            return Err(map_insert_error(error));
        }
        insert_profile_revision(&transaction, &profile, now)?;
        transaction.commit().map_err(database_error)?;
        load_profile(&connection, &profile.id)
    }

    pub fn update_profile(
        &self,
        id: &AccessProfileId,
        expected_revision: u64,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let current = load_profile(&connection, id)?;
        if current.profile.revision != expected_revision {
            return Err(LocalCredentialError::StaleProfileRevision);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let profile = AccessProfile {
            revision,
            entries,
            ..current.profile
        };
        validate_profile_entries(
            &profile,
            &load_ready_credential_metadata(&connection)?,
            &self.catalog,
        )?;
        let now = unix_millis()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE profiles SET current_revision = ?3, updated_at_unix_ms = ?4
                 WHERE id = ?1 AND current_revision = ?2",
                params![
                    id.as_str(),
                    i64::try_from(expected_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleProfileRevision);
        }
        insert_profile_revision(&transaction, &profile, now)?;
        transaction.commit().map_err(database_error)?;
        load_profile(&connection, id)
    }

    pub fn get_profile(
        &self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_profile(&connection, id)
    }

    pub fn get_profile_revision(
        &self,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfileRevisionRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_profile_revision(&connection, id, revision)
    }

    pub fn list_profile_revisions(
        &self,
        id: &AccessProfileId,
    ) -> Result<Vec<AccessProfileRevisionRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        if !profile_exists(&connection, id)? {
            return Err(LocalCredentialError::ProfileNotFound);
        }
        let mut statement = connection
            .prepare(
                "SELECT revision FROM profile_revisions
                 WHERE profile_id = ?1 ORDER BY revision",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([id.as_str()], |row| row.get::<_, i64>(0))
            .map_err(database_error)?;
        let revisions = rows
            .map(|row| {
                let revision = row.map_err(database_error)?;
                u64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)
            })
            .collect::<Result<Vec<_>, _>>()?;
        revisions
            .into_iter()
            .map(|revision| load_profile_revision(&connection, id, revision))
            .collect()
    }

    pub fn resolve_profile(
        &self,
        reference: &AccessProfileReference,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        if reference.scope() != AccessProfileScope::User {
            return Err(AccessError::LocalOrganizationUnsupported.into());
        }
        let connection = self.connection()?;
        let id = connection
            .query_row(
                "SELECT id FROM profiles WHERE owner_id = ?1 AND name = ?2 COLLATE NOCASE",
                params![self.owner_id.as_str(), reference.name().as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(LocalCredentialError::ProfileNotFound)?;
        let id = AccessProfileId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        load_profile(&connection, &id)
    }

    pub fn list_profiles(&self) -> Result<Vec<AccessProfileRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id FROM profiles ORDER BY name COLLATE NOCASE, id")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        let ids = rows
            .map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id = AccessProfileId::parse(id)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?;
                load_profile(&connection, &id)
            })
            .collect()
    }

    pub fn delete_profile(&self, id: &AccessProfileId) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        if environment_binding_references_profile(&connection, id)? {
            return Err(LocalCredentialError::ProfileInUse);
        }
        let changed = connection
            .execute("DELETE FROM profiles WHERE id = ?1", [id.as_str()])
            .map_err(database_error)?;
        if changed == 0 {
            return Err(LocalCredentialError::ProfileNotFound);
        }
        Ok(())
    }

    pub fn create_environment_access_binding(
        &self,
        binding: EnvironmentAccessBinding,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        binding.validate()?;
        let connection = self.connection()?;
        if environment_binding_exists(&connection, &binding.environment_id)? {
            return Err(LocalCredentialError::EnvironmentBindingAlreadyExists);
        }
        derive_local_environment_grants(&connection, &binding, 1, &self.owner_id, &self.catalog)?;
        let now = unix_millis()?;
        let changed = connection
            .execute(
                "INSERT INTO environment_access_bindings(
                   environment_id, profile_id, profile_revision,
                   created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    binding.environment_id.as_str(),
                    binding.profile_id.as_str(),
                    i64::try_from(binding.profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_environment_access_binding(&connection, &binding.environment_id)
    }

    pub fn replace_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
        profile_id: AccessProfileId,
        profile_revision: u64,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        let replacement = EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id,
            profile_revision,
        };
        replacement.validate()?;
        let connection = self.connection()?;
        let current = load_environment_access_binding(&connection, environment_id)?;
        if current.binding.profile_id != *expected_profile_id
            || current.binding.profile_revision != expected_profile_revision
        {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        derive_local_environment_grants(
            &connection,
            &replacement,
            1,
            &self.owner_id,
            &self.catalog,
        )?;
        let changed = connection
            .execute(
                "UPDATE environment_access_bindings
                 SET profile_id = ?4, profile_revision = ?5, updated_at_unix_ms = ?6
                 WHERE environment_id = ?1 AND profile_id = ?2 AND profile_revision = ?3",
                params![
                    environment_id.as_str(),
                    expected_profile_id.as_str(),
                    i64::try_from(expected_profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    replacement.profile_id.as_str(),
                    i64::try_from(replacement.profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        load_environment_access_binding(&connection, environment_id)
    }

    pub fn get_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_environment_access_binding(&connection, environment_id)
    }

    pub fn list_environment_access_bindings(
        &self,
    ) -> Result<Vec<EnvironmentAccessBindingRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT environment_id FROM environment_access_bindings
                 ORDER BY environment_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        rows.map(|row| {
            let id = EnvironmentId::parse(row.map_err(database_error)?)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?;
            load_environment_access_binding(&connection, &id)
        })
        .collect()
    }

    pub fn delete_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
    ) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_environment_access_binding(&connection, environment_id)?;
        if current.binding.profile_id != *expected_profile_id
            || current.binding.profile_revision != expected_profile_revision
        {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        let changed = connection
            .execute(
                "DELETE FROM environment_access_bindings
                 WHERE environment_id = ?1 AND profile_id = ?2 AND profile_revision = ?3",
                params![
                    environment_id.as_str(),
                    expected_profile_id.as_str(),
                    i64::try_from(expected_profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        Ok(())
    }

    pub fn evaluate_environment_grants(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
    ) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
        let connection = self.connection()?;
        let binding = load_environment_access_binding(&connection, environment_id)?.binding;
        derive_local_environment_grants(
            &connection,
            &binding,
            environment_generation,
            &self.owner_id,
            &self.catalog,
        )
    }

    pub(crate) fn evaluate_selected_environment_grants(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        expected: Option<&EnvironmentAccessBinding>,
    ) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
        let connection = self.connection()?;
        check_selected_environment_binding(&connection, environment_id, expected)?;
        match expected {
            Some(binding) => derive_local_environment_grants(
                &connection,
                binding,
                environment_generation,
                &self.owner_id,
                &self.catalog,
            ),
            None => Ok(Vec::new()),
        }
    }

    fn reconcile(&self) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let records = load_all_internal_credentials(&connection)?;
        let expected_persistence = self.protected_store.persistence();
        for record in &records {
            if record.public.persistence != expected_persistence {
                return Err(LocalCredentialError::ProtectedStoreMismatch);
            }
        }
        for record in records {
            match record.material_state {
                MaterialState::PendingWrite => {
                    if load_protected_entry_journal(&connection, &record.public.metadata.id)?
                        .is_some()
                    {
                        return Err(LocalCredentialError::CorruptMetadata);
                    }
                    self.protected_store.delete(&record.protected_entry_id)?;
                    delete_pending_write(&connection, &record.public.metadata.id)?;
                }
                MaterialState::PendingDelete => {
                    let journal = load_validated_protected_entry_journal(&connection, &record)?;
                    self.protected_store.delete(&record.protected_entry_id)?;
                    if let Some(journal) = journal {
                        self.protected_store.delete(&journal.protected_entry_id)?;
                    }
                    delete_pending_delete(&connection, &record.public.metadata.id)?;
                }
                MaterialState::Ready => {
                    reconcile_ready_journal(&connection, &self.protected_store, &record)?;
                    if expected_persistence == ProtectedStorePersistence::ProcessLifetime {
                        // Refresh recovery can atomically promote the staged
                        // generation and retire the entry held by `record`.
                        // Check the reloaded active entry rather than that
                        // intentionally deleted predecessor.
                        let current = load_internal_credential(
                            &connection,
                            &record.public.metadata.id,
                            Some(MaterialState::Ready),
                        )?;
                        if self
                            .protected_store
                            .get(&current.protected_entry_id)?
                            .is_none()
                        {
                            connection
                                .execute(
                                    "UPDATE credentials SET status = 'expired', updated_at_unix_ms = ?2
                                     WHERE id = ?1 AND material_state = 'ready'",
                                    params![
                                        record.public.metadata.id.as_str(),
                                        i64::try_from(unix_millis()?)
                                            .map_err(|_| LocalCredentialError::InvalidTime)?
                                    ],
                                )
                                .map_err(database_error)?;
                        }
                    }
                }
            }
        }
        let orphaned_refresh_marker = connection
            .query_row(
                "SELECT 1 FROM authority_metadata
                 WHERE key GLOB 'credential_refresh/*' LIMIT 1",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(database_error)?
            .is_some();
        if orphaned_refresh_marker {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        validate_environment_access_bindings(&connection)?;
        validate_database(&connection)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, LocalCredentialError> {
        self.connection
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)
    }
}

fn check_selected_environment_binding(
    connection: &Connection,
    environment_id: &EnvironmentId,
    expected: Option<&EnvironmentAccessBinding>,
) -> Result<(), LocalCredentialError> {
    match load_environment_access_binding(connection, environment_id) {
        Ok(record) if Some(&record.binding) == expected => Ok(()),
        Err(LocalCredentialError::EnvironmentBindingNotFound) if expected.is_none() => Ok(()),
        Ok(_) | Err(LocalCredentialError::EnvironmentBindingNotFound) => {
            Err(LocalCredentialError::StaleEnvironmentBinding)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn deny_generic_ssh_lease(
    metadata: &CredentialMetadata,
) -> Result<(), LocalCredentialError> {
    if metadata.provider.as_str() == "ssh"
        || metadata.authentication_kind == CredentialAuthKind::SshKey
    {
        return Err(LocalCredentialError::CredentialOperationLeaseDenied);
    }
    Ok(())
}

struct AuthorityLock {
    #[cfg(unix)]
    _file: fs::File,
}

impl AuthorityLock {
    fn acquire(root: &Path) -> Result<Self, LocalCredentialError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(LocalCredentialError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let path = root.join(AUTHORITY_LOCK_FILE);
            let descriptor = open(
                &path,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
            let file = fs::File::from(descriptor);
            validate_private_file(
                &file
                    .metadata()
                    .map_err(|_| LocalCredentialError::InvalidDatabasePath)?,
            )?;
            // CLOEXEC still permits a concurrent fork to retain this lock
            // briefly until exec. Match the supervisor's bounded handoff;
            // never unlock or take ownership from a live authority.
            const RETRY_DELAY: Duration = Duration::from_millis(10);
            const MAX_RETRIES: usize = 25;
            let mut retries = 0;
            loop {
                match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => return Ok(Self { _file: file }),
                    Err(error) if error == rustix::io::Errno::INTR && retries < MAX_RETRIES => {
                        retries += 1;
                    }
                    Err(error)
                        if error == rustix::io::Errno::WOULDBLOCK && retries < MAX_RETRIES =>
                    {
                        retries += 1;
                        std::thread::sleep(RETRY_DELAY);
                    }
                    Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                        return Err(LocalCredentialError::AlreadyRunning);
                    }
                    Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
                }
            }
        }
    }
}

fn open_database(root: &Path) -> Result<Connection, LocalCredentialError> {
    #[cfg(not(unix))]
    {
        let _ = root;
        return Err(LocalCredentialError::UnsupportedPlatform);
    }

    #[cfg(unix)]
    {
        ensure_private_root(root)?;
        let path = root.join(DATABASE_FILE);
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_private_file(&metadata)?;
                Some(metadata.len())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(database_error)?;
        if before.is_none() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        }
        let after =
            fs::symlink_metadata(&path).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        validate_private_file(&after)?;
        let initialize = before.is_none() || before == Some(0);
        if !initialize {
            validate_openable_schema(&connection)?;
        }
        configure_database(&connection)?;
        if initialize {
            initialize_schema(&connection)?;
        } else {
            upgrade_schema(&connection)?;
        }
        validate_database(&connection)?;
        Ok(connection)
    }
}

#[cfg(unix)]
pub(crate) fn ensure_private_root(root: &Path) -> Result<(), LocalCredentialError> {
    validate_private_parent(root)?;
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(root)
                .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        }
        Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
    let current_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(root).map_err(|_| LocalCredentialError::InvalidDatabasePath)? != root
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_private_parent(root: &Path) -> Result<(), LocalCredentialError> {
    let parent = root
        .parent()
        .filter(|parent| *parent != root)
        .ok_or(LocalCredentialError::InvalidDatabasePath)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.mode() & 0o022 != 0
        || fs::canonicalize(parent).map_err(|_| LocalCredentialError::InvalidDatabasePath)?
            != parent
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), LocalCredentialError> {
    let current_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

fn configure_database(connection: &Connection) -> Result<(), LocalCredentialError> {
    connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(database_error)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(database_error)?;
    let journal: String = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(database_error)?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE authority_metadata(
               key TEXT PRIMARY KEY NOT NULL,
               value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE credentials(
               id TEXT PRIMARY KEY NOT NULL,
               provider TEXT NOT NULL,
               authentication_kind TEXT NOT NULL,
               display_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
               account_hint TEXT NULL,
               ssh_public_key_openssh TEXT NULL,
               ssh_public_key_fingerprint TEXT NULL
                 CHECK((ssh_public_key_openssh IS NULL) = (ssh_public_key_fingerprint IS NULL)),
               status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'refresh_failed', 'revoked')),
               expires_at_unix INTEGER NULL CHECK(expires_at_unix IS NULL OR expires_at_unix >= 0),
               revocation_generation INTEGER NOT NULL CHECK(revocation_generation > 0),
               material_generation INTEGER NOT NULL CHECK(material_generation > 0),
               protected_entry_id TEXT NOT NULL UNIQUE,
               store_persistence TEXT NOT NULL CHECK(store_persistence IN ('operating_system', 'process_lifetime')),
               material_state TEXT NOT NULL CHECK(material_state IN ('pending_write', 'ready', 'pending_delete')),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms)
             ) STRICT;
             CREATE TABLE protected_entry_journal(
               credential_id TEXT PRIMARY KEY NOT NULL,
               operation TEXT NOT NULL CHECK(operation IN ('rollback_write', 'delete_retired')),
               protected_entry_id TEXT NOT NULL UNIQUE,
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE profiles(
               id TEXT PRIMARY KEY NOT NULL,
               owner_id TEXT NOT NULL,
               name TEXT NOT NULL COLLATE NOCASE,
               current_revision INTEGER NOT NULL CHECK(current_revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               UNIQUE(owner_id, name)
             ) STRICT;
             CREATE TABLE profile_revisions(
               profile_id TEXT NOT NULL,
               revision INTEGER NOT NULL CHECK(revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               PRIMARY KEY(profile_id, revision),
               FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE profile_entries(
               profile_id TEXT NOT NULL,
               revision INTEGER NOT NULL,
               capability_slot TEXT NOT NULL,
               credential_id TEXT NOT NULL,
               PRIMARY KEY(profile_id, revision, capability_slot),
               FOREIGN KEY(profile_id, revision)
                 REFERENCES profile_revisions(profile_id, revision) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE environment_access_bindings(
               environment_id TEXT PRIMARY KEY NOT NULL,
               profile_id TEXT NOT NULL,
               profile_revision INTEGER NOT NULL CHECK(profile_revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               FOREIGN KEY(profile_id, profile_revision)
                 REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT
             ) STRICT;
             CREATE INDEX environment_access_bindings_profile
               ON environment_access_bindings(profile_id, profile_revision);
             CREATE TABLE secret_projects(
               id TEXT PRIMARY KEY NOT NULL,
               owner_id TEXT NOT NULL,
               name TEXT NOT NULL COLLATE NOCASE,
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               UNIQUE(owner_id, name)
             ) STRICT;
             CREATE TABLE workload_secrets(
               id TEXT PRIMARY KEY NOT NULL,
               scope_kind TEXT NOT NULL CHECK(scope_kind IN ('user', 'project')),
               scope_id TEXT NOT NULL,
               project_id TEXT NULL,
               key TEXT NOT NULL,
               material_generation INTEGER NOT NULL CHECK(material_generation > 0),
               protected_entry_id TEXT NOT NULL UNIQUE,
               material_state TEXT NOT NULL CHECK(material_state IN ('pending_write', 'ready', 'pending_delete')),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               UNIQUE(scope_kind, scope_id, key),
               CHECK((scope_kind = 'user' AND project_id IS NULL) OR
                     (scope_kind = 'project' AND project_id = scope_id)),
               FOREIGN KEY(project_id) REFERENCES secret_projects(id) ON DELETE RESTRICT
             ) STRICT;
             CREATE INDEX workload_secrets_scope
               ON workload_secrets(scope_kind, scope_id, key);
             CREATE TABLE workload_secret_journal(
               secret_id TEXT PRIMARY KEY NOT NULL,
               operation TEXT NOT NULL CHECK(operation IN ('rollback_write', 'delete_retired')),
               protected_entry_id TEXT NOT NULL UNIQUE,
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               FOREIGN KEY(secret_id) REFERENCES workload_secrets(id) ON DELETE CASCADE
             ) STRICT;",
        )
        .map_err(database_error)?;
    connection
        .execute_batch(&format!("{GITHUB_SINGLETON_SCHEMA} COMMIT;"))
        .map_err(database_error)?;
    connection
        .pragma_update(None, "application_id", DATABASE_APPLICATION_ID)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    validate_schema_identity(connection)?;
    validate_schema_tables(connection)?;
    let ssh_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('credentials')
             WHERE name IN ('ssh_public_key_openssh', 'ssh_public_key_fingerprint')",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if ssh_columns != 2 {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    let github_schema: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE (type = 'index' AND name = 'credentials_github_oauth_singleton')
                OR (type = 'trigger' AND name IN (
                    'profile_entries_github_insert', 'profile_entries_github_update'))",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if github_schema != 3 {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    Ok(())
}

fn validate_openable_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if application_id != DATABASE_APPLICATION_ID
        || !matches!(
            schema_version,
            PREVIOUS_DATABASE_SCHEMA_VERSION
                | SSH_DATABASE_SCHEMA_VERSION
                | DATABASE_SCHEMA_VERSION
        )
    {
        return Err(LocalCredentialError::UnsupportedSchema);
    }
    validate_schema_tables(connection)
}

fn validate_schema_tables(connection: &Connection) -> Result<(), LocalCredentialError> {
    for table in [
        "authority_metadata",
        "credentials",
        "protected_entry_journal",
        "profiles",
        "profile_revisions",
        "profile_entries",
        "environment_access_bindings",
        "secret_projects",
        "workload_secrets",
        "workload_secret_journal",
    ] {
        let present = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()
            .map_err(database_error)?
            .is_some();
        if !present {
            return Err(LocalCredentialError::InvalidDatabase);
        }
    }
    Ok(())
}

fn upgrade_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if application_id != DATABASE_APPLICATION_ID {
        return Err(LocalCredentialError::UnsupportedSchema);
    }
    match schema_version {
        DATABASE_SCHEMA_VERSION => validate_schema(connection),
        PREVIOUS_DATABASE_SCHEMA_VERSION => {
            validate_schema_tables(connection)?;
            upgrade_ssh_schema(connection)?;
            upgrade_github_singleton_schema(connection)?;
            validate_schema(connection)
        }
        SSH_DATABASE_SCHEMA_VERSION => {
            validate_schema_tables(connection)?;
            upgrade_github_singleton_schema(connection)?;
            validate_schema(connection)
        }
        _ => Err(LocalCredentialError::UnsupportedSchema),
    }
}

/// Version 3 to 4: typed SSH public-key metadata. One atomic step.
fn upgrade_ssh_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    transaction
        .execute_batch(
            "ALTER TABLE credentials ADD COLUMN ssh_public_key_openssh TEXT NULL;
             ALTER TABLE credentials ADD COLUMN ssh_public_key_fingerprint TEXT NULL
               CHECK((ssh_public_key_openssh IS NULL) = (ssh_public_key_fingerprint IS NULL));",
        )
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", SSH_DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

/// Version 4 to 5: GitHub becomes one connection that every profile includes,
/// so pinned GitHub credential IDs are discarded without new revisions. More
/// than one active GitHub connection is ambiguous: the upgrade fails and
/// leaves version 4 unchanged rather than choosing one.
/// Revoked GitHub rows are kept; their protected material is not in SQLite.
fn upgrade_github_singleton_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let active: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM credentials
             WHERE provider = 'github' AND authentication_kind = 'oauth' AND status = 'active'",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if active > 1 {
        return Err(LocalCredentialError::AmbiguousGitHubConnections);
    }
    transaction
        .execute_batch(&format!(
            "DELETE FROM profile_entries WHERE capability_slot = 'github';
             {GITHUB_SINGLETON_SCHEMA}"
        ))
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

fn validate_schema_identity(connection: &Connection) -> Result<(), LocalCredentialError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if application_id != DATABASE_APPLICATION_ID || schema_version != DATABASE_SCHEMA_VERSION {
        return Err(LocalCredentialError::UnsupportedSchema);
    }
    Ok(())
}

fn validate_database(connection: &Connection) -> Result<(), LocalCredentialError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if result != "ok" {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    let foreign_key_violation = connection
        .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |_| {
            Ok(())
        })
        .optional()
        .map_err(database_error)?
        .is_some();
    if foreign_key_violation {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    Ok(())
}

fn ensure_authority_identity(
    connection: &Connection,
    owner_id: &OwnerId,
    persistence: ProtectedStorePersistence,
) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    for (key, expected) in [
        ("owner_id", owner_id.as_str()),
        ("store_persistence", persistence_to_str(persistence)),
    ] {
        match transaction
            .query_row(
                "SELECT value FROM authority_metadata WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
        {
            Some(observed) if observed == expected => {}
            Some(_) if key == "owner_id" => return Err(LocalCredentialError::OwnerMismatch),
            Some(_) => return Err(LocalCredentialError::ProtectedStoreMismatch),
            None => {
                transaction
                    .execute(
                        "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)",
                        [key, expected],
                    )
                    .map_err(database_error)?;
            }
        }
    }
    transaction.commit().map_err(database_error)
}

/// Stage a refreshed OAuth bundle as the next exact protected-store
/// generation, only while the refresh's execution deadline holds and only if
/// that entry is still empty. An error does not say whether the write took
/// effect; the refresh journal reconciles either outcome.
pub(crate) fn stage_refreshed_material<S: ProtectedStore>(
    store: &S,
    entry_id: &ProtectedEntryId,
    material: &ProtectedValue,
    execution_deadline_unix_ms: u64,
) -> Result<(), codewire_protected_store::ProtectedStoreError> {
    let before_deadline = || {
        unix_millis()
            .ok()
            .is_some_and(|now| now < execution_deadline_unix_ms)
    };
    if !before_deadline() {
        return Err(codewire_protected_store::ProtectedStoreError::Unavailable);
    }
    if store.get(entry_id)?.is_some() {
        return Err(codewire_protected_store::ProtectedStoreError::AmbiguousEntry);
    }
    if !before_deadline() {
        return Err(codewire_protected_store::ProtectedStoreError::Unavailable);
    }
    store.put(entry_id, material)
}

pub(crate) fn protected_entry_id(
    id: &CredentialId,
    generation: u64,
) -> Result<ProtectedEntryId, LocalCredentialError> {
    ProtectedEntryId::parse(format!("local/credentials/{id}/material-v{generation}"))
        .map_err(Into::into)
}

fn insert_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
    operation: JournalOperation,
    protected_entry_id: &ProtectedEntryId,
    now: u64,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "INSERT INTO protected_entry_journal(
               credential_id, operation, protected_entry_id, created_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                credential_id.as_str(),
                operation.as_str(),
                protected_entry_id.expose_reference(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn credential_refresh_marker_key(credential_id: &CredentialId) -> String {
    format!("credential_refresh/{}", credential_id.as_str())
}

fn insert_credential_refresh_journal(
    connection: &Connection,
    credential_id: &CredentialId,
    protected_entry_id: &ProtectedEntryId,
    marker: &CredentialRefreshJournal,
    now: u64,
) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let journal_changed = transaction
        .execute(
            "INSERT INTO protected_entry_journal(
               credential_id, operation, protected_entry_id, created_at_unix_ms
             ) VALUES (?1, 'rollback_write', ?2, ?3)",
            params![
                credential_id.as_str(),
                protected_entry_id.expose_reference(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    let marker_changed = transaction
        .execute(
            "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)",
            params![
                credential_refresh_marker_key(credential_id),
                serde_json::to_string(marker).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
        )
        .map_err(database_error)?;
    if journal_changed != 1 || marker_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    transaction.commit().map_err(database_error)
}

fn load_credential_refresh_marker(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<Option<CredentialRefreshJournal>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT value FROM authority_metadata WHERE key = ?1",
            [credential_refresh_marker_key(credential_id)],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|value| {
            let marker: CredentialRefreshJournal =
                serde_json::from_str(&value).map_err(|_| LocalCredentialError::CorruptMetadata)?;
            let permit = &marker.permit;
            let owner_valid = match permit {
                CredentialRefreshPermit::Environment(permit) => {
                    permit.grant.environment_generation != 0
                        && permit
                            .grant
                            .profile
                            .as_ref()
                            .is_some_and(|profile| profile.revision != 0)
                        && permit.grant.permissions.contains(&permit.permission)
                }
                CredentialRefreshPermit::Repository(permit) => {
                    !permit.repository.request_id.is_nil()
                        && permit.repository.profile_revision != 0
                }
            };
            if !owner_valid
                || permit.channel_id().is_nil()
                || permit.refresh_id().is_nil()
                || permit.request_id().is_nil()
                || permit.credential_id() != credential_id
                || permit.credential_revocation_generation() == 0
                || permit.current_material_generation() == 0
                || permit.current_material_generation().checked_add(1)
                    != Some(permit.next_material_generation())
                || matches!(
                    marker.phase,
                    CredentialRefreshPhase::Started {
                        execution_deadline_unix_ms: 0
                    }
                )
            {
                return Err(LocalCredentialError::CorruptMetadata);
            }
            Ok(marker)
        })
        .transpose()
}

fn validate_refresh_current(
    current: &InternalCredentialRecord,
    marker: &CredentialRefreshJournal,
) -> Result<(), LocalCredentialError> {
    if current.public.metadata.authentication_kind != CredentialAuthKind::OAuth
        || current.public.metadata.status != CredentialStatus::Active
        || current.public.metadata.id != *marker.permit.credential_id()
        || current.public.metadata.revocation_generation
            != marker.permit.credential_revocation_generation()
        || current.material_generation != marker.permit.current_material_generation()
    {
        return Err(LocalCredentialError::StaleCredentialRefresh);
    }
    Ok(())
}

fn refresh_grant_matches(
    current: &DerivedGrant,
    pinned: &DerivedGrant,
) -> Result<bool, LocalCredentialError> {
    let now = unix_seconds()?;
    if pinned
        .expires_at_unix
        .is_some_and(|deadline| deadline <= now)
    {
        return Ok(false);
    }
    if let Some(current_deadline) = current.expires_at_unix
        && pinned
            .expires_at_unix
            .is_none_or(|deadline| deadline > current_deadline)
    {
        return Ok(false);
    }
    let mut expected = current.clone();
    expected.expires_at_unix = pinned.expires_at_unix;
    Ok(expected == *pinned)
}

fn fail_oauth_refresh(
    connection: &Connection,
    current: &InternalCredentialRecord,
) -> Result<(), LocalCredentialError> {
    let id = &current.public.metadata.id;
    let revocation_generation = current
        .public
        .metadata
        .revocation_generation
        .checked_add(1)
        .ok_or(LocalCredentialError::CorruptMetadata)?;
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let changed = transaction
        .execute(
            "UPDATE credentials
         SET status = 'refresh_failed', revocation_generation = ?2, updated_at_unix_ms = ?3
         WHERE id = ?1 AND authentication_kind = 'oauth' AND status = 'active'
           AND material_state = 'ready' AND revocation_generation = ?4
           AND material_generation = ?5 AND protected_entry_id = ?6",
            params![
                id.as_str(),
                i64::try_from(revocation_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?,
                i64::try_from(current.public.metadata.revocation_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(current.material_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                current.protected_entry_id.expose_reference(),
            ],
        )
        .map_err(database_error)?;
    let journal_changed = transaction
        .execute(
            "DELETE FROM protected_entry_journal WHERE credential_id = ?1",
            [id.as_str()],
        )
        .map_err(database_error)?;
    let marker_changed = transaction
        .execute(
            "DELETE FROM authority_metadata WHERE key = ?1",
            [credential_refresh_marker_key(id)],
        )
        .map_err(database_error)?;
    if changed != 1 || journal_changed != 1 || marker_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    transaction.commit().map_err(database_error)
}

fn delete_credential_refresh_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let journal_changed = transaction
        .execute(
            "DELETE FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
        )
        .map_err(database_error)?;
    let marker_changed = transaction
        .execute(
            "DELETE FROM authority_metadata WHERE key = ?1",
            [credential_refresh_marker_key(credential_id)],
        )
        .map_err(database_error)?;
    if journal_changed != 1 || marker_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    transaction.commit().map_err(database_error)
}

fn load_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<Option<ProtectedEntryJournal>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT operation, protected_entry_id
             FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(database_error)?
        .map(|(operation, protected_entry_id)| {
            Ok(ProtectedEntryJournal {
                operation: JournalOperation::parse(&operation)?,
                protected_entry_id: ProtectedEntryId::parse(protected_entry_id)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            })
        })
        .transpose()
}

fn delete_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn load_validated_protected_entry_journal(
    connection: &Connection,
    credential: &InternalCredentialRecord,
) -> Result<Option<ProtectedEntryJournal>, LocalCredentialError> {
    let Some(journal) = load_protected_entry_journal(connection, &credential.public.metadata.id)?
    else {
        return Ok(None);
    };
    let expected_generation = match journal.operation {
        JournalOperation::RollbackWrite => credential
            .material_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?,
        JournalOperation::DeleteRetired => credential
            .material_generation
            .checked_sub(1)
            .filter(|generation| *generation > 0)
            .ok_or(LocalCredentialError::CorruptMetadata)?,
    };
    if journal.protected_entry_id
        != protected_entry_id(&credential.public.metadata.id, expected_generation)?
    {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(Some(journal))
}

fn reconcile_ready_journal<S: ProtectedStore>(
    connection: &Connection,
    protected_store: &S,
    credential: &InternalCredentialRecord,
) -> Result<(), LocalCredentialError> {
    let Some(journal) = load_validated_protected_entry_journal(connection, credential)? else {
        if load_credential_refresh_marker(connection, &credential.public.metadata.id)?.is_some() {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        return Ok(());
    };
    let refresh_marker =
        load_credential_refresh_marker(connection, &credential.public.metadata.id)?;
    match journal.operation {
        JournalOperation::RollbackWrite => {
            if let Some(marker) = refresh_marker {
                let expected_generation = credential
                    .material_generation
                    .checked_add(1)
                    .ok_or(LocalCredentialError::CorruptMetadata)?;
                if credential.public.metadata.authentication_kind != CredentialAuthKind::OAuth
                    || marker.permit.next_material_generation() != expected_generation
                    || marker.permit.current_material_generation() != credential.material_generation
                {
                    return Err(LocalCredentialError::CorruptMetadata);
                }
                if credential.public.metadata.status == CredentialStatus::Active {
                    validate_refresh_current(credential, &marker)?;
                    let staged = protected_store.get(&journal.protected_entry_id)?.is_some();
                    match marker.phase {
                        CredentialRefreshPhase::Reserved if staged => {
                            // A reservation never permits provider I/O or staging.
                            return Err(LocalCredentialError::CorruptMetadata);
                        }
                        CredentialRefreshPhase::Reserved => {}
                        CredentialRefreshPhase::Started { .. } if staged => {
                            return promote_oauth_refresh(
                                connection,
                                protected_store,
                                credential,
                                &journal,
                            );
                        }
                        CredentialRefreshPhase::Started { .. } => {
                            // The owner is known gone (restart or drained
                            // channel). No output does not prove no request was
                            // sent: invalidate rather than retry the old token.
                            return fail_oauth_refresh(connection, credential);
                        }
                    }
                }
                protected_store.delete(&journal.protected_entry_id)?;
                return delete_credential_refresh_journal(
                    connection,
                    &credential.public.metadata.id,
                );
            }
            protected_store.delete(&journal.protected_entry_id)?;
        }
        JournalOperation::DeleteRetired => {
            if refresh_marker.is_some() {
                return Err(LocalCredentialError::CorruptMetadata);
            }
            protected_store.delete(&journal.protected_entry_id)?;
        }
    }
    delete_protected_entry_journal(connection, &credential.public.metadata.id)
}

fn promote_oauth_refresh<S: ProtectedStore>(
    connection: &Connection,
    protected_store: &S,
    current: &InternalCredentialRecord,
    journal: &ProtectedEntryJournal,
) -> Result<(), LocalCredentialError> {
    if current.public.metadata.authentication_kind != CredentialAuthKind::OAuth
        || current.public.metadata.status != CredentialStatus::Active
        || journal.operation != JournalOperation::RollbackWrite
    {
        return Err(LocalCredentialError::StaleCredentialRefresh);
    }
    let material_generation = current
        .material_generation
        .checked_add(1)
        .ok_or(LocalCredentialError::CorruptMetadata)?;
    let marker = load_credential_refresh_marker(connection, &current.public.metadata.id)?
        .filter(|marker| matches!(marker.phase, CredentialRefreshPhase::Started { .. }))
        .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
    validate_refresh_current(current, &marker)?;
    if journal.protected_entry_id
        != protected_entry_id(&current.public.metadata.id, material_generation)?
        || marker.permit.next_material_generation() != material_generation
        || protected_store.get(&journal.protected_entry_id)?.is_none()
    {
        return Err(LocalCredentialError::CredentialMaterialMissing);
    }
    let revocation_generation = current
        .public
        .metadata
        .revocation_generation
        .checked_add(1)
        .ok_or(LocalCredentialError::CorruptMetadata)?;
    let now = unix_millis()?;
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let changed = transaction
        .execute(
            "UPDATE credentials
             SET protected_entry_id = ?2, revocation_generation = ?3,
                 material_generation = ?4, updated_at_unix_ms = ?5
             WHERE id = ?1 AND authentication_kind = 'oauth' AND status = 'active'
               AND material_state = 'ready' AND revocation_generation = ?6
               AND material_generation = ?7 AND protected_entry_id = ?8",
            params![
                current.public.metadata.id.as_str(),
                journal.protected_entry_id.expose_reference(),
                i64::try_from(revocation_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(material_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
                i64::try_from(current.public.metadata.revocation_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(current.material_generation)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                current.protected_entry_id.expose_reference(),
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::StaleCredentialRefresh);
    }
    let journal_changed = transaction
        .execute(
            "UPDATE protected_entry_journal
             SET operation = 'delete_retired', protected_entry_id = ?2
             WHERE credential_id = ?1 AND operation = 'rollback_write'",
            params![
                current.public.metadata.id.as_str(),
                current.protected_entry_id.expose_reference()
            ],
        )
        .map_err(database_error)?;
    if journal_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    let marker_changed = transaction
        .execute(
            "DELETE FROM authority_metadata WHERE key = ?1",
            [credential_refresh_marker_key(&current.public.metadata.id)],
        )
        .map_err(database_error)?;
    if marker_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    transaction.commit().map_err(database_error)?;

    if protected_store.delete(&current.protected_entry_id).is_ok() {
        delete_protected_entry_journal(connection, &current.public.metadata.id)?;
    }
    Ok(())
}

fn load_internal_credential(
    connection: &Connection,
    id: &CredentialId,
    required_state: Option<MaterialState>,
) -> Result<InternalCredentialRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT provider, authentication_kind, display_name, account_hint,
                    ssh_public_key_openssh, ssh_public_key_fingerprint,
                    status, expires_at_unix, revocation_generation,
                    material_generation, protected_entry_id, store_persistence, material_state,
                    created_at_unix_ms, updated_at_unix_ms,
                    EXISTS(
                      SELECT 1 FROM protected_entry_journal j
                      WHERE j.credential_id = credentials.id
                    )
             FROM credentials WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, bool>(15)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::CredentialNotFound)?;
    let material_state = MaterialState::parse(&raw.12)?;
    if required_state.is_some_and(|state| material_state != state) {
        return Err(LocalCredentialError::CredentialUnavailable);
    }
    let metadata = CredentialMetadata {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(OwnerId::parse(LOCAL_OWNER_ID)?),
        provider: ProviderId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        authentication_kind: parse_auth_kind(&raw.1)?,
        display_name: raw.2,
        account_hint: raw.3,
        ssh_public_key: match (raw.4, raw.5) {
            (Some(openssh), Some(fingerprint)) => Some(SshPublicKeyMetadata {
                openssh,
                fingerprint,
            }),
            (None, None) => None,
            _ => return Err(LocalCredentialError::CorruptMetadata),
        },
        status: parse_status(&raw.6)?,
        expires_at_unix: optional_i64_to_u64(raw.7)?,
        revocation_generation: u64::try_from(raw.8)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    };
    metadata
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let material_generation =
        u64::try_from(raw.9).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let active_entry_id =
        ProtectedEntryId::parse(raw.10).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if active_entry_id != protected_entry_id(id, material_generation)? {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(InternalCredentialRecord {
        public: CredentialRecord {
            metadata,
            persistence: parse_persistence(&raw.11)?,
            protected_store_cleanup_pending: raw.15,
            created_at_unix_ms: u64::try_from(raw.13)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            updated_at_unix_ms: u64::try_from(raw.14)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        },
        material_generation,
        protected_entry_id: active_entry_id,
        material_state,
    })
}

fn load_all_internal_credentials(
    connection: &Connection,
) -> Result<Vec<InternalCredentialRecord>, LocalCredentialError> {
    let mut statement = connection
        .prepare("SELECT id FROM credentials ORDER BY id")
        .map_err(database_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(database_error)?;
    let ids = rows
        .map(|row| row.map_err(database_error))
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|id| {
            let id = CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
            load_internal_credential(connection, &id, None)
        })
        .collect()
}

fn load_ready_credential_metadata(
    connection: &Connection,
) -> Result<BTreeMap<CredentialId, CredentialMetadata>, LocalCredentialError> {
    load_all_internal_credentials(connection)?
        .into_iter()
        .filter(|record| record.material_state == MaterialState::Ready)
        .map(|record| {
            let metadata = record.public.metadata;
            Ok((metadata.id.clone(), metadata))
        })
        .collect()
}

fn delete_pending_write(
    connection: &Connection,
    id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM credentials WHERE id = ?1 AND material_state = 'pending_write'",
            [id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn delete_pending_delete(
    connection: &Connection,
    id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM credentials WHERE id = ?1 AND material_state = 'pending_delete'",
            [id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn profile_or_binding_references_credential(
    connection: &Connection,
    id: &CredentialId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM profiles p
               JOIN profile_entries e
                 ON e.profile_id = p.id AND e.revision = p.current_revision
               WHERE e.credential_id = ?1
             ) OR EXISTS(
               SELECT 1 FROM environment_access_bindings b
               JOIN profile_entries e
                 ON e.profile_id = b.profile_id AND e.revision = b.profile_revision
               WHERE e.credential_id = ?1
             )",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn environment_binding_exists(
    connection: &Connection,
    environment_id: &EnvironmentId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM environment_access_bindings WHERE environment_id = ?1
             )",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn environment_binding_references_profile(
    connection: &Connection,
    profile_id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM environment_access_bindings WHERE profile_id = ?1
             )",
            [profile_id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn load_environment_access_binding(
    connection: &Connection,
    environment_id: &EnvironmentId,
) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT profile_id, profile_revision, created_at_unix_ms, updated_at_unix_ms
             FROM environment_access_bindings WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::EnvironmentBindingNotFound)?;
    let record = EnvironmentAccessBindingRecord {
        binding: EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: AccessProfileId::parse(raw.0)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            profile_revision: u64::try_from(raw.1)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        },
        created_at_unix_ms: u64::try_from(raw.2)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        updated_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    };
    record.binding.validate()?;
    if record.updated_at_unix_ms < record.created_at_unix_ms {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(record)
}

fn derive_local_environment_grants(
    connection: &Connection,
    binding: &EnvironmentAccessBinding,
    environment_generation: u64,
    owner_id: &OwnerId,
    catalog: &ProviderCatalog,
) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
    let profile =
        load_profile_revision(connection, &binding.profile_id, binding.profile_revision)?.profile;
    let credentials = load_ready_credential_metadata(connection)?;
    let context = GrantContext {
        environment_id: binding.environment_id.clone(),
        environment_generation,
        placement: GrantPlacement::Local,
        user_id: owner_id.clone(),
        organization_id: None,
        allow_personal_credentials: false,
        authorized_credentials: profile
            .entries
            .values()
            .cloned()
            .chain(if profile.includes_github() {
                active_github_connection(connection)?
            } else {
                None
            })
            .collect::<BTreeSet<_>>(),
    };
    derive_grants(
        &context,
        binding,
        &profile,
        &credentials,
        catalog,
        unix_seconds()?,
    )
    .map_err(Into::into)
}

/// Whether the store already holds a GitHub connection in any state.
fn github_connection_exists(connection: &Connection) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials
                           WHERE provider = 'github' AND authentication_kind = 'oauth')",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)
}

/// The store's one GitHub connection when it can be used now. A missing,
/// inactive or expired connection yields `None`, so a profile omits GitHub
/// instead of fabricating access.
fn active_github_connection(
    connection: &Connection,
) -> Result<Option<CredentialId>, LocalCredentialError> {
    let now = i64::try_from(unix_seconds()?).map_err(|_| LocalCredentialError::InvalidTime)?;
    let mut statement = connection
        .prepare(
            "SELECT id FROM credentials
             WHERE provider = 'github' AND authentication_kind = 'oauth' AND status = 'active'
               AND material_state = 'ready'
               AND (expires_at_unix IS NULL OR expires_at_unix > ?1)
             ORDER BY id LIMIT 2",
        )
        .map_err(database_error)?;
    let ids = statement
        .query_map([now], |row| row.get::<_, String>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    match ids.as_slice() {
        [] => Ok(None),
        [id] => CredentialId::parse(id.as_str())
            .map(Some)
            .map_err(|_| LocalCredentialError::CorruptMetadata),
        // The singleton index forbids this; never pick a winner.
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn validate_environment_access_bindings(
    connection: &Connection,
) -> Result<(), LocalCredentialError> {
    let environment_ids = {
        let mut statement = connection
            .prepare("SELECT environment_id FROM environment_access_bindings")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        rows.map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?
    };
    for environment_id in environment_ids {
        let environment_id = EnvironmentId::parse(environment_id)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let binding = load_environment_access_binding(connection, &environment_id)?.binding;
        load_profile_revision(connection, &binding.profile_id, binding.profile_revision)?;
    }
    Ok(())
}

fn insert_profile_revision(
    transaction: &rusqlite::Transaction<'_>,
    profile: &AccessProfile,
    now: u64,
) -> Result<(), LocalCredentialError> {
    transaction
        .execute(
            "INSERT INTO profile_revisions(profile_id, revision, created_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            params![
                profile.id.as_str(),
                i64::try_from(profile.revision)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    for (slot, credential_id) in &profile.entries {
        transaction
            .execute(
                "INSERT INTO profile_entries(profile_id, revision, capability_slot, credential_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    profile.id.as_str(),
                    i64::try_from(profile.revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    slot.as_str(),
                    credential_id.as_str()
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn load_profile(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<AccessProfileRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT owner_id, name, current_revision, created_at_unix_ms, updated_at_unix_ms
             FROM profiles WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::ProfileNotFound)?;
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let revision = u64::try_from(raw.2).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let entries = load_profile_entries(connection, id, revision)?;
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRecord {
        profile,
        created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        updated_at_unix_ms: u64::try_from(raw.4)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

fn profile_exists(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = ?1)",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn load_profile_revision(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<AccessProfileRevisionRecord, LocalCredentialError> {
    if revision == 0 {
        return Err(LocalCredentialError::ProfileRevisionNotFound);
    }
    let raw = connection
        .query_row(
            "SELECT p.owner_id, p.name, p.created_at_unix_ms, r.created_at_unix_ms
             FROM profiles p
             JOIN profile_revisions r ON r.profile_id = p.id
             WHERE p.id = ?1 AND r.revision = ?2",
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some(raw) = raw else {
        return if profile_exists(connection, id)? {
            Err(LocalCredentialError::ProfileRevisionNotFound)
        } else {
            Err(LocalCredentialError::ProfileNotFound)
        };
    };
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries: load_profile_entries(connection, id, revision)?,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRevisionRecord {
        profile,
        profile_created_at_unix_ms: u64::try_from(raw.2)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision_created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

fn load_profile_entries(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT capability_slot, credential_id FROM profile_entries
             WHERE profile_id = ?1 AND revision = ?2 ORDER BY capability_slot",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map(
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(database_error)?;
    let mut entries = BTreeMap::new();
    for row in rows {
        let (slot, credential_id) = row.map_err(database_error)?;
        let slot =
            CapabilitySlot::parse(slot).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let credential_id = CredentialId::parse(credential_id)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        if entries.insert(slot, credential_id).is_some() {
            return Err(LocalCredentialError::CorruptMetadata);
        }
    }
    Ok(entries)
}

fn auth_kind_to_str(kind: CredentialAuthKind) -> &'static str {
    match kind {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
        CredentialAuthKind::SshKey => "ssh_key",
    }
}

fn parse_auth_kind(value: &str) -> Result<CredentialAuthKind, LocalCredentialError> {
    match value {
        "oauth" => Ok(CredentialAuthKind::OAuth),
        "api_key" => Ok(CredentialAuthKind::ApiKey),
        "access_token" => Ok(CredentialAuthKind::AccessToken),
        "github_app" => Ok(CredentialAuthKind::GitHubApp),
        "ssh_key" => Ok(CredentialAuthKind::SshKey),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn status_to_str(status: CredentialStatus) -> &'static str {
    match status {
        CredentialStatus::Active => "active",
        CredentialStatus::Expired => "expired",
        CredentialStatus::RefreshFailed => "refresh_failed",
        CredentialStatus::Revoked => "revoked",
    }
}

fn parse_status(value: &str) -> Result<CredentialStatus, LocalCredentialError> {
    match value {
        "active" => Ok(CredentialStatus::Active),
        "expired" => Ok(CredentialStatus::Expired),
        "refresh_failed" => Ok(CredentialStatus::RefreshFailed),
        "revoked" => Ok(CredentialStatus::Revoked),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn persistence_to_str(persistence: ProtectedStorePersistence) -> &'static str {
    match persistence {
        ProtectedStorePersistence::OperatingSystem => "operating_system",
        ProtectedStorePersistence::ProcessLifetime => "process_lifetime",
    }
}

fn parse_persistence(value: &str) -> Result<ProtectedStorePersistence, LocalCredentialError> {
    match value {
        "operating_system" => Ok(ProtectedStorePersistence::OperatingSystem),
        "process_lifetime" => Ok(ProtectedStorePersistence::ProcessLifetime),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn optional_u64_to_i64(value: Option<u64>) -> Result<Option<i64>, LocalCredentialError> {
    value
        .map(|value| i64::try_from(value).map_err(|_| LocalCredentialError::InvalidTime))
        .transpose()
}

fn optional_i64_to_u64(value: Option<i64>) -> Result<Option<u64>, LocalCredentialError> {
    value
        .map(|value| u64::try_from(value).map_err(|_| LocalCredentialError::CorruptMetadata))
        .transpose()
}

fn unix_millis() -> Result<u64, LocalCredentialError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LocalCredentialError::InvalidTime)?
        .as_millis();
    u64::try_from(millis).map_err(|_| LocalCredentialError::InvalidTime)
}

fn unix_seconds() -> Result<u64, LocalCredentialError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LocalCredentialError::InvalidTime)
}

fn database_error(_: rusqlite::Error) -> LocalCredentialError {
    LocalCredentialError::DatabaseUnavailable
}

fn map_insert_error(error: rusqlite::Error) -> LocalCredentialError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        LocalCredentialError::AlreadyExists
    } else {
        database_error(error)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocalCredentialError {
    #[error("local credential metadata path is not an owner-only directory or private file")]
    InvalidDatabasePath,
    #[error("local credential metadata database is unavailable")]
    DatabaseUnavailable,
    #[error("local credential authority is already running")]
    AlreadyRunning,
    #[error("local credential metadata database is invalid")]
    InvalidDatabase,
    #[error("local credential metadata schema is unsupported")]
    UnsupportedSchema,
    #[error("local credential metadata is corrupt")]
    CorruptMetadata,
    /// Stored values were left in the recorded backend, unchanged.
    #[error("local protected storage could not switch backends: {0}")]
    ProtectedStoreSwitch(ProtectedStoreError),
    #[error("local credential authority owner does not match persisted metadata")]
    OwnerMismatch,
    #[error("local credential protected-store backend does not match persisted metadata")]
    ProtectedStoreMismatch,
    #[error("local credential operation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local credential time value is invalid")]
    InvalidTime,
    #[error(
        "a local credential, access profile, secret project, or workload-secret key already exists"
    )]
    AlreadyExists,
    #[error("a local GitHub connection already exists; reconnect or delete it")]
    GitHubAlreadyConnected,
    #[error(
        "local credential metadata has more than one active GitHub connection; keep one before upgrading"
    )]
    AmbiguousGitHubConnections,
    #[error("local credential was not found")]
    CredentialNotFound,
    #[error("local credential is not available")]
    CredentialUnavailable,
    #[error("local credential is inactive")]
    CredentialInactive,
    #[error("local credential material is missing from protected storage")]
    CredentialMaterialMissing,
    #[error("SSH credentials require the dedicated enrollment operation")]
    SshCredentialRequiresEnrollment,
    #[error("local SSH credential enrollment admission is closed")]
    SshEnrollmentClosed,
    #[error("local SSH credential enrollment deadline elapsed")]
    SshEnrollmentDeadlineElapsed,
    #[error("local credential operation lease is unavailable")]
    CredentialOperationLeaseDenied,
    #[error("local credential refresh is already in progress")]
    CredentialRefreshInProgress,
    #[error("local credential refresh is stale or invalid")]
    StaleCredentialRefresh,
    #[error("local credential revision changed or was not supplied")]
    StaleCredentialRevision,
    #[error("local credential protected entry unexpectedly already exists")]
    ProtectedEntryCollision,
    #[error("local credential is selected by an access profile or environment")]
    CredentialInUse,
    #[error("local access profile was not found")]
    ProfileNotFound,
    #[error("local access profile revision was not found")]
    ProfileRevisionNotFound,
    #[error("local access profile revision changed")]
    StaleProfileRevision,
    #[error("local access profile is selected by an environment")]
    ProfileInUse,
    #[error("local environment access binding already exists")]
    EnvironmentBindingAlreadyExists,
    #[error("local environment access binding was not found")]
    EnvironmentBindingNotFound,
    #[error("local environment access binding changed")]
    StaleEnvironmentBinding,
    #[error("local secret project was not found")]
    SecretProjectNotFound,
    #[error("local workload secret was not found")]
    WorkloadSecretNotFound,
    #[error("local workload secret request is invalid")]
    InvalidWorkloadSecret,
    #[error("organization workload secrets are unsupported locally")]
    OrganizationSecretsUnsupported,
    #[error("local workload secret material is missing from protected storage")]
    WorkloadSecretMaterialMissing,
    #[error(transparent)]
    Access(#[from] AccessError),
    #[error(transparent)]
    ProtectedStore(#[from] ProtectedStoreError),
}

#[cfg(all(test, target_os = "linux"))]
mod process_test_support;
#[cfg(test)]
mod rpc_tests;
#[cfg(test)]
mod tests;
