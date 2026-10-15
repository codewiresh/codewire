#![forbid(unsafe_code)]

//! Provider-neutral credential and environment-access policy.
//!
//! This crate is deliberately I/O-free and contains no protected values. It
//! validates placement-local credential metadata, revisioned access profiles,
//! and the derived grants consumed by a placement credential broker.

mod catalog;
mod grant;
mod id;
mod model;
mod projection;

pub use catalog::{
    CLAUDE_LOGIN_OPERATION, CLAUDE_LOGIN_ROUTE, CODEX_LOGIN_OPERATION, CODEX_LOGIN_ROUTE,
    builtin_provider_catalog, claude_login_permission, codex_login_permission,
};
pub use grant::{
    AvailableGrants, DerivedGrant, GrantContext, GrantPlacement, GrantProfile,
    derive_account_github_grant, derive_available_grants, derive_grants, validate_profile_entries,
};
pub use id::{
    AccessProfileId, AccessProfileName, AccessProfileReference, AccessProfileScope,
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId, EnvironmentId, OwnerId,
    ProviderId,
};
pub use model::{
    AccessProfile, CapabilityPolicy, CredentialAuthKind, CredentialMetadata, CredentialStatus,
    EnvironmentAccessBinding, GrantPermission, HttpProvider, Owner, Placement, ProviderCatalog,
    ProviderDefinition, SshPublicKeyMetadata,
};
pub use projection::{
    CODEX_CONFIG_FILE_NAME, CODEX_MANAGED_CONFIG_HEADER, CODEX_NATIVE_HOME, CODEX_PLATFORM_HOME,
    CODEX_PLATFORM_TOKEN_FILE, CodexProviderProjection, GH_CONFIG_FILE_NAME, GH_NATIVE_CONFIG_DIR,
    GH_PLATFORM_CONFIG_DIR, GH_TOKEN_PLACEHOLDER, GITHUB_GIT_URL, GITHUB_HTTPS_URL, GITHUB_SCP_URL,
    GITHUB_SSH_KNOWN_HOSTS, GITHUB_SSH_URL, GhConfigProjection, MANAGED_ANTHROPIC_API_PREFIX,
    MANAGED_CREDENTIAL_CLIENTS_ENV, MANAGED_GITHUB_GIT_PREFIX, MANAGED_HTTP_NATIVE_SOCKET,
    MANAGED_HTTP_PLATFORM_SOCKET, MANAGED_HTTP_PORT, MANAGED_NO_PROXY, MANAGED_OPENAI_API_PREFIX,
    ManagedAgent, ManagedCredentialClient, ManagedCredentialClientPlacement,
    ManagedCredentialClientProjection, ManagedCredentialClients, NO_PROXY_NAMES, ProjectionError,
    SSH_NATIVE_AUTH_SOCK, SSH_PLATFORM_AUTH_SOCK, github_known_hosts_additions,
};

use thiserror::Error;

/// Maximum duration of a provider refresh exchange, including its response body.
pub const PROVIDER_REFRESH_TIMEOUT_SECONDS: u64 = 30;

/// Durable fence on a started refresh owner's ability to stage a result.
///
/// Expiry permits failing an unstaged attempt closed, never resending the old
/// refresh token. Already staged results remain recoverable. Local authorities
/// also retain ownership until active protected-store writes have drained.
pub const CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS: u64 = 90;

/// Stable policy failures safe to return through local or platform adapters.
///
/// Error variants contain identifiers and metadata only. Provider responses,
/// protected-store references, and credential material never enter this type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AccessError {
    #[error("invalid {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid {field}")]
    InvalidField { field: &'static str },
    #[error("invalid access profile reference")]
    InvalidProfileReference,
    #[error("{field} must be greater than zero")]
    ZeroGeneration { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("provider {provider} is declared more than once")]
    DuplicateProvider { provider: ProviderId },
    #[error("environment access binding does not match the selected profile revision")]
    BindingMismatch,
    #[error("{subject} belongs to a different placement")]
    PlacementMismatch { subject: &'static str },
    #[error("organization credential access is not supported by local placement")]
    LocalOrganizationUnsupported,
    #[error("organizations cannot hold OAuth credentials; OAuth logins are personal")]
    OrganizationOAuthUnsupported,
    #[error("personal credentials require an explicitly confirmed shared-environment policy")]
    PersonalCredentialsForbidden,
    #[error("access profile owner is incompatible with the environment organization")]
    ProfileOwnerMismatch,
    #[error("credential {credential} is not authorized for this environment")]
    CredentialNotAuthorized { credential: CredentialId },
    #[error("credential {credential} has an incompatible owner")]
    CredentialOwnerMismatch { credential: CredentialId },
    #[error("credential {credential} does not exist")]
    CredentialMissing { credential: CredentialId },
    #[error("credential metadata identity does not match profile entry {credential}")]
    CredentialIdentityMismatch { credential: CredentialId },
    #[error("credential {credential} is not active")]
    CredentialInactive { credential: CredentialId },
    #[error("credential {credential} is expired")]
    CredentialExpired { credential: CredentialId },
    #[error("provider {provider} is not enabled")]
    ProviderUnavailable { provider: ProviderId },
    #[error("provider {provider} does not support authentication kind {kind:?}")]
    UnsupportedAuthenticationKind {
        provider: ProviderId,
        kind: CredentialAuthKind,
    },
    #[error("provider {provider} does not support slot {slot} with this authentication kind")]
    UnsupportedCapability {
        provider: ProviderId,
        slot: CapabilitySlot,
    },
}

#[cfg(test)]
mod tests;
