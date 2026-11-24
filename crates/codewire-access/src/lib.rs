#![forbid(unsafe_code)]

//! Provider-neutral credential and environment-access policy.
//!
//! This crate is deliberately I/O-free and contains no protected values. It
//! validates placement-local credential metadata, revisioned access profiles,
//! and the derived grants consumed by a placement credential broker.

mod catalog;
mod credential_name;
mod credential_types;
mod front_door;
mod grant;
mod id;
mod managed_refresh;
mod model;
mod placeholder;
mod projected_placeholders;
mod projection;
mod refusal;

pub use catalog::{
    CLAUDE_LOGIN_OPERATION, CLAUDE_LOGIN_ROUTE, CODEX_LOGIN_OPERATION, CODEX_LOGIN_ROUTE,
    builtin_provider_catalog, claude_login_permission, codex_login_permission,
};
pub use credential_name::{
    CREDENTIAL_NAME_PROVIDERS, credential_name_provider_prefixes, is_credential_name_provider,
    reserves_provider_prefix,
};
pub use credential_types::{
    AgentHolds, CREDENTIAL_TYPES, CredentialFlow, CredentialType, CredentialVerb, credential_type,
    credential_type_of, credential_types_docs_table, credential_types_for,
};
pub use front_door::{
    ANTHROPIC_API_HOST, CHATGPT_HOST, CHATGPT_WILDCARD, CLAUDE_TOKEN_HOST, CODEX_TOKEN_HOST,
    FRONT_DOOR_HOSTS, FrontDoorHost, GITHUB_HOSTS, GITHUB_INTERCEPTED, INTERCEPT_PORT,
    OPENAI_API_HOST, ROUTED_SUFFIXES, binds_github, front_door_hosts, one_label_under,
    routed_suffix,
};
pub use grant::{
    AvailableGrants, DerivedGrant, GrantContext, GrantPlacement, GrantProfile, UngrantedGitHub,
    Withheld, WithheldReason, derive_account_github_grant, derive_available_grants, derive_grants,
    ungranted_github, validate_profile_entries,
};
pub use id::{
    AccessProfileId, AccessProfileName, AccessProfileReference, AccessProfileScope,
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId, EnvironmentId, OwnerId,
    ProviderId,
};
pub use managed_refresh::{
    CLAUDE_MANAGED_REFRESH_NONCE_BYTES, CLAUDE_MANAGED_REFRESH_NONCE_LENGTH,
    CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX, CODEX_MANAGED_REFRESH_TOKEN,
    is_managed_claude_refresh_token, managed_claude_refresh_token,
};
pub use model::{
    AccessProfile, CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS, CapabilityPolicy,
    CredentialAuthKind, CredentialMetadata, CredentialStatus, EnvironmentAccessBinding,
    GrantPermission, HttpProvider, Owner, Placement, ProviderCatalog, ProviderDefinition,
    SshPublicKeyMetadata, is_claude_subscription_token_shape,
};
pub use placeholder::{
    CREDENTIAL_PLACEHOLDER_LENGTH, CREDENTIAL_PLACEHOLDER_TAG, CredentialPlaceholder,
    PLACEHOLDER_KEY_BYTES, PlaceholderKey, known_answer,
};
pub use projected_placeholders::{PROJECTED_PLACEHOLDER_SLOTS, ProjectedPlaceholders};
pub use projection::{
    CODEX_CONFIG_FILE_NAME, CODEX_MANAGED_CONFIG_HEADER, CODEX_NATIVE_HOME, CODEX_PLATFORM_HOME,
    CODEX_PLATFORM_TOKEN_FILE, CodexProviderProjection, GH_CONFIG_FILE_NAME, GH_NATIVE_CONFIG_DIR,
    GH_PLATFORM_CONFIG_DIR, GH_TOKEN_PLACEHOLDER, GITHUB_GIT_URL, GITHUB_HTTPS_URL, GITHUB_SCP_URL,
    GITHUB_SSH_KNOWN_HOSTS, GITHUB_SSH_URL, GhConfigProjection, Interception,
    MANAGED_ANTHROPIC_API_PREFIX, MANAGED_ANTHROPIC_OAUTH_PREFIX, MANAGED_CREDENTIAL_CLIENTS_ENV,
    MANAGED_GITHUB_GIT_PREFIX, MANAGED_HTTP_NATIVE_SOCKET, MANAGED_HTTP_PLATFORM_SOCKET,
    MANAGED_HTTP_PORT, MANAGED_NO_PROXY, MANAGED_OPENAI_API_PREFIX, ManagedAgent,
    ManagedCredentialClient, ManagedCredentialClientPlacement, ManagedCredentialClientProjection,
    ManagedCredentialClients, NO_PROXY_NAMES, ProjectionError, SSH_NATIVE_AUTH_SOCK,
    SSH_PLATFORM_AUTH_SOCK, github_known_hosts_additions,
};
pub use refusal::{
    REFUSAL_HEADER, Refusal, RefusalCode, RefusalProvider, Unforwarded, UpstreamFailure,
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
