#![forbid(unsafe_code)]

//! Credential-bearing provider request preparation for the isolated Codewire
//! broker process.
//!
//! The crate owns the authenticated guest stream plus provider-specific DNS,
//! socket, TLS, mutation, and streaming-redaction code used inside the isolated
//! broker process. It has no public listener or persistent state. Secret-bearing
//! values must remain inside that process.

// Predates this workspace lint; #4125 tracks removing the allow.
#![allow(clippy::unwrap_used)]

pub mod anthropic;
mod bridge;
mod claude_oauth;
mod codex_oauth;
pub mod github;
pub mod github_app;
#[cfg(all(feature = "host-agent-synthetic-smoke", target_os = "linux"))]
pub mod host_agent_smoke;
#[cfg(test)]
mod http_test_support;
mod network;
mod openai;
#[cfg(feature = "platform")]
pub mod platform;
#[cfg(all(test, feature = "ssh-agent", target_os = "linux"))]
mod process_test_support;
#[cfg(feature = "ssh-agent")]
pub mod provider_enrollment;
pub mod provider_oauth;
mod reconnect;
mod refresh_failure;
mod runtime;
#[cfg(all(feature = "ssh-agent", any(target_os = "linux", target_os = "macos")))]
pub mod ssh_agent;
pub mod timing;
mod transparent;

pub use claude_oauth::{
    CanonicalClaudeOAuthBundle, ClaudeIssuedTokens, ClaudeOAuthImport, ClaudeOAuthMaterialError,
    ClaudeProfile, ClaudeSubscriptionType, import_claude_tokens,
};
pub use codewire_access::{CODEX_CONFIG_FILE_NAME, CodexProviderProjection};
pub use codex_oauth::{
    CanonicalCodexOAuthBundle, CodexOAuthImport, CodexOAuthMaterialError, import_codex_tokens,
};
pub use github_app::{
    GitHubAccountKind, GitHubAppAuthorizationConfig, GitHubAppAuthorizationError,
    GitHubAppAuthorizationImport, GitHubAppAuthorizationOwner, GitHubAppInstallationReach,
    GitHubAppPendingPermissions, GitHubAppRefreshError, GitHubAppStatusError,
    GitHubAppUserOAuthBundle, github_access_token,
};
pub use network::ProviderHttpsTransport;
pub use openai::{
    OpenAiApiKeyAdapter, OpenAiStreamingResponse, PreparedOpenAiRequest, PreparedOpenAiResponse,
    ValidatedOpenAiRequest,
};
pub use runtime::{
    BrokerCredentialRefreshKind, BrokerCredentialRefreshRequest, BrokerHttpResponse,
    BrokerLeaseError, BrokerLeaseProvider, BrokerRefreshAdmission, BrokerRefreshError,
    BrokerRequestError, BrokerResponseBody, BrokerUpstreamError, BrokerUpstreamRequest,
    BrokerUpstreamResponse, BrokerUpstreamTransport, OpenAiBroker,
};
#[cfg(feature = "local-broker-synthetic-smoke")]
pub use runtime::{SyntheticOpenAiSmokeTransport, SyntheticProviderHost};

use codewire_access::{CredentialMetadata, DerivedGrant, GrantPermission};
use thiserror::Error;

/// One authority-admitted credential operation consumed inside a placement's
/// isolated broker process.
///
/// Local and platform authorities implement this interface for their own
/// non-serializable lease types. The shared provider adapters consequently do
/// not depend on a placement's vault or metadata implementation.
pub trait BrokerCredentialLease: Sized {
    /// Return non-secret metadata for the selected credential.
    fn credential_metadata(&self) -> &CredentialMetadata;
    /// Return the material-free environment grant rederived for this lease.
    fn grant(&self) -> &DerivedGrant;
    /// Return the exact provider operation and route admitted by the authority.
    fn permission(&self) -> &GrantPermission;
    /// Return the exact protected-value generation admitted by the authority.
    fn material_generation(&self) -> u64;
    /// Consume the lease while the provider adapter prepares one request.
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T;
}

#[cfg(any(test, feature = "local"))]
impl BrokerCredentialLease for codewire_local_credentials::CredentialOperationLease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        &self.credential.metadata
    }

    fn grant(&self) -> &DerivedGrant {
        &self.grant
    }

    fn permission(&self) -> &GrantPermission {
        &self.permission
    }

    fn material_generation(&self) -> u64 {
        self.material_generation()
    }

    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        codewire_local_credentials::CredentialOperationLease::with_material(self, operation)
    }
}

/// Stable failures safe to return across the credential-free broker control
/// boundary. Provider material and policy-engine diagnostics are deliberately
/// not retained as error sources.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CredentialBrokerError {
    /// The broker's compiled provider policy failed its startup validation.
    #[error("credential broker provider policy is invalid")]
    InvalidProviderPolicy,
    /// The authority lease does not belong to this provider adapter.
    #[error("credential operation lease is not supported by this provider route")]
    UnsupportedLease,
    /// The guest request is outside the provider route policy.
    #[error("credential broker request is not permitted")]
    RequestDenied,
    /// The upstream response is outside the provider route policy.
    #[error("credential broker upstream response is not permitted")]
    ResponseDenied,
    /// The upstream response exceeded the provider route byte ceiling.
    #[error("credential broker upstream response is too large")]
    ResponseTooLarge,
    /// The protected provider value cannot be used by this adapter.
    #[error("protected credential material is invalid for this provider")]
    InvalidCredentialMaterial,
}
pub use bridge::{
    AdmittedCredentialBridge, BrokerBridgeError, CredentialBridgeRelayInput,
    CredentialBridgeRelayOutput, CredentialBridgeResponseSink, CredentialBridgeTransport,
    admit_credential_bridge, run_admitted_credential_bridge, run_admitted_credential_bridge_relay,
    run_credential_bridge,
};
