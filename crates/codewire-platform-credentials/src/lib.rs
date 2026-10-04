#![forbid(unsafe_code)]

//! Platform placement persistence for typed credentials.
//!
//! The caller supplies an already-authorized owner, never an unchecked owner
//! from a request body. This library enforces exact owner isolation and the
//! database deletion fence; it does not authenticate users or derive grants.
//! Enrollment adapters validate the provider payload before storage; this
//! layer validates the explicit provider/authentication-kind catalog and keeps
//! material opaque rather than guessing its type from a value or key name.
//! OAuth logins are personal: an organization may hold API keys and SSH keys,
//! but registering or reconnecting an organization OAuth credential fails.
//! Provider material has no public read/response representation. Only a trusted broker
//! or enrollment authority may hold [`PlatformCredentialStore`]. A control
//! service can instead hold [`CredentialMetadataReader`] with a SELECT-only
//! database role that cannot read the material table and has no KEK provider.
//!
//! OpenBao work precedes short, owner-fenced database transactions. Every
//! material replacement uses a fresh DEK and atomically publishes its envelope
//! with the matching metadata version. PostgreSQL owns publication atomicity.
//! A durable OAuth attempt records whether a provider request may have started
//! and retains encrypted results for recovery; it is not a second environment
//! generation or a local-store fallback.
//! The shared Transit key and generic workload-secret DEKs are never deleted.
//!
//! A successful material read establishes one storage admission point. It does
//! not revoke bytes already returned, authenticate a sandbox, or replace the
//! broker's grant, lifecycle, expiry and revocation checks.
//! [`EpochMaterialCache`] is the only retained copy: one platform broker
//! bridge epoch (hosted or owner-local delegation) may reuse a value for at
//! most two minutes, for its exact credential record.

/// The account's active, unexpired GitHub OAuth connections for the user `$1`.
/// At most two, so that a second connection is reported instead of a winner
/// being picked. One text, so every statement that reads the connection reads
/// exactly the same rows.
macro_rules! active_github_connection_ids {
    () => {
        "SELECT id FROM platform_credentials \
         WHERE user_id=$1 AND organization_id IS NULL \
           AND provider='github' AND authentication_kind='oauth' AND status='active' \
           AND (expires_at_unix IS NULL OR expires_at_unix>extract(epoch FROM clock_timestamp())) \
         ORDER BY id LIMIT 2"
    };
}

mod material_cache;
mod model;
mod profiles;
mod refresh;
mod store;

pub use material_cache::{
    EpochMaterialCache, MATERIAL_REUSE_TTL, MAX_REUSED_MATERIAL_BYTES, MAX_REUSED_MATERIALS,
};
pub use model::{CredentialRecord, CredentialRegistration, CredentialVersion};
pub use profiles::{PlatformAccessProfileStore, PlatformBindingMetadata, PlatformProfileError};
pub use refresh::{
    OAuthKeepAliveCandidate, OAuthRefreshAttemptInfo, OAuthRefreshState, PreparedOAuthRefresh,
    PreparedOAuthRefreshResult, StartedOAuthRefresh,
};
pub use store::{
    CredentialMetadataReader, OwnedCredentials, PlatformCredentialStore,
    PreparedCredentialCreation, PreparedCredentialReplacement, active_github_connection,
    owned_credentials_and_github_connection,
};

/// Closed, value-blind errors. SQL/provider errors are deliberately discarded:
/// neither their messages nor their source chains are safe output contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlatformCredentialError {
    #[error("invalid credential metadata or version")]
    InvalidInput,
    #[error("unsupported credential provider or authentication kind")]
    UnsupportedCredential,
    #[error("credential or active owner not found")]
    NotFound,
    #[error("credential name or identity already exists")]
    AlreadyExists,
    #[error("credential version changed")]
    StaleVersion,
    #[error("credential refresh is in progress")]
    RefreshInProgress,
    #[error("credential refresh attempt changed")]
    StaleRefresh,
    #[error("credential refresh outcome is unknown")]
    RefreshOutcomeUnknown,
    #[error("credential is referenced by a current profile or environment binding")]
    CredentialInUse,
    #[error("credential is not active")]
    Inactive,
    #[error("credential is expired")]
    Expired,
    #[error("credential metadata or material is corrupt")]
    CorruptRecord,
    #[error("credential database is unavailable")]
    DatabaseUnavailable,
    #[error("credential envelope provider is unavailable")]
    ProviderUnavailable,
    #[error("credential envelope provider timed out")]
    ProviderTimedOut,
    #[error("credential clock is unavailable")]
    ClockUnavailable,
}
