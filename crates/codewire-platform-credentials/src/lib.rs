#![forbid(unsafe_code)]

//! Platform placement persistence for typed credentials.
//!
//! The caller supplies an already-authorized owner, never an unchecked owner
//! from a request body. This library enforces exact owner isolation and the
//! database deletion fence; it does not authenticate users or derive grants.
//! Enrollment adapters validate the provider payload before storage; this
//! layer validates the explicit provider/authentication-kind catalog and keeps
//! material opaque rather than guessing its type from a value or key name.
//! Provider material has no public wire representation. Only a trusted broker
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
//! broker's per-operation grant, lifecycle, expiry and revocation checks.

mod model;
mod profiles;
mod refresh;
mod store;

pub use model::{CredentialRecord, CredentialRegistration, CredentialVersion};
pub use profiles::{PlatformAccessProfileStore, PlatformProfileError};
pub use refresh::{
    OAuthRefreshAttemptInfo, OAuthRefreshState, PreparedOAuthRefresh, PreparedOAuthRefreshResult,
    StartedOAuthRefresh,
};
pub use store::{CredentialMetadataReader, PlatformCredentialStore};

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
