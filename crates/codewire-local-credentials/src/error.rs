//! The local credential authority's failures, none of which carries material.

use codewire_access::{AccessError, ProviderId, WithheldReason};
use codewire_protected_store::ProtectedStoreError;
use thiserror::Error;

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
    /// A name with no provider matched credentials of more than one provider.
    /// The providers are sorted, each once; never the credentials' IDs.
    #[error("local credential name matches more than one provider's credential")]
    CredentialNameAmbiguous { providers: Vec<ProviderId> },
    /// A new or renamed credential's name starts with a provider id and `/`,
    /// which `PROVIDER/NAME` would read as another credential.
    #[error("a new local credential name may not start with anthropic/, openai/, github/ or ssh/")]
    CredentialNameReservesProvider,
    #[error("local credential is not available")]
    CredentialUnavailable,
    #[error("local credential is inactive")]
    CredentialInactive,
    /// A lease for a slot whose credential the environment's profile
    /// withholds, and why: its broker answers the reason (#5593).
    #[error("local credential needs reconnecting")]
    CredentialWithheld(WithheldReason),
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
    #[error("local access profile is the default")]
    ProfileIsDefault,
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
