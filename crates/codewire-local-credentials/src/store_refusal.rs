//! The closed reason the authority attaches to a definite refusal whose
//! cause its caller words itself (#4826). The authority's own message is for
//! its log, never for a person.

use tonic::Status;
use tonic::metadata::MetadataValue;

/// The status metadata key that carries a [`StoreRefusal`]. It is not the
/// intercepted route's `Codewire-Refusal` header, which an agent reads: the
/// two answer different callers and never feed each other.
pub const STORE_REFUSAL_KEY: &str = "codewire-store-refusal";

/// Why the authority definitely refused an operation, for the causes its
/// caller has words for. Every other refusal carries no reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreRefusal {
    /// The credential's revision changed after the caller read it.
    RevisionChanged,
    /// A second GitHub connection; there is one per user.
    GithubAlreadyConnected,
    /// The protected store is locked in this session.
    KeychainLocked,
    /// The keychain that holds local credentials does not exist.
    KeychainMissing,
    /// The protected store didn't answer within its bound. A write that
    /// timed out was never made ready, so nothing lists or leases it
    /// (#5271).
    KeyringTimedOut,
    /// A name with no provider matched credentials of more than one provider.
    /// [`STORE_REFUSAL_PROVIDERS_KEY`] lists them.
    CredentialNameAmbiguous,
    /// A new or renamed credential's name starts with a provider id and `/`.
    CredentialNameReservesProvider,
    /// Another add of this name, or of the GitHub connection, is still
    /// writing its material (#5413).
    CredentialAddInProgress,
    /// An earlier add of this name, or of the GitHub connection, never
    /// finished; nothing is writing it, and the authority's next start
    /// removes it (#5413).
    CredentialAddUnfinished,
    /// A secret bound while host-bound secrets are off.
    HostBoundSecretsUnavailable,
    /// A change to a secret's binding that needs its value, sent without one.
    SecretValueRequired,
    /// A binding naming a host a built-in credential names.
    BoundHostProvider,
    /// Any other binding, or a value for one, that the rules refuse.
    SecretBindingInvalid,
    /// A rename of a bound secret.
    SecretBoundRename,
}

/// The status metadata key that lists, comma-joined and sorted, the providers
/// of a [`StoreRefusal::CredentialNameAmbiguous`] refusal; never an ID. The
/// cloud's ErrorInfo carries the same list as `providers`.
pub const STORE_REFUSAL_PROVIDERS_KEY: &str = "codewire-store-refusal-providers";

impl StoreRefusal {
    /// The reason on the wire. Where the cloud's credential service refuses
    /// for the same cause, this is its `ErrorInfo` reason verbatim, so one
    /// classifier reads both placements.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::RevisionChanged => "CREDENTIAL_REVISION_CHANGED",
            Self::GithubAlreadyConnected => "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
            Self::KeychainLocked => "LOCAL_KEYCHAIN_LOCKED",
            Self::KeychainMissing => "LOCAL_KEYCHAIN_MISSING",
            Self::KeyringTimedOut => "LOCAL_KEYRING_TIMED_OUT",
            Self::CredentialNameAmbiguous => "CREDENTIAL_NAME_AMBIGUOUS",
            Self::CredentialNameReservesProvider => "CREDENTIAL_NAME_RESERVES_PROVIDER",
            Self::CredentialAddInProgress => "LOCAL_CREDENTIAL_ADD_IN_PROGRESS",
            Self::CredentialAddUnfinished => "LOCAL_CREDENTIAL_ADD_UNFINISHED",
            Self::HostBoundSecretsUnavailable => "LOCAL_HOST_BOUND_SECRETS_UNAVAILABLE",
            Self::SecretValueRequired => "secret_value_required",
            Self::BoundHostProvider => "bound_host_provider",
            Self::SecretBindingInvalid => "secret_binding_invalid",
            Self::SecretBoundRename => "secret_bound_rename",
        }
    }

    pub(crate) fn attach(self, mut status: Status) -> Status {
        status
            .metadata_mut()
            .insert(STORE_REFUSAL_KEY, MetadataValue::from_static(self.reason()));
        status
    }
}

/// The reason `status` carries, if any. A caller matches it against the
/// reasons it knows; an authority older than #4826 sends none.
pub fn store_refusal_reason(status: &Status) -> Option<&str> {
    status.metadata().get(STORE_REFUSAL_KEY)?.to_str().ok()
}

/// The providers a [`StoreRefusal::CredentialNameAmbiguous`] refusal lists,
/// in its order; empty when `status` carries none.
pub fn store_refusal_providers(status: &Status) -> Vec<&str> {
    status
        .metadata()
        .get(STORE_REFUSAL_PROVIDERS_KEY)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter(|provider| !provider.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
