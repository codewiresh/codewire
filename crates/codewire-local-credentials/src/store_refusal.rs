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
}

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
