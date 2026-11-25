//! The runtime authority's closed failures, and how a lease reads them.

use crate::BrokerLeaseError;

/// Closed failures: authenticators must discard Kubernetes, SQL, transport and
/// token parser text rather than retaining upstream messages or error sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformRuntimeError {
    #[error("platform runtime authority denied the session")]
    Denied,
    /// A denial because the Sandbox's creator is no longer a member of its
    /// organization: none of its credentials is used (#6406).
    #[error("platform runtime authority denied the session: its creator left the organization")]
    CreatorDeparted,
    /// A denial because the Sandbox's creator's account is disabled (#6406).
    #[error("platform runtime authority denied the session: its creator's account is disabled")]
    CreatorDisabled,
    #[error("platform runtime authority is unavailable")]
    Unavailable,
}

pub(super) fn runtime_error(error: PlatformRuntimeError) -> BrokerLeaseError {
    match error {
        PlatformRuntimeError::Denied => BrokerLeaseError::Denied,
        PlatformRuntimeError::CreatorDeparted => BrokerLeaseError::CreatorDeparted,
        PlatformRuntimeError::CreatorDisabled => BrokerLeaseError::CreatorDisabled,
        PlatformRuntimeError::Unavailable => BrokerLeaseError::Unavailable,
    }
}
