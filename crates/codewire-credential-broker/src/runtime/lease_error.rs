//! A lease's closed failures.

use codewire_access::WithheldReason;
use thiserror::Error;

/// Stable lease failures that never retain authority or protected-store
/// diagnostics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerLeaseError {
    #[error("credential broker lease request is invalid")]
    InvalidRequest,
    #[error("credential broker lease was denied")]
    Denied,
    /// A denial because the Sandbox's creator left its organization (#6406).
    #[error("credential broker lease was denied: the Sandbox's creator left its organization")]
    CreatorDeparted,
    /// A denial because the Sandbox's creator's account is disabled (#6406).
    #[error("credential broker lease was denied: the Sandbox's creator's account is disabled")]
    CreatorDisabled,
    #[error("credential broker lease authority is unavailable")]
    Unavailable,
    #[error("credential broker lease authority returned invalid metadata")]
    InvalidResponse,
    /// The selected capability's credential needs Reconnect (its refresh
    /// failed, or it was revoked or expired). Only this capability is withheld.
    #[error("credential broker lease needs the selected credential reconnected")]
    ReconnectRequired(WithheldReason),
    /// The bound profile fills no credential for the requested slot.
    #[error("credential broker lease names a slot the profile does not fill")]
    NotSelected,
}

impl BrokerLeaseError {
    /// Every denial of the whole session, whatever its cause: it clears what
    /// the epoch holds, as `Denied` always has.
    pub fn is_denial(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::CreatorDeparted | Self::CreatorDisabled
        )
    }
}
