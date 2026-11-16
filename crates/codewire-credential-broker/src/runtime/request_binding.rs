//! Whether a refresh still belongs to the request binding it was admitted
//! under (moved out of `runtime.rs` unchanged).

use codewire_access::DerivedGrant;

use super::{BrokerRequestError, current_unix_time};

/// Refresh and its bounded retry belong to the original request binding, not
/// whichever account/profile happens to be current after an asynchronous wait.
/// Material and revocation generations may advance when tokens rotate.
pub(super) fn validate_request_binding(
    current: &DerivedGrant,
    admitted: &DerivedGrant,
) -> Result<(), BrokerRequestError> {
    let now = current_unix_time()?;
    if current.environment_id != admitted.environment_id
        || current.environment_generation != admitted.environment_generation
        || current.profile != admitted.profile
        || current.capability_slot != admitted.capability_slot
        || current.credential_id != admitted.credential_id
        || admitted.expires_at_unix.is_some_and(|expiry| expiry <= now)
    {
        return Err(BrokerRequestError::Denied);
    }
    Ok(())
}
