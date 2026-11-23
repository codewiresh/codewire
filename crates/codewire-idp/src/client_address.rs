//! The client address an abuser controls as one unit, kept only as a keyed
//! hash. The per-address sign-up limit counts under it (#3297), so no IdP
//! table keeps a client's address for its limits.

/// The label the hash key is derived under from the session secret, so a
/// stored hash can't be reversed by trying every address. The value predates
/// sign-up's use of it; changing it would restart every address's sign-up
/// count.
pub const CLIENT_ADDRESS_KEY_LABEL: &str = "codewire/idp-oauth-client-address/v1";

/// The keyed hash of the address an abuser controls as one unit, shared with
/// billing's card-setup limit. `None` when the edge named no address.
pub(crate) use codewire_server_core::client_address::unit_hash;
