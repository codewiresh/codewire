pub mod billing;
pub mod catalog;

use codewire_server_core::AppBuilder;
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::ConnectAuthLayer;

use crate::routes::BillingState;

/// The methods billing answers without a credential. The signed-out pricing
/// page reads the sign-up credit and Regular's rates; nothing else on the
/// billing mount is public.
pub const PUBLIC_METHODS: [&str; 2] = [
    "/codewire.console.v1.BillingService/GetSignupCredit",
    "/codewire.console.v1.BillingService/GetPublicRates",
];

/// Mounts billing's Connect services on `app`, each behind its auth mode.
/// The binary and the wire tests both build billing through this.
pub fn mount(app: AppBuilder, state: BillingState, auth: AuthState) -> AppBuilder {
    let connect_auth = ConnectAuthLayer::authenticated(auth.clone()).allow_public(PUBLIC_METHODS);
    app.with_unary_connect_routes_auth(billing::router(state.clone()), connect_auth)
        .with_unary_connect_routes_auth(catalog::router(state), ConnectAuthLayer::admin(auth))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allowlist on its own: a method added to it is public even while
    /// its handler still checks the caller, which the wire test can't see.
    #[test]
    fn only_the_sign_up_credit_and_regulars_rates_are_public() {
        assert_eq!(
            PUBLIC_METHODS,
            [
                "/codewire.console.v1.BillingService/GetSignupCredit",
                "/codewire.console.v1.BillingService/GetPublicRates",
            ]
        );
    }
}
