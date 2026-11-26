//! # codewire-idp
//!
//! The Codewire OIDC provider **service**: it wires the transport-agnostic
//! [`codewire_oidc`] library to Postgres and the Codewire session/org model.
//! The library owns the OAuth/OIDC mechanics behind storage traits; this
//! crate implements those traits against the existing `oidc_clients` /
//! `jwks` / `sessions` / `oidc_refresh_tokens` schema and adds the
//! Codewire-specific glue (the session `UserAuthenticator`, profile/email
//! claim customization, client provisioning).
//!
//! This first slice ships the read-mostly data layer — [`PgClientStore`] and
//! [`PgKeyStore`] — plus the JWK codec that keeps the Rust and Go providers
//! on the same signing keys. The authorization/token stores, the auth
//! bridge, and the axum wiring land in subsequent slices.

#![forbid(unsafe_code)]

mod abuse_metrics;
pub mod access_admin;
pub mod account_admin_delete;
pub mod admin_bootstrap;
pub mod auth_requests;
pub mod auth_session;
pub mod client_address;
pub mod clients;
pub mod customizer;
pub mod device_authorizations;
pub mod device_verification;
pub mod email_password;
mod expired_rows;
pub mod feedback_notice;
pub mod invitation_email;
pub mod invitation_link;
pub mod jwk;
pub mod jwk_envelope;
pub mod keys;
mod mail_limit;
pub mod oauth;
pub mod operator_notice;
pub mod password_add;
pub mod private_api;
pub mod provisioning;
mod refresh_metrics;
pub mod request_spans;
pub mod service;
mod signup_limit;
pub mod tokens;
pub mod two_factor;
mod undeliverable;
pub mod user_auth;
pub mod user_tokens;

pub use abuse_metrics::expose as expose_abuse_metrics;
pub use auth_requests::PgAuthorizationStore;
pub use clients::PgClientStore;
pub use customizer::PgTokenCustomizer;
pub use device_authorizations::PgDeviceAuthorizationStore;
pub use jwk_envelope::SigningKekKeyring;
pub use keys::{PgKeyStore, SigningKekRewrapReport};
pub use service::{IdpConfig, build_provider};
pub use tokens::PgTokenStore;
pub use user_auth::PgUserAuthenticator;
