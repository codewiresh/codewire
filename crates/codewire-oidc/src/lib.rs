//! `codewire-oidc` — a standalone, transport-agnostic OpenID Connect /
//! OAuth 2.0 **provider** (OP) library.
//!
//! The crate implements the protocol mechanics — discovery, JWKS, the
//! authorization-code flow with mandatory PKCE (S256), opaque Bearer access
//! tokens, EdDSA-signed id_tokens, refresh-token rotation, revocation,
//! introspection, userinfo, and RP-initiated logout — while delegating all
//! state and deployment policy to the [`store`] traits. That separation is
//! deliberate: the crate carries **zero Codewire-internal dependencies** so
//! it can be extracted and published on its own (the CI extraction guard,
//! `cargo check -p codewire-oidc --no-default-features`, enforces this), and
//! is dual-licensed `MIT OR Apache-2.0` to keep that extraction cheap.
//!
//! # Shape
//!
//! - [`types`] — protocol value types (clients, scopes, claims, grants).
//! - [`error`] — the OAuth error taxonomy and the opaque store error.
//! - [`jwks`] — Ed25519 JWK/JWKS and signing-key types.
//! - [`discovery`] — the `/.well-known/openid-configuration` document.
//! - [`store`] — the six traits a host implements to back the provider.
//! - [`Provider`] — ties a set of store implementations to an issuer and
//!   serves the stateless metadata endpoints today; the interactive flows
//!   (`/authorize`, `/token`, `/userinfo`, …) land in subsequent slices.
//!
//! See `examples/in_memory.rs` for a complete, dependency-free backing.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod device;
pub mod discovery;
pub mod endsession;
pub mod error;
pub mod flow;
pub mod introspection;
pub mod jwks;
pub mod pkce;
pub mod store;
pub mod token;
#[cfg(feature = "axum")]
pub mod transport;
pub mod types;
pub mod userinfo;

pub use device::DeviceAuthorizationResponse;
pub use discovery::{DiscoveryDocument, EndpointPaths};
pub use endsession::{EndSessionOutcome, RawEndSessionParams};
pub use error::{ErrorCode, OAuthError, StoreError, StoreResult};
pub use flow::{AuthorizeOutcome, RawAuthorizeParams, TokenResponse};
pub use introspection::IntrospectionResponse;
pub use jwks::{Jwk, Jwks, PublicJwk, SigningKey};
pub use pkce::CodeChallengeMethod;
pub use store::{
    AuthorizationStore, ClientStore, DeviceAuthorizationStore, KeyStore, TokenCustomizer,
    TokenStore, UserAuthenticator,
};
pub use types::{
    AccessGrant, ApplicationType, AuthCodeGrant, AuthMethod, AuthOutcome, AuthRequestId,
    AuthorizationRequest, Claims, Client, DeviceAuthorization, DeviceStatus, GrantType, Issuer,
    RefreshGrant, RequestContext, ResponseType, Scopes, StoredAuthRequest, Subject,
};

use std::sync::Arc;

/// The provider's static configuration.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// The issuer identifier (also the base for endpoint URLs).
    pub issuer: Issuer,
    /// Endpoint paths (defaults match the current Go provider).
    pub paths: EndpointPaths,
    /// Scopes advertised in discovery (e.g. `openid profile email`).
    pub scopes_supported: Vec<String>,
}

/// The OpenID provider: a configuration plus the host's store
/// implementations.
///
/// Construct it with [`ProviderBuilder`]. Today it serves the two stateless
/// metadata endpoints — [`Provider::discovery`] and [`Provider::jwks`] —
/// from the [`KeyStore`]; the interactive endpoints attach in later slices,
/// reusing the same injected stores.
#[derive(Clone)]
pub struct Provider {
    config: ProviderConfig,
    auth_requests: Arc<dyn AuthorizationStore>,
    tokens: Arc<dyn TokenStore>,
    clients: Arc<dyn ClientStore>,
    keys: Arc<dyn KeyStore>,
    authenticator: Arc<dyn UserAuthenticator>,
    customizer: Arc<dyn TokenCustomizer>,
    device_store: Option<Arc<dyn store::DeviceAuthorizationStore>>,
    device_verification_uri: Option<String>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Provider {
    /// Start building a provider for the given configuration.
    pub fn builder(config: ProviderConfig) -> ProviderBuilder {
        ProviderBuilder::new(config)
    }

    /// The provider configuration.
    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// The authorization-request store.
    pub fn auth_requests(&self) -> &Arc<dyn AuthorizationStore> {
        &self.auth_requests
    }

    /// The token store.
    pub fn tokens(&self) -> &Arc<dyn TokenStore> {
        &self.tokens
    }

    /// The client store.
    pub fn clients(&self) -> &Arc<dyn ClientStore> {
        &self.clients
    }

    /// The key store.
    pub fn keys(&self) -> &Arc<dyn KeyStore> {
        &self.keys
    }

    /// The user authenticator.
    pub fn authenticator(&self) -> &Arc<dyn UserAuthenticator> {
        &self.authenticator
    }

    /// The token customizer.
    pub fn customizer(&self) -> &Arc<dyn TokenCustomizer> {
        &self.customizer
    }

    /// The device-authorization store, if device flow is enabled.
    pub fn device_store(&self) -> Option<&Arc<dyn store::DeviceAuthorizationStore>> {
        self.device_store.as_ref()
    }

    /// The user-facing verification URI for device flow (where the end-user
    /// enters their user code). Defaults to `{issuer}/device` when unset.
    pub fn device_verification_uri(&self) -> String {
        self.device_verification_uri.clone().unwrap_or_else(|| {
            format!(
                "{}/device",
                self.config.issuer.as_str().trim_end_matches('/')
            )
        })
    }

    /// Build the discovery document (`/.well-known/openid-configuration`).
    ///
    /// Pure — derived from the static configuration, safe to cache.
    pub fn discovery(&self) -> DiscoveryDocument {
        DiscoveryDocument::build(
            &self.config.issuer,
            &self.config.paths,
            self.config.scopes_supported.clone(),
            self.device_store.is_some(),
        )
    }

    /// Build the JWKS document from the [`KeyStore`]'s published keys.
    pub async fn jwks(&self) -> StoreResult<Jwks> {
        let keys = self.keys.public_jwks().await?;
        Ok(Jwks {
            keys: keys.iter().map(PublicJwk::to_jwk).collect(),
        })
    }
}

/// Builder for [`Provider`]. Every store is required; there are no silent
/// defaults for stateful collaborators (a missing one is a compile-time-ish
/// runtime panic at [`ProviderBuilder::build`], surfaced as a clear
/// message), except [`TokenCustomizer`], which defaults to a no-op.
pub struct ProviderBuilder {
    config: ProviderConfig,
    auth_requests: Option<Arc<dyn AuthorizationStore>>,
    tokens: Option<Arc<dyn TokenStore>>,
    clients: Option<Arc<dyn ClientStore>>,
    keys: Option<Arc<dyn KeyStore>>,
    authenticator: Option<Arc<dyn UserAuthenticator>>,
    customizer: Option<Arc<dyn TokenCustomizer>>,
    device_store: Option<Arc<dyn store::DeviceAuthorizationStore>>,
    device_verification_uri: Option<String>,
}

impl ProviderBuilder {
    /// Start a builder with the given configuration.
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            auth_requests: None,
            tokens: None,
            clients: None,
            keys: None,
            authenticator: None,
            customizer: None,
            device_store: None,
            device_verification_uri: None,
        }
    }

    /// Set the authorization-request store.
    pub fn auth_requests(mut self, s: Arc<dyn AuthorizationStore>) -> Self {
        self.auth_requests = Some(s);
        self
    }

    /// Set the token store.
    pub fn tokens(mut self, s: Arc<dyn TokenStore>) -> Self {
        self.tokens = Some(s);
        self
    }

    /// Set the client store.
    pub fn clients(mut self, s: Arc<dyn ClientStore>) -> Self {
        self.clients = Some(s);
        self
    }

    /// Set the key store.
    pub fn keys(mut self, s: Arc<dyn KeyStore>) -> Self {
        self.keys = Some(s);
        self
    }

    /// Set the user authenticator.
    pub fn authenticator(mut self, s: Arc<dyn UserAuthenticator>) -> Self {
        self.authenticator = Some(s);
        self
    }

    /// Set the token customizer (optional; defaults to a no-op).
    pub fn customizer(mut self, s: Arc<dyn TokenCustomizer>) -> Self {
        self.customizer = Some(s);
        self
    }

    /// Enable the device-authorization grant (RFC 8628) by supplying its
    /// store. When unset, the device endpoints return `invalid_request`.
    pub fn device_store(mut self, s: Arc<dyn store::DeviceAuthorizationStore>) -> Self {
        self.device_store = Some(s);
        self
    }

    /// Override the device-flow verification URI (defaults to `{issuer}/device`).
    pub fn device_verification_uri(mut self, uri: impl Into<String>) -> Self {
        self.device_verification_uri = Some(uri.into());
        self
    }

    /// Finish building, returning the [`Provider`].
    ///
    /// # Errors
    ///
    /// Returns an error naming the first missing required store.
    pub fn build(self) -> Result<Provider, &'static str> {
        Ok(Provider {
            config: self.config,
            auth_requests: self
                .auth_requests
                .ok_or("auth_requests store is required")?,
            tokens: self.tokens.ok_or("tokens store is required")?,
            clients: self.clients.ok_or("clients store is required")?,
            keys: self.keys.ok_or("keys store is required")?,
            authenticator: self.authenticator.ok_or("authenticator is required")?,
            customizer: self
                .customizer
                .unwrap_or_else(|| Arc::new(DefaultCustomizer)),
            device_store: self.device_store,
            device_verification_uri: self.device_verification_uri,
        })
    }
}

/// A no-op [`TokenCustomizer`] — adds no extra claims.
struct DefaultCustomizer;

#[async_trait::async_trait]
impl TokenCustomizer for DefaultCustomizer {}
