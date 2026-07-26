//! Storage and host-integration traits — the entire boundary between this
//! library and a deployment.
//!
//! The library owns the OAuth/OIDC *mechanics*; everything stateful or
//! deployment-specific lives behind these traits, so a host can back them
//! with sqlx, an in-memory map (see `examples/in_memory.rs`), or anything
//! else. Each trait is `async` (via [`async_trait`]) and `Send + Sync` so
//! it can sit in shared application state.
//!
//! Fallible methods return [`StoreResult`], whose error
//! ([`crate::error::StoreError`]) is opaque to the library — it surfaces as
//! a `server_error` to the client and the cause is the host's to log.

use async_trait::async_trait;

use crate::error::StoreResult;
use crate::jwks::{PublicJwk, SigningKey};
use crate::types::{
    AccessGrant, AuthCodeGrant, AuthOutcome, AuthRequestId, Client, DeviceAuthorization,
    RefreshGrant, RequestContext, StoredAuthRequest,
};

/// Persistence for in-flight authorization requests.
///
/// The `/authorize` endpoint stores a request before bouncing the user
/// through login; the callback reloads and updates it once the subject is
/// known, and the code-issuing step reads it back a final time.
#[async_trait]
pub trait AuthorizationStore: Send + Sync {
    /// Persist a new authorization request, returning its opaque id.
    async fn create(&self, request: StoredAuthRequest) -> StoreResult<AuthRequestId>;

    /// Load a stored request by id, or `None` if unknown/expired.
    async fn get(&self, id: &AuthRequestId) -> StoreResult<Option<StoredAuthRequest>>;

    /// Persist an updated request (e.g. after binding the subject).
    async fn update(&self, request: &StoredAuthRequest) -> StoreResult<()>;

    /// Delete a request once it has been consumed.
    async fn delete(&self, id: &AuthRequestId) -> StoreResult<()>;
}

/// Persistence for issued tokens — authorization codes, opaque access
/// tokens, and refresh tokens.
///
/// Codes and refresh tokens are **single-use**: `consume_*` must atomically
/// fetch-and-invalidate so a replayed code/token cannot be exchanged twice
/// (threat T6/T9). Access tokens are opaque (not JWTs); `get_access` is how
/// the userinfo/introspection paths resolve them.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Store an authorization code → grant, with an absolute expiry.
    async fn store_code(
        &self,
        code: &str,
        grant: AuthCodeGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()>;

    /// Atomically consume an authorization code, returning its grant if the
    /// code was valid and unexpired (and deleting it). A second call for the
    /// same code returns `None`.
    async fn consume_code(&self, code: &str) -> StoreResult<Option<AuthCodeGrant>>;

    /// Store an opaque access token → grant, with an absolute expiry.
    async fn store_access(
        &self,
        token: &str,
        grant: AccessGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()>;

    /// Resolve an opaque access token to its grant, or `None` if
    /// unknown/expired/revoked.
    async fn get_access(&self, token: &str) -> StoreResult<Option<AccessGrant>>;

    /// Non-destructively resolve a refresh token to its grant (for token
    /// introspection / revocation ownership checks). Unlike [`Self::consume_refresh`]
    /// this does **not** rotate the token. The default returns `None`, so a
    /// host that doesn't support refresh-token introspection need not
    /// implement it.
    async fn get_refresh(&self, _token: &str) -> StoreResult<Option<RefreshGrant>> {
        Ok(None)
    }

    /// Store a refresh token → grant, with an absolute expiry.
    async fn store_refresh(
        &self,
        token: &str,
        grant: RefreshGrant,
        expires_in_secs: u64,
    ) -> StoreResult<()>;

    /// Atomically consume a refresh token (rotation), returning its grant if
    /// valid (and deleting it). A replayed refresh token returns `None`.
    ///
    /// Hardening (recommended, OAuth 2.1 / RFC 9700 §4.14.2): treat the replay
    /// of an already-consumed token as a breach signal and revoke the whole
    /// token family for that subject+client. The library cannot do this — it
    /// has no family graph — so the choice lives with the store.
    async fn consume_refresh(&self, token: &str) -> StoreResult<Option<RefreshGrant>>;

    /// Revoke an access or refresh token (RFC 7009). Revoking an unknown
    /// token is a no-op success.
    async fn revoke(&self, token: &str) -> StoreResult<()>;
}

/// Lookup of registered relying parties.
///
/// Read-only from the library's perspective — client registration/rotation
/// is the host's concern; the provider only ever resolves a `client_id` to
/// its capability set.
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// Load a client by `client_id`, or `None` if unknown.
    async fn get(&self, client_id: &str) -> StoreResult<Option<Client>>;

    /// Verify a confidential client's secret. Implementations MUST compare
    /// in constant time (e.g. bcrypt/argon2 verify). Public clients have no
    /// secret and never reach this path.
    async fn verify_secret(&self, client_id: &str, secret: &str) -> StoreResult<bool>;
}

/// Access to the provider's signing keys.
///
/// id_tokens are signed with **EdDSA (Ed25519)**. The active signer mints
/// new id_tokens; `public_jwks` publishes the active key plus any
/// still-valid retired keys so tokens issued before a rotation still
/// verify.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// The key currently used to sign id_tokens.
    async fn active_signer(&self) -> StoreResult<SigningKey>;

    /// All public keys to publish at the JWKS endpoint (active first).
    async fn public_jwks(&self) -> StoreResult<Vec<PublicJwk>>;
}

/// Resolves the end-user behind an authorization request.
///
/// This is the bridge to the host's existing session/login system. Given
/// the ambient request context (e.g. the session cookie) and the request
/// being authorized, it returns whether the user is authenticated, must be
/// sent to login, or is denied by policy (e.g. not a member of the org a
/// resource client is scoped to).
#[async_trait]
pub trait UserAuthenticator: Send + Sync {
    /// Resolve the current end-user for `request` given `ctx`.
    async fn authenticate(
        &self,
        ctx: &RequestContext,
        request: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome>;
}

/// Persistence for the device-authorization grant (RFC 8628).
///
/// Optional — only hosts that enable device flow implement and inject it. The
/// `get_by_*` lookups must return `None` once the record has expired (the
/// store owns expiry, as with codes and tokens).
#[async_trait]
pub trait DeviceAuthorizationStore: Send + Sync {
    /// Persist a new device-authorization request with an absolute expiry.
    async fn store_device(
        &self,
        auth: DeviceAuthorization,
        expires_in_secs: u64,
    ) -> StoreResult<()>;

    /// Look up a pending request by its (human-entered) user code — for the
    /// verification UI and the approve/deny step.
    async fn get_by_user_code(&self, user_code: &str) -> StoreResult<Option<DeviceAuthorization>>;

    /// Look up a request by its device code — for token-endpoint polling.
    async fn get_by_device_code(
        &self,
        device_code: &str,
    ) -> StoreResult<Option<DeviceAuthorization>>;

    /// Atomically consume an approved device authorization, returning its
    /// grant if it was still valid. A concurrent or replayed redemption
    /// returns `None`, so a device code cannot mint more than one token set.
    async fn consume_approved(&self, device_code: &str)
    -> StoreResult<Option<DeviceAuthorization>>;

    /// Persist a status change (approved/denied).
    async fn update(&self, auth: &DeviceAuthorization) -> StoreResult<()>;

    /// Delete a request once its code has been redeemed.
    async fn delete(&self, device_code: &str) -> StoreResult<()>;
}

/// Lets the host inject deployment-specific claims into id_tokens and
/// userinfo responses (e.g. `org_id`, `org_role`, `org_assignments`).
///
/// Called with the resolved subject, the granted scopes, and the client; it
/// returns the extra claims merged into the standard set. The default
/// implementation adds nothing, keeping the library deployment-neutral.
#[async_trait]
pub trait TokenCustomizer: Send + Sync {
    /// Extra claims for this subject/client/scope combination. Keys collide
    /// last-writer-wins with the standard claims, so avoid reserved names.
    async fn extra_claims(
        &self,
        _subject: &crate::types::Subject,
        _scopes: &crate::types::Scopes,
        _client: &Client,
    ) -> StoreResult<std::collections::BTreeMap<String, serde_json::Value>> {
        Ok(Default::default())
    }
}
