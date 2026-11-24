//! Minting a Sandbox's identity token (docs/dev/SANDBOX-IDENTITY.md,
//! "Minting" and "Kill switches"), once `IssueIdentityToken` has
//! authenticated the caller as its bound Pod
//! (`workspace_binding::service::identity`). In this order:
//!
//! 1. the circuit breaker;
//! 2. the organization's limit, once the Sandbox's organization is read;
//! 3. the organization (not suspended or being deleted), then the Sandbox
//!    (running, its access not suspended);
//! 4. the kill switches;
//! 5. the organization's registration of the audience;
//! 6. the cache;
//! 7. the signature, with the key version that signs now, and its row in
//!    `identity_mints`.
//!
//! So a stopped Sandbox gets no token from here, not even a cached one.
//! Every refusal is one of the spec's names, and none carries a value.

mod breaker;
mod cache;
pub mod limits;
mod store;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use super::config::{IdentitySettings, IssuerBase, MintingSwitch, SignerConfig};
use super::keys::{KeySet, SigningKey, SigningRefusal};
use super::token::{SubjectFacts, TokenSubject, TrustDomain, UnsignedToken, new_jti};
use super::transit::{JwsSignature, TransitError, TransitKeyClient};
use breaker::CircuitBreaker;
pub use breaker::{TRIP_AFTER_FAILURES, TRIP_FOR};
use cache::{CacheKey, TokenCache};
pub(crate) use limits::MintLimits;
use store::{MintRecord, MintStore, OrgStanding, PgMintStore};

/// Why no token was issued. Each is a refusal name of the spec; the RPC
/// sends the name as its error message, and the daemon and `cw identity
/// token` read it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintRefusal {
    /// The resource isn't an `https` URI, or isn't registered for the
    /// organization: one answer for both.
    InvalidTarget,
    NotRunning,
    /// The organization is suspended or being deleted, the Sandbox's access
    /// is suspended, or a kill switch is on.
    IdentityStopped,
    ResourceExhausted,
    /// The breaker is open, identity is off, or OpenBao can't sign.
    IdentityUnavailable,
    KeyNotYetPublished,
}

impl MintRefusal {
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidTarget => "invalid_target",
            Self::NotRunning => "not_running",
            Self::IdentityStopped => "identity_stopped",
            Self::ResourceExhausted => "resource_exhausted",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::KeyNotYetPublished => "key_not_yet_published",
        }
    }

    pub fn connect(self) -> connectrpc::ConnectError {
        use connectrpc::ConnectError;
        let name = self.name();
        match self {
            Self::InvalidTarget => ConnectError::invalid_argument(name),
            Self::NotRunning => ConnectError::failed_precondition(name),
            Self::IdentityStopped => ConnectError::permission_denied(name),
            Self::ResourceExhausted => ConnectError::resource_exhausted(name),
            Self::IdentityUnavailable | Self::KeyNotYetPublished => ConnectError::unavailable(name),
        }
    }
}

/// An issued token. Never logged.
pub struct IssuedToken {
    pub token: Zeroizing<String>,
    pub expires_at: i64,
}

/// The OpenBao calls a mint makes. [`TransitKeyClient`] in production.
#[async_trait]
pub(crate) trait IdentitySigner: Send + Sync {
    async fn read_key(&self) -> Result<KeySet, TransitError>;
    async fn sign(&self, key: SigningKey, input: &[u8]) -> Result<JwsSignature, TransitError>;
}

#[async_trait]
impl IdentitySigner for TransitKeyClient {
    async fn read_key(&self) -> Result<KeySet, TransitError> {
        TransitKeyClient::read_key(self).await
    }
    async fn sign(&self, key: SigningKey, input: &[u8]) -> Result<JwsSignature, TransitError> {
        TransitKeyClient::sign(self, key, input).await
    }
}

/// Minting for one orchestration replica.
pub struct IdentityMinting {
    issuer_base: IssuerBase,
    trust_domain: TrustDomain,
    signer: Arc<dyn IdentitySigner>,
    store: Arc<dyn MintStore>,
    breaker: CircuitBreaker,
    limits: MintLimits,
    cache: TokenCache,
}

impl IdentityMinting {
    /// Minting for enabled identity: its own OpenBao login under the signer
    /// role, its own database pool, and the trust domain under the
    /// deployment's public origin, which must be an https DNS origin.
    pub fn from_settings(
        settings: &IdentitySettings,
        switch: MintingSwitch,
        kube: kube::Client,
        database_url: &str,
        public_origin: &str,
    ) -> anyhow::Result<Self> {
        let SignerConfig::OpenBaoTransit(transit) = &settings.signer;
        Ok(Self::new(
            settings.issuer_base.clone(),
            TrustDomain::from_public_origin(public_origin)?,
            Arc::new(super::transit_key_client(transit, kube)?),
            Arc::new(PgMintStore::connect_lazy(database_url)?),
            switch,
        ))
    }

    pub(crate) fn new(
        issuer_base: IssuerBase,
        trust_domain: TrustDomain,
        signer: Arc<dyn IdentitySigner>,
        store: Arc<dyn MintStore>,
        switch: MintingSwitch,
    ) -> Self {
        Self {
            issuer_base,
            trust_domain,
            signer,
            store,
            breaker: CircuitBreaker::new(switch),
            limits: MintLimits::default(),
            cache: TokenCache::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: MintLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn limits(&self) -> &MintLimits {
        &self.limits
    }

    /// A token for the authenticated, bound Sandbox `environment_id` and
    /// the canonical `audience`, at `now`.
    pub(crate) async fn mint(
        &self,
        environment_id: &str,
        audience: &str,
        now: DateTime<Utc>,
    ) -> Result<IssuedToken, MintRefusal> {
        if !self.breaker.allows(std::time::Instant::now()) {
            return Err(MintRefusal::IdentityUnavailable);
        }
        let sandbox = self
            .store
            .subject(environment_id)
            .await
            .map_err(|_| MintRefusal::IdentityUnavailable)?
            .ok_or(MintRefusal::NotRunning)?;
        if !self.limits.admit_org(&sandbox.org_id) {
            return Err(MintRefusal::ResourceExhausted);
        }
        if sandbox.org != OrgStanding::Active {
            return Err(MintRefusal::IdentityStopped);
        }
        if !sandbox.running {
            return Err(MintRefusal::NotRunning);
        }
        if sandbox.access_suspended || sandbox.stopped {
            return Err(MintRefusal::IdentityStopped);
        }
        let registration = self
            .store
            .registration(&sandbox.org_id, audience)
            .await
            .map_err(|_| MintRefusal::IdentityUnavailable)?
            .ok_or(MintRefusal::InvalidTarget)?;
        let subject = TokenSubject::new(&SubjectFacts {
            issuer_base: &self.issuer_base,
            trust_domain: &self.trust_domain,
            org_id: &sandbox.org_id,
            environment_id,
            created_by: &sandbox.created_by,
            environment_name: sandbox.name.as_deref(),
            groups: &sandbox.groups,
            audience,
            visible_groups: registration.visible_groups.as_deref(),
            lifetime_seconds: i64::from(registration.lifetime_seconds),
            claim_created_by: registration.claim_created_by,
            claim_environment_name: registration.claim_environment_name,
        });
        let key = CacheKey {
            environment_id: environment_id.to_owned(),
            audience: audience.to_owned(),
            groups_version: sandbox.groups_version,
            audience_version: registration.version,
        };
        let issued_at = now.timestamp();
        if let Some(cached) = self.cache.get(&key, &subject, issued_at) {
            return Ok(IssuedToken {
                token: cached.token,
                expires_at: cached.expires_at,
            });
        }

        let signing_key = self.signing_key(now).await?;
        let jti = new_jti().map_err(|_| MintRefusal::IdentityUnavailable)?;
        let unsigned = UnsignedToken::new(&subject, signing_key, issued_at, &jti);
        let signature = match self
            .signer
            .sign(signing_key, unsigned.signing_input())
            .await
        {
            Ok(signature) => {
                self.breaker.signed();
                signature
            }
            Err(error) => {
                self.breaker.failed(std::time::Instant::now());
                tracing::warn!(error = %error, audience, "sandbox identity signing failed");
                return Err(MintRefusal::IdentityUnavailable);
            }
        };
        let expires_at = unsigned.expires_at();
        let kid = signing_key.kid();
        // A token whose mint isn't logged is never handed out.
        self.store
            .record(&MintRecord {
                jti,
                environment_id: environment_id.to_owned(),
                org_id: sandbox.org_id.clone(),
                audience: audience.to_owned(),
                kid: kid.clone(),
                groups_version: sandbox.groups_version,
                audience_version: registration.version,
                minted_at: now,
            })
            .await
            .map_err(|_| MintRefusal::IdentityUnavailable)?;
        let token = unsigned.signed(&signature);
        self.cache
            .insert(key, subject, token.clone(), issued_at, expires_at);
        tracing::info!(
            environment_id,
            audience,
            kid,
            "sandbox identity token minted"
        );
        Ok(IssuedToken { token, expires_at })
    }

    /// The key version that signs at `now`, read from OpenBao for this mint.
    async fn signing_key(&self, now: DateTime<Utc>) -> Result<SigningKey, MintRefusal> {
        let key_set = match self.signer.read_key().await {
            Ok(key_set) => key_set,
            Err(error) => {
                self.breaker.failed(std::time::Instant::now());
                tracing::warn!(error = %error, "sandbox identity key read failed");
                return Err(MintRefusal::IdentityUnavailable);
            }
        };
        key_set.signing_key(now).map_err(|refusal| match refusal {
            SigningRefusal::NotYetPublished(_) => MintRefusal::KeyNotYetPublished,
            SigningRefusal::Drift => {
                tracing::error!("{refusal}; minting refuses to sign");
                MintRefusal::IdentityUnavailable
            }
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
