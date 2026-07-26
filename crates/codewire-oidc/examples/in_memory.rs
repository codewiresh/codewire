//! A complete, dependency-free in-memory backing for [`codewire_oidc`].
//!
//! This is the smallest thing that satisfies all six store traits and wires
//! up a [`Provider`]. It is meant as a reference for host implementors and
//! as a smoke test that the trait surface is actually usable — it is **not**
//! production-grade (a real host uses a database, constant-time secret
//! verification, and a real session system).
//!
//! Run with: `cargo run -p codewire-oidc --example in_memory`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use codewire_oidc::jwks::{PublicJwk, SigningKey};
use codewire_oidc::{
    AccessGrant, AuthCodeGrant, AuthOutcome, AuthRequestId, AuthorizationStore, Client,
    ClientStore, Issuer, KeyStore, Provider, ProviderConfig, RefreshGrant, RequestContext,
    StoreResult, StoredAuthRequest, Subject, TokenStore, UserAuthenticator,
};

/// Everything stored, behind one mutex for brevity.
#[derive(Default)]
struct State {
    auth_requests: HashMap<String, StoredAuthRequest>,
    codes: HashMap<String, AuthCodeGrant>,
    access: HashMap<String, AccessGrant>,
    refresh: HashMap<String, RefreshGrant>,
    next_id: u64,
}

#[derive(Default, Clone)]
struct Memory(Arc<Mutex<State>>);

#[async_trait::async_trait]
impl AuthorizationStore for Memory {
    async fn create(&self, mut request: StoredAuthRequest) -> StoreResult<AuthRequestId> {
        let mut s = self.0.lock().unwrap();
        s.next_id += 1;
        let id = AuthRequestId(format!("areq_{}", s.next_id));
        request.id = id.clone();
        s.auth_requests.insert(id.0.clone(), request);
        Ok(id)
    }
    async fn get(&self, id: &AuthRequestId) -> StoreResult<Option<StoredAuthRequest>> {
        Ok(self.0.lock().unwrap().auth_requests.get(&id.0).cloned())
    }
    async fn update(&self, request: &StoredAuthRequest) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .auth_requests
            .insert(request.id.0.clone(), request.clone());
        Ok(())
    }
    async fn delete(&self, id: &AuthRequestId) -> StoreResult<()> {
        self.0.lock().unwrap().auth_requests.remove(&id.0);
        Ok(())
    }
}

#[async_trait::async_trait]
impl TokenStore for Memory {
    async fn store_code(&self, code: &str, grant: AuthCodeGrant, _e: u64) -> StoreResult<()> {
        self.0.lock().unwrap().codes.insert(code.to_owned(), grant);
        Ok(())
    }
    async fn consume_code(&self, code: &str) -> StoreResult<Option<AuthCodeGrant>> {
        Ok(self.0.lock().unwrap().codes.remove(code))
    }
    async fn store_access(&self, token: &str, grant: AccessGrant, _e: u64) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .access
            .insert(token.to_owned(), grant);
        Ok(())
    }
    async fn get_access(&self, token: &str) -> StoreResult<Option<AccessGrant>> {
        Ok(self.0.lock().unwrap().access.get(token).cloned())
    }
    async fn store_refresh(&self, token: &str, grant: RefreshGrant, _e: u64) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .refresh
            .insert(token.to_owned(), grant);
        Ok(())
    }
    async fn consume_refresh(&self, token: &str) -> StoreResult<Option<RefreshGrant>> {
        Ok(self.0.lock().unwrap().refresh.remove(token))
    }
    async fn revoke(&self, token: &str) -> StoreResult<()> {
        let mut s = self.0.lock().unwrap();
        s.access.remove(token);
        s.refresh.remove(token);
        Ok(())
    }
}

/// A single hard-coded public client, for illustration.
struct OneClient(Client);

#[async_trait::async_trait]
impl ClientStore for OneClient {
    async fn get(&self, client_id: &str) -> StoreResult<Option<Client>> {
        Ok((client_id == self.0.id).then(|| self.0.clone()))
    }
    async fn verify_secret(&self, _client_id: &str, _secret: &str) -> StoreResult<bool> {
        // Public client: no secret to verify.
        Ok(false)
    }
}

/// A fixed Ed25519 key (all-zero material — illustrative only, never real).
struct OneKey;

#[async_trait::async_trait]
impl KeyStore for OneKey {
    async fn active_signer(&self) -> StoreResult<SigningKey> {
        Ok(SigningKey {
            kid: "demo-1".into(),
            secret_key: vec![0u8; 32],
            public_key: vec![0u8; 32],
        })
    }
    async fn public_jwks(&self) -> StoreResult<Vec<PublicJwk>> {
        Ok(vec![PublicJwk {
            kid: "demo-1".into(),
            public_key: vec![0u8; 32],
        }])
    }
}

/// Always authenticates as a fixed user.
struct AlwaysAlice;

#[async_trait::async_trait]
impl UserAuthenticator for AlwaysAlice {
    async fn authenticate(
        &self,
        _ctx: &RequestContext,
        _request: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome> {
        Ok(AuthOutcome::Authenticated {
            subject: Subject("user_alice".into()),
            auth_time: None,
        })
    }
}

#[tokio::main]
async fn main() {
    let mem = Memory::default();
    let client = Client {
        id: "demo-client".into(),
        name: "Demo".into(),
        application_type: codewire_oidc::ApplicationType::UserAgent,
        auth_method: codewire_oidc::AuthMethod::None,
        redirect_uris: vec!["https://app.example/callback".into()],
        post_logout_redirect_uris: vec![],
        grant_types: vec![
            codewire_oidc::GrantType::AuthorizationCode,
            codewire_oidc::GrantType::RefreshToken,
        ],
        response_types: vec![codewire_oidc::ResponseType::Code],
        scopes: codewire_oidc::Scopes::parse("openid profile email"),
        skip_consent: true,
        access_token_lifetime_secs: 3600,
        id_token_lifetime_secs: 3600,
        refresh_token_lifetime_secs: Some(2_592_000),
        clock_skew_secs: 60,
        disabled: false,
    };

    let provider = Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
    })
    .auth_requests(Arc::new(mem.clone()))
    .tokens(Arc::new(mem.clone()))
    .clients(Arc::new(OneClient(client)))
    .keys(Arc::new(OneKey))
    .authenticator(Arc::new(AlwaysAlice))
    .build()
    .expect("all required stores provided");

    let disco = provider.discovery();
    println!("issuer:           {}", disco.issuer);
    println!("authorization:    {}", disco.authorization_endpoint);
    println!("token:            {}", disco.token_endpoint);
    println!("jwks_uri:         {}", disco.jwks_uri);
    println!(
        "id_token alg:     {:?}",
        disco.id_token_signing_alg_values_supported
    );
    println!(
        "pkce methods:     {:?}",
        disco.code_challenge_methods_supported
    );

    let jwks = provider.jwks().await.expect("jwks");
    println!("published keys:   {}", jwks.keys.len());
    println!("first kid:        {}", jwks.keys[0].kid);
}
