//! End-to-end exercise of the authorization-code grant against an in-memory
//! backing: happy path, PKCE enforcement, single-use codes, and the
//! pre-redirect validation gates.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use codewire_oidc::jwks::{PublicJwk, SigningKey};
use codewire_oidc::{
    AccessGrant, ApplicationType, AuthCodeGrant, AuthMethod, AuthOutcome, AuthRequestId,
    AuthorizationStore, AuthorizeOutcome, Client, ClientStore, EndSessionOutcome, GrantType,
    Issuer, KeyStore, Provider, ProviderConfig, RawAuthorizeParams, RawEndSessionParams,
    RefreshGrant, RequestContext, ResponseType, Scopes, StoreResult, StoredAuthRequest, Subject,
    TokenStore, UserAuthenticator,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;

#[derive(Default)]
struct Inner {
    reqs: HashMap<String, StoredAuthRequest>,
    codes: HashMap<String, AuthCodeGrant>,
    access: HashMap<String, AccessGrant>,
    refresh: HashMap<String, RefreshGrant>,
    seq: u64,
}

#[derive(Default, Clone)]
struct Mem(Arc<Mutex<Inner>>);

#[async_trait::async_trait]
impl AuthorizationStore for Mem {
    async fn create(&self, mut r: StoredAuthRequest) -> StoreResult<AuthRequestId> {
        let mut g = self.0.lock().unwrap();
        g.seq += 1;
        let id = AuthRequestId(format!("r{}", g.seq));
        r.id = id.clone();
        g.reqs.insert(id.0.clone(), r);
        Ok(id)
    }
    async fn get(&self, id: &AuthRequestId) -> StoreResult<Option<StoredAuthRequest>> {
        Ok(self.0.lock().unwrap().reqs.get(&id.0).cloned())
    }
    async fn update(&self, r: &StoredAuthRequest) -> StoreResult<()> {
        self.0
            .lock()
            .unwrap()
            .reqs
            .insert(r.id.0.clone(), r.clone());
        Ok(())
    }
    async fn delete(&self, id: &AuthRequestId) -> StoreResult<()> {
        self.0.lock().unwrap().reqs.remove(&id.0);
        Ok(())
    }
}

#[async_trait::async_trait]
impl TokenStore for Mem {
    async fn store_code(&self, c: &str, g: AuthCodeGrant, _e: u64) -> StoreResult<()> {
        self.0.lock().unwrap().codes.insert(c.into(), g);
        Ok(())
    }
    async fn consume_code(&self, c: &str) -> StoreResult<Option<AuthCodeGrant>> {
        Ok(self.0.lock().unwrap().codes.remove(c))
    }
    async fn store_access(&self, t: &str, g: AccessGrant, _e: u64) -> StoreResult<()> {
        self.0.lock().unwrap().access.insert(t.into(), g);
        Ok(())
    }
    async fn get_access(&self, t: &str) -> StoreResult<Option<AccessGrant>> {
        Ok(self.0.lock().unwrap().access.get(t).cloned())
    }
    async fn store_refresh(&self, t: &str, g: RefreshGrant, _e: u64) -> StoreResult<()> {
        self.0.lock().unwrap().refresh.insert(t.into(), g);
        Ok(())
    }
    async fn consume_refresh(&self, t: &str) -> StoreResult<Option<RefreshGrant>> {
        Ok(self.0.lock().unwrap().refresh.remove(t))
    }
    async fn get_refresh(&self, t: &str) -> StoreResult<Option<RefreshGrant>> {
        Ok(self.0.lock().unwrap().refresh.get(t).cloned())
    }
    async fn revoke(&self, t: &str) -> StoreResult<()> {
        let mut g = self.0.lock().unwrap();
        g.access.remove(t);
        g.refresh.remove(t);
        Ok(())
    }
}

/// One public client + one confidential client, with a real signing key.
struct Clients {
    public: Client,
    confidential: Client,
    /// A public client that supports only the authorization_code grant (no
    /// refresh) — to exercise the grant-type check.
    code_only: Client,
    confidential_secret: String,
}

#[async_trait::async_trait]
impl ClientStore for Clients {
    async fn get(&self, id: &str) -> StoreResult<Option<Client>> {
        Ok([&self.public, &self.confidential, &self.code_only]
            .into_iter()
            .find(|c| c.id == id)
            .cloned())
    }
    async fn verify_secret(&self, id: &str, secret: &str) -> StoreResult<bool> {
        Ok(id == self.confidential.id && secret == self.confidential_secret)
    }
}

struct Keys(SigningKey);

#[async_trait::async_trait]
impl KeyStore for Keys {
    async fn active_signer(&self) -> StoreResult<SigningKey> {
        Ok(self.0.clone())
    }
    async fn public_jwks(&self) -> StoreResult<Vec<PublicJwk>> {
        Ok(vec![PublicJwk {
            kid: self.0.kid.clone(),
            public_key: self.0.public_key.clone(),
        }])
    }
}

/// Authenticator that returns a fixed subject, or denies, or needs login.
enum Auth {
    Ok(&'static str),
    NeedsLogin(&'static str),
    Denied(&'static str),
}

#[async_trait::async_trait]
impl UserAuthenticator for Auth {
    async fn authenticate(
        &self,
        _ctx: &RequestContext,
        _r: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome> {
        Ok(match self {
            Auth::Ok(s) => AuthOutcome::Authenticated {
                subject: Subject((*s).into()),
                auth_time: Some(1_700_000_000),
            },
            Auth::NeedsLogin(u) => AuthOutcome::NeedsLogin((*u).into()),
            Auth::Denied(r) => AuthOutcome::Denied((*r).into()),
        })
    }
}

fn client(id: &str, method: AuthMethod, app: ApplicationType) -> Client {
    Client {
        id: id.into(),
        name: id.into(),
        application_type: app,
        auth_method: method,
        redirect_uris: vec!["https://app.example/cb".into()],
        post_logout_redirect_uris: vec!["https://app.example/logged-out".into()],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        response_types: vec![ResponseType::Code],
        scopes: Scopes::parse("openid profile email offline_access"),
        skip_consent: true,
        access_token_lifetime_secs: 3600,
        id_token_lifetime_secs: 3600,
        refresh_token_lifetime_secs: Some(2_592_000),
        clock_skew_secs: 60,
        disabled: false,
    }
}

fn signing_key() -> SigningKey {
    let s = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    SigningKey {
        kid: "codewire-test".into(),
        secret_key: s.to_bytes().to_vec(),
        public_key: s.verifying_key().to_bytes().to_vec(),
    }
}

fn provider(auth: Auth) -> Provider {
    let mem = Mem::default();
    let clients = Clients {
        public: client("pub", AuthMethod::None, ApplicationType::UserAgent),
        confidential: client("conf", AuthMethod::ClientSecretBasic, ApplicationType::Web),
        code_only: {
            let mut c = client("codeonly", AuthMethod::None, ApplicationType::UserAgent);
            c.grant_types = vec![GrantType::AuthorizationCode];
            c.refresh_token_lifetime_secs = None;
            c
        },
        confidential_secret: "s3cr3t".into(),
    };
    Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
    })
    .auth_requests(Arc::new(mem.clone()))
    .tokens(Arc::new(mem))
    .clients(Arc::new(clients))
    .keys(Arc::new(Keys(signing_key())))
    .authenticator(Arc::new(auth))
    .build()
    .unwrap()
}

// PKCE pair from RFC 7636 Appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn authorize_params(client_id: &str) -> RawAuthorizeParams {
    RawAuthorizeParams {
        client_id: Some(client_id.into()),
        redirect_uri: Some("https://app.example/cb".into()),
        response_type: Some("code".into()),
        // Real clients request offline_access to receive a
        // refresh token; the provider gates refresh issuance on this scope.
        scope: Some("openid profile offline_access".into()),
        state: Some("xyz".into()),
        nonce: Some("n-123".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    }
}

/// Pull `code` out of a success redirect URL.
fn code_from(url: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn public_client_happy_path() {
    let p = provider(Auth::Ok("user_alice"));
    let out = p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap();
    let url = match out {
        AuthorizeOutcome::Redirect(u) => u,
        other => panic!("expected redirect, got {other:?}"),
    };
    assert!(url.starts_with("https://app.example/cb?code="));
    assert!(url.contains("state=xyz"));
    let code = code_from(&url);

    let tokens = p
        .exchange_authorization_code("pub", None, &code, "https://app.example/cb", Some(VERIFIER))
        .await
        .unwrap();
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(tokens.expires_in, 3600);
    assert!(tokens.refresh_token.is_some());
    assert_eq!(tokens.scope, "openid profile offline_access");

    // id_token is a 3-part JWT carrying our claims.
    let idt = tokens.id_token.unwrap();
    let parts: Vec<&str> = idt.split('.').collect();
    assert_eq!(parts.len(), 3);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body: serde_json::Value = serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(body["iss"], "https://idp.example");
    assert_eq!(body["sub"], "user_alice");
    assert_eq!(body["aud"], serde_json::json!(["pub"])); // array, matching the Go provider
    assert_eq!(body["azp"], "pub");
    assert_eq!(body["auth_time"], 1_700_000_000);
    assert_eq!(body["nonce"], "n-123");
    assert!(body["at_hash"].is_string());

    // An RP would verify the id_token's EdDSA signature against the
    // provider's published JWKS — selecting the key by the header `kid`. This
    // exercises the full sign-then-publish-then-verify path end to end.
    let jwks = p.jwks().await.unwrap();
    assert!(
        verify_jwt_against_jwks(&idt, &jwks),
        "id_token must verify against the published JWKS"
    );

    // at_hash must actually bind to the issued access token (OIDC §3.1.3.6).
    assert_eq!(
        body["at_hash"].as_str().unwrap(),
        codewire_oidc::token::at_hash(&tokens.access_token)
    );
}

/// Verify a compact JWT's EdDSA signature against a JWKS, selecting the key by
/// the JWT header `kid` — i.e. what a relying party does with our id_token.
fn verify_jwt_against_jwks(jwt: &str, jwks: &codewire_oidc::Jwks) -> bool {
    use base64::Engine;
    use ed25519_dalek::{Verifier, VerifyingKey};
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    let kid = header["kid"].as_str().unwrap();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .expect("header kid must be in the JWKS");
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    let pk: [u8; 32] = b64.decode(&jwk.x).unwrap().as_slice().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let sig: [u8; 64] = b64.decode(parts[2]).unwrap().as_slice().try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .is_ok()
}

#[tokio::test]
async fn prompt_none_without_session_is_login_required() {
    // prompt=none must not bounce to login; it errors with login_required.
    let p = provider(Auth::NeedsLogin("https://idp.example/login"));
    let params = RawAuthorizeParams {
        prompt: Some("none".into()),
        ..authorize_params("pub")
    };
    match p
        .authorize(&RequestContext::default(), params)
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => {
            assert!(u.contains("error=login_required"), "got {u}");
            assert!(u.contains("state=xyz"));
        }
        o => panic!("expected login_required error redirect, got {o:?}"),
    }
}

#[tokio::test]
async fn confidential_client_requires_secret() {
    let p = provider(Auth::Ok("user_bob"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("conf"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);

    // Wrong secret → invalid_client.
    let err = p
        .exchange_authorization_code(
            "conf",
            Some("wrong"),
            &code,
            "https://app.example/cb",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidClient);

    // The code was consumed even though client auth failed? No — client auth
    // happens before code consumption, so the code is still valid with the
    // right secret.
    let tokens = p
        .exchange_authorization_code(
            "conf",
            Some("s3cr3t"),
            &code,
            "https://app.example/cb",
            Some(VERIFIER),
        )
        .await
        .unwrap();
    assert!(tokens.id_token.is_some());
}

#[tokio::test]
async fn wrong_pkce_verifier_rejected() {
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    let err = p
        .exchange_authorization_code(
            "pub",
            None,
            &code,
            "https://app.example/cb",
            Some("not-the-verifier"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn code_is_single_use() {
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    assert!(
        p.exchange_authorization_code("pub", None, &code, "https://app.example/cb", Some(VERIFIER))
            .await
            .is_ok()
    );
    // Replayed code → invalid_grant.
    let err = p
        .exchange_authorization_code("pub", None, &code, "https://app.example/cb", Some(VERIFIER))
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn redirect_uri_mismatch_at_exchange_rejected() {
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    let err = p
        .exchange_authorization_code(
            "pub",
            None,
            &code,
            "https://evil.example/cb",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn unregistered_redirect_uri_is_not_reflected() {
    let p = provider(Auth::Ok("u"));
    let params = RawAuthorizeParams {
        redirect_uri: Some("https://evil.example/cb".into()),
        ..authorize_params("pub")
    };
    // Must NOT redirect (threat T1): a Fail is returned instead.
    match p
        .authorize(&RequestContext::default(), params)
        .await
        .unwrap()
    {
        AuthorizeOutcome::Fail(e) => assert_eq!(e.code, codewire_oidc::ErrorCode::InvalidRequest),
        o => panic!("expected Fail, got {o:?}"),
    }
}

#[tokio::test]
async fn missing_pkce_is_error_redirect() {
    let p = provider(Auth::Ok("u"));
    let params = RawAuthorizeParams {
        code_challenge: None,
        ..authorize_params("pub")
    };
    match p
        .authorize(&RequestContext::default(), params)
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => {
            assert!(u.contains("error=invalid_request"));
            assert!(u.contains("state=xyz"));
        }
        o => panic!("expected error redirect, got {o:?}"),
    }
}

#[tokio::test]
async fn non_openid_scope_rejected() {
    let p = provider(Auth::Ok("u"));
    let params = RawAuthorizeParams {
        scope: Some("profile".into()),
        ..authorize_params("pub")
    };
    match p
        .authorize(&RequestContext::default(), params)
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => assert!(u.contains("error=invalid_scope")),
        o => panic!("{o:?}"),
    }
}

/// Run the happy path and return (provider, token response).
async fn issue_via_code(p: &Provider) -> codewire_oidc::TokenResponse {
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    p.exchange_authorization_code("pub", None, &code, "https://app.example/cb", Some(VERIFIER))
        .await
        .unwrap()
}

#[tokio::test]
async fn refresh_token_rotates_and_old_one_is_dead() {
    let p = provider(Auth::Ok("user_alice"));
    let first = issue_via_code(&p).await;
    let rt1 = first.refresh_token.clone().unwrap();

    let second = p
        .exchange_refresh_token("pub", None, &rt1, None)
        .await
        .unwrap();
    let rt2 = second.refresh_token.clone().unwrap();
    assert_ne!(rt1, rt2, "refresh token must rotate");
    assert_ne!(first.access_token, second.access_token);
    assert!(second.id_token.is_some());
    assert_eq!(second.scope, "openid profile offline_access");

    // The rotated-away token is dead.
    let err = p
        .exchange_refresh_token("pub", None, &rt1, None)
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidGrant);
    // The new one still works.
    assert!(
        p.exchange_refresh_token("pub", None, &rt2, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn refresh_scope_can_narrow_but_not_widen() {
    let p = provider(Auth::Ok("u"));
    let rt = issue_via_code(&p).await.refresh_token.unwrap();
    // Narrow to a subset (keeping offline_access so a new refresh token is
    // still issued) → ok.
    let narrowed = p
        .exchange_refresh_token("pub", None, &rt, Some("openid offline_access"))
        .await
        .unwrap();
    assert_eq!(narrowed.scope, "openid offline_access");
    // Widen beyond the original grant → invalid_scope.
    let rt2 = narrowed.refresh_token.unwrap();
    let err = p
        .exchange_refresh_token("pub", None, &rt2, Some("openid profile email"))
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidScope);
}

#[tokio::test]
async fn no_refresh_token_without_offline_access() {
    // A client that *supports* the refresh grant still must not receive a
    // refresh token unless the request asked for offline_access.
    let p = provider(Auth::Ok("u"));
    let params = RawAuthorizeParams {
        scope: Some("openid profile".into()),
        ..authorize_params("pub")
    };
    let url = match p
        .authorize(&RequestContext::default(), params)
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    let tokens = p
        .exchange_authorization_code("pub", None, &code, "https://app.example/cb", Some(VERIFIER))
        .await
        .unwrap();
    assert!(
        tokens.refresh_token.is_none(),
        "no offline_access → no refresh token"
    );
    assert!(tokens.id_token.is_some()); // openid still yields an id_token
    assert_eq!(tokens.scope, "openid profile");
}

#[tokio::test]
async fn userinfo_resolves_access_token() {
    let p = provider(Auth::Ok("user_carol"));
    let tokens = issue_via_code(&p).await;
    let claims = p.userinfo(&tokens.access_token).await.unwrap();
    assert_eq!(claims.sub, "user_carol");

    // Bad token → invalid_token.
    let err = p.userinfo("not-a-real-token").await.unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidToken);
}

#[tokio::test]
async fn userinfo_includes_custom_claims() {
    // A provider whose customizer injects org_* claims.
    struct OrgClaims;
    #[async_trait::async_trait]
    impl codewire_oidc::TokenCustomizer for OrgClaims {
        async fn extra_claims(
            &self,
            _s: &Subject,
            _sc: &Scopes,
            _c: &Client,
        ) -> StoreResult<std::collections::BTreeMap<String, serde_json::Value>> {
            let mut m = std::collections::BTreeMap::new();
            m.insert("org_id".into(), serde_json::json!("org_42"));
            m.insert("email".into(), serde_json::json!("c@example.com"));
            Ok(m)
        }
    }

    let mem = Mem::default();
    let clients = Clients {
        public: client("pub", AuthMethod::None, ApplicationType::UserAgent),
        confidential: client("conf", AuthMethod::ClientSecretBasic, ApplicationType::Web),
        code_only: {
            let mut c = client("codeonly", AuthMethod::None, ApplicationType::UserAgent);
            c.grant_types = vec![GrantType::AuthorizationCode];
            c.refresh_token_lifetime_secs = None;
            c
        },
        confidential_secret: "s3cr3t".into(),
    };
    let p = Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
    })
    .auth_requests(Arc::new(mem.clone()))
    .tokens(Arc::new(mem))
    .clients(Arc::new(clients))
    .keys(Arc::new(Keys(signing_key())))
    .authenticator(Arc::new(Auth::Ok("user_dave")))
    .customizer(Arc::new(OrgClaims))
    .build()
    .unwrap();

    let tokens = issue_via_code(&p).await;
    let claims = p.userinfo(&tokens.access_token).await.unwrap();
    let v = serde_json::to_value(&claims).unwrap();
    assert_eq!(v["sub"], "user_dave");
    assert_eq!(v["org_id"], "org_42");
    assert_eq!(v["email"], "c@example.com");

    // The id_token carries the same custom claims.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body: serde_json::Value = serde_json::from_slice(
        &b64.decode(tokens.id_token.unwrap().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["org_id"], "org_42");
}

#[tokio::test]
async fn needs_login_and_denied_outcomes() {
    let p = provider(Auth::NeedsLogin("https://idp.example/login"));
    match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::RedirectToLogin(u) => assert_eq!(u, "https://idp.example/login"),
        o => panic!("{o:?}"),
    }

    let p = provider(Auth::Denied("not a member"));
    match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => assert!(u.contains("error=access_denied")),
        o => panic!("{o:?}"),
    }
}

// ----------------------------------------------------------------------------
// Negative cases mined from the zitadel op test suite (token_request_test.go,
// token_code.go, token_refresh.go) — behaviors the library already enforces.
// ----------------------------------------------------------------------------

#[tokio::test]
async fn public_client_must_not_present_a_secret() {
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    // Public client ("pub" = AuthMethod::None) presenting a secret → invalid_client.
    let err = p
        .exchange_authorization_code(
            "pub",
            Some("unexpected"),
            &code,
            "https://app.example/cb",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidClient);
}

#[tokio::test]
async fn confidential_client_without_secret_is_rejected() {
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("conf"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    let err = p
        .exchange_authorization_code(
            "conf",
            None,
            &code,
            "https://app.example/cb",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidClient);
}

#[tokio::test]
async fn code_exchange_without_verifier_is_rejected() {
    // A code is always issued with a PKCE challenge; exchanging it with no
    // code_verifier at all must fail (not just a wrong verifier).
    let p = provider(Auth::Ok("u"));
    let url = match p
        .authorize(&RequestContext::default(), authorize_params("pub"))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect(u) => u,
        o => panic!("{o:?}"),
    };
    let code = code_from(&url);
    let err = p
        .exchange_authorization_code("pub", None, &code, "https://app.example/cb", None)
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn refresh_grant_rejected_for_client_without_the_grant() {
    // `codeonly` supports only authorization_code; a refresh attempt is
    // unauthorized_client (checked before the token is even looked up).
    let p = provider(Auth::Ok("u"));
    let err = p
        .exchange_refresh_token("codeonly", None, "any-token", None)
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::UnauthorizedClient);
}

#[tokio::test]
async fn refresh_issued_id_token_omits_nonce_and_auth_time() {
    // OIDC §12.2: the id_token from a refresh carries no nonce, and we do not
    // re-assert auth_time.
    let p = provider(Auth::Ok("user_alice"));
    let rt = issue_via_code(&p).await.refresh_token.unwrap();
    let refreshed = p
        .exchange_refresh_token("pub", None, &rt, None)
        .await
        .unwrap();

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let idt = refreshed.id_token.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&b64.decode(idt.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(body["sub"], "user_alice");
    assert!(
        body.get("nonce").is_none(),
        "refresh id_token must omit nonce"
    );
    assert!(
        body.get("auth_time").is_none(),
        "refresh id_token must omit auth_time"
    );
    // at_hash still binds to the new access token.
    assert_eq!(
        body["at_hash"].as_str().unwrap(),
        codewire_oidc::token::at_hash(&refreshed.access_token)
    );
}

#[tokio::test]
async fn id_token_validity_window_includes_clock_skew() {
    // The test client has clock_skew_secs = 60 and id_token_lifetime = 3600.
    // The id_token's window must be widened by skew on both ends:
    // exp - iat == lifetime + 2*skew, independent of wall-clock time.
    let p = provider(Auth::Ok("u"));
    let idt = issue_via_code(&p).await.id_token.unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body: serde_json::Value =
        serde_json::from_slice(&b64.decode(idt.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let iat = body["iat"].as_i64().unwrap();
    let exp = body["exp"].as_i64().unwrap();
    assert_eq!(
        exp - iat,
        3600 + 2 * 60,
        "exp-iat must be lifetime + 2*clock_skew"
    );
}

// ----------------------------------------------------------------------------
// RP-initiated logout (end_session)
// ----------------------------------------------------------------------------

/// Issue tokens via the code flow and return the id_token (for use as a hint).
async fn issue_id_token(p: &Provider) -> String {
    issue_via_code(p).await.id_token.unwrap()
}

#[tokio::test]
async fn end_session_redirects_to_registered_uri_with_state() {
    let p = provider(Auth::Ok("user_alice"));
    let hint = issue_id_token(&p).await;
    let out = p
        .end_session(RawEndSessionParams {
            id_token_hint: Some(hint),
            post_logout_redirect_uri: Some("https://app.example/logged-out".into()),
            state: Some("bye-123".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::Redirect { url, subject } => {
            assert!(
                url.starts_with("https://app.example/logged-out?state=bye-123"),
                "got {url}"
            );
            assert_eq!(subject, Some(Subject("user_alice".into())));
        }
        o => panic!("expected redirect, got {o:?}"),
    }
}

#[tokio::test]
async fn end_session_without_redirect_is_logged_out() {
    let p = provider(Auth::Ok("user_bob"));
    let hint = issue_id_token(&p).await;
    let out = p
        .end_session(RawEndSessionParams {
            id_token_hint: Some(hint),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::LoggedOut { subject } => {
            assert_eq!(subject, Some(Subject("user_bob".into())));
        }
        o => panic!("expected logged-out, got {o:?}"),
    }
}

#[tokio::test]
async fn end_session_rejects_unregistered_post_logout_uri() {
    let p = provider(Auth::Ok("u"));
    let hint = issue_id_token(&p).await;
    let out = p
        .end_session(RawEndSessionParams {
            id_token_hint: Some(hint),
            post_logout_redirect_uri: Some("https://evil.example/x".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::Fail(e) => assert_eq!(e.code, codewire_oidc::ErrorCode::InvalidRequest),
        o => panic!("expected Fail, got {o:?}"),
    }
}

#[tokio::test]
async fn end_session_rejects_forged_id_token_hint() {
    let p = provider(Auth::Ok("u"));
    // A syntactically-plausible but unsigned/garbage JWT.
    let out = p
        .end_session(RawEndSessionParams {
            id_token_hint: Some("aaa.bbb.ccc".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::Fail(e) => assert_eq!(e.code, codewire_oidc::ErrorCode::InvalidRequest),
        o => panic!("expected Fail, got {o:?}"),
    }
}

#[tokio::test]
async fn end_session_post_logout_requires_client() {
    // No id_token_hint and no client_id, but a post_logout_redirect_uri →
    // cannot validate it against any client.
    let p = provider(Auth::Ok("u"));
    let out = p
        .end_session(RawEndSessionParams {
            post_logout_redirect_uri: Some("https://app.example/logged-out".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::Fail(e) => assert_eq!(e.code, codewire_oidc::ErrorCode::InvalidRequest),
        o => panic!("expected Fail, got {o:?}"),
    }
}

#[tokio::test]
async fn end_session_client_id_must_match_hint() {
    let p = provider(Auth::Ok("u"));
    let hint = issue_id_token(&p).await; // audience = "pub"
    let out = p
        .end_session(RawEndSessionParams {
            id_token_hint: Some(hint),
            client_id: Some("conf".into()),
            post_logout_redirect_uri: Some("https://app.example/logged-out".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    match out {
        EndSessionOutcome::Fail(e) => assert_eq!(e.code, codewire_oidc::ErrorCode::InvalidRequest),
        o => panic!("expected Fail, got {o:?}"),
    }
}

// ----------------------------------------------------------------------------
// Token introspection (RFC 7662) and revocation (RFC 7009)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn introspect_active_access_token() {
    let p = provider(Auth::Ok("user_x"));
    let tokens = issue_via_code(&p).await;
    let r = p
        .introspect("pub", None, &tokens.access_token, None)
        .await
        .unwrap();
    assert!(r.active);
    assert_eq!(r.sub.as_deref(), Some("user_x"));
    assert_eq!(r.client_id.as_deref(), Some("pub"));
    assert_eq!(r.token_type.as_deref(), Some("Bearer"));
    assert_eq!(r.scope.as_deref(), Some("openid profile offline_access"));
    assert_eq!(r.iss.as_deref(), Some("https://idp.example"));
}

#[tokio::test]
async fn introspect_refresh_token_with_hint() {
    let p = provider(Auth::Ok("user_x"));
    let rt = issue_via_code(&p).await.refresh_token.unwrap();
    let r = p
        .introspect("pub", None, &rt, Some("refresh_token"))
        .await
        .unwrap();
    assert!(r.active);
    assert_eq!(r.token_type.as_deref(), Some("refresh_token"));
}

#[tokio::test]
async fn introspect_unknown_token_is_inactive() {
    let p = provider(Auth::Ok("u"));
    let r = p.introspect("pub", None, "nope", None).await.unwrap();
    assert!(!r.active);
    assert!(r.sub.is_none());
}

#[tokio::test]
async fn introspect_other_clients_token_is_inactive() {
    // Token issued to "pub"; "conf" must not see it as active.
    let p = provider(Auth::Ok("u"));
    let at = issue_via_code(&p).await.access_token;
    let r = p
        .introspect("conf", Some("s3cr3t"), &at, None)
        .await
        .unwrap();
    assert!(!r.active);
}

#[tokio::test]
async fn introspect_requires_client_auth() {
    let p = provider(Auth::Ok("u"));
    let at = issue_via_code(&p).await.access_token;
    let err = p
        .introspect("conf", Some("wrong"), &at, None)
        .await
        .unwrap_err();
    assert_eq!(err.code, codewire_oidc::ErrorCode::InvalidClient);
}

#[tokio::test]
async fn revoke_then_introspect_is_inactive() {
    let p = provider(Auth::Ok("u"));
    let tokens = issue_via_code(&p).await;
    let at = tokens.access_token.clone();
    p.revoke("pub", None, &at, None).await.unwrap();
    assert!(!p.introspect("pub", None, &at, None).await.unwrap().active);
    // userinfo now rejects it too.
    assert_eq!(
        p.userinfo(&at).await.unwrap_err().code,
        codewire_oidc::ErrorCode::InvalidToken
    );
}

#[tokio::test]
async fn revoke_other_clients_token_is_a_noop() {
    let p = provider(Auth::Ok("u"));
    let at = issue_via_code(&p).await.access_token;
    // "conf" tries to revoke "pub"'s token → no-op success, token still active.
    p.revoke("conf", Some("s3cr3t"), &at, None).await.unwrap();
    assert!(p.introspect("pub", None, &at, None).await.unwrap().active);
}

#[tokio::test]
async fn revoke_unknown_token_succeeds() {
    let p = provider(Auth::Ok("u"));
    assert!(p.revoke("pub", None, "nope", None).await.is_ok());
}
