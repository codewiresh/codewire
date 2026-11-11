//! HTTP-level tests for the optional axum transport. Drives the router with
//! `tower::ServiceExt::oneshot` so requests exercise real parsing, status
//! codes, and headers.
#![cfg(feature = "axum")]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use codewire_oidc::jwks::{PublicJwk, SigningKey};
use codewire_oidc::{
    AccessGrant, ApplicationType, AuthCodeGrant, AuthMethod, AuthOutcome, AuthRequestId,
    AuthorizationStore, Client, ClientStore, GrantType, Issuer, KeyStore, Provider, ProviderConfig,
    RefreshGrant, RequestContext, ResponseType, Scopes, StoreResult, StoredAuthRequest, Subject,
    TokenStore, UserAuthenticator,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use http_body_util::BodyExt;
use tower::ServiceExt;

// Minimal in-memory backing (same shape as the unit tests, kept compact).
#[derive(Default, Clone)]
struct Mem(Arc<Mutex<Inner>>);
#[derive(Default)]
struct Inner {
    reqs: HashMap<String, StoredAuthRequest>,
    codes: HashMap<String, AuthCodeGrant>,
    access: HashMap<String, AccessGrant>,
    refresh: HashMap<String, RefreshGrant>,
    seq: u64,
}

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

struct OneClient(Client);
#[async_trait::async_trait]
impl ClientStore for OneClient {
    async fn get(&self, id: &str) -> StoreResult<Option<Client>> {
        Ok((id == self.0.id).then(|| self.0.clone()))
    }
    async fn verify_secret(&self, _id: &str, _s: &str) -> StoreResult<bool> {
        Ok(false)
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

struct Alice;
#[async_trait::async_trait]
impl UserAuthenticator for Alice {
    async fn authenticate(
        &self,
        _: &RequestContext,
        _: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome> {
        Ok(AuthOutcome::Authenticated {
            subject: Subject("alice".into()),
            auth_time: Some(1_700_000_000),
        })
    }
}

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn test_provider() -> Provider {
    let mem = Mem::default();
    let signer = Ed25519SigningKey::from_bytes(&[9u8; 32]);
    let key = SigningKey {
        kid: "k1".into(),
        secret_key: signer.to_bytes().to_vec(),
        public_key: signer.verifying_key().to_bytes().to_vec(),
    };
    let client = Client {
        id: "web-app".into(),
        name: "Web".into(),
        application_type: ApplicationType::UserAgent,
        auth_method: AuthMethod::None,
        redirect_uris: vec!["https://app.example/cb".into()],
        post_logout_redirect_uris: vec!["https://app.example/bye".into()],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        response_types: vec![ResponseType::Code],
        scopes: Scopes::parse("openid profile offline_access"),
        skip_consent: true,
        access_token_lifetime_secs: 3600,
        id_token_lifetime_secs: 3600,
        refresh_token_lifetime_secs: Some(2_592_000),
        clock_skew_secs: 0,
        disabled: false,
    };
    Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into(), "profile".into()],
    })
    .auth_requests(Arc::new(mem.clone()))
    .tokens(Arc::new(mem))
    .clients(Arc::new(OneClient(client)))
    .keys(Arc::new(Keys(key)))
    .authenticator(Arc::new(Alice))
    .build()
    .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn discovery_and_jwks_served() {
    let app = codewire_oidc::transport::router(test_provider());
    let resp = app
        .clone()
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["issuer"], "https://idp.example");
    assert_eq!(v["token_endpoint"], "https://idp.example/api/oauth/token");

    let resp = app
        .oneshot(
            Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["keys"][0]["kid"], "k1");
}

#[tokio::test]
async fn full_code_flow_over_http() {
    let app = codewire_oidc::transport::router(test_provider());

    // 1. Authorize → 302 with ?code=...
    let auth_uri = format!(
        "/api/oauth/authorize?client_id=web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
         &response_type=code&scope=openid%20offline_access&state=xyz\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(Request::get(&auth_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with("https://app.example/cb?code="));
    assert!(loc.contains("state=xyz"));
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();

    // 2. Token (public client + PKCE verifier) → 200 JSON + no-store.
    let form = format!(
        "grant_type=authorization_code&client_id=web-app&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier={VERIFIER}"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(resp.headers().get(header::PRAGMA).unwrap(), "no-cache");
    let v = body_json(resp).await;
    assert_eq!(v["token_type"], "Bearer");
    let access = v["access_token"].as_str().unwrap().to_string();
    assert!(v["id_token"].is_string());
    assert!(v["refresh_token"].is_string());

    // 3. UserInfo with the Bearer token → 200 with sub.
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/oauth/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["sub"], "alice");

    // 4. UserInfo without a token → 401 + WWW-Authenticate: Bearer.
    let resp = app
        .oneshot(
            Request::get("/api/oauth/userinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );
}

#[tokio::test]
async fn token_unsupported_grant_type_is_400() {
    let app = codewire_oidc::transport::router(test_provider());
    let resp = app
        .oneshot(
            Request::post("/api/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=password&client_id=web-app"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(body_json(resp).await["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn end_session_redirects_with_state() {
    let app = codewire_oidc::transport::router(test_provider());
    let uri = "/api/oauth/end_session?client_id=web-app\
               &post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fbye&state=s1";
    let resp = app
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with("https://app.example/bye?state=s1"),
        "got {loc}"
    );
}

/// Drive authorize→token over HTTP and return the access token.
async fn obtain_access_token(app: &axum::Router) -> String {
    let auth_uri = format!(
        "/api/oauth/authorize?client_id=web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
         &response_type=code&scope=openid%20offline_access&state=s\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(Request::get(&auth_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let form = format!(
        "grant_type=authorization_code&client_id=web-app&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier={VERIFIER}"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn introspect_and_revoke_over_http() {
    let app = codewire_oidc::transport::router(test_provider());
    let access = obtain_access_token(&app).await;

    // Introspect → active.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/oauth/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("client_id=web-app&token={access}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let v = body_json(resp).await;
    assert_eq!(v["active"], true);
    assert_eq!(v["sub"], "alice");

    // Revoke → 200.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/oauth/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("client_id=web-app&token={access}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Introspect again → inactive.
    let resp = app
        .oneshot(
            Request::post("/api/oauth/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("client_id=web-app&token={access}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["active"], false);
}
