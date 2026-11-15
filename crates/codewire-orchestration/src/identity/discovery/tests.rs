use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{Method, Request};
use http_body_util::BodyExt as _;
use serde_json::json;
use tower::ServiceExt as _;

use super::*;
use crate::identity::keys::KeySetError;
use crate::identity::keys::tests::{key_read, key_set};

const ORG: &str = "0e3c5a1f9b2d4c6e8a0b1c2d3e4f5a6b";
const DELETING_ORG: &str = "7b1f00aa11bb22cc33dd44ee55ff6677";
const BASE: &str = "https://identity.example.test";

struct Orgs {
    active: HashSet<&'static str>,
    failing: bool,
    lookups: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl OrgDirectory for Orgs {
    async fn is_active(&self, org_id: &str) -> Result<bool, sqlx::Error> {
        self.lookups.lock().unwrap().push(org_id.to_owned());
        if self.failing {
            return Err(sqlx::Error::PoolTimedOut);
        }
        Ok(self.active.contains(org_id))
    }
}

struct Keys {
    reads: AtomicUsize,
    result: fn() -> Result<KeySet, TransitError>,
}

#[async_trait]
impl KeySource for Keys {
    async fn key_set(&self) -> Result<KeySet, TransitError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        (self.result)()
    }
}

fn two_versions() -> Result<KeySet, TransitError> {
    Ok(key_set(key_read(
        &[(1, "2026-11-01T00:00:00Z"), (2, "2026-11-02T00:00:00Z")],
        1,
        1,
    ))
    .unwrap())
}

fn unreadable() -> Result<KeySet, TransitError> {
    Err(TransitError::KeySet(KeySetError::Empty))
}

struct Fixture {
    app: Router,
    keys: Arc<Keys>,
    orgs: Arc<Orgs>,
}

fn fixture_with(failing_orgs: bool, keys: fn() -> Result<KeySet, TransitError>) -> Fixture {
    let keys = Arc::new(Keys {
        reads: AtomicUsize::new(0),
        result: keys,
    });
    let orgs = Arc::new(Orgs {
        // The deleting org is in the table but not active, so the directory
        // reports it inactive.
        active: HashSet::from([ORG]),
        failing: failing_orgs,
        lookups: std::sync::Mutex::default(),
    });
    let state = DiscoveryState::new(IssuerBase::parse(BASE).unwrap(), orgs.clone(), keys.clone());
    Fixture {
        app: router(state),
        keys,
        orgs,
    }
}

fn fixture() -> Fixture {
    fixture_with(false, two_versions)
}

struct Answer {
    status: StatusCode,
    cache_control: Option<String>,
    location: bool,
    body: Vec<u8>,
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let header = |name| {
        response
            .headers()
            .get(name)
            .map(|value: &HeaderValue| value.to_str().unwrap().to_owned())
    };
    let cache_control = header(header::CACHE_CONTROL);
    let location = response.headers().contains_key(header::LOCATION);
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Answer {
        status,
        cache_control,
        location,
        body,
    }
}

async fn get_path(app: &Router, path: &str) -> Answer {
    send(app, Request::get(path).body(Body::empty()).unwrap()).await
}

fn discovery_path(org: &str) -> String {
    format!("/orgs/{org}/.well-known/openid-configuration")
}

fn assert_refused(answer: &Answer, status: StatusCode, what: &str) {
    assert_eq!(answer.status, status, "{what}");
    assert_eq!(answer.cache_control.as_deref(), Some("no-store"), "{what}");
    assert!(!answer.location, "{what} never redirects");
}

#[tokio::test]
async fn discovery_names_the_orgs_own_issuer_built_from_configuration() {
    let Fixture { app, .. } = fixture();
    let answer = get_path(&app, &discovery_path(ORG)).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.cache_control.as_deref(), Some("public, max-age=300"));
    let issuer = format!("{BASE}/orgs/{ORG}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&answer.body).unwrap(),
        json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks.json"),
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"]
        })
    );
}

#[tokio::test]
async fn forged_host_and_forwarding_headers_change_no_byte() {
    let Fixture { app, .. } = fixture();
    for path in [discovery_path(ORG), format!("/orgs/{ORG}/jwks.json")] {
        let plain = get_path(&app, &path).await;
        let forged = send(
            &app,
            Request::get(path.as_str())
                .header(header::HOST, "attacker.example")
                .header("x-forwarded-host", "attacker.example")
                .header("x-forwarded-proto", "http")
                .header("x-forwarded-prefix", "/evil")
                .header(header::FORWARDED, "host=attacker.example;proto=http")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(forged.status, StatusCode::OK, "{path}");
        assert_eq!(forged.body, plain.body, "{path}");
        assert!(!String::from_utf8_lossy(&forged.body).contains("attacker"));
    }
}

#[tokio::test]
async fn only_an_existing_active_orgs_exact_id_is_served() {
    let Fixture { app, orgs, .. } = fixture();
    for (org, what) in [
        ("ffffffffffffffffffffffffffffffff", "an unknown org"),
        (DELETING_ORG, "an org being deleted"),
        (
            "0E3C5A1F9B2D4C6E8A0B1C2D3E4F5A6B",
            "an upper-case spelling of a real org",
        ),
        ("0e3c5a1f9b2d4c6e8a0b1c2d3e4f5a6B", "one upper-case letter"),
        ("x.y", "a dotted segment"),
    ] {
        for path in [discovery_path(org), format!("/orgs/{org}/jwks.json")] {
            let answer = get_path(&app, &path).await;
            assert_refused(&answer, StatusCode::NOT_FOUND, what);
            assert!(
                !String::from_utf8_lossy(&answer.body).contains(org),
                "{what} is not echoed"
            );
        }
    }
    // A non-canonical spelling never reaches the database.
    let looked_up = orgs.lookups.lock().unwrap().clone();
    assert!(
        looked_up
            .iter()
            .all(|id| id == "ffffffffffffffffffffffffffffffff" || id == DELETING_ORG),
        "{looked_up:?}"
    );
}

#[tokio::test]
async fn every_other_path_method_and_query_is_404_without_a_redirect() {
    let Fixture { app, keys, .. } = fixture();
    for path in [
        "/".to_owned(),
        "/healthz".to_owned(),
        "/metrics".to_owned(),
        "/.well-known/openid-configuration".to_owned(),
        "/jwks.json".to_owned(),
        format!("/orgs/{ORG}"),
        format!("/orgs/{ORG}/"),
        format!("/orgs/{ORG}/jwks.json/"),
        format!("/orgs/{ORG}/.well-known/openid-configuration/"),
        format!("/orgs/{ORG}/.well-known/oauth-authorization-server"),
        format!("//orgs/{ORG}/jwks.json"),
        format!("/orgs/{ORG}//jwks.json"),
        format!("/orgs/{ORG}/jwks.json?x=1"),
        format!("/orgs/{ORG}/jwks.json?"),
        format!("{}?issuer=https://attacker.example", discovery_path(ORG)),
        // A percent-encoded spelling of the real ID decodes to it, but is not
        // its canonical path.
        format!("/orgs/%30{}/jwks.json", &ORG[1..]),
        format!("/orgs/{ORG}/%6Awks.json"),
    ] {
        assert_refused(&get_path(&app, &path).await, StatusCode::NOT_FOUND, &path);
    }
    for method in [
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
        Method::PATCH,
    ] {
        let answer = send(
            &app,
            Request::builder()
                .method(method.clone())
                .uri(format!("/orgs/{ORG}/jwks.json"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_refused(&answer, StatusCode::NOT_FOUND, method.as_str());
    }
    assert_eq!(
        keys.reads.load(Ordering::SeqCst),
        0,
        "no refused request reads the key"
    );
}

#[tokio::test]
async fn the_jwks_publishes_every_listed_version_and_reuses_one_read() {
    let Fixture { app, keys, .. } = fixture();
    let path = format!("/orgs/{ORG}/jwks.json");
    let first = get_path(&app, &path).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.cache_control.as_deref(), Some("public, max-age=300"));
    let jwks: serde_json::Value = serde_json::from_slice(&first.body).unwrap();
    let kids: Vec<_> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["kid"].clone())
        .collect();
    assert_eq!(
        kids,
        [json!("sandbox-identity-1"), json!("sandbox-identity-2")]
    );
    for key in jwks["keys"].as_array().unwrap() {
        assert_eq!(
            (&key["kty"], &key["crv"], &key["alg"], &key["use"]),
            (
                &json!("EC"),
                &json!("P-256"),
                &json!("ES256"),
                &json!("sig")
            )
        );
        for location in ["jku", "x5u", "x5c", "d"] {
            assert!(key.get(location).is_none(), "{location}");
        }
    }
    let second = get_path(&app, &path).await;
    assert_eq!(second.body, first.body);
    assert_eq!(keys.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unreadable_key_set_is_503_and_never_an_empty_jwks() {
    let Fixture { app, keys, .. } = fixture_with(false, unreadable);
    let path = format!("/orgs/{ORG}/jwks.json");
    for _ in 0..2 {
        let answer = get_path(&app, &path).await;
        assert_refused(
            &answer,
            StatusCode::SERVICE_UNAVAILABLE,
            "unreadable key set",
        );
        assert!(!String::from_utf8_lossy(&answer.body).contains("keys"));
    }
    // A failure is never cached: each request reads again.
    assert_eq!(keys.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_failed_org_lookup_is_503_no_store() {
    let Fixture { app, .. } = fixture_with(true, two_versions);
    for path in [discovery_path(ORG), format!("/orgs/{ORG}/jwks.json")] {
        assert_refused(
            &get_path(&app, &path).await,
            StatusCode::SERVICE_UNAVAILABLE,
            &path,
        );
    }
}
