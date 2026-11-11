//! Connect auth-layer acceptance matrix (doc 03 WI-2/WI-3).
//!
//! Mounts the shared D8 probe service
//! ([`codewire_server_core::connect_testing`] — the exact wiring the
//! orchestration and billing binaries mount behind
//! `CONNECT_TESTING_SURFACE=1`) behind the full [`AppBuilder`] stack and
//! drives every credential row against a real Postgres:
//!
//! - session cookie, `cw_` API key, and product-scoped flavor-2 opaque OIDC
//!   bearer (the 15 WI-1/WI-1a `oidc_access_tokens` lookup) authenticate;
//!   raw session-token bearers reject and an identity-only OIDC bearer receives
//!   `permission_denied`,
//! - absent / invalid / expired credentials reject with the exact
//!   `unauthenticated` JSON wire shape (canonical code +
//!   `google.rpc.ErrorInfo` with reason/hint/request_id, doc 01 D2/D4),
//! - a non-admin caller on an admin-gated method (and on a whole-service
//!   admin mount) rejects with the exact `permission_denied` wire shape,
//! - the D3 public allowlist bypasses authentication,
//! - the probe's empty-message `Ping` renders `invalid_argument` with a
//!   `google.rpc.BadRequest` field violation — 01's renderer end to end
//!   through a real mount (D8),
//! - the D7 per-RPC log event carries the correct credential kind per row,
//! - credentialed Connect GET responses carry `Cache-Control: private`
//!   (D6b cache posture).
//!
//! Skipped unless `DATABASE_URL` is set (same convention as the idp
//! `db_flow` suite); the migration-integration gate runs it against a
//! Postgres initialized through the standard SQLx entrypoint and fails on
//! skip.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine;
use codewire_proto::codewire::testing::v1::{PingRequest, PingServiceClient};
use codewire_server_core::AppBuilder;
use codewire_server_core::auth::{
    AuthState, api_key_prefix, generate_api_key, hash_api_key, hash_oauth_token, hash_session_token,
};
use codewire_server_core::connect::{ConnectAuthLayer, ProtocolPolicy};
use codewire_server_core::connect_testing::{self, ProbePingService};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{ErrorCode, Protocol};
use http::header::AUTHORIZATION;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

const SERVICE: &str = "codewire.testing.v1.PingService";

// --- log capture (same pattern as the WI-1 connect_mount tests) -------------

static LOG_BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_log_capture() -> Arc<Mutex<Vec<u8>>> {
    LOG_BUFFER
        .get_or_init(|| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let writer_buffer = Arc::clone(&buffer);
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || SharedWriter(Arc::clone(&writer_buffer)))
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            buffer
        })
        .clone()
}

/// Asserts some captured `connect_rpc` log line contains every fragment.
fn assert_log_line(fragments: &[&str]) {
    let logs = String::from_utf8_lossy(&init_log_capture().lock().unwrap()).into_owned();
    let found = logs
        .lines()
        .filter(|line| line.contains("connect_rpc"))
        .any(|line| fragments.iter().all(|fragment| line.contains(fragment)));
    assert!(
        found,
        "no connect_rpc log line contains {fragments:?}; captured connect_rpc lines:\n{}",
        logs.lines()
            .filter(|line| line.contains("connect_rpc"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn find_log_line(fragments: &[&str]) -> String {
    let logs = String::from_utf8_lossy(&init_log_capture().lock().unwrap()).into_owned();
    logs.lines()
        .filter(|line| line.contains("connect_rpc"))
        .find(|line| fragments.iter().all(|fragment| line.contains(fragment)))
        .unwrap_or_else(|| panic!("no connect_rpc log line contains {fragments:?}"))
        .to_owned()
}

fn principal_fingerprint(user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"codewire.connect_rpc.principal.v1\0");
    hasher.update(user_id.as_bytes());
    hasher.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// --- seeding -----------------------------------------------------------------

/// Credentials seeded for one test's ID namespace (`ns` keeps parallel test
/// fns from racing each other's rows).
struct Seeded {
    user_id: String,
    admin_user_id: String,
    session_token: String,
    admin_session_token: String,
    api_key: String,
    admin_api_key: String,
    oidc_token: String,
    identity_oidc_token: String,
    expired_oidc_token: String,
}

async fn seed(pool: &PgPool, ns: &str) -> Seeded {
    let user_id = format!("u_cwi2_{ns}");
    let admin_user_id = format!("u_cwi2_{ns}_admin");
    let org_id = format!("org_cwi2_{ns}");
    let client_id = format!("cwi2-{ns}-client");

    // Fresh start for this namespace (reruns against a dirty DB).
    for sql in [
        "DELETE FROM oidc_access_tokens WHERE user_id = $1",
        "DELETE FROM api_keys WHERE user_id = $1",
        "DELETE FROM sessions WHERE user_id = $1",
    ] {
        for uid in [&user_id, &admin_user_id] {
            let _ = sqlx::query(sql).bind(uid).execute(pool).await;
        }
    }
    let _ = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(&client_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM environments WHERE org_id = $1")
        .bind(&org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM environment_presets WHERE org_id = $1")
        .bind(&org_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&org_id)
        .execute(pool)
        .await;
    for uid in [&user_id, &admin_user_id] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(uid)
            .execute(pool)
            .await;
    }

    for (uid, email, is_admin) in [
        (&user_id, format!("{ns}-user@example.com"), false),
        (&admin_user_id, format!("{ns}-admin@example.com"), true),
    ] {
        sqlx::query(
            "INSERT INTO users (id, email, name, email_verified, is_admin) \
             VALUES ($1, $2, $3, true, $4)",
        )
        .bind(uid)
        .bind(email)
        .bind(format!("Connect WI2 {ns}"))
        .bind(is_admin)
        .execute(pool)
        .await
        .unwrap();
    }

    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)")
        .bind(&org_id)
        .bind(format!("Connect WI2 {ns}"))
        .bind(format!("cwi2-{ns}"))
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();

    // An API key acts only for a current member of its organization (#3254).
    for (uid, role) in [(&user_id, "owner"), (&admin_user_id, "member")] {
        sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $1, $3)")
            .bind(uid)
            .bind(&org_id)
            .bind(role)
            .execute(pool)
            .await
            .unwrap();
    }

    let session_token = format!("sess_cwi2_{ns}");
    let admin_session_token = format!("sess_cwi2_{ns}_admin");
    for (sid, uid, token) in [
        (format!("s_cwi2_{ns}"), &user_id, &session_token),
        (
            format!("s_cwi2_{ns}_admin"),
            &admin_user_id,
            &admin_session_token,
        ),
    ] {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
             VALUES ($1, $2, $3, NOW() + interval '1 hour')",
        )
        .bind(sid)
        .bind(uid)
        .bind(hash_session_token(token))
        .execute(pool)
        .await
        .unwrap();
    }

    let api_key = generate_api_key();
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(format!("ak_cwi2_{ns}"))
    .bind(&user_id)
    .bind(&org_id)
    .bind(format!("connect-wi2-{ns}"))
    .bind(hash_api_key(&api_key))
    .bind(api_key_prefix(&api_key))
    .execute(pool)
    .await
    .unwrap();

    let admin_api_key = generate_api_key();
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(format!("ak_cwi2_{ns}_admin"))
    .bind(&admin_user_id)
    .bind(&org_id)
    .bind(format!("connect-wi2-{ns}-admin"))
    .bind(hash_api_key(&admin_api_key))
    .bind(api_key_prefix(&admin_api_key))
    .execute(pool)
    .await
    .unwrap();

    // Flavor-2 opaque access tokens, stored exactly the way the idp mints
    // them: SHA-256 digest at rest, fixed expiry, issued by a live client
    // (the idp `db_flow` suite pins that at-rest contract end to end from
    // the PKCE flow; this seeds the same rows for the layer's lookup).
    sqlx::query(
        "INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris) \
         VALUES ($1, $2, 'native', 'none', ARRAY['http://localhost:9878/callback'])",
    )
    .bind(&client_id)
    .bind(format!("Connect WI2 {ns}"))
    .execute(pool)
    .await
    .unwrap();

    let oidc_token = format!("at_cwi2_{ns}_{}", uuid_like());
    let identity_oidc_token = format!("at_cwi2_{ns}_identity_{}", uuid_like());
    let expired_oidc_token = format!("at_cwi2_{ns}_expired_{}", uuid_like());
    for (raw, scopes, interval) in [
        (
            &oidc_token,
            vec!["openid", "codewire.api"],
            "interval '1 hour'",
        ),
        (&identity_oidc_token, vec!["openid"], "interval '1 hour'"),
        (
            &expired_oidc_token,
            vec!["openid", "codewire.api"],
            "interval '-1 minute'",
        ),
    ] {
        sqlx::query(&format!(
            "INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, NOW() + {interval})"
        ))
        .bind(hash_oauth_token(raw))
        .bind(&client_id)
        .bind(&user_id)
        .bind(scopes)
        .execute(pool)
        .await
        .unwrap();
    }

    Seeded {
        user_id,
        admin_user_id,
        session_token,
        admin_session_token,
        api_key,
        admin_api_key,
        oidc_token,
        identity_oidc_token,
        expired_oidc_token,
    }
}

fn uuid_like() -> String {
    // Unique-enough suffix without another dev-dependency.
    format!("{:x}", std::process::id() as u64 ^ nanos())
}

fn nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
}

// --- harness -----------------------------------------------------------------

/// Starts the full stack with the shared probe mounted behind the given
/// auth layer.
async fn start_app(auth: ConnectAuthLayer) -> SocketAddr {
    start_app_with_protocol(auth, ProtocolPolicy::ConnectOnly).await
}

async fn start_app_with_protocol(
    auth: ConnectAuthLayer,
    protocol_policy: ProtocolPolicy,
) -> SocketAddr {
    init_log_capture();
    let connect = connectrpc::Router::new().add_service(Arc::new(ProbePingService));
    let app = AppBuilder::new("codewire-server-core-test")
        .with_health()
        .with_connect_routes_auth_and_protocol_policy(connect, auth, protocol_policy)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    addr
}

/// [`start_app`] with the exact production wiring
/// ([`connect_testing::router`]) — the same mount + auth layer the
/// orchestration and billing binaries get from
/// `AppBuilder::with_connect_testing_surface`.
async fn start_probe_app(pool: PgPool, synthetic_user_ids: &[String]) -> SocketAddr {
    init_log_capture();
    let (connect, layer) = connect_testing::router(AuthState { pool });
    let layer = layer.synthetic_user_ids(synthetic_user_ids.iter().cloned());
    let app = AppBuilder::new("codewire-server-core-test")
        .with_health()
        .with_connect_routes_auth(connect, layer)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    addr
}

fn ping_url(addr: SocketAddr, method: &str) -> String {
    format!("http://{addr}/{SERVICE}/{method}")
}

fn decode_error_info(detail: &serde_json::Value) -> codewire_proto::google::rpc::ErrorInfo {
    assert_eq!(detail["type"], "google.rpc.ErrorInfo");
    let b64 = detail["value"].as_str().expect("base64 value");
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
        .expect("base64 detail value");
    buffa::Message::decode_from_slice(&bytes).expect("protobuf ErrorInfo")
}

async fn post_ping(
    client: &reqwest::Client,
    url: &str,
    body: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
) -> reqwest::Response {
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_owned());
    if let Some(cookie) = cookie {
        req = req.header("cookie", format!("codewire.session_token={cookie}"));
    }
    if let Some(bearer) = bearer {
        req = req.header("authorization", format!("Bearer {bearer}"));
    }
    req.send().await.expect("request")
}

// --- tests ---------------------------------------------------------------------

#[tokio::test]
async fn authenticated_native_grpc_opt_in_preserves_connect_auth_and_errors() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping authenticated protocol-parity test");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let seeded = seed(&pool, "protocol-parity").await;
    let addr = start_app_with_protocol(
        ConnectAuthLayer::authenticated(AuthState { pool }),
        ProtocolPolicy::ConnectAndGrpc,
    )
    .await;

    for protocol in [Protocol::Connect, Protocol::Grpc] {
        let config = ClientConfig::new(format!("http://{addr}").parse().expect("base URI"))
            .with_protocol(protocol)
            .with_default_header(AUTHORIZATION, format!("Bearer {}", seeded.api_key));
        let client = PingServiceClient::new(HttpClient::plaintext_http2_only(), config);

        let response = client
            .ping(PingRequest {
                message: "whoami".into(),
                ..Default::default()
            })
            .await
            .expect("authenticated request");
        assert_eq!(response.view().message, seeded.user_id);

        let error = client
            .ping(PingRequest::default())
            .await
            .expect_err("empty message must reject");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message.as_deref(), Some("validation failed"));
        assert!(
            error.details.iter().any(|detail| {
                detail.type_url == "google.rpc.BadRequest"
                    || detail.type_url.ends_with("/google.rpc.BadRequest")
            }),
            "{protocol:?} invalid_argument lacks google.rpc.BadRequest"
        );

        let unauthenticated = PingServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{addr}").parse().expect("base URI"))
                .with_protocol(protocol),
        )
        .ping(PingRequest {
            message: "whoami".into(),
            ..Default::default()
        })
        .await
        .expect_err("missing credential must reject");
        assert_eq!(unauthenticated.code, ErrorCode::Unauthenticated);
        assert_eq!(unauthenticated.message.as_deref(), Some("unauthorized"));
        assert!(
            unauthenticated.details.iter().any(|detail| {
                detail.type_url == "google.rpc.ErrorInfo"
                    || detail.type_url.ends_with("/google.rpc.ErrorInfo")
            }),
            "{protocol:?} unauthenticated lacks google.rpc.ErrorInfo"
        );

        let label = match protocol {
            Protocol::Connect => "connect",
            Protocol::Grpc => "grpc",
            _ => unreachable!(),
        };
        assert_log_line(&[
            "method=Ping",
            &format!("protocol={label}"),
            "credential=api_key",
        ]);
    }
}

#[tokio::test]
async fn locked_api_key_usage_row_does_not_block_authentication() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping locked API-key usage test");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    let namespace = "locked-api-key-touch";
    let seeded = seed(&pool, namespace).await;
    let key_id = format!("ak_cwi2_{namespace}");

    let mut locker = pool.begin().await.expect("begin API-key row lock");
    let locked: String = sqlx::query_scalar("SELECT id FROM api_keys WHERE id = $1 FOR UPDATE")
        .bind(&key_id)
        .fetch_one(&mut *locker)
        .await
        .expect("lock API-key row");
    assert_eq!(locked, key_id);

    let addr = start_app(ConnectAuthLayer::authenticated(AuthState {
        pool: pool.clone(),
    }))
    .await;
    let started = std::time::Instant::now();
    let response = post_ping(
        &reqwest::Client::new(),
        &ping_url(addr, "Ping"),
        r#"{"message":"row-lock"}"#,
        None,
        Some(&seeded.api_key),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(response.status(), 200);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "best-effort usage touch blocked API-key authentication for {elapsed:?}"
    );

    // Keep the row locked beyond the background write budget. Authentication
    // remains successful even though this usage sample cannot be recorded.
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    locker.rollback().await.expect("release API-key row lock");
    let last_used: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = $1")
            .bind(&key_id)
            .fetch_one(&pool)
            .await
            .expect("read API-key usage timestamp");
    assert!(last_used.is_none());
}

/// The WI-2 acceptance matrix against the production probe wiring
/// ([`connect_testing::router`]): an `authenticated` mount with the probe's
/// public allowlist and admin-elevated method (D3/D8).
#[tokio::test]
async fn connect_auth_matrix() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping Connect auth matrix");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let seeded = seed(&pool, "matrix").await;

    let addr = start_probe_app(pool.clone(), std::slice::from_ref(&seeded.user_id)).await;
    let client = reqwest::Client::new();
    let user_fingerprint = principal_fingerprint(&seeded.user_id);
    let admin_fingerprint = principal_fingerprint(&seeded.admin_user_id);

    // Row 1 — allowlisted public method bypasses authentication.
    let resp = post_ping(&client, &ping_url(addr, "PublicPing"), "{}", None, None).await;
    assert_eq!(resp.status(), 200, "PublicPing must not require auth");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "public pong");
    assert_log_line(&["method=PublicPing", "code=ok", "credential=none"]);

    // Row 2 — session cookie authenticates; the handler-side extractor sees
    // the same user the credential resolved to.
    let resp = client
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .header(
            "cookie",
            format!("codewire.session_token={}", seeded.session_token),
        )
        .header("x-codewire-synthetic", "false")
        .header("x-codewire-principal-fingerprint", "forged-by-caller")
        .body(r#"{"message":"whoami"}"#)
        .send()
        .await
        .expect("session request");
    assert_eq!(resp.status(), 200, "session cookie must authenticate");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], seeded.user_id.as_str());
    assert_log_line(&[
        "method=Ping",
        "code=ok",
        "credential=session",
        &format!("principal_fingerprint={user_fingerprint}"),
        "synthetic=true",
    ]);
    let session_log = find_log_line(&[
        "method=Ping",
        "credential=session",
        &format!("principal_fingerprint={user_fingerprint}"),
    ]);
    for forbidden in [
        seeded.user_id.as_str(),
        "matrix-user@example.com",
        seeded.session_token.as_str(),
        seeded.api_key.as_str(),
        "forged-by-caller",
    ] {
        assert!(
            !session_log.contains(forbidden),
            "connect_rpc event leaked or trusted caller-controlled value"
        );
    }

    // Row 3 — `cw_` API key authenticates.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        Some(&seeded.api_key),
    )
    .await;
    assert_eq!(resp.status(), 200, "cw_ API key must authenticate");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], seeded.user_id.as_str());
    assert_log_line(&[
        "method=Ping",
        "code=ok",
        "credential=api_key",
        &format!("principal_fingerprint={user_fingerprint}"),
        "synthetic=true",
    ]);

    // Row 4 — a flavor-2 opaque OIDC access token with the explicit product
    // scope authenticates through the Connect layer.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        Some(&seeded.oidc_token),
    )
    .await;
    assert_eq!(resp.status(), 200, "OIDC access token must authenticate");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], seeded.user_id.as_str());
    assert_log_line(&[
        "method=Ping",
        "code=ok",
        "credential=oidc",
        &format!("principal_fingerprint={user_fingerprint}"),
        "synthetic=true",
    ]);

    // Row 4b — identity-only access remains a valid OIDC credential but is
    // not product authority. Connect renders authorization failure rather
    // than pretending the token is invalid, and telemetry retains the
    // validated credential/principal classification.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        Some(&seeded.identity_oidc_token),
    )
    .await;
    assert_eq!(resp.status(), 403, "identity-only OIDC must be denied");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "permission_denied");
    assert_eq!(
        body["message"],
        "OIDC access token lacks required codewire.api scope"
    );
    let details = body["details"].as_array().expect("details");
    assert_eq!(details.len(), 1);
    let info = decode_error_info(&details[0]);
    assert_eq!(info.reason, "INSUFFICIENT_SCOPE");
    assert_eq!(
        info.metadata.get("hint").map(String::as_str),
        Some("Request the codewire.api scope and re-authorize")
    );
    assert_log_line(&[
        "method=Ping",
        "code=permission_denied",
        "credential=oidc",
        &format!("principal_fingerprint={user_fingerprint}"),
    ]);

    // Row 5 — a raw session token in Authorization is not a product bearer.
    // The same token continues to work only as the browser session cookie
    // exercised in Row 2 and Row 5b.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        Some(&seeded.session_token),
    )
    .await;
    assert_eq!(resp.status(), 401, "raw session bearer must reject");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");
    assert_log_line(&["method=Ping", "code=unauthenticated", "credential=none"]);

    // Row 5b — authenticated Ping with an empty message: 01's renderer end
    // to end through a real handler (D8) — `invalid_argument` with a
    // `google.rpc.BadRequest` field violation on the dotted path.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":""}"#,
        Some(&seeded.session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "invalid_argument");
    assert_eq!(body["message"], "validation failed");
    let details = body["details"].as_array().expect("details");
    let bad = details
        .iter()
        .find(|d| d["type"] == "google.rpc.BadRequest")
        .expect("BadRequest detail");
    let decoded: codewire_proto::google::rpc::BadRequest = {
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(bad["value"].as_str().expect("base64 value"))
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD
                    .decode(bad["value"].as_str().expect("base64 value"))
            })
            .expect("base64 detail value");
        buffa::Message::decode_from_slice(&bytes).expect("protobuf BadRequest")
    };
    assert_eq!(decoded.field_violations.len(), 1);
    assert_eq!(decoded.field_violations[0].field, "message");
    assert_eq!(decoded.field_violations[0].description, "must not be empty");
    assert_log_line(&[
        "method=Ping",
        "code=invalid_argument",
        "http_status=400",
        "credential=session",
    ]);

    // Row 6 — absent credential: exact `unauthenticated` wire shape
    // (doc 01 D2/D4), request id mirrored into ErrorInfo.metadata.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"hi"}"#,
        None,
        None,
    )
    .await;
    assert_eq!(resp.status(), 401);
    let request_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id on rejection")
        .to_owned();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");
    assert_eq!(body["message"], "unauthorized");
    let details = body["details"].as_array().expect("details");
    assert_eq!(details.len(), 1);
    let info = decode_error_info(&details[0]);
    assert_eq!(info.reason, "SESSION_EXPIRED");
    assert_eq!(info.domain, "codewire.sh");
    assert_eq!(
        info.metadata.get("hint").map(String::as_str),
        Some("Run 'cw login' to re-authenticate")
    );
    assert_eq!(
        info.metadata.get("request_id").map(String::as_str),
        Some(request_id.as_str())
    );
    assert_log_line(&[
        "method=Ping",
        "code=unauthenticated",
        "http_status=401",
        "credential=none",
    ]);

    // Row 7 — invalid cookie and invalid (non-`cw_`) bearer both fail.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"hi"}"#,
        Some("not-a-real-session"),
        Some("not-a-real-bearer"),
    )
    .await;
    assert_eq!(resp.status(), 401, "invalid credentials must reject");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");

    // Row 8 — expired OIDC access token fails.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"hi"}"#,
        None,
        Some(&seeded.expired_oidc_token),
    )
    .await;
    assert_eq!(resp.status(), 401, "expired OIDC token must reject");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");

    // Row 8b — auth runs BEFORE method dispatch (doc 03 D3 ordering
    // note): an unauthenticated request to an unknown method of a mounted
    // service is rejected `unauthenticated` — method existence is not
    // enumerable without a credential.
    let resp = post_ping(&client, &ping_url(addr, "NoSuchMethod"), "{}", None, None).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");

    // Row 8c — past the auth layer, an unknown method gets the
    // dispatcher's Connect-shaped `unimplemented`.
    let resp = post_ping(
        &client,
        &ping_url(addr, "NoSuchMethod"),
        "{}",
        Some(&seeded.session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unimplemented");

    // Row 9 — non-admin on the admin-gated method: exact
    // `permission_denied` wire shape; credential kind still reported.
    let resp = post_ping(
        &client,
        &ping_url(addr, "AdminPing"),
        "{}",
        Some(&seeded.session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "permission_denied");
    assert_eq!(body["message"], "forbidden");
    let details = body["details"].as_array().expect("details");
    assert_eq!(details.len(), 1);
    let info = decode_error_info(&details[0]);
    assert_eq!(info.reason, "FORBIDDEN");
    assert_eq!(info.domain, "codewire.sh");
    assert!(info.metadata.contains_key("request_id"));
    assert_log_line(&[
        "method=AdminPing",
        "code=permission_denied",
        "http_status=403",
        "credential=session",
        &format!("principal_fingerprint={user_fingerprint}"),
        "synthetic=true",
    ]);

    // Row 10 — admin user passes the admin-gated method.
    let resp = post_ping(
        &client,
        &ping_url(addr, "AdminPing"),
        "{}",
        Some(&seeded.admin_session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200, "admin must pass AdminPing");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "admin pong");
    assert_log_line(&[
        "method=AdminPing",
        "code=ok",
        "credential=session",
        &format!("principal_fingerprint={admin_fingerprint}"),
        "synthetic=false",
    ]);
    assert_ne!(user_fingerprint, admin_fingerprint);

    // Row 11 — credentialed Connect GET carries Cache-Control: private
    // (D6b cache posture).
    let get_url = format!(
        "{}?connect=v1&encoding=json&message=%7B%22message%22%3A%22via-get%22%7D",
        ping_url(addr, "Ping")
    );
    let resp = client
        .get(&get_url)
        .header(
            "cookie",
            format!("codewire.session_token={}", seeded.session_token),
        )
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("private"),
        "credentialed Connect GET must be Cache-Control: private"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "via-get");

    // Row 12 — an uncredentialed allowlisted GET gets no cache directive
    // from the layer (nothing credentialed to protect).
    let get_url = format!(
        "{}?connect=v1&encoding=json&message=%7B%7D",
        ping_url(addr, "PublicPing")
    );
    let resp = client.get(&get_url).send().await.expect("request");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("cache-control").is_none(),
        "public bypass adds no cache-control header"
    );
}

#[tokio::test]
async fn stalled_auth_lookup_is_bounded_before_unknown_method_dispatch() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping stalled Connect auth lookup test");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect single-connection auth pool");
    let seeded = seed(&pool, "stalled-auth").await;
    let held_connection = pool.acquire().await.expect("hold only auth connection");

    let layer = ConnectAuthLayer::authenticated(AuthState { pool: pool.clone() })
        .allow_public([format!("/{SERVICE}/PublicPing")]);
    let addr = start_app(layer).await;
    let client = reqwest::Client::new();

    // Public methods bypass credential resolution entirely, even while the
    // auth database pool is stalled.
    let resp = post_ping(&client, &ping_url(addr, "PublicPing"), "{}", None, None).await;
    assert_eq!(resp.status(), 200, "public method must bypass stalled auth");

    // Auth remains before dispatch. With the only DB connection held, a
    // credentialed request to an unknown method reaches the 10-second auth
    // bound and cannot enumerate the dispatcher's `unimplemented` result.
    let started = std::time::Instant::now();
    let resp = post_ping(
        &client,
        &ping_url(addr, "NoSuchMethod"),
        "{}",
        Some(&seeded.session_token),
        None,
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), 504);
    assert!(
        elapsed < std::time::Duration::from_secs(12),
        "stalled auth was not bounded at 10 seconds: {elapsed:?}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "deadline_exceeded");
    assert_eq!(body["message"], "authentication deadline exceeded");
    let details = body["details"].as_array().expect("details");
    let info = decode_error_info(&details[0]);
    assert_eq!(info.reason, "AUTHENTICATION_TIMEOUT");

    // A legitimate shorter Connect deadline also bounds authentication; the
    // 10-second policy is a ceiling, never an upward clamp.
    let started = std::time::Instant::now();
    let resp = client
        .post(ping_url(addr, "NoSuchMethod"))
        .header("content-type", "application/json")
        .header("connect-timeout-ms", "25")
        .header(
            "cookie",
            format!("codewire.session_token={}", seeded.session_token),
        )
        .body("{}")
        .send()
        .await
        .expect("short-deadline request");
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), 504);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "stalled auth did not honor the shorter Connect deadline: {elapsed:?}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "deadline_exceeded");
    let details = body["details"].as_array().expect("details");
    assert_eq!(
        decode_error_info(&details[0]).reason,
        "AUTHENTICATION_TIMEOUT"
    );

    drop(held_connection);

    // Once credential resolution can complete, the same authenticated
    // request reaches the dispatcher and gets its ordinary Connect-shaped
    // unknown-method result.
    let resp = post_ping(
        &client,
        &ping_url(addr, "NoSuchMethod"),
        "{}",
        Some(&seeded.session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unimplemented");
}

/// `allow_anonymous`: a method that needs no credential still uses one that
/// is presented, and refuses one that does not validate instead of treating
/// the caller as anonymous (`cw feedback`, #4061).
#[tokio::test]
async fn anonymous_methods_use_a_presented_credential_and_refuse_an_invalid_one() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping Connect anonymous-method test");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let seeded = seed(&pool, "anonymous").await;
    let layer = ConnectAuthLayer::authenticated(AuthState { pool: pool.clone() })
        .allow_anonymous([format!("/{SERVICE}/PublicPing"), format!("/{SERVICE}/Ping")]);
    let addr = start_app(layer).await;
    let client = reqwest::Client::new();

    // No credential: the request reaches the handler.
    let resp = post_ping(&client, &ping_url(addr, "PublicPing"), "{}", None, None).await;
    assert_eq!(resp.status(), 200, "no credential continues anonymously");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "public pong");

    // ...without an AuthUser: Ping's own extractor refuses it.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        None,
    )
    .await;
    assert_eq!(resp.status(), 401, "an anonymous handler sees no AuthUser");

    // A presented credential that does not validate is refused by the layer.
    for (cookie, bearer) in [
        (Some("not-a-session"), None),
        (None, Some("cw_not_a_key")),
        (None, Some("")),
    ] {
        let resp = post_ping(&client, &ping_url(addr, "PublicPing"), "{}", cookie, bearer).await;
        assert_eq!(
            resp.status(),
            401,
            "an invalid credential is refused, never anonymous: {cookie:?} {bearer:?}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "unauthenticated");
    }

    // A valid credential authenticates and reaches the handler as its user.
    for (cookie, bearer) in [
        (Some(seeded.session_token.as_str()), None),
        (None, Some(seeded.api_key.as_str())),
        (None, Some(seeded.oidc_token.as_str())),
    ] {
        let resp = post_ping(
            &client,
            &ping_url(addr, "Ping"),
            r#"{"message":"whoami"}"#,
            cookie,
            bearer,
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["message"], seeded.user_id.as_str());
    }

    // The allowance is per method: the rest of the mount still requires one.
    let resp = post_ping(&client, &ping_url(addr, "AdminPing"), "{}", None, None).await;
    assert_eq!(resp.status(), 401);
}

/// D3's whole-service `admin` mount: every method requires `is_admin`.
#[tokio::test]
async fn admin_mount_gates_whole_service() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping Connect admin-mount test");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let seeded = seed(&pool, "adminmount").await;

    let addr = start_app(ConnectAuthLayer::admin(AuthState { pool: pool.clone() })).await;
    let client = reqwest::Client::new();

    // Non-admin session: permission_denied on a plain method.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"hi"}"#,
        Some(&seeded.session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 403, "non-admin on admin mount must reject");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "permission_denied");

    // Admin session passes.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        Some(&seeded.admin_session_token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200, "admin on admin mount must pass");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], seeded.admin_user_id.as_str());

    // An org-scoped API key never inherits its owner's global-admin
    // authority, even when the owning user is an administrator.
    let resp = post_ping(
        &client,
        &ping_url(addr, "Ping"),
        r#"{"message":"whoami"}"#,
        None,
        Some(&seeded.admin_api_key),
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "admin-owned API key must stay org-scoped"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "permission_denied");

    // No credential: unauthenticated wins over permission_denied.
    let resp = post_ping(&client, &ping_url(addr, "Ping"), "{}", None, None).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthenticated");
}
