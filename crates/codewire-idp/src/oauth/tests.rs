use super::*;

#[test]
fn return_targets_keep_only_same_origin_paths_and_bounded_request_ids() {
    let target = ReturnTarget::sanitized("request-id", "/device?user_code=ABCD-EFGH");
    assert_eq!(target.auth_request_id.as_deref(), Some("request-id"));
    assert_eq!(target.completion(), "/api/oidc/callback?id=request-id");

    let target = ReturnTarget::sanitized("", "/device?user_code=ABCD-EFGH");
    assert_eq!(target.completion(), "/device?user_code=ABCD-EFGH");

    for unsafe_path in [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example",
        "/x\nLocation: https://evil.example",
        "dashboard",
    ] {
        assert_eq!(safe_return_to(unsafe_path), None, "{unsafe_path:?}");
    }
    assert_eq!(clean_auth_request_id(&"a".repeat(257)), None);
    assert_eq!(clean_auth_request_id("a\u{7}"), None);
    assert_eq!(ReturnTarget::default().completion(), "/dashboard/");
}

#[test]
fn refusals_land_on_login_with_a_fixed_code_and_the_target() {
    let target = ReturnTarget::sanitized("request-id", "");
    let response = login_with_refusal(Refusal::LinkRequired, &target, Vec::new());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/login?oauth_error=link_required&authRequestID=request-id"
    );
}

#[test]
fn pkce_challenges_are_s256_of_the_verifier() {
    // RFC 7636 Appendix B.
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let verifier = pkce_verifier();
    assert_eq!(verifier.len(), 43);
    assert!(
        verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn oauth_cookies_are_http_only_lax_scoped_and_secure_on_https() {
    let value = cookie(STATE_COOKIE, "abc", STATE_COOKIE_PATH, 600, true);
    assert_eq!(
        value,
        "codewire_oauth_state=abc; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
    );
    let cleared = clear_cookie(STATE_COOKIE, STATE_COOKIE_PATH, false);
    assert_eq!(
        cleared,
        "codewire_oauth_state=; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

#[test]
fn a_cookie_sent_twice_is_not_trusted() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("codewire_oauth_state=one; other=x"),
    );
    assert_eq!(unique_cookie(&headers, STATE_COOKIE), Some("one"));
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("codewire_oauth_state=two"),
    );
    assert_eq!(unique_cookie(&headers, STATE_COOKIE), None);
}

// --- the sealed state cookie over HTTP, with no database ---

/// Fails every provider call, and counts them.
#[derive(Default)]
struct NoProvider {
    calls: std::sync::Mutex<u32>,
}

#[async_trait]
impl OAuthUpstream for NoProvider {
    async fn execute(&self, _: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        *self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        Err(UpstreamError)
    }
}

struct NoMail;

#[async_trait]
impl LinkConfirmationMailer for NoMail {
    fn is_available(&self) -> bool {
        false
    }

    async fn send(&self, _: &str, _: Provider, _: &str, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("no mail in these tests")
    }
}

const STATE_SECRET: &str = "synthetic-state-secret";

/// A router whose database is unreachable, so a request that touches it is
/// refused as `failed`: the paths these tests drive must not.
fn stateless_router(upstream: Arc<NoProvider>) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect_lazy("postgres://codewire@127.0.0.1:1/unreachable")
        .unwrap();
    router_with_state(OAuthState {
        session: SessionAuthState::trusted_test(
            pool,
            true,
            crate::auth_session::SignupInvitePolicy::open(),
            "https://app.codewire.test".into(),
        ),
        providers: OAuthProviders::with_upstream(
            Some(("github-client", "github-secret")),
            Some(("google-client", "google-secret")),
            upstream,
        ),
        mailer: Arc::new(NoMail),
        state_key: StateCookieKey::derive(STATE_SECRET).unwrap(),
    })
}

async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> Response {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::get(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("{STATE_COOKIE}={cookie}"));
    }
    app.clone()
        .oneshot(request.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap()
}

fn location(response: &Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

#[tokio::test]
async fn a_start_writes_nothing_and_seals_its_round_trip() {
    let app = stateless_router(Arc::default());
    let response = get(
        &app,
        "/api/auth/oauth/google/start?return_to=%2Fdevice&authRequestID=request-id",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let authorize = reqwest::Url::parse(location(&response)).unwrap();
    let query: std::collections::HashMap<_, _> = authorize.query_pairs().into_owned().collect();
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    let sealed = set_cookie
        .strip_prefix("codewire_oauth_state=")
        .and_then(|rest| rest.split_once(';'))
        .unwrap()
        .0;
    assert!(
        set_cookie
            .ends_with("; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure")
    );

    let key = StateCookieKey::derive(STATE_SECRET).unwrap();
    let now = chrono::Utc::now().timestamp();
    let opened = state_cookie::open(&key, Provider::Google, sealed, &query["state"], now).unwrap();
    assert_eq!(pkce_challenge(&opened.verifier), query["code_challenge"]);
    assert_eq!(opened.nonce.as_deref(), Some(query["nonce"].as_str()));
    assert_eq!(
        opened.target,
        ReturnTarget::sanitized("request-id", "/device")
    );
    // Ten minutes from now, and not more.
    assert!(state_cookie::open(&key, Provider::Google, sealed, &query["state"], now + 590).is_ok());
    assert!(
        state_cookie::open(&key, Provider::Google, sealed, &query["state"], now + 601).is_err()
    );
}

#[tokio::test]
async fn a_refused_state_cookie_never_reaches_the_provider() {
    let upstream = Arc::new(NoProvider::default());
    let app = stateless_router(upstream.clone());
    let key = StateCookieKey::derive(STATE_SECRET).unwrap();
    let now = chrono::Utc::now().timestamp();
    let sealed = |provider, target, expires_at| {
        let start = SignInStart::new(
            "raw-state",
            pkce_verifier(),
            (provider == Provider::Google).then(hex_token),
            target,
            expires_at,
        );
        state_cookie::seal(&key, provider, &start).unwrap()
    };
    let live = sealed(Provider::GitHub, ReturnTarget::default(), now + 600);
    let mut changed = URL_SAFE_NO_PAD.decode(&live).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    let mut other_version = URL_SAFE_NO_PAD.decode(&live).unwrap();
    other_version[0] = 2;
    // Sealed before the session secret rotated.
    let rotated = state_cookie::seal(
        &StateCookieKey::derive("the-previous-session-secret").unwrap(),
        Provider::GitHub,
        &SignInStart::new(
            "raw-state",
            pkce_verifier(),
            None,
            ReturnTarget::default(),
            now + 600,
        ),
    )
    .unwrap();
    let unsafe_target = ReturnTarget {
        auth_request_id: None,
        return_to: Some("//evil.example/".into()),
    };

    let refused = [
        ("github", "raw-state", None),
        ("github", "raw-state", Some(URL_SAFE_NO_PAD.encode(changed))),
        (
            "github",
            "raw-state",
            Some(URL_SAFE_NO_PAD.encode(other_version)),
        ),
        (
            "github",
            "raw-state",
            Some(sealed(Provider::GitHub, ReturnTarget::default(), now - 1)),
        ),
        ("google", "raw-state", Some(live.clone())),
        ("github", "another-state", Some(live.clone())),
        (
            "github",
            "raw-state",
            Some(sealed(Provider::GitHub, unsafe_target, now + 600)),
        ),
        ("github", "raw-state", Some(rotated)),
    ];
    for (provider, state, cookie) in refused {
        let response = get(
            &app,
            &format!("/api/auth/oauth/{provider}/callback?code=some-code&state={state}"),
            cookie.as_deref(),
        )
        .await;
        assert_eq!(
            location(&response),
            "/login?oauth_error=expired",
            "{cookie:?}"
        );
        assert_eq!(
            response.headers()[header::SET_COOKIE],
            clear_cookie(STATE_COOKIE, STATE_COOKIE_PATH, true)
        );
    }
    assert_eq!(*upstream.calls.lock().unwrap(), 0);

    // The live cookie, used rightly, reaches the provider (which fails it).
    let response = get(
        &app,
        "/api/auth/oauth/github/callback?code=some-code&state=raw-state",
        Some(&live),
    )
    .await;
    assert_eq!(location(&response), "/login?oauth_error=failed");
    assert_eq!(*upstream.calls.lock().unwrap(), 1);
}
