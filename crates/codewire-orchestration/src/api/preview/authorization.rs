//! Dedicated raw browser transport for granting access to one preview host.
//! Account-session authority is consumed only on the configured frontend.
#[cfg(test)]
mod database_tests;

use axum::{
    body::{Body, to_bytes},
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    response::Response,
};
use codewire_server_core::auth::{AuthUser, SESSION_COOKIE_NAME, hash_session_token};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::{ApiState, PreviewHostMatch, PreviewTarget, browser::*, preview_error};

/// The preview protocol needs no lifecycle client, Kubernetes connection or
/// secret-store handle. Keep its real handlers usable with a synthetic DB.
pub(super) struct PreviewContext<'a> {
    pool: &'a sqlx::PgPool,
    preview_base_domain: &'a str,
    frontend_url: &'a str,
    session_secret: &'a str,
    confidential_storage_flags: crate::confidential_storage::FeatureFlags,
    /// Shared org-slug snapshot cache (#2505 L5).
    org_slugs: &'a super::OrgSlugCache,
}

/// Zero-TTL org cache for tests: every `get` is one query, exactly the
/// pre-L5 behavior, so tests observe database writes immediately.
#[cfg(test)]
fn zero_ttl_org_slugs() -> &'static super::OrgSlugCache {
    static ZERO_TTL: std::sync::OnceLock<super::OrgSlugCache> = std::sync::OnceLock::new();
    ZERO_TTL.get_or_init(|| super::OrgSlugCache::new(std::time::Duration::ZERO))
}

impl<'a> From<&'a ApiState> for PreviewContext<'a> {
    fn from(state: &'a ApiState) -> Self {
        Self {
            pool: &state.pool,
            preview_base_domain: &state.preview_base_domain,
            frontend_url: &state.frontend_url,
            session_secret: &state.session_secret,
            confidential_storage_flags: state.confidential_storage_flags,
            org_slugs: &state.org_slugs,
        }
    }
}

const CHALLENGE_SECONDS: i64 = 300;

enum ValidationError {
    Invalid,
    Unavailable,
}

impl From<ValidationError> for Response {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::Invalid => invalid(),
            ValidationError::Unavailable => unavailable(),
        }
    }
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct Challenge {
    id: String,
    organization_id: String,
    environment_id: String,
    port_id: String,
    host: String,
    return_path: String,
}

#[derive(Serialize, Deserialize)]
struct Start {
    challenge: Challenge,
    nonce_hash: String,
    expires_at: i64,
}

fn decode_start(state: &PreviewContext<'_>, token: &str) -> Result<Start, ValidationError> {
    let start: Start =
        open_start(state.session_secret, token).map_err(|_| ValidationError::Invalid)?;
    let now = chrono::Utc::now().timestamp();
    if start.expires_at <= now
        || start.expires_at > now + CHALLENGE_SECONDS
        || uuid::Uuid::parse_str(&start.challenge.id).is_err()
        || !safe_return_path(&start.challenge.return_path)
        || start.nonce_hash.len() != 64
        || !start.nonce_hash.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ValidationError::Invalid);
    }
    Ok(start)
}

#[derive(sqlx::FromRow)]
struct BrowserSession {
    id: String,
    user_id: String,
    is_admin: bool,
}

impl BrowserSession {
    fn user(&self) -> AuthUser {
        AuthUser {
            user_id: self.user_id.clone(),
            org_id: None,
            is_admin: self.is_admin,
            via_api_key: false,
        }
    }
}

fn unavailable() -> Response {
    preview_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "preview authorization unavailable",
    )
}
fn invalid() -> Response {
    preview_error(
        StatusCode::BAD_REQUEST,
        "invalid or expired preview authorization; reopen the preview",
    )
}
fn denied() -> Response {
    preview_error(StatusCode::FORBIDDEN, "preview access denied")
}

pub(super) fn denied_page(state: &PreviewContext<'_>) -> Response {
    let Ok(frontend) = preview_frontend_origin(state.frontend_url, state.preview_base_domain)
    else {
        return unavailable();
    };
    let html = format!(
        include_str!("denied.html"),
        frontend = html_escape(&frontend)
    );
    no_store(
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(
                header::CONTENT_SECURITY_POLICY,
                format!("default-src 'none'; style-src {frontend}; font-src {frontend}; img-src {frontend}; script-src {frontend}; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"),
            )
            .body(Body::from(html))
            .expect("fixed HTML headers"),
    )
}

pub(super) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Keep a page's own policy: the handoff pages need `strict-origin` so
    // their automatic POST carries a real Origin (see `page`).
    response
        .headers_mut()
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn redirect(location: &str) -> Response {
    no_store(
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, location)
            .body(Body::empty())
            .expect("validated redirect"),
    )
}

fn cookie(name: &str, value: &str, seconds: Option<i64>, same_site: &str) -> HeaderValue {
    let lifetime = seconds
        .map(|seconds| format!("; Max-Age={seconds}"))
        .unwrap_or_default();
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/{lifetime}; Secure; HttpOnly; SameSite={same_site}"
    ))
    .expect("generated cookie")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(
    frontend: &str,
    title: &str,
    body: &str,
    form_origin: &str,
    script: Option<(&str, &str)>,
) -> Response {
    let script_policy = script
        .map(|(nonce, _)| format!("'nonce-{nonce}'"))
        .unwrap_or_else(|| "'none'".into());
    let script_html = script
        .map(|(nonce, text)| format!("<script nonce=\"{nonce}\">{text}</script>"))
        .unwrap_or_default();
    let html = format!(
        include_str!("authorization.html"),
        title = html_escape(title),
        body = body,
        script_html = script_html,
        frontend = html_escape(frontend),
        form_origin = html_escape(form_origin)
    );
    let mut response = no_store(Response::builder().header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_SECURITY_POLICY, format!("default-src 'none'; style-src {frontend}; font-src {frontend}; img-src {frontend}; script-src {script_policy}; form-action {form_origin}; frame-ancestors 'none'; base-uri 'none'"))
        .body(Body::from(html)).expect("fixed HTML headers"));
    // These pages POST to an exact Origin check. Under no-referrer a browser
    // sends `Origin: null` for that POST, so they disclose only their origin.
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin"),
    );
    response
}

fn canonical_request(
    state: &PreviewContext<'_>,
    headers: &HeaderMap,
) -> Result<String, ValidationError> {
    let origin = preview_frontend_origin(state.frontend_url, state.preview_base_domain)
        .map_err(|_| ValidationError::Unavailable)?;
    let expected = url::Url::parse(&origin).map_err(|_| ValidationError::Unavailable)?;
    let authority = match expected.port() {
        Some(port) => format!(
            "{}:{port}",
            expected.host_str().ok_or(ValidationError::Unavailable)?
        ),
        None => expected
            .host_str()
            .ok_or(ValidationError::Unavailable)?
            .to_owned(),
    };
    let mut hosts = headers.get_all(header::HOST).iter();
    if hosts.next().and_then(|h| h.to_str().ok()) != Some(authority.as_str())
        || hosts.next().is_some()
    {
        return Err(ValidationError::Invalid);
    }
    Ok(origin)
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn session(
    state: &PreviewContext<'_>,
    headers: &HeaderMap,
) -> Result<Option<BrowserSession>, Response> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(invalid());
    }
    let Some(token) = unique_cookie(headers, SESSION_COOKIE_NAME).map_err(|_| invalid())? else {
        return Ok(None);
    };
    sqlx::query_as("SELECT s.id, s.user_id, u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at > clock_timestamp() AND u.enabled")
        .bind(hash_session_token(token)).fetch_optional(state.pool).await.map_err(|_| unavailable())
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn challenge_target(
    state: &PreviewContext<'_>,
    challenge: &Challenge,
) -> Result<(PreviewHostMatch, PreviewTarget), Response> {
    // Cached org list (#2505 L5): the challenge already binds the exact
    // org/env/port ids, and a stale slug snapshot cannot mint a match for a
    // host it shouldn't — the ids must still line up below. Worst case a
    // just-renamed org's old-slug host resolves for one TTL window.
    let matched = super::resolve_preview_host_with(
        state.pool,
        state.org_slugs,
        state.preview_base_domain,
        &challenge.host,
    )
    .await
    // A database failure is transient: answer 503 so the browser may retry,
    // not 400, which tells it the challenge itself is bad (#2315).
    .map_err(|error| match error {
        super::PreviewHostError::Internal => unavailable(),
        super::PreviewHostError::Invalid | super::PreviewHostError::NotFound => invalid(),
    })?
    .ok_or_else(invalid)?;
    let target = super::resolve_preview_target(state.pool, &matched).await?;
    if matched.org_id != challenge.organization_id
        || target.env_id != challenge.environment_id
        || target.port_id != challenge.port_id
    {
        return Err(invalid());
    }
    Ok((matched, target))
}

/// The proxy's access decision for an authenticated preview request, for a
/// preview grant and a Bearer credential alike.
#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(super) async fn authorize_proxy_user(
    state: &PreviewContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    user: &AuthUser,
    matched: &PreviewHostMatch,
    target: &PreviewTarget,
) -> Result<(), Response> {
    let forbidden =
        |message: &'static str| super::preview_forbidden(state, method, headers, message);
    // API keys are capabilities for exactly one organization. Enforce
    // that boundary before creator/member shortcuts can grant access to
    // an environment owned by the same user in another organization.
    if !user.permits_organization(&matched.org_id) {
        return Err(forbidden(
            "forbidden: API key belongs to another organization",
        ));
    }

    if let Err(error) = crate::confidential_storage::require_interactive_access(
        state.confidential_storage_flags,
        user,
        &target.isolation_tier,
    ) {
        return Err(match error {
            codewire_server_core::AppError::Coded { status, .. } => preview_error(
                status,
                if status == StatusCode::SERVICE_UNAVAILABLE {
                    "confidential persistent storage is disabled"
                } else {
                    "global administrator user credential required"
                },
            ),
            _ => forbidden("forbidden"),
        });
    }

    if target.access == "org_members" {
        if super::require_environment_access(
            state.pool,
            user,
            &target.env_id,
            &matched.org_id,
            "viewer",
            "forbidden: no access to this environment",
        )
        .await
        .is_err()
        {
            return Err(forbidden("forbidden: no access to this environment"));
        }
    } else if target.access == "creator" {
        if user.user_id != target.created_by {
            return Err(forbidden(
                "forbidden: only the creator can access this preview",
            ));
        }
        // The creator must still be a member, as check_access requires. The
        // proxy decides every request, so a grant or Bearer credential issued
        // before the removal stops working with it (#3254).
        match codewire_server_core::org::user_org_role(state.pool, user, &matched.org_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(forbidden("forbidden: no access to this environment")),
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(super) async fn check_access(
    state: &PreviewContext<'_>,
    user: &AuthUser,
    matched: &PreviewHostMatch,
    target: &PreviewTarget,
) -> Result<(), Response> {
    if !user.permits_organization(&matched.org_id) {
        return Err(denied());
    }
    crate::confidential_storage::require_interactive_access(
        state.confidential_storage_flags,
        user,
        &target.isolation_tier,
    )
    .map_err(|_| denied())?;
    match target.access.as_str() {
        // The creator must still be a member: removal deletes only the
        // membership row, not the environment's creator (#3254).
        "creator" if user.user_id == target.created_by => {
            match codewire_server_core::org::user_org_role(state.pool, user, &matched.org_id).await
            {
                Ok(Some(_)) => Ok(()),
                Ok(None) => Err(denied()),
                Err(_) => Err(unavailable()),
            }
        }
        "org_members" => super::require_environment_access(
            state.pool,
            user,
            &target.env_id,
            &matched.org_id,
            "viewer",
            "preview access denied",
        )
        .await
        .map_err(|_| denied()),
        "public" => Ok(()),
        _ => Err(denied()),
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(super) async fn start(
    state: &PreviewContext<'_>,
    matched: &PreviewHostMatch,
    target: &PreviewTarget,
    host: &str,
    path: &str,
) -> Result<Response, Response> {
    let frontend = preview_frontend_origin(state.frontend_url, state.preview_base_domain)
        .map_err(|_| unavailable())?;
    if !safe_return_path(path) || host != super::normalize_dns_name(host) || host.contains(':') {
        return Err(invalid());
    }
    // Always a fresh nonce in a cookie of its own. A preview page can write
    // cookies for its host, so adopting one the browser offers would let it
    // know the nonce that redeems an intercepted code; one cookie per sign-in
    // keeps concurrent tabs from replacing each other's.
    let nonce = random_token().map_err(|_| unavailable())?;
    let start = Start {
        challenge: Challenge {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: matched.org_id.clone(),
            environment_id: target.env_id.clone(),
            port_id: target.port_id.clone(),
            host: host.to_owned(),
            return_path: path.to_owned(),
        },
        nonce_hash: token_hash(&nonce),
        expires_at: chrono::Utc::now().timestamp() + CHALLENGE_SECONDS,
    };
    // No anonymous database allocation. The encrypted continuation is only a
    // request to confirm, without any account or preview-access authority.
    let continuation = seal_start(state.session_secret, &start).map_err(|_| invalid())?;
    let mut response = redirect(&format!(
        "{frontend}{AUTHORIZE_PATH}?challenge={continuation}"
    ));
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(
            &nonce_cookie(&start.challenge.id),
            &nonce,
            Some(CHALLENGE_SECONDS),
            "None",
        ),
    );
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizationQuery {
    challenge: String,
}

pub(crate) async fn authorize_page(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    let context = PreviewContext::from(&state);
    match authorize_page_inner(&context, &headers, &query.challenge).await {
        Ok(response) => no_store(response),
        Err(response) if response.status() == StatusCode::FORBIDDEN => denied_page(&context),
        Err(response) => no_store(response),
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn authorize_page_inner(
    state: &PreviewContext<'_>,
    headers: &HeaderMap,
    id: &str,
) -> Result<Response, Response> {
    let frontend = canonical_request(state, headers)?;
    let start = decode_start(state, id)?;
    let challenge = &start.challenge;
    let Some(session) = session(state, headers).await? else {
        let local = format!("{AUTHORIZE_PATH}?challenge={id}");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", &local)
            .finish();
        return Ok(redirect(&format!("{frontend}/login?{query}")));
    };
    let (matched, target) = challenge_target(state, challenge).await?;
    check_access(state, &session.user(), &matched, &target).await?;
    let csrf = confirmation_token(state.session_secret, &session.id, &challenge.id);
    let body = format!(
        "<p>Opening your preview.</p><input type=\"hidden\" name=\"challenge\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\" class=\"cw-button\">Continue to preview</button>",
        html_escape(id),
        csrf,
    );
    let nonce = random_token().map_err(|_| unavailable())?;
    Ok(page(
        &frontend,
        "Opening preview",
        &body,
        &format!("{frontend}{AUTHORIZE_PATH}"),
        Some((
            &nonce,
            "document.getElementById('preview-form').requestSubmit();",
        )),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    challenge: String,
    csrf: String,
}

pub(crate) async fn authorize(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Form(form): Form<Approval>,
) -> Response {
    let context = PreviewContext::from(&state);
    match authorize_inner(&context, &headers, form).await {
        Ok(response) => no_store(response),
        Err(response) if response.status() == StatusCode::FORBIDDEN => denied_page(&context),
        Err(response) => no_store(response),
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn authorize_inner(
    state: &PreviewContext<'_>,
    headers: &HeaderMap,
    form: Approval,
) -> Result<Response, Response> {
    let frontend = canonical_request(state, headers)?;
    if !exact_origin(headers, &frontend) {
        return Err(invalid());
    }
    let start = decode_start(state, &form.challenge)?;
    let challenge = &start.challenge;
    let session = session(state, headers).await?.ok_or_else(denied)?;
    if !verify_confirmation(state.session_secret, &session.id, &challenge.id, &form.csrf) {
        return Err(denied());
    }
    let (matched, target) = challenge_target(state, challenge).await?;
    check_access(state, &session.user(), &matched, &target).await?;
    cleanup_expired(state.pool).await?;
    let code = random_token().map_err(|_| unavailable())?;
    let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('codewire-preview-auth:' || $1,0))")
        .bind(&session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let user_hash = token_hash(&session.user_id);
    sqlx::query("DELETE FROM preview_auth_challenges WHERE client_hash=$1 AND expires_at <= clock_timestamp()").bind(&user_hash).execute(&mut *tx).await.map_err(|_| unavailable())?;
    let (user_count, session_count): (i64, i64) = sqlx::query_as("SELECT count(*),count(*) FILTER (WHERE session_id=$2) FROM preview_auth_challenges WHERE client_hash=$1")
        .bind(&user_hash).bind(&session.id).fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
    if user_count >= 32 || session_count >= 8 {
        return Err(preview_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many preview requests; retry shortly",
        ));
    }
    // Consumed IDs remain until expiry: replay cannot mint another callback.
    let changed = sqlx::query("WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS value) INSERT INTO preview_auth_challenges (id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,value,to_timestamp($9),$10,$11,LEAST(to_timestamp($9),value+interval '60 seconds') FROM stamp WHERE to_timestamp($9)>value AND EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$10 AND s.expires_at>clock_timestamp() AND u.enabled) ON CONFLICT(id) DO NOTHING")
        .bind(&challenge.id).bind(&start.nonce_hash).bind(&user_hash).bind(&challenge.organization_id).bind(&challenge.environment_id).bind(&challenge.port_id).bind(&challenge.host).bind(&challenge.return_path).bind(start.expires_at as f64).bind(&session.id).bind(token_hash(&code)).execute(&mut *tx).await.map_err(|_| unavailable())?;
    if changed.rows_affected() != 1 {
        return Err(invalid());
    }
    tx.commit().await.map_err(|_| unavailable())?;
    let callback = format!("https://{}{CALLBACK_PATH}", challenge.host);
    let body = format!(
        "<p>Continue to your preview.</p><input type=\"hidden\" name=\"code\" value=\"{code}\"><input type=\"hidden\" name=\"challenge\" value=\"{}\"><button type=\"submit\" class=\"cw-button\">Continue to preview</button>",
        html_escape(&challenge.id),
    );
    let nonce = random_token().map_err(|_| unavailable())?;
    Ok(page(
        &frontend,
        "Opening preview",
        &body,
        &callback,
        Some((
            &nonce,
            "document.getElementById('preview-form').requestSubmit();",
        )),
    ))
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn cleanup_expired(pool: &sqlx::PgPool) -> Result<(), Response> {
    // Authenticated traffic also retires expired rows belonging to inactive
    // users. Bounded indexed batches never wait on another callback's rows.
    for statement in [
        "WITH expired AS (SELECT id FROM preview_auth_challenges WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 128 FOR UPDATE SKIP LOCKED) DELETE FROM preview_auth_challenges c USING expired e WHERE c.id=e.id",
        "WITH expired AS (SELECT g.token_hash FROM preview_browser_grants g JOIN sessions s ON s.id=g.session_id WHERE s.expires_at <= clock_timestamp() ORDER BY s.expires_at LIMIT 128 FOR UPDATE OF g SKIP LOCKED) DELETE FROM preview_browser_grants g USING expired e WHERE g.token_hash=e.token_hash",
    ] {
        sqlx::query(statement)
            .execute(pool)
            .await
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    code: String,
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(super) async fn callback(
    state: &PreviewContext<'_>,
    request: Request<Body>,
    host: &str,
) -> Result<Response, Response> {
    let frontend = preview_frontend_origin(state.frontend_url, state.preview_base_domain)
        .map_err(|_| unavailable())?;
    if request.method() != Method::POST
        || !exact_origin(request.headers(), &frontend)
        || request.uri().query().is_some()
    {
        return Err(invalid());
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/x-www-form-urlencoded")
    {
        return Err(invalid());
    }
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 4096).await.map_err(|_| invalid())?;
    let values: Vec<_> = url::form_urlencoded::parse(&bytes).collect();
    let value = |name: &str| {
        let mut found = values.iter().filter(|(key, _)| key == name);
        match (found.next(), found.next()) {
            (Some((_, value)), None) => Some(value.to_string()),
            _ => None,
        }
    };
    let (Some(code), Some(challenge_id)) = (value("code"), value("challenge")) else {
        return Err(invalid());
    };
    if values.len() != 2
        || !opaque_token(&code)
        || uuid::Uuid::parse_str(&challenge_id)
            .map_or(true, |id| id.hyphenated().to_string() != challenge_id)
    {
        return Err(invalid());
    }
    let nonce_name = nonce_cookie(&challenge_id);
    let nonce = unique_cookie(&parts.headers, &nonce_name)
        .map_err(|_| invalid())?
        .filter(|value| opaque_token(value))
        .ok_or_else(invalid)?
        .to_owned();
    let code = Callback { code };
    // Complete policy reads before reserving a pool connection. A callback
    // must never wait on itself even when the pool has only one connection.
    let row = sqlx::query("SELECT id,organization_id,environment_id,port_id,host,return_path,session_id FROM preview_auth_challenges WHERE code_hash=$1 AND nonce_hash=$2 AND host=$3 AND id=$4 AND expires_at > clock_timestamp() AND code_expires_at > clock_timestamp() AND consumed_at IS NULL")
        .bind(token_hash(&code.code)).bind(token_hash(&nonce)).bind(host).bind(&challenge_id).fetch_optional(state.pool).await.map_err(|_| unavailable())?.ok_or_else(invalid)?;
    let challenge = Challenge {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        environment_id: row.get("environment_id"),
        port_id: row.get("port_id"),
        host: row.get("host"),
        return_path: row.get("return_path"),
    };
    let session_id: String = row.get("session_id");
    let session: BrowserSession = sqlx::query_as("SELECT s.id,s.user_id,u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at > clock_timestamp() AND u.enabled")
        .bind(&session_id).fetch_optional(state.pool).await.map_err(|_| unavailable())?.ok_or_else(denied)?;
    let (matched, target) = challenge_target(state, &challenge).await?;
    check_access(state, &session.user(), &matched, &target).await?;
    if !safe_return_path(&challenge.return_path) {
        return Err(invalid());
    }
    let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    // Same order as admission/expiry cleanup, before locking codes. Parent
    // user/session locks precede child locks, matching account revocation.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('codewire-preview-auth:' || $1,0))")
        .bind(&session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let enabled: Option<String> =
        sqlx::query_scalar("SELECT id FROM users WHERE id=$1 AND enabled FOR SHARE")
            .bind(&session.user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
    if enabled.is_none() {
        return Err(denied());
    }
    let live: Option<String> = sqlx::query_scalar("SELECT id FROM sessions WHERE id=$1 AND user_id=$2 AND expires_at > clock_timestamp() FOR SHARE")
        .bind(&session_id).bind(&session.user_id).fetch_optional(&mut *tx).await.map_err(|_| unavailable())?;
    if live.is_none() {
        return Err(denied());
    }
    let consumed = sqlx::query("UPDATE preview_auth_challenges c SET consumed_at=clock_timestamp() WHERE c.consumed_at IS NULL AND c.id=$1 AND c.code_hash=$2 AND c.nonce_hash=$3 AND c.host=$4 AND c.session_id=$5 AND c.expires_at > clock_timestamp() AND c.code_expires_at > clock_timestamp() AND EXISTS (SELECT 1 FROM environment_ports p JOIN environments e ON e.id=p.environment_id WHERE p.id=c.port_id AND e.id=c.environment_id AND e.org_id=c.organization_id AND p.deletion_requested_at IS NULL AND e.state='running' AND p.access=$6 AND e.created_by=$7)")
        .bind(&challenge.id).bind(token_hash(&code.code)).bind(token_hash(&nonce)).bind(host).bind(&session_id).bind(&target.access).bind(&target.created_by).execute(&mut *tx).await.map_err(|_| unavailable())?;
    if consumed.rows_affected() != 1 {
        return Err(invalid());
    }
    let token = scoped_grant_token(
        state.session_secret,
        &session_id,
        &challenge.organization_id,
        &challenge.environment_id,
        &challenge.port_id,
        host,
    );
    let digest = token_hash(&token);
    sqlx::query("DELETE FROM preview_browser_grants g USING sessions s WHERE g.session_id=s.id AND s.user_id=$1 AND s.expires_at <= clock_timestamp()")
        .bind(&session.user_id).execute(&mut *tx).await.map_err(|_| unavailable())?;
    // A lost browser cookie may be reissued for the same originating session
    // and exact preview scope. The advisory lock plus the unique scope tuple
    // make concurrent callbacks idempotent without evicting another tab.
    let existing: Option<String> = sqlx::query_scalar("SELECT token_hash FROM preview_browser_grants WHERE session_id=$1 AND organization_id=$2 AND environment_id=$3 AND port_id=$4 AND host=$5 FOR UPDATE")
        .bind(&session_id).bind(&challenge.organization_id).bind(&challenge.environment_id).bind(&challenge.port_id).bind(host).fetch_optional(&mut *tx).await.map_err(|_| unavailable())?;
    if let Some(existing) = existing {
        if existing != digest {
            // A signing-key rotation replaces the old scoped token. The
            // account session and current policy remain the authority.
            sqlx::query("UPDATE preview_browser_grants SET token_hash=$1 WHERE session_id=$2 AND organization_id=$3 AND environment_id=$4 AND port_id=$5 AND host=$6")
                .bind(&digest).bind(&session_id).bind(&challenge.organization_id).bind(&challenge.environment_id).bind(&challenge.port_id).bind(host).execute(&mut *tx).await.map_err(|_| unavailable())?;
        }
    } else {
        let (total, scoped): (i64, i64) = sqlx::query_as("SELECT count(*),count(*) FILTER (WHERE g.session_id=$1 AND g.port_id=$2) FROM preview_browser_grants g JOIN sessions s ON s.id=g.session_id WHERE s.user_id=$3")
            .bind(&session_id).bind(&challenge.port_id).bind(&session.user_id).fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        if total >= 64 || scoped >= 8 {
            return Err(preview_error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many preview sessions; retry shortly",
            ));
        }
        sqlx::query("INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&digest).bind(&session_id).bind(&challenge.organization_id).bind(&challenge.environment_id).bind(&challenge.port_id).bind(host).execute(&mut *tx).await.map_err(|_| unavailable())?;
    }
    tx.commit().await.map_err(|_| unavailable())?;
    let mut response = redirect(&challenge.return_path);
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(GRANT_COOKIE, &token, None, "Lax"),
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie(&nonce_name, "", Some(0), "None"));
    Ok(response)
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(super) async fn grant_user(
    state: &PreviewContext<'_>,
    headers: &HeaderMap,
    host: &str,
    matched: &PreviewHostMatch,
    target: &PreviewTarget,
) -> Result<Option<AuthUser>, Response> {
    let Some(token) = unique_cookie(headers, GRANT_COOKIE).map_err(|_| invalid())? else {
        return Ok(None);
    };
    if !opaque_token(token) {
        return Ok(None);
    }
    let row: Option<(String,bool)> = sqlx::query_as("SELECT s.user_id,u.is_admin FROM preview_browser_grants g JOIN sessions s ON s.id=g.session_id JOIN users u ON u.id=s.user_id WHERE g.token_hash=$1 AND g.host=$2 AND g.organization_id=$3 AND g.environment_id=$4 AND g.port_id=$5 AND s.expires_at > clock_timestamp() AND u.enabled")
        .bind(token_hash(token)).bind(host).bind(&matched.org_id).bind(&target.env_id).bind(&target.port_id).fetch_optional(state.pool).await.map_err(|_| unavailable())?;
    Ok(row.map(|(user_id, is_admin)| AuthUser {
        user_id,
        org_id: None,
        is_admin,
        via_api_key: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_handoff_fixture_keeps_the_shared_semantic_shell() {
        let product = include_str!("authorization.html");
        let fixture = include_str!(
            "../../../../../packages/codewire-design/reference/fixtures/preview-authorization.html"
        );
        for fragment in [
            "<main class=\"cw-auth-shell\">",
            "<section class=\"cw-auth-panel\" aria-labelledby=\"preview-title\">",
            "<header class=\"cw-auth-header\">",
            "<h1 id=\"preview-title\" class=\"cw-page-title\">",
            "<form id=\"preview-form\" class=\"cw-form\" method=\"post\"",
        ] {
            assert!(product.contains(fragment), "product missing {fragment}");
            assert!(fixture.contains(fragment), "fixture missing {fragment}");
        }
        assert!(fixture.contains(">Continue to preview</button>"));
        assert!(!fixture.contains("one hour"));
        assert!(!fixture.contains(">Open preview</button>"));
    }

    #[test]
    fn denied_page_and_fixture_share_the_cosmos_auth_shell() {
        let product = include_str!("denied.html");
        let fixture = include_str!(
            "../../../../../packages/codewire-design/reference/fixtures/preview-access-denied.html"
        );
        for fragment in [
            "<div class=\"cw-cosmos\" aria-hidden=\"true\">",
            "<main class=\"cw-auth-shell\">",
            "<section class=\"cw-auth-panel\" aria-labelledby=\"preview-denied-title\">",
            "<h1 id=\"preview-denied-title\" class=\"cw-page-title\">Preview access denied</h1>",
            "<p class=\"cw-auth-copy\">Your account can't open this preview.",
        ] {
            assert!(product.contains(fragment), "product missing {fragment}");
            assert!(fixture.contains(fragment), "fixture missing {fragment}");
        }
        assert!(!product.contains("gradient"));
        assert!(!fixture.contains("gradient"));
    }

    // A database failure while resolving a challenge's host is transient, so the
    // callback answers 503 and the browser may retry. A 400 would tell it to
    // reopen the preview, as if the challenge itself were invalid (#2315).
    #[tokio::test]
    async fn challenge_target_reports_a_database_failure_as_unavailable() {
        // Nothing listens on port 1: every query fails to acquire a connection.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        let context = PreviewContext {
            pool: &pool,
            preview_base_domain: "preview.test",
            frontend_url: "https://dashboard.test",
            session_secret: "synthetic-key",
            confidential_storage_flags: crate::confidential_storage::FeatureFlags {
                enabled: false,
                admin_only: true,
            },
            org_slugs: zero_ttl_org_slugs(),
        };
        let challenge = Challenge {
            id: "00000000-0000-4000-8000-000000000001".to_string(),
            organization_id: "org-synthetic".to_string(),
            environment_id: "env-synthetic".to_string(),
            port_id: "port-synthetic".to_string(),
            host: "web-abcde-acme.preview.test".to_string(),
            return_path: "/".to_string(),
        };
        let response = challenge_target(&context, &challenge).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn denied_page_is_private_and_never_embeddable() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://synthetic:synthetic@localhost/synthetic")
            .unwrap();
        let context = PreviewContext {
            pool: &pool,
            preview_base_domain: "preview.test",
            frontend_url: "https://dashboard.test",
            session_secret: "synthetic-key",
            confidential_storage_flags: crate::confidential_storage::FeatureFlags {
                enabled: false,
                admin_only: true,
            },
            org_slugs: zero_ttl_org_slugs(),
        };
        let response = denied_page(&context);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(policy.contains("form-action 'none'"));
        assert!(!policy.contains("unsafe-inline"));
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Preview access denied"));
        assert!(html.contains("/assets/codewire/cosmos-v1.js"));
        assert!(html.contains("/assets/codewire/brand-icon-v1.svg"));
        assert!(html.contains("class=\"cw-auth-header\""));
    }

    #[tokio::test]
    async fn automatic_handoff_uses_private_nonce_csp_and_native_fallback() {
        let response = page(
            "https://dashboard.test",
            "Opening preview",
            "<button type=\"submit\">Continue to preview</button>",
            "https://dashboard.test/api/v1/preview-auth/authorize",
            Some((
                "synthetic-nonce",
                "document.getElementById('preview-form').requestSubmit();",
            )),
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        // A browser POST from a no-referrer page carries `Origin: null` and
        // would fail the exact Origin check on the next step.
        assert_eq!(response.headers()[header::REFERRER_POLICY], "strict-origin");
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.contains("script-src 'nonce-synthetic-nonce'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("/assets/codewire/design-v1.css"));
        assert!(html.contains("/assets/codewire/routes/auth-v2.css"));
        assert!(html.contains("<main"));
        assert!(html.contains("<form"));
        assert!(html.contains("<script nonce=\"synthetic-nonce\">"));
    }

    #[test]
    fn handler_no_store_keeps_the_handoff_referrer_policy() {
        // `authorize_page` and `authorize` wrap the page in `no_store` again.
        // Overwriting its policy with no-referrer made the browser send
        // `Origin: null`, so every signed-in handoff failed with 400 on Dev.
        let handoff = no_store(page(
            "https://dashboard.test",
            "Opening preview",
            "<button type=\"submit\">Continue to preview</button>",
            "https://dashboard.test/api/v1/preview-auth/authorize",
            Some((
                "synthetic-nonce",
                "document.getElementById('preview-form').requestSubmit();",
            )),
        ));
        assert_eq!(handoff.headers()[header::REFERRER_POLICY], "strict-origin");
        assert_eq!(
            handoff
                .headers()
                .get_all(header::REFERRER_POLICY)
                .iter()
                .count(),
            1
        );
        let error = no_store(invalid());
        assert_eq!(error.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(error.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn callback_code_is_only_in_post_body_not_headers_or_location() {
        let code = "synthetic-code-canary";
        let response = page(
            "https://dashboard.test",
            "Opening preview",
            &format!(
                "<input type=\"hidden\" name=\"code\" value=\"{code}\"><button type=\"submit\">Continue to preview</button>"
            ),
            "https://web-abcde-org.preview.test/.codewire/preview-auth/callback",
            Some((
                "synthetic-nonce",
                "document.getElementById('preview-form').requestSubmit();",
            )),
        );
        assert!(!response.headers().contains_key(header::LOCATION));
        for value in response.headers().values() {
            assert!(!value.to_str().unwrap().contains(code));
        }
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.contains("script-src 'nonce-synthetic-nonce'"));
        assert!(policy.contains(
            "form-action https://web-abcde-org.preview.test/.codewire/preview-auth/callback"
        ));
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("method=\"post\""));
        assert!(html.contains(code));
        assert!(!html.contains("?code="));
    }

    #[test]
    fn scoped_cookies_have_distinct_samesite_policy_and_no_domain() {
        let nonce = cookie(NONCE_COOKIE, "synthetic", Some(CHALLENGE_SECONDS), "None");
        let grant = cookie(GRANT_COOKIE, "synthetic", None, "Lax");
        for value in [&nonce, &grant] {
            let value = value.to_str().unwrap();
            assert!(value.starts_with("__Host-"));
            assert!(value.contains("Path=/"));
            assert!(value.contains("Secure; HttpOnly"));
            assert!(!value.contains("Domain="));
        }
        assert!(
            nonce
                .to_str()
                .unwrap()
                .contains("Max-Age=300; Secure; HttpOnly; SameSite=None")
        );
        assert!(
            grant
                .to_str()
                .unwrap()
                .contains("Secure; HttpOnly; SameSite=Lax")
        );
        assert!(!grant.to_str().unwrap().contains("Max-Age="));
        assert!(!grant.to_str().unwrap().contains("Expires="));
    }

    #[test]
    fn names_are_html_text_not_markup() {
        assert_eq!(
            html_escape("<script>\"'&"),
            "&lt;script&gt;&quot;&#39;&amp;"
        );
    }
}
