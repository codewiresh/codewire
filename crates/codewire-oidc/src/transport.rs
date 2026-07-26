//! Optional axum HTTP transport (`--features axum`).
//!
//! [`router`] turns a [`Provider`] into an [`axum::Router`] mounting every
//! implemented endpoint at the provider's configured paths: discovery, JWKS,
//! authorize, token (authorization_code + refresh_token), userinfo, and
//! end-session. The transport is a thin shell — it parses requests, calls the
//! provider, and maps the domain outcomes to HTTP — so non-axum hosts pay
//! nothing for it and can drive the [`Provider`] methods directly.
//!
//! Session teardown at end-session is not the transport's job (it has no
//! session store): the host should use [`Provider::end_session`] directly, or
//! a wrapping layer, when it needs to act on the returned subject.

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;

use crate::Provider;
use crate::endsession::{EndSessionOutcome, RawEndSessionParams};
use crate::error::{ErrorCode, OAuthError};
use crate::flow::{AuthorizeOutcome, RawAuthorizeParams};
use crate::types::RequestContext;

/// Build an [`axum::Router`] serving the provider's HTTP endpoints, mounted at
/// the paths in its [`crate::EndpointPaths`] (plus the two well-known
/// discovery URLs).
pub fn router(provider: Provider) -> Router {
    let paths = provider.config().paths.clone();
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .route(&paths.jwks, get(jwks))
        .route(&paths.authorization, get(authorize).post(authorize))
        .route(&paths.token, post(token))
        .route(&paths.userinfo, get(userinfo).post(userinfo))
        .route(&paths.introspection, post(introspect))
        .route(&paths.revocation, post(revoke))
        .route(&paths.device_authorization, post(device_authorization))
        .route(&paths.end_session, get(end_session).post(end_session))
        .with_state(provider)
}

async fn discovery(State(p): State<Provider>) -> Json<crate::DiscoveryDocument> {
    Json(p.discovery())
}

async fn jwks(State(p): State<Provider>) -> Response {
    match p.jwks().await {
        Ok(j) => Json(j).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn authorize(
    State(p): State<Provider>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ctx = RequestContext {
        cookie: headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    };
    let params = RawAuthorizeParams {
        client_id: q.get("client_id").cloned(),
        redirect_uri: q.get("redirect_uri").cloned(),
        response_type: q.get("response_type").cloned(),
        scope: q.get("scope").cloned(),
        state: q.get("state").cloned(),
        nonce: q.get("nonce").cloned(),
        code_challenge: q.get("code_challenge").cloned(),
        code_challenge_method: q.get("code_challenge_method").cloned(),
        prompt: q.get("prompt").cloned(),
        max_age: q.get("max_age").and_then(|s| s.parse().ok()),
    };
    match p.authorize(&ctx, params).await {
        Ok(AuthorizeOutcome::Redirect(url)) | Ok(AuthorizeOutcome::RedirectToLogin(url)) => {
            found(&url)
        }
        // Cannot safely redirect (untrusted client/redirect_uri) — render the error.
        Ok(AuthorizeOutcome::Fail(e)) => oauth_error(&e),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn token(
    State(p): State<Provider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // Client authentication: HTTP Basic (client_secret_basic) takes precedence,
    // otherwise the form fields (client_secret_post / public + PKCE).
    let (client_id, client_secret) = client_auth(&headers, &form);
    let Some(client_id) = client_id else {
        return oauth_error(&OAuthError::invalid_client("missing client_id"));
    };

    let result = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            p.exchange_authorization_code(
                &client_id,
                client_secret.as_deref(),
                form.get("code").map(String::as_str).unwrap_or_default(),
                form.get("redirect_uri")
                    .map(String::as_str)
                    .unwrap_or_default(),
                form.get("code_verifier").map(String::as_str),
            )
            .await
        }
        Some("refresh_token") => {
            p.exchange_refresh_token(
                &client_id,
                client_secret.as_deref(),
                form.get("refresh_token")
                    .map(String::as_str)
                    .unwrap_or_default(),
                form.get("scope").map(String::as_str),
            )
            .await
        }
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            p.exchange_device_code(
                &client_id,
                client_secret.as_deref(),
                form.get("device_code")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )
            .await
        }
        other => Err(OAuthError::new(
            ErrorCode::UnsupportedGrantType,
            format!("unsupported grant_type: {}", other.unwrap_or("(missing)")),
        )),
    };

    match result {
        Ok(tokens) => no_store(Json(tokens).into_response()),
        Err(e) => oauth_error(&e),
    }
}

async fn userinfo(State(p): State<Provider>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return bearer_challenge(StatusCode::UNAUTHORIZED, None);
    };
    match p.userinfo(token).await {
        Ok(claims) => Json(claims).into_response(),
        Err(e) if e.code == ErrorCode::InvalidToken => {
            bearer_challenge(StatusCode::UNAUTHORIZED, Some(&e))
        }
        Err(e) => oauth_error(&e),
    }
}

async fn introspect(
    State(p): State<Provider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (client_id, client_secret) = client_auth(&headers, &form);
    let Some(client_id) = client_id else {
        return oauth_error(&OAuthError::invalid_client("missing client_id"));
    };
    let token = form.get("token").map(String::as_str).unwrap_or_default();
    let hint = form.get("token_type_hint").map(String::as_str);
    match p
        .introspect(&client_id, client_secret.as_deref(), token, hint)
        .await
    {
        Ok(resp) => no_store(Json(resp).into_response()),
        Err(e) => oauth_error(&e),
    }
}

async fn revoke(
    State(p): State<Provider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (client_id, client_secret) = client_auth(&headers, &form);
    let Some(client_id) = client_id else {
        return oauth_error(&OAuthError::invalid_client("missing client_id"));
    };
    let token = form.get("token").map(String::as_str).unwrap_or_default();
    let hint = form.get("token_type_hint").map(String::as_str);
    match p
        .revoke(&client_id, client_secret.as_deref(), token, hint)
        .await
    {
        // RFC 7009: a successful revocation returns 200 with an empty body.
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(e) => oauth_error(&e),
    }
}

async fn device_authorization(
    State(p): State<Provider>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (client_id, client_secret) = client_auth(&headers, &form);
    let Some(client_id) = client_id else {
        return oauth_error(&OAuthError::invalid_client("missing client_id"));
    };
    match p
        .authorize_device(
            &client_id,
            client_secret.as_deref(),
            form.get("scope").map(String::as_str),
        )
        .await
    {
        Ok(resp) => no_store(Json(resp).into_response()),
        Err(e) => oauth_error(&e),
    }
}

async fn end_session(
    State(p): State<Provider>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let params = RawEndSessionParams {
        id_token_hint: q.get("id_token_hint").cloned(),
        client_id: q.get("client_id").cloned(),
        post_logout_redirect_uri: q.get("post_logout_redirect_uri").cloned(),
        state: q.get("state").cloned(),
    };
    match p.end_session(params).await {
        // Session teardown (using `subject`) is the host's responsibility.
        Ok(EndSessionOutcome::Redirect { url, .. }) => found(&url),
        Ok(EndSessionOutcome::LoggedOut { .. }) => {
            (StatusCode::OK, "You are now signed out.").into_response()
        }
        Ok(EndSessionOutcome::Fail(e)) => oauth_error(&e),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// --- helpers ---------------------------------------------------------------

/// A 302 Found redirect to `location`.
fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Add the RFC 6749 §5.1 no-cache headers to a token response.
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

/// Render an OAuth error as a JSON problem body (RFC 6749 §5.2). `invalid_client`
/// is `401` with a `WWW-Authenticate` header; everything else is `400`.
fn oauth_error(e: &OAuthError) -> Response {
    let status = if e.code == ErrorCode::InvalidClient {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = serde_json::json!({
        "error": e.code.as_str(),
        "error_description": e.description,
    });
    let mut resp = (status, Json(body)).into_response();
    if e.code == ErrorCode::InvalidClient {
        resp.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
    }
    no_store(resp)
}

/// Render a Bearer-token challenge (RFC 6750) for the userinfo endpoint.
fn bearer_challenge(status: StatusCode, err: Option<&OAuthError>) -> Response {
    let challenge = match err {
        Some(e) => format!(
            "Bearer error=\"{}\", error_description=\"{}\"",
            e.code.as_str(),
            e.description
        ),
        None => "Bearer".to_string(),
    };
    let header_val =
        HeaderValue::from_str(&challenge).unwrap_or(HeaderValue::from_static("Bearer"));
    (status, [(header::WWW_AUTHENTICATE, header_val)]).into_response()
}

/// Extract the Bearer access token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Resolve client credentials from HTTP Basic auth or the form body.
fn client_auth(
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> (Option<String>, Option<String>) {
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
        })
        .and_then(|raw| String::from_utf8(raw).ok())
        && let Some((id, secret)) = basic.split_once(':')
    {
        return (Some(id.to_string()), Some(secret.to_string()));
    }
    (
        form.get("client_id").cloned(),
        form.get("client_secret").cloned(),
    )
}
