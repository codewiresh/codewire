//! Metadata-only adapter for the cookie-owned IdP session controls. Never
//! forward upstream diagnostics or accept an alternate authentication method.
use std::collections::BTreeSet;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use codewire_server_core::auth::SESSION_COOKIE_NAME;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::state::AppState;

const RESPONSE_LIMIT: usize = 64 * 1024;
const PAGE_LIMIT: usize = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentSession {
    pub(crate) id: String,
    pub(crate) expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionMetadata {
    pub(crate) id: String,
    pub(crate) created_at: Option<String>,
    pub(crate) expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inventory {
    pub(crate) account_id: String,
    pub(crate) current_session: CurrentSession,
    pub(crate) sessions: Vec<SessionMetadata>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revoked {
    pub(crate) revoked: bool,
    pub(crate) current_session_revoked: bool,
}

pub(crate) enum Failure {
    Unauthorized,
    Forbidden,
    NoLongerAvailable,
    Unavailable,
    UnknownOutcome,
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub(crate) fn valid_time(value: &str) -> bool {
    value.len() <= 40 && value.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

pub(crate) fn cookie_authority_is_unique(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::AUTHORIZATION) {
        return false;
    }
    let mut count = 0;
    for cookie in headers.get_all(header::COOKIE) {
        let Ok(cookie) = cookie.to_str() else {
            return false;
        };
        for pair in cookie.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == SESSION_COOKIE_NAME {
                count += 1;
                if value.is_empty()
                    || value.len() > 256
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return false;
                }
            }
        }
    }
    count == 1
}

pub(crate) fn mutation_origin_is_exact(headers: &HeaderMap, public_origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(public_origin) else {
        return false;
    };
    let Ok(expected) = HeaderValue::from_str(&url.origin().ascii_serialization()) else {
        return false;
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    origins.next() == Some(&expected) && origins.next().is_none()
}

impl Inventory {
    fn validate(&self, account_id: &str, cursor: Option<&str>) -> bool {
        if self.account_id != account_id
            || !valid_id(account_id)
            || !valid_id(&self.current_session.id)
            || !valid_time(&self.current_session.expires_at)
            || self.sessions.len() > PAGE_LIMIT
        {
            return false;
        }
        let mut ids = BTreeSet::new();
        let mut previous = cursor.unwrap_or("");
        for session in &self.sessions {
            if !valid_id(&session.id)
                || session.id.as_str() <= previous
                || !ids.insert(session.id.as_str())
                || !valid_time(&session.expires_at)
                || session
                    .created_at
                    .as_deref()
                    .is_some_and(|time| !valid_time(time))
                || (session.id == self.current_session.id
                    && session.expires_at != self.current_session.expires_at)
            {
                return false;
            }
            previous = &session.id;
        }
        match &self.next_cursor {
            None => true,
            Some(next) => self.sessions.len() == PAGE_LIMIT && valid_id(next) && next == previous,
        }
    }
}

async fn bounded_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > RESPONSE_LIMIT as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > RESPONSE_LIMIT.saturating_sub(body.len()) {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ())
}

pub(crate) async fn inventory(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    cursor: Option<&str>,
) -> Result<Inventory, Failure> {
    if !valid_id(account_id) || cursor.is_some_and(|id| !valid_id(id)) {
        return Err(Failure::Unavailable);
    }
    let mut url = reqwest::Url::parse(&format!(
        "{}/api/auth/sessions",
        state.identity_origin_string
    ))
    .map_err(|_| Failure::Unavailable)?;
    url.query_pairs_mut().append_pair("account_id", account_id);
    if let Some(cursor) = cursor {
        url.query_pairs_mut().append_pair("cursor", cursor);
    }
    let response = state
        .account_http
        .get(url)
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(Failure::Unauthorized),
        StatusCode::FORBIDDEN => return Err(Failure::Forbidden),
        _ => return Err(Failure::Unavailable),
    }
    let inventory: Inventory = bounded_json(response)
        .await
        .map_err(|_| Failure::Unavailable)?;
    if !inventory.validate(account_id, cursor) {
        return Err(Failure::Unavailable);
    }
    Ok(inventory)
}

pub(crate) async fn revoke(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    session_id: &str,
) -> Result<Revoked, Failure> {
    if !valid_id(account_id) || !valid_id(session_id) {
        return Err(Failure::NoLongerAvailable);
    }
    #[derive(Serialize)]
    struct Request<'a> {
        account_id: &'a str,
        session_id: &'a str,
    }
    let origin = reqwest::Url::parse(&state.public_origin)
        .map_err(|_| Failure::UnknownOutcome)?
        .origin()
        .ascii_serialization();
    let response = state
        .account_http
        .post(format!(
            "{}/api/auth/sessions/revoke",
            state.identity_origin_string
        ))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, origin)
        .json(&Request {
            account_id,
            session_id,
        })
        .send()
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(Failure::Unauthorized),
        StatusCode::FORBIDDEN => return Err(Failure::Forbidden),
        StatusCode::NOT_FOUND => return Err(Failure::NoLongerAvailable),
        _ => return Err(Failure::UnknownOutcome),
    }
    let acknowledgement: Revoked = bounded_json(response)
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    if !acknowledgement.revoked {
        return Err(Failure::UnknownOutcome);
    }
    Ok(acknowledgement)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic IdP, not a proxy or alternate verification topology. The
    // optional fixed port supports an exact local firewall permission; CI uses
    // the ordinary ephemeral listener. No real identity or token is loaded.
    #[tokio::test]
    async fn adapter_bounds_streams_denies_redirects_and_requires_source_acknowledgement() {
        use axum::{Router, body::Body, extract::Request, response::Response, routing::any};
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        let response_case = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let case = response_case.clone();
        let requests = observed.clone();
        let router = Router::new().fallback(any(move |request: Request| {
            let case = case.load(Ordering::SeqCst);
            let requests = requests.clone();
            async move {
                assert!(!request.headers().contains_key(header::AUTHORIZATION));
                assert_eq!(request.headers()[header::COOKIE], "codewire.session_token=synthetic");
                let path = request.uri().to_string();
                let origin = request.headers().get(header::ORIGIN).cloned();
                let body = axum::body::to_bytes(request.into_body(), 2048).await.unwrap();
                requests.lock().unwrap().push((path, origin, body));
                let mut builder = Response::builder().header(header::CONTENT_TYPE, "application/json");
                let body = match case {
                    0 => Body::from(r#"{"account_id":"account-1","current_session":{"id":"session-current","expires_at":"2026-09-17T00:00:00Z"},"sessions":[],"next_cursor":null}"#),
                    1 => {
                        builder = builder.status(StatusCode::TEMPORARY_REDIRECT).header(header::LOCATION, "/redirect-must-not-be-followed");
                        Body::empty()
                    }
                    2 => {
                        // Stream without Content-Length: the cumulative bound
                        // must apply even when the header cannot preflight it.
                        let chunks = (0..9).map(|_| Ok::<_, std::io::Error>(vec![b' '; 8192]));
                        Body::from_stream(tokio_stream::iter(chunks))
                    }
                    3 => Body::from(r#"{"revoked":true,"current_session_revoked":false}"#),
                    4 => Body::from(r#"{"revoked":true,"current_session_revoked":true}"#),
                    5 => Body::from(r#"{"revoked":false,"current_session_revoked":false}"#),
                    6 => Body::from(r#"{"revoked":true,"current_session_revoked":true,"token":"synthetic-private-material"}"#),
                    7 => { builder = builder.status(StatusCode::NOT_FOUND); Body::empty() }
                    8 => { builder = builder.status(StatusCode::FORBIDDEN); Body::empty() }
                    9 => Body::from("null"),
                    _ => Body::from(r#"{"user":{"id":"account-1","name":"Synthetic Owner","email":"owner@example.test","email_verified":true,"created_at":"2026-09-09T17:00:00Z","two_factor_enabled":true}}"#),
                };
                builder.body(body).unwrap()
            }
        }));
        let port: u16 = std::env::var("CODEWIRE_ACCOUNT_ADAPTER_TEST_PORT")
            .map(|port| port.parse().expect("synthetic adapter test port"))
            .unwrap_or(0);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (finish, finished) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = finished.await;
                })
                .await
                .unwrap();
        });
        let state = AppState::new(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: origin.parse().unwrap(),
            credential_origin: origin.parse().unwrap(),
            identity_origin_string: origin.clone(),
            browser_api_origin: origin.clone(),
            billing_origin: origin.parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            confidential_admin_only: true,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        });
        let cookie = HeaderValue::from_static("codewire.session_token=synthetic");
        assert!(
            inventory(&state, cookie.clone(), "account-1", Some("session-000"))
                .await
                .is_ok()
        );
        response_case.store(1, Ordering::SeqCst);
        assert!(matches!(
            inventory(&state, cookie.clone(), "account-1", None).await,
            Err(Failure::Unavailable)
        ));
        response_case.store(2, Ordering::SeqCst);
        assert!(matches!(
            inventory(&state, cookie.clone(), "account-1", None).await,
            Err(Failure::Unavailable)
        ));
        for (case, current) in [(3, false), (4, true)] {
            response_case.store(case, Ordering::SeqCst);
            let ack = revoke(&state, cookie.clone(), "account-1", "session-other")
                .await
                .ok()
                .unwrap();
            assert_eq!(ack.current_session_revoked, current);
        }
        for case in [5, 6] {
            response_case.store(case, Ordering::SeqCst);
            assert!(matches!(
                revoke(&state, cookie.clone(), "account-1", "session-other").await,
                Err(Failure::UnknownOutcome)
            ));
        }
        response_case.store(7, Ordering::SeqCst);
        assert!(matches!(
            revoke(&state, cookie.clone(), "account-1", "session-other").await,
            Err(Failure::NoLongerAvailable)
        ));
        response_case.store(8, Ordering::SeqCst);
        assert!(matches!(
            inventory(&state, cookie.clone(), "account-1", None).await,
            Err(Failure::Forbidden)
        ));
        assert!(matches!(
            revoke(&state, cookie.clone(), "account-1", "session-other").await,
            Err(Failure::Forbidden)
        ));
        let mut browser_headers = HeaderMap::new();
        browser_headers.insert(header::COOKIE, cookie);
        response_case.store(9, Ordering::SeqCst);
        assert!(matches!(
            crate::auth::authenticated_identity(&state, &browser_headers).await,
            Err(crate::error::WebError::Unauthorized)
        ));
        response_case.store(10, Ordering::SeqCst);
        let identity = crate::auth::authenticated_identity(&state, &browser_headers)
            .await
            .unwrap();
        assert_eq!(identity.id, "account-1");
        assert!(identity.email_verified());
        assert_eq!(identity.created_at(), "2026-09-09T17:00:00Z");
        assert!(identity.two_factor_enabled());
        finish.send(()).unwrap();
        server.await.unwrap();
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 12, "redirect must not add a second request");
        assert_eq!(
            requests[0].0,
            "/api/auth/sessions?account_id=account-1&cursor=session-000"
        );
        for (path, origin, body) in requests
            .iter()
            .filter(|(path, _, _)| path.ends_with("/revoke"))
        {
            assert_eq!(path, "/api/auth/sessions/revoke");
            assert_eq!(origin.as_ref().unwrap(), "https://app.example.test");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(body).unwrap(),
                serde_json::json!({"account_id":"account-1", "session_id":"session-other"})
            );
        }
    }

    fn inventory_fixture() -> Inventory {
        serde_json::from_value(serde_json::json!({
            "account_id":"account-1",
            "current_session":{"id":"session-current","expires_at":"2026-09-17T00:00:00Z"},
            "sessions":[{"id":"session-001","created_at":null,"expires_at":"2026-09-17T00:00:00Z"}],
            "next_cursor":null
        }))
        .unwrap()
    }

    #[test]
    fn inventory_is_scoped_bounded_ordered_and_capability_free() {
        let mut inventory = inventory_fixture();
        assert!(inventory.validate("account-1", None));
        assert!(!inventory.validate("another-account", None));
        assert!(!inventory.validate("account-1", Some("session-002")));
        inventory.next_cursor = Some("session-001".into());
        assert!(!inventory.validate("account-1", None));
        inventory.next_cursor = None;
        inventory.sessions[0].created_at = Some("upstream-sensitive-detail".into());
        assert!(!inventory.validate("account-1", None));
        inventory.sessions[0].created_at = None;
        inventory.sessions[0].id = "x".repeat(129);
        assert!(!inventory.validate("account-1", None));
        let mut raw = serde_json::json!({
            "account_id":"account-1", "current_session":{"id":"session-current","expires_at":"2026-09-17T00:00:00Z"},
            "sessions":[],"next_cursor":null,"token":"must-not-be-accepted"
        });
        assert!(serde_json::from_value::<Inventory>(raw.clone()).is_err());
        raw.as_object_mut().unwrap().remove("token");
        raw["current_session"]["token_hash"] = "must-not-be-accepted".into();
        assert!(serde_json::from_value::<Inventory>(raw).is_err());
    }

    #[test]
    fn keyset_pages_progress_without_silent_truncation() {
        let mut inventory = inventory_fixture();
        inventory.sessions = (0..PAGE_LIMIT)
            .map(|n| SessionMetadata {
                id: format!("session-{n:03}"),
                created_at: None,
                expires_at: "2026-09-17T00:00:00Z".into(),
            })
            .collect();
        inventory.next_cursor = Some("session-049".into());
        assert!(inventory.validate("account-1", None));
        inventory.next_cursor = Some("session-048".into());
        assert!(!inventory.validate("account-1", None));
        inventory.next_cursor = None;
        inventory.sessions.push(SessionMetadata {
            id: "session-050".into(),
            created_at: None,
            expires_at: "2026-09-17T00:00:00Z".into(),
        });
        assert!(!inventory.validate("account-1", None));
        inventory.sessions.pop();
        inventory.sessions.swap(0, 1);
        assert!(!inventory.validate("account-1", None));
    }

    #[test]
    fn mixed_id_pages_share_the_idp_byte_order_across_the_page_boundary() {
        let mut ids: Vec<String> = ["A", "a", "-", "_", "0", "9"]
            .into_iter()
            .flat_map(|prefix| (0..10).map(move |n| format!("{prefix}-{n}")))
            .collect();
        ids.sort();
        let mut first = inventory_fixture();
        first.sessions = ids[..PAGE_LIMIT]
            .iter()
            .map(|id| SessionMetadata {
                id: id.clone(),
                created_at: None,
                expires_at: "2026-09-17T00:00:00Z".into(),
            })
            .collect();
        first.next_cursor = Some(ids[PAGE_LIMIT - 1].clone());
        assert!(first.validate("account-1", None));
        let mut second = inventory_fixture();
        second.sessions = ids[PAGE_LIMIT..]
            .iter()
            .map(|id| SessionMetadata {
                id: id.clone(),
                created_at: None,
                expires_at: "2026-09-17T00:00:00Z".into(),
            })
            .collect();
        assert!(second.validate("account-1", first.next_cursor.as_deref()));
        second.sessions[0].id = ids[PAGE_LIMIT - 1].clone();
        assert!(!second.validate("account-1", first.next_cursor.as_deref()));
        first.sessions.swap(0, 1);
        assert!(!first.validate("account-1", None));
    }

    #[test]
    fn duplicate_and_mixed_cookie_authority_cannot_be_normalized_away() {
        let mut headers = HeaderMap::new();
        assert!(!cookie_authority_is_unique(&headers));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "codewire.session_token=synthetic_token; codewire_ssr_csrf=synthetic",
            ),
        );
        assert!(cookie_authority_is_unique(&headers));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=another"),
        );
        assert!(!cookie_authority_is_unique(&headers));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=one; codewire.session_token=two"),
        );
        assert!(!cookie_authority_is_unique(&headers));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=one"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer unrelated"),
        );
        assert!(!cookie_authority_is_unique(&headers));
    }

    #[test]
    fn mutations_require_one_exact_origin_not_a_referer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://app.example.test/settings/"),
        );
        assert!(!mutation_origin_is_exact(
            &headers,
            "https://app.example.test"
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.test"),
        );
        assert!(mutation_origin_is_exact(
            &headers,
            "https://app.example.test"
        ));
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://app.example.test"),
        );
        assert!(!mutation_origin_is_exact(
            &headers,
            "https://app.example.test"
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://other.example.test"),
        );
        assert!(!mutation_origin_is_exact(
            &headers,
            "https://app.example.test"
        ));
    }
}
