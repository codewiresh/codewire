//! Host-based app preview proxy, ported from `environment_preview.go`.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use futures_util::{TryStream, TryStreamExt};
use sqlx::Row;

use super::ApiState;
use super::environments::require_environment_access;
use super::prepare::plain_error;
use super::terminal::authenticate_socket_request;
use crate::confidential_storage::require_interactive_access;

const PREVIEW_SERVICE_HEADER: &str = "x-codewire-service";
const PREVIEW_SERVICE_NAME: &str = "codewire-orchestration";

pub(crate) mod authorization;
mod browser;
mod headers;

/// Authorize one target, then return its response to the browser. A workload
/// redirect must never cause the service to fetch another internal origin.
pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[derive(Debug, Clone)]
struct PreviewTarget {
    port_id: String,
    port: i32,
    env_id: String,
    access: String,
    created_by: String,
    pod_ip: String,
    isolation_tier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewHostMatch {
    org_id: String,
    label: String,
    env_prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewHostError {
    Invalid,
    Internal,
    NotFound,
}

/// Intercepts `*.PREVIEW_BASE_DOMAIN` requests before normal API routing.
/// Non-preview hosts pass through to the orchestration router unchanged.
pub async fn preview_proxy_middleware(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(host) = request_host(request.headers(), request.uri()).map(str::to_string) else {
        return next.run(request).await;
    };
    if !is_preview_host(&host, &state.preview_base_domain) {
        return next.run(request).await;
    }
    if request.uri().path() == browser::CALLBACK_PATH {
        let context = authorization::PreviewContext::from(&state);
        return match authorization::callback(&context, request, &host).await {
            Ok(response) => authorization::no_store(response),
            Err(response) if response.status() == StatusCode::FORBIDDEN => {
                authorization::denied_page(&context)
            }
            Err(response) => authorization::no_store(response),
        };
    }
    if request.uri().path().starts_with("/.codewire/") {
        return preview_error(StatusCode::NOT_FOUND, "preview endpoint not found");
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = request.into_body();

    let host_match =
        match resolve_preview_host(&state.pool, &state.preview_base_domain, &host).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                return next
                    .run(
                        Request::builder()
                            .method(method)
                            .uri(uri)
                            .body(body)
                            .expect("request rebuild"),
                    )
                    .await;
            }
            Err(PreviewHostError::Invalid) => {
                return preview_error(StatusCode::BAD_REQUEST, "invalid preview hostname");
            }
            Err(PreviewHostError::Internal) => {
                return preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
            Err(PreviewHostError::NotFound) => {
                return preview_error(StatusCode::NOT_FOUND, "preview hostname not found");
            }
        };

    let target = match resolve_preview_target(&state.pool, &host_match).await {
        Ok(target) => target,
        Err(response) => return response,
    };

    if target.isolation_tier == "confidential" && !state.confidential_storage_flags.enabled {
        return preview_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "confidential persistent storage is disabled",
        );
    }

    // Whether the proxy authenticated with the request's Bearer credential;
    // that credential then stops here instead of reaching the workload.
    let mut platform_bearer = false;
    if target.access != "public" || target.isolation_tier == "confidential" {
        let grant = match authorization::grant_user(
            &authorization::PreviewContext::from(&state),
            &headers,
            &host,
            &host_match,
            &target,
        )
        .await
        {
            Ok(user) => user,
            Err(response) => return response,
        };
        if grant.is_some()
            && !browser::safe_cookie_request(&method, &headers, &format!("https://{host}"))
        {
            return preview_error(StatusCode::FORBIDDEN, "preview request origin denied");
        }
        // The account session cookie is host-only on the dashboard origin, so
        // one sent to a preview host was planted by another preview. Only the
        // preview grant or a Bearer credential authenticates here.
        let authenticated = match grant {
            Some(user) => Ok(user),
            None => {
                let mut bearer_only = headers.clone();
                bearer_only.remove(header::COOKIE);
                platform_bearer = bearer_only.contains_key(header::AUTHORIZATION);
                authenticate_socket_request(&state, &bearer_only, "").await
            }
        };
        let user = match authenticated {
            Ok(user) => user,
            Err(response) if response.status() == StatusCode::UNAUTHORIZED => {
                // Only an actual top-level browser navigation starts sign-in.
                // API requests, POST bodies and upgrade handshakes fail closed.
                if method != axum::http::Method::GET
                    || headers.contains_key(header::UPGRADE)
                    || headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok())
                        != Some("navigate")
                    || headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok())
                        != Some("document")
                {
                    return response;
                }
                return match authorization::start(
                    &authorization::PreviewContext::from(&state),
                    &headers,
                    &host_match,
                    &target,
                    &host,
                    uri.path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/"),
                )
                .await
                {
                    Ok(response) | Err(response) => response,
                };
            }
            Err(response) => return response,
        };

        // API keys are capabilities for exactly one organization. Enforce
        // that boundary before creator/member shortcuts can grant access to
        // an environment owned by the same user in another organization.
        if !user.permits_organization(&host_match.org_id) {
            return preview_forbidden(
                &state,
                &method,
                &headers,
                "forbidden: API key belongs to another organization",
            );
        }

        if let Err(error) = require_interactive_access(
            state.confidential_storage_flags,
            &user,
            &target.isolation_tier,
        ) {
            return match error {
                codewire_server_core::AppError::Coded { status, .. } => preview_error(
                    status,
                    if status == StatusCode::SERVICE_UNAVAILABLE {
                        "confidential persistent storage is disabled"
                    } else {
                        "global administrator user credential required"
                    },
                ),
                _ => preview_forbidden(&state, &method, &headers, "forbidden"),
            };
        }

        if target.access == "org_members" {
            if require_environment_access(
                &state.pool,
                &user,
                &target.env_id,
                &host_match.org_id,
                "viewer",
                "forbidden: no access to this environment",
            )
            .await
            .is_err()
            {
                return preview_forbidden(
                    &state,
                    &method,
                    &headers,
                    "forbidden: no access to this environment",
                );
            }
        } else if target.access == "creator" && user.user_id != target.created_by {
            return preview_forbidden(
                &state,
                &method,
                &headers,
                "forbidden: only the creator can access this preview",
            );
        }
    }

    proxy_to_preview_target(
        &state,
        method,
        uri,
        headers,
        platform_bearer,
        body,
        &host,
        &target,
    )
    .await
}

fn request_host<'a>(headers: &'a HeaderMap, uri: &'a axum::http::Uri) -> Option<&'a str> {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
}

fn is_preview_host(host: &str, base_domain: &str) -> bool {
    preview_subdomain(host, base_domain).is_some()
}

fn preview_subdomain(host: &str, base_domain: &str) -> Option<String> {
    let base = normalize_dns_name(base_domain);
    if base.is_empty() {
        return None;
    }
    let host = normalize_dns_name(strip_port(host));
    let suffix = format!(".{base}");
    host.strip_suffix(&suffix).map(str::to_string)
}

fn strip_port(host: &str) -> &str {
    host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

async fn resolve_preview_host(
    pool: &sqlx::PgPool,
    base_domain: &str,
    host: &str,
) -> Result<Option<PreviewHostMatch>, PreviewHostError> {
    let rows = sqlx::query("SELECT id, slug FROM organizations ORDER BY length(slug) DESC")
        .fetch_all(pool)
        .await
        .map_err(|_| PreviewHostError::Internal)?;
    let orgs = rows.iter().filter_map(|row| {
        let id: String = row.try_get("id").ok()?;
        let slug: String = row.try_get("slug").ok()?;
        Some((id, slug))
    });
    match_preview_host(host, base_domain, orgs)
}

fn match_preview_host<I>(
    host: &str,
    base_domain: &str,
    orgs: I,
) -> Result<Option<PreviewHostMatch>, PreviewHostError>
where
    I: IntoIterator<Item = (String, String)>,
{
    let Some(subdomain) = preview_subdomain(host, base_domain) else {
        return Ok(None);
    };
    if !subdomain.contains('-') {
        return Err(PreviewHostError::Invalid);
    }

    for (org_id, org_slug) in orgs {
        let suffix = format!("-{}", normalize_dns_name(&org_slug));
        let Some(remainder) = subdomain.strip_suffix(&suffix) else {
            continue;
        };
        let Some((label, env_prefix)) = remainder.rsplit_once('-') else {
            continue;
        };
        if !label.is_empty() && env_prefix.len() == 5 {
            return Ok(Some(PreviewHostMatch {
                org_id,
                label: label.to_string(),
                env_prefix: env_prefix.to_string(),
            }));
        }
    }

    Err(PreviewHostError::NotFound)
}

async fn resolve_preview_target(
    pool: &sqlx::PgPool,
    host_match: &PreviewHostMatch,
) -> Result<PreviewTarget, Response> {
    let rows = sqlx::query(
        r#"SELECT ep.id AS port_id, ep.port, e.id,
                  ep.access, e.created_by, e.state, e.isolation_tier,
                  COALESCE(b.pod_ip, '') AS pod_ip
             FROM environment_ports ep
             JOIN environments e ON e.id = ep.environment_id
             LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
            WHERE ep.label = $1
              AND starts_with(e.id, $2)
              AND e.org_id = $3
              AND ep.deletion_requested_at IS NULL
            LIMIT 2"#,
    )
    .bind(&host_match.label)
    .bind(&host_match.env_prefix)
    .bind(&host_match.org_id)
    .fetch_all(pool)
    .await
    .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;

    let [row] = rows.as_slice() else {
        return Err(preview_error(
            StatusCode::NOT_FOUND,
            "port mapping not found",
        ));
    };

    let state_text: String = row
        .try_get("state")
        .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;
    if state_text != "running" {
        return Err(preview_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "environment is not running",
        ));
    }

    let pod_ip: String = row
        .try_get("pod_ip")
        .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;
    if pod_ip.trim().is_empty() {
        return Err(preview_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox backend unavailable",
        ));
    }

    Ok(PreviewTarget {
        port_id: row
            .try_get("port_id")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
        port: row
            .try_get("port")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
        env_id: row
            .try_get("id")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
        access: row
            .try_get("access")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
        created_by: row
            .try_get("created_by")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
        pod_ip,
        isolation_tier: row
            .try_get("isolation_tier")
            .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?,
    })
}

#[allow(clippy::too_many_arguments)]
async fn proxy_to_preview_target(
    state: &ApiState,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    platform_bearer: bool,
    body: Body,
    original_host: &str,
    target: &PreviewTarget,
) -> Response {
    let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    let target_url = format!("http://{}:{}{}", target.pod_ip, target.port, path_and_query);

    let Ok(method) = method.as_str().parse::<reqwest::Method>() else {
        return preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable");
    };
    let mut req = state.http_client.request(method, target_url);
    for (name, value) in headers::workload_request_headers(&headers, platform_bearer).iter() {
        req = req.header(name.as_str(), value.as_bytes());
    }
    req = req
        .header(header::HOST.as_str(), original_host)
        .header("x-forwarded-host", original_host)
        .header("x-forwarded-proto", "https")
        .body(stream_preview_request(body));

    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(env = %target.env_id, error = %err, "preview proxy error");
            return preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable");
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let builder = preview_response_builder(status, resp.headers(), original_host);
    let body = stream_preview_response(resp.bytes_stream(), target.env_id.clone());
    let response = builder
        .body(body)
        .unwrap_or_else(|_| preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable"));
    if target.access != "public" || target.isolation_tier == "confidential" {
        private_response(response)
    } else {
        response
    }
}

fn private_response(mut response: Response) -> Response {
    // An application cannot opt authenticated content into a shared cache.
    // Apply equally to conditional/304 responses so cached metadata is replaced.
    let headers = response.headers_mut();
    for name in [
        "cache-control",
        "surrogate-control",
        "cdn-cache-control",
        "cloudflare-cdn-cache-control",
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("private, no-store"),
        );
    }
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn stream_preview_request(body: Body) -> reqwest::Body {
    reqwest::Body::wrap_stream(body.into_data_stream())
}

fn stream_preview_response<S, E>(stream: S, env_id: String) -> Body
where
    S: TryStream<Ok = Bytes, Error = E> + Send + 'static,
    E: Into<axum::BoxError> + std::fmt::Display + Send + Sync + 'static,
{
    Body::from_stream(stream.map_err(move |error| {
        tracing::warn!(env = %env_id, error = %error, "preview proxy response stream failed");
        error
    }))
}

fn preview_response_builder(
    status: StatusCode,
    headers: &HeaderMap,
    preview_host: &str,
) -> axum::http::response::Builder {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers::browser_response_headers(headers, preview_host).iter() {
        let Ok(name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    builder.header(PREVIEW_SERVICE_HEADER, PREVIEW_SERVICE_NAME)
}

fn preview_error(status: StatusCode, message: &'static str) -> Response {
    let mut response = plain_error(status, message);
    response.headers_mut().insert(
        HeaderName::from_static(PREVIEW_SERVICE_HEADER),
        HeaderValue::from_static(PREVIEW_SERVICE_NAME),
    );
    response
}

fn preview_forbidden(
    state: &ApiState,
    method: &axum::http::Method,
    headers: &HeaderMap,
    message: &'static str,
) -> Response {
    if *method == axum::http::Method::GET
        && headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()) == Some("navigate")
        && headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) == Some("document")
    {
        authorization::denied_page(&authorization::PreviewContext::from(state))
    } else {
        preview_error(StatusCode::FORBIDDEN, message)
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use super::*;
    use futures_util::StreamExt;
    use tokio_stream::wrappers::ReceiverStream;

    #[tokio::test]
    async fn workload_redirect_is_returned_not_followed_and_stays_private() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let destination = format!("http://{address}/must-not-fetch");
        let location = destination.clone();
        let router = axum::Router::new()
            .route(
                "/",
                axum::routing::get(move || async move {
                    (
                        StatusCode::FOUND,
                        [
                            (header::LOCATION, location),
                            (header::CACHE_CONTROL, "public, max-age=86400".into()),
                        ],
                    )
                }),
            )
            .route(
                "/must-not-fetch",
                axum::routing::get(move || async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    "redirect target must not be requested"
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let result = http_client()
            .unwrap()
            .get(format!("http://{address}/"))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        server.abort();
        let _ = server.await;
        let upstream = result.expect("synthetic redirect request");
        assert_eq!(upstream.status(), StatusCode::FOUND);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        let response = private_response(
            preview_response_builder(
                upstream.status(),
                upstream.headers(),
                "web-abcde-org.preview.test",
            )
            .body(Body::empty())
            .unwrap(),
        );
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers()[header::LOCATION], destination);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert!(
            include_str!("../main.rs")
                .contains("http_client: codewire_orchestration::api::preview::http_client()?")
        );
    }

    #[test]
    fn non_preview_hosts_pass_through() {
        assert_eq!(
            match_preview_host(
                "codewire.localhost",
                "codewire-dev.local",
                [("org1".to_string(), "kind-e2e".to_string())]
            ),
            Ok(None)
        );
    }

    #[test]
    fn invalid_preview_host_without_dash_is_rejected() {
        assert_eq!(
            match_preview_host(
                "web.codewire-dev.local",
                "codewire-dev.local",
                [("org1".to_string(), "kind-e2e".to_string())]
            ),
            Err(PreviewHostError::Invalid)
        );
    }

    #[test]
    fn preview_host_matches_longest_org_slug_and_dashy_label() {
        assert_eq!(
            match_preview_host(
                "api-server-env_1-kind-e2e.codewire-dev.local:8080",
                "codewire-dev.local",
                [
                    ("short".to_string(), "e2e".to_string()),
                    ("long".to_string(), "kind-e2e".to_string())
                ]
            ),
            Ok(Some(PreviewHostMatch {
                org_id: "long".to_string(),
                label: "api-server".to_string(),
                env_prefix: "env_1".to_string()
            }))
        );
    }

    #[tokio::test]
    async fn preview_body_bridges_forward_each_chunk_before_end_of_stream() {
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
        let request = Body::from_stream(ReceiverStream::new(request_rx));
        let mut forwarded_request = Body::new(stream_preview_request(request)).into_data_stream();

        request_tx
            .send(Ok::<_, io::Error>(Bytes::from_static(b"request-one")))
            .await
            .unwrap();
        assert_eq!(
            next_chunk(&mut forwarded_request).await,
            Bytes::from_static(b"request-one")
        );
        request_tx
            .send(Ok::<_, io::Error>(Bytes::from_static(b"request-two")))
            .await
            .unwrap();
        assert_eq!(
            next_chunk(&mut forwarded_request).await,
            Bytes::from_static(b"request-two")
        );

        let (response_tx, response_rx) = tokio::sync::mpsc::channel(1);
        let mut forwarded_response =
            stream_preview_response(ReceiverStream::new(response_rx), "env_test".to_string())
                .into_data_stream();

        response_tx
            .send(Ok::<_, io::Error>(Bytes::from_static(b"response-one")))
            .await
            .unwrap();
        assert_eq!(
            next_chunk(&mut forwarded_response).await,
            Bytes::from_static(b"response-one")
        );
        response_tx
            .send(Ok::<_, io::Error>(Bytes::from_static(b"response-two")))
            .await
            .unwrap();
        assert_eq!(
            next_chunk(&mut forwarded_response).await,
            Bytes::from_static(b"response-two")
        );
    }

    #[test]
    fn private_preview_overrides_hostile_cache_headers_including_not_modified() {
        for status in [StatusCode::OK, StatusCode::NOT_MODIFIED] {
            let mut response = Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap();
            for name in [
                "cache-control",
                "surrogate-control",
                "cdn-cache-control",
                "cloudflare-cdn-cache-control",
            ] {
                response.headers_mut().append(
                    HeaderName::from_static(name),
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response.headers_mut().append(
                    HeaderName::from_static(name),
                    HeaderValue::from_static("s-maxage=86400"),
                );
            }
            let response = private_response(response);
            assert_eq!(response.status(), status);
            for name in [
                "cache-control",
                "surrogate-control",
                "cdn-cache-control",
                "cloudflare-cdn-cache-control",
            ] {
                assert_eq!(response.headers()[name], "private, no-store");
                assert_eq!(response.headers().get_all(name).iter().count(), 1);
            }
            assert_eq!(response.headers()[header::EXPIRES], "0");
        }
    }

    #[test]
    fn preview_response_preserves_end_to_end_headers_and_filters_hop_by_hop_headers() {
        let headers = HeaderMap::from_iter([
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            ),
            (header::CONNECTION, HeaderValue::from_static("keep-alive")),
            (
                HeaderName::from_static("x-upstream"),
                HeaderValue::from_static("preserved"),
            ),
        ]);

        let response = preview_response_builder(
            StatusCode::PARTIAL_CONTENT,
            &headers,
            "web-abcde-org.preview.test",
        )
        .body(Body::empty())
        .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/event-stream"))
        );
        assert_eq!(
            response.headers().get("x-upstream"),
            Some(&HeaderValue::from_static("preserved"))
        );
        assert_eq!(
            response.headers().get(PREVIEW_SERVICE_HEADER),
            Some(&HeaderValue::from_static(PREVIEW_SERVICE_NAME))
        );
        assert!(!response.headers().contains_key(header::CONNECTION));
    }

    async fn next_chunk<S>(stream: &mut S) -> Bytes
    where
        S: futures_util::Stream<Item = Result<Bytes, axum::Error>> + Unpin,
    {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("body bridge waited for end-of-stream")
            .expect("body bridge ended before the next chunk")
            .expect("body bridge returned an error")
    }
}
