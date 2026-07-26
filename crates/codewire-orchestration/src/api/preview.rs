//! Host-based app preview proxy, ported from `environment_preview.go`.

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::Row;

use super::ApiState;
use super::environments::require_environment_access;
use super::prepare::plain_error;
use super::terminal::authenticate_socket_request;

const PREVIEW_SERVICE_HEADER: &str = "x-codewire-service";
const PREVIEW_SERVICE_NAME: &str = "codewire-orchestration";

#[derive(Debug, Clone)]
struct PreviewTarget {
    port: i32,
    env_id: String,
    access: String,
    created_by: String,
    pod_ip: String,
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

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = request.into_body();

    let host_match = match resolve_preview_host(&state, &host).await {
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

    let target = match resolve_preview_target(&state, &host_match).await {
        Ok(target) => target,
        Err(response) => return response,
    };

    if target.access != "public" {
        let user = match authenticate_socket_request(&state, &headers, "").await {
            Ok(user) => user,
            Err(response) if response.status() == StatusCode::UNAUTHORIZED => {
                return redirect_to_login(&state.frontend_url, uri.to_string().as_str());
            }
            Err(response) => return response,
        };

        // API keys are capabilities for exactly one organization. Enforce
        // that boundary before creator/member shortcuts can grant access to
        // an environment owned by the same user in another organization.
        if !user.permits_organization(&host_match.org_id) {
            return preview_error(
                StatusCode::FORBIDDEN,
                "forbidden: API key belongs to another organization",
            );
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
                return preview_error(
                    StatusCode::FORBIDDEN,
                    "forbidden: no access to this environment",
                );
            }
        } else if target.access == "creator" && user.user_id != target.created_by {
            return preview_error(
                StatusCode::FORBIDDEN,
                "forbidden: only the creator can access this preview",
            );
        }
    }

    proxy_to_preview_target(&state, method, uri, headers, body, &host, &target).await
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
    state: &ApiState,
    host: &str,
) -> Result<Option<PreviewHostMatch>, PreviewHostError> {
    let rows = sqlx::query("SELECT id, slug FROM organizations ORDER BY length(slug) DESC")
        .fetch_all(&state.pool)
        .await
        .map_err(|_| PreviewHostError::Internal)?;
    let orgs = rows.iter().filter_map(|row| {
        let id: String = row.try_get("id").ok()?;
        let slug: String = row.try_get("slug").ok()?;
        Some((id, slug))
    });
    match_preview_host(host, &state.preview_base_domain, orgs)
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
    state: &ApiState,
    host_match: &PreviewHostMatch,
) -> Result<PreviewTarget, Response> {
    let row = sqlx::query(
        r#"SELECT ep.port, e.id, ep.access, e.created_by, e.state,
                  COALESCE(b.pod_ip, '') AS pod_ip
             FROM environment_ports ep
             JOIN environments e ON e.id = ep.environment_id
             LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
            WHERE ep.label = $1
              AND e.id LIKE $2
              AND e.org_id = $3"#,
    )
    .bind(&host_match.label)
    .bind(format!("{}%", host_match.env_prefix))
    .bind(&host_match.org_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| preview_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;

    let Some(row) = row else {
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
    })
}

async fn proxy_to_preview_target(
    state: &ApiState,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Body,
    original_host: &str,
    target: &PreviewTarget,
) -> Response {
    let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    let target_url = format!("http://{}:{}{}", target.pod_ip, target.port, path_and_query);

    let Ok(method) = method.as_str().parse::<reqwest::Method>() else {
        return preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable");
    };
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(env = %target.env_id, error = %err, "preview proxy body read failed");
            return preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable");
        }
    };

    let mut req = state.http_client.request(method, target_url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST {
            continue;
        }
        req = req.header(name.as_str(), value.as_bytes());
    }
    req = req
        .header(header::HOST.as_str(), original_host)
        .header("x-forwarded-host", original_host)
        .header("x-forwarded-proto", "https")
        .body(body_bytes);

    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(env = %target.env_id, error = %err, "preview proxy error");
            return preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable");
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers().iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    builder = builder.header(PREVIEW_SERVICE_HEADER, PREVIEW_SERVICE_NAME);

    match resp.bytes().await {
        Ok(bytes) => builder.body(Body::from(bytes)).unwrap_or_else(|_| {
            preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable")
        }),
        Err(err) => {
            tracing::warn!(env = %target.env_id, error = %err, "preview proxy response read failed");
            preview_error(StatusCode::BAD_GATEWAY, "preview backend unreachable")
        }
    }
}

fn preview_error(status: StatusCode, message: &'static str) -> Response {
    let mut response = plain_error(status, message);
    response.headers_mut().insert(
        HeaderName::from_static(PREVIEW_SERVICE_HEADER),
        HeaderValue::from_static(PREVIEW_SERVICE_NAME),
    );
    response
}

fn redirect_to_login(frontend_url: &str, redirect_uri: &str) -> Response {
    let frontend = frontend_url.trim_end_matches('/');
    let encoded: String = url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect();
    let location = format!("{frontend}/sign-in?redirect_uri={encoded}");
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location.as_str())
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(PREVIEW_SERVICE_HEADER, PREVIEW_SERVICE_NAME)
        .body(Body::from(format!(
            r#"<a href="{location}">Found</a>.

"#
        )))
        .expect("static redirect")
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
    use super::*;

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
}
