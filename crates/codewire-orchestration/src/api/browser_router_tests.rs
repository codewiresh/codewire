//! The raw browser routes, served through [`super::router`] as `main` mounts
//! them, never answer with anything a shared cache may store
//! (`docs/dev/AUTH-POLICY.md`, #5054). Signing in needs the database, so
//! these drive the answers a caller gets before it: no credential, and a
//! credential the closed pool cannot check.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use sqlx::PgPool;
use tower::ServiceExt;

use super::{ApiState, router};

const SSH_PROXY_CHECK: &str =
    "/api/v1/organizations/org-no-store/environments/env-no-store/ssh-proxy/check";

/// Every dependency is local or offline, and the pool is closed, so a
/// request that reaches the database fails at once.
pub(super) async fn state() -> ApiState {
    let pool = PgPool::connect_lazy("postgres://synthetic@127.0.0.1:1/none").unwrap();
    pool.close().await;
    super::test_state::offline(pool).await
}

async fn get(path: &str, bearer: Option<&str>) -> Response {
    let mut request = Request::get(path);
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let state = state().await;
    router(state.clone(), state.auth.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn assert_never_shared_cached(response: &Response) {
    let headers = response.headers();
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store, private"
    );
    assert!(headers.get(header::ETAG).is_none());
    assert!(headers.get(header::LAST_MODIFIED).is_none());
}

#[tokio::test]
async fn ssh_proxy_check_is_never_shared_cached() {
    for bearer in [None, Some("synthetic-unverifiable-access-token")] {
        let response = get(SSH_PROXY_CHECK, bearer).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{bearer:?}");
        assert_never_shared_cached(&response);
    }
}

#[tokio::test]
async fn every_browser_route_refusal_is_never_shared_cached() {
    for path in [
        "/api/v1/organizations/org-no-store/environments/env-no-store/terminal",
        "/api/v1/organizations/org-no-store/environments/env-no-store/ssh-proxy",
        "/api/v1/preview-auth/authorize?challenge=synthetic",
    ] {
        let response = get(path, None).await;
        assert!(
            response.status().is_client_error(),
            "{path}: {}",
            response.status()
        );
        assert_never_shared_cached(&response);
    }
}
