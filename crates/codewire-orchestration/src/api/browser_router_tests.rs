//! The raw browser routes, served through [`super::router`] as `main` mounts
//! them, never answer with anything a shared cache may store
//! (`docs/dev/AUTH-POLICY.md`, #5054). Signing in needs the database, so
//! these drive the answers a caller gets before it: no credential, and a
//! credential the closed pool cannot check.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_server_core::auth::AuthState;
use sqlx::PgPool;
use tower::ServiceExt;

use super::{ApiState, router};

const SSH_PROXY_CHECK: &str =
    "/api/v1/organizations/org-no-store/environments/env-no-store/ssh-proxy/check";

/// Every dependency is local or offline, and the pool is closed, so a
/// request that reaches the database fails at once.
async fn state() -> ApiState {
    let pool = PgPool::connect_lazy("postgres://synthetic@127.0.0.1:1/none").unwrap();
    pool.close().await;
    let session_secret = "synthetic-no-store-session-secret".to_string();
    ApiState {
        credit_enforcement: Default::default(),
        pool: pool.clone(),
        preview_base_domain: "preview.test".to_string(),
        frontend_url: "https://dashboard.example.test".to_string(),
        http_client: reqwest::Client::new(),
        preview_upstream: super::preview::PreviewUpstream::new(
            pool.clone(),
            None,
            session_secret.clone(),
            Default::default(),
        ),
        temporal_trigger: Arc::new(crate::temporal::tests::offline_trigger().await),
        secrets: Arc::new(crate::worker::secrets::SecretStore::new_for_test(
            pool.clone(),
            Arc::new(TestKekProvider),
        )),
        auth: AuthState { pool: pool.clone() },
        kube: None,
        runtime: None,
        environment_daemon_endpoints: Default::default(),
        session_secret,
        terminal_ticket_replays: Arc::default(),
        org_slugs: Arc::new(super::preview::OrgSlugCache::new(Duration::from_secs(5))),
        sandbox_cfg: Default::default(),
        confidential_storage_flags: crate::confidential_storage::FeatureFlags { enabled: false },
        network_policy_flags: Default::default(),
        environment_logs: super::log_notifications::EnvironmentLogNotifications::new(1),
        drain: Default::default(),
        cw_runtime_staging: super::cw_runtime::staging::Staging::removed(),
        revocation: codewire_server_core::revocation::Fence::new(),
    }
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
