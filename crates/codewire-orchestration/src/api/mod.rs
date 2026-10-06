//! Shared orchestration service logic and permanent browser-facing routes.
//!
//! Connect owns every control-plane procedure. This module continues to host
//! their shared domain implementations and the deliberately non-RPC browser
//! terminal/SSH transports and scoped preview-browser authorization.

pub(crate) mod account;
pub mod admin;
pub mod api_keys;
pub mod assignments;
pub mod create;
pub mod env_access;
pub mod environment_daemon;
pub mod environment_resize;
pub mod environment_sources;
pub mod environments;
pub mod host_key;
pub mod log_notifications;
pub mod logs;
pub mod organizations;
pub mod ports;
pub mod prepare;
pub mod presets;
pub mod preview;
pub mod proxy;
#[cfg(test)]
mod runtime_lease_test_support;
pub mod secret_projects;
pub mod secrets;
pub mod ssh_proxy;
pub mod terminal;
pub mod trust_report;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use codewire_server_core::auth::AuthState;
use sqlx::PgPool;

use crate::confidential_storage::FeatureFlags;
use crate::temporal::TemporalTrigger;
use crate::worker::create::SandboxWorkerCfg;
use crate::worker::secrets::SecretStore;
use kube::Client as KubeClient;

// (No FromRef: two String fields would collide; handlers take
// State<ApiState> whole.)
#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    /// PREVIEW_BASE_DOMAIN, for port preview URLs (Go:
    /// cfg.PreviewBaseDomain).
    pub preview_base_domain: String,
    /// FRONTEND_URL, used for private preview sign-in redirects.
    pub frontend_url: String,
    /// Reusable HTTP client for app preview reverse proxy requests.
    pub http_client: reqwest::Client,
    /// The lifecycle trigger: Temporal is the only orchestrator, so this
    /// is always present (the binary fails fast if it can't connect).
    pub temporal_trigger: Arc<TemporalTrigger>,
    /// Tenant workload-secret store.
    pub secrets: Arc<SecretStore>,
    /// Session/bearer authenticator for the retained browser terminal and SSH
    /// transports. Control-plane procedures use their Connect auth layers.
    pub auth: AuthState,
    /// Ambient kube client for the exec/file proxy routes; None mirrors
    /// Go's nil sandbox client (503 "sandbox client not configured").
    pub kube: Option<KubeClient>,
    /// Cluster-local daemon resolution plus a loopback-only external wire-test
    /// override that cannot be enabled without CONNECT_TESTING_SURFACE=1.
    pub environment_daemon_endpoints: environment_daemon::EnvironmentDaemonEndpointOverrides,
    /// Shared session secret for daemon tokens and preview authorization.
    pub session_secret: String,
    /// Sandbox/runtime config slice: the daemon support image and the
    /// workspace-binding listener's namespace and relay endpoints.
    pub sandbox_cfg: SandboxWorkerCfg,
    /// Disabled-by-default confidential storage product gates.
    pub confidential_storage_flags: FeatureFlags,
    /// The process-wide environment-log listener fan-out and the
    /// per-account bound on live StreamLogs follows.
    pub environment_logs: Arc<log_notifications::EnvironmentLogNotifications>,
}

/// The deliberately permanent browser-facing routes.
///
/// Connect-RPC owns control-plane procedures. Browser terminal/SSH transports
/// and the session-owned preview handoff remain raw by design.
pub fn router(state: ApiState, _auth: AuthState) -> Router {
    Router::new()
        // Deliberately raw browser authorization transport, not a general
        // credential API. Session authority stays on FRONTEND_URL's host.
        .route(
            "/api/v1/preview-auth/authorize",
            get(preview::authorization::authorize_page)
                .post(preview::authorization::authorize)
                .layer(axum::extract::DefaultBodyLimit::max(12 * 1024)),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/terminal",
            get(terminal::terminal_websocket),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/ssh-proxy",
            get(ssh_proxy::ssh_proxy_websocket),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/ssh-proxy/check",
            get(ssh_proxy::ssh_proxy_check),
        )
        .with_state(state)
}
