//! Shared orchestration service logic and permanent browser-facing routes.
//!
//! Connect owns every control-plane procedure. This module continues to host
//! their shared domain implementations and the deliberately non-RPC browser,
//! OAuth, and SSH transports.

pub(crate) mod account;
pub mod admin;
pub mod api_keys;
pub mod assignments;
pub mod create;
pub mod detect;
pub mod env_access;
pub mod environment_daemon;
pub mod environment_resize;
pub mod environments;
pub mod github;
pub mod internal;
pub mod logs;
pub mod organizations;
pub mod ports;
pub mod prepare;
pub mod presets;
pub mod preview;
pub mod proxy;
pub mod secret_projects;
pub mod secrets;
pub mod ssh_proxy;
pub mod terminal;
pub mod trust_report;

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use codewire_server_core::auth::{AuthState, require_account_auth, require_auth};
use sqlx::PgPool;

use crate::confidential_storage::FeatureFlags;
use crate::temporal::TemporalTrigger;
use crate::worker::create::SandboxWorkerCfg;
use crate::worker::github::GitHubAppConfig;
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
    /// ANTHROPIC_API_KEY (Go: cfg.AnthropicAPIKey); empty disables the
    /// smart-create detection path with ai_detection_unavailable.
    pub anthropic_api_key: String,
    /// GitHub App credentials for forge-token resolution.
    pub github_cfg: GitHubAppConfig,
    /// Tenant secret store for forge tokens.
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
    /// Shared session secret (Go: cfg.SessionSecret). Used by the
    /// internal gateway-binding endpoint to issue coordinate-scoped
    /// sidecar tokens (Go: gatewayservice.NewInProcessService).
    pub session_secret: String,
    /// Sandbox/runtime config slice used by internal gateway binding
    /// to publish dynamic transport endpoints for this environment.
    pub sandbox_cfg: SandboxWorkerCfg,
    /// Disabled-by-default confidential storage product gates.
    pub confidential_storage_flags: FeatureFlags,
}

/// The deliberately permanent browser-facing routes.
///
/// Connect-RPC owns control-plane procedures. OAuth redirects and browser
/// terminal/SSH transports remain raw by design.
pub fn router(state: ApiState, auth: AuthState) -> Router {
    let raw = Router::new()
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
        .route(
            "/api/v1/github/oauth/callback",
            get(github::github_oauth_callback),
        );

    // The OAuth redirect start still needs an account session. Its callback is
    // deliberately outside this layer because it is the browser return path.
    let account = Router::new()
        .route(
            "/api/v1/github/oauth/authorize",
            get(github::github_oauth_authorize),
        )
        .route_layer(middleware::from_fn(require_account_auth))
        .route_layer(middleware::from_fn_with_state(auth, require_auth));

    raw.merge(account).with_state(state)
}
