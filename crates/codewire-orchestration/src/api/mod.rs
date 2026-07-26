//! The environments HTTP surface (#38), served by the orchestration service.
//! Handlers prove the Rust wire contract through the contract suite and
//! migration integration gate.

pub(crate) mod account;
pub mod admin;
pub mod api_keys;
pub mod assignments;
pub mod contract;
pub mod create;
pub mod detect;
pub mod env_access;
pub mod environment_daemon;
pub mod environments;
pub mod git_credentials;
pub mod github;
pub mod internal;
pub mod login_keys;
pub mod logs;
pub mod organizations;
pub mod ports;
pub mod prepare;
pub mod presets;
pub mod preview;
pub mod proxy;
pub mod repo_configs;
pub mod secret_projects;
pub mod secrets;
pub mod ssh_keys;
pub mod ssh_proxy;
pub mod terminal;
pub mod trust_report;

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use codewire_server_core::auth::{AuthState, require_account_auth, require_admin, require_auth};
use codewire_server_core::rest_sunset::{RestSunsetConfig, observe as observe_rest_sunset};
use sqlx::PgPool;

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
    /// Tenant secret store (Infisical or local) for forge tokens.
    pub secrets: Arc<SecretStore>,
    /// Auth state for the raw prepare handler (it authenticates
    /// manually to reproduce Go's http.Error rejection bodies).
    pub auth: AuthState,
    /// Ambient kube client for the exec/file proxy routes; None mirrors
    /// Go's nil sandbox client (503 "sandbox client not configured").
    pub kube: Option<KubeClient>,
    /// Shared session secret (Go: cfg.SessionSecret). Used by the
    /// internal gateway-binding endpoint to issue coordinate-scoped
    /// sidecar tokens (Go: gatewayservice.NewInProcessService).
    pub session_secret: String,
    /// Sandbox/runtime config slice used by internal gateway binding
    /// to publish dynamic transport endpoints for this environment.
    pub sandbox_cfg: SandboxWorkerCfg,
}

/// Authenticated environments routes. Org membership/access checks
/// live in the handlers, mirroring the Go registration. The prepare
/// route sits OUTSIDE require_auth: it authenticates manually with
/// Go's raw-handler rejection bodies.
pub fn router(state: ApiState, auth: AuthState, rest_sunset: RestSunsetConfig) -> Router {
    let raw = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/environment-create/prepare",
            post(prepare::prepare_environment_create),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/logs",
            get(logs::environment_logs),
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
        // Internal sidecar endpoints (#140): authenticated by the
        // environment's auth_token (Bearer) or pod-keyed lookup, NOT a
        // user session — so they sit OUTSIDE require_auth alongside the
        // other raw handlers, mirroring the Go chi registration.
        .route(
            "/api/v1/internal/gateway/binding",
            get(internal::gateway_binding),
        )
        .route(
            "/api/v1/internal/credentials/github",
            get(internal::internal_github_credentials),
        )
        .route(
            "/api/v1/internal/credentials/git",
            get(internal::internal_git_credentials),
        )
        .route(
            "/api/v1/github/oauth/callback",
            get(github::github_oauth_callback),
        )
        // Public (unauthenticated) invitation lookup by token — Go's
        // registerPublicInvitationRoutes. Sits outside require_auth.
        .route(
            "/api/v1/invitations/{token}",
            get(organizations::get_invitation_by_token),
        )
        .with_state(state.clone());

    // Admin-only reads (#38): is_admin-gated, so require_admin layers on
    // top of the require_auth applied to the merged surface below — the
    // same chain as the Go `adminSecurity` (requireAuth → requireAdmin).
    let admin = Router::new()
        .route("/api/v1/admin/stats", get(admin::get_admin_stats))
        .route(
            "/api/v1/admin/organizations",
            get(admin::list_admin_organizations),
        )
        .route("/api/v1/admin/audit-logs", get(admin::list_audit_logs))
        .route(
            "/api/v1/admin/environments/{environment_id}/lifecycle-journal",
            get(admin::list_admin_environment_lifecycle_journal),
        )
        .route(
            "/api/v1/admin/environments/startup-summary",
            get(admin::get_admin_environment_startup_summary),
        )
        .route(
            "/api/v1/admin/environments/{environment_id}/startup-timings",
            get(admin::get_admin_environment_startup_timings),
        )
        .route_layer(middleware::from_fn(require_admin));

    // Account-global user operations never accept an org-scoped API key.
    // Keep this as an explicit route group so adding a new unscoped endpoint
    // requires a visible policy choice rather than silently inheriting key
    // authority from the owning user.
    let account = Router::new()
        .route(
            "/api/v1/environment-create/detect",
            post(prepare::detect_environment_repo),
        )
        .route("/api/v1/github/config", get(github::get_github_config))
        .route("/api/v1/github/status", get(github::get_github_status))
        .route("/api/v1/github/repos", get(github::list_github_repos))
        .route(
            "/api/v1/github/oauth/authorize",
            get(github::github_oauth_authorize),
        )
        .route(
            "/api/v1/github/token",
            post(github::save_github_token).delete(github::delete_github_token),
        )
        .route("/api/v1/terminal/ticket", post(terminal::terminal_ticket))
        .route(
            "/api/v1/user/login-keys",
            get(login_keys::list_login_keys).post(login_keys::add_login_key),
        )
        .route(
            "/api/v1/user/login-keys/{id}",
            axum::routing::delete(login_keys::delete_login_key),
        )
        .route("/api/v1/user/ssh-key", get(ssh_keys::get_ssh_key))
        .route(
            "/api/v1/user/ssh-key/regenerate",
            post(ssh_keys::regenerate_ssh_key),
        )
        .route(
            "/api/v1/user/git-identity",
            get(ssh_keys::get_git_identity).put(ssh_keys::update_git_identity),
        )
        .route(
            "/api/v1/git-credentials",
            get(git_credentials::list_git_credentials).post(git_credentials::create_git_credential),
        )
        .route(
            "/api/v1/git-credentials/{credential_id}",
            axum::routing::put(git_credentials::update_git_credential)
                .delete(git_credentials::delete_git_credential),
        )
        .route(
            "/api/v1/user/secrets",
            get(secrets::list_user_secrets).put(secrets::set_user_secret),
        )
        .route(
            "/api/v1/user/secrets/{key}",
            axum::routing::delete(secrets::delete_user_secret),
        )
        .route(
            "/api/v1/user/secrets/{key}/rename",
            post(secrets::rename_user_secret),
        )
        .route(
            "/api/v1/organizations",
            post(organizations::create_organization),
        )
        .route(
            "/api/v1/invitations/{token}/accept",
            post(organizations::accept_invitation),
        )
        .route_layer(middleware::from_fn(require_account_auth));

    let authenticated = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/environment-create/options",
            get(prepare::get_create_options),
        )
        .route(
            "/api/v1/organizations/{org_id}/api-keys",
            get(api_keys::list_api_keys).post(api_keys::create_api_key),
        )
        .route(
            "/api/v1/organizations/{org_id}/api-keys/{key_id}",
            axum::routing::patch(api_keys::update_api_key).delete(api_keys::delete_api_key),
        )
        .route(
            "/api/v1/organizations/{org_id}/presets",
            get(presets::list_presets_handler).post(presets::create_preset),
        )
        .route(
            "/api/v1/organizations/{org_id}/presets/{preset_id}",
            get(presets::get_preset_handler)
                .patch(presets::update_preset_handler)
                .delete(presets::delete_preset_handler),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/ports",
            get(ports::list_ports).post(ports::create_port),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/ports/{port_id}",
            axum::routing::delete(ports::delete_port),
        )
        .route(
            "/api/v1/organizations/{org_id}/repo-configs/lookup",
            get(repo_configs::lookup_repo_config),
        )
        .route(
            "/api/v1/organizations/{org_id}/repo-configs",
            get(repo_configs::list_repo_configs).put(repo_configs::upsert_repo_config),
        )
        .route(
            "/api/v1/organizations/{org_id}/repo-configs/{config_id}",
            axum::routing::delete(repo_configs::delete_repo_config),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/exec",
            post(proxy::exec_in_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/exec/stream",
            post(proxy::exec_stream),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/files/cat",
            get(proxy::download_file_exec),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/files",
            get(proxy::list_files),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/files/upload",
            post(proxy::upload_file),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/files/download",
            get(proxy::download_file),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments",
            get(environments::list_environments).post(create::create_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}",
            get(environments::get_environment).delete(environments::delete_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/trust-report",
            get(trust_report::get_environment_trust_report),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/stop",
            post(environments::stop_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/start",
            post(environments::start_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/protect",
            post(environments::protect_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/unprotect",
            post(environments::unprotect_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/cancel-deletion",
            post(environments::cancel_environment_deletion),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/extend-ttl",
            post(environments::extend_environment_ttl),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/access",
            get(env_access::list_environment_access).post(env_access::grant_environment_access),
        )
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/access/{user_id}",
            axum::routing::delete(env_access::revoke_environment_access),
        )
        .route(
            "/api/v1/organizations/{org_id}/secret-projects",
            get(secret_projects::list_secret_projects).post(secret_projects::create_secret_project),
        )
        .route(
            "/api/v1/secrets",
            get(secrets::list_secrets).put(secrets::set_secret),
        )
        .route(
            "/api/v1/secrets/{key}",
            axum::routing::delete(secrets::delete_secret),
        )
        .route("/api/v1/secrets/{key}/rename", post(secrets::rename_secret))
        .route(
            "/api/v1/organizations/{org_id}/secret-projects/{project_id}",
            axum::routing::delete(secret_projects::delete_secret_project),
        )
        .route(
            "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets",
            get(secret_projects::list_project_secrets).put(secret_projects::set_project_secret),
        )
        .route(
            "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets/{key}",
            axum::routing::delete(secret_projects::delete_project_secret),
        )
        .route(
            "/api/v1/organizations/{org_id}/secret-projects/{project_id}/secrets/{key}/rename",
            post(secret_projects::rename_project_secret),
        )
        .route(
            "/api/v1/organizations",
            get(organizations::list_organizations),
        )
        .route(
            "/api/v1/organizations/{org_id}",
            get(organizations::get_organization).delete(organizations::delete_organization),
        )
        .route(
            "/api/v1/organizations/{org_id}/members",
            get(organizations::list_members),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{member_id}/assignments",
            get(assignments::get_member_assignments).put(assignments::update_member_assignments),
        )
        // The `{member_id}` segment label here is the USER id (Go's
        // `{userId}` for updateMemberRole/removeMember); the name only
        // matches the assignments route above to satisfy the router's
        // shared-segment-name rule.
        .route(
            "/api/v1/organizations/{org_id}/members/{member_id}",
            axum::routing::put(organizations::update_member_role)
                .delete(organizations::remove_member),
        )
        .route(
            "/api/v1/organizations/{org_id}/invitations",
            get(organizations::list_invitations).post(organizations::create_invitation),
        )
        .route(
            "/api/v1/organizations/{org_id}/invitations/{invitation_id}",
            axum::routing::delete(organizations::revoke_invitation),
        )
        .merge(admin)
        .merge(account);

    observe_rest_sunset(authenticated, rest_sunset)
        .route_layer(middleware::from_fn_with_state(auth, require_auth))
        .with_state(state)
        .merge(observe_rest_sunset(raw, rest_sunset))
}
