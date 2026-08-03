//! Route registry and naming conventions.
//!
//! Each product lane owns a route module. Browser mutations live below that
//! route's `/_actions/` namespace, partial HTML below `/_fragments/`, and
//! server-sent event streams below `/_events/`. Public page URLs stay clean,
//! and later lanes add their route constants here only when integrating.

mod admin;
mod authentication;
mod billing;
mod dashboard;
mod device;
mod environments;
mod invitations;
mod organization_governance;
mod organizations;
mod public;
mod secrets_presets;
mod settings;
mod terminal;

use axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};

use crate::state::AppState;

pub(crate) const DASHBOARD_PATH: &str = "/dashboard";
pub(crate) const ORGANIZATIONS_FRAGMENT_PATH: &str = "/dashboard/_fragments/organizations";
pub(crate) const NEW_ORGANIZATION_PATH: &str = "/dashboard/orgs/new";
pub(crate) const CREATE_ORGANIZATION_ACTION_PATH: &str = "/dashboard/_actions/organizations";

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(public::home))
        .route("/verify-email", get(public::verify_email))
        .route("/login", get(authentication::login))
        .route(
            "/login/_actions/sign-in",
            post(authentication::login_action),
        )
        .route("/signup", get(authentication::signup))
        .route(
            "/signup/_actions/sign-up",
            post(authentication::signup_action),
        )
        .route("/forgot-password", get(authentication::forgot_password))
        .route(
            "/forgot-password/_actions/request",
            post(authentication::forgot_password_action),
        )
        .route("/reset-password", get(authentication::reset_password))
        .route(
            "/reset-password/_actions/reset",
            post(authentication::reset_password_action),
        )
        .route("/two-factor", get(authentication::two_factor))
        .route(
            "/two-factor/_actions/validate",
            post(authentication::two_factor_action),
        )
        .route("/setup-2fa", get(authentication::setup_two_factor))
        .route(
            "/setup-2fa/_actions/verify",
            post(authentication::setup_two_factor_action),
        )
        .route("/device", get(device::device))
        .route("/device/_actions/approve", post(device::approve))
        .route("/accept-invite", get(invitations::invitation_page))
        .route("/accept-invite/_actions/accept", post(invitations::accept))
        .route(DASHBOARD_PATH, get(dashboard::dashboard))
        .route("/admin", get(admin::overview))
        .route("/admin/", get(admin::overview))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/billing", get(admin::billing))
        .route(
            "/admin/billing/_actions/plans/create",
            post(admin::create_plan),
        )
        .route(
            "/admin/billing/_actions/plans/update",
            post(admin::update_plan),
        )
        .route(
            "/admin/billing/_actions/plans/archive",
            post(admin::archive_plan),
        )
        .route(
            "/admin/billing/_actions/prices/create",
            post(admin::create_price),
        )
        .route(
            "/admin/billing/_actions/prices/update",
            post(admin::update_price),
        )
        .route(
            "/admin/billing/_actions/prices/archive",
            post(admin::archive_price),
        )
        .route(
            "/admin/billing/_actions/settings/update",
            post(admin::update_setting),
        )
        .route(
            "/admin/billing/_actions/migrations/preview",
            post(admin::preview_migration),
        )
        .route(
            "/admin/billing/_actions/migrations/run",
            post(admin::run_migration),
        )
        .route(
            ORGANIZATIONS_FRAGMENT_PATH,
            get(organizations::organization_fragment),
        )
        .route(NEW_ORGANIZATION_PATH, get(organizations::new_organization))
        .route(
            CREATE_ORGANIZATION_ACTION_PATH,
            post(organizations::create_organization),
        )
        .route(
            "/dashboard/orgs/{slug}",
            get(organization_governance::organization_root),
        )
        .route(
            "/dashboard/orgs/{slug}/members",
            get(organization_governance::members_page),
        )
        .route(
            "/dashboard/orgs/{slug}/members/_actions/invite",
            post(organization_governance::invite_member),
        )
        .route(
            "/dashboard/orgs/{slug}/members/_actions/role",
            post(organization_governance::update_role),
        )
        .route(
            "/dashboard/orgs/{slug}/members/_actions/assignments",
            post(organization_governance::update_assignments),
        )
        .route(
            "/dashboard/orgs/{slug}/members/_actions/remove",
            post(organization_governance::remove_member),
        )
        .route(
            "/dashboard/orgs/{slug}/members/_actions/revoke-invitation",
            post(organization_governance::revoke_invitation),
        )
        .route(
            "/dashboard/orgs/{slug}/api-keys",
            get(organization_governance::api_keys_page),
        )
        .route(
            "/dashboard/orgs/{slug}/api-keys/_actions/create",
            post(organization_governance::create_api_key),
        )
        .route(
            "/dashboard/orgs/{slug}/api-keys/_actions/toggle",
            post(organization_governance::toggle_api_key),
        )
        .route(
            "/dashboard/orgs/{slug}/api-keys/_actions/delete",
            post(organization_governance::delete_api_key),
        )
        .route("/dashboard/orgs/{slug}/billing", get(billing::page))
        .route(
            "/dashboard/orgs/{slug}/billing/_actions/portal",
            post(billing::portal),
        )
        .route(
            "/dashboard/orgs/{slug}/billing/_actions/setup",
            post(billing::setup),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets",
            get(secrets_presets::secrets_page),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/_actions/projects/create",
            post(secrets_presets::create_secret_project),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/_actions/projects/delete",
            post(secrets_presets::delete_secret_project),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/{bucket}",
            get(secrets_presets::secret_bucket_page),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/{bucket}/_actions/set",
            post(secrets_presets::set_secret),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/{bucket}/_actions/rename",
            post(secrets_presets::rename_secret),
        )
        .route(
            "/dashboard/orgs/{slug}/secrets/{bucket}/_actions/delete",
            post(secrets_presets::delete_secret),
        )
        .route(
            "/dashboard/orgs/{slug}/presets",
            get(secrets_presets::presets_page),
        )
        .route(
            "/dashboard/orgs/{slug}/presets/_actions/update",
            post(secrets_presets::update_preset),
        )
        .route(
            "/dashboard/orgs/{slug}/presets/_actions/delete",
            post(secrets_presets::delete_preset),
        )
        .route(
            "/dashboard/orgs/{slug}/environments",
            get(environments::page),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_fragments/list",
            get(environments::list_fragment),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/prepare",
            post(environments::prepare),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_events/prepare",
            post(environments::prepare_events),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/create",
            post(environments::create),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/secret-projects/create",
            post(environments::create_secret_project),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/start",
            post(environments::start),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/stop",
            post(environments::stop),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/delete",
            post(environments::delete),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/ports/create",
            post(environments::create_port),
        )
        .route(
            "/dashboard/orgs/{slug}/environments/_actions/ports/delete",
            post(environments::delete_port),
        )
        .route("/terminal/{org_id}/{environment_id}", get(terminal::page))
        .route("/dashboard/settings", get(settings::settings))
        .route(
            "/dashboard/settings/_actions/github/disconnect",
            post(settings::disconnect_github_action),
        )
        .route(
            "/dashboard/settings/_actions/credentials/create",
            post(settings::create_credential_action),
        )
        .route(
            "/dashboard/settings/_actions/credentials/delete",
            post(settings::delete_credential_action),
        )
        .route(
            "/dashboard/settings/_actions/git-identity",
            post(settings::update_identity_action),
        )
        .route(
            "/dashboard/settings/_actions/ssh/ensure",
            post(settings::ensure_ssh_action),
        )
        .route(
            "/dashboard/settings/_actions/ssh/regenerate",
            post(settings::regenerate_ssh_action),
        )
        .route(
            "/dashboard/settings/_actions/sign-out",
            post(authentication::sign_out_action),
        )
        .route("/settings/account", get(settings::account))
        .route("/settings/security", get(settings::security))
        .route("/settings/sessions", get(settings::sessions))
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}
