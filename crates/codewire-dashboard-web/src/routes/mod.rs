//! Route registry and naming conventions.
//!
//! Each product lane owns a route module. Browser mutations live below that
//! route's `/_actions/` namespace, partial HTML below `/_fragments/`, and
//! server-sent event streams below `/_events/`. Public page URLs stay clean,
//! and later lanes add their route constants here only when integrating.

mod admin;
mod authentication;
mod billing;
mod credentials;
mod dashboard;
mod device;
mod environment_drafts;
mod environments;
mod github_repositories;
mod hosts;
mod invitations;
mod my_invitations;
mod organization_context;
mod organization_governance;
mod organizations;
mod personal_api_keys;
mod personal_secrets;
mod public;
mod sandbox_resize;
mod secrets_presets;
mod settings;
mod setup_progress;
mod sign_in_methods;
mod snapshots;
mod terminal;
mod terminal_readiness;
mod terminal_sessions;

use axum::{
    Router,
    extract::{DefaultBodyLimit, OriginalUri, Path},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};

use crate::state::AppState;

pub(crate) const DASHBOARD_PATH: &str = "/dashboard/";
pub(crate) const ORGANIZATIONS_FRAGMENT_PATH: &str = "/dashboard/_fragments/organizations";
pub(crate) const ACCOUNT_OVERVIEW_FRAGMENT_PATH: &str = "/dashboard/_fragments/overview";
pub(crate) const NEW_ORGANIZATION_PATH: &str = "/organizations/new/";
pub(crate) const CREATE_ORGANIZATION_ACTION_PATH: &str = "/organizations/_actions/create";

use organization_context::remember as remember_organization_choice;
pub(crate) use organization_context::remember_organization;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(public::home))
        .route("/pricing", get(public::pricing))
        .route("/privacy", get(public::privacy))
        .route("/terms", get(public::terms))
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
        .route("/login/link", get(authentication::link_confirm))
        .route(
            "/login/link/_actions/confirm",
            post(authentication::link_confirm_action),
        )
        .route("/signup/complete", get(authentication::signup_complete))
        .route(
            "/signup/complete/_actions/complete",
            post(authentication::signup_complete_action),
        )
        .route(
            "/login/_actions/resend-verification",
            post(authentication::resend_verification_action),
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
        .route(
            "/setup-2fa/_actions/skip",
            post(authentication::skip_two_factor_setup_action),
        )
        .route("/device", get(device::device))
        .route("/device/_actions/approve", post(device::approve))
        .route("/accept-invite", get(invitations::invitation_page))
        .route("/accept-invite/_actions/accept", post(invitations::accept))
        .route("/dashboard", get(slash_redirect))
        .route(DASHBOARD_PATH, get(dashboard::dashboard))
        .route(
            ACCOUNT_OVERVIEW_FRAGMENT_PATH,
            get(dashboard::overview_fragment),
        )
        .route("/admin", get(slash_redirect))
        .route("/admin/", get(admin::overview))
        .route("/admin/accounts", get(slash_redirect))
        .route("/admin/accounts/", get(admin::accounts))
        .route(
            "/admin/accounts/_actions/enabled",
            post(admin::set_account_enabled),
        )
        .route(
            "/admin/accounts/_actions/resend-verification",
            post(admin::resend_account_verification),
        )
        .route("/admin/organizations", get(slash_redirect))
        .route("/admin/organizations/", get(admin::organizations))
        .route(
            "/admin/organizations/_actions/quota/set",
            post(admin::set_organization_quota),
        )
        .route(
            "/admin/organizations/_actions/quota/clear",
            post(admin::clear_organization_quota),
        )
        .route(
            "/admin/organizations/_actions/confidential/set",
            post(admin::set_organization_confidential),
        )
        .route(
            "/admin/organizations/_actions/rate-card/set",
            post(admin::set_organization_rate_card),
        )
        .route(
            "/admin/organizations/_actions/dedicated-cpu/set",
            post(admin::set_organization_dedicated_cpu),
        )
        .route(
            "/admin/organizations/_actions/credit/adjust",
            post(admin::adjust_organization_credit),
        )
        .route(
            "/admin/organizations/_actions/defaults/set",
            post(admin::set_default_quota),
        )
        .route(
            "/admin/organizations/{organization_id}",
            get(slash_redirect),
        )
        .route(
            "/admin/organizations/{organization_id}/",
            get(admin::organization),
        )
        .route("/admin/audit", get(slash_redirect))
        .route("/admin/audit/", get(admin::audit))
        .route("/admin/billing", get(slash_redirect))
        .route("/admin/billing/", get(admin::billing))
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
        .route("/organizations/new", get(slash_redirect))
        .route(NEW_ORGANIZATION_PATH, get(organizations::new_organization))
        .route(
            CREATE_ORGANIZATION_ACTION_PATH,
            post(organizations::create_organization),
        )
        .route("/{slug}/members", get(slash_redirect))
        .route(
            "/{slug}/members/",
            get(organization_governance::members_page),
        )
        .route(
            "/{slug}/members/_actions/invite",
            post(organization_governance::invite_member),
        )
        .route(
            "/{slug}/members/_actions/role",
            post(organization_governance::update_role),
        )
        .route(
            "/{slug}/members/_actions/assignments",
            post(organization_governance::update_assignments),
        )
        .route(
            "/{slug}/members/_actions/remove",
            post(organization_governance::remove_member),
        )
        .route(
            "/{slug}/members/_actions/revoke-invitation",
            post(organization_governance::revoke_invitation),
        )
        .route("/{slug}/api-keys", get(slash_redirect))
        .route("/settings/api-keys", get(slash_redirect))
        .route("/settings/api-keys/", get(personal_api_keys::page))
        .route(
            "/settings/api-keys/_actions/create",
            post(personal_api_keys::create_action).layer(DefaultBodyLimit::max(8192)),
        )
        .route(
            "/settings/api-keys/_actions/toggle",
            post(personal_api_keys::toggle_action).layer(DefaultBodyLimit::max(8192)),
        )
        .route(
            "/settings/api-keys/_actions/delete",
            post(personal_api_keys::delete_action).layer(DefaultBodyLimit::max(8192)),
        )
        .route(
            "/{slug}/api-keys/",
            get(organization_governance::api_keys_page),
        )
        .route(
            "/{slug}/api-keys/_actions/create",
            post(organization_governance::create_api_key),
        )
        .route(
            "/{slug}/api-keys/_actions/toggle",
            post(organization_governance::toggle_api_key),
        )
        .route(
            "/{slug}/api-keys/_actions/delete",
            post(organization_governance::delete_api_key),
        )
        .route("/{slug}/billing", get(slash_redirect))
        .route("/{slug}/billing/", get(billing::page))
        .route("/{slug}/billing/_actions/portal", post(billing::portal))
        .route("/{slug}/billing/_actions/setup", post(billing::setup))
        .route(
            "/{slug}/billing/_actions/auto-top-up",
            post(billing::auto_top_up),
        )
        .route(
            "/{slug}/billing/_actions/add-credit",
            post(billing::add_credit),
        )
        .route("/{slug}/secrets", get(slash_redirect))
        .route("/{slug}/secrets/", get(secrets_presets::secrets_page))
        // Legacy personal URLs keep no organization authority. Static user
        // aliases use the exact same typed, bounded handlers as Settings.
        .route("/{slug}/secrets/user/", get(personal_secrets::legacy_page))
        .route(
            "/{slug}/secrets/user/_actions/set",
            post(personal_secrets::set_action).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/{slug}/secrets/user/_actions/rename",
            post(personal_secrets::rename_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/{slug}/secrets/user/_actions/delete",
            post(personal_secrets::delete_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/{slug}/secrets/_actions/projects/create",
            post(secrets_presets::create_secret_project),
        )
        .route(
            "/{slug}/secrets/_actions/projects/delete",
            post(secrets_presets::delete_secret_project),
        )
        .route("/{slug}/secrets/{bucket}", get(slash_redirect))
        .route(
            "/{slug}/secrets/{bucket}/",
            get(secrets_presets::secret_bucket_page),
        )
        .route(
            "/{slug}/secrets/{bucket}/_actions/set",
            post(secrets_presets::set_secret),
        )
        .route(
            "/{slug}/secrets/{bucket}/_actions/rename",
            post(secrets_presets::rename_secret),
        )
        .route(
            "/{slug}/secrets/{bucket}/_actions/delete",
            post(secrets_presets::delete_secret),
        )
        .route("/{slug}/presets", get(slash_redirect))
        .route("/{slug}/presets/", get(secrets_presets::presets_page))
        .route(
            "/{slug}/presets/_actions/update",
            post(secrets_presets::update_preset),
        )
        .route(
            "/{slug}/presets/_actions/delete",
            post(secrets_presets::delete_preset),
        )
        .route("/{slug}/hosts", get(slash_redirect))
        .route("/{slug}/hosts/", get(hosts::page))
        .route("/{slug}/snapshots", get(slash_redirect))
        .route("/{slug}/snapshots/", get(snapshots::page))
        .route(
            "/{slug}/_fragments/sandboxes",
            get(environments::list_fragment),
        )
        .route(
            "/{slug}/_fragments/sandbox-rail",
            get(environments::rail_fragment),
        )
        .route(
            "/{slug}/_fragments/billing-banner",
            get(billing::banner_fragment),
        )
        .route("/{slug}/new", get(organization_slash_redirect))
        .route("/{slug}/new/", get(environments::new_page))
        .route(
            "/{slug}/_fragments/github-repositories",
            post(github_repositories::repositories),
        )
        .route(
            "/{slug}/_fragments/create-draft",
            post(environment_drafts::restore)
                .layer(axum::extract::DefaultBodyLimit::max(32 * 1024)),
        )
        .route(
            "/{slug}/_fragments/create-options",
            post(environments::create_options_fragment)
                .layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .route(
            "/{slug}/_actions/sandboxes/create",
            post(environments::create),
        )
        .route(
            "/{slug}/_actions/sandboxes/start",
            post(environments::start),
        )
        .route("/{slug}/_actions/sandboxes/stop", post(environments::stop))
        .route(
            "/{slug}/_actions/sandboxes/sources",
            post(environments::update_sources),
        )
        .route(
            "/{slug}/_actions/sandboxes/delete",
            post(environments::delete),
        )
        .route(
            "/{slug}/_actions/sandboxes/resize/plan",
            post(environments::resize_plan),
        )
        .route(
            "/{slug}/_actions/sandboxes/resize/apply",
            post(environments::resize_apply),
        )
        .route(
            "/{slug}/_fragments/sandbox-resize",
            get(environments::resize_operation_fragment),
        )
        .route(
            "/{slug}/_actions/sandboxes/ports/create",
            post(environments::create_port),
        )
        .route(
            "/{slug}/_actions/sandboxes/ports/delete",
            post(environments::delete_port),
        )
        .route("/settings", get(slash_redirect))
        .route("/settings/", get(settings::settings))
        .route("/settings/credentials", get(slash_redirect))
        .route("/settings/credentials/", get(credentials::page))
        .route("/settings/invitations", get(slash_redirect))
        .route(my_invitations::PATH, get(my_invitations::page))
        .route(
            my_invitations::ACCEPT_PATH,
            post(my_invitations::accept).layer(DefaultBodyLimit::max(2048)),
        )
        .route("/settings/secrets", get(slash_redirect))
        .route("/settings/secrets/", get(personal_secrets::page))
        .route(
            "/settings/secrets/_actions/set",
            post(personal_secrets::set_action).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/settings/secrets/_actions/rename",
            post(personal_secrets::rename_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/secrets/_actions/delete",
            post(personal_secrets::delete_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/api-key/add",
            post(credentials::add_api_key_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/api-key/rotate",
            post(credentials::rotate_api_key_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/claude-subscription-token/add",
            post(credentials::add_claude_subscription_token_action)
                .layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/ssh/generate",
            post(credentials::generate_ssh_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/ssh/import",
            post(credentials::import_ssh_action).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/rename",
            post(credentials::rename_credential_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/revoke",
            post(credentials::revoke_credential_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/delete",
            post(credentials::delete_credential_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/credentials/oauth/enroll",
            post(credentials::enroll_oauth_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/github/authorize",
            post(credentials::github_app_authorize_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            credentials::GITHUB_APP_CALLBACK_PATH,
            get(credentials::github_app_callback),
        )
        .route(
            "/settings/credentials/_actions/profiles/create",
            post(credentials::create_profile_action),
        )
        .route(
            "/settings/credentials/_actions/profiles/update",
            post(credentials::update_profile_action),
        )
        .route(
            "/settings/credentials/_actions/profiles/rename",
            post(credentials::rename_profile_action).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/settings/credentials/_actions/profiles/delete",
            post(credentials::delete_profile_action),
        )
        .route(
            "/settings/_actions/git-identity",
            post(credentials::update_identity_action),
        )
        .route(
            "/settings/credentials/_actions/git-identity",
            post(credentials::update_identity_action),
        )
        .route(
            "/settings/_actions/sessions/revoke",
            post(settings::revoke_session_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/two-factor/replace/start",
            post(settings::replace_authenticator_start_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/two-factor/replace/confirm",
            post(settings::replace_authenticator_confirm_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/two-factor/recovery-codes/regenerate",
            post(settings::regenerate_recovery_codes_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/send-verification",
            post(settings::send_verification_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/sign-in-methods/connect",
            post(sign_in_methods::connect_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/sign-in-methods/disconnect",
            post(sign_in_methods::disconnect_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/settings/_actions/sign-out",
            post(authentication::sign_out_action),
        )
        .route("/settings/delete-account", get(slash_redirect))
        .route(
            "/settings/delete-account/",
            get(settings::delete_account_page),
        )
        .route(
            "/settings/_actions/delete-account",
            post(settings::delete_account_action).layer(DefaultBodyLimit::max(2048)),
        )
        .route("/settings/security", get(slash_redirect))
        .route("/settings/security/", get(settings::security))
        .route("/settings/sessions", get(slash_redirect))
        .route("/settings/sessions/", get(settings::sessions))
        .route("/dashboard/settings", get(legacy_not_found))
        .route("/dashboard/orgs/{*rest}", get(legacy_not_found))
        .route("/terminal/{*rest}", get(legacy_not_found))
        .route(
            "/{slug}/{environment_id}",
            get(sandbox_detail_slash_redirect),
        )
        .route("/{slug}/{environment_id}/", get(terminal::page))
        .route(
            "/{slug}/{environment_id}/_actions/resize/plan",
            post(sandbox_resize::plan).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/{slug}/{environment_id}/_actions/resize/apply",
            post(sandbox_resize::apply).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/{slug}/{environment_id}/_fragments/resize-operation",
            get(sandbox_resize::operation),
        )
        .route(
            "/{slug}/{environment_id}/_fragments/terminal-readiness",
            get(terminal_readiness::get),
        )
        .route(
            "/{slug}/{environment_id}/_events/setup-progress",
            get(setup_progress::events),
        )
        .route(
            "/{slug}/{environment_id}/_fragments/terminal-sessions",
            get(terminal_sessions::list),
        )
        .route(
            "/{slug}/{environment_id}/_actions/terminal-sessions/launch",
            post(terminal_sessions::launch).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/{slug}/{environment_id}/_actions/terminal-sessions/stop",
            post(terminal_sessions::stop).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/{slug}/{environment_id}/ports/",
            get(environments::port_fragment),
        )
        .route("/{slug}", get(organization_slash_redirect))
        .route("/{slug}/", get(environments::page))
}

async fn slash_redirect(OriginalUri(uri): OriginalUri) -> Response {
    let mut target = format!("{}/", uri.path().trim_end_matches('/'));
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    Redirect::permanent(&target).into_response()
}

async fn sandbox_detail_slash_redirect(
    Path((slug, environment_id)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug)
        || !terminal::canonical_environment_id(&environment_id)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    slash_redirect(OriginalUri(uri)).await
}

async fn organization_slash_redirect(
    Path(slug): Path<String>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug) {
        return StatusCode::NOT_FOUND.into_response();
    }
    slash_redirect(OriginalUri(uri)).await
}

async fn legacy_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use axum::http::{Uri, header};

    use super::*;

    #[test]
    fn route_registry_accepts_clean_static_and_root_slug_routes() {
        let _ = router();
    }

    #[tokio::test]
    async fn slash_redirect_is_permanent_and_preserves_query() {
        let response =
            slash_redirect(OriginalUri(Uri::from_static("/dashboard?org=route-safe"))).await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/dashboard/?org=route-safe"
        );
    }

    #[tokio::test]
    async fn organization_redirect_rejects_non_slug_browser_paths() {
        let response = organization_slash_redirect(
            Path("favicon.ico".to_owned()),
            OriginalUri(Uri::from_static("/favicon.ico")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = organization_slash_redirect(
            Path("route-safe".to_owned()),
            OriginalUri(Uri::from_static("/route-safe?panel=create")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/route-safe/?panel=create"
        );
    }

    #[tokio::test]
    async fn detail_redirect_requires_canonical_slug_and_uuid() {
        let uuid = "5d1db799-4300-4ab3-b957-efb980760542";
        let response = sandbox_detail_slash_redirect(
            Path(("route-safe".to_owned(), uuid.to_owned())),
            OriginalUri(format!("/route-safe/{uuid}?panel=ports").parse().unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("/route-safe/{uuid}/?panel=ports")
        );

        for (slug, id) in [
            ("admin", uuid),
            ("route-safe", "5D1DB799-4300-4AB3-B957-EFB980760542"),
            ("route-safe", "environment-id"),
        ] {
            let response = sandbox_detail_slash_redirect(
                Path((slug.to_owned(), id.to_owned())),
                OriginalUri(format!("/{slug}/{id}").parse().unwrap()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn legacy_handler_fails_closed() {
        assert_eq!(legacy_not_found().await, StatusCode::NOT_FOUND);
    }
}
