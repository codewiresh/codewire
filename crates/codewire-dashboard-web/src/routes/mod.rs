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
mod snapshots;
mod terminal;

use axum::{
    Router,
    extract::{OriginalUri, Path},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};

use crate::state::AppState;

pub(crate) const DASHBOARD_PATH: &str = "/dashboard/";
pub(crate) const ORGANIZATIONS_FRAGMENT_PATH: &str = "/dashboard/_fragments/organizations";
pub(crate) const NEW_ORGANIZATION_PATH: &str = "/organizations/new/";
pub(crate) const CREATE_ORGANIZATION_ACTION_PATH: &str = "/organizations/_actions/create";

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
        .route("/dashboard", get(slash_redirect))
        .route(DASHBOARD_PATH, get(dashboard::dashboard))
        .route("/admin", get(slash_redirect))
        .route("/admin/", get(admin::overview))
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
        .route("/{slug}/secrets", get(slash_redirect))
        .route("/{slug}/secrets/", get(secrets_presets::secrets_page))
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
        .route("/{slug}/new", get(organization_slash_redirect))
        .route("/{slug}/new/", get(environments::new_page))
        .route(
            "/{slug}/_actions/sandboxes/prepare",
            post(environments::prepare),
        )
        .route(
            "/{slug}/_events/sandboxes/prepare",
            post(environments::prepare_events),
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
        .route(
            "/settings/_actions/github/disconnect",
            post(settings::disconnect_github_action),
        )
        .route(
            "/settings/_actions/credentials/create",
            post(settings::create_credential_action),
        )
        .route(
            "/settings/_actions/credentials/delete",
            post(settings::delete_credential_action),
        )
        .route(
            "/settings/_actions/git-identity",
            post(settings::update_identity_action),
        )
        .route(
            "/settings/_actions/ssh/ensure",
            post(settings::ensure_ssh_action),
        )
        .route(
            "/settings/_actions/ssh/regenerate",
            post(settings::regenerate_ssh_action),
        )
        .route(
            "/settings/_actions/sign-out",
            post(authentication::sign_out_action),
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
