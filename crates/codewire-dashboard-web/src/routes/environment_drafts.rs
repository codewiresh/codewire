//! Private, read-only recovery of an explicit metadata-only Create draft.

use askama::Template as _;
use axum::{
    extract::{Path, RawForm, State, rejection::RawFormRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
};

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    environment_drafts::{SelectionDraft, canonical_id},
    error::WebError,
    security::{canonical_cookie, valid_csrf_token},
    state::AppState,
    templates::EnvironmentCreateFormTemplate,
    view::OrganizationContext,
};

struct Submission {
    csrf: String,
    draft: String,
    metadata: String,
}

impl Submission {
    fn parse(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() > 32 * 1024 {
            return Err(());
        }
        let mut fields = std::collections::BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(bytes) {
            if !matches!(key.as_ref(), "_csrf" | "creation_draft" | "metadata")
                || value.len() > crate::environment_drafts::MAX_BYTES
                || fields
                    .insert(key.into_owned(), value.into_owned())
                    .is_some()
            {
                return Err(());
            }
        }
        let csrf = fields.remove("_csrf").ok_or(())?;
        let draft = fields.remove("creation_draft").ok_or(())?;
        let metadata = fields.remove("metadata").ok_or(())?;
        if csrf.len() > 64 || !canonical_id(&draft) {
            return Err(());
        }
        Ok(Self {
            csrf,
            draft,
            metadata,
        })
    }
}

fn valid_authority(headers: &HeaderMap, origin: &str, csrf: &str) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin_matches = origins
        .next()
        .is_some_and(|value| value.as_bytes() == origin.as_bytes())
        && origins.next().is_none();
    let cookies: Vec<_> = headers.get_all(header::COOKIE).iter().collect();
    let unique_cookies = cookies.len() == 1
        && cookies[0].to_str().ok().is_some_and(|raw| {
            [
                "codewire_ssr_csrf",
                codewire_server_core::auth::SESSION_COOKIE_NAME,
            ]
            .into_iter()
            .all(|expected| {
                raw.split(';')
                    .filter(|pair| {
                        pair.trim()
                            .split_once('=')
                            .is_some_and(|(name, _)| name.trim_end() == expected)
                    })
                    .count()
                    == 1
            })
        });
    origin_matches
        && !headers.contains_key(header::AUTHORIZATION)
        && unique_cookies
        && canonical_cookie(headers).is_ok()
        && valid_csrf_token(headers, csrf)
}

fn response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "private, no-store"),
            (header::VARY, "Cookie"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn unavailable(status: StatusCode) -> Response {
    response(status, "<p role=\"alert\">Saved selections could not be restored. Reload, sign in if needed, and review current options. No Sandbox was created.</p>".into())
}

pub(super) async fn restore(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Result<RawForm, RawFormRejection>,
) -> Response {
    let form = match body.ok().and_then(|body| Submission::parse(&body.0).ok()) {
        Some(form) => form,
        None => return unavailable(StatusCode::BAD_REQUEST),
    };
    if !valid_authority(&headers, &state.public_origin, &form.csrf) {
        return unavailable(StatusCode::FORBIDDEN);
    }
    let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let draft = match SelectionDraft::parse(form.metadata.as_bytes(), now) {
        Ok(draft) => draft,
        Err(()) => return unavailable(StatusCode::UNPROCESSABLE_ENTITY),
    };
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return unavailable(StatusCode::UNAUTHORIZED),
        Err(_) => return unavailable(StatusCode::SERVICE_UNAVAILABLE),
    };
    if enforce_two_factor(&identity).is_err() || !canonical_id(&identity.id) {
        return unavailable(StatusCode::FORBIDDEN);
    }
    let cookie = canonical_cookie(&headers).expect("authority validated canonical cookie");
    let organizations = match crate::connect::organizations(&state, cookie.clone()).await {
        Ok(organizations) => organizations,
        Err(_) => return unavailable(StatusCode::SERVICE_UNAVAILABLE),
    };
    let Some(organization) = organizations
        .iter()
        .find(|organization| organization.slug == slug)
    else {
        return unavailable(StatusCode::NOT_FOUND);
    };
    if !draft.matches(&identity.id, &organization.id, &form.draft) {
        return unavailable(StatusCode::FORBIDDEN);
    }
    let organization = OrganizationContext::from_row(organization);
    let mut fields = super::environments::default_create_form(form.csrf, true);
    let options =
        match crate::environment_connect::create_options(&state, cookie, &organization.id).await {
            Ok(options) => options,
            Err(_) => return unavailable(StatusCode::SERVICE_UNAVAILABLE),
        };
    super::environments::hydrate_options(&mut fields, options);
    let confidential_allowed =
        state.confidential_storage_enabled && (!state.confidential_admin_only || identity.is_admin);
    fields.show_confidential_controls = confidential_allowed;
    fields.confidential_available &= confidential_allowed;
    fields.draft_actor = identity.id;
    fields.draft_organization.clone_from(&organization.id);
    if draft.hydrate(&mut fields).is_err() {
        return unavailable(StatusCode::CONFLICT);
    }
    match (EnvironmentCreateFormTemplate {
        organization: &organization,
        form: &fields,
    })
    .render()
    {
        Ok(body) if body.len() <= 1024 * 1024 => response(StatusCode::OK, body),
        _ => unavailable(StatusCode::BAD_GATEWAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: &str = "https://dashboard.example.test";
    const DRAFT: &str = "00000000-0000-4000-8000-000000000003";
    const ORG: &str = "00000000-0000-4000-8000-000000000002";
    const ACTOR: &str = "00000000-0000-4000-8000-000000000001";
    const NOW: u64 = 4_000_000;

    fn metadata() -> serde_json::Value {
        serde_json::json!({
            "version": 1, "actor": ACTOR, "organization": ORG, "draft": DRAFT, "saved_at": NOW,
            "selections": {
                "preset_id": "", "cpu": "1250", "memory": "3072", "disk": "17", "ttl": "8h",
                "isolation_tier": "standard", "agents": ["codex"], "ports": [],
                "secret_project": "", "credential_profile": format!("{DRAFT}@9007199254740993"),
                "include_org_secrets": false, "include_user_secrets": true
            }
        })
    }

    #[test]
    fn restore_retains_stale_exact_sources_and_requires_free_form_reentry() {
        let mut value = metadata();
        value["selections"]["secret_project"] = serde_json::json!(ORG);
        value["selections"]["ports"] = serde_json::json!([{ "port": "3000", "access": "creator" }]);
        let draft = SelectionDraft::parse(value.to_string().as_bytes(), NOW)
            .ok()
            .unwrap();
        let mut form = super::super::environments::default_create_form("current-csrf".into(), true);
        form.agents.push(crate::view::EnvironmentAgentView {
            id: "codex",
            label: "Codex",
        });
        form.sources.application_selection_enabled = true;
        form.sources.credential_selection_enabled = true;
        let current_default_image = form.image.clone();
        draft.hydrate(&mut form).unwrap();
        assert_eq!(form.sources.projects.len(), 1);
        assert_eq!(form.sources.projects[0].id, ORG);
        assert!(form.sources.projects[0].selected && form.sources.projects[0].synthetic);
        assert_eq!(form.sources.profiles.len(), 1);
        assert_eq!(form.sources.profiles[0].id, DRAFT);
        assert_eq!(form.sources.profiles[0].revision, 9_007_199_254_740_993);
        assert!(form.sources.profiles[0].selected && form.sources.profiles[0].synthetic);
        assert!(!form.sources.project_selection_error.is_empty());
        assert!(!form.sources.profile_selection_error.is_empty());
        assert_eq!(form.app_ports[0].port, "3000");
        assert!(form.app_ports[0].label.is_empty());
        assert!(form.name.is_empty());
        assert_eq!(form.image, current_default_image);
        assert!(form.install_command.is_empty() && form.startup_script.is_empty());
        assert_eq!(form.csrf_token, "current-csrf");
        assert!(form.draft_restored && !form.draft_restore_allowed);
        let mut missing_preset = value;
        missing_preset["selections"]["preset_id"] = serde_json::json!(ACTOR);
        SelectionDraft::parse(missing_preset.to_string().as_bytes(), NOW)
            .ok()
            .unwrap()
            .hydrate(&mut form)
            .unwrap();
        assert_eq!(form.preset_id, ACTOR);
        assert!(!form.form_error.is_empty());
    }

    #[test]
    fn current_capability_and_agent_catalog_reject_unavailable_choices() {
        let mut value = metadata();
        let mut form = super::super::environments::default_create_form("current-csrf".into(), true);
        assert!(
            SelectionDraft::parse(value.to_string().as_bytes(), NOW)
                .ok()
                .unwrap()
                .hydrate(&mut form)
                .is_err()
        );
        value["selections"]["agents"] = serde_json::json!([]);
        value["selections"]["isolation_tier"] = serde_json::json!("confidential");
        assert!(
            SelectionDraft::parse(value.to_string().as_bytes(), NOW)
                .ok()
                .unwrap()
                .hydrate(&mut form)
                .is_err()
        );
        form.confidential_available = true;
        assert!(
            SelectionDraft::parse(value.to_string().as_bytes(), NOW)
                .ok()
                .unwrap()
                .hydrate(&mut form)
                .is_ok()
        );
    }

    fn authority() -> (HeaderMap, String) {
        let csrf = crate::security::new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
        headers.insert(
            header::COOKIE,
            format!("codewire.session_token=synthetic-session; codewire_ssr_csrf={csrf}")
                .parse()
                .unwrap(),
        );
        (headers, csrf)
    }

    // Durable synthetic HTTP fixtures exercise the real registered route and
    // generated Connect transport, not a browser-intercepted success response.
    struct TestServer {
        origin: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(router: axum::Router) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        TestServer { origin, task }
    }

    type Calls = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    async fn fixture(mode: &'static str) -> (TestServer, Calls) {
        use axum::{Json, Router, routing::any};
        use buffa::Message as _;
        use codewire_proto::codewire::{
            console::v1::GetEnvironmentCreateOptionsResponse,
            v1::{
                ListAccessProfilesResponse, ListOrganizationsResponse, ListSecretProjectsResponse,
                Organization, OrganizationMembership,
            },
        };
        let calls = Calls::default();
        let captured = calls.clone();
        let router = Router::new().fallback(any(move |request: axum::extract::Request| {
            let calls = captured.clone();
            async move {
                let path = request.uri().path().to_owned();
                calls.lock().unwrap().push(path.clone());
                assert_eq!(request.headers()[header::COOKIE], "codewire.session_token=synthetic-session");
                assert!(!request.headers().contains_key(header::AUTHORIZATION));
                if path == "/api/auth/get-session" {
                    if mode == "unauthenticated" { return StatusCode::UNAUTHORIZED.into_response(); }
                    if mode == "identity unavailable" { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    if mode == "null identity" { return Json(serde_json::json!({"user": null})).into_response(); }
                    return Json(serde_json::json!({"user": {"id": ACTOR, "email": "synthetic@example.test", "two_factor_enabled": mode != "two factor required"}})).into_response();
                }
                let bytes = if path.ends_with("/ListOrganizations") {
                    ListOrganizationsResponse {
                        organizations: if mode == "revoked membership" { vec![] } else { vec![OrganizationMembership {
                            organization: Some(Organization { id: ORG.into(), name: "Synthetic organization".into(), slug: "synthetic".into(), ..Default::default() }).into(),
                            ..Default::default()
                        }] },
                        ..Default::default()
                    }.encode_to_vec()
                } else if path.ends_with("/GetEnvironmentCreateOptions") {
                    if mode == "catalog unavailable" { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    GetEnvironmentCreateOptionsResponse { preview_base_domain: "cwpreview.sh".into(), ..Default::default() }.encode_to_vec()
                } else if path.ends_with("/ListSecretProjects") {
                    if mode == "source catalogs unavailable" { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    ListSecretProjectsResponse::default().encode_to_vec()
                } else if path.ends_with("/ListAccessProfiles") {
                    if mode == "source catalogs unavailable" { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    ListAccessProfilesResponse::default().encode_to_vec()
                } else {
                    // Billing failure is supported by create_options; unexpected
                    // operations are rejected and detected in the recorded calls.
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                };
                ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
            }
        }));
        (serve(router).await, calls)
    }

    fn fixture_config(upstream: &str) -> crate::Config {
        crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: ORIGIN.into(),
            api_origin: upstream.parse().unwrap(),
            credential_origin: upstream.parse().unwrap(),
            identity_origin_string: upstream.into(),
            browser_api_origin: ORIGIN.into(),
            billing_origin: upstream.parse().unwrap(),
            docs_root: std::path::PathBuf::new(),
            confidential_storage_enabled: false,
            confidential_admin_only: true,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
        }
    }

    async fn submit(mode: &'static str) -> (StatusCode, HeaderMap, String, Vec<String>) {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(fixture_config(&upstream.origin))).await;
        let (mut headers, csrf) = authority();
        if mode == "foreign origin" {
            headers.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
        }
        let mut draft = metadata();
        draft["saved_at"] = serde_json::json!(chrono::Utc::now().timestamp_millis() as u64);
        draft["selections"]["secret_project"] = serde_json::json!(ORG);
        draft["selections"]["ports"] = serde_json::json!([{ "port": "3000", "access": "creator" }]);
        if mode == "wrong actor" {
            draft["actor"] = serde_json::json!(ORG);
        }
        if mode == "wrong organization" {
            draft["organization"] = serde_json::json!(ACTOR);
        }
        if mode == "wrong draft" {
            draft["draft"] = serde_json::json!(ACTOR);
        }
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
            .post(format!(
                "{}/synthetic/_fragments/create-draft",
                dashboard.origin
            ))
            .headers(headers)
            .form(&[
                ("_csrf", csrf),
                ("creation_draft", DRAFT.into()),
                ("metadata", draft.to_string()),
            ])
            .send()
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let html = response.text().await.unwrap();
        let calls = calls.lock().unwrap().clone();
        (status, headers, html, calls)
    }

    fn assert_private_without_dispatch(headers: &HeaderMap, calls: &[String]) {
        assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
        assert_eq!(headers[header::VARY], "Cookie");
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(!headers.contains_key(header::LOCATION));
        for path in calls {
            assert!(
                path == "/api/auth/get-session"
                    || [
                        "/ListOrganizations",
                        "/GetEnvironmentCreateOptions",
                        "/GetBillingOverview",
                        "/ListResourcePlans",
                        "/ListSecretProjects",
                        "/ListAccessProfiles"
                    ]
                    .iter()
                    .any(|suffix| path.ends_with(suffix)),
                "unexpected upstream operation {path}"
            );
        }
    }

    #[tokio::test]
    async fn registered_restore_route_rechecks_current_authority_and_membership_before_catalogs() {
        for (mode, expected) in [
            ("foreign origin", StatusCode::FORBIDDEN),
            ("unauthenticated", StatusCode::UNAUTHORIZED),
            ("null identity", StatusCode::UNAUTHORIZED),
            ("identity unavailable", StatusCode::SERVICE_UNAVAILABLE),
            ("two factor required", StatusCode::FORBIDDEN),
            ("revoked membership", StatusCode::NOT_FOUND),
            ("wrong actor", StatusCode::FORBIDDEN),
            ("wrong organization", StatusCode::FORBIDDEN),
            ("wrong draft", StatusCode::FORBIDDEN),
            ("catalog unavailable", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let (status, headers, html, calls) = submit(mode).await;
            assert_eq!(status, expected, "mode {mode}");
            assert_private_without_dispatch(&headers, &calls);
            assert!(html.contains("No Sandbox was created"));
            assert!(
                !html.contains("synthetic-session") && !html.contains("synthetic@example.test")
            );
            if mode == "foreign origin" {
                assert!(calls.is_empty());
            }
            if mode != "catalog unavailable" {
                assert!(
                    !calls
                        .iter()
                        .any(|path| path.ends_with("/GetEnvironmentCreateOptions"))
                );
            }
        }
    }

    #[tokio::test]
    async fn registered_restore_route_renders_exact_stale_sources_with_current_catalogs_or_safe_catalog_failure()
     {
        for mode in ["removed sources", "source catalogs unavailable"] {
            let (status, headers, html, calls) = submit(mode).await;
            assert_eq!(status, StatusCode::OK, "mode {mode}");
            assert_private_without_dispatch(&headers, &calls);
            assert!(html.contains("data-create-draft-restored=\"true\""));
            assert!(html.contains(&format!("value=\"{DRAFT}@9007199254740993\"")));
            assert!(html.contains(&format!("value=\"{ORG}\"")));
            assert!(html.contains("not saved") && html.contains("preview labels"));
            assert!(
                calls
                    .iter()
                    .any(|path| path.ends_with("/ListSecretProjects"))
            );
            assert!(
                calls
                    .iter()
                    .any(|path| path.ends_with("/ListAccessProfiles"))
            );
            assert!(!html.contains("synthetic-session"));
        }
    }

    #[test]
    fn restore_requires_unique_exact_origin_cookie_and_csrf_without_bearer_fallback() {
        let (headers, csrf) = authority();
        assert!(valid_authority(&headers, ORIGIN, &csrf));
        assert!(!valid_authority(&headers, ORIGIN, "wrong-csrf"));
        for mutation in 0..8 {
            let mut invalid = headers.clone();
            match mutation {
                0 => {
                    invalid.remove(header::ORIGIN);
                    invalid.insert(header::REFERER, ORIGIN.parse().unwrap());
                }
                1 => {
                    invalid.append(header::ORIGIN, ORIGIN.parse().unwrap());
                }
                2 => {
                    invalid.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
                }
                3 => {
                    invalid.append(header::COOKIE, headers[header::COOKIE].clone());
                }
                4 => {
                    invalid.insert(
                        header::COOKIE,
                        format!(
                            "{}; codewire_ssr_csrf={csrf}",
                            headers[header::COOKIE].to_str().unwrap()
                        )
                        .parse()
                        .unwrap(),
                    );
                }
                5 => {
                    invalid.insert(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
                }
                6 => {
                    invalid.remove(header::COOKIE);
                }
                _ => {
                    invalid.insert(
                        header::COOKIE,
                        format!(
                            "{}; codewire.session_token=another-session",
                            headers[header::COOKIE].to_str().unwrap()
                        )
                        .parse()
                        .unwrap(),
                    );
                }
            }
            assert!(!valid_authority(&invalid, ORIGIN, &csrf));
        }
    }

    #[test]
    fn submissions_are_bounded_closed_and_unambiguous() {
        let body = format!("_csrf=synthetic&creation_draft={DRAFT}&metadata=%7B%7D");
        assert!(Submission::parse(body.as_bytes()).is_ok());
        for invalid in [
            format!("{body}&metadata=duplicate"),
            format!("{body}&password=canary"),
            "_csrf=synthetic&creation_draft=alias&metadata=%7B%7D".into(),
            "_csrf=synthetic&metadata=%7B%7D".into(),
        ] {
            assert!(Submission::parse(invalid.as_bytes()).is_err());
        }
        assert!(Submission::parse(&vec![b'x'; 32 * 1024 + 1]).is_err());
    }

    #[test]
    fn recovery_failure_is_private_and_never_redirects_rotates_csrf_or_advises_retrying_create() {
        let response = unavailable(StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(response.headers()[header::VARY], "Cookie");
        for key in [header::LOCATION, header::SET_COOKIE, header::RETRY_AFTER] {
            assert!(!response.headers().contains_key(key));
        }
    }
}
