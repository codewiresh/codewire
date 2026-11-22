use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use url::Url;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    environment_connect,
    error::WebError,
    response::{TerminalStyleNonce, error_page, render_terminal_page},
    routes::organization_governance::{connect_page_error, get_context},
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::TerminalTemplate,
    view::{SandboxListContext, TerminalPageView},
};

#[derive(Default, Deserialize)]
pub(super) struct TerminalQuery {
    #[serde(flatten)]
    list_context: SandboxListContext,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    /// `reclone` after a Retry setup that must confirm its reclone (#4767).
    #[serde(default)]
    confirm: String,
    /// When a Retry setup that started was asked for (#4767).
    #[serde(default)]
    setup_retry: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    Query(query): Query<TerminalQuery>,
    headers: HeaderMap,
) -> Response {
    let list_context = query.list_context.normalized();
    let continuation = list_context.detail_url(&slug, &environment_id);
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug)
        || !canonical_environment_id(&environment_id)
    {
        return error_page(WebError::NotFound);
    }
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    // Capture the immutable actor from this request's authenticated cookie,
    // never from terminal inventory, display names or browser storage. Private
    // Resize requests compare it with freshly authenticated identity again.
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error_page(error),
    };
    if let Err(error) = enforce_two_factor(&identity) {
        return error_page(error);
    }
    let (environment, credit) = tokio::join!(
        environment_connect::environment(&state, cookie.clone(), &organization.id, &environment_id),
        crate::billing_connect::credit_facts(&state, cookie.clone(), &organization.id),
    );
    let mut environment = match environment {
        Ok(environment) => environment,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    // Its rate at the organization's rate card (#5186).
    if let Some(facts) = &credit {
        crate::billing_banner::price_sandbox(facts, &mut environment);
    }
    super::environments::apply_confidential_visibility(&state, &mut environment);
    environment_connect::mark_bound_credential_attention(&state, cookie, &mut environment).await;
    let websocket_origin =
        match browser_websocket_origin(&state.public_origin, &state.browser_api_origin) {
            Some(origin) => origin,
            None => {
                return error_page(WebError::BrowserConfigurationUnavailable);
            }
        };
    let message = detail_message(&query.message);
    let view = TerminalPageView {
        account_id: identity.id,
        organization_id: organization.id.clone(),
        environment,
        websocket_origin,
        list_url: list_context.list_url(&slug),
        list_context,
        message,
        error: super::environments::page_error(&query.error).into(),
    };
    let token = page_csrf_token(&headers);
    let style_nonce = TerminalStyleNonce::new();
    with_csrf_cookie(
        render_terminal_page(
            TerminalTemplate {
                confirm_reclone: query.confirm == "reclone"
                    && !view.environment.setup_failure.is_empty(),
                setup_retry_since: query.setup_retry_since(&view.environment),
                ..TerminalTemplate::new(
                    &dashboard,
                    &organization,
                    &view,
                    &token,
                    style_nonce.as_str(),
                )
            },
            &view.websocket_origin,
            &style_nonce,
        ),
        csrf_cookie(&state.public_origin, &token),
    )
}

impl TerminalQuery {
    /// A page returning from a Retry setup follows it in the step list from
    /// when it was asked for, whether or not the failure still shows: the
    /// retry clears it only when its setup starts, and a quick retry can
    /// finish before this page renders, so the render time is no boundary
    /// (#4767). A Sandbox no longer running renders as it is.
    pub(super) fn setup_retry_since(&self, environment: &crate::view::EnvironmentRow) -> String {
        retry_since(&self.setup_retry, environment)
    }
}

fn retry_since(asked_at: &str, environment: &crate::view::EnvironmentRow) -> String {
    match chrono::DateTime::parse_from_rfc3339(asked_at) {
        Ok(asked_at) if environment.state == "running" && !environment.deletion_started() => {
            asked_at
                .with_timezone(&chrono::Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
        _ => String::new(),
    }
}

pub(super) fn canonical_environment_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

pub(crate) fn browser_websocket_origin(public_origin: &str, api_origin: &str) -> Option<String> {
    let public = Url::parse(public_origin).ok()?;
    let mut api = Url::parse(api_origin).ok()?;
    if public.host_str()? != api.host_str()? {
        return None;
    }
    let websocket_scheme = match api.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return None,
    };
    api.set_scheme(websocket_scheme).ok()?;
    Some(api.as_str().trim_end_matches('/').to_owned())
}

/// The detail page's feedback. Create, Start and a managed restart lead into
/// the step list, which says what is happening, so they add no alert (the
/// owner, 2026-11-14: "I do not want another banner also that says sandbox
/// start request received"). Alerts stay for what the list cannot show.
fn detail_message(message: &str) -> String {
    match message {
        "environment-created" | "environment-started" | "environment-sources-restarting" => {
            String::new()
        }
        other => super::environments::page_message(other).into(),
    }
}

pub(super) fn terminal_path(slug: &str, environment_id: &str) -> String {
    let mut url = Url::parse("https://codewire.invalid").expect("static base URL");
    url.path_segments_mut()
        .expect("base URL can have path segments")
        .extend([slug, environment_id, ""]);
    url.path().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_query_decodes_list_context_without_changing_feedback() {
        let uri = "/my-org/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/?list_search=a%26state%3Ddestroyed&list_state=running&message=environment-started".parse().unwrap();
        let Query(query) = Query::<TerminalQuery>::try_from_uri(&uri).unwrap();
        assert_eq!(query.list_context.list_search, "a&state=destroyed");
        assert_eq!(query.list_context.list_state, "running");
        assert_eq!(query.message, "environment-started");
        let Query(legacy) = Query::<TerminalQuery>::try_from_uri(
            &"/my-org/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/"
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(legacy.list_context.normalized().list_state, "all");
        assert_eq!(legacy.list_context.list_search, "");
    }

    #[test]
    fn actions_that_lead_into_the_step_list_add_no_alert() {
        for message in [
            "environment-created",
            "environment-started",
            "environment-sources-restarting",
        ] {
            assert_eq!(detail_message(message), "", "{message}");
        }
        // What the list cannot show keeps its alert.
        assert_eq!(
            detail_message("environment-stopping"),
            "Sandbox stop requested."
        );
        assert_eq!(
            detail_message("environment-sources-stored"),
            "Sandbox sources saved. The Sandbox remains stopped."
        );
        let template = include_str!("../../templates/terminal.html");
        assert!(!template.contains("data-sandbox-creation-notice"));
    }

    #[test]
    fn disruptive_controls_use_native_dialogs_and_keep_the_detail_context() {
        let template = include_str!("../../templates/terminal.html");
        for name in ["stop", "delete"] {
            assert!(template.contains(&format!("data-dialog-open=\"sandbox-{name}\"")));
            assert!(template.contains(&format!("data-dialog id=\"sandbox-{name}\"")));
        }
        // Retry setup's reclone confirmation opens itself after the server
        // asks for it (#4767).
        assert!(template.contains("data-dialog id=\"setup-reclone\""));
        assert_eq!(
            template
                .matches("data-dialog-close autofocus>Cancel")
                .count(),
            3
        );
        assert_eq!(
            template
                .matches("name=\"return_to\" value=\"detail\"")
                .count(),
            4
        );
        // Start, the status panel's Start, Stop and Delete; Retry setup and
        // its reclone confirmation return to the detail page by themselves.
        for name in ["list_search", "list_state"] {
            assert_eq!(template.matches(&format!("name=\"{name}\"")).count(), 6);
        }
        assert!(
            template
                .contains("href=\"{{ page.list_url }}\" aria-label=\"Back to Sandboxes\"><svg class=\"cw-icon\" aria-hidden=\"true\"><use href=\"/assets/codewire/icons-v2.svg#icon-arrow-left\"/></svg></a>")
        );
        assert!(template.contains("href=\"{{ page.list_context.detail_url(organization.slug, page.environment.id) }}\" data-sandbox-observation-reload"));
        assert!(!template.contains("cw-action-menu--danger"));
        assert!(
            template.contains("{% if page.environment.confidential_actions_allowed %}<noscript>")
        );
        assert!(template.contains("href=\"{{ organization.environments_url }}?ports={{ page.environment.id }}\">Manage Ports</a>"));
        assert_eq!(template.matches("data-terminal-root ").count(), 1);
    }

    #[test]
    fn terminal_htmx_uses_external_indicator_styles_under_strict_csp() {
        let template = include_str!("../../templates/terminal.html");
        let config = template
            .split("name=\"htmx-config\" content='")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(config).unwrap();
        assert_eq!(config["includeIndicatorStyles"], false);
        assert_eq!(config["allowEval"], false);
        assert_eq!(config["allowScriptTags"], false);
    }

    #[test]
    fn browser_websocket_origin_is_same_host_and_protocol_bounded() {
        assert_eq!(
            browser_websocket_origin("http://127.0.0.1:5173", "http://127.0.0.1:8080").as_deref(),
            Some("ws://127.0.0.1:8080")
        );
        assert_eq!(
            browser_websocket_origin("https://codewire.test", "https://codewire.test"),
            Some("wss://codewire.test".to_owned())
        );
        assert!(
            browser_websocket_origin("https://codewire.test", "https://internal-api.test")
                .is_none()
        );
        assert!(browser_websocket_origin("https://codewire.test", "file:///tmp/api").is_none());
    }

    #[test]
    fn sandbox_continuation_encodes_path_segments() {
        assert_eq!(
            terminal_path("org/unsafe", "env?unsafe"),
            "/org%2Funsafe/env%3Funsafe/"
        );
    }

    #[test]
    fn detail_route_requires_a_full_lowercase_uuid() {
        assert!(canonical_environment_id(
            "5d1db799-4300-4ab3-b957-efb980760542"
        ));
        assert!(!canonical_environment_id(
            "5D1DB799-4300-4AB3-B957-EFB980760542"
        ));
        assert!(!canonical_environment_id(
            "5d1db79943004ab3b957efb980760542"
        ));
        assert!(!canonical_environment_id("environment-id"));
    }
}
