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
    let mut environment = match environment_connect::environment(
        &state,
        cookie.clone(),
        &organization.id,
        &environment_id,
    )
    .await
    {
        Ok(environment) => environment,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    super::environments::apply_confidential_visibility(&state, &mut environment);
    environment_connect::mark_bound_credential_attention(&state, cookie, &mut environment).await;
    let websocket_origin =
        match browser_websocket_origin(&state.public_origin, &state.browser_api_origin) {
            Some(origin) => origin,
            None => {
                return error_page(WebError::BrowserConfigurationUnavailable);
            }
        };
    let (message, creation_notice) = detail_message(&query.message, environment.state);
    let view = TerminalPageView {
        account_id: identity.id,
        organization_id: organization.id.clone(),
        environment,
        websocket_origin,
        list_url: list_context.list_url(&slug),
        list_context,
        message,
        creation_notice,
        error: super::environments::page_error(&query.error).into(),
    };
    let token = page_csrf_token(&headers);
    let style_nonce = TerminalStyleNonce::new();
    with_csrf_cookie(
        render_terminal_page(
            TerminalTemplate {
                view: &dashboard,
                organization: &organization,
                page: &view,
                csrf_token: &token,
                style_nonce: style_nonce.as_str(),
            },
            &view.websocket_origin,
            &style_nonce,
        ),
        csrf_cookie(&state.public_origin, &token),
    )
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

/// The detail page's feedback, and whether it is the creation notice.
/// "Sandbox creation started." is news only until the Sandbox runs, so a
/// reload after that shows nothing; the page withdraws it live as well.
fn detail_message(message: &str, environment_state: &str) -> (String, bool) {
    let creation_notice = message == "environment-created";
    if creation_notice && environment_state == "running" {
        return (String::new(), false);
    }
    (
        super::environments::page_message(message).into(),
        creation_notice,
    )
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
    fn the_creation_notice_is_marked_and_withdrawn_once_the_sandbox_runs() {
        assert_eq!(
            detail_message("environment-created", "creating"),
            ("Sandbox creation started.".to_owned(), true)
        );
        assert_eq!(
            detail_message("environment-created", "running"),
            (String::new(), false)
        );
        let (started, notice) = detail_message("environment-started", "running");
        assert!(!started.is_empty());
        assert!(!notice);
        let template = include_str!("../../templates/terminal.html");
        assert!(template.contains(
            "{% if page.creation_notice %} data-sandbox-creation-notice{% endif %}>{{ page.message }}</p>"
        ));
    }

    #[test]
    fn disruptive_controls_use_native_dialogs_and_keep_the_detail_context() {
        let template = include_str!("../../templates/terminal.html");
        for name in ["stop", "delete"] {
            assert!(template.contains(&format!("data-dialog-open=\"sandbox-{name}\"")));
            assert!(template.contains(&format!("data-dialog id=\"sandbox-{name}\"")));
        }
        assert_eq!(
            template
                .matches("data-dialog-close autofocus>Cancel")
                .count(),
            2
        );
        assert_eq!(
            template
                .matches("name=\"return_to\" value=\"detail\"")
                .count(),
            4
        );
        // Start, the status panel's Start, Stop and Delete.
        for name in ["list_search", "list_state"] {
            assert_eq!(template.matches(&format!("name=\"{name}\"")).count(), 4);
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
