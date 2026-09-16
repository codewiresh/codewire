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
    security::{csrf_cookie, new_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::TerminalTemplate,
    view::TerminalPageView,
};

#[derive(Default, Deserialize)]
pub(super) struct TerminalQuery {
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
    let continuation = terminal_path(&slug, &environment_id);
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
    let mut environment =
        match environment_connect::environment(&state, cookie, &organization.id, &environment_id)
            .await
        {
            Ok(environment) => environment,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    super::environments::apply_confidential_visibility(
        &state,
        dashboard.is_admin,
        &mut environment,
    );
    let websocket_origin =
        match browser_websocket_origin(&state.public_origin, &state.browser_api_origin) {
            Some(origin) => origin,
            None => {
                return error_page(WebError::BrowserConfigurationUnavailable);
            }
        };
    let view = TerminalPageView {
        account_id: identity.id,
        organization_id: organization.id.clone(),
        environment,
        websocket_origin,
        message: super::environments::page_message(&query.message).into(),
        error: super::environments::page_error(&query.error).into(),
    };
    let token = new_csrf_token();
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
            3
        );
        assert!(!template.contains("cw-action-menu--danger"));
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
