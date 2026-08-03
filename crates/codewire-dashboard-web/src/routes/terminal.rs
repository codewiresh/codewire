use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use url::Url;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    environment_connect,
    error::WebError,
    response::{error_page, login_redirect, render_page_with_connect_origin, two_factor_redirect},
    routes::organization_governance::connect_page_error,
    security::canonical_cookie,
    state::AppState,
    templates::TerminalTemplate,
    view::TerminalPageView,
};

pub(super) async fn page(
    State(state): State<AppState>,
    Path((org_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let continuation = terminal_path(&org_id, &environment_id);
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(error) => return error_page(error),
    };
    if let Err(error) = enforce_two_factor(&identity) {
        return match error {
            WebError::TwoFactorRequired => two_factor_redirect(&continuation, &headers),
            error => error_page(error),
        };
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(&continuation, &headers),
    };
    let environment =
        match environment_connect::environment(&state, cookie, &org_id, &environment_id).await {
            Ok(environment) => environment,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    let websocket_origin =
        match browser_websocket_origin(&state.public_origin, &state.browser_api_origin) {
            Some(origin) => origin,
            None => {
                return error_page(WebError::BrowserConfigurationUnavailable);
            }
        };
    let view = TerminalPageView {
        organization_id: org_id,
        environment,
        websocket_origin,
        environments_url: "/dashboard".to_owned(),
    };
    render_page_with_connect_origin(TerminalTemplate { page: &view }, &view.websocket_origin)
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

fn terminal_path(org_id: &str, environment_id: &str) -> String {
    let mut url = Url::parse("https://codewire.invalid").expect("static base URL");
    url.path_segments_mut()
        .expect("base URL can have path segments")
        .extend(["terminal", org_id, environment_id]);
    url.path().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn terminal_continuation_encodes_path_segments() {
        assert_eq!(
            terminal_path("org/unsafe", "env?unsafe"),
            "/terminal/org%2Funsafe/env%3Funsafe"
        );
    }
}
