//! The credentials page's deferred GitHub permission notice (#5206).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};

use crate::{
    account_sessions,
    auth::{authenticated_identity, enforce_two_factor},
    response::render_template,
    security::canonical_cookie,
    state::AppState,
    templates::GithubPermissionsTemplate,
    view::GithubAcceptView,
};

/// The GitHub permission notice the credentials page asks for after it has
/// loaded (#5206). It answers with the notice, or with an empty body that
/// removes the placeholder when there is nothing to say or anything it needs
/// is unavailable; GitHub's own words never reach the page.
///
/// The check can make the credential service renew a person's GitHub token,
/// which is a state change behind a GET. It runs only for a request the
/// browser marks `same-origin` and that carries htmx's own header, which a
/// cross-origin page cannot add without a preflight this server never
/// answers. Anything else is refused before anything is read (#2712).
pub(super) async fn fragment(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !from_this_page(&headers) {
        return axum::response::IntoResponse::into_response((
            StatusCode::FORBIDDEN,
            [(header::CACHE_CONTROL, "private, no-store")],
        ));
    }
    let pending = async {
        // The page's own gate comes first, so a session the page turns away
        // makes no call for GitHub and starts no window: one session cookie
        // and no `Authorization` header, then the session, then two-factor.
        if !account_sessions::cookie_authority_is_unique(&headers) {
            return None;
        }
        let identity = authenticated_identity(&state, &headers).await.ok()?;
        enforce_two_factor(&identity).ok()?;
        if !account_sessions::valid_id(&identity.id) {
            return None;
        }
        let cookie = canonical_cookie(&headers).ok()?;
        Some(crate::github_check::github_pending_checked(&state, &identity.id, cookie).await)
    }
    .await
    .unwrap_or_default();
    let pending: Vec<GithubAcceptView> = pending
        .into_iter()
        .map(|pending| GithubAcceptView {
            url: pending.settings_url().unwrap_or_default(),
            account: pending.account,
        })
        .collect();
    render_template(
        StatusCode::OK,
        GithubPermissionsTemplate { pending: &pending },
    )
}

/// A fetch this dashboard's own page started: the browser says `same-origin`,
/// and htmx's header is there.
fn from_this_page(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .is_some_and(|site| site == "same-origin")
        && headers.contains_key(crate::response::HTMX_REQUEST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template as _;
    use axum::http::HeaderValue;

    fn rendered_notice(pending: Vec<GithubAcceptView>) -> String {
        GithubPermissionsTemplate { pending: &pending }
            .render()
            .unwrap()
    }

    #[test]
    fn the_notice_names_installations_still_short_of_permissions() {
        // #2712: the live status names each installation and links its
        // settings page; it is empty when every installation granted what is
        // needed, so the placeholder it replaces just goes away.
        let html = rendered_notice(vec![GithubAcceptView {
            account: "octo-org".into(),
            url: "https://github.com/organizations/octo-org/settings/installations/43".into(),
        }]);
        assert!(html.contains(
            r#"<section class="cw-alert cw-alert--warning" aria-label="GitHub permissions">"#
        ));
        assert!(html.contains(
            "<p>GitHub is waiting for you to accept Codewire's updated permissions on octo-org. \
             <a class=\"cw-link-button\" href=\"https://github.com/organizations/octo-org/settings/installations/43\" \
             target=\"_blank\" rel=\"noopener noreferrer\">Review on GitHub</a></p>"
        ), "{html}");
        assert_eq!(rendered_notice(Vec::new()), "");
        // An enterprise accepts in its own settings: the notice links nothing.
        let html = rendered_notice(vec![GithubAcceptView {
            account: "octo-enterprise".into(),
            url: String::new(),
        }]);
        assert!(html.contains(
            "<p>GitHub is waiting for you to accept Codewire's updated permissions on octo-enterprise.</p>"
        ));
        assert!(!html.contains("Review on GitHub"));
    }

    #[test]
    fn only_a_fetch_this_page_started_may_ask_for_the_notice() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(*name, HeaderValue::from_static(value));
            }
            headers
        };
        assert!(from_this_page(&headers(&[
            ("sec-fetch-site", "same-origin"),
            ("hx-request", "true"),
        ])));
        for refused in [
            headers(&[]),
            headers(&[("hx-request", "true")]),
            headers(&[("sec-fetch-site", "same-origin")]),
            headers(&[("sec-fetch-site", "same-site"), ("hx-request", "true")]),
            headers(&[("sec-fetch-site", "none"), ("hx-request", "true")]),
            headers(&[("sec-fetch-site", "cross-site"), ("hx-request", "true")]),
        ] {
            assert!(!from_this_page(&refused), "{refused:?}");
        }
    }
}
