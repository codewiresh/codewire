//! The analytics tag (infra#2677): Umami's tracker, served from the
//! dashboard's own assets, counting page views without cookies on every page,
//! signed in or not. A deployment turns it on with `CODEWIRE_ANALYTICS_ORIGIN`
//! and `CODEWIRE_ANALYTICS_WEBSITE_ID`; with neither, no page carries it, so a
//! self-hosted deployment reports to no one.
//!
//! A public page sends its path and title; every other page sends only its
//! route pattern, such as `/:slug/:environment_id/`, and a fixed title, so no
//! organization or Sandbox name or ID reaches analytics. No page sends its
//! query or fragment, and same-site referrers are dropped. Every secret a URL
//! carries (an invitation, a reset or verification token, a device code) is
//! in the query or the fragment, so no path holds one either;
//! `routes::analytics_tests` keeps every path parameter to names and IDs.

use anyhow::{Context as _, bail};
use askama::Template as _;
use axum::{
    body::{Body, HttpBody as _},
    extract::{MatchedPath, Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use url::Url;

use crate::{response::with_analytics_policy, state::AppState};

/// What the tag needs: where it sends, the website it counts for, and the
/// one host it may send from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Analytics {
    pub(crate) origin: String,
    pub(crate) website_id: String,
    pub(crate) domain: String,
}

#[derive(askama::Template)]
#[template(path = "analytics.html")]
struct AnalyticsTag<'a> {
    analytics: &'a Analytics,
    /// The route pattern a page outside the public site sends in place of
    /// its address and title.
    route: Option<String>,
}

/// The public site's pages, whose path and title say nothing about an
/// account; the docs and the Go module page are under these prefixes.
const PUBLIC_PAGES: [&str; 5] = ["/", "/pricing", "/privacy", "/terms", "/updates"];
const PUBLIC_PREFIXES: [&str; 2] = ["/docs", "/sdk-go"];

/// What a page outside the public site sends for its address: its route
/// pattern with each parameter named, never filled in. A page no route
/// matched, such as a missing one, sends `/:unmatched`.
fn route_pattern(matched: Option<&str>) -> Option<String> {
    let Some(matched) = matched else {
        return Some("/:unmatched".to_owned());
    };
    if PUBLIC_PAGES.contains(&matched)
        || PUBLIC_PREFIXES
            .iter()
            .any(|prefix| matched.starts_with(prefix))
    {
        return None;
    }
    Some(
        matched
            .replace("{*", "*")
            .replace('{', ":")
            .replace('}', ""),
    )
}

const SELF_CONNECT: &str = "connect-src 'self'";

/// Tags every whole HTML page the dashboard serves, the docs included, where
/// the tag is configured. A page's header policy gains the tracker's one
/// connection; its scripts are the page's own, so nothing else changes. An
/// htmx fragment, a response that isn't HTML, a page whose policy doesn't
/// already allow its own scripts and connections, and a page streamed as it
/// is made (its size isn't known), which reading whole would hold back, are
/// served as they are.
pub(crate) async fn tag_pages(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let fragment = request.headers().contains_key("hx-request");
    let route = route_pattern(
        request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let response = next.run(request).await;
    let Some(analytics) = state.analytics.as_ref().filter(|_| !fragment) else {
        return response;
    };
    if !taggable(&response) || response.body().size_hint().exact().is_none() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    // Every HTML page is rendered whole in memory before it is sent, so
    // reading it back holds nothing new.
    let Ok(body) = axum::body::to_bytes(body, usize::MAX).await else {
        return axum::response::IntoResponse::into_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        );
    };
    match tag_page(&body, analytics, route) {
        Some(page) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            let status = parts.status;
            with_analytics_policy(
                Response::from_parts(parts, Body::from(page)),
                status,
                &analytics.origin,
            )
        }
        None => Response::from_parts(parts, Body::from(body)),
    }
}

/// Whether `response` is HTML under a policy that already allows the page's
/// own scripts and connections.
fn taggable(response: &Response) -> bool {
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let policy = header(header::CONTENT_SECURITY_POLICY);
    header(header::CONTENT_TYPE).starts_with("text/html")
        && policy.contains(SELF_CONNECT)
        && policy.contains("script-src 'self'")
}

/// `body` with the tag at the end of its head. A page that also states its
/// policy in a meta tag, as each docs page does, has that policy enforced
/// beside the header, so it gains the connection too; one whose meta policy
/// doesn't hold exactly one `connect-src 'self'`, such as a docs redirect, is
/// served as built.
fn tag_page(body: &[u8], analytics: &Analytics, route: Option<String>) -> Option<String> {
    let page = std::str::from_utf8(body).ok()?;
    let (head, rest) = page.split_once("</head>")?;
    let head = if head.contains(r#"http-equiv="Content-Security-Policy""#) {
        if head.matches(SELF_CONNECT).count() != 1 {
            return None;
        }
        head.replace(
            SELF_CONNECT,
            &format!("{SELF_CONNECT} {}", analytics.origin),
        )
    } else {
        head.to_owned()
    };
    let tag = AnalyticsTag { analytics, route }.render().ok()?;
    Some(format!("{head}{tag}\n</head>{rest}"))
}

/// Both values or neither, like the Updates page's: one without the other
/// is a half-configured deployment, which refuses to start. The tag sends
/// only from the public origin's host, so a copy of the configuration on
/// another deployment counts nothing.
pub(crate) fn parse(
    origin: Option<String>,
    website_id: Option<String>,
    public_origin: &str,
) -> anyhow::Result<Option<Analytics>> {
    let (origin, website_id) = match (origin, website_id) {
        (None, None) => return Ok(None),
        (Some(origin), Some(website_id)) => (origin, website_id),
        _ => bail!(
            "CODEWIRE_ANALYTICS_ORIGIN and CODEWIRE_ANALYTICS_WEBSITE_ID are set together or not at all"
        ),
    };
    let (_, origin) = crate::config::parse_origin("CODEWIRE_ANALYTICS_ORIGIN", origin)?;
    if !origin.starts_with("https://") {
        bail!("CODEWIRE_ANALYTICS_ORIGIN must be an https:// origin");
    }
    let website_id = website_id.trim().to_ascii_lowercase();
    if !is_uuid(&website_id) {
        bail!("CODEWIRE_ANALYTICS_WEBSITE_ID must be an Umami website ID, a UUID");
    }
    let domain = Url::parse(public_origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .context("CODEWIRE_PUBLIC_ORIGIN has no host for the analytics tag")?;
    Ok(Some(Analytics {
        origin,
        website_id,
        domain,
    }))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00000000-0000-4000-8000-0000000000aa";

    #[test]
    fn both_values_or_neither() {
        assert_eq!(parse(None, None, "https://codewire.test").unwrap(), None);
        assert!(
            parse(
                Some("https://umami.test".into()),
                None,
                "https://codewire.test"
            )
            .is_err()
        );
        assert!(parse(None, Some(ID.into()), "https://codewire.test").is_err());
        assert_eq!(
            parse(
                Some("https://umami.test/".into()),
                Some(ID.to_ascii_uppercase()),
                "https://codewire.test"
            )
            .unwrap(),
            Some(Analytics {
                origin: "https://umami.test".into(),
                website_id: ID.into(),
                domain: "codewire.test".into(),
            })
        );
    }

    /// A public page keeps its address; every other page names only its
    /// kind, with each parameter named and never filled in.
    #[test]
    fn a_page_outside_the_public_site_sends_only_its_route_pattern() {
        for public in [
            "/",
            "/pricing",
            "/privacy",
            "/terms",
            "/updates",
            "/docs",
            "/docs/{*path}",
            "/sdk-go/{*package}",
        ] {
            assert_eq!(route_pattern(Some(public)), None, "{public}");
        }
        for (matched, sent) in [
            ("/login", "/login"),
            ("/settings/", "/settings/"),
            ("/{slug}", "/:slug"),
            ("/{slug}/{environment_id}/", "/:slug/:environment_id/"),
            ("/{slug}/secrets/{bucket}/", "/:slug/secrets/:bucket/"),
            ("/terminal/{*rest}", "/terminal/*rest"),
        ] {
            assert_eq!(route_pattern(Some(matched)).as_deref(), Some(sent));
        }
        assert_eq!(route_pattern(None).as_deref(), Some("/:unmatched"));
    }

    #[test]
    fn only_an_https_origin_and_a_uuid() {
        for origin in ["http://umami.test", "https://umami.test/path", "umami.test"] {
            assert!(
                parse(
                    Some(origin.into()),
                    Some(ID.into()),
                    "https://codewire.test"
                )
                .is_err(),
                "{origin}"
            );
        }
        for id in [
            "",
            "00000000",
            "00000000-0000-4000-8000-0000000000ag",
            "\"><script>",
        ] {
            assert!(
                parse(
                    Some("https://umami.test".into()),
                    Some(id.into()),
                    "https://codewire.test"
                )
                .is_err(),
                "{id}"
            );
        }
    }
}
