//! The organization a signed-in browser last worked in.
//!
//! Organization pages carry their organization in the path (`/{slug}/…`).
//! Personal and admin pages (`/settings/…`, `/admin/…`) show the remembered
//! organization in their navigation without putting it in their URLs. The
//! remembered slug is only a navigation hint: every page resolves it against
//! the caller's own memberships, and it never grants access.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    middleware::Next,
    response::Response,
};
use codewire_server_core::{auth::session_cookie, organization_slug::valid_organization_slug};

use crate::{
    response::redirect,
    security::{cookie_value, with_response_cookie},
    state::AppState,
};

const COOKIE: &str = "codewire_current_org";
/// Browsers cap cookie lifetimes at 400 days.
const MAX_AGE_SECONDS: u32 = 400 * 24 * 60 * 60;
/// Organization sections a switch keeps; anything deeper returns to the
/// section itself, because a sandbox or bucket belongs to one organization.
const SECTIONS: &[&str] = &[
    "new",
    "members",
    "api-keys",
    "billing",
    "secrets",
    "presets",
    "snapshots",
];

/// Apply the remembered organization to one request.
///
/// - `?org=<slug>` on a page read switches organization: the browser
///   remembers it and lands on the equivalent page without the parameter.
///   Navigation offers the switch as the relative link `?org=<slug>`, so it
///   works from any page.
/// - Personal and admin requests without `org` receive the remembered slug
///   as their query parameter, so their navigation shows it.
/// - A successful organization page read remembers its organization.
pub(crate) async fn remember_organization(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let reads_page = matches!(*request.method(), Method::GET | Method::HEAD)
        && session_cookie(request.headers()).is_some();
    let (requested, rest) = split_org(request.uri().query());
    if reads_page
        && let Some(requested) = requested.as_deref()
        && let Some(target) = switch_target(&path, requested, &rest)
    {
        let response = redirect(target, request.headers());
        return if valid_organization_slug(requested) {
            with_response_cookie(response, cookie(&state.public_origin, requested))
        } else {
            response
        };
    }
    if is_account_page(&path)
        && requested.is_none()
        && let Some(remembered) = remembered(request.headers())
        && let Some(uri) = with_org(request.uri(), remembered)
    {
        *request.uri_mut() = uri;
    }
    let organization = organization_of(&path)
        .filter(|slug| reads_page && remembered(request.headers()) != Some(*slug))
        .map(str::to_owned);
    let response = next.run(request).await;
    match organization {
        Some(slug) if response.status() == StatusCode::OK => {
            with_response_cookie(response, cookie(&state.public_origin, &slug))
        }
        _ => response,
    }
}

/// Remember `slug` as the browser's organization. Only a route that has
/// already resolved `slug` from the caller's own memberships calls this.
pub(crate) fn remember(response: Response, public_origin: &str, slug: &str) -> Response {
    if valid_organization_slug(slug) {
        with_response_cookie(response, cookie(public_origin, slug))
    } else {
        response
    }
}

fn cookie(public_origin: &str, slug: &str) -> String {
    let secure = if public_origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{COOKIE}={slug}; Path=/; HttpOnly; SameSite=Lax; Max-Age={MAX_AGE_SECONDS}{secure}")
}

fn remembered(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, COOKIE).filter(|slug| valid_organization_slug(slug))
}

/// Personal settings, admin pages and the account home carry no organization
/// in their URLs.
fn is_account_page(path: &str) -> bool {
    path == "/dashboard/"
        || ["/settings", "/admin"].iter().any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
}

fn organization_of(path: &str) -> Option<&str> {
    let slug = path.strip_prefix('/')?.split('/').next()?;
    (path.len() > slug.len() + 1 && valid_organization_slug(slug)).then_some(slug)
}

/// Separate every `org` parameter from the rest of a query. More than one
/// `org` value selects nothing.
fn split_org(query: Option<&str>) -> (Option<String>, String) {
    let mut requested = Vec::new();
    let mut rest = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if key == "org" {
            requested.push(value.into_owned());
        } else {
            rest.append_pair(&key, &value);
        }
    }
    let requested = match requested.len() {
        0 => None,
        1 => requested.pop(),
        _ => Some(String::new()),
    };
    (requested, rest.finish())
}

/// Where a switch to `requested` lands from `path`, or `None` when the path
/// has no organization context to switch.
fn switch_target(path: &str, requested: &str, rest: &str) -> Option<String> {
    let valid = valid_organization_slug(requested);
    if path == "/dashboard/" && valid {
        return Some(format!("/{requested}/"));
    }
    if is_account_page(path) {
        return Some(if rest.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{rest}")
        });
    }
    let current = organization_of(path)?;
    if !valid || current == requested {
        return Some(if rest.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{rest}")
        });
    }
    let section = path[current.len() + 2..]
        .split('/')
        .next()
        .filter(|section| SECTIONS.contains(section));
    Some(match section {
        Some(section) => format!("/{requested}/{section}/"),
        None => format!("/{requested}/"),
    })
}

fn with_org(uri: &Uri, slug: &str) -> Option<Uri> {
    let mut query =
        url::form_urlencoded::Serializer::new(uri.query().unwrap_or_default().to_owned());
    query.append_pair("org", slug);
    format!("{}?{}", uri.path(), query.finish()).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    #[test]
    fn switching_keeps_the_equivalent_page() {
        let cases = [
            ("/settings/api-keys/", "acme", "", "/settings/api-keys/"),
            ("/settings/", "acme", "cursor=a", "/settings/?cursor=a"),
            ("/admin/audit/", "acme", "", "/admin/audit/"),
            ("/dashboard/", "acme", "", "/acme/"),
            ("/noel/members/", "acme", "", "/acme/members/"),
            ("/noel/secrets/project-1/", "acme", "", "/acme/secrets/"),
            ("/noel/new/", "acme", "", "/acme/new/"),
            (
                "/noel/00000000-0000-4000-8000-000000000001/",
                "acme",
                "",
                "/acme/",
            ),
            ("/noel/", "acme", "state=running", "/acme/"),
            ("/noel/members/", "noel", "", "/noel/members/"),
            ("/noel/members/", "Not Valid", "", "/noel/members/"),
        ];
        for (path, requested, rest, target) in cases {
            assert_eq!(
                switch_target(path, requested, rest).as_deref(),
                Some(target),
                "{path} -> {requested}"
            );
        }
        assert_eq!(switch_target("/organizations/new/", "acme", ""), None);
        assert_eq!(switch_target("/login", "acme", ""), None);
    }

    #[test]
    fn org_parameters_split_from_the_rest_of_the_query() {
        assert_eq!(split_org(None), (None, String::new()));
        assert_eq!(
            split_org(Some("org=acme&cursor=x%20y")),
            (Some("acme".into()), "cursor=x+y".into())
        );
        assert_eq!(
            split_org(Some("org=a&org=b&creation_draft=d")),
            (Some(String::new()), "creation_draft=d".into())
        );
    }

    #[test]
    fn account_pages_and_organization_pages_are_distinct() {
        for path in [
            "/settings",
            "/settings/",
            "/settings/api-keys/",
            "/admin/",
            "/dashboard/",
        ] {
            assert!(is_account_page(path), "{path}");
            assert_eq!(organization_of(path), None, "{path}");
        }
        for path in ["/settingsx/", "/organizations/new/", "/login", "/"] {
            assert!(!is_account_page(path), "{path}");
        }
        assert_eq!(organization_of("/noel/"), Some("noel"));
        assert_eq!(organization_of("/noel/members/"), Some("noel"));
        assert_eq!(organization_of("/noel"), None);
        assert_eq!(organization_of("/assets/codewire/x.css"), None);
    }

    #[test]
    fn remembered_organization_is_a_host_only_lax_cookie() {
        assert_eq!(
            cookie("https://codewire.sh", "acme"),
            "codewire_current_org=acme; Path=/; HttpOnly; SameSite=Lax; Max-Age=34560000; Secure"
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire_current_org=../evil"),
        );
        assert_eq!(remembered(&headers), None);
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire_current_org=acme"),
        );
        assert_eq!(remembered(&headers), Some("acme"));
        assert_eq!(
            with_org(&Uri::from_static("/settings/?cursor=a"), "acme")
                .unwrap()
                .to_string(),
            "/settings/?cursor=a&org=acme"
        );
    }
}
