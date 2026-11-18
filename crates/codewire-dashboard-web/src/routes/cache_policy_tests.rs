//! Every route the dashboard serves answers `no-store` (#5054): an edge that
//! caches what isn't marked would serve one visitor's page to another. The
//! walk reads the routes from `mod.rs`, so a new route is covered without
//! being listed; only the anonymous homepage may be shared.

use axum::http::header;
use codewire_server_core::auth::SESSION_COOKIE_NAME;

use crate::security::HOME_CACHE_CONTROL;

const ROUTES: &str = include_str!("mod.rs");
const ID: &str = "00000000-0000-4000-8000-000000000001";

/// Routes registered by a named constant rather than a literal path.
fn named_routes() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (super::DASHBOARD_PATH, vec!["get"]),
        (super::ACCOUNT_OVERVIEW_FRAGMENT_PATH, vec!["get"]),
        (super::ORGANIZATIONS_FRAGMENT_PATH, vec!["get"]),
        (super::NEW_ORGANIZATION_PATH, vec!["get"]),
        (super::CREATE_ORGANIZATION_ACTION_PATH, vec!["post"]),
        (super::my_invitations::PATH, vec!["get"]),
        (super::my_invitations::ACCEPT_PATH, vec!["post"]),
        (super::credentials::GITHUB_APP_CALLBACK_PATH, vec!["get"]),
    ]
}

/// Each `.route(` in `mod.rs` with a literal path, and the methods it serves.
fn literal_routes() -> (Vec<(String, Vec<&'static str>)>, usize) {
    let calls: Vec<&str> = ROUTES.split(".route(").skip(1).collect();
    let mut routes = Vec::new();
    for call in &calls {
        let call = call.trim_start();
        let Some(rest) = call.strip_prefix('"') else {
            continue;
        };
        let path = &rest[..rest.find('"').expect("a closed path literal")];
        let methods = ["get", "post", "put", "patch", "delete"]
            .into_iter()
            .filter(|method| {
                call.match_indices(&format!("{method}(")).any(|(at, _)| {
                    at == 0
                        || (!call.as_bytes()[at - 1].is_ascii_alphanumeric()
                            && call.as_bytes()[at - 1] != b'_')
                })
            })
            .collect();
        routes.push((path.to_owned(), methods));
    }
    (routes, calls.len())
}

/// A request path for a route: each parameter takes a sample value.
fn sample(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = open + rest[open..].find('}').expect("a closed parameter");
        out.push_str(match &rest[open + 1..close] {
            "slug" => "example-org",
            "environment_id" | "organization_id" => ID,
            _ => "x",
        });
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn every_route_forbids_storage_but_the_anonymous_homepage() {
    let (literal, calls) = literal_routes();
    let named = named_routes();
    // Every .route( is walked: a route added by another constant fails here.
    assert_eq!(
        literal.len() + named.len(),
        calls,
        "a .route( the walk can't read"
    );
    let mut routes: Vec<(String, Vec<&str>)> = literal;
    routes.extend(
        named
            .into_iter()
            .map(|(path, methods)| (path.to_owned(), methods)),
    );
    routes.push(("/no-such-route".into(), vec!["get"]));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            crate::app(crate::test_support::unreachable_config()),
        )
        .await
        .unwrap()
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap();

    let mut stored = Vec::new();
    for (path, methods) in &routes {
        let url = format!("{origin}{}", sample(path));
        for method in methods {
            for signed_in in [false, true] {
                let mut request = match *method {
                    "get" => client.get(&url),
                    "post" => client
                        .post(&url)
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
                    "put" => client.put(&url),
                    "patch" => client.patch(&url),
                    _ => client.delete(&url),
                };
                if signed_in {
                    request =
                        request.header(header::COOKIE, format!("{SESSION_COOKIE_NAME}=synthetic"));
                }
                let response = match request.send().await {
                    Ok(response) => response,
                    Err(error) => {
                        stored.push(format!("{method} {path} signed_in={signed_in}: {error}"));
                        continue;
                    }
                };
                let policy = response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let public_home = path == "/" && *method == "get" && !signed_in;
                let allowed = if public_home {
                    policy == HOME_CACHE_CONTROL
                } else {
                    policy
                        .split(',')
                        .any(|directive| directive.trim() == "no-store")
                };
                if !allowed {
                    stored.push(format!(
                        "{method} {path} signed_in={signed_in}: {} Cache-Control {policy:?}",
                        response.status()
                    ));
                }
            }
        }
    }
    server.abort();
    assert!(
        stored.is_empty(),
        "responses a cache may keep:\n{}",
        stored.join("\n")
    );
}
