//! The managed GitHub credential follows the environment's network policy
//! (#4926).
//!
//! A credential route on the host never passes the environment's network
//! policy, so without this a policy that lets nothing out would still let a
//! workload write to GitHub with the owner's connection. Selecting a
//! credential must not widen a network policy: when the policy does not
//! allow GitHub's hosts by rule, the GitHub slot is refused here, before any
//! lease, and no provider is contacted. The answer is decided outside this
//! process, by whoever holds the policy, and only read here.
//!
//! The body is a constant. It carries no credential, account or identifier.

use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::BrokerHttpResponse;

/// Stable machine-readable code of the refusal.
pub(crate) const NETWORK_POLICY_REFUSES_GITHUB_CODE: &str = "network_policy_refuses_github";

const MESSAGE: &str = "This environment's network policy does not allow GitHub, so Codewire's GitHub connection is not used here. To use it, select a network policy that allows github.com and api.github.com on port 443.";

/// The slot this rule covers.
pub(crate) const GITHUB_SLOT: &str = "github";
const GIT_ROUTE: &str = "github-https";

/// The refusal's status, headers and body for a request on `route`. 403 is
/// final for Git and `gh`: neither retries it. Git prints a plain-text error
/// body to the user and nothing of a JSON one, and `gh` prints a JSON body's
/// `message`, so each route answers in the form its client shows.
pub(crate) fn github_refusal(route: &str) -> (StatusCode, HeaderMap, Bytes) {
    let (content_type, body) = if route == GIT_ROUTE {
        ("text/plain; charset=utf-8", format!("{MESSAGE}\n"))
    } else {
        (
            "application/json",
            serde_json::json!({
                "message": MESSAGE,
                "code": NETWORK_POLICY_REFUSES_GITHUB_CODE,
            })
            .to_string(),
        )
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::FORBIDDEN, headers, Bytes::from(body))
}

/// [`github_refusal`] as a broker response, and the one log line that counts
/// the refusal. The line names the route and nothing of the request.
pub(crate) fn github_refused_response(route: &str) -> BrokerHttpResponse {
    log_refusal(route);
    let (status, headers, body) = github_refusal(route);
    BrokerHttpResponse::new(
        status,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}

pub(crate) fn log_refusal(route: &str) {
    tracing::info!(
        event = "credential_refused",
        slot = GITHUB_SLOT,
        route,
        reason = NETWORK_POLICY_REFUSES_GITHUB_CODE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_route_answers_in_the_form_its_client_shows() {
        let (status, headers, body) = github_refusal("github-https");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("network policy") && text.ends_with('\n'),
            "{text}"
        );

        let (status, headers, body) = github_refusal("github-api");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], NETWORK_POLICY_REFUSES_GITHUB_CODE);
        let message = json["message"].as_str().unwrap();
        for part in ["network policy", "github.com", "api.github.com", "443"] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }
}
