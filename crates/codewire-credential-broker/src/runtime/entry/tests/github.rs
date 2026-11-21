//! GitHub's two hosts behind a front door (#3999): a request with no
//! placeholder is forwarded as it was sent, this environment's placeholder
//! is swapped only on the route's grammar, a placeholder anywhere else is
//! refused without a lease, and none of it happens unless the network policy
//! allows GitHub by rule.

use super::*;
use crate::BrokerRequestBodyStream;

const USERS_TOKEN: &str = "ghp_usersOwnToken0123456789";

fn github(
    host: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: headers
            .iter()
            .map(|(name, value)| v1::CredentialHttpHeader {
                name: (*name).into(),
                value: value.as_bytes().to_vec(),
            })
            .collect(),
        body: body.to_vec(),
        capability_slot: "github".into(),
        route: if host == "github.com" {
            "github-https"
        } else {
            "github-api"
        }
        .into(),
        intercepted_host: host.into(),
        destination_ip: String::new(),
        streamed_body: false,
        intercept_decision: Vec::new(),
    }
}

fn basic(password: &str) -> String {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{password}"));
    format!("Basic {encoded}")
}

fn ours() -> Recorded {
    Recorded {
        placeholder: Some(OURS),
        ..Recorded::default()
    }
}

fn streamed(chunks: Vec<Vec<u8>>) -> BrokerRequestBodyStream {
    Box::pin(futures::stream::iter(
        chunks.into_iter().map(|chunk| Ok(Bytes::from(chunk))),
    ))
}

fn carries(outbound: &Outbound, value: &str) -> bool {
    outbound.2.iter().any(|(_, header)| {
        header
            .windows(value.len())
            .any(|window| window == value.as_bytes())
    }) || contains(&outbound.3, value)
}

/// What the route serves with the placeholder, one request per host.
fn on_the_grammar() -> [v1::CredentialBridgeRequest; 2] {
    [
        github(
            "github.com",
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &[("authorization", basic(OURS))],
            b"",
        ),
        github(
            "api.github.com",
            "GET",
            "/user",
            "",
            &[("authorization", format!("token {OURS}"))],
            b"",
        ),
    ]
}

/// No credential, or the user's own, on any path of either host: no lease,
/// the forward path, and the request as it was sent, its path and query byte
/// for byte.
#[tokio::test]
async fn a_request_without_a_placeholder_is_forwarded_as_it_was_sent() {
    let own = [("authorization", format!("token {USERS_TOKEN}"))];
    for (host, method, path, query, headers) in [
        // On the route's grammar, anonymously and with the user's own token.
        (
            "github.com",
            "GET",
            "/git/git.git/info/refs",
            "service=git-upload-pack",
            &[][..],
        ),
        ("api.github.com", "GET", "/user", "", &own[..]),
        // Paths the managed route never served.
        ("api.github.com", "GET", "/rate_limit", "", &own[..]),
        (
            "api.github.com",
            "GET",
            "/search/code",
            "q=a%20b+c&x=%7E&empty=",
            &own[..],
        ),
        (
            "github.com",
            "GET",
            "/owner/repo/releases/download/v1.0/a%20file.tar.gz",
            "",
            &[][..],
        ),
        (
            "github.com",
            "POST",
            "/owner/repo.git/info/lfs/objects/batch",
            "",
            &[("authorization", basic(USERS_TOKEN))][..],
        ),
    ] {
        let recorded = ours();
        let broker = recorded.broker();
        let (status, _, _) = collect(
            broker
                .execute_front_door(github(host, method, path, query, headers, b""))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{host}{path}");
        assert_eq!(recorded.leases(), 0, "{host}{path}");
        assert_eq!(recorded.forwarded(), 1, "{host}{path}");
        let outbound = recorded.outbound();
        assert_eq!(outbound.len(), 1);
        let expected = if query.is_empty() {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}{path}?{query}")
        };
        assert_eq!(outbound[0].1, expected);
        assert_eq!(
            header(&outbound[0], "authorization"),
            headers
                .iter()
                .map(|(_, value)| value.as_bytes())
                .collect::<Vec<_>>(),
            "{host}{path}: the credential is the environment's own, untouched"
        );
        assert!(!carries(
            &outbound[0],
            std::str::from_utf8(crate::http_test_support::TOKEN).unwrap()
        ));
    }
}

/// This environment's placeholder on the route's grammar is swapped: one
/// lease, the exact transport path, and the provider receives what the
/// loopback route sends, never the placeholder.
#[tokio::test]
async fn this_environments_placeholder_is_swapped_on_the_routes_grammar() {
    for request in on_the_grammar() {
        let recorded = ours();
        let broker = recorded.broker();
        let mut loopback = request.clone();
        loopback.intercepted_host.clear();
        loopback.request_id = Uuid::new_v4().to_string();
        collect(broker.execute(loopback).await.unwrap()).await;

        let host = request.intercepted_host.clone();
        let (status, _, _) = collect(broker.execute_front_door(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{host}");
        assert_eq!(recorded.leases(), 2, "{host}");
        assert_eq!(
            recorded.forwarded(),
            0,
            "{host}: leased material never forwards"
        );
        let outbound = recorded.outbound();
        assert_eq!(outbound[1], outbound[0], "{host}");
        assert!(
            !carries(&outbound[1], OURS),
            "{host}: the placeholder never leaves"
        );
        assert!(
            carries(
                &outbound[1],
                &base64::engine::general_purpose::STANDARD
                    .encode([b"x-access-token:", crate::http_test_support::TOKEN].concat())
            ) || carries(
                &outbound[1],
                std::str::from_utf8(crate::http_test_support::TOKEN).unwrap()
            ),
            "{host}: the leased credential is injected"
        );
    }
}

/// A placeholder-shaped value outside the route's grammar is refused with
/// the refusal's code, whoever's placeholder it looks like: no lease, and
/// nothing reaches GitHub, forwarded or otherwise. Git LFS is one such path.
#[tokio::test]
async fn a_placeholder_outside_the_routes_grammar_is_refused_without_a_lease() {
    for placeholder in [OURS, THEIRS] {
        for (host, method, path, credential) in [
            (
                "api.github.com",
                "GET",
                "/rate_limit",
                format!("token {placeholder}"),
            ),
            (
                "api.github.com",
                "DELETE",
                "/repos/owner/repo",
                format!("Bearer {placeholder}"),
            ),
            (
                "github.com",
                "POST",
                "/owner/repo.git/info/lfs/objects/batch",
                basic(placeholder),
            ),
            (
                "github.com",
                "GET",
                "/owner/repo/archive/refs/heads/main.zip",
                basic(placeholder),
            ),
        ] {
            let recorded = ours();
            let broker = recorded.broker();
            let (status, headers, body) = collect(
                broker
                    .execute_front_door(github(
                        host,
                        method,
                        path,
                        "",
                        &[("authorization", credential)],
                        b"",
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{host}{path}");
            assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
            let text = String::from_utf8(body).unwrap();
            assert!(text.contains("Git LFS is not served"), "{text}");
            if host == "api.github.com" {
                let json: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(json["code"], "placeholder_outside_route");
            } else {
                assert_eq!(
                    headers[http::header::CONTENT_TYPE],
                    "text/plain; charset=utf-8"
                );
            }
            assert_eq!(recorded.leases(), 0, "{host}{path}");
            assert!(recorded.outbound().is_empty(), "{host}{path}");
        }
    }
}

/// Another environment's placeholder on the grammar takes the one lease that
/// shows it is not ours, and is then forwarded untouched like any other
/// value; while ours is fresh, the next one costs no lease.
#[tokio::test]
async fn another_environments_placeholder_is_forwarded_untouched() {
    let recorded = ours();
    let broker = recorded.broker();
    for expected_leases in [1, 1] {
        let request = github(
            "api.github.com",
            "GET",
            "/user",
            "",
            &[("authorization", format!("token {THEIRS}"))],
            b"",
        );
        let (status, _, _) = collect(broker.execute_front_door(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(recorded.leases(), expected_leases);
    }
    assert_eq!(recorded.forwarded(), 2);
    for outbound in recorded.outbound() {
        assert_eq!(
            header(&outbound, "authorization"),
            [format!("token {THEIRS}").as_bytes()]
        );
    }
}

/// A placeholder beside another credential is refused as on every route.
#[tokio::test]
async fn a_placeholder_beside_another_credential_is_refused() {
    let recorded = ours();
    let broker = recorded.broker();
    let (status, headers, body) = collect(
        broker
            .execute_front_door(github(
                "api.github.com",
                "GET",
                "/user",
                "",
                &[
                    ("authorization", format!("token {OURS}")),
                    ("cookie", "user_session=1".to_owned()),
                ],
                b"",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers["codewire-refusal"], "credential_conflict");
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "Codewire: this request carries the Codewire placeholder and another credential; send only one.\n"
    );
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// #4926 behind the front door: where the network policy does not allow
/// GitHub by rule, nothing is sent to either host, with the placeholder,
/// with the user's own token or with no credential, and nothing is leased.
#[tokio::test]
async fn nothing_reaches_github_unless_the_network_policy_allows_it_by_rule() {
    let recorded = ours();
    let refusing = recorded.broker().with_network_policy_allowing_github(false);
    let mut requests = on_the_grammar().to_vec();
    requests.push(github(
        "api.github.com",
        "GET",
        "/rate_limit",
        "",
        &[("authorization", format!("token {USERS_TOKEN}"))],
        b"",
    ));
    requests.push(github(
        "github.com",
        "GET",
        "/git/git.git/info/refs",
        "service=git-upload-pack",
        &[],
        b"",
    ));
    for request in requests.clone() {
        let (status, _, body) = collect(refusing.execute_front_door(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(contains(&body, "network policy"));
    }
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());

    // With a rule for both hosts every one of them is served or forwarded.
    let allowing = recorded.broker().with_network_policy_allowing_github(true);
    for request in requests {
        let (status, _, _) = collect(allowing.execute_front_door(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(recorded.outbound().len(), 4);
    assert_eq!(recorded.forwarded(), 2);
}

/// A forwarded body streams whole whatever its size, on either host.
#[tokio::test]
async fn a_forwarded_body_streams_whole_whatever_its_size() {
    let chunk = vec![b'u'; 1024 * 1024];
    for (host, path, media) in [
        (
            "api.github.com",
            "/repos/owner/repo/git/blobs",
            "application/json",
        ),
        (
            "github.com",
            "/owner/repo.git/git-receive-pack",
            "application/x-git-receive-pack-request",
        ),
    ] {
        let recorded = ours();
        let broker = recorded.broker();
        let mut request = github(
            host,
            "POST",
            path,
            "",
            &[
                ("content-type", media.to_owned()),
                ("authorization", basic(USERS_TOKEN)),
            ],
            b"",
        );
        request.streamed_body = true;
        let (status, _, _) = collect(
            broker
                .execute_front_door_streamed(
                    request,
                    streamed(vec![chunk.clone(); 5]),
                    &Arc::default(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{host}");
        assert_eq!(recorded.leases(), 0);
        assert_eq!(recorded.forwarded(), 1);
        assert_eq!(recorded.outbound()[0].3.len(), 5 * 1024 * 1024, "{host}");
    }
}

/// An API request given the credential keeps the loopback route's 4 MiB
/// bound: at the bound it is served, one byte over it is answered 413 before
/// any lease. A Git POST given the credential streams past it. (The fetch
/// POST stands for both: the test upstream answers with a fetch result.)
#[tokio::test]
async fn a_credentialed_api_body_keeps_its_bound_and_a_git_post_streams() {
    let api = |body_len: usize| {
        let recorded = ours();
        let broker = recorded.broker();
        let mut request = github(
            "api.github.com",
            "POST",
            "/graphql",
            "",
            &[
                ("content-type", "application/json".to_owned()),
                ("authorization", format!("token {OURS}")),
            ],
            b"",
        );
        request.streamed_body = true;
        // A GraphQL body of exactly `body_len` bytes.
        let prefix = b"{\"query\":\"".to_vec();
        let mut body = prefix;
        body.resize(body_len - 2, b'q');
        body.extend_from_slice(b"\"}");
        async move {
            let response = broker
                .execute_front_door_streamed(request, streamed(vec![body]), &Arc::default())
                .await
                .unwrap();
            let (status, _, _) = collect(response).await;
            (status, recorded)
        }
    };
    let (status, recorded) = api(4 * 1024 * 1024).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!((recorded.leases(), recorded.forwarded()), (1, 0));
    assert_eq!(recorded.outbound()[0].3.len(), 4 * 1024 * 1024);

    let (status, recorded) = api(4 * 1024 * 1024 + 1).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());

    let recorded = ours();
    let broker = recorded.broker();
    let mut push = github(
        "github.com",
        "POST",
        "/owner/repo.git/git-upload-pack",
        "",
        &[
            (
                "content-type",
                "application/x-git-upload-pack-request".to_owned(),
            ),
            ("authorization", basic(OURS)),
        ],
        b"",
    );
    push.streamed_body = true;
    let (status, _, _) = collect(
        broker
            .execute_front_door_streamed(
                push,
                streamed(vec![vec![b'p'; 1024 * 1024]; 6]),
                &Arc::default(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!((recorded.leases(), recorded.forwarded()), (1, 0));
    let outbound = recorded.outbound();
    assert_eq!(outbound[0].3.len(), 6 * 1024 * 1024);
    assert!(!carries(&outbound[0], OURS));
}

/// A path the URL parser would write differently is refused rather than
/// sent as something other than what the front door admitted.
#[tokio::test]
async fn a_path_that_would_not_reach_github_byte_for_byte_is_refused() {
    for path in ["/owner/%2e%2e/other", "/owner/./repo", "/a b", "/tab\there"] {
        let recorded = ours();
        let broker = recorded.broker();
        let served = broker
            .execute_front_door(github("api.github.com", "GET", path, "", &[], b""))
            .await;
        assert!(
            matches!(served, Err(BrokerRequestError::InvalidRequest)),
            "{path}"
        );
        assert!(recorded.outbound().is_empty(), "{path}");
    }
}

/// Only a front-door session streams an API body: on the loopback entry it
/// is still an invalid request, and no other slot streams on either.
#[test]
fn only_a_front_door_github_request_streams_an_api_body() {
    let mut api = github("api.github.com", "POST", "/graphql", "", &[], b"");
    api.streamed_body = true;
    assert!(ValidatedGuestRequest::parse(BridgeEntry::FrontDoor, api.clone(), true).is_ok());
    api.intercepted_host.clear();
    assert!(ValidatedGuestRequest::parse(BridgeEntry::Loopback, api, true).is_err());

    let mut other = anthropic("api.anthropic.com", &[]);
    other.streamed_body = true;
    other.body.clear();
    assert!(ValidatedGuestRequest::parse(BridgeEntry::FrontDoor, other, true).is_err());
}

/// #5555: GitHub's forward branch asks the same answer. A broker started
/// without it sends nothing that lacks this environment's placeholder, even
/// where the older GitHub answer (#4926) says yes; a hosted broker never
/// does.
#[tokio::test]
async fn without_the_policys_answer_github_sends_nothing_without_our_placeholder() {
    let own = [("authorization", format!("token {USERS_TOKEN}"))];
    for hosted in [false, true] {
        let recorded = ours();
        let broker = recorded.broker_without_answer();
        let broker = if hosted {
            broker.with_untouched_forwards_refused()
        } else {
            broker
        };
        let refused = broker
            .execute_front_door(github("api.github.com", "GET", "/user", "", &own, b""))
            .await;
        let expected = if hosted {
            BrokerRequestError::SelectedCredentialOnly
        } else {
            BrokerRequestError::NameNotAllowed
        };
        assert_eq!(refused.err(), Some(expected), "hosted: {hosted}");
        assert_eq!(recorded.forwarded(), 0);
        assert!(recorded.outbound().is_empty());
    }
}
