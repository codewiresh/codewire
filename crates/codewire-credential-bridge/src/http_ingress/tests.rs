use super::*;
use crate::*;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

fn request(method: &str, uri: &str, host: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(host) = host {
        request = request.header("host", host);
    }
    request.body(Body::empty()).unwrap()
}

#[test]
fn provider_families_keep_provider_relative_paths_and_queries() {
    for (method, uri, host, slot, route, path, query) in [
        (
            "POST",
            "/v1/responses",
            None,
            "codex",
            "openai-api",
            "/responses",
            None,
        ),
        (
            "GET",
            "/v1/models?client_version=0.160.0",
            None,
            "codex",
            "openai-api",
            "/models",
            Some("client_version=0.160.0"),
        ),
        (
            "POST",
            "/_codewire/openai/v1/chat/completions",
            None,
            "openai",
            "openai-api",
            "/chat/completions",
            None,
        ),
        (
            "POST",
            "/_codewire/anthropic/v1/messages",
            None,
            "anthropic",
            "anthropic-api",
            "/v1/messages",
            None,
        ),
        (
            "POST",
            "/_codewire/anthropic/v1/messages?beta=true",
            Some("127.0.0.1:38081"),
            "anthropic",
            "anthropic-api",
            "/v1/messages",
            Some("beta=true"),
        ),
        (
            "POST",
            "/_codewire/anthropic/v1/messages/count_tokens?beta=true",
            Some("gateway.example"),
            "anthropic",
            "anthropic-api",
            "/v1/messages/count_tokens",
            Some("beta=true"),
        ),
        (
            "GET",
            "/_codewire/anthropic/api/oauth/usage",
            Some("[::1]:38081"),
            "anthropic",
            "anthropic-api",
            "/api/oauth/usage",
            None,
        ),
        (
            "DELETE",
            "/_codewire/anthropic/v1/files/file%2Dabc",
            None,
            "anthropic",
            "anthropic-api",
            "/v1/files/file%2Dabc",
            None,
        ),
        (
            "GET",
            "/user",
            Some("api.github.com"),
            "github",
            "github-api",
            "/user",
            None,
        ),
        (
            "GET",
            "/repos/owner/repo/issues?state=open&labels=good%20first+issue&page=2",
            Some("api.github.com"),
            "github",
            "github-api",
            "/repos/owner/repo/issues",
            Some("state=open&labels=good%20first+issue&page=2"),
        ),
        (
            "POST",
            "/graphql",
            Some("api.github.com"),
            "github",
            "github-api",
            "/graphql",
            None,
        ),
        // The API root `gh auth status` reads: GET only, with no query.
        (
            "GET",
            "/",
            Some("api.github.com"),
            "github",
            "github-api",
            "/",
            None,
        ),
        (
            "PATCH",
            "/repos/owner/repo/issues/7",
            Some("api.github.com"),
            "github",
            "github-api",
            "/repos/owner/repo/issues/7",
            None,
        ),
        (
            "PUT",
            "/repos/owner/repo/pulls/7/merge",
            Some("api.github.com"),
            "github",
            "github-api",
            "/repos/owner/repo/pulls/7/merge",
            None,
        ),
        (
            "GET",
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
            Some("127.0.0.1:38081"),
            "github",
            "github-https",
            "/owner/repo.git/info/refs",
            Some("service=git-upload-pack"),
        ),
        (
            "GET",
            "/_codewire/github/owner/repo.git/info/refs?service=git-receive-pack",
            None,
            "github",
            "github-https",
            "/owner/repo.git/info/refs",
            Some("service=git-receive-pack"),
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/git-upload-pack",
            None,
            "github",
            "github-https",
            "/owner/repo.git/git-upload-pack",
            None,
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/git-receive-pack",
            None,
            "github",
            "github-https",
            "/owner/repo.git/git-receive-pack",
            None,
        ),
    ] {
        let request = request(method, uri, host);
        let classified =
            classify_http_request(request.method(), request.uri(), request.headers()).unwrap();
        assert_eq!(
            classified,
            ClassifiedHttpRequest {
                capability_slot: slot,
                route,
                path,
                query
            }
        );
    }
}

#[test]
fn wrong_provider_hosts_routes_and_methods_are_denied() {
    for (method, uri, host) in rejected_routes() {
        let request = request(method, uri, host);
        assert_eq!(
            classify_http_request(request.method(), request.uri(), request.headers()),
            Err(StatusCode::FORBIDDEN),
            "{method} {uri} {host:?}",
        );
    }
}

#[tokio::test]
async fn explicit_openai_prefix_selects_only_its_distinct_api_key_slot() {
    let path = format!("{MANAGED_OPENAI_API_PREFIX}/responses");
    let frame = crate::prepare_guest_request(request("POST", &path, None))
        .await
        .unwrap();
    assert_eq!(frame.capability_slot, "openai");
    assert_eq!(frame.route, "openai-api");
    assert_eq!(frame.path, "/responses");
    assert!(frame.query.is_empty());
    let codex = crate::prepare_guest_request(request("POST", "/v1/responses", None))
        .await
        .unwrap();
    assert_eq!(codex.capability_slot, "codex");
    for (method, uri) in [
        ("GET", path.clone()),
        ("POST", format!("{path}?query=x")),
        (
            "POST",
            format!("{MANAGED_OPENAI_API_PREFIX}/chat/completions"),
        ),
    ] {
        let request = request(method, &uri, None);
        let classified =
            classify_http_request(request.method(), request.uri(), request.headers()).unwrap();
        assert_eq!(classified.capability_slot, "openai", "{method} {uri}");
    }
    for (method, uri, host) in [
        ("POST", path.clone(), Some("api.github.com")),
        (
            "POST",
            format!("{MANAGED_OPENAI_API_PREFIX}0/responses"),
            None,
        ),
        (
            "POST",
            format!("{MANAGED_OPENAI_API_PREFIX}/../responses"),
            None,
        ),
    ] {
        let request = request(method, &uri, host);
        assert!(classify_http_request(request.method(), request.uri(), request.headers()).is_err());
    }
}

fn rejected_routes() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
    vec![
        // Provider families admit anything below their base path, so only
        // paths outside every base, unsafe paths and GitHub hosts fail.
        ("POST", "/", None),
        ("GET", "/v2/models", None),
        ("POST", "/messages", None),
        ("POST", "/_codewire/anthropic0/v1/messages", None),
        ("POST", "/_codewire/anthropic/v1/../messages", None),
        ("POST", "/_codewire/anthropic/v1//messages", None),
        ("POST", "/_codewire/openai/v10/responses", None),
        (
            "POST",
            "/_codewire/openai/v1/responses",
            Some("api.github.com"),
        ),
        ("POST", "/v1/responses", Some("api.github.com")),
        (
            "POST",
            "/_codewire/anthropic/v1/messages",
            Some("api.github.com"),
        ),
        (
            "POST",
            "/_codewire/github/owner/repo/git-upload-pack",
            Some("api.github.com"),
        ),
        ("GET", "/user", None),
        ("GET", "/user", Some("api.github.com.evil.example")),
        ("GET", "/user", Some("github.com")),
        ("DELETE", "/user", Some("api.github.com")),
        ("GET", "/graphql", Some("api.github.com")),
        ("POST", "/graphql?query=anything", Some("api.github.com")),
        ("HEAD", "/repos/owner/repo/issues", Some("api.github.com")),
        ("GET", "/admin", Some("api.github.com")),
        // Near misses of the API root, and the README `gh repo view` reads:
        // a private repository's README carries a GitHub-minted download
        // token, and no token enters the Sandbox.
        ("GET", "/repos/owner/repo/readme", Some("api.github.com")),
        ("GET", "/?x=1", Some("api.github.com")),
        ("GET", "/?", Some("api.github.com")),
        ("POST", "/", Some("api.github.com")),
        ("HEAD", "/", Some("api.github.com")),
        ("PUT", "/", Some("api.github.com")),
        ("DELETE", "/", Some("api.github.com")),
        ("GET", "//", Some("api.github.com")),
        (
            "GET",
            "/repos/owner/repo/readme/docs",
            Some("api.github.com"),
        ),
        (
            "GET",
            "/repos/owner/repo/readme?ref=x",
            Some("api.github.com"),
        ),
        ("GET", "/repos/owner/repo/readme/", Some("api.github.com")),
        ("GET", "/repos/owner/repo/./readme", Some("api.github.com")),
        (
            "GET",
            "/repos/owner/repo/../repo/readme",
            Some("api.github.com"),
        ),
        ("POST", "/repos/owner/repo/readme", Some("api.github.com")),
        ("HEAD", "/repos/owner/repo/readme", Some("api.github.com")),
        // The same requests on the Git host or with no host never reach the
        // API: there is no GitHub route for them.
        ("GET", "/", Some("github.com")),
        ("GET", "/", None),
        ("GET", "/repos/owner/repo/readme", Some("github.com")),
        ("GET", "/repos/owner/repo/readme", None),
        ("GET", "/_codewire/github/owner/repo/readme", None),
        ("GET", "/_codewire/github/", None),
        ("GET", "/repos/owner/repo/actions", Some("api.github.com")),
        ("GET", "/repos/owner/repo/secrets", Some("api.github.com")),
        (
            "GET",
            "/repos/owner/repo/releases/assets/7",
            Some("api.github.com"),
        ),
        (
            "GET",
            "/repos/owner/repo/issues/1/comments/2/extra",
            Some("api.github.com"),
        ),
        (
            "GET",
            "/owner/repo.git/info/refs?service=git-upload-pack",
            None,
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
            None,
        ),
        ("GET", "/_codewire/github/owner/repo.git/info/refs", None),
        (
            "GET",
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack&x=1",
            None,
        ),
        (
            "GET",
            "/_codewire/github/owner/repo.git/git-upload-pack",
            None,
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/git-upload-pack?x=1",
            None,
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/info/lfs/objects/batch",
            None,
        ),
        ("POST", "/_codewire/github/owner/repo.git/objects", None),
        (
            "POST",
            "/_codewire/githubx/owner/repo.git/git-upload-pack",
            None,
        ),
        ("CONNECT", "api.github.com:443", Some("api.github.com")),
        ("OPTIONS", "*", Some("api.github.com")),
        (
            "POST",
            "https://api.github.com/graphql",
            Some("api.github.com"),
        ),
        (
            "POST",
            "http://127.0.0.1:38081/v1/responses",
            Some("127.0.0.1:38081"),
        ),
        ("GET", "//api.github.com/user", Some("api.github.com")),
    ]
}

#[test]
fn duplicate_and_ambiguous_hosts_do_not_fall_through_to_managed_routes() {
    for host in [
        "",
        "api.github.com:443",
        "API.GITHUB.COM",
        "api.github.com.",
        "api.github.com,api.github.com",
        "user@api.github.com",
        "api.github.com/path",
        "api.github.com\\evil",
        "api.github.com%2f",
        " api.github.com",
        "api.github.com ",
        "api.github.com:",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:038081",
        "bad_host",
        "-host.example",
        "host-.example",
        "[not-ipv6]",
    ] {
        let request = request("POST", "/v1/responses", Some(host));
        assert!(
            classify_http_request(request.method(), request.uri(), request.headers()).is_err(),
            "{host}"
        );
    }
    for uri in ["/v1/responses", "/graphql"] {
        let mut request = request("POST", uri, Some("api.github.com"));
        request
            .headers_mut()
            .append("host", HeaderValue::from_static("api.github.com"));
        assert!(classify_http_request(request.method(), request.uri(), request.headers()).is_err());
        request
            .headers_mut()
            .insert("host", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(classify_http_request(request.method(), request.uri(), request.headers()).is_err());
    }
}

#[test]
fn malformed_paths_and_query_components_are_denied_without_normalization() {
    for uri in [
        "/repos/owner//issues",
        "/repos/owner/repo/../issues",
        "/repos/owner/repo/./issues",
        "/repos/owner/repo/issues/",
        "/repos/owner/repo/issues%2f1",
        "/repos/owner/repo/%69ssues",
        "/repos/owner/repo/issues?state=%",
        "/repos/owner/repo/issues?state=%0",
        "/repos/owner/repo/issues?state=%GG",
        "/repos/owner/repo/issues?state=%00",
        "/repos/owner/repo/issues?state=%0d%0a",
        "/repos/owner/repo/issues?state=%FF",
        "/repos/owner/repo/issues?state=%C0%80",
        "/repos/owner/repo/issues?state=%C2%85",
        "/repos/owner/repo/issues?state=open&&page=1",
        "/repos/owner/repo/issues?state=open&",
        "/repos/owner/repo/issues?=open",
        "/repos/owner/repo/issues?state",
        "/repos/owner/repo/issues?state=open&%73tate=closed",
        "/repos/owner/repo/issues?state=open&state=closed",
        "/repos/owner/repo/issues?bad+key=x",
    ] {
        let request = request("GET", uri, Some("api.github.com"));
        assert!(
            classify_http_request(request.method(), request.uri(), request.headers()).is_err(),
            "{uri}"
        );
    }
}

#[test]
fn lexical_routing_limits_do_not_expand_broker_bounds() {
    for uri in [
        format!("/repos/{}/repo/issues", "o".repeat(129)),
        format!("/repos/owner/repo/issues?labels={}", "x".repeat(1025)),
        format!("/repos/owner/repo/issues?{}=value", "k".repeat(129)),
        format!(
            "/repos/owner/repo/issues?{}",
            (0..33)
                .map(|n| format!("key{n}=v"))
                .collect::<Vec<_>>()
                .join("&")
        ),
        format!(
            "/repos/owner/repo/issues?labels={}",
            "x".repeat(MAX_QUERY_BYTES)
        ),
        format!("/{}", "segment/".repeat(300)),
    ] {
        let request = request("GET", &uri, Some("api.github.com"));
        assert!(classify_http_request(request.method(), request.uri(), request.headers()).is_err());
    }
}

#[test]
fn classifier_selects_families_without_claiming_exact_broker_authority() {
    // These are syntactically valid families, not valid provider operations.
    // The broker, not this material-free crate, rejects the suffix/query/ID.
    for uri in [
        "/repos/owner/repo/issues/not-a-number",
        "/repos/owner/repo/issues?unknown=value",
    ] {
        let request = request("GET", uri, Some("api.github.com"));
        assert_eq!(
            classify_http_request(request.method(), request.uri(), request.headers())
                .unwrap()
                .route,
            "github-api"
        );
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("bounded synthetic ingress")
}

#[tokio::test]
async fn active_bridge_emits_exact_provider_frames_and_preserves_body() {
    let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
    let (prepared, mut output) = bridge.prepare_connection().unwrap();
    assert!(matches!(
        bounded(output.next()).await.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    let (input, receiver) = mpsc::channel(8);
    let connection = prepared
        .activate(ReceiverStream::new(receiver))
        .await
        .unwrap();
    let task = tokio::spawn(connection.run());
    for (method, uri, host, slot, route, path, query) in [
        (
            "POST",
            "/_codewire/openai/v1/responses",
            None,
            "openai",
            "openai-api",
            "/responses",
            "",
        ),
        (
            "POST",
            "/v1/responses",
            None,
            "codex",
            "openai-api",
            "/responses",
            "",
        ),
        (
            "POST",
            "/_codewire/anthropic/v1/messages?beta=true",
            None,
            "anthropic",
            "anthropic-api",
            "/v1/messages",
            "beta=true",
        ),
        (
            "GET",
            "/_codewire/anthropic/api/oauth/usage",
            None,
            "anthropic",
            "anthropic-api",
            "/api/oauth/usage",
            "",
        ),
        (
            "GET",
            "/repos/owner/repo/issues?state=open&page=2",
            Some("api.github.com"),
            "github",
            "github-api",
            "/repos/owner/repo/issues",
            "state=open&page=2",
        ),
        (
            "POST",
            "/graphql",
            Some("api.github.com"),
            "github",
            "github-api",
            "/graphql",
            "",
        ),
        (
            "GET",
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
            None,
            "github",
            "github-https",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
        ),
        (
            "POST",
            "/_codewire/github/owner/repo.git/git-receive-pack",
            None,
            "github",
            "github-https",
            "/owner/repo.git/git-receive-pack",
            "",
        ),
    ] {
        let mut request = request(method, uri, host);
        let bytes = if method == "GET" {
            &b""[..]
        } else {
            &b"synthetic-body\x00"[..]
        };
        *request.body_mut() = Body::from(bytes);
        request
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
        let current = bridge.clone();
        let response = tokio::spawn(async move { current.respond(request).await });
        let Some(GuestPayload::Request(frame)) =
            bounded(output.next()).await.unwrap().unwrap().payload
        else {
            panic!("HTTP frame expected");
        };
        assert_eq!(
            (
                &*frame.capability_slot,
                &*frame.route,
                &*frame.method,
                &*frame.path,
                &*frame.query
            ),
            (slot, route, method, path, query)
        );
        assert_eq!(frame.body, bytes);
        assert!(
            frame
                .headers
                .iter()
                .any(|h| h.name == "content-type" && h.value == b"application/json")
        );
        for payload in [
            HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
                request_id: frame.request_id.clone(),
                status_code: 200,
                headers: Vec::new(),
            }),
            HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
                request_id: frame.request_id,
            }),
        ] {
            bounded(input.send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })))
            .await
            .unwrap();
        }
        let response = bounded(response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            bounded(to_bytes(response.into_body(), 1))
                .await
                .unwrap()
                .is_empty()
        );
    }
    drop(input);
    bounded(task).await.unwrap();
}

#[tokio::test]
async fn unsupported_requests_poll_no_body_emit_no_frame_and_change_no_epoch() {
    let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
    let (prepared, mut output) = bridge.prepare_connection().unwrap();
    assert!(matches!(
        bounded(output.next()).await.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    for active in [false, true] {
        let mut connection_task = None;
        let mut input = None;
        if active {
            let (sender, receiver) = mpsc::channel(1);
            let (next_prepared, mut next_output) = bridge.prepare_connection().unwrap();
            assert!(matches!(
                bounded(next_output.next()).await.unwrap().unwrap().payload,
                Some(GuestPayload::Ready(_))
            ));
            output = next_output;
            connection_task = Some(tokio::spawn(
                next_prepared
                    .activate(ReceiverStream::new(receiver))
                    .await
                    .unwrap()
                    .run(),
            ));
            input = Some(sender);
        }
        let before = bridge.inner.lock().await.next_epoch;
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rejected = rejected_routes()
            .into_iter()
            .map(|(method, uri, host)| request(method, uri, host));
        for mut request in rejected.chain(upgrade_attempts()) {
            let count = polls.clone();
            *request.body_mut() = Body::from_stream(
                tokio_stream::iter([Ok::<_, io::Error>(WireBytes::from_static(b"body"))]).map(
                    move |chunk| {
                        count.fetch_add(1, Ordering::SeqCst);
                        chunk
                    },
                ),
            );
            assert_eq!(
                bounded(bridge.respond(request)).await.status(),
                StatusCode::FORBIDDEN
            );
            assert!(matches!(
                output.frames.as_mut().try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let state = bridge.inner.lock().await;
        assert_eq!(state.next_epoch, before);
        assert_eq!(state.active.is_some(), active);
        assert!(state.pending.is_empty());
        assert!(state.projections.is_empty());
        drop(state);
        drop(input);
        if let Some(task) = connection_task {
            bounded(task).await.unwrap();
        }
    }
    drop(prepared);
}

fn upgrade_attempts() -> Vec<Request<Body>> {
    let mut requests = Vec::new();
    for (uri, host) in [
        ("/user", "api.github.com"),
        (
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
            "localhost",
        ),
    ] {
        for (name, value) in [
            ("upgrade", "websocket"),
            ("upgrade", "h2c"),
            ("connection", "keep-alive, UpGrAdE"),
            ("sec-websocket-key", "synthetic"),
            ("sec-websocket-version", "13"),
        ] {
            let mut request = request("GET", uri, Some(host));
            request
                .headers_mut()
                .append(name, HeaderValue::from_static(value));
            requests.push(request);
        }
    }
    requests
}

#[tokio::test]
async fn newly_routed_requests_keep_existing_body_and_header_limits() {
    let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
    for (uri, host) in [
        ("/_codewire/openai/v1/responses", None),
        ("/_codewire/anthropic/v1/messages", None),
        ("/graphql", Some("api.github.com")),
        ("/_codewire/github/owner/repo.git/git-upload-pack", None),
    ] {
        let mut oversized = request("POST", uri, host);
        *oversized.body_mut() = Body::from(vec![0; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1]);
        assert_eq!(
            bounded(bridge.respond(oversized)).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let mut oversized = request("POST", uri, host);
        oversized.headers_mut().insert(
            "x-test",
            HeaderValue::from_str(&"x".repeat(CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES + 1))
                .unwrap(),
        );
        assert_eq!(
            bounded(bridge.respond(oversized)).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(bridge.inner.lock().await.active.is_none());
}
