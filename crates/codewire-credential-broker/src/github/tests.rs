use super::*;
use crate::http_test_support::{Lease, TOKEN as VALUE};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use std::sync::atomic::Ordering;

fn headers(content_type: &str) -> HeaderMap {
    HeaderMap::from_iter([(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    )])
}
fn lease(operation: GitHubOperation) -> Lease {
    Lease::new(
        "github",
        CredentialAuthKind::OAuth,
        "github",
        operation.operation_name(),
        operation.route_name(),
    )
}
fn prepared(operation: GitHubOperation) -> PreparedGitHubRequest {
    let (path, body, media) = match operation {
        GitHubOperation::Rest => (
            "/repos/owner/repo/issues",
            br#"{"title":"synthetic"}"#.as_slice(),
            "application/json",
        ),
        GitHubOperation::Graphql => (
            "/graphql",
            br#"{"query":"query { viewer { login } }"}"#.as_slice(),
            "application/json",
        ),
        GitHubOperation::GitFetch => (
            "/owner/repo.git/git-upload-pack",
            b"0000".as_slice(),
            "application/x-git-upload-pack-request",
        ),
        GitHubOperation::GitPush => (
            "/owner/repo.git/git-receive-pack",
            b"0000".as_slice(),
            "application/x-git-receive-pack-request",
        ),
    };
    let adapter = GitHubOAuthAdapter::new().unwrap();
    let request = adapter
        .validate_request(
            operation.route_name(),
            &Method::POST,
            path,
            None,
            headers(media),
            body.to_vec(),
        )
        .unwrap();
    adapter
        .prepare_validated(lease(operation), request)
        .unwrap()
}

#[test]
fn gzip_fetch_keeps_exact_bounded_wire_body_and_fixed_upstream_without_decompression() {
    // Deterministic gzip member for the Git flush packet "0000" (gzip -n).
    let body = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x33\x30\x30\x30\x00\x00\x72\xc4\x9b\x0c\x04\x00\x00\x00";
    let adapter = GitHubOAuthAdapter::new().unwrap();
    let mut input = headers("application/x-git-upload-pack-request");
    input.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let request = adapter
        .validate_request(
            "github-https",
            &Method::POST,
            "/owner/repo.git/git-upload-pack",
            None,
            input.clone(),
            body.to_vec(),
        )
        .unwrap();
    let (method, target, outbound, forwarded, response) = adapter
        .prepare_validated(lease(GitHubOperation::GitFetch), request)
        .unwrap()
        .into_parts();
    assert_eq!(method, Method::POST);
    assert_eq!(
        target.as_str(),
        "https://github.com/owner/repo.git/git-upload-pack"
    );
    assert_eq!(outbound[header::CONTENT_ENCODING], "gzip");
    assert_eq!(forwarded, body);
    assert_eq!(outbound[header::ACCEPT_ENCODING], "identity");
    // Request compatibility does not allow compressed provider responses.
    let mut compressed_response = headers("application/x-git-upload-pack-result");
    compressed_response.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    assert!(
        response
            .begin(StatusCode::OK, &compressed_response)
            .is_err()
    );
    assert!(
        adapter
            .validate_request(
                "github-https",
                &Method::POST,
                "/owner/repo.git/git-upload-pack",
                None,
                input.clone(),
                vec![0; MAX_REQUEST_BYTES + 1]
            )
            .is_err()
    );
    assert!(
        adapter
            .validate_request(
                "github-https",
                &Method::POST,
                "/owner/repo.git/git-upload-pack",
                None,
                input,
                Vec::new()
            )
            .is_err()
    );
}

#[test]
fn gzip_is_only_one_exact_coding_on_fetch_post_never_an_api_push_or_get_alias() {
    let adapter = GitHubOAuthAdapter::new().unwrap();
    for coding in [
        "GZIP",
        "br",
        "deflate",
        "identity,gzip",
        "gzip,identity",
        "gzip;q=1",
        "",
        " gzip",
    ] {
        let mut input = headers("application/x-git-upload-pack-request");
        input.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_str(coding).unwrap(),
        );
        assert!(
            adapter
                .validate_request(
                    "github-https",
                    &Method::POST,
                    "/owner/repo.git/git-upload-pack",
                    None,
                    input,
                    b"opaque".to_vec()
                )
                .is_err(),
            "{coding:?}"
        );
    }
    let mut input = headers("application/x-git-upload-pack-request");
    input.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    input.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    assert!(
        adapter
            .validate_request(
                "github-https",
                &Method::POST,
                "/owner/repo.git/git-upload-pack",
                None,
                input,
                b"opaque".to_vec()
            )
            .is_err()
    );
    for (route, method, path, query, media) in [
        (
            "github-api",
            Method::POST,
            "/graphql",
            None,
            "application/json",
        ),
        (
            "github-api",
            Method::POST,
            "/user/repos",
            None,
            "application/json",
        ),
        (
            "github-https",
            Method::POST,
            "/owner/repo.git/git-receive-pack",
            None,
            "application/x-git-receive-pack-request",
        ),
        (
            "github-https",
            Method::GET,
            "/owner/repo.git/info/refs",
            Some("service=git-upload-pack"),
            "application/x-git-upload-pack-request",
        ),
        (
            "github-https",
            Method::POST,
            "/owner/repo.git/git-upload-pack",
            None,
            "application/json",
        ),
    ] {
        let mut input = headers(media);
        input.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(
            adapter
                .validate_request(route, &method, path, query, input, b"opaque".to_vec())
                .is_err()
        );
    }
}

#[test]
fn finite_routes_bind_exact_operations_and_never_normalize_path_aliases() {
    for (route, method, path, query, expected) in [
        (
            "github-api",
            Method::GET,
            "/user",
            None,
            GitHubOperation::Rest,
        ),
        (
            "github-api",
            Method::GET,
            "/repos/owner/repo/pulls/12/files",
            Some("page=2&per_page=50"),
            GitHubOperation::Rest,
        ),
        (
            "github-api",
            Method::PATCH,
            "/repos/owner/repo/issues/12",
            None,
            GitHubOperation::Rest,
        ),
        (
            "github-api",
            Method::PUT,
            "/repos/owner/repo/pulls/12/merge",
            None,
            GitHubOperation::Rest,
        ),
        (
            "github-api",
            Method::POST,
            "/graphql",
            None,
            GitHubOperation::Graphql,
        ),
        // The API root `gh auth status` reads, and the README `gh repo view`
        // shows (an owner-accepted exception, see SECRETS-AND-CREDENTIALS.md):
        // GET only, with no query.
        ("github-api", Method::GET, "/", None, GitHubOperation::Rest),
        (
            "github-api",
            Method::GET,
            "/repos/owner/repo/readme",
            None,
            GitHubOperation::Rest,
        ),
        (
            "github-api",
            Method::GET,
            "/",
            Some(""),
            GitHubOperation::Rest,
        ),
        (
            "github-https",
            Method::GET,
            "/owner/repo.git/info/refs",
            Some("service=git-upload-pack"),
            GitHubOperation::GitFetch,
        ),
        (
            "github-https",
            Method::GET,
            "/owner/repo/info/refs",
            Some("service=git-receive-pack"),
            GitHubOperation::GitPush,
        ),
        (
            "github-https",
            Method::POST,
            "/owner/repo.git/git-upload-pack",
            None,
            GitHubOperation::GitFetch,
        ),
        (
            "github-https",
            Method::POST,
            "/owner/repo.git/git-receive-pack",
            None,
            GitHubOperation::GitPush,
        ),
    ] {
        assert_eq!(
            classify_request(route, &method, path, query),
            Ok(expected),
            "{path}"
        );
    }
    for path in [
        "/repos/owner/repo/actions",
        "/repos/owner/repo/secrets",
        "/repos/owner/repo/releases",
        "/admin",
        "/applications",
        "/user/keys",
        "/repos/owner/repo/issues/01",
        "/repos/owner/repo/issues/0",
        "/repos/owner/repo/../issues",
        "//user",
        "/user/",
        "/%75ser",
        "https://api.github.com/user",
    ] {
        assert!(
            classify_request("github-api", &Method::GET, path, None).is_err(),
            "{path}"
        );
    }
    for (path, query) in [
        ("/owner/repo.git/HEAD", None),
        ("/owner/repo.git/objects/pack/pack-x", None),
        ("/owner/repo.git/info/lfs", None),
        (
            "/owner/repo.git/info/refs",
            Some("service=git-upload-pack&extra=x"),
        ),
        (
            "/owner/repo.git/info/refs",
            Some("service=git-upload-archive"),
        ),
        (
            "/owner/repo.git/info/refs",
            Some("service=git-upload-pack&service=git-upload-pack"),
        ),
    ] {
        assert!(classify_request("github-https", &Method::GET, path, query).is_err());
    }
    for query in [
        "url=https://evil.test",
        "page=1&page=2",
        "page=%XX",
        "state=%00",
    ] {
        assert!(classify_request("github-api", &Method::GET, "/user", Some(query)).is_err());
    }
    assert!(classify_request("github-api", &Method::DELETE, "/repos/owner/repo", None).is_err());
    assert!(classify_request("github-api", &Method::GET, "/graphql", None).is_err());

    // Near misses of the two requests admitted for stock `gh`.
    for (method, path, query) in [
        (Method::GET, "/", Some("x=1")),
        (Method::GET, "/", Some("page=1")),
        (Method::POST, "/", None),
        (Method::HEAD, "/", None),
        (Method::PUT, "/", None),
        (Method::PATCH, "/", None),
        (Method::DELETE, "/", None),
        (Method::GET, "//", None),
        (Method::GET, "/repos/owner/repo/readme/docs", None),
        (Method::GET, "/repos/owner/repo/readme", Some("ref=x")),
        (Method::GET, "/repos/owner/repo/readme", Some("page=1")),
        (Method::GET, "/repos/owner/repo/readme/", None),
        (Method::GET, "/repos/owner/repo/./readme", None),
        (Method::GET, "/repos/owner/repo/../readme", None),
        (Method::POST, "/repos/owner/repo/readme", None),
        (Method::PUT, "/repos/owner/repo/readme", None),
        (Method::DELETE, "/repos/owner/repo/readme", None),
        (Method::HEAD, "/repos/owner/repo/readme", None),
    ] {
        assert!(
            classify_request("github-api", &method, path, query).is_err(),
            "{method} {path} {query:?}"
        );
    }
    // The same requests on the Git host are never API requests.
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/repos/owner/repo/readme"),
        (Method::GET, "/owner/repo/readme"),
    ] {
        assert!(
            classify_request("github-https", &method, path, None).is_err(),
            "{path}"
        );
    }
    // Still refused, as before: Actions runs, arbitrary REST and release
    // uploads.
    for (method, path) in [
        (Method::GET, "/repos/owner/repo/actions/runs"),
        (Method::GET, "/repos/owner/repo/contents/README.md"),
        (Method::GET, "/repos/owner/repo/releases/tags/v1"),
        (Method::POST, "/repos/owner/repo/releases/1/assets"),
        (Method::GET, "/rate_limit"),
    ] {
        assert!(
            classify_request("github-api", &method, path, None).is_err(),
            "{path}"
        );
    }
}

/// The newly admitted API root and README are prepared like every other
/// REST call: one exact path on api.github.com, the injected bearer only, and
/// nothing of the guest's own authorization forwarded.
#[test]
fn the_api_root_and_readme_go_only_to_their_exact_api_path_with_the_injected_bearer() {
    let adapter = GitHubOAuthAdapter::new().unwrap();
    for path in ["/", "/repos/owner/repo/readme"] {
        let mut input = HeaderMap::new();
        input.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("token codewire-managed"),
        );
        input.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.github.merge-info-preview+json"),
        );
        let valid = adapter
            .validate_request("github-api", &Method::GET, path, None, input, vec![])
            .unwrap();
        assert_eq!(valid.operation(), GitHubOperation::Rest);
        let (method, target, outbound, body, response) = adapter
            .prepare_validated(lease(GitHubOperation::Rest), valid)
            .unwrap()
            .into_parts();
        assert_eq!(method, Method::GET);
        assert_eq!(target.as_str(), format!("https://api.github.com{path}"));
        assert!(body.is_empty());
        assert_eq!(
            outbound[header::AUTHORIZATION],
            format!("Bearer {}", std::str::from_utf8(VALUE).unwrap())
        );
        assert!(
            !outbound
                .values()
                .any(|value| value == "token codewire-managed")
        );
        // Their responses get the REST redaction: a provider that echoed the
        // injected token, raw or base64 as a README's content would be, never
        // returns it to the Sandbox.
        let (_, mut redacted) = response
            .begin(StatusCode::OK, &headers("application/json"))
            .unwrap();
        let mut output = redacted
            .push(format!("{{\"content\":\"{}\",\"raw\":\"", STANDARD.encode(VALUE)).as_bytes())
            .unwrap();
        output.extend(redacted.push(VALUE).unwrap());
        output.extend(redacted.push(b"\"}").unwrap());
        output.extend(redacted.finish().unwrap());
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains(std::str::from_utf8(VALUE).unwrap()));
        assert!(!output.contains(&STANDARD.encode(VALUE)));
        assert_eq!(output.matches("[REDACTED]").count(), 2, "{path}");
    }
}

#[test]
fn bearer_and_basic_injection_never_forward_caller_credentials_or_authority() {
    for operation in [
        GitHubOperation::Rest,
        GitHubOperation::Graphql,
        GitHubOperation::GitFetch,
        GitHubOperation::GitPush,
    ] {
        let (method, target, outbound, _, _) = prepared(operation).into_parts();
        assert_eq!(method, Method::POST);
        assert_eq!(
            target.host_str(),
            Some(if operation.is_git() {
                "github.com"
            } else {
                "api.github.com"
            })
        );
        let expected = if operation.is_git() {
            format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "x-access-token:{}",
                    std::str::from_utf8(VALUE).unwrap()
                ))
            )
        } else {
            format!("Bearer {}", std::str::from_utf8(VALUE).unwrap())
        };
        assert_eq!(outbound[header::AUTHORIZATION], expected);
        assert!(outbound[header::AUTHORIZATION].is_sensitive());
        assert_eq!(outbound[header::ACCEPT_ENCODING], "identity");
        assert_eq!(outbound[header::USER_AGENT], "Codewire-Credential-Broker");
    }
    let adapter = GitHubOAuthAdapter::new().unwrap();
    let mut input = HeaderMap::new();
    for name in [
        "authorization",
        "cookie",
        "proxy-authorization",
        "host",
        "user-agent",
        "x-github-token",
        "x-http-method-override",
    ] {
        input.insert(
            http::HeaderName::from_static(name),
            HeaderValue::from_static("guest-canary"),
        );
    }
    let valid = adapter
        .validate_request("github-api", &Method::GET, "/user", None, input, vec![])
        .unwrap();
    let (_, _, outbound, _, _) = adapter
        .prepare_validated(lease(GitHubOperation::Rest), valid)
        .unwrap()
        .into_parts();
    assert!(!outbound.values().any(|value| value == "guest-canary"));
}

#[test]
fn invalid_framing_bodies_and_graphql_documents_fail_before_a_lease_is_needed() {
    let adapter = GitHubOAuthAdapter::new().unwrap();
    for body in [
        b"not-json".to_vec(),
        b"[]".to_vec(),
        br#"{"query":""}"#.to_vec(),
        br#"{"query":"query { viewer { login } }","url":"https://evil.test"}"#.to_vec(),
        vec![b'x'; MAX_REQUEST_BYTES + 1],
    ] {
        assert!(
            adapter
                .validate_request(
                    "github-api",
                    &Method::POST,
                    "/graphql",
                    None,
                    headers("application/json"),
                    body
                )
                .is_err()
        );
    }
    for name in ["content-encoding", "upgrade", "git-protocol"] {
        let mut input = headers("application/json");
        input.insert(
            http::HeaderName::from_static(name),
            HeaderValue::from_static("invalid"),
        );
        assert!(
            adapter
                .validate_request("github-api", &Method::GET, "/user", None, input, vec![])
                .is_err()
        );
    }
    let mut duplicate = headers("application/json");
    duplicate.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(
        adapter
            .validate_request("github-api", &Method::GET, "/user", None, duplicate, vec![])
            .is_err()
    );
    assert!(
        adapter
            .validate_request(
                "github-api",
                &Method::GET,
                "/user",
                None,
                HeaderMap::new(),
                b"body".to_vec()
            )
            .is_err()
    );
}

#[test]
fn wrong_provider_slot_permission_revision_or_expiry_never_borrows_material() {
    let adapter = GitHubOAuthAdapter::new().unwrap();
    for case in 0..9 {
        let mut lease = lease(GitHubOperation::Rest);
        match case {
            0 => lease.metadata.provider = codewire_access::ProviderId::parse("openai").unwrap(),
            1 => lease.metadata.authentication_kind = CredentialAuthKind::ApiKey,
            2 => lease.grant.capability_slot = codewire_access::CapabilitySlot::codex(),
            3 => {
                lease.permission.operation =
                    codewire_access::BrokerOperationId::parse("git-push").unwrap()
            }
            4 => {
                lease.permission.route =
                    codewire_access::BrokerRouteId::parse("github-https").unwrap()
            }
            5 => lease.metadata.revocation_generation += 1,
            6 => lease.metadata.expires_at_unix = Some(0),
            7 => lease.grant.expires_at_unix = Some(0),
            _ => lease.grant.permissions.clear(),
        }
        let reads = lease.reads.clone();
        let request = adapter
            .validate_request(
                "github-api",
                &Method::GET,
                "/user",
                None,
                HeaderMap::new(),
                vec![],
            )
            .unwrap();
        assert_eq!(
            adapter.prepare_validated(lease, request).err(),
            Some(CredentialBrokerError::UnsupportedLease)
        );
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn complete_actual_authorization_encodings_redact_at_every_split() {
    for operation in [GitHubOperation::Rest, GitHubOperation::GitFetch] {
        let (_, _, request_headers, _, _) = prepared(operation).into_parts();
        let authorization = request_headers[header::AUTHORIZATION].as_bytes();
        for value in [
            VALUE.to_vec(),
            authorization.to_vec(),
            STANDARD.encode(authorization).into_bytes(),
            STANDARD_NO_PAD.encode(authorization).into_bytes(),
            URL_SAFE.encode(authorization).into_bytes(),
            URL_SAFE_NO_PAD.encode(authorization).into_bytes(),
        ] {
            for split in 0..=value.len() {
                let policy = prepared(operation).into_parts().4;
                let (_, mut response) = policy
                    .begin(StatusCode::OK, &headers("text/plain"))
                    .unwrap();
                let mut output = response.push(&value[..split]).unwrap();
                output.extend(response.push(&value[split..]).unwrap());
                output.extend(response.finish().unwrap());
                assert_eq!(output, b"[REDACTED]");
            }
        }
    }
}

#[test]
fn response_coding_media_headers_and_bodyless_status_are_strict() {
    for coding in ["gzip", "br", "identity,gzip", "", "identity;q=1"] {
        let mut input = headers("application/json");
        input.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
        assert!(
            prepared(GitHubOperation::Rest)
                .into_parts()
                .4
                .begin(StatusCode::OK, &input)
                .is_err()
        );
    }
    for media in [
        "application/octet-stream",
        "application/json; charset=utf-16",
        "text/html",
    ] {
        assert!(
            prepared(GitHubOperation::Rest)
                .into_parts()
                .4
                .begin(StatusCode::OK, &headers(media))
                .is_err()
        );
    }
    let mut input = headers("application/json");
    input.insert("x-error-json", HeaderValue::from_static("opaque"));
    input.insert(
        header::LOCATION,
        HeaderValue::from_static("https://evil.test"),
    );
    input.insert(
        "x-github-request-id",
        HeaderValue::from_bytes(VALUE).unwrap(),
    );
    let (output, _) = prepared(GitHubOperation::Rest)
        .into_parts()
        .4
        .begin(StatusCode::OK, &input)
        .unwrap();
    assert!(!output.contains_key("x-error-json"));
    assert!(!output.contains_key(header::LOCATION));
    assert_eq!(output["x-github-request-id"], "[REDACTED]");
    assert!(
        prepared(GitHubOperation::Rest)
            .into_parts()
            .4
            .begin(StatusCode::OK, &HeaderMap::new())
            .is_err()
    );
    assert!(
        prepared(GitHubOperation::Rest)
            .into_parts()
            .4
            .begin(StatusCode::NO_CONTENT, &HeaderMap::new())
            .is_ok()
    );
    let (_, mut response) = prepared(GitHubOperation::GitFetch)
        .into_parts()
        .4
        .begin(
            StatusCode::OK,
            &headers("application/x-git-upload-pack-result"),
        )
        .unwrap();
    let wire = b"0008NAK\nPACK\x00\x01\xff";
    let mut result = response.push(wire).unwrap();
    result.extend(response.finish().unwrap());
    assert_eq!(result, wire);
}
