//! Synthetic upstream fixtures, never a network or credential-store test.

use super::*;
use crate::http_test_support::Lease;

const ANTHROPIC_KEY: &str = "cwlocalanthropic0123456789abcdef0123456789abcdef";
const OPENAI_KEY: &str = "cwlocalopenai0123456789abcdef0123456789abcdef";
const CODEX_KEY: &str = "cwlocalbroker0123456789abcdef0123456789abcdef";

fn anthropic_headers() -> HeaderMap {
    HeaderMap::from_iter([
        (
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ),
        (
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        ),
        (
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static("2023-06-01"),
        ),
        (
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static(ANTHROPIC_KEY),
        ),
    ])
}

fn anthropic_body(messages: bool) -> Vec<u8> {
    let mut body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "Return the synthetic smoke marker."}],
    });
    if messages {
        body["stream"] = true.into();
        body["max_tokens"] = 64.into();
    }
    serde_json::to_vec(&body).unwrap()
}

fn anthropic_request() -> BrokerUpstreamRequest {
    BrokerUpstreamRequest {
        method: Method::POST,
        target: Url::parse("https://api.anthropic.com/v1/messages").unwrap(),
        headers: anthropic_headers(),
        body: anthropic_body(true),
        body_stream: None,
    }
}

fn events(body: &str) -> Vec<serde_json::Value> {
    body.split("\n\n")
        .filter(|event| !event.is_empty())
        .map(|event| {
            let mut lines = event.lines();
            let event_name = lines.next().unwrap().strip_prefix("event: ").unwrap();
            let data = lines.next().unwrap().strip_prefix("data: ").unwrap();
            assert!(lines.next().is_none());
            let data: serde_json::Value = serde_json::from_str(data).unwrap();
            assert_eq!(data["type"], event_name);
            data
        })
        .collect()
}

#[tokio::test]
async fn anthropic_exact_routes_filter_real_injection_and_complete_stream_or_count() {
    for messages in [true, false] {
        for beta in [false, true] {
            let path = if messages {
                "/v1/messages"
            } else {
                "/v1/messages/count_tokens"
            };
            let mut lease = Lease::new(
                "anthropic",
                CredentialAuthKind::ApiKey,
                "anthropic",
                "messages",
                "anthropic-api",
            );
            lease.material = Zeroizing::new(ANTHROPIC_KEY.as_bytes().to_vec());
            let mut headers = anthropic_headers();
            // The adapter must replace/drop caller authentication rather than
            // allowing this synthetic upstream to accept it accidentally.
            headers.insert("x-api-key", HeaderValue::from_static("caller-key"));
            headers.insert("authorization", HeaderValue::from_static("Bearer caller"));
            headers.insert("cookie", HeaderValue::from_static("caller=session"));
            headers.insert("proxy-authorization", HeaderValue::from_static("caller"));
            if beta {
                headers.insert(
                    "anthropic-beta",
                    HeaderValue::from_static("token-counting-2024-11-01"),
                );
            }
            let (method, target, headers, body, policy) = AnthropicApiKeyAdapter::new()
                .unwrap()
                .prepare(
                    lease,
                    &Method::POST,
                    path,
                    beta.then_some("beta=true"),
                    &headers,
                    &anthropic_body(messages),
                )
                .unwrap()
                .into_parts();
            assert_eq!(headers["x-api-key"], ANTHROPIC_KEY);
            assert!(headers["x-api-key"].is_sensitive());
            let response = SyntheticOpenAiSmokeTransport
                .execute(BrokerUpstreamRequest {
                    method,
                    target,
                    headers,
                    body,
                    body_stream: None,
                })
                .await
                .unwrap();
            let (status, headers, mut body) = response.into_parts();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(headers["request-id"], ANTHROPIC_KEY);
            assert!(headers.contains_key("x-error-json"));
            let (headers, mut redaction) = policy.begin(&headers).unwrap();
            assert_eq!(headers["request-id"], "[REDACTED]");
            assert_eq!(headers["x-error-json"], "{\"error\":\"[REDACTED]\"}");
            let mut output = Vec::new();
            let mut chunks = 0;
            while let Some(chunk) = body.next().await {
                let chunk = chunk.unwrap();
                assert!(
                    !chunk
                        .windows(ANTHROPIC_KEY.len())
                        .any(|window| window == ANTHROPIC_KEY.as_bytes())
                );
                chunks += 1;
                output.extend(redaction.push(&chunk).unwrap());
            }
            output.extend(redaction.finish().unwrap());
            let output = String::from_utf8(output).unwrap();
            assert!(!output.contains(ANTHROPIC_KEY));
            if messages {
                assert_eq!(chunks, 2);
                assert_eq!(headers["content-type"], "text/event-stream");
                let events = events(&output);
                assert_eq!(
                    events
                        .iter()
                        .map(|event| event["type"].as_str().unwrap())
                        .collect::<Vec<_>>(),
                    [
                        "message_start",
                        "content_block_start",
                        "content_block_delta",
                        "content_block_stop",
                        "message_delta",
                        "message_stop"
                    ],
                );
                assert_eq!(events[0]["message"]["model"], "claude-sonnet-4-6");
                assert_eq!(
                    events[2]["delta"]["text"],
                    "CWCLAUDE21238 broker [REDACTED]"
                );
                assert_eq!(events[4]["delta"]["stop_reason"], "end_turn");
                assert_eq!(events[4]["usage"]["output_tokens"], 8);
            } else {
                assert_eq!(chunks, 1);
                assert_eq!(headers["content-type"], "application/json");
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&output).unwrap(),
                    serde_json::json!({"input_tokens":42})
                );
            }
        }
    }
}

/// A target the broker never builds fails the fixture; another route, method
/// or query on the pinned origin is a stock-client request the fixture does
/// not serve, which it answers as the provider would.
#[tokio::test]
async fn anthropic_rejects_foreign_targets_and_answers_unserved_routes() {
    for target in [
        "http://api.anthropic.com/v1/messages",
        "https://api.anthropic.com:444/v1/messages",
        "https://user@api.anthropic.com/v1/messages",
        "https://api.anthropic.com/v1/messages#fragment",
        "https://other.example/v1/messages",
    ] {
        let mut request = anthropic_request();
        request.target = Url::parse(target).unwrap();
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    for target in [
        "https://api.anthropic.com/v1/messages?beta=false",
        "https://api.anthropic.com/v1/messages?beta=true&beta=true",
        "https://api.anthropic.com/v1/messages?beta=true&host=other",
        "https://api.anthropic.com/v1/messages/count_tokens?beta=%74rue",
        "https://api.anthropic.com/v1/models",
        "https://api.anthropic.com/v1/messages/batches",
    ] {
        let mut request = anthropic_request();
        request.target = Url::parse(target).unwrap();
        not_found_answer(request, ANTHROPIC_KEY).await;
    }
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let mut request = anthropic_request();
        request.method = method;
        not_found_answer(request, ANTHROPIC_KEY).await;
    }
}

#[tokio::test]
async fn anthropic_rejects_missing_wrong_duplicate_or_caller_headers() {
    for name in [
        "x-api-key",
        "anthropic-version",
        "content-type",
        "accept-encoding",
    ] {
        let mut request = anthropic_request();
        request.headers.remove(name);
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
        let mut request = anthropic_request();
        request
            .headers
            .append(HeaderName::from_static(name), request.headers[name].clone());
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    for (name, value) in [
        ("x-api-key", "caller-key"),
        (
            "x-api-key",
            "cwlocalanthropic0123456789abcdef0123456789abcdeF",
        ),
        (
            "x-api-key",
            "cwlocalanthropic0123456789abcdef0123456789abcde",
        ),
        ("x-api-key", OPENAI_KEY),
        ("anthropic-version", "2020-01-01"),
        ("content-type", "text/plain"),
        ("accept-encoding", "gzip"),
        ("authorization", "Bearer caller"),
        ("cookie", "caller=session"),
        ("proxy-authorization", "caller"),
    ] {
        let mut request = anthropic_request();
        request.headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
}

#[tokio::test]
async fn anthropic_rejects_unexpected_claude_shapes_instead_of_simulating_success() {
    let mut cases = vec![
        Vec::new(),
        b"not JSON".to_vec(),
        b"[]".to_vec(),
        vec![b' '; 4 * 1024 * 1024 + 1],
    ];
    for (name, value) in [
        ("model", serde_json::json!("other-model")),
        ("messages", serde_json::json!([])),
        ("messages", serde_json::Value::Null),
        ("stream", serde_json::json!(false)),
        ("max_tokens", serde_json::json!(0)),
    ] {
        let mut payload: serde_json::Value = serde_json::from_slice(&anthropic_body(true)).unwrap();
        payload[name] = value;
        cases.push(serde_json::to_vec(&payload).unwrap());
    }
    for body in cases {
        let mut request = anthropic_request();
        request.body = body;
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    let mut request = anthropic_request();
    request.target = Url::parse("https://api.anthropic.com/v1/messages/count_tokens").unwrap();
    assert!(matches!(
        SyntheticOpenAiSmokeTransport.execute(request).await,
        Err(BrokerUpstreamError::Protocol)
    ));
}

#[tokio::test]
async fn openai_api_retains_real_redaction_with_a_distinct_marker() {
    let mut lease = Lease::new(
        "openai",
        CredentialAuthKind::ApiKey,
        "openai",
        "responses",
        "openai-api",
    );
    lease.material = Zeroizing::new(OPENAI_KEY.as_bytes().to_vec());
    let headers = HeaderMap::from_iter([(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    )]);
    let (method, target, headers, body, policy) = OpenAiApiKeyAdapter::new().unwrap().prepare(
        lease, &Method::POST, "/responses", None, &headers,
        br#"{"model":"codewire-synthetic","input":"Return the synthetic smoke marker.","stream":true}"#,
    ).unwrap().into_parts();
    let response = SyntheticOpenAiSmokeTransport
        .execute(BrokerUpstreamRequest {
            method,
            target,
            headers,
            body,
            body_stream: None,
        })
        .await
        .unwrap();
    let (_, headers, mut body) = response.into_parts();
    assert_eq!(headers["x-request-id"], OPENAI_KEY);
    assert!(headers.contains_key("x-error-json"));
    let (headers, mut redaction) = policy.begin(&headers).unwrap();
    assert_eq!(headers["x-request-id"], "[REDACTED]");
    assert_eq!(headers["x-error-json"], "{\"error\":\"[REDACTED]\"}");
    let mut output = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.unwrap();
        assert!(
            !chunk
                .windows(OPENAI_KEY.len())
                .any(|window| window == OPENAI_KEY.as_bytes())
        );
        chunks += 1;
        output.extend(redaction.push(&chunk).unwrap());
    }
    output.extend(redaction.finish().unwrap());
    let output = String::from_utf8(output).unwrap();
    assert_eq!(chunks, 2);
    assert!(!output.contains(OPENAI_KEY));
    assert!(output.contains("CWOPENAI broker [REDACTED]"));
    assert_eq!(
        events(&output).last().unwrap()["type"],
        "response.completed"
    );
}

#[tokio::test]
async fn openai_and_chatgpt_route_and_account_negatives_remain_closed() {
    fn request(target: &str) -> BrokerUpstreamRequest {
        let codex = target.contains("chatgpt.com");
        let mut request = BrokerUpstreamRequest {
            method: Method::POST,
            target: Url::parse(target).unwrap(),
            headers: HeaderMap::from_iter([(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    if codex { CODEX_KEY } else { OPENAI_KEY }
                ))
                .unwrap(),
            )]),
            body: br#"{"input":"hello"}"#.to_vec(),
            body_stream: None,
        };
        if codex {
            request.headers.insert(
                "chatgpt-account-id",
                HeaderValue::from_static(SYNTHETIC_CODEX_ACCOUNT_ID),
            );
        }
        request
    }
    for target in [
        "https://api.openai.com/v1/responses",
        "https://chatgpt.com/backend-api/codex/responses",
    ] {
        let valid = request(target);
        let response = SyntheticOpenAiSmokeTransport.execute(valid).await.unwrap();
        let (_, _, mut body) = response.into_parts();
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend_from_slice(&chunk.unwrap());
        }
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains(if target.contains("chatgpt.com") {
                    "CWCODEX149"
                } else {
                    "CWOPENAI"
                })
        );
        for (name, value) in [
            ("chatgpt-account-id", "wrong-account"),
            ("cookie", "caller"),
            ("proxy-authorization", "caller"),
        ] {
            let mut invalid = request(target);
            invalid.headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            assert!(matches!(
                SyntheticOpenAiSmokeTransport.execute(invalid).await,
                Err(BrokerUpstreamError::Protocol)
            ));
        }
        for key in [
            ANTHROPIC_KEY,
            if target.contains("chatgpt.com") {
                OPENAI_KEY
            } else {
                CODEX_KEY
            },
        ] {
            let mut invalid = request(target);
            invalid.headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
            );
            assert!(matches!(
                SyntheticOpenAiSmokeTransport.execute(invalid).await,
                Err(BrokerUpstreamError::Protocol)
            ));
        }
        let mut unserved = request(target);
        unserved.method = Method::GET;
        not_found_answer(
            unserved,
            if target.contains("chatgpt.com") {
                CODEX_KEY
            } else {
                OPENAI_KEY
            },
        )
        .await;
        let mut invalid = request(target);
        invalid.body.clear();
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(invalid).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    for target in [
        "https://api.openai.com/v1/responses?other=true",
        "https://api.openai.com/v1/models",
        "https://chatgpt.com/backend-api/codex/responses?other=true",
    ] {
        not_found_answer(
            request(target),
            if target.contains("chatgpt.com") {
                CODEX_KEY
            } else {
                OPENAI_KEY
            },
        )
        .await;
    }
    for target in [
        "https://other.example/v1/responses",
        "https://api.openai.com/v2/responses",
        "https://chatgpt.com/backend-api/other",
    ] {
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request(target)).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    for authorization in [
        None,
        Some("Bearer short"),
        Some("caller"),
        Some("Bearer cwlocal invalid credential"),
        Some("Bearer cwlocalopenai0123456789abcdef0123456789abcdeF"),
        Some("Bearer cwlocalopenai0123456789abcdef0123456789abcde"),
    ] {
        let mut invalid = request("https://api.openai.com/v1/responses");
        invalid.headers.remove("authorization");
        if let Some(value) = authorization {
            invalid
                .headers
                .insert("authorization", HeaderValue::from_static(value));
        }
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(invalid).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
}

fn exact_api_request(family: &str) -> BrokerUpstreamRequest {
    match family {
        "openai" => BrokerUpstreamRequest {
            method: Method::POST,
            target: Url::parse("https://api.openai.com/v1/responses").unwrap(),
            headers: HeaderMap::from_iter([
                (http::header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
                (http::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {OPENAI_KEY}")).unwrap()),
            ]),
            body: br#"{"model":"codewire-synthetic","input":"Return the synthetic smoke marker.","stream":true}"#.to_vec(),
            body_stream: None,
        },
        "anthropic" => anthropic_request(),
        _ => panic!("unknown test family"),
    }
}

fn exact_api_key(family: &str) -> &'static str {
    match family {
        "openai" => OPENAI_KEY,
        "anthropic" => ANTHROPIC_KEY,
        _ => panic!("unknown test family"),
    }
}

fn exact_api_denied(request: &BrokerUpstreamRequest, expected: &str) {
    assert_eq!(
        SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(request, expected),
        Err(BrokerUpstreamError::Protocol)
    );
}

async fn exact_api_output(request: BrokerUpstreamRequest) -> String {
    let response = SyntheticOpenAiSmokeTransport
        .execute(request)
        .await
        .unwrap();
    let (status, _, mut body) = response.into_parts();
    assert_eq!(status, StatusCode::OK);
    let mut output = Vec::new();
    while let Some(chunk) = body.next().await {
        output.extend_from_slice(&chunk.unwrap());
        assert!(
            output.len() <= 64 * 1024,
            "unexpected fixture response size"
        );
    }
    String::from_utf8(output).unwrap()
}

#[test]
fn exact_api_family_keeps_invalid_api_urls_in_the_selected_branch() {
    for (family, targets) in [
        (
            "openai",
            vec![
                "http://api.openai.com/v1/responses",
                "https://api.openai.com:444/other",
                "https://user@api.openai.com/v1/responses",
                "https://api.openai.com/v1/responses#other",
                "https://api.openai.com/v1/models",
                "https://api.openai.com/v1/responses?other=true",
            ],
        ),
        (
            "anthropic",
            vec![
                "http://api.anthropic.com/v1/messages",
                "https://api.anthropic.com:444/other",
                "https://user@api.anthropic.com/v1/messages",
                "https://api.anthropic.com/v1/messages#other",
                "https://api.anthropic.com/v1/models",
                "https://api.anthropic.com/v1/messages?beta=false",
            ],
        ),
    ] {
        for target in targets {
            let mut request = exact_api_request(family);
            request.target = Url::parse(target).unwrap();
            assert_eq!(
                SyntheticOpenAiSmokeTransport::api_key_family(&request),
                Some(family)
            );
            exact_api_denied(&request, exact_api_key(family));
        }
    }
    for target in [
        "https://chatgpt.com/backend-api/codex/responses",
        "https://auth.openai.com/oauth/token",
        "https://api.github.com/user",
        "https://api.openai.com.evil.test/v1/responses",
        "https://other.example/v1/messages",
    ] {
        let mut request = exact_api_request("openai");
        request.target = Url::parse(target).unwrap();
        assert_eq!(
            SyntheticOpenAiSmokeTransport::api_key_family(&request),
            None
        );
        exact_api_denied(&request, OPENAI_KEY);
    }
}

#[tokio::test]
async fn exact_api_canned_routes_delegate_the_original_request_unchanged() {
    for (family, target, messages) in [
        ("openai", "https://api.openai.com/v1/responses", true),
        ("anthropic", "https://api.anthropic.com/v1/messages", true),
        (
            "anthropic",
            "https://api.anthropic.com/v1/messages?beta=true",
            true,
        ),
        (
            "anthropic",
            "https://api.anthropic.com/v1/messages/count_tokens",
            false,
        ),
        (
            "anthropic",
            "https://api.anthropic.com/v1/messages/count_tokens?beta=true",
            false,
        ),
    ] {
        let mut request = exact_api_request(family);
        request.target = Url::parse(target).unwrap();
        if family == "anthropic" {
            request.body = anthropic_body(messages);
        }
        let body_pointer = request.body.as_ptr();
        let target_pointer = request.target.as_str().as_ptr();
        let authority = if family == "openai" {
            "authorization"
        } else {
            "x-api-key"
        };
        let header_pointer = request.headers[authority].as_bytes().as_ptr();
        assert_eq!(
            SyntheticOpenAiSmokeTransport::api_key_family(&request),
            Some(family)
        );
        assert_eq!(
            SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(
                &request,
                exact_api_key(family)
            ),
            Ok(())
        );
        assert_eq!(request.body.as_ptr(), body_pointer);
        assert_eq!(request.target.as_str().as_ptr(), target_pointer);
        assert_eq!(
            request.headers[authority].as_bytes().as_ptr(),
            header_pointer
        );
        let output = exact_api_output(request).await;
        if family == "openai" {
            assert!(output.contains("CWOPENAI"));
        } else if messages {
            assert!(output.contains("CWCLAUDE21238"));
        } else {
            assert_eq!(output, "{\"input_tokens\":42}");
        }
    }
}

#[test]
fn exact_api_accepts_transparent_client_headers_but_refuses_duplicates() {
    for family in ["openai", "anthropic"] {
        let mut request = exact_api_request(family);
        for (name, value) in [
            ("user-agent", "synthetic-client/1.0"),
            ("x-app", "cli"),
            ("anthropic-beta", "dangerous-tool-use-2026-09-03"),
            ("originator", "codex_cli_rs"),
            ("x-stainless-lang", "js"),
            ("forwarded", "for=192.0.2.1"),
        ] {
            request.headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        assert_eq!(
            SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(
                &request,
                exact_api_key(family)
            ),
            Ok(())
        );
        for name in request.headers.keys().cloned().collect::<Vec<_>>() {
            let original = request.headers[&name].clone();
            request.headers.append(name.clone(), original.clone());
            exact_api_denied(&request, exact_api_key(family));
            request.headers.insert(name, original);
        }
    }
}

#[tokio::test]
async fn exact_api_selected_key_rejects_the_old_canary_shape_acceptance() {
    for (family, alternate) in [
        ("openai", "cwlocalopenai0123456789abcdef0123456789abcdee"),
        (
            "anthropic",
            "cwlocalanthropic0123456789abcdef0123456789abcdee",
        ),
    ] {
        let mut request = exact_api_request(family);
        if family == "openai" {
            request.headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {alternate}")).unwrap(),
            );
        } else {
            request
                .headers
                .insert("x-api-key", HeaderValue::from_static(alternate));
        }
        exact_api_denied(&request, exact_api_key(family));
        // The existing reusable transport deliberately accepts a random
        // same-family canary. Exact selected-key admission is the new guard;
        // retain the original transport behavior for other synthetic fixtures.
        assert!(exact_api_output(request).await.contains(alternate));
    }
}

#[test]
fn exact_api_expected_argument_must_be_the_selected_synthetic_family() {
    for family in ["openai", "anthropic"] {
        let request = exact_api_request(family);
        for expected in [
            "",
            "live-looking-key",
            CODEX_KEY,
            if family == "openai" {
                ANTHROPIC_KEY
            } else {
                OPENAI_KEY
            },
            "cwlocalopenai0123456789abcdef0123456789abcdeF",
            "cwlocalanthropic0123456789abcdef0123456789abcde",
            "cwlocalopenai0123456789abcdef0123456789abcdee",
        ] {
            exact_api_denied(&request, expected);
        }
    }
}

#[test]
fn exact_api_authority_is_single_and_foreign_headers_refuse() {
    for family in ["openai", "anthropic"] {
        let authority = if family == "openai" {
            "authorization"
        } else {
            "x-api-key"
        };
        let mut request = exact_api_request(family);
        request.headers.remove(authority);
        exact_api_denied(&request, exact_api_key(family));
        let mut foreign = vec![
            "cookie",
            "proxy-authorization",
            "host",
            "connection",
            "upgrade",
            if family == "openai" {
                "x-api-key"
            } else {
                "authorization"
            },
        ];
        if family == "openai" {
            foreign.push("chatgpt-account-id");
        }
        for foreign in foreign {
            let mut request = exact_api_request(family);
            request.headers.insert(
                HeaderName::from_static(foreign),
                HeaderValue::from_static("caller"),
            );
            exact_api_denied(&request, exact_api_key(family));
        }
        for value in [
            "caller",
            "bearer invalid",
            CODEX_KEY,
            if family == "openai" {
                ANTHROPIC_KEY
            } else {
                OPENAI_KEY
            },
        ] {
            let mut request = exact_api_request(family);
            request.headers.insert(
                HeaderName::from_static(authority),
                HeaderValue::from_static(value),
            );
            exact_api_denied(&request, exact_api_key(family));
        }
    }
}

#[test]
fn exact_api_wrong_method_or_query_never_delegates() {
    for family in ["openai", "anthropic"] {
        for method in [Method::GET, Method::PUT, Method::DELETE, Method::HEAD] {
            let mut request = exact_api_request(family);
            request.method = method;
            exact_api_denied(&request, exact_api_key(family));
        }
    }
    for target in [
        "https://api.openai.com/v1/responses?beta=true",
        "https://api.openai.com/v1/responses/",
        "https://api.anthropic.com/v1/messages?beta=%74rue",
        "https://api.anthropic.com/v1/messages?beta=true&beta=true",
        "https://api.anthropic.com/v1/messages/count_tokens?other=true",
        "https://api.anthropic.com/v1/messages/batches",
    ] {
        let family = if target.contains("anthropic") {
            "anthropic"
        } else {
            "openai"
        };
        let mut request = exact_api_request(family);
        request.target = Url::parse(target).unwrap();
        exact_api_denied(&request, exact_api_key(family));
    }
}

#[tokio::test]
async fn exact_api_body_bounds_precede_canned_parsing() {
    for family in ["openai", "anthropic"] {
        let mut request = exact_api_request(family);
        request.body.clear();
        exact_api_denied(&request, exact_api_key(family));
        request.body.resize(4 * 1024 * 1024 + 1, b' ');
        exact_api_denied(&request, exact_api_key(family));
        let mut request = exact_api_request(family);
        request.body.resize(4 * 1024 * 1024, b' ');
        assert_eq!(
            SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(
                &request,
                exact_api_key(family)
            ),
            Ok(())
        );
        assert!(!exact_api_output(request).await.is_empty());
    }
}

#[test]
fn exact_api_headers_are_bounded_and_use_existing_content_policy() {
    for family in ["openai", "anthropic"] {
        let name = if family == "openai" {
            "originator"
        } else {
            "anthropic-beta"
        };
        let mut request = exact_api_request(family);
        request.headers.insert(
            name,
            HeaderValue::from_bytes(&vec![b'a'; 8 * 1024 + 1]).unwrap(),
        );
        exact_api_denied(&request, exact_api_key(family));
        for content in [
            None,
            Some("text/plain"),
            Some("application/json, application/json"),
        ] {
            let mut request = exact_api_request(family);
            request.headers.remove("content-type");
            if let Some(content) = content {
                request
                    .headers
                    .insert("content-type", HeaderValue::from_static(content));
            }
            exact_api_denied(&request, exact_api_key(family));
        }
    }
    let mut request = exact_api_request("openai");
    for index in 0..8 {
        request.headers.insert(
            HeaderName::from_bytes(format!("x-synthetic-{index}").as_bytes()).unwrap(),
            HeaderValue::from_bytes(&vec![b'a'; 8 * 1024]).unwrap(),
        );
    }
    exact_api_denied(&request, OPENAI_KEY);
}

#[test]
fn exact_api_identity_encoding_and_anthropic_version_stay_fixed() {
    let mut openai = exact_api_request("openai");
    // The owning OpenAI adapter does not add accept-encoding; do not invent a
    // required field. If present it must still be one exact identity value.
    assert!(!openai.headers.contains_key("accept-encoding"));
    assert_eq!(
        SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(&openai, OPENAI_KEY),
        Ok(())
    );
    openai
        .headers
        .insert("accept-encoding", HeaderValue::from_static("identity"));
    assert_eq!(
        SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(&openai, OPENAI_KEY),
        Ok(())
    );
    openai
        .headers
        .append("accept-encoding", HeaderValue::from_static("identity"));
    exact_api_denied(&openai, OPENAI_KEY);
    for family in ["openai", "anthropic"] {
        let mut request = exact_api_request(family);
        request
            .headers
            .insert("accept-encoding", HeaderValue::from_static("gzip"));
        exact_api_denied(&request, exact_api_key(family));
    }
    for version in [None, Some("2020-01-01")] {
        let mut request = exact_api_request("anthropic");
        request.headers.remove("anthropic-version");
        if let Some(version) = version {
            request
                .headers
                .insert("anthropic-version", HeaderValue::from_static(version));
        }
        exact_api_denied(&request, ANTHROPIC_KEY);
    }
    let mut request = exact_api_request("anthropic");
    request.headers.remove("accept-encoding");
    exact_api_denied(&request, ANTHROPIC_KEY);
}

fn transparent_openai_request(method: Method, target: &str) -> BrokerUpstreamRequest {
    let codex = target.starts_with("https://chatgpt.com/");
    let mut headers = HeaderMap::from_iter([(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "Bearer {}",
            if codex { CODEX_KEY } else { OPENAI_KEY }
        ))
        .unwrap(),
    )]);
    if codex {
        headers.insert(
            "chatgpt-account-id",
            HeaderValue::from_static(SYNTHETIC_CODEX_ACCOUNT_ID),
        );
    }
    BrokerUpstreamRequest {
        method,
        target: Url::parse(target).unwrap(),
        headers,
        body: Vec::new(),
        body_stream: None,
    }
}

async fn not_found_answer(request: BrokerUpstreamRequest, key: &str) {
    let label = format!("{} {}", request.method, request.target);
    let response = SyntheticOpenAiSmokeTransport
        .execute(request)
        .await
        .unwrap_or_else(|_| panic!("{label}: an HTTP answer, not a transport failure"));
    let (status, headers, mut body) = response.into_parts();
    assert_eq!(status, StatusCode::NOT_FOUND, "{label}");
    assert_eq!(headers["content-type"], "application/json", "{label}");
    let mut output = Vec::new();
    while let Some(chunk) = body.next().await {
        output.extend_from_slice(&chunk.unwrap());
    }
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("not_found"), "{label}");
    assert!(!output.contains(key), "{label}");
}

/// Transparent routes carry every stock-client request (#2536). One the
/// fixture does not serve is answered as a provider answers a route it lacks,
/// with a fixed 404, never as a transport failure: the broker reports a
/// transport failure as UpstreamFailed, which ends the whole bridge epoch and
/// with it every other slot's requests.
#[tokio::test]
async fn unserved_transparent_routes_answer_404_instead_of_a_transport_failure() {
    for (method, target) in [
        (
            Method::GET,
            "https://chatgpt.com/backend-api/codex/models?client_version=0.160.0",
        ),
        (
            Method::GET,
            "https://chatgpt.com/backend-api/codex/responses",
        ),
        (
            Method::POST,
            "https://chatgpt.com/backend-api/codex/responses/compact",
        ),
        (Method::GET, "https://api.openai.com/v1/models"),
        (Method::DELETE, "https://api.openai.com/v1/responses"),
        (
            Method::POST,
            "https://api.openai.com/v1/responses?stream=true",
        ),
    ] {
        let key = if target.contains("chatgpt.com") {
            CODEX_KEY
        } else {
            OPENAI_KEY
        };
        not_found_answer(transparent_openai_request(method, target), key).await;
    }
    for (method, target) in [
        (Method::GET, "https://api.anthropic.com/v1/models"),
        (Method::GET, "https://api.anthropic.com/api/oauth/usage"),
        (
            Method::POST,
            "https://api.anthropic.com/v1/messages/batches",
        ),
    ] {
        let mut request = anthropic_request();
        request.method = method;
        request.target = Url::parse(target).unwrap();
        request.body.clear();
        not_found_answer(request, ANTHROPIC_KEY).await;
    }
}

/// An unserved route still requires exactly the credential the broker
/// injects: a missing, foreign or guest-supplied one is a fixture failure.
#[tokio::test]
async fn unserved_transparent_routes_still_require_the_injected_credential() {
    let codex_models = "https://chatgpt.com/backend-api/codex/models";
    let openai_models = "https://api.openai.com/v1/models";
    let mut cases = Vec::new();
    for target in [codex_models, openai_models] {
        let mut missing = transparent_openai_request(Method::GET, target);
        missing.headers.remove("authorization");
        cases.push(missing);
        let mut foreign = transparent_openai_request(Method::GET, target);
        foreign.headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {ANTHROPIC_KEY}")).unwrap(),
        );
        cases.push(foreign);
        for (name, value) in [("cookie", "caller"), ("proxy-authorization", "caller")] {
            let mut caller = transparent_openai_request(Method::GET, target);
            caller.headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            cases.push(caller);
        }
    }
    let mut wrong_account = transparent_openai_request(Method::GET, codex_models);
    wrong_account.headers.insert(
        "chatgpt-account-id",
        HeaderValue::from_static("wrong-account"),
    );
    cases.push(wrong_account);
    let mut guest_account = transparent_openai_request(Method::GET, openai_models);
    guest_account.headers.insert(
        "chatgpt-account-id",
        HeaderValue::from_static(SYNTHETIC_CODEX_ACCOUNT_ID),
    );
    cases.push(guest_account);
    for change in ["missing", "placeholder", "bearer"] {
        let mut request = anthropic_request();
        request.method = Method::GET;
        request.target = Url::parse("https://api.anthropic.com/v1/models").unwrap();
        match change {
            "missing" => {
                request.headers.remove("x-api-key");
            }
            "placeholder" => {
                request
                    .headers
                    .insert("x-api-key", HeaderValue::from_static("codewire-managed"));
            }
            _ => {
                request.headers.insert(
                    "authorization",
                    HeaderValue::from_str(&format!("Bearer {ANTHROPIC_KEY}")).unwrap(),
                );
            }
        }
        cases.push(request);
    }
    for request in cases {
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
}
