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
                "/messages"
            } else {
                "/messages/count_tokens"
            };
            let operation = if messages { "messages" } else { "count-tokens" };
            let mut lease = Lease::new(
                "anthropic",
                CredentialAuthKind::ApiKey,
                "anthropic",
                operation,
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
                })
                .await
                .unwrap();
            let (status, headers, mut body) = response.into_parts();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(headers["request-id"], ANTHROPIC_KEY);
            assert!(headers.contains_key("x-error-json"));
            let (headers, mut redaction) = policy.begin(&headers).unwrap();
            assert_eq!(headers["request-id"], "[REDACTED]");
            assert!(!headers.contains_key("x-error-json"));
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

#[tokio::test]
async fn anthropic_rejects_target_method_and_query_changes() {
    for target in [
        "http://api.anthropic.com/v1/messages",
        "https://api.anthropic.com:444/v1/messages",
        "https://user@api.anthropic.com/v1/messages",
        "https://api.anthropic.com/v1/messages#fragment",
        "https://api.anthropic.com/v1/messages?beta=false",
        "https://api.anthropic.com/v1/messages?beta=true&beta=true",
        "https://api.anthropic.com/v1/messages?beta=true&host=other",
        "https://api.anthropic.com/v1/messages/count_tokens?beta=%74rue",
        "https://api.anthropic.com/v1/models",
        "https://api.anthropic.com/v1/messages/batches",
        "https://other.example/v1/messages",
    ] {
        let mut request = anthropic_request();
        request.target = Url::parse(target).unwrap();
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let mut request = anthropic_request();
        request.method = method;
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        ));
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
        ("chatgpt-account-id", SYNTHETIC_CODEX_ACCOUNT_ID),
        ("x-error-json", "caller"),
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
        })
        .await
        .unwrap();
    let (_, headers, mut body) = response.into_parts();
    assert_eq!(headers["x-request-id"], OPENAI_KEY);
    assert!(headers.contains_key("x-error-json"));
    let (headers, mut redaction) = policy.begin(&headers).unwrap();
    assert_eq!(headers["x-request-id"], "[REDACTED]");
    assert!(!headers.contains_key("x-error-json"));
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
        let mut invalid = request(target);
        invalid.method = Method::GET;
        assert!(matches!(
            SyntheticOpenAiSmokeTransport.execute(invalid).await,
            Err(BrokerUpstreamError::Protocol)
        ));
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
        "https://other.example/v1/responses",
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
