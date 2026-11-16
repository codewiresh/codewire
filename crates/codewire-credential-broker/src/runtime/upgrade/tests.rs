use super::*;

fn value(text: &'static str) -> HeaderValue {
    HeaderValue::from_static(text)
}

fn client_handshake() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::SEC_WEBSOCKET_KEY, value("test-nonce"));
    headers.insert(header::SEC_WEBSOCKET_VERSION, value("13"));
    headers.insert(header::AUTHORIZATION, value("Bearer placeholder"));
    headers.insert("chatgpt-account-id", value("acct"));
    headers
}

#[test]
fn the_handshake_leaves_the_request_and_needs_one_key_and_a_version() {
    let mut headers = client_handshake();
    let handshake = take_handshake(&mut headers).unwrap();
    assert_eq!(handshake.len(), 2);
    assert!(headers.get(header::SEC_WEBSOCKET_KEY).is_none());
    assert_eq!(headers["chatgpt-account-id"], "acct");

    let mut no_key = client_handshake();
    no_key.remove(header::SEC_WEBSOCKET_KEY);
    assert!(take_handshake(&mut no_key).is_err());
    let mut two_keys = client_handshake();
    two_keys.append(header::SEC_WEBSOCKET_KEY, value("other"));
    assert!(take_handshake(&mut two_keys).is_err());
    let mut no_version = client_handshake();
    no_version.remove(header::SEC_WEBSOCKET_VERSION);
    assert!(take_handshake(&mut no_version).is_err());
}

#[test]
fn the_provider_request_is_framed_by_the_broker() {
    let mut handshake = HeaderMap::new();
    handshake.insert(header::SEC_WEBSOCKET_KEY, value("k"));
    let mut prepared = HeaderMap::new();
    prepared.insert(header::AUTHORIZATION, value("Bearer real"));
    prepared.insert(header::CONTENT_LENGTH, value("0"));
    prepared.insert(header::CONTENT_TYPE, value("application/json"));
    prepared.insert(header::HOST, value("elsewhere.example"));
    prepared.insert(header::CONNECTION, value("close"));
    let headers = handshake_request(&prepared, &handshake);
    assert_eq!(headers[header::CONNECTION], "Upgrade");
    assert_eq!(headers[header::UPGRADE], "websocket");
    assert_eq!(headers[header::SEC_WEBSOCKET_KEY], "k");
    assert_eq!(headers[header::AUTHORIZATION], "Bearer real");
    for gone in [header::CONTENT_LENGTH, header::CONTENT_TYPE, header::HOST] {
        assert!(headers.get(&gone).is_none(), "{gone}");
    }
    assert_eq!(headers.get_all(header::CONNECTION).iter().count(), 1);
}

/// A forwarded `101` (no credential of ours in it) reaches the front door as
/// the provider sent it, cookies included, but never with framing: the front
/// door frames the client's `101` itself. The swapped path's cookie removal
/// is `switched_headers`'s, after the route's response policy.
#[test]
fn a_forwarded_101_keeps_its_headers_but_never_framing() {
    let mut raw = HeaderMap::new();
    raw.insert(header::SEC_WEBSOCKET_ACCEPT, value("accept"));
    raw.insert(header::SET_COOKIE, value("session=1"));
    raw.insert(header::CONNECTION, value("upgrade"));
    raw.insert(header::UPGRADE, value("websocket"));
    let headers = with_handshake(without_framing(&raw), &raw);
    assert_eq!(headers[header::SEC_WEBSOCKET_ACCEPT], "accept");
    assert_eq!(headers[header::SET_COOKIE], "session=1");
    assert!(headers.get(header::UPGRADE).is_none());
    assert!(headers.get(header::CONNECTION).is_none());
}

#[test]
fn the_injected_credential_is_found_wherever_a_reply_echoes_it() {
    let injected = value("Bearer real-token");
    assert_eq!(&credential_value(&injected)[..], b"real-token");
    assert!(contains(b"x real-token y", b"real-token"));
    assert!(!contains(b"real-tok", b"real-token"));
}

#[test]
fn only_codex_model_calls_on_chatgpt_may_upgrade() {
    assert_eq!(UPGRADABLE.len(), 1);
    let (slot, host, path) = UPGRADABLE[0];
    assert_eq!(
        (slot, host, path),
        ("codex", "chatgpt.com", "/backend-api/codex/responses")
    );
}
