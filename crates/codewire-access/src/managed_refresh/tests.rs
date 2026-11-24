use super::*;

const REQUEST_FIXTURE: &str =
    include_str!("../../tests/fixtures/claude-oauth-token/refresh-request.json");
const RESPONSE_FIXTURE: &str =
    include_str!("../../tests/fixtures/claude-oauth-token/refresh-response.json");

/// Only the prefix and exactly 32 lowercase hexadecimal characters.
#[test]
fn a_managed_claude_marker_is_the_prefix_and_32_lowercase_hex() {
    let nonce = "0123456789abcdef0123456789abcdef";
    assert!(is_managed_claude_refresh_token(&format!(
        "{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{nonce}"
    )));
    for refused in [
        String::new(),
        CODEX_MANAGED_REFRESH_TOKEN.to_owned(),
        CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.to_owned(),
        format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{}", &nonce[1..]),
        format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{nonce}0"),
        format!(
            "{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{}",
            nonce.to_ascii_uppercase()
        ),
        format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}0123456789abcdef0123456789abcdeg"),
        format!(" {CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{nonce}"),
        format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{nonce}\n"),
        format!("provider-refresh-{nonce}"),
    ] {
        assert!(!is_managed_claude_refresh_token(&refused), "{refused:?}");
    }
}

/// Each nonce byte becomes two lowercase hexadecimal digits, high first.
#[test]
fn a_generated_claude_marker_encodes_its_nonce_in_lowercase_hex() {
    let token = managed_claude_refresh_token([
        0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xf0, 0x0f, 0x10, 0xa0, 0x5a, 0xfe,
        0xff,
    ]);
    assert_eq!(
        token,
        "codewire-managed-no-refresh-token-000123456789abcdeff00f10a05afeff"
    );
    assert!(is_managed_claude_refresh_token(&token));
}

/// The shared request fixture carries a managed marker in the body Claude
/// Code sends, and the response fixture has exactly the answer's members.
#[test]
fn the_shared_token_endpoint_fixtures_keep_their_shape() {
    let request: serde_json::Value = serde_json::from_str(REQUEST_FIXTURE).unwrap();
    assert_eq!(request["grant_type"], "refresh_token");
    assert_eq!(request["client_id"], "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
    assert!(request["scope"].is_string());
    assert!(is_managed_claude_refresh_token(
        request["refresh_token"].as_str().unwrap()
    ));
    assert_eq!(request.as_object().unwrap().len(), 4);

    let response: serde_json::Value = serde_json::from_str(RESPONSE_FIXTURE).unwrap();
    let mut members: Vec<_> = response.as_object().unwrap().keys().cloned().collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_eq!(response["expires_in"], 315_360_000);
    assert_eq!(response["token_type"], "Bearer");
    assert!(
        response["access_token"]
            .as_str()
            .unwrap()
            .starts_with(crate::CREDENTIAL_PLACEHOLDER_TAG)
    );
    assert!(
        response["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with(CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX)
    );
}

/// Codex's request fixture is the refresh the pinned Codex sends with the
/// marker Codewire writes, and its response fixture has exactly the members
/// Codex reads, the marker returned as it is (#6197).
#[test]
fn the_codex_token_endpoint_fixtures_keep_their_shape() {
    let request: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/codex-oauth-token/refresh-request.json"
    ))
    .unwrap();
    let mut members: Vec<_> = request.as_object().unwrap().keys().cloned().collect();
    members.sort_unstable();
    assert_eq!(members, ["client_id", "grant_type", "refresh_token"]);
    assert_eq!(request["grant_type"], "refresh_token");
    assert_eq!(request["refresh_token"], CODEX_MANAGED_REFRESH_TOKEN);
    assert!(request["client_id"].is_string());

    let response: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/codex-oauth-token/refresh-response.json"
    ))
    .unwrap();
    let mut members: Vec<_> = response.as_object().unwrap().keys().cloned().collect();
    members.sort_unstable();
    assert_eq!(members, ["access_token", "id_token", "refresh_token"]);
    assert_eq!(response["refresh_token"], CODEX_MANAGED_REFRESH_TOKEN);
}
