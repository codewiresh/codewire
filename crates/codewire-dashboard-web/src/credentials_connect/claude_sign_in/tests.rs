use codewire_proto::codewire::v1::CredentialAuthenticationKind;

use super::*;

const NOW: u64 = 1_800_000_000;
const ID: &str = "00000000-0000-4000-8000-000000000021";

fn started(authorize_url: &str, handle: &str, expires_at_unix: u64) -> StartedClaudeSignIn {
    StartedClaudeSignIn {
        authorize_url: authorize_url.into(),
        handle: handle.into(),
        expires_at_unix,
    }
}

fn sign_in(generation: u64) -> Credential {
    Credential {
        id: ID.into(),
        name: "Work Claude".into(),
        provider: "anthropic".into(),
        authentication_kind: CredentialAuthenticationKind::ClaudeSignIn.into(),
        status: CredentialStatus::Active.into(),
        revocation_generation: generation,
        account_hint: Some("person@example.test".into()),
        ..Default::default()
    }
}

#[test]
fn a_start_is_claudes_own_page_with_a_cookie_safe_handle_inside_its_lifetime() {
    let url = "https://claude.com/cai/oauth/authorize?code=true&state=s";
    let handle = format!("cwcs2.{NOW}.0a1b2c");
    let long = "a".repeat(MAX_HANDLE_BYTES + 1);
    assert!(valid_start(&started(url, &handle, NOW + 900), NOW));
    for (url, handle, expires) in [
        (
            "https://claude.com.example.test/cai/oauth/authorize?x",
            handle.as_str(),
            NOW + 900,
        ),
        (
            "http://claude.com/cai/oauth/authorize?x",
            handle.as_str(),
            NOW + 900,
        ),
        (
            "https://claude.com/cai/oauth/authorize",
            handle.as_str(),
            NOW + 900,
        ),
        (
            "https://claude.com/cai/oauth/authorize?a b",
            handle.as_str(),
            NOW + 900,
        ),
        (url, "", NOW + 900),
        (url, "cwcs2.1;Path=/", NOW + 900),
        (url, "cwcs2.1\r\nSet-Cookie: x", NOW + 900),
        (url, long.as_str(), NOW + 900),
        (url, handle.as_str(), NOW),
        (url, handle.as_str(), NOW + 901),
    ] {
        assert!(
            !valid_start(&started(url, handle, expires), NOW),
            "{url} {expires}"
        );
    }
}

#[test]
fn only_the_code_claude_shows_is_accepted() {
    let long = format!("{}#xyz", "c".repeat(MAX_CODE_PART_BYTES + 1));
    assert_eq!(pasted_claude_code("abc-_.~#xyz\n").unwrap(), b"abc-_.~#xyz");
    assert_eq!(pasted_claude_code("  abc#xyz  ").unwrap(), b"abc#xyz");
    for pasted in [
        "",
        "abc",
        "#xyz",
        "abc#",
        "abc#xyz#more",
        "ab c#xyz",
        "abc#x%79z",
        "https://platform.claude.com/oauth/code/callback?code=abc&state=xyz",
        long.as_str(),
    ] {
        assert!(pasted_claude_code(pasted).is_none(), "{pasted}");
    }
}

#[test]
fn a_new_sign_in_is_active_at_generation_one_with_the_accounts_email() {
    assert!(validate_sign_in_ack(&sign_in(1), "Work Claude", None).is_ok());
    let mut no_email = sign_in(1);
    no_email.account_hint = None;
    let mut token = sign_in(1);
    token.authentication_kind = CredentialAuthenticationKind::Oauth.into();
    let mut revoked = sign_in(1);
    revoked.status = CredentialStatus::Revoked.into();
    let mut expiring = sign_in(1);
    expiring.expires_at_unix = Some(NOW);
    for (credential, name) in [
        (sign_in(1), "Other"),
        (sign_in(2), "Work Claude"),
        (no_email, "Work Claude"),
        (token, "Work Claude"),
        (revoked, "Work Claude"),
        (expiring, "Work Claude"),
    ] {
        assert!(validate_sign_in_ack(&credential, name, None).is_err());
    }
}

#[test]
fn a_reconnect_keeps_its_identity_at_the_next_generation() {
    let current = sign_in(3);
    assert!(validate_sign_in_ack(&sign_in(4), "Work Claude", Some(&current)).is_ok());
    assert!(validate_sign_in_ack(&sign_in(3), "Work Claude", Some(&current)).is_err());
    let mut other = sign_in(4);
    other.id = "00000000-0000-4000-8000-000000000022".into();
    assert!(validate_sign_in_ack(&other, "Work Claude", Some(&current)).is_err());
}
