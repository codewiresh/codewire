use crate::{
    CodexLogin, CodexLoginBinding, CodexLoginContext, ProjectionRecipient, seal_codex_login,
};

use super::*;

const NOW: u64 = 1_000_000;
const ACCESS: &str = "sk-ant-oat01-synthetic-claude-access-canary";
const TIER: &str = "default_claude_max_20x";

fn context() -> CodexLoginContext {
    CodexLoginContext {
        environment_id: [1; 16],
        environment_generation: 7,
        request_id: [9; 16],
        deadline_unix_ms: NOW + 5_000,
    }
}

fn binding() -> CodexLoginBinding {
    CodexLoginBinding {
        credential_id: "credential-claude".into(),
        revocation_generation: 3,
        material_generation: 4,
    }
}

fn scopes() -> Vec<String> {
    [
        "user:profile",
        "user:inference",
        "user:sessions:claude_code",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn login() -> ClaudeLogin {
    ClaudeLogin::new(
        Zeroizing::new(ACCESS.into()),
        1_700_000_000_000,
        scopes(),
        Some("max".into()),
        Some(TIER.into()),
        1_699_999_000,
    )
    .unwrap()
}

fn sealed_for(recipient: &ProjectionRecipient) -> Vec<u8> {
    seal_claude_login(
        &login(),
        &binding(),
        &context(),
        recipient.public_key(),
        NOW,
    )
    .unwrap()
}

#[test]
fn only_the_requesting_recipient_opens_the_exact_login_and_binding() {
    let recipient = ProjectionRecipient::new();
    let sealed = sealed_for(&recipient);
    for canary in [ACCESS, TIER, "credential-claude", "user:profile"] {
        assert!(
            !sealed
                .windows(canary.len())
                .any(|part| part == canary.as_bytes()),
            "{canary} visible in ciphertext"
        );
    }
    let opened = recipient
        .open_claude_login(&sealed, &context(), NOW)
        .unwrap();
    assert_eq!(opened.binding, binding());
    assert_eq!(opened.login.access_token(), ACCESS);
    assert_eq!(opened.login.expires_at_unix_ms(), 1_700_000_000_000);
    assert_eq!(opened.login.scopes(), scopes());
    assert_eq!(opened.login.subscription_type(), Some("max"));
    assert_eq!(opened.login.rate_limit_tier(), Some(TIER));
    assert_eq!(opened.login.refreshed_at_unix(), 1_699_999_000);
    assert!(!format!("{:?}", opened.login).contains(ACCESS));

    // Another recipient, another request or a passed deadline opens nothing.
    assert!(
        ProjectionRecipient::new()
            .open_claude_login(&sealed, &context(), NOW)
            .is_err()
    );
    let recipient = ProjectionRecipient::new();
    let sealed = sealed_for(&recipient);
    let mut other = context();
    other.request_id = [8; 16];
    assert!(recipient.open_claude_login(&sealed, &other, NOW).is_err());
    let recipient = ProjectionRecipient::new();
    let sealed = sealed_for(&recipient);
    assert_eq!(
        recipient
            .open_claude_login(&sealed, &context(), NOW + 5_000)
            .err(),
        Some(ClaudeLoginError::InvalidContext)
    );
}

#[test]
fn a_codex_login_never_opens_as_a_claude_login_nor_the_reverse() {
    let recipient = ProjectionRecipient::new();
    let codex = seal_codex_login(
        &CodexLogin::new(
            Zeroizing::new("synthetic.access.token".into()),
            Zeroizing::new("synthetic.id.token".into()),
            "account".into(),
            1,
        )
        .unwrap(),
        &binding(),
        &context(),
        recipient.public_key(),
        NOW,
    )
    .unwrap();
    assert!(
        recipient
            .open_claude_login(&codex, &context(), NOW)
            .is_err()
    );
    let recipient = ProjectionRecipient::new();
    let claude = sealed_for(&recipient);
    assert!(
        recipient
            .open_codex_login(&claude, &context(), NOW)
            .is_err()
    );
}

#[test]
fn the_login_is_bounded_closed_and_without_a_plan_or_tier_when_absent() {
    let recipient = ProjectionRecipient::new();
    let bare = ClaudeLogin::new(
        Zeroizing::new(ACCESS.into()),
        1,
        vec!["user:inference".into()],
        None,
        None,
        1,
    )
    .unwrap();
    let sealed =
        seal_claude_login(&bare, &binding(), &context(), recipient.public_key(), NOW).unwrap();
    let opened = recipient
        .open_claude_login(&sealed, &context(), NOW)
        .unwrap();
    assert_eq!(opened.login.subscription_type(), None);
    assert_eq!(opened.login.rate_limit_tier(), None);
    for (token, scopes, plan, tier) in [
        ("", scopes(), None, None),
        ("with space", scopes(), None, None),
        ("quote\"", scopes(), None, None),
        (ACCESS, Vec::new(), None, None),
        (ACCESS, vec!["User:Profile".into()], None, None),
        (
            ACCESS,
            vec!["user:profile".into(), "user:profile".into()],
            None,
            None,
        ),
        (ACCESS, scopes(), Some("free".into()), None),
        (ACCESS, scopes(), None, Some("tier with space".into())),
        (ACCESS, scopes(), None, Some(String::new())),
    ] {
        assert_eq!(
            ClaudeLogin::new(Zeroizing::new(token.into()), 1, scopes, plan, tier, 1).err(),
            Some(ClaudeLoginError::InvalidLogin)
        );
    }
    assert!(
        ClaudeLogin::new(
            Zeroizing::new("x".repeat(MAX_CLAUDE_LOGIN_TOKEN_BYTES + 1)),
            1,
            scopes(),
            None,
            None,
            1
        )
        .is_err()
    );
    assert!(ClaudeLogin::new(Zeroizing::new(ACCESS.into()), 0, scopes(), None, None, 1).is_err());
    let recipient = ProjectionRecipient::new();
    assert_eq!(
        recipient
            .open_claude_login(&vec![0; MAX_SEALED_CLAUDE_LOGIN_BYTES + 1], &context(), NOW)
            .err(),
        Some(ClaudeLoginError::InvalidEnvelope)
    );
}
