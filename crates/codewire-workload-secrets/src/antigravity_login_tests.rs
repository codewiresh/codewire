use super::*;
use crate::ProjectionRecipient;

const NOW: u64 = 1_800_000_000_000;

fn placeholder() -> Zeroizing<String> {
    Zeroizing::new(format!("cwp1_{}", "A".repeat(43)))
}

fn context() -> AntigravityLoginContext {
    AntigravityLoginContext {
        environment_id: [0x11; 16],
        environment_generation: 7,
        request_id: [0x22; 16],
        deadline_unix_ms: NOW + 10_000,
    }
}

fn binding() -> AntigravityLoginBinding {
    AntigravityLoginBinding {
        credential_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        revocation_generation: 3,
        material_generation: 4,
    }
}

#[test]
fn round_trips_placeholder_and_account_hint() {
    let recipient = ProjectionRecipient::new();
    let login = AntigravityLogin::new(
        placeholder(),
        Some("dev@example.com".to_owned()),
        1_800_000_000,
    )
    .unwrap();
    let sealed =
        seal_antigravity_login(&login, &binding(), &context(), recipient.public_key(), NOW)
            .unwrap();
    let opened = recipient
        .open_antigravity_login(&sealed, &context(), NOW + 1_000)
        .unwrap();
    assert_eq!(opened.binding, binding());
    assert_eq!(opened.login.placeholder(), placeholder().as_str());
    assert_eq!(opened.login.account_hint(), Some("dev@example.com"));
    assert_eq!(opened.login.refreshed_at_unix(), 1_800_000_000);
    assert!(!format!("{:?}", opened.login).contains(placeholder().as_str()));
}

#[test]
fn refuses_real_tokens_and_malformed_placeholders() {
    for bad in [
        "",
        "ya29.a0ARrdaM-real-google-token-must-never-seal",
        "1//0g_real_google_refresh_token_must_never_seal",
        "cwp1_short",
        &format!("cwp1_{}", "A".repeat(44)),
        &format!("cwp1_{}!", "A".repeat(42)),
    ] {
        assert_eq!(
            AntigravityLogin::new(Zeroizing::new(bad.to_owned()), None, 1_800_000_000).unwrap_err(),
            AntigravityLoginError::InvalidLogin,
            "must refuse non-placeholder value {bad:?}"
        );
    }
}

#[test]
fn refuses_cross_domain_claude_or_wrong_context() {
    let recipient = ProjectionRecipient::new();
    let login = AntigravityLogin::new(placeholder(), None, 1_800_000_000).unwrap();
    let sealed =
        seal_antigravity_login(&login, &binding(), &context(), recipient.public_key(), NOW)
            .unwrap();
    let mut wrong_context = context();
    wrong_context.environment_generation += 1;
    let err = recipient
        .open_antigravity_login(&sealed, &wrong_context, NOW + 1_000)
        .unwrap_err();
    assert_eq!(err, AntigravityLoginError::InvalidEnvelope);

    let recipient2 = ProjectionRecipient::new();
    let sealed2 =
        seal_antigravity_login(&login, &binding(), &context(), recipient2.public_key(), NOW)
            .unwrap();
    assert!(
        recipient2
            .open_claude_login(&sealed2, &context(), NOW + 1_000)
            .is_err()
    );
}
