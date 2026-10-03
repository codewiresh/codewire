use crate::{
    EnvironmentProjection, ProjectionContext, ProjectionRecipient, seal_environment_projection,
};

use super::*;

const NOW: u64 = 1_000_000;
const ACCESS: &str = "synthetic.access-token.canary";
const ID: &str = "synthetic.id-token.canary";
const ACCOUNT: &str = "account-synthetic";

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
        credential_id: "credential-codex".into(),
        revocation_generation: 3,
        material_generation: 4,
    }
}

fn login() -> CodexLogin {
    CodexLogin::new(
        Zeroizing::new(ACCESS.into()),
        Zeroizing::new(ID.into()),
        ACCOUNT.into(),
        1_700_000_000,
    )
    .unwrap()
}

fn sealed_for(recipient: &ProjectionRecipient) -> Vec<u8> {
    seal_codex_login(
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
    for canary in [ACCESS, ID, ACCOUNT, "credential-codex"] {
        assert!(
            !sealed
                .windows(canary.len())
                .any(|part| part == canary.as_bytes()),
            "{canary} visible in ciphertext"
        );
    }
    assert!(sealed.len() <= MAX_SEALED_CODEX_LOGIN_BYTES);
    let opened = recipient
        .open_codex_login(&sealed, &context(), NOW + 1)
        .unwrap();
    assert_eq!(opened.binding, binding());
    assert_eq!(opened.login.access_token(), ACCESS);
    assert_eq!(opened.login.id_token(), ID);
    assert_eq!(opened.login.account_id(), ACCOUNT);
    assert_eq!(opened.login.refreshed_at_unix(), 1_700_000_000);
    let debug = format!("{opened:?}");
    for canary in [ACCESS, ID] {
        assert!(!debug.contains(canary));
    }

    let other = ProjectionRecipient::new();
    assert_eq!(
        other
            .open_codex_login(&sealed, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
}

#[test]
fn every_bound_request_field_must_match() {
    for field in 0..4 {
        let recipient = ProjectionRecipient::new();
        let sealed = sealed_for(&recipient);
        let mut expected = context();
        match field {
            0 => expected.environment_id[0] ^= 1,
            1 => expected.environment_generation += 1,
            2 => expected.request_id[0] ^= 1,
            _ => expected.deadline_unix_ms += 1,
        }
        assert_eq!(
            recipient
                .open_codex_login(&sealed, &expected, NOW + 1)
                .unwrap_err(),
            CodexLoginError::InvalidEnvelope,
            "field {field}"
        );
    }
    // The recipient key is bound inside the box as well as used to open it: a
    // login sealed with another recipient's key in its binding never opens.
    let recipient = ProjectionRecipient::new();
    let other = ProjectionRecipient::new();
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(MAGIC);
    context().encode(&mut plaintext);
    plaintext.extend_from_slice(&other.public_key());
    let mut sealed = SEALED_MAGIC.to_vec();
    sealed.extend_from_slice(
        &PublicKey::from(recipient.public_key())
            .seal(&mut OsRng, &plaintext)
            .unwrap(),
    );
    assert_eq!(
        recipient
            .open_codex_login(&sealed, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
}

#[test]
fn the_sealed_credential_binding_cannot_be_altered() {
    let recipient = ProjectionRecipient::new();
    let mut sealed = sealed_for(&recipient);
    // Any change inside the box fails authentication of the whole envelope.
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    assert_eq!(
        recipient
            .open_codex_login(&sealed, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
    // A generation of zero or a malformed credential ID is never sealed.
    for broken in [
        CodexLoginBinding {
            revocation_generation: 0,
            ..binding()
        },
        CodexLoginBinding {
            material_generation: 0,
            ..binding()
        },
        CodexLoginBinding {
            credential_id: String::new(),
            ..binding()
        },
        CodexLoginBinding {
            credential_id: "Credential/Other".into(),
            ..binding()
        },
        CodexLoginBinding {
            credential_id: "c".repeat(MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES + 1),
            ..binding()
        },
    ] {
        assert_eq!(
            seal_codex_login(
                &login(),
                &broken,
                &context(),
                ProjectionRecipient::new().public_key(),
                NOW
            )
            .unwrap_err(),
            CodexLoginError::InvalidLogin
        );
    }
}

#[test]
fn a_newer_or_other_credential_may_replace_an_older_login_never_the_reverse() {
    let written = binding();
    assert!(written.may_replace(&written));
    for newer in [
        CodexLoginBinding {
            material_generation: 5,
            revocation_generation: 4,
            ..binding()
        },
        CodexLoginBinding {
            credential_id: "credential-other".into(),
            material_generation: 1,
            revocation_generation: 1,
        },
    ] {
        assert!(newer.may_replace(&written));
    }
    let older = CodexLoginBinding {
        material_generation: 3,
        ..binding()
    };
    assert!(!older.may_replace(&written));
}

#[test]
fn expired_or_overlong_deadlines_fail_before_any_work() {
    let recipient = ProjectionRecipient::new();
    let sealed = sealed_for(&recipient);
    assert_eq!(
        recipient
            .open_codex_login(&sealed, &context(), context().deadline_unix_ms)
            .unwrap_err(),
        CodexLoginError::InvalidContext
    );
    let mut long = context();
    long.deadline_unix_ms = NOW + MAX_CODEX_LOGIN_LIFETIME_MS + 1;
    assert_eq!(
        seal_codex_login(&login(), &binding(), &long, [7; 32], NOW).unwrap_err(),
        CodexLoginError::InvalidContext
    );
    long.deadline_unix_ms = NOW + MAX_CODEX_LOGIN_LIFETIME_MS;
    let recipient = ProjectionRecipient::new();
    assert!(seal_codex_login(&login(), &binding(), &long, recipient.public_key(), NOW).is_ok());
    for zeroed in 0..3 {
        let mut invalid = context();
        match zeroed {
            0 => invalid.environment_id = [0; 16],
            1 => invalid.environment_generation = 0,
            _ => invalid.request_id = [0; 16],
        }
        assert_eq!(
            invalid.validate_at(NOW),
            Err(CodexLoginError::InvalidContext)
        );
    }
    // A noncontributory recipient key is refused before sealing.
    assert_eq!(
        seal_codex_login(&login(), &binding(), &context(), [0; 32], NOW).unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
}

#[test]
fn oversize_or_malformed_input_is_rejected() {
    let token = |length: usize| Zeroizing::new("t".repeat(length));
    assert!(
        CodexLogin::new(
            token(MAX_CODEX_LOGIN_TOKEN_BYTES),
            token(MAX_CODEX_LOGIN_TOKEN_BYTES),
            "a".repeat(MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES),
            1,
        )
        .is_ok()
    );
    for (access, id, account, refreshed) in [
        (
            token(MAX_CODEX_LOGIN_TOKEN_BYTES + 1),
            token(1),
            "a".into(),
            1,
        ),
        (
            token(1),
            token(MAX_CODEX_LOGIN_TOKEN_BYTES + 1),
            "a".into(),
            1,
        ),
        (
            token(1),
            token(1),
            "a".repeat(MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES + 1),
            1,
        ),
        (token(0), token(1), "a".into(), 1),
        (token(1), token(0), "a".into(), 1),
        (token(1), token(1), String::new(), 1),
        (Zeroizing::new("quote\"d".into()), token(1), "a".into(), 1),
        (
            Zeroizing::new("back\\slash".into()),
            token(1),
            "a".into(),
            1,
        ),
        (Zeroizing::new("new\nline".into()), token(1), "a".into(), 1),
        (token(1), token(1), "a b".into(), 1),
        (token(1), token(1), "account\"quoted".into(), 1),
        (token(1), token(1), "account\\escaped".into(), 1),
        (token(1), token(1), "a".into(), 0),
    ] {
        assert_eq!(
            CodexLogin::new(access, id, account, refreshed).unwrap_err(),
            CodexLoginError::InvalidLogin
        );
    }

    // The largest valid login seals within the bound every consumer enforces.
    let recipient = ProjectionRecipient::new();
    let largest = CodexLogin::new(
        token(MAX_CODEX_LOGIN_TOKEN_BYTES),
        token(MAX_CODEX_LOGIN_TOKEN_BYTES),
        "a".repeat(MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES),
        1,
    )
    .unwrap();
    let largest_binding = CodexLoginBinding {
        credential_id: "c".repeat(MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES),
        ..binding()
    };
    let sealed = seal_codex_login(
        &largest,
        &largest_binding,
        &context(),
        recipient.public_key(),
        NOW,
    )
    .unwrap();
    assert_eq!(sealed.len(), MAX_SEALED_CODEX_LOGIN_BYTES);
    assert!(
        recipient
            .open_codex_login(&sealed, &context(), NOW + 1)
            .is_ok()
    );

    // Oversize and truncated ciphertext fails before any decryption.
    for length in [0, 1, MAX_SEALED_CODEX_LOGIN_BYTES + 1] {
        let recipient = ProjectionRecipient::new();
        let mut bytes = SEALED_MAGIC.to_vec();
        bytes.resize(length.max(SEALED_MAGIC.len()), 0);
        bytes.truncate(length);
        assert_eq!(
            recipient
                .open_codex_login(&bytes, &context(), NOW + 1)
                .unwrap_err(),
            CodexLoginError::InvalidEnvelope
        );
    }
    // Trailing bytes inside an authentic box are refused too.
    let recipient = ProjectionRecipient::new();
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(MAGIC);
    context().encode(&mut plaintext);
    plaintext.extend_from_slice(&recipient.public_key());
    for value in [3_u64, 4, 1_700_000_000] {
        plaintext.extend_from_slice(&value.to_be_bytes());
    }
    put_u16(&mut plaintext, b"credential-codex");
    put_u32(&mut plaintext, ACCESS.as_bytes());
    put_u32(&mut plaintext, ID.as_bytes());
    put_u16(&mut plaintext, ACCOUNT.as_bytes());
    plaintext.push(0);
    let mut sealed = SEALED_MAGIC.to_vec();
    sealed.extend_from_slice(
        &PublicKey::from(recipient.public_key())
            .seal(&mut OsRng, &plaintext)
            .unwrap(),
    );
    assert_eq!(
        recipient
            .open_codex_login(&sealed, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
}

#[test]
fn logins_and_environment_projections_never_open_as_each_other() {
    let projection_context = ProjectionContext {
        environment_id: context().environment_id,
        operation_generation: context().environment_generation,
        selection_sha256: [2; 32],
        deadline_unix_ms: context().deadline_unix_ms,
    };
    let projection = || {
        EnvironmentProjection::from_entries([(
            "OPENAI_ACCESS_TOKEN".into(),
            Zeroizing::new(ACCESS.as_bytes().to_vec()),
        )])
        .unwrap()
    };

    // A projection bundle for the same recipient is not a login.
    let recipient = ProjectionRecipient::new();
    let bundle = seal_environment_projection(
        projection(),
        &projection_context,
        recipient.public_key(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        recipient
            .open_codex_login(&bundle, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );

    // A login is not a projection bundle.
    let recipient = ProjectionRecipient::new();
    let sealed = sealed_for(&recipient);
    assert!(
        recipient
            .open(&sealed, &projection_context, NOW + 1)
            .is_err()
    );

    // The inner domain is checked too: a box under the login's outer framing
    // whose plaintext uses any other domain does not open.
    let recipient = ProjectionRecipient::new();
    let mut plaintext = b"CWENV\0\0\x02".to_vec();
    context().encode(&mut plaintext);
    plaintext.extend_from_slice(&recipient.public_key());
    plaintext.resize(MIN_PLAINTEXT_BYTES + 64, b'x');
    let mut foreign = SEALED_MAGIC.to_vec();
    foreign.extend_from_slice(
        &PublicKey::from(recipient.public_key())
            .seal(&mut OsRng, &plaintext)
            .unwrap(),
    );
    assert_eq!(
        recipient
            .open_codex_login(&foreign, &context(), NOW + 1)
            .unwrap_err(),
        CodexLoginError::InvalidEnvelope
    );
}

#[test]
fn errors_never_format_material() {
    for error in [
        CodexLoginError::InvalidContext,
        CodexLoginError::InvalidLogin,
        CodexLoginError::InvalidEnvelope,
    ] {
        let text = format!("{error} {error:?}");
        assert!(!text.contains(ACCESS) && !text.contains(ID));
    }
    assert!(!format!("{:?}", login()).contains(ACCOUNT));
}
