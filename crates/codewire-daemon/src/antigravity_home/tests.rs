use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use tempfile::TempDir;
use zeroize::Zeroizing;

use super::*;

const NOW: u64 = 1_800_000_000;

fn placeholder(ch: char) -> String {
    format!("cwp1_{}A", ch.to_string().repeat(42))
}

fn delivered(ch: char, rev: u64, email: Option<&str>) -> AntigravityLoginDelivery {
    AntigravityLoginDelivery::Delivered(OpenedAntigravityLogin {
        binding: CodexLoginBinding {
            credential_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            revocation_generation: rev,
            material_generation: rev,
        },
        login: AntigravityLogin::new(
            Zeroizing::new(placeholder(ch)),
            email.map(str::to_owned),
            NOW,
        )
        .unwrap(),
    })
}

#[test]
fn writes_placeholder_token_file_only_when_intercepting_and_clears_on_denial() {
    let home = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let mut non_intercepting = AntigravityLoginWriter::new(home.path(), state.path(), 7, NOW);
    assert_eq!(
        non_intercepting
            .apply(delivered('A', 1, Some("dev@example.com")), NOW)
            .unwrap(),
        AntigravityLoginSync::NotIntercepted
    );
    let path = AntigravityHome::new(home.path()).token_path();
    assert!(!path.exists());

    let mut writer = AntigravityLoginWriter::new(home.path(), state.path(), 7, NOW).intercepting();
    assert_eq!(
        writer
            .apply(delivered('A', 1, Some("dev@example.com")), NOW)
            .unwrap(),
        AntigravityLoginSync::Written
    );
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(json["token"]["access_token"], placeholder('A'));
    assert_eq!(json["token"]["token_type"], "Bearer");
    assert_eq!(
        json["token"]["refresh_token"],
        ANTIGRAVITY_MANAGED_REFRESH_TOKEN
    );
    assert_eq!(json["token"]["expiry"], MANAGED_EXPIRY_RFC3339);
    assert_eq!(json["auth_method"], "consumer");
    assert_eq!(json["id_token_email"], "dev@example.com");
    assert!(is_codewire_token_file(&fs::read(&path).unwrap()));

    assert_eq!(
        writer
            .apply(delivered('A', 1, Some("dev@example.com")), NOW + 10)
            .unwrap(),
        AntigravityLoginSync::Current
    );
    assert_eq!(
        writer
            .apply(AntigravityLoginDelivery::Denied, NOW + 20)
            .unwrap(),
        AntigravityLoginSync::Denied
    );
    assert!(!path.exists());
}

#[test]
fn leaves_user_owned_file_untouched_and_refuses_symlinks() {
    let home = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let dir = home.path().join(".gemini/antigravity-cli");
    fs::create_dir_all(&dir).unwrap();
    let user_token = br#"{"token":{"access_token":"ya29.user","refresh_token":"1//user"},"auth_method":"consumer"}"#;
    let path = dir.join(ANTIGRAVITY_TOKEN_FILE_NAME);
    fs::write(&path, user_token).unwrap();

    let mut writer = AntigravityLoginWriter::new(home.path(), state.path(), 7, NOW).intercepting();
    assert_eq!(
        writer.apply(delivered('B', 1, None), NOW).unwrap(),
        AntigravityLoginSync::UserOwned
    );
    assert_eq!(fs::read(&path).unwrap(), user_token);
    assert_eq!(
        writer
            .apply(AntigravityLoginDelivery::Denied, NOW + 1)
            .unwrap(),
        AntigravityLoginSync::Denied
    );
    assert_eq!(fs::read(&path).unwrap(), user_token);

    // Symlinked .gemini directory receives nothing.
    let sym_home = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    symlink(outside.path(), sym_home.path().join(".gemini")).unwrap();
    let mut sym_writer =
        AntigravityLoginWriter::new(sym_home.path(), state.path(), 8, NOW).intercepting();
    assert_eq!(
        sym_writer.apply(delivered('C', 1, None), NOW).unwrap(),
        AntigravityLoginSync::UserOwned
    );
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}
