use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use codewire_access::{
    CODEX_CONFIG_FILE_NAME, CODEX_MANAGED_CONFIG_HEADER, ManagedCredentialClientPlacement,
    ManagedCredentialClients,
};
use serde_json::json;

use super::*;
use crate::codex_home::FileOwner;

const ACCOUNT: &str = "codewire-synthetic-account";
const CREDENTIAL: &str = "cred-synthetic-codex";
const GENERATION: u64 = 7;
const T0: u64 = 1_791_003_067;

fn clients(slots: &[&str]) -> ManagedCredentialClients {
    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
}

fn proxy_config() -> String {
    clients(&["codex"])
        .for_placement(ManagedCredentialClientPlacement::Platform)
        .codex
        .unwrap()
        .into_config_toml()
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |value, (index, byte)| {
                value | u32::from(*byte) << (16 - 8 * index)
            });
        for index in 0..=chunk.len() {
            output.push(char::from(
                ALPHABET[(value >> (18 - 6 * index) & 63) as usize],
            ));
        }
    }
    output
}

fn jwt(claims: serde_json::Value) -> String {
    format!(
        "e30.{}.synthetic-signature",
        base64url(&serde_json::to_vec(&claims).unwrap())
    )
}

/// A synthetic delivered login whose access token names `generation` and
/// expires at `exp`.
fn delivery(credential: &str, material_generation: u64, exp: u64) -> CodexLoginDelivery {
    CodexLoginDelivery::Delivered(opened(credential, material_generation, exp))
}

fn opened(credential: &str, material_generation: u64, exp: u64) -> OpenedCodexLogin {
    let access =
        jwt(json!({ "exp": exp, "iat": exp - 864_000, "generation": material_generation }));
    let id = jwt(json!({
        "email": "synthetic@example.test",
        "https://api.openai.com/auth": { "chatgpt_account_id": ACCOUNT, "chatgpt_plan_type": "plus" },
    }));
    OpenedCodexLogin {
        binding: CodexLoginBinding {
            credential_id: credential.to_owned(),
            revocation_generation: 1,
            material_generation,
        },
        login: CodexLogin::new(
            Zeroizing::new(access),
            Zeroizing::new(id),
            ACCOUNT.to_owned(),
            T0 - 60,
        )
        .unwrap(),
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            root: tempfile::tempdir().unwrap(),
        };
        // The daemon prepared the home before it listened, with Codex's own
        // state beside it.
        fs::create_dir(fixture.home().root()).unwrap();
        fs::set_permissions(fixture.home().root(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(fixture.home().root().join("history.jsonl"), b"synthetic").unwrap();
        fixture.home().sync(clients(&["codex"])).unwrap();
        fixture
    }

    fn home(&self) -> CodexHome {
        CodexHome::at(self.root.path().join(".codex"))
    }

    fn state(&self) -> PathBuf {
        self.root.path().join("tmp/codewire-codex-login")
    }

    fn writer(&self) -> CodexLoginWriter {
        self.writer_for(&self.state(), GENERATION)
    }

    fn writer_for(&self, state: &Path, generation: u64) -> CodexLoginWriter {
        CodexLoginWriter::new(self.home(), proxy_config(), state, generation, T0)
    }

    fn auth(&self) -> PathBuf {
        self.home().auth_path()
    }

    fn auth_json(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.auth()).unwrap()).unwrap()
    }

    fn config(&self) -> Option<String> {
        fs::read_to_string(self.home().config_path()).ok()
    }

    /// Every name in the home besides Codex's history, so a test sees any
    /// leftover temporary file.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(self.home().root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "history.jsonl")
            .collect();
        names.sort();
        names
    }

    fn snapshot(&self) -> (Vec<u8>, u64, u32) {
        let metadata = fs::symlink_metadata(self.auth()).unwrap();
        (
            fs::read(self.auth()).unwrap(),
            metadata.ino(),
            metadata.permissions().mode() & 0o7777,
        )
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn users_login() -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": jwt(json!({ "email": "user@example.test" })),
            "access_token": jwt(json!({ "exp": T0 + 86_400 })),
            "refresh_token": "users-own-synthetic-refresh-token",
            "account_id": "users-own-account",
        },
        "last_refresh": "2026-10-01T00:00:00Z",
    }))
    .unwrap()
}

#[test]
fn the_placeholder_refresh_token_is_never_empty() {
    // `codex logout` revokes the refresh token, or the access token when the
    // refresh token is empty, which would end the creator's login everywhere.
    // The constant is also checked at compile time beside its definition.
    assert_eq!(
        CODEX_MANAGED_REFRESH_TOKEN,
        "codewire-managed-no-refresh-token"
    );
    let fixture = Fixture::new();
    fixture
        .writer()
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    let written = fixture.auth_json();
    let refresh = written["tokens"]["refresh_token"].as_str().unwrap();
    assert!(!refresh.is_empty());
    assert_eq!(refresh, CODEX_MANAGED_REFRESH_TOKEN);
}

#[test]
fn a_delivered_login_is_codex_standard_chatgpt_auth_json_and_the_proxy_config_goes() {
    let fixture = Fixture::new();
    assert!(fixture.config().is_some());
    let mut writer = fixture.writer();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::Written
    );
    assert_eq!(mode(&fixture.auth()), 0o600);
    let written = fixture.auth_json();
    let OpenedCodexLogin { login, .. } = opened(CREDENTIAL, 1, T0 + 86_400);
    assert_eq!(
        written,
        json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": login.id_token(),
                "access_token": login.access_token(),
                "refresh_token": "codewire-managed-no-refresh-token",
                "account_id": ACCOUNT,
            },
            "last_refresh": "2026-10-03T04:50:07Z",
        })
    );
    // Codex reads the ID token as a three-part JWT.
    assert_eq!(
        written["tokens"]["id_token"]
            .as_str()
            .unwrap()
            .split('.')
            .count(),
        3
    );
    // Codex now uses its built-in provider; no temporary file remains.
    assert_eq!(fixture.config(), None);
    assert_eq!(fixture.entries(), [CODEX_AUTH_FILE_NAME]);
}

#[test]
fn rotation_is_adopted_and_an_unchanged_login_is_left_alone() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    let (_, inode, _) = fixture.snapshot();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0 + 120)
            .unwrap(),
        CodexLoginSync::Current
    );
    assert_eq!(
        fixture.snapshot().1,
        inode,
        "an unchanged login is not rewritten"
    );

    // Fields Codewire does not set survive a rotation.
    let mut extended = fixture.auth_json();
    extended["synthetic_extra"] = json!({ "kept": true });
    extended["tokens"]["synthetic_extra"] = json!("kept");
    fs::write(fixture.auth(), serde_json::to_vec(&extended).unwrap()).unwrap();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, T0 + 90_000), T0 + 240)
            .unwrap(),
        CodexLoginSync::Written
    );
    let rotated = fixture.auth_json();
    let OpenedCodexLogin { login, .. } = opened(CREDENTIAL, 2, T0 + 90_000);
    assert_eq!(rotated["tokens"]["access_token"], login.access_token());
    assert_eq!(rotated["synthetic_extra"], json!({ "kept": true }));
    assert_eq!(rotated["tokens"]["synthetic_extra"], "kept");
    assert_eq!(mode(&fixture.auth()), 0o600);

    // The file on disk decides, not memory: a widened mode is rewritten.
    fs::set_permissions(fixture.auth(), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, T0 + 90_000), T0 + 360)
            .unwrap(),
        CodexLoginSync::Written
    );
    assert_eq!(mode(&fixture.auth()), 0o600);
    assert_eq!(fixture.entries(), [CODEX_AUTH_FILE_NAME]);
}

#[test]
fn a_lower_material_generation_is_never_written_even_after_a_daemon_restart() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 5, T0 + 86_400), T0)
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 4, T0 + 90_000), T0)
            .unwrap(),
        CodexLoginSync::LowerGeneration
    );
    assert_eq!(fixture.snapshot(), before);
    drop(writer);
    let mut restarted = fixture.writer();
    assert_eq!(
        restarted
            .apply(delivery(CREDENTIAL, 4, T0 + 90_000), T0)
            .unwrap(),
        CodexLoginSync::LowerGeneration
    );
    assert_eq!(fixture.snapshot(), before);
    // Another credential has its own generations.
    assert_eq!(
        restarted
            .apply(delivery("cred-other-codex", 1, T0 + 90_000), T0)
            .unwrap(),
        CodexLoginSync::Written
    );
}

#[test]
fn the_users_own_login_is_never_touched() {
    let users_variants: Vec<Vec<u8>> = vec![
        users_login(),
        // Codex rewrites auth.json in place; a partial file is not Codewire's.
        br#"{"auth_mode":"chatgpt","tokens":{"refresh_token":"codewire-managed-no-ref"#.to_vec(),
        Vec::new(),
        b"[]".to_vec(),
        serde_json::to_vec(&json!({
            "auth_mode": "apikey", "OPENAI_API_KEY": "sk-synthetic-user-key",
            "tokens": { "refresh_token": CODEX_MANAGED_REFRESH_TOKEN },
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "tokens": { "refresh_token": format!("{CODEX_MANAGED_REFRESH_TOKEN} ") },
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "tokens": { "refresh_token": CODEX_MANAGED_REFRESH_TOKEN },
        }))
        .unwrap(),
    ];
    for users in users_variants {
        let fixture = Fixture::new();
        fs::write(fixture.auth(), &users).unwrap();
        fs::set_permissions(fixture.auth(), fs::Permissions::from_mode(0o640)).unwrap();
        let before = fixture.snapshot();
        let mut writer = fixture.writer();
        assert_eq!(
            writer
                .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
                .unwrap(),
            CodexLoginSync::UserOwned
        );
        assert_eq!(fixture.snapshot(), before);
        // A delivered login still means Codex's built-in provider, so the
        // user's own login is the one Codex uses.
        assert_eq!(fixture.config(), None);
        for (answer, at) in [
            (CodexLoginDelivery::Unavailable, T0 + 60),
            (CodexLoginDelivery::Unsupported, T0 + 6_000),
            (CodexLoginDelivery::Denied, T0 + 7_000),
        ] {
            writer.apply(answer, at).unwrap();
            assert_eq!(fixture.snapshot(), before);
        }
        assert_eq!(
            fixture.home().remove_codewire_login().unwrap(),
            Removal::Kept
        );
        assert_eq!(fixture.snapshot(), before);
        assert_eq!(
            fixture.entries(),
            [CODEX_AUTH_FILE_NAME, CODEX_CONFIG_FILE_NAME]
        );
    }
}

#[test]
fn symlinks_and_special_files_are_never_followed() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    // A Codewire-shaped file outside the home, reached through a symlink.
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    let outside = fixture.root.path().join("dotfiles-auth.json");
    fs::rename(fixture.auth(), &outside).unwrap();
    let outside_bytes = fs::read(&outside).unwrap();
    symlink(&outside, fixture.auth()).unwrap();
    let mut fresh = fixture.writer_for(&fixture.root.path().join("other-state"), GENERATION);
    for answer in [
        delivery(CREDENTIAL, 2, T0 + 90_000),
        CodexLoginDelivery::Denied,
        CodexLoginDelivery::Unavailable,
    ] {
        fresh.apply(answer, T0 + 7_200).unwrap();
        assert!(fs::symlink_metadata(fixture.auth()).unwrap().is_symlink());
        assert_eq!(fs::read(&outside).unwrap(), outside_bytes);
    }
    assert_eq!(
        fixture.home().remove_codewire_login().unwrap(),
        Removal::Kept
    );
    assert!(fs::symlink_metadata(fixture.auth()).unwrap().is_symlink());

    // A directory and a FIFO named auth.json are the user's, and a FIFO
    // never blocks the check.
    fs::remove_file(fixture.auth()).unwrap();
    fs::create_dir(fixture.auth()).unwrap();
    assert_eq!(
        fresh
            .apply(delivery(CREDENTIAL, 2, T0 + 90_000), T0)
            .unwrap(),
        CodexLoginSync::UserOwned
    );
    assert!(fixture.auth().is_dir());
    fs::remove_dir(fixture.auth()).unwrap();
    let path = std::ffi::CString::new(fixture.auth().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo has no other precondition.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert_eq!(
        fresh
            .apply(delivery(CREDENTIAL, 2, T0 + 90_000), T0)
            .unwrap(),
        CodexLoginSync::UserOwned
    );
    assert!(
        fs::symlink_metadata(fixture.auth())
            .unwrap()
            .file_type()
            .is_fifo()
    );

    // A symlinked ~/.codex is the user's choice: nothing is delivered into it.
    let target = fixture.root.path().join("dotfiles-codex");
    fs::create_dir(&target).unwrap();
    let linked = CodexHome::at(fixture.root.path().join("linked-codex"));
    symlink(&target, linked.root()).unwrap();
    let mut linked_writer = CodexLoginWriter::new(
        linked.clone(),
        proxy_config(),
        fixture.root.path().join("linked-state"),
        GENERATION,
        T0,
    );
    for answer in [
        delivery(CREDENTIAL, 1, T0 + 86_400),
        CodexLoginDelivery::Denied,
    ] {
        let outcome = linked_writer.apply(answer, T0).unwrap();
        assert!(matches!(
            outcome,
            CodexLoginSync::UserOwned | CodexLoginSync::Denied
        ));
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
    assert_eq!(linked.remove_codewire_login().unwrap(), Removal::Kept);
}

#[test]
fn logout_stays_logged_out_across_a_daemon_restart_until_a_new_container_or_generation() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    // `codex logout` deletes auth.json.
    fs::remove_file(fixture.auth()).unwrap();
    for at in [T0 + 120, T0 + 240] {
        assert_eq!(
            writer
                .apply(delivery(CREDENTIAL, 2, T0 + 90_000), at)
                .unwrap(),
            CodexLoginSync::LoggedOut
        );
        assert!(!fixture.auth().exists());
        // Logged out means logged out, not quietly back on the proxy.
        assert_eq!(fixture.config(), None);
    }
    // The marker is container-local, keyed by generation and credential.
    assert!(
        fixture
            .state()
            .join(format!("generation-{GENERATION}.logged-out.{CREDENTIAL}"))
            .is_file()
    );
    assert_eq!(mode(&fixture.state()), 0o700);
    drop(writer);

    // A restarted daemon in the same container keeps it.
    let mut restarted = fixture.writer();
    assert_eq!(
        restarted
            .apply(delivery(CREDENTIAL, 3, T0 + 90_000), T0 + 360)
            .unwrap(),
        CodexLoginSync::LoggedOut
    );
    assert!(!fixture.auth().exists());
    // Another credential is not covered by that logout.
    assert_eq!(
        restarted
            .apply(delivery("cred-other-codex", 1, T0 + 90_000), T0 + 480)
            .unwrap(),
        CodexLoginSync::Written
    );
    fs::remove_file(fixture.auth()).unwrap();

    // Codex re-selected is a new generation; a Sandbox restart is a new
    // container with an empty /tmp. Both write again.
    let mut reselected = fixture.writer_for(&fixture.state(), GENERATION + 1);
    assert_eq!(
        reselected
            .apply(delivery(CREDENTIAL, 3, T0 + 90_000), T0 + 600)
            .unwrap(),
        CodexLoginSync::Written
    );
    fs::remove_file(fixture.auth()).unwrap();
    let mut new_container =
        fixture.writer_for(&fixture.root.path().join("new-container-tmp"), GENERATION);
    assert_eq!(
        new_container
            .apply(delivery(CREDENTIAL, 3, T0 + 90_000), T0 + 720)
            .unwrap(),
        CodexLoginSync::Written
    );
}

#[test]
fn a_logout_while_the_daemon_was_down_stays_logged_out() {
    let fixture = Fixture::new();
    fixture
        .writer()
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    fs::remove_file(fixture.auth()).unwrap();
    assert_eq!(
        fixture
            .writer()
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0 + 30)
            .unwrap(),
        CodexLoginSync::LoggedOut
    );
    assert!(!fixture.auth().exists());
}

#[test]
fn only_an_explicit_denial_removes_codewires_login_and_restores_the_proxy() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    let before = fixture.snapshot();
    for (answer, outcome) in [
        (CodexLoginDelivery::Unavailable, CodexLoginSync::Unavailable),
        (CodexLoginDelivery::Unsupported, CodexLoginSync::Unsupported),
        (CodexLoginDelivery::Unavailable, CodexLoginSync::Unavailable),
    ] {
        assert_eq!(writer.apply(answer, T0 + 60).unwrap(), outcome);
        assert_eq!(fixture.snapshot(), before);
        assert_eq!(fixture.config(), None);
    }
    assert_eq!(
        writer.apply(CodexLoginDelivery::Denied, T0 + 120).unwrap(),
        CodexLoginSync::Denied
    );
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config(), Some(proxy_config()));
    assert_eq!(fixture.entries(), [CODEX_CONFIG_FILE_NAME]);
    // Codewire removed it, so its absence is not a logout: a later delivery
    // (re-attached) writes again.
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, T0 + 90_000), T0 + 240)
            .unwrap(),
        CodexLoginSync::Written
    );
    assert_eq!(fixture.config(), None);
}

#[test]
fn a_denial_never_replaces_the_users_config() {
    let fixture = Fixture::new();
    let users_config = "model = \"synthetic-user-model\"\n";
    fs::write(fixture.home().config_path(), users_config).unwrap();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    assert_eq!(fixture.config().as_deref(), Some(users_config));
    assert_eq!(
        writer.apply(CodexLoginDelivery::Denied, T0 + 120).unwrap(),
        CodexLoginSync::Denied
    );
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config().as_deref(), Some(users_config));
}

#[test]
fn an_expired_login_is_removed_while_the_bridge_fails() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer.apply(delivery(CREDENTIAL, 1, T0 + 100), T0).unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        writer
            .apply(CodexLoginDelivery::Unavailable, T0 + 99)
            .unwrap(),
        CodexLoginSync::Unavailable
    );
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        writer
            .apply(CodexLoginDelivery::Unsupported, T0 + 100)
            .unwrap(),
        CodexLoginSync::Expired
    );
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config(), Some(proxy_config()));
    // Once delivery works again, the login is written again: Codewire's own
    // removal is not a logout.
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, T0 + 86_400), T0 + 200)
            .unwrap(),
        CodexLoginSync::Written
    );
    assert_eq!(fixture.config(), None);
}

#[test]
fn a_login_lapses_after_ten_minutes_without_a_delivery() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    let far = T0 + 864_000;
    writer.apply(delivery(CREDENTIAL, 1, far), T0).unwrap();
    // A delivery restarts the window; failures before it do not count.
    writer
        .apply(CodexLoginDelivery::Unavailable, T0 + 300)
        .unwrap();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, far), T0 + 400)
            .unwrap(),
        CodexLoginSync::Current
    );
    let before = fixture.snapshot();
    for (answer, at) in [
        (CodexLoginDelivery::Unavailable, T0 + 500),
        (CodexLoginDelivery::Unsupported, T0 + 800),
        (CodexLoginDelivery::Unavailable, T0 + 1_099),
    ] {
        assert_ne!(writer.apply(answer, at).unwrap(), CodexLoginSync::Lapsed);
        assert_eq!(fixture.snapshot(), before);
    }
    assert_eq!(
        writer
            .apply(CodexLoginDelivery::Unavailable, T0 + 1_100)
            .unwrap(),
        CodexLoginSync::Lapsed
    );
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config(), Some(proxy_config()));
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, far), T0 + 1_200)
            .unwrap(),
        CodexLoginSync::Written
    );

    // A daemon that never receives a delivery removes a previous container's
    // login ten minutes after it starts.
    drop(writer);
    let mut never = fixture.writer_for(&fixture.root.path().join("new-container-tmp"), 9);
    assert_eq!(
        never
            .apply(CodexLoginDelivery::Unavailable, T0 + 599)
            .unwrap(),
        CodexLoginSync::Unavailable
    );
    assert!(fixture.auth().exists());
    assert_eq!(
        never
            .apply(CodexLoginDelivery::Unavailable, T0 + 600)
            .unwrap(),
        CodexLoginSync::Lapsed
    );
    assert!(!fixture.auth().exists());
}

#[test]
fn rename_away_restores_a_concurrent_users_login_and_never_deletes_one() {
    let fixture = Fixture::new();
    let home = fixture.home().open_for_login(false).unwrap().unwrap();
    let aside = ".auth.json.codewire.synthetic.aside";

    // The file moved aside turned out to be the user's (a `codex login`
    // between the inspection and the rename): it goes back.
    fs::write(fixture.home().root().join(aside), users_login()).unwrap();
    assert_eq!(settle_aside(&home, aside, |_| true).unwrap(), Removal::Kept);
    assert_eq!(fs::read(fixture.auth()).unwrap(), users_login());
    assert!(!fixture.home().root().join(aside).exists());

    // And if yet another login appeared meanwhile, neither is lost.
    fs::write(fixture.home().root().join(aside), users_login()).unwrap();
    fs::write(fixture.auth(), b"{\"newer\":true}").unwrap();
    assert_eq!(settle_aside(&home, aside, |_| true).unwrap(), Removal::Kept);
    assert_eq!(fs::read(fixture.auth()).unwrap(), b"{\"newer\":true}");
    assert_eq!(
        fs::read(fixture.home().root().join(aside)).unwrap(),
        users_login()
    );
    fs::remove_file(fixture.home().root().join(aside)).unwrap();
    fs::remove_file(fixture.auth()).unwrap();

    // Codewire's own file moved aside is removed.
    fixture
        .writer()
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    fs::rename(fixture.auth(), fixture.home().root().join(aside)).unwrap();
    assert_eq!(
        settle_aside(&home, aside, |_| true).unwrap(),
        Removal::Removed
    );
    assert!(!fixture.home().root().join(aside).exists());
    assert!(!fixture.auth().exists());
}

#[test]
fn a_file_changed_or_created_after_inspection_is_never_replaced() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    let home = fixture.home().open_for_login(false).unwrap().unwrap();
    let AuthFile::Codewire { entry, .. } = classify(&home, CODEX_AUTH_FILE_NAME).unwrap() else {
        panic!("Codewire's file expected");
    };
    // `codex login` writes in place: same inode, the user's content.
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(fixture.auth())
        .unwrap();
    fs::write(fixture.auth(), users_login()).unwrap();
    assert!(!replace(&home, &entry, b"{\"replacement\":true}").unwrap());
    assert_eq!(fs::read(fixture.auth()).unwrap(), users_login());
    // A file created after an absent inspection stays as well.
    assert!(!install_new(&home, b"{\"replacement\":true}").unwrap());
    assert_eq!(fs::read(fixture.auth()).unwrap(), users_login());
    assert_eq!(fixture.entries(), [CODEX_AUTH_FILE_NAME]);
}

#[test]
fn an_id_token_codex_cannot_read_is_never_written() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    for id_token in [
        "not-a-jwt",
        "e30.e30",
        "e30.e30.signature.extra",
        "e30..signature",
        "e30.bm90LWpzb24.signature",
        "e30.W10.signature",
    ] {
        let login = CodexLogin::new(
            Zeroizing::new(jwt(json!({ "exp": T0 + 86_400 }))),
            Zeroizing::new(id_token.to_owned()),
            ACCOUNT.to_owned(),
            T0,
        )
        .unwrap();
        let delivered = CodexLoginDelivery::Delivered(OpenedCodexLogin {
            binding: CodexLoginBinding {
                credential_id: CREDENTIAL.to_owned(),
                revocation_generation: 1,
                material_generation: 1,
            },
            login,
        });
        assert_eq!(
            writer.apply(delivered, T0).unwrap(),
            CodexLoginSync::Invalid,
            "{id_token}"
        );
        assert!(!fixture.auth().exists());
        assert_eq!(fixture.config(), Some(proxy_config()));
    }
}

#[test]
fn codex_not_selected_removes_only_codewires_files() {
    let fixture = Fixture::new();
    fixture
        .writer()
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    fixture.home().sync(clients(&["codex"])).unwrap();
    assert!(fixture.config().is_some());
    fixture.home().prepare(clients(&["openai"]));
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config(), None);
    assert!(fixture.entries().is_empty(), "{:?}", fixture.entries());

    fs::write(fixture.auth(), users_login()).unwrap();
    fixture.home().prepare(clients(&[]));
    assert_eq!(fs::read(fixture.auth()).unwrap(), users_login());
    // A missing home stays missing.
    let missing = CodexHome::at(fixture.root.path().join("never-created"));
    missing.prepare(clients(&[]));
    assert!(!missing.root().exists());
}

#[test]
fn a_daemon_with_a_bridge_and_codex_selected_runs_the_writer_for_its_own_placement() {
    use crate::{Config, CredentialBridgeConfig, CredentialBridgeTransport, DaemonAuthToken};
    let config = |transport: Option<CredentialBridgeTransport>, slots: &[&str]| Config {
        host: None,
        listen_addr: "127.0.0.1:0".into(),
        workspace_root: "/workspace".into(),
        home_root: "/home/codewire".into(),
        auth_token: DaemonAuthToken::new("synthetic-daemon-token").unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: transport.map(|transport| CredentialBridgeConfig {
            transport,
            environment_id: uuid::Uuid::from_u128(1),
            environment_generation: GENERATION,
            ingress_socket: "/codewire/run/credential.sock".into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        }),
        managed_credential_clients: clients(slots),
        launch_projection: None,
        session_working_dir: None,
    };
    let hosted = CodexHome::at("/nonexistent/.codex");
    let native = CodexHome::native(
        "/nonexistent/agent-homes/codex",
        FileOwner {
            uid: 1000,
            gid: 1000,
        },
    );
    // Each placement restores its own provider configuration.
    let writer = login_writer(
        &config(Some(CredentialBridgeTransport::Hosted), &["codex"]),
        hosted.clone(),
    )
    .unwrap();
    assert!(writer.proxy_config.starts_with(CODEX_MANAGED_CONFIG_HEADER));
    let writer = login_writer(
        &config(Some(CredentialBridgeTransport::Local), &["codex"]),
        native.clone(),
    )
    .unwrap();
    assert_eq!(
        writer.proxy_config,
        clients(&["codex"])
            .for_placement(ManagedCredentialClientPlacement::Native)
            .codex
            .unwrap()
            .into_config_toml()
    );
    for (transport, home, slots) in [
        // Codex not selected, or no bridge.
        (
            Some(CredentialBridgeTransport::Hosted),
            &hosted,
            &["openai"][..],
        ),
        (Some(CredentialBridgeTransport::Local), &native, &["openai"]),
        (None, &hosted, &["codex"]),
        (None, &native, &["codex"]),
        // A home of the other placement: a hosted home is the daemon's own,
        // a native one is always kept for its workload user.
        (Some(CredentialBridgeTransport::Local), &hosted, &["codex"]),
        (Some(CredentialBridgeTransport::Hosted), &native, &["codex"]),
    ] {
        assert!(login_writer(&config(transport, slots), home.clone()).is_none());
    }
}

/// A local VM's native home: Codewire's own directory, kept by the guest
/// daemon for the workload user. Here the owner is this test's own uid, as
/// unprivileged tests cannot give files to another user; the guest (root)
/// does, through each new file's descriptor.
struct NativeFixture {
    root: tempfile::TempDir,
}

impl NativeFixture {
    fn new() -> Self {
        let fixture = Self {
            root: tempfile::tempdir().unwrap(),
        };
        let home = fixture.home();
        // The guest prepared the home and its native provider configuration.
        fs::create_dir_all(home.root()).unwrap();
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(home.config_path(), native_config()).unwrap();
        fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }

    fn owner() -> FileOwner {
        // SAFETY: getuid and getgid have no preconditions and cannot fail.
        FileOwner {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    fn home(&self) -> CodexHome {
        CodexHome::native(self.root.path().join("agent-homes/codex"), Self::owner())
    }

    fn writer(&self) -> CodexLoginWriter {
        CodexLoginWriter::new(
            self.home(),
            native_config(),
            self.root.path().join("tmp/codewire-codex-login"),
            GENERATION,
            T0,
        )
    }
}

fn native_config() -> String {
    clients(&["codex"])
        .for_placement(ManagedCredentialClientPlacement::Native)
        .codex
        .unwrap()
        .into_config_toml()
}

/// A local VM gets exactly the login a hosted Sandbox gets: the same
/// `auth.json` bytes, the placeholder refresh token and never the real one,
/// and while it is delivered Codex uses its own login instead of the proxy.
#[test]
fn a_native_home_gets_the_same_login_document_as_a_hosted_one() {
    let hosted = Fixture::new();
    let native = NativeFixture::new();
    let mut hosted_writer = hosted.writer();
    let mut native_writer = native.writer();
    assert_eq!(
        hosted_writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::Written
    );
    assert_eq!(
        native_writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::Written
    );
    let native_auth = fs::read(native.home().auth_path()).unwrap();
    assert_eq!(native_auth, fs::read(hosted.auth()).unwrap());
    let document: serde_json::Value = serde_json::from_slice(&native_auth).unwrap();
    assert_eq!(document["auth_mode"], "chatgpt");
    assert_eq!(
        document["tokens"]["refresh_token"],
        CODEX_MANAGED_REFRESH_TOKEN
    );
    assert_eq!(document["tokens"]["account_id"], ACCOUNT);
    assert_eq!(document["OPENAI_API_KEY"], serde_json::Value::Null);
    let metadata = fs::symlink_metadata(native.home().auth_path()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), NativeFixture::owner().uid);
    // The native proxy configuration is Codewire's and is removed while the
    // login is delivered, so Codex uses its own login.
    assert!(!native.home().config_path().exists());

    // An explicit denial withdraws the login and restores the native proxy.
    assert_eq!(
        native_writer
            .apply(CodexLoginDelivery::Denied, T0 + 60)
            .unwrap(),
        CodexLoginSync::Denied
    );
    assert!(!native.home().auth_path().exists());
    assert_eq!(
        fs::read_to_string(native.home().config_path()).unwrap(),
        native_config()
    );
}

/// Only the exact native configuration is Codewire's. Once Codex adds its
/// own project-trust entry, the file is the user's: a delivered login does not
/// delete it, and a later denial does not rewrite it, so the entry is never
/// wiped. Any other file there is the user's too.
#[test]
fn a_native_home_recognizes_only_codewires_configuration() {
    let native = NativeFixture::new();
    let trusted = format!(
        "{}\n[projects.\"/workspace\"]\ntrust_level = \"trusted\"\n",
        native_config()
    );
    fs::write(native.home().config_path(), &trusted).unwrap();
    let mut writer = native.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    assert_eq!(
        fs::read_to_string(native.home().config_path()).unwrap(),
        trusted
    );
    writer.apply(CodexLoginDelivery::Denied, T0 + 60).unwrap();
    assert_eq!(
        fs::read_to_string(native.home().config_path()).unwrap(),
        trusted
    );

    let native = NativeFixture::new();
    fs::write(native.home().config_path(), b"model = \"users\"\n").unwrap();
    let mut writer = native.writer();
    writer
        .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
        .unwrap();
    assert_eq!(
        fs::read(native.home().config_path()).unwrap(),
        b"model = \"users\"\n"
    );
    // A missing native home is never created by the daemon.
    let missing = CodexHome::native(native.root.path().join("missing"), NativeFixture::owner());
    let mut writer = CodexLoginWriter::new(
        missing.clone(),
        native_config(),
        native.root.path().join("tmp/missing-state"),
        GENERATION,
        T0,
    );
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::UserOwned
    );
    assert!(!missing.root().exists());
}

/// A native home of another owner, or a file of another owner in it, is
/// never read or replaced.
#[test]
fn a_native_home_of_another_owner_is_left_alone() {
    let native = NativeFixture::new();
    let other = FileOwner {
        uid: NativeFixture::owner().uid.wrapping_add(1),
        gid: NativeFixture::owner().gid,
    };
    let home = CodexHome::native(native.home().root(), other);
    let mut writer = CodexLoginWriter::new(
        home,
        native_config(),
        native.root.path().join("tmp/other-state"),
        GENERATION,
        T0,
    );
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::UserOwned
    );
    assert!(!native.home().auth_path().exists());
    assert_eq!(
        fs::read_to_string(native.home().config_path()).unwrap(),
        native_config()
    );
}

#[test]
fn checks_back_off_with_jitter_while_nothing_is_delivered() {
    let mut retry = Retry::new(CODEX_LOGIN_CHECK_PERIOD);
    let mut ceiling = LOGIN_RETRY_MIN;
    for _ in 0..12 {
        let delay = retry.after(CodexLoginSync::Unavailable);
        assert!(
            delay >= ceiling / 2 && delay <= ceiling,
            "{delay:?} {ceiling:?}"
        );
        ceiling = (ceiling * 2).min(CODEX_LOGIN_CHECK_PERIOD);
    }
    assert_eq!(ceiling, CODEX_LOGIN_CHECK_PERIOD);
    for outcome in [
        CodexLoginSync::Written,
        CodexLoginSync::Current,
        CodexLoginSync::Denied,
        CodexLoginSync::Unsupported,
        CodexLoginSync::LoggedOut,
    ] {
        let delay = retry.after(outcome);
        assert!(delay >= CODEX_LOGIN_CHECK_PERIOD * 9 / 10 && delay <= CODEX_LOGIN_CHECK_PERIOD);
    }
    // A decision resets the backoff.
    assert!(retry.after(CodexLoginSync::Unavailable) <= LOGIN_RETRY_MIN);
}

#[test]
fn a_shorter_kind_period_bounds_checks_and_backoff() {
    let period = std::time::Duration::from_secs(30);
    let mut retry = Retry::new(period);
    for _ in 0..12 {
        assert!(retry.after(CodexLoginSync::Unavailable) <= period);
    }
    let delay = retry.after(CodexLoginSync::Current);
    assert!(delay >= period * 9 / 10 && delay <= period, "{delay:?}");
}

#[test]
fn last_refresh_is_rfc3339_utc() {
    for (unix, text) in [
        (0, "1970-01-01T00:00:00Z"),
        (946_684_799, "1999-12-31T23:59:59Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (T0, "2026-10-03T04:51:07Z"),
        (4_107_628_799, "2100-03-01T23:59:59Z"),
    ] {
        assert_eq!(rfc3339_utc(unix), text);
    }
}

#[test]
fn jwt_claims_decode_like_codex() {
    let token = jwt(json!({ "exp": 12_345, "nested": { "a": [1, 2] } }));
    let claims = jwt_claims(&token).unwrap();
    assert_eq!(claims.0["exp"], 12_345);
    assert_eq!(claims.0["nested"]["a"], json!([1, 2]));
    // Unpadded base64url of every length Codex accepts.
    for length in 0..8 {
        let bytes: Vec<u8> = (0..length).map(|value| value * 37 + 1).collect();
        assert_eq!(*base64url_decode(&base64url(&bytes)).unwrap(), bytes);
    }
    assert!(base64url_decode("a").is_none());
    assert!(base64url_decode("ab+/").is_none());
    assert!(base64url_decode("ab==").is_none());
}

/// A scripted bridge for the task loop: answers in order, then `fallback`.
struct Script {
    answers: std::sync::Mutex<Vec<Result<OpenedCodexLogin, LoginFailure>>>,
    fallback: LoginFailure,
    calls: std::sync::atomic::AtomicUsize,
}

impl CodexLoginSource for std::sync::Arc<Script> {
    fn codex_login(&self) -> impl Future<Output = Result<OpenedCodexLogin, LoginFailure>> + Send {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let next = if answers.is_empty() {
            Err(self.fallback)
        } else {
            answers.remove(0)
        };
        std::future::ready(next)
    }
}

async fn eventually(condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn the_task_checks_at_start_changes_nothing_without_the_capability_and_stops() {
    let fixture = Fixture::new();
    let script = std::sync::Arc::new(Script {
        answers: std::sync::Mutex::new(Vec::new()),
        fallback: LoginFailure::Unsupported,
        calls: Default::default(),
    });
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(run_codex_login_writer(
        fixture.writer(),
        script.clone(),
        CODEX_LOGIN_CHECK_PERIOD,
        stopped,
    ));
    eventually(|| script.calls.load(std::sync::atomic::Ordering::SeqCst) == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!fixture.auth().exists());
    assert_eq!(fixture.config(), Some(proxy_config()));
    // Waiting out its period, the task still stops at once.
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(script.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // With the capability, the first check writes the login.
    let script = std::sync::Arc::new(Script {
        answers: std::sync::Mutex::new(vec![Ok(opened(CREDENTIAL, 1, unix_now() + 86_400))]),
        fallback: LoginFailure::Unavailable,
        calls: Default::default(),
    });
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(run_codex_login_writer(
        fixture.writer(),
        script.clone(),
        CODEX_LOGIN_CHECK_PERIOD,
        stopped,
    ));
    eventually(|| fixture.auth().exists()).await;
    eventually(|| fixture.config().is_none()).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        proxy_config().starts_with(CODEX_MANAGED_CONFIG_HEADER),
        "the restored proxy config carries the ownership header"
    );
}

/// A start removes what a crash or a revocation left beside `auth.json`: a
/// write in progress and a set-aside copy of Codewire's login. A set-aside
/// file of the user's own stays, and so does Codex's own state.
#[test]
fn a_start_removes_leftover_temporaries_that_could_hold_a_token() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    assert_eq!(
        writer
            .apply(delivery("cred-a", 1, T0 + 86_400), T0)
            .unwrap(),
        CodexLoginSync::Written
    );
    let delivered = fs::read(fixture.auth()).unwrap();
    let sibling = |name: &str| fixture.home().root().join(name);
    let leftover_new = format!(".auth.json.codewire.{}.new", "a".repeat(32));
    let leftover_aside = format!(".auth.json.codewire.{}.aside", "b".repeat(32));
    let users_aside = format!(".auth.json.codewire.{}.aside", "c".repeat(32));
    for (name, bytes) in [
        (&leftover_new, b"{\"partial".to_vec()),
        (&leftover_aside, delivered.clone()),
        (
            &users_aside,
            serde_json::to_vec(&json!({
                "auth_mode": "chatgpt",
                "tokens": {"refresh_token": "users-own-refresh"}
            }))
            .unwrap(),
        ),
    ] {
        fs::write(sibling(name), bytes).unwrap();
        fs::set_permissions(sibling(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(fixture.writer().remove_leftovers().unwrap(), 2);
    assert!(!sibling(&leftover_new).exists());
    assert!(!sibling(&leftover_aside).exists());
    assert!(sibling(&users_aside).exists());
    assert!(sibling("history.jsonl").exists());
    assert_eq!(fs::read(fixture.auth()).unwrap(), delivered);
    assert_eq!(fixture.writer().remove_leftovers().unwrap(), 0);
}
