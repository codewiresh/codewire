use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::sync::{Arc, Mutex};

use codewire_access::ManagedCredentialClients;
use serde_json::json;
use zeroize::Zeroizing;

use super::*;

const ACCESS: &str = "sk-ant-oat01-synthetic-claude-access-1";
const ROTATED: &str = "sk-ant-oat01-synthetic-claude-access-2";
const CREDENTIAL: &str = "cred-synthetic-claude";
const GENERATION: u64 = 7;
const T0: u64 = 1_791_003_067;
const TIER: &str = "default_claude_max_20x";
/// Eight hours after `T0`, in milliseconds, as Claude stores `expiresAt`.
const EXPIRES: u64 = (T0 + 8 * 3_600) * 1_000;

fn scopes() -> Vec<String> {
    [
        "user:profile",
        "user:inference",
        "user:sessions:claude_code",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn opened(
    credential: &str,
    generation: u64,
    access: &str,
    expires_at_ms: u64,
) -> OpenedClaudeLogin {
    OpenedClaudeLogin {
        binding: CodexLoginBinding {
            credential_id: credential.to_owned(),
            revocation_generation: 1,
            material_generation: generation,
        },
        login: ClaudeLogin::new(
            Zeroizing::new(access.to_owned()),
            expires_at_ms,
            scopes(),
            Some("max".into()),
            Some(TIER.into()),
            T0 - 60,
        )
        .unwrap(),
    }
}

fn delivery(
    credential: &str,
    generation: u64,
    access: &str,
    expires_at_ms: u64,
) -> ClaudeLoginDelivery {
    ClaudeLoginDelivery::Delivered(opened(credential, generation, access, expires_at_ms))
}

fn first() -> ClaudeLoginDelivery {
    delivery(CREDENTIAL, 1, ACCESS, EXPIRES)
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            root: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(fixture.home()).unwrap();
        fs::set_permissions(fixture.home(), fs::Permissions::from_mode(0o750)).unwrap();
        fixture
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn config(&self) -> PathBuf {
        self.home().join(CLAUDE_CONFIG_DIR_NAME)
    }

    fn credentials(&self) -> PathBuf {
        self.config().join(CLAUDE_CREDENTIALS_FILE_NAME)
    }

    fn state(&self) -> PathBuf {
        self.root.path().join("tmp/codewire-claude-login")
    }

    fn writer(&self) -> ClaudeLoginWriter {
        self.writer_for(&self.state(), GENERATION)
    }

    fn writer_for(&self, state: &Path, generation: u64) -> ClaudeLoginWriter {
        ClaudeLoginWriter::new(self.home(), state, generation, T0)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&fs::read(self.credentials()).unwrap()).unwrap()
    }

    /// Write `value` as Claude Code would, creating `~/.claude`.
    fn store(&self, value: &Value) {
        self.store_bytes(&serde_json::to_vec_pretty(value).unwrap());
    }

    fn store_bytes(&self, bytes: &[u8]) {
        fs::create_dir_all(self.config()).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_file(self.credentials());
        fs::write(self.credentials(), bytes).unwrap();
        fs::set_permissions(self.credentials(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Every name in `~/.claude`, so a test sees any leftover temporary file.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(self.config())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn snapshot(&self) -> (Vec<u8>, u64, u32) {
        let metadata = fs::symlink_metadata(self.credentials()).unwrap();
        (
            fs::read(self.credentials()).unwrap(),
            metadata.ino(),
            metadata.permissions().mode() & 0o7777,
        )
    }

    fn refresh_token(&self) -> String {
        self.json()[CLAUDE_LOGIN_KEY]["refreshToken"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Members Claude Code keeps in the same file.
fn unrelated() -> Value {
    json!({
        "mcpOAuth": { "synthetic-server": { "accessToken": "synthetic-mcp-token" } },
        "organizationUuid": "00000000-0000-4000-8000-000000000001",
    })
}

/// Claude Code's own login after `claude /login` in the Sandbox.
fn users_login() -> Value {
    json!({
        "accessToken": "sk-ant-oat01-synthetic-users-own-access",
        "refreshToken": "sk-ant-ort01-synthetic-users-own-refresh",
        "expiresAt": EXPIRES,
        "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "pro",
    })
}

#[test]
fn a_delivered_login_is_claude_codes_own_login_with_a_placeholder_and_the_marker() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    assert_eq!(writer.apply(first(), T0).unwrap(), ClaudeLoginSync::Written);
    assert_eq!(mode(&fixture.config()), 0o700);
    assert_eq!(mode(&fixture.credentials()), 0o600);
    let metadata = fs::symlink_metadata(fixture.credentials()).unwrap();
    // SAFETY: geteuid has no preconditions and cannot fail.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    let written = fixture.json();
    let refresh = fixture.refresh_token();
    assert!(is_placeholder(&refresh), "{refresh}");
    assert!(refresh.starts_with("codewire-managed-no-refresh-token-"));
    assert_eq!(
        written,
        json!({
            "claudeAiOauth": {
                "accessToken": ACCESS,
                "refreshToken": refresh,
                "expiresAt": EXPIRES,
                "scopes": ["user:profile", "user:inference", "user:sessions:claude_code"],
                "subscriptionType": "max",
                "rateLimitTier": TIER,
            },
            "codewireManaged": 1,
        })
    );
    // Neither the client ID nor a refresh-token expiry is written.
    assert!(written[CLAUDE_LOGIN_KEY].get("clientId").is_none());
    assert!(
        written[CLAUDE_LOGIN_KEY]
            .get("refreshTokenExpiresAt")
            .is_none()
    );
    // No temporary file remains.
    assert_eq!(fixture.entries(), [CLAUDE_CREDENTIALS_FILE_NAME]);
}

#[test]
fn a_login_without_plan_or_tier_omits_both() {
    let fixture = Fixture::new();
    let login = OpenedClaudeLogin {
        binding: CodexLoginBinding {
            credential_id: CREDENTIAL.into(),
            revocation_generation: 1,
            material_generation: 1,
        },
        login: ClaudeLogin::new(
            Zeroizing::new(ACCESS.into()),
            EXPIRES,
            vec!["user:inference".into(), "user:profile".into()],
            None,
            None,
            T0,
        )
        .unwrap(),
    };
    fixture
        .writer()
        .apply(ClaudeLoginDelivery::Delivered(login), T0)
        .unwrap();
    let oauth = fixture.json()[CLAUDE_LOGIN_KEY].clone();
    assert!(oauth.get("subscriptionType").is_none());
    assert!(oauth.get("rateLimitTier").is_none());
}

#[test]
fn unrelated_members_are_kept_and_the_nonce_changes_only_with_the_token() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    let mut writer = fixture.writer();
    assert_eq!(writer.apply(first(), T0).unwrap(), ClaudeLoginSync::Written);
    let written = fixture.json();
    assert_eq!(written["mcpOAuth"], unrelated()["mcpOAuth"]);
    assert_eq!(written["organizationUuid"], unrelated()["organizationUuid"]);
    assert_eq!(written[CLAUDE_MANAGED_MARKER], 1);
    let nonce = fixture.refresh_token();

    // The same login again: nothing is written, the nonce stays.
    let before = fixture.snapshot();
    assert_eq!(
        writer.apply(first(), T0 + 120).unwrap(),
        ClaudeLoginSync::Current
    );
    assert_eq!(fixture.snapshot(), before);

    // A rotated token is written with a new nonce; other members stay.
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, ROTATED, EXPIRES + 60_000), T0 + 240)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    let rotated = fixture.json();
    assert_eq!(rotated[CLAUDE_LOGIN_KEY]["accessToken"], ROTATED);
    assert_eq!(rotated[CLAUDE_LOGIN_KEY]["expiresAt"], EXPIRES + 60_000);
    assert_ne!(fixture.refresh_token(), nonce);
    assert!(is_placeholder(&fixture.refresh_token()));
    assert_eq!(rotated["mcpOAuth"], unrelated()["mcpOAuth"]);
    assert_eq!(fixture.entries(), [CLAUDE_CREDENTIALS_FILE_NAME]);

    // A wider mode is narrowed on the next check.
    fs::set_permissions(fixture.credentials(), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, ROTATED, EXPIRES + 60_000), T0 + 360)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    assert_eq!(mode(&fixture.credentials()), 0o600);
}

#[test]
fn a_member_claude_code_writes_later_is_kept_by_the_next_rotation() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer.apply(first(), T0).unwrap();
    // Claude Code adds an MCP login to the same file.
    let mut value = fixture.json();
    value["mcpOAuth"] = unrelated()["mcpOAuth"].clone();
    fixture.store(&value);
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, ROTATED, EXPIRES + 1_000), T0 + 120)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    assert_eq!(fixture.json()["mcpOAuth"], unrelated()["mcpOAuth"]);
    assert_eq!(fixture.json()[CLAUDE_LOGIN_KEY]["accessToken"], ROTATED);
}

#[test]
fn the_users_own_login_is_never_touched() {
    let mut with_marker = json!({ "claudeAiOauth": users_login(), "codewireManaged": 1 });
    with_marker["mcpOAuth"] = unrelated()["mcpOAuth"].clone();
    let mut almost = users_login();
    almost["refreshToken"] = json!("codewire-managed-no-refresh-token-short");
    let variants: Vec<Vec<u8>> = vec![
        serde_json::to_vec(&json!({ "claudeAiOauth": users_login() })).unwrap(),
        // After `claude /login` the marker may remain; the login is the user's.
        serde_json::to_vec(&with_marker).unwrap(),
        serde_json::to_vec(&json!({ "claudeAiOauth": almost, "codewireManaged": 1 })).unwrap(),
        // An empty refresh token without the marker is not Codewire's.
        serde_json::to_vec(
            &json!({ "claudeAiOauth": { "accessToken": "", "refreshToken": "", "expiresAt": 0 } }),
        )
        .unwrap(),
        serde_json::to_vec(&json!({ "claudeAiOauth": { "accessToken": "x" } })).unwrap(),
        serde_json::to_vec(&json!({ "claudeAiOauth": "not an object" })).unwrap(),
        serde_json::to_vec(&json!({ "claudeAiOauth": null, "codewireManaged": 1 })).unwrap(),
        b"not json".to_vec(),
        b"[]".to_vec(),
        b"{\"claudeAiOauth\": ".to_vec(),
    ];
    for users in variants {
        let fixture = Fixture::new();
        fixture.store_bytes(&users);
        let before = fixture.snapshot();
        let mut writer = fixture.writer();
        assert_eq!(
            writer.apply(first(), T0).unwrap(),
            ClaudeLoginSync::UserOwned,
            "{}",
            String::from_utf8_lossy(&users)
        );
        assert_eq!(fixture.snapshot(), before);
        // Neither a denial nor a lapse nor deselection removes it.
        assert_eq!(
            writer.apply(ClaudeLoginDelivery::Denied, T0).unwrap(),
            ClaudeLoginSync::Denied
        );
        assert_eq!(
            writer
                .apply(ClaudeLoginDelivery::Unavailable, T0 + 10 * 3_600)
                .unwrap(),
            ClaudeLoginSync::Unavailable
        );
        assert_eq!(
            ClaudeHome::new(fixture.home(), Path::new("/workspace"))
                .remove_codewire_login()
                .unwrap(),
            Removal::Kept
        );
        assert_eq!(fixture.snapshot(), before);
        assert_eq!(fixture.entries(), [CLAUDE_CREDENTIALS_FILE_NAME]);
    }
}

#[test]
fn symlinks_special_files_and_foreign_homes_are_never_followed() {
    // A symlinked store: its target is never read or written.
    let fixture = Fixture::new();
    fs::create_dir(fixture.config()).unwrap();
    let target = fixture.root.path().join("dotfiles-credentials.json");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, fixture.credentials()).unwrap();
    let mut writer = fixture.writer();
    assert_eq!(
        writer.apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );
    assert_eq!(
        writer.apply(ClaudeLoginDelivery::Denied, T0).unwrap(),
        ClaudeLoginSync::Denied
    );
    assert_eq!(fs::read(&target).unwrap(), b"{}");
    assert!(
        fs::symlink_metadata(fixture.credentials())
            .unwrap()
            .is_symlink()
    );

    // A dangling symlink is not created through.
    let dangling = Fixture::new();
    fs::create_dir(dangling.config()).unwrap();
    let missing = dangling.root.path().join("never-created.json");
    symlink(&missing, dangling.credentials()).unwrap();
    assert_eq!(
        dangling.writer().apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );
    assert!(fs::symlink_metadata(&missing).is_err());

    // A FIFO is never opened for reading content.
    let fifo = Fixture::new();
    fs::create_dir(fifo.config()).unwrap();
    let path = std::ffi::CString::new(fifo.credentials().as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert_eq!(
        fifo.writer().apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );

    // A symlinked `~/.claude` receives nothing.
    let linked = Fixture::new();
    let elsewhere = linked.root.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, linked.config()).unwrap();
    assert_eq!(
        linked.writer().apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);

    // A symlinked home receives nothing either.
    let home_link = Fixture::new();
    let real_home = home_link.root.path().join("real-home");
    fs::create_dir(&real_home).unwrap();
    fs::remove_dir(home_link.home()).unwrap();
    symlink(&real_home, home_link.home()).unwrap();
    assert_eq!(
        home_link.writer().apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );
    assert_eq!(fs::read_dir(&real_home).unwrap().count(), 0);

    // An oversized store is never read or replaced.
    let oversized = Fixture::new();
    oversized.store_bytes(b"{}");
    fs::File::options()
        .write(true)
        .open(oversized.credentials())
        .unwrap()
        .set_len(MAX_CREDENTIALS_BYTES + 1)
        .unwrap();
    assert_eq!(
        oversized.writer().apply(first(), T0).unwrap(),
        ClaudeLoginSync::UserOwned
    );
    assert_eq!(
        fs::metadata(oversized.credentials()).unwrap().len(),
        MAX_CREDENTIALS_BYTES + 1
    );
}

#[test]
fn logout_stays_logged_out_across_a_daemon_restart_until_a_new_container_or_generation() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    let mut writer = fixture.writer();
    writer.apply(first(), T0).unwrap();
    // `/logout` deletes `claudeAiOauth` and keeps every other member,
    // including the marker.
    let mut value = fixture.json();
    value.as_object_mut().unwrap().remove(CLAUDE_LOGIN_KEY);
    fixture.store(&value);
    let before = fixture.snapshot();
    for at in [T0 + 120, T0 + 240] {
        assert_eq!(
            writer
                .apply(delivery(CREDENTIAL, 2, ROTATED, EXPIRES), at)
                .unwrap(),
            ClaudeLoginSync::LoggedOut
        );
        assert_eq!(fixture.snapshot(), before);
    }
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
            .apply(delivery(CREDENTIAL, 3, ROTATED, EXPIRES), T0 + 360)
            .unwrap(),
        ClaudeLoginSync::LoggedOut
    );
    assert_eq!(fixture.snapshot(), before);
    // Another credential is not covered by that logout.
    assert_eq!(
        restarted
            .apply(delivery("cred-other-claude", 1, ROTATED, EXPIRES), T0 + 480)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    fixture.store(&value);

    // The sign-in re-selected is a new generation; a Sandbox restart is a new
    // container with an empty /tmp. Both write again.
    let mut reselected = fixture.writer_for(&fixture.state(), GENERATION + 1);
    assert_eq!(
        reselected
            .apply(delivery(CREDENTIAL, 3, ROTATED, EXPIRES), T0 + 600)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    fixture.store(&value);
    let mut new_container =
        fixture.writer_for(&fixture.root.path().join("new-container-tmp"), GENERATION);
    assert_eq!(
        new_container
            .apply(delivery(CREDENTIAL, 3, ROTATED, EXPIRES), T0 + 720)
            .unwrap(),
        ClaudeLoginSync::Written
    );
    assert_eq!(fixture.json()["mcpOAuth"], unrelated()["mcpOAuth"]);
}

#[test]
fn a_removed_store_after_codewires_write_is_a_logout_too() {
    let fixture = Fixture::new();
    fixture.writer().apply(first(), T0).unwrap();
    fs::remove_file(fixture.credentials()).unwrap();
    // Also after a daemon restart in the same container.
    assert_eq!(
        fixture.writer().apply(first(), T0 + 30).unwrap(),
        ClaudeLoginSync::LoggedOut
    );
    assert!(!fixture.credentials().exists());
}

#[test]
fn a_denial_removes_only_codewires_login_and_keeps_every_other_member() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    let mut writer = fixture.writer();
    writer.apply(first(), T0).unwrap();
    assert_eq!(
        writer.apply(ClaudeLoginDelivery::Denied, T0 + 60).unwrap(),
        ClaudeLoginSync::Denied
    );
    assert_eq!(fixture.json(), unrelated());
    assert_eq!(mode(&fixture.credentials()), 0o600);
    assert_eq!(fixture.entries(), [CLAUDE_CREDENTIALS_FILE_NAME]);
    // Codewire's own removal is not a logout: delivery writes again.
    assert_eq!(
        writer.apply(first(), T0 + 120).unwrap(),
        ClaudeLoginSync::Written
    );
    assert_eq!(fixture.json()["mcpOAuth"], unrelated()["mcpOAuth"]);

    // A store that held only Codewire's login is removed whole.
    let alone = Fixture::new();
    let mut writer = alone.writer();
    writer.apply(first(), T0).unwrap();
    assert_eq!(
        writer.apply(ClaudeLoginDelivery::Denied, T0 + 60).unwrap(),
        ClaudeLoginSync::Denied
    );
    assert!(!alone.credentials().exists());
    assert!(alone.entries().is_empty());
    assert_eq!(
        writer.apply(first(), T0 + 120).unwrap(),
        ClaudeLoginSync::Written
    );
}

#[test]
fn unavailable_and_unsupported_change_nothing_before_expiry_or_lapse() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer.apply(first(), T0).unwrap();
    let before = fixture.snapshot();
    for (answer, outcome) in [
        (
            ClaudeLoginDelivery::Unavailable,
            ClaudeLoginSync::Unavailable,
        ),
        (
            ClaudeLoginDelivery::Unsupported,
            ClaudeLoginSync::Unsupported,
        ),
    ] {
        assert_eq!(writer.apply(answer, T0 + 60).unwrap(), outcome);
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn an_expired_login_is_removed_while_the_bridge_fails() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    let mut writer = fixture.writer();
    let expires = (T0 + 100) * 1_000;
    writer
        .apply(delivery(CREDENTIAL, 1, ACCESS, expires), T0)
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        writer
            .apply(ClaudeLoginDelivery::Unavailable, T0 + 99)
            .unwrap(),
        ClaudeLoginSync::Unavailable
    );
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        writer
            .apply(ClaudeLoginDelivery::Unsupported, T0 + 100)
            .unwrap(),
        ClaudeLoginSync::Expired
    );
    assert_eq!(fixture.json(), unrelated());
    assert_eq!(
        writer.apply(first(), T0 + 200).unwrap(),
        ClaudeLoginSync::Written
    );
}

#[test]
fn a_login_lapses_after_ten_minutes_without_a_delivery() {
    assert_eq!(CLAUDE_LOGIN_LAPSE, Duration::from_secs(600));
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    let far = (T0 + 864_000) * 1_000;
    writer
        .apply(delivery(CREDENTIAL, 1, ACCESS, far), T0)
        .unwrap();
    // A delivery restarts the window; failures before it do not count.
    writer
        .apply(ClaudeLoginDelivery::Unavailable, T0 + 300)
        .unwrap();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, ACCESS, far), T0 + 400)
            .unwrap(),
        ClaudeLoginSync::Current
    );
    let before = fixture.snapshot();
    for (answer, at) in [
        (ClaudeLoginDelivery::Unavailable, T0 + 500),
        (ClaudeLoginDelivery::Unsupported, T0 + 800),
        (ClaudeLoginDelivery::Unavailable, T0 + 1_099),
    ] {
        assert_ne!(writer.apply(answer, at).unwrap(), ClaudeLoginSync::Lapsed);
        assert_eq!(fixture.snapshot(), before);
    }
    assert_eq!(
        writer
            .apply(ClaudeLoginDelivery::Unavailable, T0 + 1_100)
            .unwrap(),
        ClaudeLoginSync::Lapsed
    );
    assert!(!fixture.credentials().exists());
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 2, ROTATED, far), T0 + 1_200)
            .unwrap(),
        ClaudeLoginSync::Written
    );

    // A daemon that never receives a delivery removes a previous
    // container's login ten minutes after it starts.
    drop(writer);
    let mut never = fixture.writer_for(&fixture.root.path().join("new-container-tmp"), 9);
    assert_eq!(
        never
            .apply(ClaudeLoginDelivery::Unavailable, T0 + 599)
            .unwrap(),
        ClaudeLoginSync::Unavailable
    );
    assert!(fixture.credentials().exists());
    assert_eq!(
        never
            .apply(ClaudeLoginDelivery::Unavailable, T0 + 600)
            .unwrap(),
        ClaudeLoginSync::Lapsed
    );
    assert!(!fixture.credentials().exists());
}

#[test]
fn a_cleared_copy_is_codewires_and_is_rewritten_with_a_new_nonce() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    let mut writer = fixture.writer();
    writer.apply(first(), T0).unwrap();
    let nonce = fixture.refresh_token();
    // Claude Code's refresh with the placeholder was refused: it clears its
    // copy and keeps every other member, the marker included.
    let mut value = fixture.json();
    value[CLAUDE_LOGIN_KEY] = json!({
        "accessToken": "",
        "refreshToken": "",
        "expiresAt": 0,
        "scopes": ["user:inference", "user:profile"],
    });
    fixture.store(&value);
    assert_eq!(
        writer.apply(first(), T0 + 120).unwrap(),
        ClaudeLoginSync::Written
    );
    assert_eq!(fixture.json()[CLAUDE_LOGIN_KEY]["accessToken"], ACCESS);
    assert_ne!(fixture.refresh_token(), nonce);
    assert_eq!(fixture.json()["mcpOAuth"], unrelated()["mcpOAuth"]);

    // While the bridge fails, a cleared copy (expiry 0) is removed at once.
    fixture.store(&value);
    assert_eq!(
        writer
            .apply(ClaudeLoginDelivery::Unavailable, T0 + 240)
            .unwrap(),
        ClaudeLoginSync::Expired
    );
    assert_eq!(fixture.json(), unrelated());
}

#[test]
fn a_lower_material_generation_is_never_written_even_after_a_daemon_restart() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    writer
        .apply(delivery(CREDENTIAL, 5, ACCESS, EXPIRES), T0)
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 4, ROTATED, EXPIRES), T0)
            .unwrap(),
        ClaudeLoginSync::LowerGeneration
    );
    assert_eq!(fixture.snapshot(), before);
    drop(writer);
    assert_eq!(
        fixture
            .writer()
            .apply(delivery(CREDENTIAL, 4, ROTATED, EXPIRES), T0)
            .unwrap(),
        ClaudeLoginSync::LowerGeneration
    );
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn an_already_expired_delivery_is_never_written() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    assert_eq!(
        writer
            .apply(delivery(CREDENTIAL, 1, ACCESS, T0 * 1_000), T0)
            .unwrap(),
        ClaudeLoginSync::Invalid
    );
    assert!(!fixture.config().exists());
}

#[test]
fn a_store_changed_or_created_after_inspection_is_never_replaced() {
    let fixture = Fixture::new();
    fixture.writer().apply(first(), T0).unwrap();
    let config = open_config(&fixture.home(), false, None).unwrap().unwrap();
    let Credentials::Owned { entry, .. } = classify(&config, CLAUDE_CREDENTIALS_FILE_NAME).unwrap()
    else {
        panic!("Codewire's store expected");
    };
    // Claude Code rewrites in place: same inode, other content.
    let users = serde_json::to_vec(&json!({ "claudeAiOauth": users_login() })).unwrap();
    fs::write(fixture.credentials(), &users).unwrap();
    assert!(!replace(&config, &entry, b"{\"replacement\":true}").unwrap());
    assert_eq!(fs::read(fixture.credentials()).unwrap(), users);
    // A store created after an absent inspection stays as well.
    assert!(!install_new(&config, b"{\"replacement\":true}").unwrap());
    assert_eq!(fs::read(fixture.credentials()).unwrap(), users);
    assert_eq!(fixture.entries(), [CLAUDE_CREDENTIALS_FILE_NAME]);
}

#[test]
fn rename_aside_restores_a_concurrent_login_and_never_deletes_one() {
    let fixture = Fixture::new();
    fixture.writer().apply(first(), T0).unwrap();
    let config = open_config(&fixture.home(), false, None).unwrap().unwrap();
    let aside = ".credentials.json.codewire.synthetic.aside";
    let users = serde_json::to_vec(&json!({ "claudeAiOauth": users_login() })).unwrap();

    // The file moved aside turned out to be the user's: it goes back.
    fs::rename(fixture.credentials(), fixture.config().join(aside)).unwrap();
    fs::write(fixture.config().join(aside), &users).unwrap();
    assert_eq!(
        settle_aside(&config, aside, |_| true).unwrap(),
        Removal::Kept
    );
    assert_eq!(fs::read(fixture.credentials()).unwrap(), users);

    // And if yet another store appeared meanwhile, neither is lost.
    fs::write(fixture.config().join(aside), &users).unwrap();
    fs::write(fixture.credentials(), b"{\"newer\":true}").unwrap();
    assert_eq!(
        settle_aside(&config, aside, |_| true).unwrap(),
        Removal::Kept
    );
    assert_eq!(
        fs::read(fixture.credentials()).unwrap(),
        b"{\"newer\":true}"
    );
    assert_eq!(fs::read(fixture.config().join(aside)).unwrap(), users);
}

#[test]
fn deselection_removes_only_codewires_login() {
    let clients = |slots: &[&str]| {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    };
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    fixture.writer().apply(first(), T0).unwrap();
    let home = ClaudeHome::new(fixture.home(), Path::new("/workspace"));
    // Selected in its sign-in form: kept.
    home.prepare(clients(&["anthropic"]).with_anthropic_sign_in().unwrap());
    assert_eq!(fixture.json()[CLAUDE_LOGIN_KEY]["accessToken"], ACCESS);
    // Any other form, or not selected: Codewire's login goes, the rest stays.
    home.prepare(
        clients(&["anthropic"])
            .with_anthropic_subscription_token()
            .unwrap(),
    );
    assert_eq!(fixture.json(), unrelated());
    fixture
        .writer_for(&fixture.root.path().join("other-tmp"), 8)
        .apply(first(), T0)
        .unwrap();
    home.prepare(clients(&["codex"]));
    assert_eq!(fixture.json(), unrelated());
    // The user's own login is never removed.
    fixture.store(&json!({ "claudeAiOauth": users_login() }));
    home.prepare(clients(&[]));
    assert_eq!(fixture.json(), json!({ "claudeAiOauth": users_login() }));
    // An absent `~/.claude` is not created.
    let empty = Fixture::new();
    ClaudeHome::new(empty.home(), Path::new("/workspace")).prepare(clients(&[]));
    assert!(!empty.config().exists());
    assert_eq!(
        ClaudeHome::new(empty.home(), Path::new("/workspace")).credentials_path(),
        empty.credentials()
    );
}

#[test]
fn only_a_hosted_daemon_with_the_sign_in_form_runs_the_writer() {
    use crate::{Config, CredentialBridgeConfig, CredentialBridgeTransport, DaemonAuthToken};
    let config = |transport: Option<CredentialBridgeTransport>,
                  clients: ManagedCredentialClients| Config {
        host: None,
        listen_addr: "127.0.0.1:0".into(),
        workspace_root: "/workspace".into(),
        home_root: "/home/codewire".into(),
        mount_roots: Vec::new(),
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
        managed_credential_clients: clients,
        launch_projection: None,
        session_working_dir: None,
    };
    let anthropic = ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap();
    let sign_in = anthropic.with_anthropic_sign_in().unwrap();
    let owner = crate::private_files::FileOwner {
        uid: 1000,
        gid: 1000,
    };
    let writer = login_writer(
        &config(Some(CredentialBridgeTransport::Hosted), sign_in),
        None,
    )
    .unwrap();
    assert_eq!(writer.home, Path::new("/home/codewire"));
    assert_eq!(writer.owner, None);
    // A local VM's guest keeps the workload user's home on that user's behalf.
    let writer = login_writer(
        &config(Some(CredentialBridgeTransport::Local), sign_in),
        Some(owner),
    )
    .unwrap();
    assert_eq!(writer.home, Path::new("/home/codewire"));
    assert_eq!(writer.owner, Some(owner));
    for (transport, clients, owner) in [
        (Some(CredentialBridgeTransport::Hosted), anthropic, None),
        (
            Some(CredentialBridgeTransport::Hosted),
            anthropic.with_anthropic_subscription_token().unwrap(),
            None,
        ),
        (
            Some(CredentialBridgeTransport::Local),
            anthropic,
            Some(owner),
        ),
        // A local guest without its workload user, or a hosted daemon with one.
        (Some(CredentialBridgeTransport::Local), sign_in, None),
        (
            Some(CredentialBridgeTransport::Hosted),
            sign_in,
            Some(owner),
        ),
        (None, sign_in, None),
        (None, sign_in, Some(owner)),
    ] {
        assert!(login_writer(&config(transport, clients), owner).is_none());
    }
}

#[test]
fn checks_retry_soon_only_while_nothing_is_delivered() {
    for outcome in [
        ClaudeLoginSync::Unavailable,
        ClaudeLoginSync::Expired,
        ClaudeLoginSync::Lapsed,
    ] {
        assert!(outcome.retries_soon(), "{outcome:?}");
    }
    for outcome in [
        ClaudeLoginSync::Written,
        ClaudeLoginSync::Current,
        ClaudeLoginSync::UserOwned,
        ClaudeLoginSync::LoggedOut,
        ClaudeLoginSync::LowerGeneration,
        ClaudeLoginSync::Invalid,
        ClaudeLoginSync::Denied,
        ClaudeLoginSync::Unsupported,
    ] {
        assert!(!outcome.retries_soon(), "{outcome:?}");
    }
    assert_eq!(ClaudeLoginSync::FAILED, ClaudeLoginSync::Unavailable);
}

#[test]
fn placeholders_are_fresh_hex_nonces_after_the_prefix() {
    let one = placeholder();
    let two = placeholder();
    assert_ne!(one, two);
    for token in [&one, &two] {
        assert!(is_placeholder(token));
        assert_eq!(
            token.len(),
            CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.len() + NONCE_LENGTH
        );
    }
    for other in [
        "",
        "codewire-managed-no-refresh-token-",
        "codewire-managed-no-refresh-token",
        &format!("{one}0"),
        &one.to_uppercase(),
        "sk-ant-ort01-synthetic",
    ] {
        assert!(!is_placeholder(other), "{other}");
    }
}

/// A scripted bridge for the task loop: answers in order, then `fallback`.
struct Script {
    answers: Mutex<Vec<Result<OpenedClaudeLogin, LoginFailure>>>,
    fallback: LoginFailure,
    calls: std::sync::atomic::AtomicUsize,
}

impl ClaudeLoginSource for Arc<Script> {
    fn claude_login(&self) -> impl Future<Output = Result<OpenedClaudeLogin, LoginFailure>> + Send {
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

/// Every log line's message and field values, captured on this thread.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for Captured {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Fields(&mut line));
        self.0.lock().unwrap().push(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Waits for `condition`, checking every 10 ms. The deadline is a hang guard,
/// not a speed expectation (docs/dev/AGENT-WORKFLOW.md "Failure convergence");
/// a fixed 5 s ran out on a loaded runner (#4318).
async fn eventually(condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

#[test]
fn the_task_writes_at_start_logs_only_states_and_stops() {
    let fixture = Fixture::new();
    let captured = Captured::default();
    let _guard = tracing::subscriber::set_default(captured.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // Without the capability nothing is written.
        let script = Arc::new(Script {
            answers: Mutex::new(Vec::new()),
            fallback: LoginFailure::Unsupported,
            calls: Default::default(),
        });
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_claude_login_writer(
            fixture.writer(),
            script.clone(),
            crate::config::CODEX_LOGIN_CHECK_PERIOD,
            stopped,
        ));
        eventually(|| script.calls.load(std::sync::atomic::Ordering::SeqCst) == 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!fixture.config().exists());
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();

        // With it, the first check writes the login; a denial removes it.
        let script = Arc::new(Script {
            answers: Mutex::new(vec![
                Ok(opened(CREDENTIAL, 1, ACCESS, (unix_now() + 28_800) * 1_000)),
                Err(LoginFailure::Denied),
            ]),
            fallback: LoginFailure::Unavailable,
            calls: Default::default(),
        });
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_claude_login_writer(
            fixture.writer(),
            script.clone(),
            Duration::from_millis(50),
            stopped,
        ));
        eventually(|| fixture.credentials().exists()).await;
        eventually(|| !fixture.credentials().exists()).await;
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    });
    let lines = captured.0.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("claude_login=Written")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("claude_login=Denied")),
        "{lines:?}"
    );
    let home = fixture.home().to_string_lossy().into_owned();
    for line in &lines {
        for secret in [
            ACCESS,
            "codewire-managed-no-refresh-token-",
            home.as_str(),
            CREDENTIAL,
        ] {
            assert!(!line.contains(secret), "{line}");
        }
    }
}

/// A start removes what a crash or a revocation left beside the store: a
/// write in progress and a set-aside copy of Codewire's login. A set-aside
/// store of the user's own stays, and so does every other file.
#[test]
fn a_start_removes_leftover_temporaries_that_could_hold_a_token() {
    let fixture = Fixture::new();
    let mut writer = fixture.writer();
    assert_eq!(writer.apply(first(), T0).unwrap(), ClaudeLoginSync::Written);
    let delivered = fs::read(fixture.credentials()).unwrap();
    let sibling = |name: &str| fixture.config().join(name);
    let leftover_new = format!(".credentials.json.codewire.{}.new", "a".repeat(32));
    let leftover_aside = format!(".credentials.json.codewire.{}.aside", "b".repeat(32));
    let users_aside = format!(".credentials.json.codewire.{}.aside", "c".repeat(32));
    for (name, bytes) in [
        (&leftover_new, b"{\"partial".to_vec()),
        (&leftover_aside, delivered.clone()),
        (
            &users_aside,
            serde_json::to_vec(&json!({
                "claudeAiOauth": {"accessToken": "users-own", "refreshToken": "users-own-refresh"}
            }))
            .unwrap(),
        ),
        (&"unrelated.json".to_owned(), b"{}".to_vec()),
    ] {
        fs::write(sibling(name), bytes).unwrap();
        fs::set_permissions(sibling(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(fixture.writer().remove_leftovers().unwrap(), 2);
    assert!(!sibling(&leftover_new).exists());
    assert!(!sibling(&leftover_aside).exists());
    assert!(sibling(&users_aside).exists());
    assert!(sibling("unrelated.json").exists());
    // The store itself is untouched, and a second start finds nothing.
    assert_eq!(fs::read(fixture.credentials()).unwrap(), delivered);
    assert_eq!(fixture.writer().remove_leftovers().unwrap(), 0);
    // Without `~/.claude` there is nothing to remove.
    assert_eq!(Fixture::new().writer().remove_leftovers().unwrap(), 0);
}

/// A Codewire login that no writer keeps for this boot and owner is cleared
/// when the daemon starts, as a stopped or carried state disk may still hold
/// one. A login a writer keeps, every other member, and the user's own login
/// stay.
#[test]
fn a_login_no_writer_keeps_is_cleared_at_start() {
    let fixture = Fixture::new();
    fixture.store(&unrelated());
    fixture.writer().apply(first(), T0).unwrap();
    let home = ClaudeHome::new(fixture.home(), Path::new("/workspace"));
    let codex = crate::codex_home::CodexHome::at(fixture.root.path().join("codex-home"));
    crate::login_cleanup::clear_unkept_logins(&codex, &home, true, true);
    assert_eq!(fixture.json()[CLAUDE_LOGIN_KEY]["accessToken"], ACCESS);
    crate::login_cleanup::clear_unkept_logins(&codex, &home, true, false);
    assert_eq!(fixture.json(), unrelated());

    fixture.store(&users_login());
    crate::login_cleanup::clear_unkept_logins(&codex, &home, false, false);
    assert_eq!(fixture.json(), users_login());
}

#[test]
fn a_disk_reader_recognises_a_store_holding_codewires_login() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let codewire = json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-synthetic-delivered",
            "refreshToken": format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{nonce}"),
        },
        "codewireManaged": 1,
        "mcpOAuth": {},
    });
    let bytes = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    assert!(holds_codewire_login(&bytes(&codewire)));
    // The placeholder alone is Codewire's, as the daemon removes by.
    let mut unmarked = codewire.clone();
    unmarked.as_object_mut().unwrap().remove("codewireManaged");
    assert!(holds_codewire_login(&bytes(&unmarked)));
    // Claude Code's cleared copy beside the marker is Codewire's too.
    let mut cleared = codewire.clone();
    cleared["claudeAiOauth"]["refreshToken"] = json!("");
    assert!(holds_codewire_login(&bytes(&cleared)));
    let mut cleared_unmarked = cleared.clone();
    cleared_unmarked
        .as_object_mut()
        .unwrap()
        .remove("codewireManaged");
    let mut short = codewire.clone();
    short["claudeAiOauth"]["refreshToken"] =
        json!(format!("{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}short"));
    for other in [
        cleared_unmarked,
        short,
        json!({ "claudeAiOauth": users_login(), "codewireManaged": 1 }),
        json!({ "codewireManaged": 1 }),
        json!({ "claudeAiOauth": null, "codewireManaged": 1 }),
    ] {
        assert!(!holds_codewire_login(&bytes(&other)), "{other}");
    }
    assert!(!holds_codewire_login(b"[]"));

    // Leftovers: a write in progress is Codewire's unread; a set-aside file
    // only when it holds Codewire's login.
    let users = bytes(&json!({ "claudeAiOauth": users_login() }));
    assert!(is_codewire_leftover(
        ".credentials.json.codewire.0123.new",
        b"anything"
    ));
    assert!(is_codewire_leftover(
        ".credentials.json.codewire.0123.aside",
        &bytes(&cleared)
    ));
    assert!(!is_codewire_leftover(
        ".credentials.json.codewire.0123.aside",
        &users
    ));
    assert!(!is_codewire_leftover(".credentials.json", b"anything"));
    assert!(!is_codewire_leftover("other.new", b"anything"));
}
