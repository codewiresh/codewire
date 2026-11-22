use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::claude_home::CLAUDE_CONFIG_DIR_NAME;

const WORKSPACE: &str = "/cw-test-workspace-absent";

fn home() -> (tempfile::TempDir, ClaudeHome) {
    let root = tempfile::tempdir().unwrap();
    let home = ClaudeHome::new(root.path().join("codewire"), Path::new(WORKSPACE));
    fs::create_dir(home.root()).unwrap();
    (root, home)
}

fn settings_path(home: &ClaudeHome) -> PathBuf {
    home.root()
        .join(CLAUDE_CONFIG_DIR_NAME)
        .join(CLAUDE_SETTINGS_FILE_NAME)
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// What a new file holds.
fn fresh() -> Value {
    json!({
        "skipDangerousModePermissionPrompt": true,
        "enableAllProjectMcpServers": true,
        "permissions": { "defaultMode": "bypassPermissions" }
    })
}

/// Every name in `~/.claude` but `settings.json`, so a test can prove no
/// temporary file remains.
fn others(home: &ClaudeHome) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(home.root().join(CLAUDE_CONFIG_DIR_NAME))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != CLAUDE_SETTINGS_FILE_NAME)
        .collect();
    names.sort();
    names
}

#[test]
fn a_missing_file_and_directory_get_exactly_the_settings() {
    let (_root, home) = home();
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::Created);
    let path = settings_path(&home);
    assert_eq!(read(&path), fresh());
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    assert!(others(&home).is_empty());

    let inode = fs::metadata(&path).unwrap().ino();
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::Current);
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
}

#[test]
fn the_users_values_win_and_every_other_member_is_kept() {
    let (_root, home) = home();
    let path = settings_path(&home);
    fs::create_dir(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{"permissions":{"defaultMode":"default","deny":["Bash(rm:*)"],"disableBypassPermissionsMode":"disable"},"enableAllProjectMcpServers":false,"theme":"dark"}"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::Marked);
    assert_eq!(
        read(&path),
        json!({
            "permissions": {
                "defaultMode": "default",
                "deny": ["Bash(rm:*)"],
                "disableBypassPermissionsMode": "disable"
            },
            "enableAllProjectMcpServers": false,
            "theme": "dark",
            "skipDangerousModePermissionPrompt": true
        })
    );
    // Its own mode, narrowed to at most 0600.
    assert_eq!(mode(&path), 0o600);
    assert!(others(&home).is_empty());
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::Current);
}

#[test]
fn a_permissions_object_without_a_mode_gets_bypass() {
    let (_root, home) = home();
    let path = settings_path(&home);
    fs::create_dir(path.parent().unwrap()).unwrap();
    fs::write(&path, r#"{"permissions":{"allow":["Bash(git:*)"]}}"#).unwrap();
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::Marked);
    assert_eq!(
        read(&path)["permissions"],
        json!({ "allow": ["Bash(git:*)"], "defaultMode": "bypassPermissions" })
    );
}

#[test]
fn anything_but_a_users_json_object_is_left_alone() {
    for contents in [
        "not json",
        "[1, 2]",
        r#"{"permissions":"bypassPermissions"}"#,
        r#"{"permissions":null}"#,
    ] {
        let (_root, home) = home();
        let path = settings_path(&home);
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        assert_eq!(
            home.sync_settings().unwrap(),
            ClaudeSettingsSync::UserOwned,
            "{contents}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        assert!(others(&home).is_empty());
    }
}

#[test]
fn a_symlink_is_never_followed() {
    // A symlinked settings file.
    let (root, home) = home();
    let path = settings_path(&home);
    fs::create_dir(path.parent().unwrap()).unwrap();
    let target = root.path().join("elsewhere.json");
    fs::write(&target, "{}").unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::UserOwned);
    assert_eq!(fs::read_to_string(&target).unwrap(), "{}");

    // A symlinked `~/.claude`.
    let (root, home) = self::home();
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, home.root().join(CLAUDE_CONFIG_DIR_NAME)).unwrap();
    assert_eq!(home.sync_settings().unwrap(), ClaudeSettingsSync::UserOwned);
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn nothing_written_names_a_credential() {
    let (_root, home) = home();
    home.sync_settings().unwrap();
    let written = fs::read_to_string(settings_path(&home)).unwrap();
    for word in ["token", "codewire-managed", "apiKey", "Authorization"] {
        assert!(!written.contains(word), "{word}");
    }
}
