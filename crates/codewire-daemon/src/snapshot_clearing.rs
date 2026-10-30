//! Clearing a restored copy of a hosted workspace volume before it is kept as a
//! snapshot (docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted disk snapshots").
//!
//! This runs as the only process of a clearing Sandbox, which has no network and
//! no credentials, never in a workspace. It differs from the daemon's own login
//! removal on purpose ([`crate::login_cleanup`] keeps a store's other members,
//! unlinks without zeroing, and answers "absent" for a home it may not open):
//! here every recognised token file is zeroed on disk first, a recognised store
//! goes whole, and any failure is an error, so a volume that could not be cleared
//! is never kept. Which files are Codewire's has one definition, the daemon's.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use crate::{claude_home, codex_home};

/// More than any login Codewire writes, so a larger file is not Codewire's.
const MAX_LOGIN_BYTES: u64 = 1024 * 1024;

/// Trees bound to the source environment that a new environment must not hold:
/// its sessions, with their command lines and output, and its managed agents'
/// books, which are keyed by the source's environment and Pod.
const ENVIRONMENT_BOUND_TREES: [&[&str]; 2] = [
    &[".codewire", "daemon", "sessions"],
    &[".local", "state", "codewire", "platform-managed-agents-v1"],
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClearingReport {
    pub logins_removed: usize,
    pub trees_removed: usize,
}

#[derive(Clone, Copy)]
enum LoginKind {
    Codex,
    Claude,
}

impl LoginKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Codex => ".codex",
            Self::Claude => ".claude",
        }
    }

    fn is_login_name(self, name: &str) -> bool {
        match self {
            Self::Codex => {
                name == codex_home::CODEX_AUTH_FILE_NAME || codex_home::is_codewire_temporary(name)
            }
            Self::Claude => {
                name == claude_home::CLAUDE_CREDENTIALS_FILE_NAME
                    || claude_home::is_codewire_temporary(name)
            }
        }
    }

    /// A write in progress is Codewire's whatever it holds, so it is not read.
    fn is_write_in_progress(self, name: &str) -> bool {
        match self {
            Self::Codex => codex_home::is_codewire_write_in_progress(name),
            Self::Claude => claude_home::is_codewire_write_in_progress(name),
        }
    }

    fn is_codewire(self, name: &str, contents: &[u8]) -> bool {
        match self {
            Self::Codex if name == codex_home::CODEX_AUTH_FILE_NAME => {
                codex_home::is_codewire_auth_file(contents)
            }
            Self::Codex => codex_home::is_codewire_leftover(name, contents),
            Self::Claude if name == claude_home::CLAUDE_CREDENTIALS_FILE_NAME => {
                claude_home::holds_codewire_login(contents)
            }
            Self::Claude => claude_home::is_codewire_leftover(name, contents),
        }
    }
}

/// Clear the volume mounted at `root`: its home and `/workspace` are one tree.
pub fn clear_workspace_volume(root: &Path) -> io::Result<ClearingReport> {
    let mut report = ClearingReport::default();
    for kind in [LoginKind::Codex, LoginKind::Claude] {
        report.logins_removed += clear_logins(&root.join(kind.directory()), kind)?;
    }
    for components in ENVIRONMENT_BOUND_TREES {
        if remove_tree(root, components)? {
            report.trees_removed += 1;
        }
    }
    sync_directory(root)?;
    Ok(report)
}

fn undecided(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Zero and remove Codewire's files in one agent's home. A symlink, here or at a
/// login's name, or a login too large to read fails the capture: the daemon
/// delivers through neither, but clearing can't show that none is there, and a
/// volume that can't be cleared isn't kept.
fn clear_logins(directory: &Path, kind: LoginKind) -> io::Result<usize> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(metadata) if metadata.is_symlink() => {
            return Err(undecided("an agent's home is a symbolic link"));
        }
        Ok(_) => return Ok(0),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    }
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !kind.is_login_name(&name) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(undecided("an agent's login is a symbolic link"));
        }
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        let codewire = kind.is_write_in_progress(&name) || {
            let contents = read_bounded(&path)?
                .ok_or_else(|| undecided("an agent's login is too large to read"))?;
            kind.is_codewire(&name, &contents)
        };
        if codewire {
            zero_and_remove(&path)?;
            removed += 1;
        }
    }
    if removed > 0 {
        sync_directory(directory)?;
    }
    Ok(removed)
}

fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// The file's contents, or `None` when it is too large to be a login.
fn read_bounded(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = open_no_follow(path, false)?;
    let mut contents = Vec::new();
    file.take(MAX_LOGIN_BYTES + 1).read_to_end(&mut contents)?;
    Ok((contents.len() as u64 <= MAX_LOGIN_BYTES).then_some(contents))
}

/// Overwrite the file's blocks with zeros, flush them, then unlink it, so the
/// token isn't left whole in a block the unlink frees. An unlink alone leaves it
/// readable in a snapshot of the disk (measured on Dev, 2026-10-30).
fn zero_and_remove(path: &Path) -> io::Result<()> {
    let mut file = open_no_follow(path, true)?;
    let zeros = [0u8; 64 * 1024];
    let mut remaining = file.metadata()?.len();
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)
}

/// Remove the tree at `components` below `root`, without following a symlink at
/// any level. `remove_dir_all` itself does not follow one.
fn remove_tree(root: &Path, components: &[&str]) -> io::Result<bool> {
    let mut path = root.to_path_buf();
    let (last, parents) = components.split_last().expect("a tree has a path");
    for component in parents {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(metadata) if metadata.is_symlink() => {
                return Err(undecided("a cleared path is a symbolic link"));
            }
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    let parent = path.clone();
    path.push(last);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_symlink() => {
            return Err(undecided("a cleared path is a symbolic link"));
        }
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path)?,
        Ok(_) => fs::remove_file(&path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    sync_directory(&parent)?;
    Ok(true)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use tempfile::TempDir;

    use super::*;

    const TOKEN: &str = "synthetic-snapshot-clearing-token";

    fn codex_login() -> String {
        format!(
            r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{TOKEN}","refresh_token":"codewire-managed-no-refresh-token"}}}}"#
        )
    }

    fn claude_login() -> String {
        let nonce = "0123456789abcdef0123456789abcdef";
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{TOKEN}","refreshToken":"codewire-managed-no-refresh-token-{nonce}"}},"mcpOAuth":{{"kept":"no"}}}}"#
        )
    }

    fn volume() -> TempDir {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join(".codex")).unwrap();
        fs::create_dir_all(root.path().join(".claude")).unwrap();
        root
    }

    #[test]
    fn it_removes_codewire_logins_their_temporaries_and_a_claude_store_whole() {
        let root = volume();
        let codex = root.path().join(".codex");
        let claude = root.path().join(".claude");
        fs::write(codex.join("auth.json"), codex_login()).unwrap();
        fs::write(codex.join(".auth.json.codewire.1.aside"), codex_login()).unwrap();
        fs::write(codex.join(".auth.json.codewire.2.new"), "partial").unwrap();
        fs::write(claude.join(".credentials.json"), claude_login()).unwrap();
        fs::write(
            claude.join(".credentials.json.codewire.3.aside"),
            claude_login(),
        )
        .unwrap();
        fs::write(claude.join(".credentials.json.codewire.4.new"), "partial").unwrap();

        let report = clear_workspace_volume(root.path()).unwrap();

        assert_eq!(report.logins_removed, 6);
        assert_eq!(fs::read_dir(&codex).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&claude).unwrap().count(), 0);
    }

    #[test]
    fn it_keeps_the_users_own_logins_and_everything_else() {
        let root = volume();
        let codex = root.path().join(".codex");
        let claude = root.path().join(".claude");
        let users_codex = r#"{"auth_mode":"chatgpt","tokens":{"refresh_token":"users-own"}}"#;
        let users_claude = r#"{"claudeAiOauth":{"refreshToken":"sk-ant-ort01-users-own"}}"#;
        fs::write(codex.join("auth.json"), users_codex).unwrap();
        fs::write(codex.join(".auth.json.codewire.1.aside"), users_codex).unwrap();
        fs::write(codex.join("config.toml"), "kept").unwrap();
        fs::write(claude.join(".credentials.json"), users_claude).unwrap();
        fs::write(root.path().join(".env"), "KEPT=1").unwrap();
        fs::create_dir_all(root.path().join(".codewire")).unwrap();
        fs::write(root.path().join(".codewire/environment.json"), "{}").unwrap();

        let report = clear_workspace_volume(root.path()).unwrap();

        assert_eq!(report, ClearingReport::default());
        assert_eq!(
            fs::read_to_string(codex.join("auth.json")).unwrap(),
            users_codex
        );
        assert!(codex.join(".auth.json.codewire.1.aside").exists());
        assert!(codex.join("config.toml").exists());
        assert_eq!(
            fs::read_to_string(claude.join(".credentials.json")).unwrap(),
            users_claude
        );
        assert!(root.path().join(".env").exists());
        assert!(root.path().join(".codewire/environment.json").exists());
    }

    #[test]
    fn zeroing_overwrites_the_file_before_the_unlink() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("login");
        fs::write(&path, codex_login()).unwrap();
        // A second name for the same inode shows what the first name's blocks
        // hold once it is gone.
        let witness = root.path().join("witness");
        fs::hard_link(&path, &witness).unwrap();

        zero_and_remove(&path).unwrap();

        assert!(!path.exists());
        let held = fs::read(&witness).unwrap();
        assert_eq!(held.len(), codex_login().len());
        assert!(held.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn it_removes_the_environment_bound_trees_and_is_idempotent() {
        let root = volume();
        let sessions = root.path().join(".codewire/daemon/sessions/one");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("output.bin"), "output").unwrap();
        let books = root
            .path()
            .join(".local/state/codewire/platform-managed-agents-v1/env");
        fs::create_dir_all(&books).unwrap();
        fs::write(books.join("requests"), "books").unwrap();

        let first = clear_workspace_volume(root.path()).unwrap();
        let second = clear_workspace_volume(root.path()).unwrap();

        assert_eq!(first.trees_removed, 2);
        assert_eq!(second, ClearingReport::default());
        assert!(!root.path().join(".codewire/daemon/sessions").exists());
        assert!(root.path().join(".codewire/daemon").exists());
    }

    fn assert_refused_and_untouched(root: &TempDir, elsewhere: &TempDir) {
        let error = clear_workspace_volume(root.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("auth.json")).unwrap(),
            codex_login()
        );
    }

    fn elsewhere() -> TempDir {
        let elsewhere = TempDir::new().unwrap();
        fs::write(elsewhere.path().join("auth.json"), codex_login()).unwrap();
        elsewhere
    }

    #[test]
    fn a_symlinked_home_fails_the_capture_and_is_not_followed() {
        let root = TempDir::new().unwrap();
        let elsewhere = elsewhere();
        symlink(elsewhere.path(), root.path().join(".codex")).unwrap();
        assert_refused_and_untouched(&root, &elsewhere);
    }

    #[test]
    fn a_symlinked_login_fails_the_capture_and_is_not_followed() {
        let root = volume();
        let elsewhere = elsewhere();
        symlink(
            elsewhere.path().join("auth.json"),
            root.path().join(".codex/auth.json"),
        )
        .unwrap();
        assert_refused_and_untouched(&root, &elsewhere);
    }

    #[test]
    fn a_symlinked_tree_or_its_parent_fails_the_capture_and_is_not_followed() {
        let elsewhere = elsewhere();
        fs::create_dir_all(elsewhere.path().join("daemon/sessions")).unwrap();

        let parent = volume();
        symlink(elsewhere.path(), parent.path().join(".codewire")).unwrap();
        assert_refused_and_untouched(&parent, &elsewhere);

        let tree = volume();
        fs::create_dir_all(tree.path().join(".codewire/daemon")).unwrap();
        symlink(
            elsewhere.path().join("daemon/sessions"),
            tree.path().join(".codewire/daemon/sessions"),
        )
        .unwrap();
        assert_refused_and_untouched(&tree, &elsewhere);
        assert!(elsewhere.path().join("daemon/sessions").exists());
    }

    #[test]
    fn a_login_too_large_to_read_fails_the_capture() {
        let root = volume();
        let path = root.path().join(".codex/auth.json");
        let padding = " ".repeat(MAX_LOGIN_BYTES as usize);
        fs::write(&path, format!("{}{padding}", codex_login())).unwrap();

        let error = clear_workspace_volume(root.path()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(path.exists());
    }

    /// The failure a silent "absent" would hide: an unreadable login stops the
    /// capture. Root reads anything, so this proves nothing as root.
    #[test]
    fn a_login_it_cannot_read_is_an_error_never_success() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = volume();
        let path = root.path().join(".codex/auth.json");
        fs::write(&path, codex_login()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let error = clear_workspace_volume(root.path()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
