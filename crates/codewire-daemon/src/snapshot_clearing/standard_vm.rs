//! Clearing a restored copy of a `standard` VM Sandbox's PVC before it is kept
//! as a snapshot (#5602, docs/dev/SECRETS-AND-CREDENTIALS.md "Hosted disk
//! snapshots").
//!
//! A `standard` Sandbox's PVC holds the VM's disk images under `runtime/vms/`,
//! not the guest's home tree directly. The guest's home and workspace live
//! inside the nested ext4 image `runtime/vms/<POD_VM_ID>/disks/state.raw`.
//! Clearing that image without mounting it follows the same four steps as
//! [`super::block::clear_block_volume`], punching free and tail blocks on the
//! regular image file (`FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`) so the
//! image's inode, length, permissions and ext4 UUID stay unchanged for the
//! forked VM's revalidation.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use codewire_ext4_scrub::files;
use codewire_ext4_scrub::{SystemTools, Tools, e2fsck, punch_unreadable_blocks};

use super::block::{BlockClearingError, clear_logins_at};
use super::{ClearingReport, LoginKind};

/// Relative path from the `standard` PVC root to the VM's persistent state disk
/// (`POD_VM_ID` in `crates/codewire-local-vmm/src/pod_runtime.rs`).
const STATE_DISK_COMPONENTS: [&str; 5] = [
    "runtime",
    "vms",
    "5ead0001-0000-4000-8000-000000000001",
    "disks",
    "state.raw",
];

/// Delivered login locations inside a `standard` VM's `state.raw` (`guest.rs`
/// mounts `state.raw` at `/state`, overlayfs home upper at `/state/home`, and
/// Codex home at `/state/agent-homes/codex`).
const STATE_DISK_LOGIN_DIRECTORIES: [(&[&str], LoginKind); 4] = [
    (&["agent-homes", "codex"], LoginKind::Codex),
    (&["home", ".codex"], LoginKind::Codex),
    (&["home", ".claude"], LoginKind::Claude),
    (
        &["home", ".gemini", "antigravity-cli"],
        LoginKind::Antigravity,
    ),
];

/// Environment-bound trees inside `state.raw` that a fork must never inherit.
const STATE_DISK_ENVIRONMENT_BOUND_TREES: [&[&str]; 4] = [
    &["home", ".codewire", "daemon", "sessions"],
    &[
        "home",
        ".local",
        "state",
        "codewire",
        "platform-managed-agents-v1",
    ],
    &["home", ".codewire", "tmp"],
    &["codewire", "cw-runtime"],
];

/// Host-side hibernate artifacts on a `standard` Sandbox's PVC that a product
/// snapshot or fork must never keep (`docs/dev/SANDBOX-SLEEP.md`, #6647):
/// - `runtime/vms/<POD_VM_ID>/checkpoints` holds the VMM memory image
///   (`memory-ranges`, `config.json`, `state.json`, and any staging tree).
/// - `runtime/hibernate` holds the sibling hibernate metadata record and
///   one-shot generation guard.
const STANDARD_VM_HOST_HIBERNATE_TREES: [&[&str]; 2] = [
    &[
        "runtime",
        "vms",
        "5ead0001-0000-4000-8000-000000000001",
        "checkpoints",
    ],
    &["runtime", "hibernate"],
];

/// Clear the nested ext4 `state.raw` image on a `standard` Sandbox's mounted
/// PVC at `root`, and remove any host-side hibernate memory image or metadata
/// record so a snapshot or fork always boots clean from disk (#6647). Any
/// missing state disk, symlink, or e2fsprogs error fails closed.
pub async fn clear_standard_vm_volume(root: &Path) -> Result<ClearingReport, BlockClearingError> {
    let state_disk = resolve_state_disk(root)?;
    let mut report = clear_state_disk(&SystemTools, &state_disk).await?;
    for components in STANDARD_VM_HOST_HIBERNATE_TREES {
        let removed = super::remove_tree(root, components).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                BlockClearingError::Undecided("standard VM hibernate path contains a symbolic link")
            } else {
                BlockClearingError::Wipe(codewire_ext4_scrub::Error::Io(error))
            }
        })?;
        if removed {
            report.trees_removed += 1;
        }
    }
    sync_path(&state_disk)?;
    if let Some(parent) = state_disk.parent() {
        sync_path(parent)?;
    }
    Ok(report)
}

fn resolve_state_disk(root: &Path) -> Result<PathBuf, BlockClearingError> {
    let mut path = root.to_path_buf();
    let (leaf, parents) = STATE_DISK_COMPONENTS
        .split_last()
        .expect("state disk has components");
    for component in parents {
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            BlockClearingError::Undecided("standard VM state disk directory is missing")
        })?;
        if metadata.is_symlink() {
            return Err(BlockClearingError::Undecided(
                "standard VM state disk path contains a symbolic link",
            ));
        }
        if !metadata.is_dir() {
            return Err(BlockClearingError::Undecided(
                "standard VM state disk path component is not a directory",
            ));
        }
    }
    path.push(leaf);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| BlockClearingError::Undecided("standard VM state disk is missing"))?;
    if metadata.is_symlink() {
        return Err(BlockClearingError::Undecided(
            "standard VM state disk is a symbolic link",
        ));
    }
    if !metadata.is_file() {
        return Err(BlockClearingError::Undecided(
            "standard VM state disk is not a regular file",
        ));
    }
    Ok(path)
}

async fn clear_state_disk(
    tools: &impl Tools,
    disk: &Path,
) -> Result<ClearingReport, BlockClearingError> {
    e2fsck(tools, disk)
        .await
        .map_err(BlockClearingError::Check)?;
    let block_size = files::block_size(tools, disk)
        .await
        .map_err(BlockClearingError::Files)?;
    let mut report = ClearingReport::default();
    for (directory, kind) in STATE_DISK_LOGIN_DIRECTORIES {
        report.logins_removed += clear_logins_at(tools, disk, directory, kind, block_size).await?;
    }
    for components in STATE_DISK_ENVIRONMENT_BOUND_TREES {
        if files::remove_tree(tools, disk, components)
            .await
            .map_err(BlockClearingError::Files)?
        {
            report.trees_removed += 1;
        }
    }
    e2fsck(tools, disk)
        .await
        .map_err(BlockClearingError::Check)?;
    punch_unreadable_blocks(tools, disk, block_size)
        .await
        .map_err(BlockClearingError::Wipe)?;
    Ok(report)
}

fn sync_path(path: &Path) -> Result<(), BlockClearingError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| BlockClearingError::Wipe(codewire_ext4_scrub::Error::Io(error)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::process::Command;

    use codewire_ext4_scrub::files::{self, Lookup};

    use super::*;

    const TOKEN: &str = "synthetic-standard-vm-clearing-token";

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

    fn antigravity_login() -> String {
        let marker = crate::delivered_logins::antigravity::ANTIGRAVITY_MANAGED_REFRESH_TOKEN;
        format!(
            r#"{{"auth_method":"consumer","token":{{"access_token":"{TOKEN}","refresh_token":"{marker}"}}}}"#
        )
    }

    fn tool(name: &str) -> PathBuf {
        ["/usr/sbin", "/usr/bin", "/sbin"]
            .iter()
            .map(|directory| Path::new(directory).join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("{name} for standard VM clearing tests"))
    }

    fn make_standard_pvc_with_state_disk(scratch: &Path) -> PathBuf {
        let disks_dir = scratch.join("runtime/vms/5ead0001-0000-4000-8000-000000000001/disks");
        fs::create_dir_all(&disks_dir).unwrap();
        let disk = disks_dir.join("state.raw");
        File::create(&disk)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        let status = Command::new(tool("mkfs.ext4"))
            .args(["-q", "-F", "-b", "4096", "-E", "nodiscard"])
            .arg(&disk)
            .env_clear()
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success());
        fs::set_permissions(&disk, fs::Permissions::from_mode(0o600)).unwrap();
        disk
    }

    fn debugfs_setup(disk: &Path, request: &str) {
        let output = Command::new(tool("debugfs"))
            .args(["-w", "-R", request])
            .arg(disk)
            .env_clear()
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(output.status.success(), "{request}: {:?}", output);
    }

    fn plant(disk: &Path, scratch: &Path, destination: &str, contents: &str) {
        let host = scratch.join("planted");
        fs::write(&host, contents).unwrap();
        debugfs_setup(
            disk,
            &format!("write {} {destination}", host.to_str().unwrap()),
        );
        fs::remove_file(host).unwrap();
    }

    fn holds_token(disk: &Path) -> bool {
        fs::read(disk)
            .unwrap()
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes())
    }

    #[tokio::test]
    async fn clears_delivered_logins_and_environment_trees_inside_standard_state_raw() {
        let scratch = tempfile::tempdir().unwrap();
        let pvc = scratch.path().join("pvc");
        fs::create_dir(&pvc).unwrap();
        let disk = make_standard_pvc_with_state_disk(&pvc);

        for dir in [
            "agent-homes",
            "agent-homes/codex",
            "home",
            "home/.codex",
            "home/.claude",
            "home/.gemini",
            "home/.gemini/antigravity-cli",
            "home/.codewire",
            "home/.codewire/daemon",
            "home/.codewire/daemon/sessions",
            "home/.codewire/tmp",
            "home/.local",
            "home/.local/state",
            "home/.local/state/codewire",
            "home/.local/state/codewire/platform-managed-agents-v1",
            "codewire",
            "codewire/cw-runtime",
        ] {
            debugfs_setup(&disk, &format!("mkdir {dir}"));
        }

        plant(
            &disk,
            scratch.path(),
            "agent-homes/codex/auth.json",
            &codex_login(),
        );
        plant(
            &disk,
            scratch.path(),
            "home/.codex/auth.json",
            &codex_login(),
        );
        plant(
            &disk,
            scratch.path(),
            "home/.claude/.credentials.json",
            &claude_login(),
        );
        plant(
            &disk,
            scratch.path(),
            "home/.gemini/antigravity-cli/antigravity-oauth-token",
            &antigravity_login(),
        );
        plant(
            &disk,
            scratch.path(),
            "home/.codewire/daemon/sessions/s1.log",
            "session-data",
        );
        plant(
            &disk,
            scratch.path(),
            "home/.local/state/codewire/platform-managed-agents-v1/book",
            "agent-book",
        );
        plant(
            &disk,
            scratch.path(),
            "home/.codewire/tmp/scratch",
            "tmp-data",
        );
        plant(
            &disk,
            scratch.path(),
            "codewire/cw-runtime/selected",
            "env-1",
        );
        plant(&disk, scratch.path(), "home/keep.txt", "user-work-kept");

        assert!(holds_token(&disk));
        let before = fs::metadata(&disk).unwrap();

        let report = clear_standard_vm_volume(&pvc).await.unwrap();
        assert_eq!(report.logins_removed, 4);
        assert_eq!(report.trees_removed, 4);
        assert!(
            !holds_token(&disk),
            "token bytes must not remain anywhere in state.raw after clearing and punching"
        );

        let kept = files::read_file(&SystemTools, &disk, &["home"], "keep.txt")
            .await
            .unwrap();
        assert_eq!(kept, b"user-work-kept");
        assert!(matches!(
            files::lookup_directory(&SystemTools, &disk, &["codewire", "cw-runtime"])
                .await
                .unwrap(),
            Lookup::Absent
        ));

        let after = fs::metadata(&disk).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_eq!(before.mode(), after.mode());
    }

    #[tokio::test]
    async fn refuses_missing_or_symlinked_standard_state_disk() {
        let scratch = tempfile::tempdir().unwrap();
        let empty = scratch.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(matches!(
            clear_standard_vm_volume(&empty).await,
            Err(BlockClearingError::Undecided(_))
        ));

        let linked = scratch.path().join("linked");
        let disks_dir = linked.join("runtime/vms/5ead0001-0000-4000-8000-000000000001/disks");
        fs::create_dir_all(&disks_dir).unwrap();
        let real = scratch.path().join("elsewhere.raw");
        fs::write(&real, b"not-in-pvc").unwrap();
        symlink(&real, disks_dir.join("state.raw")).unwrap();
        assert!(matches!(
            clear_standard_vm_volume(&linked).await,
            Err(BlockClearingError::Undecided(_))
        ));
    }

    /// `docs/dev/SANDBOX-SLEEP.md` (#6647): product snapshots and forks never
    /// keep a hibernate memory file or metadata record, and symlinks planted on
    /// those paths fail closed without touching their target.
    #[tokio::test]
    async fn removes_hibernate_memory_files_and_refuses_symlinks() {
        let scratch = tempfile::tempdir().unwrap();
        let pvc = scratch.path().join("pvc");
        fs::create_dir(&pvc).unwrap();
        let _disk = make_standard_pvc_with_state_disk(&pvc);

        // Plant sealed (0400) VMM memory files and sibling hibernate metadata.
        let ckpt_in = pvc.join("runtime/vms/5ead0001-0000-4000-8000-000000000001/checkpoints/in");
        fs::create_dir_all(&ckpt_in).unwrap();
        for name in ["config.json", "state.json", "memory-ranges"] {
            let path = ckpt_in.join(name);
            fs::write(&path, b"hibernated-ram-and-state").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        let hib_dir = pvc.join("runtime/hibernate");
        fs::create_dir_all(&hib_dir).unwrap();
        fs::write(hib_dir.join("record.json"), b"{\"generation\":2}").unwrap();
        fs::write(hib_dir.join("generation"), b"2\n").unwrap();

        let report = clear_standard_vm_volume(&pvc).await.unwrap();
        assert_eq!(report.trees_removed, 2);
        assert!(
            !pvc.join("runtime/vms/5ead0001-0000-4000-8000-000000000001/checkpoints")
                .exists()
        );
        assert!(!hib_dir.exists());

        // A symlink at checkpoints or hibernate fails closed and never touches its target.
        let outside = scratch.path().join("outside-keep");
        fs::create_dir(&outside).unwrap();
        let victim = outside.join("keep.txt");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&outside, &hib_dir).unwrap();
        assert!(matches!(
            clear_standard_vm_volume(&pvc).await,
            Err(BlockClearingError::Undecided(_))
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    }
}
