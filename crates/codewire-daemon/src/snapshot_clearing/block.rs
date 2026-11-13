//! Clearing a restore that is a Block volume (#3718). Its fork's guest formats
//! and reads the disk block by block, so besides the files every block the
//! guest cannot read through the filesystem is wiped. This runs as the only
//! process of a clearing Sandbox, a VM with no network, so the host never
//! parses the guest's filesystem.
//!
//! It never mounts the disk, so the clearing container needs no `SYS_ADMIN`
//! (#4013):
//!
//! 1. a settling `e2fsck -f -p`, which replays the journal and refuses a
//!    filesystem it cannot fix without asking;
//! 2. through debugfs ([`codewire_ext4_scrub::files`]), zero and remove the
//!    files a Filesystem restore's clearing removes, by the same rules
//!    ([`super::clear_workspace_volume`]), proving each gone;
//! 3. settle it again, so the block bitmaps are exact;
//! 4. wipe every free range and each file's unwritten extents and blocks past
//!    its end ([`codewire_ext4_scrub::wipe_unreadable_blocks`]).
//!
//! Any failure is an error, never retried with `e2fsck -y`, so a volume that
//! could not be cleared is never kept.

use std::os::unix::fs::FileTypeExt as _;
use std::path::Path;

use codewire_ext4_scrub::files::{self, EntryKind, Lookup};
use codewire_ext4_scrub::{SystemTools, Tools, WipeReport, e2fsck, wipe_unreadable_blocks};

use super::{ClearingReport, ENVIRONMENT_BOUND_TREES, LoginKind, MAX_LOGIN_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockClearingReport {
    pub files: ClearingReport,
    pub wipe: WipeReport,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockClearingError {
    #[error("the restore is not a block device")]
    NotBlockDevice,
    #[error("the volume's filesystem could not be settled: {0}")]
    Check(codewire_ext4_scrub::Error),
    #[error("the volume's delivered sign-ins could not be cleared: {0}")]
    Files(codewire_ext4_scrub::Error),
    #[error("the volume's delivered sign-ins could not be cleared: {0}")]
    Undecided(&'static str),
    #[error("the volume's free blocks could not be wiped: {0}")]
    Wipe(codewire_ext4_scrub::Error),
}

/// Clear the ext4 filesystem on the block device `device`.
pub async fn clear_block_volume(device: &Path) -> Result<BlockClearingReport, BlockClearingError> {
    let is_block_device = std::fs::metadata(device)
        .map_err(|_| BlockClearingError::NotBlockDevice)?
        .file_type()
        .is_block_device();
    if !is_block_device {
        return Err(BlockClearingError::NotBlockDevice);
    }
    let files = clear_files(&SystemTools, device).await?;
    let wipe = wipe_unreadable_blocks(&SystemTools, device)
        .await
        .map_err(BlockClearingError::Wipe)?;
    Ok(BlockClearingReport { files, wipe })
}

/// Steps 1 to 3 on the ext4 filesystem on `disk`.
async fn clear_files(
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
    for kind in [LoginKind::Codex, LoginKind::Claude] {
        report.logins_removed += clear_logins(tools, disk, kind, block_size).await?;
    }
    for components in ENVIRONMENT_BOUND_TREES {
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
    Ok(report)
}

/// Zero and remove Codewire's files in one agent's home, by the rules
/// [`super::clear_workspace_volume`] applies to a mounted volume: a symlink,
/// here or at a login's name, or a login too large to read fails the capture.
async fn clear_logins(
    tools: &impl Tools,
    disk: &Path,
    kind: LoginKind,
    block_size: u64,
) -> Result<usize, BlockClearingError> {
    let directory = [kind.directory()];
    let entries = match files::lookup_directory(tools, disk, &directory)
        .await
        .map_err(BlockClearingError::Files)?
    {
        Lookup::Directory(entries) => entries,
        Lookup::NotDirectory(EntryKind::SymbolicLink) => {
            return Err(BlockClearingError::Undecided(
                "an agent's home is a symbolic link",
            ));
        }
        Lookup::Absent | Lookup::NotDirectory(_) => return Ok(0),
    };
    let mut removed = 0;
    for entry in entries {
        let Some(name) = entry.name.as_deref() else {
            continue;
        };
        if !kind.is_login_name(name) {
            continue;
        }
        if entry.kind == EntryKind::SymbolicLink {
            return Err(BlockClearingError::Undecided(
                "an agent's login is a symbolic link",
            ));
        }
        if entry.kind != EntryKind::File {
            continue;
        }
        let codewire = kind.is_write_in_progress(name) || {
            if entry.size > MAX_LOGIN_BYTES {
                return Err(BlockClearingError::Undecided(
                    "an agent's login is too large to read",
                ));
            }
            let contents = files::read_file(tools, disk, &directory, name)
                .await
                .map_err(BlockClearingError::Files)?;
            kind.is_codewire(name, &contents)
        };
        if codewire {
            files::zero_and_remove(tools, disk, &directory, name, entry.size, block_size)
                .await
                .map_err(BlockClearingError::Files)?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    const TOKEN: &str = "synthetic-block-clearing-token";

    fn codex_login() -> String {
        format!(
            r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{TOKEN}","refresh_token":"codewire-managed-no-refresh-token"}}}}"#
        )
    }

    fn tool(name: &str) -> PathBuf {
        ["/usr/sbin", "/usr/bin", "/sbin"]
            .iter()
            .map(|directory| Path::new(directory).join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("{name} for block clearing tests"))
    }

    /// An ext4 image holding a home, as a Block workspace's volume does.
    fn volume(scratch: &Path) -> PathBuf {
        let disk = scratch.join("disk.img");
        std::fs::File::create(&disk)
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
        assert!(output.status.success());
    }

    fn plant(disk: &Path, scratch: &Path, destination: &str, contents: &str) {
        let host = scratch.join("planted");
        std::fs::write(&host, contents).unwrap();
        debugfs_setup(
            disk,
            &format!("write {} {destination}", host.to_str().unwrap()),
        );
        std::fs::remove_file(host).unwrap();
    }

    fn holds_token(disk: &Path) -> bool {
        std::fs::read(disk)
            .unwrap()
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes())
    }

    async fn names(disk: &Path, components: &[&str]) -> Vec<String> {
        match files::lookup_directory(&SystemTools, disk, components)
            .await
            .unwrap()
        {
            Lookup::Directory(entries) => {
                let mut names = entries
                    .into_iter()
                    .filter_map(|entry| entry.name)
                    .collect::<Vec<_>>();
                names.sort();
                names
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn anything_but_a_block_device_is_refused_before_any_tool_runs() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("disk.raw");
        std::fs::write(&image, [0_u8; 4096]).unwrap();

        for device in [
            image.as_path(),
            &scratch.path().join("missing"),
            scratch.path(),
        ] {
            let error = clear_block_volume(device).await.unwrap_err();
            assert!(
                matches!(error, BlockClearingError::NotBlockDevice),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn the_unmounted_volume_loses_codewires_logins_and_bound_trees_only() {
        let scratch = tempfile::tempdir().unwrap();
        let disk = volume(scratch.path());
        for directory in [
            "/.codex",
            "/.claude",
            "/.codewire",
            "/.codewire/daemon",
            "/.codewire/daemon/sessions",
            "/.codewire/tmp",
        ] {
            debugfs_setup(&disk, &format!("mkdir {directory}"));
        }
        plant(&disk, scratch.path(), "/.codex/auth.json", &codex_login());
        plant(
            &disk,
            scratch.path(),
            "/.codex/.auth.json.codewire.2.new",
            "partial",
        );
        plant(&disk, scratch.path(), "/.codex/config.toml", "kept");
        plant(
            &disk,
            scratch.path(),
            "/.claude/.credentials.json",
            r#"{"own":"login"}"#,
        );
        plant(
            &disk,
            scratch.path(),
            "/.codewire/daemon/sessions/1",
            "session",
        );
        plant(&disk, scratch.path(), "/.codewire/tmp/scratch", "scratch");
        assert!(holds_token(&disk));

        let report = clear_files(&SystemTools, &disk).await.unwrap();

        assert_eq!(
            report,
            ClearingReport {
                logins_removed: 2,
                trees_removed: 2
            }
        );
        // A removed login's blocks are zeroed; a removed tree's are left to the
        // wipe of free blocks that follows.
        assert!(!holds_token(&disk), "the login's token was zeroed");
        assert_eq!(names(&disk, &[".codex"]).await, ["config.toml"]);
        assert_eq!(names(&disk, &[".claude"]).await, [".credentials.json"]);
        assert_eq!(
            names(&disk, &[".codewire", "daemon"]).await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_symbolic_link_for_a_home_or_a_login_or_an_oversized_login_fails_the_clearing() {
        let scratch = tempfile::tempdir().unwrap();
        let home = volume(scratch.path());
        debugfs_setup(&home, "mkdir /elsewhere");
        debugfs_setup(&home, "symlink /.claude /elsewhere");
        let login = volume(&{
            let path = scratch.path().join("login");
            std::fs::create_dir(&path).unwrap();
            path
        });
        debugfs_setup(&login, "mkdir /.codex");
        debugfs_setup(&login, "symlink /.codex/auth.json /elsewhere");
        let oversized = volume(&{
            let path = scratch.path().join("oversized");
            std::fs::create_dir(&path).unwrap();
            path
        });
        debugfs_setup(&oversized, "mkdir /.claude");
        plant(
            &oversized,
            scratch.path(),
            "/.claude/.credentials.json",
            &"x".repeat(MAX_LOGIN_BYTES as usize + 1),
        );

        for disk in [&home, &login, &oversized] {
            let error = clear_files(&SystemTools, disk).await.unwrap_err();
            assert!(matches!(error, BlockClearingError::Undecided(_)), "{error}");
        }
    }
}
