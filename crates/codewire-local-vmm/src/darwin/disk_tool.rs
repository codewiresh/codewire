//! Confinement for the host e2fsprogs that check and grow a guest-written
//! filesystem.
//!
//! Growing a state disk runs the runtime's `e2fsck -p -f` and then `resize2fs`
//! on a filesystem the guest wrote, so a parser bug in either is reachable
//! from inside the VM. Each runs under a deny-default Seatbelt profile that
//! `/usr/bin/sandbox-exec` applies before it executes the tool: the same
//! `sandbox_init` that confines the packet worker and egress broker, applied
//! by a fresh single-threaded process, so nothing runs between fork and exec
//! in the multithreaded supervisor. The profile names the tool and the disk
//! by parameter, so no path is ever spliced into its text.
//!
//! The tool may execute only itself, read and write only its one disk and
//! `/dev/null`, and read the system libraries, dyld's shared cache, the root
//! directory and a few informational sysctls that the dynamic loader and
//! e2fsprogs read at startup. It gets no other file, no network, no Mach
//! service, no other program, no fork and no signal to another process.

use std::ffi::OsString;
use std::io;
use std::path::Path;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Every dyld and libSystem read the tools need was observed under this
/// profile on macOS 26; reading the root directory is required at startup.
/// Seatbelt matches resolved paths, so `TOOL` and `DISK` are canonical.
const PROFILE: &str = r#"(version 1)
(deny default)
(allow process-exec (literal (param "TOOL")))
(allow file-read* file-map-executable (literal (param "TOOL")))
(allow file-read* file-write-data (literal (param "DISK")))
(allow file-read* file-write-data (literal "/dev/null"))
(allow file-read* file-map-executable (subpath "/usr/lib") (subpath "/System/Library")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS"))
(allow file-read-data (literal "/"))
(allow file-read-metadata (literal "/") (literal "/var") (literal "/etc") (literal "/tmp")
  (literal "/System/Cryptexes/OS"))
(allow sysctl-read (sysctl-name "kern.bootargs") (sysctl-name "security.mac.lockdown_mode_state")
  (sysctl-name "kern.osproductversion") (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.iossupportversion") (sysctl-name "hw.memsize") (sysctl-name "hw.ncpu")
  (sysctl-name "hw.pagesize") (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.ephemeral_storage"))
(allow signal (target self))
"#;

/// `tool leading_args... disk` under the disk-tool profile. The caller sets
/// the environment and standard streams.
pub(crate) fn command(
    tool: &Path,
    leading_args: &[&str],
    disk: &Path,
) -> io::Result<tokio::process::Command> {
    let tool = std::fs::canonicalize(tool)?;
    let disk = std::fs::canonicalize(disk)?;
    let mut command = tokio::process::Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(PROFILE)
        .arg("-D")
        .arg(parameter("TOOL", &tool))
        .arg("-D")
        .arg(parameter("DISK", &disk))
        .arg(&tool)
        .args(leading_args)
        .arg(&disk)
        // The profile cannot read the supervisor's working directory.
        .current_dir("/");
    Ok(command)
}

fn parameter(name: &str, path: &Path) -> OsString {
    let mut value = OsString::from(format!("{name}="));
    value.push(path);
    value
}

#[cfg(test)]
mod tests {
    use std::process::{Output, Stdio};

    use super::*;

    async fn run(tool: &str, leading_args: &[&str], disk: &Path) -> Output {
        command(Path::new(tool), leading_args, disk)
            .unwrap()
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .await
            .unwrap()
    }

    /// `/bin/bash -c SCRIPT bash DISK`: the script sees the disk as `$1`.
    async fn bash(script: &str, disk: &Path) -> Output {
        run("/bin/bash", &["-c", script, "bash"], disk).await
    }

    fn disk() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let disk = root.path().join("state.raw");
        std::fs::write(&disk, b"guest\n").unwrap();
        (root, disk)
    }

    #[tokio::test]
    async fn the_tool_reads_and_writes_its_disk() {
        let (_root, disk) = disk();
        let output = bash(
            r#"read -r line < "$1" && printf '%s-grown' "$line" > "$1""#,
            &disk,
        )
        .await;
        assert!(output.status.success(), "{output:?}");
        assert_eq!(std::fs::read(&disk).unwrap(), b"guest-grown");
    }

    #[tokio::test]
    async fn the_tool_reads_and_writes_no_other_file() {
        let (root, disk) = disk();
        let other = root.path().join("other");
        std::fs::write(&other, b"host").unwrap();
        for script in [
            format!("read -r line < {}", other.display()),
            "read -r line < /etc/hosts".to_owned(),
            format!("printf x > {}", other.display()),
            format!("printf x > {}", root.path().join("new").display()),
        ] {
            let output = bash(&script, &disk).await;
            assert!(!output.status.success(), "{script} succeeded");
        }
        assert_eq!(std::fs::read(&other).unwrap(), b"host");
        assert!(!root.path().join("new").exists());
    }

    #[tokio::test]
    async fn the_tool_runs_no_other_program_and_signals_only_itself() {
        let (_root, disk) = disk();
        // exec replaces the shell without a fork; `( : )` forks a subshell.
        for script in ["exec /bin/echo escaped", "( : )", "kill -0 $PPID"] {
            let output = bash(script, &disk).await;
            assert!(!output.status.success(), "{script} succeeded");
            assert!(!String::from_utf8_lossy(&output.stdout).contains("escaped"));
        }
        assert!(bash("kill -0 $$", &disk).await.status.success());
    }

    #[tokio::test]
    async fn the_tool_reaches_no_network() {
        let (_root, disk) = disk();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let output = bash(&format!("exec 3<>/dev/tcp/127.0.0.1/{port}"), &disk).await;
        assert!(!output.status.success(), "{output:?}");
        assert!(listener.accept().is_err(), "the confined tool connected");
    }

    #[tokio::test]
    async fn an_unconfinable_tool_is_never_run_unconfined() {
        let (root, _disk) = disk();
        let missing = root.path().join("missing.raw");
        assert!(command(Path::new("/bin/bash"), &[], &missing).is_err());
    }

    /// The runtime's own e2fsck and resize2fs check and grow a filesystem
    /// under the profile, as growing a stopped state disk does.
    #[tokio::test]
    async fn the_runtimes_e2fsprogs_check_and_grow_a_filesystem_confined() {
        let mkfs = crate::host::e2fsprogs("mkfs.ext4").expect("runtime mkfs.ext4");
        let config = crate::host::mke2fs_config().expect("runtime mke2fs.conf");
        let e2fsck = crate::host::e2fsprogs("e2fsck").expect("runtime e2fsck");
        let resize2fs = crate::host::e2fsprogs("resize2fs").expect("runtime resize2fs");
        let root = tempfile::tempdir().unwrap();
        let disk = root.path().join("state.raw");
        std::fs::File::create(&disk)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        let formatted = std::process::Command::new(mkfs)
            .args(["-q", "-F", "-t", "ext4"])
            .arg(&disk)
            .env_clear()
            .env("LC_ALL", "C")
            .env("MKE2FS_CONFIG", config)
            .status()
            .unwrap();
        assert!(formatted.success());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&disk)
            .unwrap()
            .set_len(128 << 20)
            .unwrap();
        let tool = |program: &Path, leading: &'static [&'static str]| {
            let mut command = command(program, leading, &disk).unwrap();
            command
                .env_clear()
                .env("LC_ALL", "C")
                .env("E2FSCK_CONFIG", "/dev/null")
                .stdin(Stdio::null());
            command
        };
        let checked = tool(&e2fsck, &["-p", "-f"]).output().await.unwrap();
        assert!(matches!(checked.status.code(), Some(0 | 1)), "{checked:?}");
        let grown = tool(&resize2fs, &[]).output().await.unwrap();
        assert!(grown.status.success(), "{grown:?}");
        assert!(
            String::from_utf8_lossy(&grown.stdout).contains("is now 32768 (4k) blocks long"),
            "{grown:?}"
        );
        let clean = tool(&e2fsck, &["-n", "-f"]).output().await.unwrap();
        assert_eq!(clean.status.code(), Some(0), "{clean:?}");
    }
}
