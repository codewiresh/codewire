#![cfg(any(target_os = "linux", target_os = "macos"))]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;
use uuid::Uuid;

const TOKEN: &str = "synthetic-github-helper-token";
#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// A private directory whose `cwgr-*/c` socket is canonical and fits the
/// platform's socket path bound (Darwin's is 104 bytes).
fn temporary_root() -> TempDir {
    let parent = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    };
    tempfile::Builder::new()
        .prefix("cw-helper-")
        .tempdir_in(parent)
        .unwrap()
}

/// Confine Git as the repository executor's Git launcher does.
fn confine_git(command: &mut Command, confined: bool) {
    // SAFETY: the hook applies scalar-only confinement before exec. No
    // ambient or owner credential is available to this synthetic test.
    unsafe {
        command.pre_exec(move || {
            if !confined {
                return Ok(());
            }
            #[cfg(target_os = "linux")]
            {
                let header = LinuxCapabilityHeader {
                    version: LINUX_CAPABILITY_VERSION_3,
                    pid: 0,
                };
                let empty = LinuxCapabilityData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                };
                let capabilities = [empty; 2];
                if libc::syscall(
                    libc::SYS_capset,
                    std::ptr::addr_of!(header),
                    capabilities.as_ptr(),
                ) != 0
                    || libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // macOS has no capabilities or no-new-privileges bit: the
            // executor's Git launcher disables core files instead.
            #[cfg(target_os = "macos")]
            {
                let no_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn fill_through_helper(socket: &Path, confined: bool) -> Output {
    let executable = env!("CARGO_BIN_EXE_cw");
    let helper = format!(
        "!exec '{}' __local-git-credential-helper --credential-socket '{}'",
        executable.replace('\'', "'\\''"),
        socket.to_string_lossy().replace('\'', "'\\''"),
    );
    let mut command = Command::new("/usr/bin/git");
    command
        .args([
            "-c",
            "credential.helper=",
            "-c",
            &format!("credential.helper={helper}"),
            "credential",
            "fill",
        ])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    confine_git(&mut command, confined);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\n\n")
        .unwrap();
    child.wait_with_output().unwrap()
}

fn one_use_socket(temporary: &TempDir) -> (std::path::PathBuf, std::os::unix::net::UnixListener) {
    let root = fs::canonicalize(temporary.path()).unwrap();
    let staging = root.join(format!("cwgr-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .unwrap();
    let socket = staging.join("c");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    (socket, listener)
}

#[test]
fn git_receives_one_synthetic_token_through_the_isolated_helper_channel() {
    let temporary = temporary_root();
    let (socket, listener) = one_use_socket(&temporary);
    let token_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(TOKEN.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let output = fill_through_helper(&socket, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    token_server.join().unwrap();
    let response = String::from_utf8(output.stdout).unwrap();
    assert!(response.contains("protocol=https\n"));
    assert!(response.contains("host=github.com\n"));
    assert!(response.contains("username=x-access-token\n"));
    assert!(response.contains(&format!("password={TOKEN}\n")));
}

/// A helper Git started without the executor's confinement never connects to
/// the one-use socket, so no token leaves it.
#[cfg(target_os = "macos")]
#[test]
fn an_unconfined_helper_refuses_before_reading_the_token() {
    let temporary = temporary_root();
    let (socket, listener) = one_use_socket(&temporary);
    listener.set_nonblocking(true).unwrap();
    let output = fill_through_helper(&socket, false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the helper connected to the token socket"
    );
}
