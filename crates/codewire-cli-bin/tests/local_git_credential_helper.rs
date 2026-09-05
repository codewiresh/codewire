#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use tempfile::TempDir;
use uuid::Uuid;

const TOKEN: &str = "synthetic-github-helper-token";
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[test]
fn git_receives_one_synthetic_token_through_the_isolated_helper_channel() {
    let executable = env!("CARGO_BIN_EXE_cw");
    let temporary = TempDir::new().unwrap();
    let staging = temporary.path().join(format!("cwgr-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .unwrap();
    let socket = staging.join("c");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let token_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(TOKEN.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });
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
    // SAFETY: the hook applies scalar-only confinement before exec. No
    // ambient or owner credential is available to this synthetic test.
    unsafe {
        command.pre_exec(|| {
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
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
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
