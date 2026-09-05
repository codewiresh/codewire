#![cfg(target_os = "linux")]

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

const NETWORK_BOOTSTRAP_FD: libc::c_int = 4;
const INHERITED_DESCRIPTOR_EXIT_CODE: i32 = 21;

#[test]
fn cw_hidden_network_worker_preserves_its_typed_failure_exit() {
    let invalid_bootstrap = File::open("/dev/null").unwrap();
    let source = invalid_bootstrap.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .arg("__native-network-worker")
        .arg("--environment-id")
        .arg("00112233-4455-6677-8899-aabbccddeeff")
        .arg("--generation")
        .arg("9")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the hook uses only descriptor syscalls before exec and makes fd
    // 4 an intentionally invalid (non-socket) bootstrap fixture.
    unsafe {
        command.pre_exec(move || {
            if source != NETWORK_BOOTSTRAP_FD && libc::dup2(source, NETWORK_BOOTSTRAP_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(NETWORK_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let status = command.status().unwrap();
    assert_eq!(status.code(), Some(INHERITED_DESCRIPTOR_EXIT_CODE));
}
