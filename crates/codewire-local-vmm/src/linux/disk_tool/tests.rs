use std::io;
use std::path::Path;

use super::{DISK_TOOL_ARCH_DENIED_SYSCALLS, DISK_TOOL_DENIED_SYSCALLS, command, confined_to};
use crate::linux::confinement::{PreparedSyscallFilter, lock_exec_process_privileges};

/// A fresh ext4 disk of `mib` MiB, formatted as cw formats one.
fn ext4_disk(directory: &Path, name: &str, mib: u64) -> std::path::PathBuf {
    let disk = directory.join(name);
    std::fs::File::create(&disk)
        .unwrap()
        .set_len(mib << 20)
        .unwrap();
    let status = std::process::Command::new(crate::linux::e2fsprogs("mkfs.ext4").unwrap())
        .args(crate::linux::EXT4_FORMAT)
        .args(["-q", "-F", "-m", "0"])
        .arg(&disk)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
    disk
}

fn block_count(disk: &Path) -> u32 {
    let image = std::fs::read(disk).unwrap();
    u32::from_le_bytes(image[1024 + 4..1024 + 8].try_into().unwrap())
}

/// Runs `command` as the runner does: no inherited environment, e2fsck's
/// configuration empty, standard streams `/dev/null`.
async fn status(mut command: tokio::process::Command) -> Option<i32> {
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("E2FSCK_CONFIG", "/dev/null")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap()
        .code()
}

fn tool(name: &str) -> std::path::PathBuf {
    crate::linux::e2fsprogs(name).unwrap()
}

#[tokio::test]
async fn confined_e2fsck_and_resize2fs_grow_the_disk_they_are_given() {
    let directory = tempfile::tempdir().unwrap();
    let disk = ext4_disk(directory.path(), "state.raw", 64);
    assert_eq!(block_count(&disk), 16384);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&disk)
        .unwrap()
        .set_len(96 << 20)
        .unwrap();
    let check = status(command(&tool("e2fsck"), &["-p", "-f"], &disk).unwrap()).await;
    assert!(matches!(check, Some(0 | 1)), "e2fsck: {check:?}");
    assert_eq!(
        status(command(&tool("resize2fs"), &[], &disk).unwrap()).await,
        Some(0)
    );
    assert_eq!(block_count(&disk), 24576);
}

/// The tool can open only the disk its domain names: the same check on
/// another disk works unconfined and fails confined.
#[tokio::test]
async fn a_confined_tool_cannot_open_any_other_file() {
    let directory = tempfile::tempdir().unwrap();
    let granted = ext4_disk(directory.path(), "granted.raw", 16);
    let other = ext4_disk(directory.path(), "other.raw", 16);
    let mut unconfined = tokio::process::Command::new(tool("e2fsck"));
    unconfined.args(["-n", "-f"]).arg(&other);
    assert_eq!(status(unconfined).await, Some(0));
    // The domain names `granted`; the argument names `other`. e2fsck exits 8
    // for an operational error (it could not open the disk), resize2fs 1.
    let mut check = confined_to(&tool("e2fsck"), &granted).unwrap();
    check.args(["-n", "-f"]).arg(&other);
    assert_eq!(status(check).await, Some(8));
    let mut resize = confined_to(&tool("resize2fs"), &granted).unwrap();
    resize.arg(&other);
    assert_eq!(status(resize).await, Some(1));
    // The same commands on the granted disk work.
    assert_eq!(
        status(command(&tool("e2fsck"), &["-n", "-f"], &granted).unwrap()).await,
        Some(0)
    );
}

#[test]
fn the_disk_tool_filter_refuses_sockets_processes_and_signals() {
    const CHILD_MARKER: &str = "CODEWIRE_TEST_DISK_TOOL_FILTER";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let mut filter = PreparedSyscallFilter::denying(
            DISK_TOOL_DENIED_SYSCALLS,
            DISK_TOOL_ARCH_DENIED_SYSCALLS,
        );
        lock_exec_process_privileges().unwrap();
        filter.install().unwrap();
        let refused = |result: libc::c_long| {
            assert_eq!(result, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        };
        for family in [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
        ] {
            refused(unsafe { libc::socket(family, libc::SOCK_STREAM, 0) }.into());
        }
        refused(unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0) });
        refused(unsafe { libc::kill(libc::getppid(), 0) }.into());
        refused(unsafe { libc::syscall(libc::SYS_memfd_create, c"x".as_ptr(), 0) });
        refused(unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER) });
        // Ordinary file work still runs.
        assert!(std::fs::read("/proc/self/status").is_ok());
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("linux::disk_tool::tests::the_disk_tool_filter_refuses_sockets_processes_and_signals")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
    assert!(status.success());
}
