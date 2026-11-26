//! A clean guest poweroff (#2760).
//!
//! Stopping a VM used to SIGKILL the workload at once and power off with only
//! a `sync`, leaving every guest-written ext4 disk mounted: the journal kept
//! `needs_recovery`, so the next mount and every host `e2fsck` before a resize
//! replayed it, and a workload never got to save what it held in memory.
//! Now the workload gets SIGTERM and a bounded grace first, and every ext4
//! and overlay mount is unmounted, or remounted read-only when it cannot be,
//! before the poweroff.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

/// How long the workload may take to exit after SIGTERM before the container
/// is killed. The host waits 30 s for the whole poweroff.
pub(super) const WORKLOAD_STOP_GRACE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Outcome of one non-blocking `waitpid(-1, ..., WNOHANG)` poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reap {
    Exited(libc::pid_t),
    Pending,
    NoChildren,
}

fn reap_any_child() -> io::Result<Reap> {
    let mut status = 0;
    // SAFETY: `status` is a valid stack pointer for `waitpid` with `WNOHANG`.
    let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if reaped > 0 {
        return Ok(Reap::Exited(reaped));
    }
    if reaped == 0 {
        return Ok(Reap::Pending);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        return Ok(Reap::NoChildren);
    }
    if error.kind() == io::ErrorKind::Interrupted {
        return Ok(Reap::Pending);
    }
    Err(error)
}

/// Reaps container children until `poweroff` is requested. When a local-VM
/// `credential_forwarder` child is present, its exit ends container PID 1.
pub(super) fn wait_for_poweroff(
    credential_forwarder: Option<Child>,
    poweroff: &AtomicBool,
) -> Result<()> {
    wait_for_poweroff_with(credential_forwarder, poweroff, reap_any_child)
}

fn wait_for_poweroff_with(
    mut credential_forwarder: Option<Child>,
    poweroff: &AtomicBool,
    mut reap_any: impl FnMut() -> io::Result<Reap>,
) -> Result<()> {
    loop {
        if poweroff.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(forwarder) = credential_forwarder.as_mut()
            && forwarder
                .try_wait()
                .context("observe credential loopback forwarder")?
                .is_some()
        {
            bail!("credential loopback forwarder exited");
        }
        match reap_any().context("reap workspace child")? {
            Reap::Exited(pid) => {
                if credential_forwarder.as_ref().is_some_and(|forwarder| {
                    pid == libc::pid_t::try_from(forwarder.id()).unwrap_or(-1)
                }) {
                    bail!("credential loopback forwarder exited");
                }
                thread::sleep(POLL_INTERVAL);
            }
            Reap::NoChildren => {
                if credential_forwarder.is_some() {
                    bail!("workspace init lost its credential loopback forwarder");
                }
                thread::sleep(POLL_INTERVAL);
            }
            Reap::Pending => {
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// The workspace container's PID 1 in this namespace, from `runc state`.
pub(super) fn container_init_pid() -> Option<i32> {
    let mut child = Command::new(super::RUNC_PATH)
        .args([
            "--root",
            super::RUNC_STATE_PATH,
            "state",
            super::WORKSPACE_CONTAINER_ID,
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut output = Vec::new();
    io::Read::read_to_end(&mut child.stdout.take()?, &mut output).ok()?;
    let state: serde_json::Value = serde_json::from_slice(&output).ok()?;
    state
        .get("pid")
        .and_then(serde_json::Value::as_i64)
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
}

/// SIGTERM every process of the workspace container except its init and the
/// init's credential forwarder, wait until they are gone or the grace ends,
/// then SIGKILL what is left. Either of those two ending ends the container,
/// and every process in it with SIGKILL, at once. The container's own init
/// cannot do this: it holds no `CAP_KILL`, and the workload runs as another
/// user.
pub(super) fn terminate_workload(container_init: i32, grace: Duration) -> usize {
    let Some(namespace) = pid_namespace(container_init) else {
        return 0;
    };
    // Only the container's own namespace: never the guest's services (the
    // daemon, the network agent, Docker), which share this init's.
    if std::fs::read_link("/proc/self/ns/pid").ok().as_deref() == Some(namespace.as_path()) {
        return 0;
    }
    // A zombie has already exited and holds nothing; it is gone once the
    // container's init reaps it or the container ends.
    let members = |namespace: &Path| -> Vec<i32> {
        processes()
            .into_iter()
            .filter(|pid| *pid != container_init)
            .filter(|pid| pid_namespace(*pid).as_deref() == Some(namespace))
            .filter(|pid| !exited(*pid))
            .filter(|pid| !is_credential_forwarder(*pid, container_init))
            .collect()
    };
    let signalled = members(&namespace);
    for pid in &signalled {
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline && !members(&namespace).is_empty() {
        thread::sleep(POLL_INTERVAL);
    }
    // The grace is over; what still runs ignored SIGTERM. Kill it now, so
    // the daemon's session teardown does not wait out its own timeout on it.
    for pid in members(&namespace) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    signalled.len()
}

fn processes() -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect()
}

/// The container init's credential forwarder: its child running the sealed
/// forwarder command. A workload process that copies that command only skips
/// the SIGTERM; the container's SIGKILL still ends it.
fn is_credential_forwarder(pid: i32, container_init: i32) -> bool {
    let parent = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| process_parent(&stat));
    parent == Some(container_init)
        && std::fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|command| is_forwarder_command(&command))
}

fn is_forwarder_command(command: &[u8]) -> bool {
    let mut expected = super::CONTAINER_INIT_PATH.as_bytes().to_vec();
    expected.push(0);
    expected.extend_from_slice(b"credential-forwarder\0");
    command == expected
}

/// The parent PID of a /proc/PID/stat line, the field after the state.
fn process_parent(stat: &str) -> Option<i32> {
    stat.rsplit_once(") ")?.1.split(' ').nth(1)?.parse().ok()
}

/// Whether `pid` has exited (a zombie, or already gone).
fn exited(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| process_state(&stat))
        .is_none_or(|state| matches!(state, 'Z' | 'X' | 'x'))
}

/// The state letter of a /proc/PID/stat line, which follows the command
/// name's closing parenthesis (the name itself may contain any byte).
fn process_state(stat: &str) -> Option<char> {
    stat.rsplit_once(") ")?.1.chars().next()
}

fn pid_namespace(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/pid")).ok()
}

/// One line of /proc/self/mountinfo: where it is mounted and its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mount {
    pub target: PathBuf,
    pub fstype: String,
}

/// The mounts in mount order. Fields are space-separated with spaces, tabs,
/// newlines and backslashes in paths octal-escaped; the filesystem type
/// follows the ` - ` separator.
pub(super) fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let target = before.split(' ').nth(4)?;
            let fstype = after.split(' ').next()?;
            Some(Mount {
                target: PathBuf::from(OsString::from_vec(unescape(target))),
                fstype: fstype.to_owned(),
            })
        })
        .collect()
}

fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 4 <= bytes.len()
            && bytes[index + 1..index + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            out.push(value);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

/// What [`release_filesystems`] did with each guest-written mount.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Released {
    pub unmounted: usize,
    pub read_only: usize,
    pub failed: Vec<PathBuf>,
}

/// The mounts to release, last mounted first: every ext4 mount (the guest
/// disks and binds of them) and every overlay over them.
pub(super) fn release_order(mounts: &[Mount]) -> Vec<Mount> {
    mounts
        .iter()
        .rev()
        .filter(|mount| matches!(mount.fstype.as_str(), "ext4" | "overlay"))
        .cloned()
        .collect()
}

/// Unmount every guest-written filesystem, or remount it read-only when it is
/// still busy, so each ext4 journal is checkpointed and marked clean.
pub(super) fn release_filesystems() -> Released {
    let mut released = Released::default();
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return released;
    };
    for mount in release_order(&parse_mountinfo(&text)) {
        let Ok(target) = std::ffi::CString::new(mount.target.as_os_str().as_bytes()) else {
            released.failed.push(mount.target);
            continue;
        };
        if unsafe { libc::umount2(target.as_ptr(), 0) } == 0 {
            released.unmounted += 1;
        } else if mount.fstype == "ext4"
            && unsafe {
                libc::mount(
                    std::ptr::null(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_RDONLY,
                    std::ptr::null(),
                )
            } == 0
        {
            released.read_only += 1;
        } else {
            released.failed.push(mount.target);
        }
    }
    released
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_lines_give_targets_and_types_in_mount_order() {
        let text = "\
22 1 0:20 / / rw,relatime - rootfs rootfs rw
30 22 254:16 / /generation rw,relatime - ext4 /dev/vdb rw
31 22 254:0 / /workspace rw,nosuid,nodev,relatime - ext4 /dev/vda rw
40 22 0:41 / /run/merged rw,relatime - overlay overlay rw,lowerdir=/generation/lower
41 40 254:0 /home /run/merged/home\\040dir rw - ext4 /dev/vda rw
42 22 0:5 / /proc rw - proc proc rw
";
        let mounts = parse_mountinfo(text);
        assert_eq!(mounts.len(), 6);
        assert_eq!(mounts[1].target, Path::new("/generation"));
        assert_eq!(mounts[1].fstype, "ext4");
        assert_eq!(mounts[4].target, Path::new("/run/merged/home dir"));
        let order: Vec<_> = release_order(&mounts)
            .into_iter()
            .map(|mount| mount.target)
            .collect();
        assert_eq!(
            order,
            [
                PathBuf::from("/run/merged/home dir"),
                PathBuf::from("/run/merged"),
                PathBuf::from("/workspace"),
                PathBuf::from("/generation"),
            ]
        );
    }

    #[test]
    fn the_state_follows_the_last_parenthesis() {
        assert_eq!(process_state("42 (sh) S 1 42 42 0"), Some('S'));
        assert_eq!(process_state("43 (we (ird) )) Z 1 43"), Some('Z'));
        assert_eq!(process_state("garbage"), None);
        assert!(exited(i32::MAX));
        assert!(!exited(std::process::id() as i32));
    }

    #[test]
    fn only_the_sealed_forwarder_command_is_the_forwarder() {
        assert!(is_forwarder_command(
            b"/run/codewire-runtime/init\0credential-forwarder\0"
        ));
        assert!(!is_forwarder_command(
            b"/run/codewire-runtime/init\0workspace-exec\0"
        ));
        assert!(!is_forwarder_command(
            b"/run/codewire-runtime/init\0credential-forwarder\0extra\0"
        ));
        assert!(!is_forwarder_command(b"/bin/sh\0-c\0sleep 1\0"));
        assert_eq!(process_parent("153 (init) S 145 145 145 0"), Some(145));
        assert_eq!(process_parent("43 (we (ird) )) S 1 43"), Some(1));
        assert_eq!(process_parent("garbage"), None);
    }

    #[test]
    fn escapes_decode_and_malformed_lines_are_skipped() {
        assert_eq!(unescape("a\\011b\\134c\\012"), b"a\tb\\c\n");
        assert_eq!(unescape("trailing\\04"), b"trailing\\04");
        assert!(parse_mountinfo("no separator here\n").is_empty());
    }

    #[test]
    fn wait_for_poweroff_without_local_forwarder_tolerates_no_children_until_poweroff() {
        let poweroff = AtomicBool::new(false);
        let mut polls = 0usize;
        let result = wait_for_poweroff_with(None, &poweroff, || {
            polls += 1;
            if polls >= 2 {
                poweroff.store(true, Ordering::Release);
            }
            Ok(Reap::NoChildren)
        });
        assert!(result.is_ok(), "expected clean poweroff, got {result:?}");
        assert!(polls >= 2);
    }

    #[test]
    fn wait_for_poweroff_fails_if_local_forwarder_exits() {
        let poweroff = AtomicBool::new(false);
        let child = Command::new("/bin/true").spawn().expect("spawn /bin/true");
        let error = wait_for_poweroff_with(Some(child), &poweroff, || Ok(Reap::Pending))
            .expect_err("exiting local credential forwarder must fail wait_for_poweroff");
        assert!(
            error
                .to_string()
                .contains("credential loopback forwarder exited"),
            "unexpected error: {error:#}"
        );
    }
}
