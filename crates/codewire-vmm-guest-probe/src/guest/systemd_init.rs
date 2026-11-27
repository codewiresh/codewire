//! Guest-side setup and handoff for `CODEWIRE_WORKSPACE_INIT=systemd` on the
//! `standard` runtime profile (`docs/dev/SYSTEMD-WORKSPACE.md`, "On the
//! `standard` profile", #5638).
//!
//! Guest init stays the VM's PID 1 and mounts a private cgroup v2 hierarchy
//! alongside `runc`'s cgroup v1 hierarchy. Before any workspace code executes,
//! guest init moves the container's PID 1 into the delegated `workspace`
//! cgroup v2 subtree; container PID 1 enters a new cgroup namespace, mounts
//! `cgroup2` at `/sys/fs/cgroup`, drops `CAP_SYS_ADMIN` permanently from its
//! bounding set, masks `codewire-daemon.service` and `docker.service`, spawns
//! the hosted daemon in `/sys/fs/cgroup/init.scope`, and finally
//! `exec`s `/sbin/init`.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};

use super::{
    CGROUP2_MOUNT_PATH, CGROUP2_WORKSPACE_PATH, LINUX_CAPABILITY_VERSION_3, LinuxCapabilityData,
    LinuxCapabilityHeader, WORKSPACE_READY_FD, create_dir, ensure_workspace_start_active, mount_fs,
};

/// Handshake frames exchanged over `WORKSPACE_READY_FD` before bootstrap so
/// guest init places container PID 1 into the delegated cgroup v2 subtree
/// prior to `unshare(CLONE_NEWCGROUP)`.
const CGROUP_JOIN_REQUEST: &[u8] = b"codewire-workspace-cgroup2-join-v1\n";
const CGROUP_JOIN_ACK: &[u8] = b"codewire-workspace-cgroup2-joined-v1\n";

/// Where container PID 1 mounts the delegated cgroup v2 subtree.
const CONTAINER_CGROUP_PATH: &str = "/sys/fs/cgroup";
/// Dedicated child cgroup holding the guest-init-spawned hosted daemon. Using
/// `init.scope` matches systemd's own PID 1 scope so systemd never prunes it
/// as an orphan unit at boot, while still keeping the container root cgroup
/// free of internal processes.
pub(super) const CONTAINER_DAEMON_SCOPE_PATH: &str = "/sys/fs/cgroup/init.scope";
pub(super) const CONTAINER_DAEMON_SCOPE_PROCS_PATH: &str = "/sys/fs/cgroup/init.scope/cgroup.procs";

/// Systemd units masked in `/run/systemd/system` for `standard` workspaces:
/// the guest's own `dockerd` runs outside the container, and `/etc/machine-id`
/// is a read-only runtime bind mount so committing it is a no-op.
const MASKED_RUNTIME_UNITS: [&str; 2] = ["docker.service", "systemd-machine-id-commit.service"];
/// Systemd units shipped under `/etc/systemd/system` in `workspace-systemd`
/// that must be masked there (since `/etc/systemd/system` outranks
/// `/run/systemd/system`): guest init spawns the hosted daemon with the held
/// listener directly.
const MASKED_ETC_UNITS: [&str; 1] = ["codewire-daemon.service"];
const RUNTIME_SYSTEMD_UNITS_DIR: &str = "/run/systemd/system";
const ETC_SYSTEMD_UNITS_DIR: &str = "/etc/systemd/system";
const CONTAINER_RUN_LOCK_DIR: &str = "/run/lock";
const SYSTEMD_INIT_PATH: &str = "/sbin/init";

/// Linux `CGROUP2_SUPER_MAGIC` (`<linux/magic.h>`).
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// Linux `CAP_SYS_ADMIN` bit index (`<linux/capability.h>`).
const CAP_SYS_ADMIN: libc::c_ulong = 21;

/// Bitmask of `codewire_daemon::execution::WORKLOAD_ROOT_CAPABILITIES` in
/// capability word 0 (bits 0..31). Never includes `CAP_SYS_ADMIN`,
/// `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, or `CAP_SYS_BOOT`.
pub(super) const WORKLOAD_ROOT_CAPABILITIES_MASK: u32 = (1 << 0)  // CAP_CHOWN
    | (1 << 1)  // CAP_DAC_OVERRIDE
    | (1 << 3)  // CAP_FOWNER
    | (1 << 4)  // CAP_FSETID
    | (1 << 5)  // CAP_KILL
    | (1 << 6)  // CAP_SETGID
    | (1 << 7)  // CAP_SETUID
    | (1 << 8)  // CAP_SETPCAP
    | (1 << 10) // CAP_NET_BIND_SERVICE
    | (1 << 13) // CAP_NET_RAW
    | (1 << 18) // CAP_SYS_CHROOT
    | (1 << 27) // CAP_MKNOD
    | (1 << 29) // CAP_AUDIT_WRITE
    | (1 << 31); // CAP_SETFCAP

/// Guest-init side: mount a private `cgroup2` hierarchy outside `runc`'s v1
/// mount and create the delegated `workspace` subtree.
pub(super) fn prepare_cgroup2() -> Result<()> {
    create_dir(Path::new(CGROUP2_MOUNT_PATH), 0o755)?;
    mount_fs(
        "cgroup2",
        CGROUP2_MOUNT_PATH,
        "cgroup2",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "nsdelegate",
    )
    .context("mount private cgroup v2 hierarchy")?;
    verify_cgroup2_filesystem(CGROUP2_MOUNT_PATH)?;
    create_dir(Path::new(CGROUP2_WORKSPACE_PATH), 0o755)?;
    Ok(())
}

/// Guest-init side: wait for container PID 1's cgroup v2 join request, place
/// it into `CGROUP2_WORKSPACE_PATH`, and acknowledge.
pub(super) fn serve_cgroup2_join(
    readiness: &mut UnixStream,
    workspace: &mut std::process::Child,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<()> {
    let mut received = Vec::with_capacity(CGROUP_JOIN_REQUEST.len());
    let mut chunk = [0_u8; 64];
    while received.len() < CGROUP_JOIN_REQUEST.len() {
        ensure_workspace_start_active(deadline, canceled)?;
        if workspace
            .try_wait()
            .context("observe workspace container during cgroup2 join")?
            .is_some()
        {
            bail!("workspace container exited before cgroup2 join");
        }
        match readiness.read(&mut chunk) {
            Ok(0) => bail!("workspace readiness channel closed before cgroup2 join"),
            Ok(read) => {
                received.extend_from_slice(&chunk[..read]);
                ensure!(
                    CGROUP_JOIN_REQUEST.starts_with(&received),
                    "unexpected message before cgroup2 join"
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error).context("read cgroup2 join request"),
        }
    }
    let init_pid = wait_for_container_init_pid(workspace, deadline, canceled)?;
    let procs = Path::new(CGROUP2_WORKSPACE_PATH).join("cgroup.procs");
    fs::write(&procs, format!("{init_pid}\n"))
        .with_context(|| format!("move container PID {init_pid} into {}", procs.display()))?;
    readiness
        .write_all(CGROUP_JOIN_ACK)
        .context("acknowledge cgroup2 join")?;
    readiness.flush().context("flush cgroup2 join ack")
}

fn wait_for_container_init_pid(
    workspace: &mut std::process::Child,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<i32> {
    loop {
        ensure_workspace_start_active(deadline, canceled)?;
        if let Some(pid) = super::shutdown::container_init_pid() {
            return Ok(pid);
        }
        if workspace
            .try_wait()
            .context("observe workspace container waiting for init PID")?
            .is_some()
        {
            bail!("workspace container exited before reporting init PID");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Container-PID-1 side: ask guest init to move us into the delegated cgroup
/// v2 subtree, unshare the cgroup namespace, mount `/sys/fs/cgroup`, create
/// the daemon scope, drop `CAP_SYS_ADMIN` permanently, and mask conflicting
/// systemd units.
pub(super) fn prepare_container_for_systemd(deadline: Instant) -> Result<()> {
    request_cgroup2_join(deadline)?;
    // SAFETY: `unshare(CLONE_NEWCGROUP)` requires no pointers and isolates our
    // cgroup namespace root to the delegated `workspace` subtree.
    if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } == -1 {
        return Err(io::Error::last_os_error()).context("unshare workspace cgroup namespace");
    }
    mount_fs(
        "cgroup2",
        CONTAINER_CGROUP_PATH,
        "cgroup2",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "nsdelegate",
    )
    .context("mount delegated cgroup v2 at /sys/fs/cgroup")?;
    verify_cgroup2_filesystem(CONTAINER_CGROUP_PATH)?;
    create_dir(Path::new(CONTAINER_DAEMON_SCOPE_PATH), 0o755)?;
    drop_sys_admin_permanently()?;
    prepare_runtime_directories_and_masks(
        Path::new(CONTAINER_RUN_LOCK_DIR),
        Path::new(RUNTIME_SYSTEMD_UNITS_DIR),
        Path::new(ETC_SYSTEMD_UNITS_DIR),
    )
}

fn request_cgroup2_join(deadline: Instant) -> Result<()> {
    // Borrow `WORKSPACE_READY_FD` without closing it; `BootstrapChild` and
    // `publish_workspace_readiness` continue using the same descriptor.
    let mut borrowed = unsafe {
        // SAFETY: `WORKSPACE_READY_FD` is open for this process's lifetime
        // until `publish_workspace_readiness` takes ownership.
        let duplicated = rustix::io::fcntl_dupfd_cloexec(
            std::os::fd::BorrowedFd::borrow_raw(WORKSPACE_READY_FD),
            10,
        )
        .context("duplicate workspace readiness channel for cgroup2 join")?;
        UnixStream::from(duplicated)
    };
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::from_secs(1));
    borrowed
        .set_read_timeout(Some(timeout))
        .context("bound cgroup2 join read")?;
    borrowed
        .set_write_timeout(Some(timeout))
        .context("bound cgroup2 join write")?;
    borrowed
        .write_all(CGROUP_JOIN_REQUEST)
        .context("request delegated cgroup2 join")?;
    borrowed.flush().context("flush delegated cgroup2 join")?;
    let mut ack = [0_u8; CGROUP_JOIN_ACK.len()];
    borrowed
        .read_exact(&mut ack)
        .context("receive delegated cgroup2 join acknowledgement")?;
    ensure!(
        ack == CGROUP_JOIN_ACK,
        "invalid delegated cgroup2 join acknowledgement"
    );
    Ok(())
}

/// Remove `CAP_SYS_ADMIN` from the bounding set and reduce effective/permitted
/// capabilities to [`WORKLOAD_ROOT_CAPABILITIES_MASK`]. Fails closed if
/// `CAP_SYS_ADMIN` remains present in the bounding set.
fn drop_sys_admin_permanently() -> Result<()> {
    // SAFETY: `PR_CAPBSET_DROP` takes only the integer capability number.
    if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error())
            .context("drop CAP_SYS_ADMIN from workspace bounding set");
    }
    // SAFETY: `PR_CAP_AMBIENT` with `PR_CAP_AMBIENT_CLEAR_ALL` takes zeroes.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == -1
    {
        return Err(io::Error::last_os_error()).context("clear ambient capabilities");
    }
    set_workload_root_capabilities()
        .context("restrict workspace capabilities after cgroup mount")?;
    // SAFETY: `PR_CAPBSET_READ` queries whether the bit is still in `CapBnd`.
    let remaining = unsafe { libc::prctl(libc::PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0) };
    ensure!(
        remaining == 0,
        "CAP_SYS_ADMIN remained in workspace bounding set"
    );
    Ok(())
}

fn set_workload_root_capabilities() -> io::Result<()> {
    let mut header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        LinuxCapabilityData {
            effective: WORKLOAD_ROOT_CAPABILITIES_MASK,
            permitted: WORKLOAD_ROOT_CAPABILITIES_MASK,
            inheritable: 0,
        },
        LinuxCapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: `header` and `data` match the Linux v3 `capset` ABI layout.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn prepare_runtime_directories_and_masks(
    run_lock_dir: &Path,
    runtime_units_dir: &Path,
    etc_units_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(run_lock_dir)
        .with_context(|| format!("create {}", run_lock_dir.display()))?;
    mask_units_in(runtime_units_dir, &MASKED_RUNTIME_UNITS)?;
    mask_units_in(etc_units_dir, &MASKED_ETC_UNITS)?;
    Ok(())
}

fn mask_units_in(units_dir: &Path, units: &[&str]) -> Result<()> {
    fs::create_dir_all(units_dir).with_context(|| format!("create {}", units_dir.display()))?;
    for unit in units {
        let link = units_dir.join(unit);
        if link.symlink_metadata().is_ok() {
            fs::remove_file(&link).with_context(|| format!("replace {}", link.display()))?;
        }
        symlink("/dev/null", &link)
            .with_context(|| format!("mask systemd unit {}", link.display()))?;
    }
    Ok(())
}

/// Open the hosted daemon's dedicated cgroup v2 `cgroup.procs` file so
/// `spawn_workspace_process` can move the daemon out of the container root
/// cgroup before dropping uid/gid.
pub(super) fn open_daemon_scope_procs() -> Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .open(CONTAINER_DAEMON_SCOPE_PROCS_PATH)
        .context("open init.scope cgroup.procs")
}

/// Container-PID-1 side: hand PID 1 over to `/sbin/init` (`systemd`).
/// Never returns on success.
pub(super) fn exec_systemd() -> Result<()> {
    // Restore the OCI root capability set (without CAP_SYS_ADMIN, which was
    // dropped from CapBnd earlier) so systemd can manage units and user
    // sessions cleanly.
    set_workload_root_capabilities().context("set systemd capability set")?;

    let program = CString::new(SYSTEMD_INIT_PATH).expect("static path has no NUL");
    let argv = [program.as_ptr(), std::ptr::null()];
    let env_entries = [
        CString::new("container=oci").expect("static env has no NUL"),
        CString::new("HOME=/root").expect("static env has no NUL"),
        CString::new("USER=root").expect("static env has no NUL"),
        CString::new("SHELL=/bin/sh").expect("static env has no NUL"),
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .expect("static env has no NUL"),
        CString::new("LANG=C.UTF-8").expect("static env has no NUL"),
    ];
    let mut envp: Vec<*const libc::c_char> = env_entries.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: `program`, `argv`, and `envp` are valid NUL-terminated arrays
    // kept alive through the `execve` call. All private init descriptors
    // (readiness, listener, log pipe) are either already closed or `O_CLOEXEC`.
    unsafe {
        libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    Err(io::Error::last_os_error()).context("exec /sbin/init for systemd workspace")
}

/// Guest-init side: wait for the container's workspace user manager bus
/// (`/run/user/<uid>/bus`) to appear so `systemctl --user` works immediately
/// once the sandbox reports ready.
pub(super) fn wait_for_user_manager(
    uid: u32,
    workspace: &mut std::process::Child,
    deadline: Instant,
) -> Result<()> {
    loop {
        if let Some(status) = workspace
            .try_wait()
            .context("observe systemd workspace container while waiting for user manager")?
        {
            bail!("systemd workspace container exited ({status}) before user manager became ready");
        }
        if let Some(init_pid) = super::shutdown::container_init_pid() {
            let bus = format!("/proc/{init_pid}/root/run/user/{uid}/bus");
            if fs::symlink_metadata(&bus).is_ok() {
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "systemd user manager (/run/user/{uid}/bus) did not become ready in time"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

/// Guest-init side: verify `path` is mounted as `cgroup2`.
fn verify_cgroup2_filesystem(path: &str) -> Result<()> {
    let mut statistics: libc::statfs = unsafe { std::mem::zeroed() };
    let target = CString::new(path).context("cgroup2 path contains NUL")?;
    // SAFETY: `target` is NUL-terminated and `statistics` is a valid stack struct.
    if unsafe { libc::statfs(target.as_ptr(), &mut statistics) } == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("inspect cgroup v2 mount at {path}"));
    }
    ensure!(
        u64::try_from(statistics.f_type).unwrap_or_default() == CGROUP2_SUPER_MAGIC,
        "cgroup v2 mount at {path} has the wrong filesystem type"
    );
    Ok(())
}

/// Ensure `XDG_RUNTIME_DIR=/run/user/<uid>` is present in the hosted daemon's
/// environment so every session it spawns reaches the workspace user's systemd
/// manager.
pub(super) fn ensure_xdg_runtime_dir(environment: &mut Vec<String>, uid: u32) {
    let value = format!("XDG_RUNTIME_DIR=/run/user/{uid}");
    environment.retain(|entry| {
        entry
            .split_once('=')
            .is_none_or(|(key, _)| key != "XDG_RUNTIME_DIR")
    });
    environment.push(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_root_capabilities_mask_excludes_privileged_caps() {
        // Must exclude CAP_SYS_ADMIN (21), CAP_SYS_MODULE (16),
        // CAP_SYS_RAWIO (17), and CAP_SYS_BOOT (22).
        for forbidden in [16_u32, 17, 21, 22] {
            assert_eq!(
                WORKLOAD_ROOT_CAPABILITIES_MASK & (1 << forbidden),
                0,
                "bit {forbidden} must not be in WORKLOAD_ROOT_CAPABILITIES_MASK"
            );
        }
        // Must contain exactly 14 capabilities matching WORKLOAD_ROOT_CAPABILITIES.
        assert_eq!(
            WORKLOAD_ROOT_CAPABILITIES_MASK.count_ones() as usize,
            codewire_daemon::execution::WORKLOAD_ROOT_CAPABILITIES.len()
        );
    }

    #[test]
    fn prepare_runtime_directories_masks_daemon_and_docker_units() {
        let root = tempfile::tempdir().unwrap();
        let lock_dir = root.path().join("lock");
        let runtime_dir = root.path().join("run/systemd/system");
        let etc_dir = root.path().join("etc/systemd/system");
        fs::create_dir_all(&etc_dir).unwrap();
        fs::write(etc_dir.join("codewire-daemon.service"), b"[Unit]\n").unwrap();
        prepare_runtime_directories_and_masks(&lock_dir, &runtime_dir, &etc_dir).unwrap();
        assert!(lock_dir.is_dir());
        for unit in MASKED_RUNTIME_UNITS {
            assert_eq!(
                fs::read_link(runtime_dir.join(unit)).unwrap(),
                Path::new("/dev/null")
            );
        }
        for unit in MASKED_ETC_UNITS {
            assert_eq!(
                fs::read_link(etc_dir.join(unit)).unwrap(),
                Path::new("/dev/null")
            );
        }
        // Idempotent on re-run.
        prepare_runtime_directories_and_masks(&lock_dir, &runtime_dir, &etc_dir).unwrap();
    }

    #[test]
    fn ensure_xdg_runtime_dir_replaces_existing_entry() {
        let mut env = vec![
            "HOME=/home/codewire".to_owned(),
            "XDG_RUNTIME_DIR=/tmp/wrong".to_owned(),
        ];
        ensure_xdg_runtime_dir(&mut env, 1000);
        assert_eq!(
            env,
            vec![
                "HOME=/home/codewire".to_owned(),
                "XDG_RUNTIME_DIR=/run/user/1000".to_owned(),
            ]
        );
    }
}
