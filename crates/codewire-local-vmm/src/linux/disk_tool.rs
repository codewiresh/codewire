//! Host e2fsprogs that work on a guest-written disk.
//!
//! Growing a state disk runs the host's `e2fsck` and `resize2fs` on a
//! filesystem the guest wrote, so a parser bug in either is reachable from
//! inside the VM. Each runs as the user with no capabilities and
//! `no_new_privs`, in a Landlock domain that can read and write only that disk
//! ([`super::confinement::prepare_disk_tool_filesystem_domain`]), and under a
//! seccomp filter that refuses sockets, new processes, signals to other
//! processes, and other kernel interfaces neither tool uses. It dies with the
//! runner and inherits no descriptor beyond its standard streams.

use std::io;
use std::path::Path;

use super::confinement::{
    PreparedSyscallFilter, lock_exec_process_privileges, prepare_disk_tool_filesystem_domain,
};

const DISK_TOOL_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_send_signal,
    libc::SYS_process_madvise,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_memfd_create,
    libc::SYS_reboot,
];

#[cfg(target_arch = "x86_64")]
const DISK_TOOL_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const DISK_TOOL_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

/// `program leading_args... disk` confined to `disk`, where `program` is a
/// trusted e2fsprogs path from [`super::e2fsprogs`]. The caller sets the
/// environment and standard streams.
pub(crate) fn command(
    program: &Path,
    leading_args: &[&str],
    disk: &Path,
) -> io::Result<tokio::process::Command> {
    let mut command = confined_to(program, disk)?;
    command.args(leading_args).arg(disk);
    Ok(command)
}

/// `program`, with no arguments yet, confined to `disk`.
fn confined_to(program: &Path, disk: &Path) -> io::Result<tokio::process::Command> {
    let filesystem_domain = prepare_disk_tool_filesystem_domain(disk, program)?;
    let mut filter =
        PreparedSyscallFilter::denying(DISK_TOOL_DENIED_SYSCALLS, DISK_TOOL_ARCH_DENIED_SYSCALLS);
    let expected_parent_pid = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(program);
    command.kill_on_drop(true);
    // SAFETY: only direct syscalls run between fork and exec; the filter and
    // the Landlock ruleset were built before the fork.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            lock_exec_process_privileges()?;
            filter.install()?;
            filesystem_domain.restrict_self()?;
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

#[cfg(test)]
mod tests;
