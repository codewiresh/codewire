//! The syscalls every confined host process that serves an environment
//! denies, whatever else its own list adds, so the lists cannot drift
//! apart (#3999). They cover:
//! - signalling or inspecting another process, including the queued-signal
//!   calls, which reach any process of the same user;
//! - new mounts, namespaces and kernel modules;
//! - kernel attack surface a server never needs: io_uring, BPF, perf,
//!   userfaultfd and the keyring;
//! - exec, swap and reboot;
//! - another process's resource limits.

/// The floor, for `install_denied_syscalls` and the credential broker.
pub const DENIED_SYSCALL_FLOOR: &[libc::c_long] = &[
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_add_key,
    libc::SYS_bind,
    libc::SYS_bpf,
    libc::SYS_delete_module,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_finit_module,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fsopen,
    libc::SYS_fspick,
    libc::SYS_init_module,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_io_uring_setup,
    libc::SYS_kcmp,
    libc::SYS_keyctl,
    libc::SYS_kill,
    libc::SYS_listen,
    libc::SYS_mount,
    libc::SYS_mount_setattr,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_open_by_handle_at,
    libc::SYS_perf_event_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    libc::SYS_pivot_root,
    libc::SYS_prlimit64,
    libc::SYS_process_madvise,
    libc::SYS_process_mrelease,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_prctl,
    libc::SYS_ptrace,
    libc::SYS_reboot,
    libc::SYS_request_key,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_setns,
    libc::SYS_socketpair,
    libc::SYS_swapoff,
    libc::SYS_swapon,
    libc::SYS_tgkill,
    libc::SYS_tkill,
    libc::SYS_umount2,
    libc::SYS_unshare,
    libc::SYS_userfaultfd,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_denies_every_way_to_signal_another_process() {
        for call in [
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_rt_tgsigqueueinfo,
            libc::SYS_pidfd_send_signal,
        ] {
            assert!(DENIED_SYSCALL_FLOOR.contains(&call), "{call}");
        }
    }
}
