use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{FromRawFd as _, OwnedFd};

const MINIMUM_BROKER_LANDLOCK_ABI: i32 = 4;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_SOCKET_DOMAIN_OFFSET: u32 = 16;
const SECCOMP_DATA_SOCKET_TYPE_OFFSET: u32 = 24;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SOCKET_TYPE_MASK: u32 = 0x0f;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketFilter {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

#[repr(C)]
struct SocketFilterProgram {
    length: u16,
    filters: *const SocketFilter,
}

/// Apply the irreversible broker domain after all startup-only filesystem,
/// DNS, supervisor, and guest-channel work is complete. Existing descriptors
/// remain usable; future filesystem opens, TCP destinations other than port
/// 443, datagram/raw sockets, listeners, process execution, and high-risk
/// process-control syscalls fail closed.
pub(super) fn apply_broker_runtime_confinement() -> io::Result<()> {
    apply_broker_landlock_confinement()?;
    apply_broker_seccomp_confinement()
}

/// Enter the filesystem, remote-port, and signal Landlock domain before
/// establishing the broker's one encrypted Secret Service connection.
pub(super) fn apply_broker_landlock_confinement() -> io::Result<()> {
    verify_single_threaded()?;
    apply_landlock()
}

/// Seal syscall and socket creation after every required Unix connection is
/// already open. New sockets are limited to provider TCP over IPv4 or IPv6.
pub(super) fn apply_broker_seccomp_confinement() -> io::Result<()> {
    apply_seccomp()
}

/// Checked-in host verification entrypoint for the exact broker process
/// sandbox. It never opens credential storage or performs network I/O.
pub(crate) async fn run_local_credential_broker_confinement_probe() -> anyhow::Result<()> {
    // SAFETY: this scalar prctl affects only this dedicated disposable process.
    anyhow::ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "enable broker probe no-new-privileges"
    );
    // SAFETY: this is a scalar query of the current disposable process.
    anyhow::ensure!(
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "broker probe became dumpable after exec"
    );
    apply_broker_runtime_confinement()?;
    anyhow::ensure!(
        std::fs::File::open("/etc/passwd").is_err(),
        "broker filesystem confinement did not deny a new read"
    );
    anyhow::ensure!(
        UdpSocket::bind("127.0.0.1:0").is_err(),
        "broker socket confinement did not deny UDP"
    );
    anyhow::ensure!(
        TcpListener::bind("127.0.0.1:0").is_err(),
        "broker socket confinement did not deny TCP listen"
    );
    anyhow::ensure!(
        TcpStream::connect("127.0.0.1:80").is_err(),
        "broker network confinement did not deny non-provider TCP"
    );
    // SAFETY: this disposable probe closes the descriptor if the filter
    // unexpectedly admits new Unix sockets.
    let unix_socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if unix_socket >= 0 {
        // SAFETY: a nonnegative result is owned by this probe.
        unsafe { libc::close(unix_socket) };
    }
    anyhow::ensure!(
        unix_socket < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "broker socket confinement did not deny new Unix sockets"
    );
    let mut io_uring_parameters = [0_u64; 32];
    // SAFETY: the disposable probe supplies writable, zero-initialized storage
    // larger than Linux's fixed io_uring_params structure. The seccomp filter
    // must reject the call before the kernel consumes it.
    let io_uring = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1_u32,
            io_uring_parameters.as_mut_ptr(),
        )
    };
    if io_uring >= 0 {
        // SAFETY: a nonnegative result is an owned descriptor returned only to
        // this disposable probe.
        unsafe { libc::close(io_uring as libc::c_int) };
    }
    anyhow::ensure!(
        io_uring < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "broker syscall confinement did not deny io_uring"
    );
    // SAFETY: signal zero performs only a permission/existence check. The
    // broker filter must reject even signalling its own process.
    let signal = unsafe { libc::kill(libc::getpid(), 0) };
    anyhow::ensure!(
        signal < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "broker syscall confinement did not deny process signalling"
    );
    // SAFETY: this scalar call would make the process ptrace/core-dump
    // eligible if the filter failed to reject it.
    let dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
    anyhow::ensure!(
        dumpable < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "broker syscall confinement did not preserve non-dumpable state"
    );
    let worker_confined =
        tokio::task::spawn_blocking(|| std::fs::File::open("/etc/passwd").is_err())
            .await
            .map_err(|_| anyhow::anyhow!("broker confinement blocked protected-store worker"))?;
    anyhow::ensure!(
        worker_confined,
        "broker protected-store worker escaped filesystem confinement"
    );
    Ok(())
}

fn verify_single_threaded() -> io::Result<()> {
    let mut tasks = std::fs::read_dir("/proc/self/task")?;
    if tasks.next().transpose()?.is_none() || tasks.next().transpose()?.is_some() {
        return Err(io::Error::other(
            "credential broker must enter Landlock before creating worker threads",
        ));
    }
    Ok(())
}

fn apply_landlock() -> io::Result<()> {
    let abi = landlock_abi()?;
    if abi < MINIMUM_BROKER_LANDLOCK_ABI {
        return Err(io::Error::other(format!(
            "credential broker requires Landlock ABI {MINIMUM_BROKER_LANDLOCK_ABI}, found {abi}"
        )));
    }
    let attributes = LandlockRulesetAttr {
        handled_access_fs: filesystem_access_for_abi(abi),
        handled_access_net: LANDLOCK_ACCESS_NET_CONNECT_TCP,
        scoped: scopes_for_abi(abi),
    };
    // SAFETY: the kernel reads exactly the initialized ruleset structure for
    // this syscall and returns a new descriptor on success.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::addr_of!(attributes),
            std::mem::size_of::<LandlockRulesetAttr>(),
            0_u32,
        )
    };
    if ruleset_fd < 0 || ruleset_fd > libc::c_int::MAX as libc::c_long {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of the newly returned descriptor is transferred once.
    let ruleset_fd = unsafe { OwnedFd::from_raw_fd(ruleset_fd as libc::c_int) };
    let port = LandlockNetPortAttr {
        allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
        port: 443,
    };
    // SAFETY: the ruleset descriptor and fixed-layout port attribute remain
    // valid for the duration of the syscall.
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            std::os::fd::AsRawFd::as_raw_fd(&ruleset_fd),
            LANDLOCK_RULE_NET_PORT,
            std::ptr::addr_of!(port),
            0_u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: restriction consumes no userspace pointer and affects only this
    // single-threaded process plus threads it creates afterward.
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            std::os::fd::AsRawFd::as_raw_fd(&ruleset_fd),
            0_u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn landlock_abi() -> io::Result<i32> {
    // SAFETY: the VERSION query requires a null attribute and zero size.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 || abi > i32::MAX as libc::c_long {
        return Err(io::Error::last_os_error());
    }
    Ok(abi as i32)
}

fn filesystem_access_for_abi(abi: i32) -> u64 {
    // ABI 4 includes EXECUTE through TRUNCATE. ABI 5 adds IOCTL_DEV. The
    // ABI-9 RESOLVE_UNIX right is intentionally not handled while entering
    // Landlock: startup must reach the user's exact inherited Secret Service
    // socket once. Seccomp then denies every new Unix socket.
    let mut access = (1_u64 << 15) - 1;
    if abi >= 5 {
        access |= 1_u64 << 15;
    }
    access
}

fn scopes_for_abi(abi: i32) -> u64 {
    if abi >= 6 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    }
}

fn apply_seccomp() -> io::Result<()> {
    let filters = seccomp_filters();
    let length = u16::try_from(filters.len())
        .map_err(|_| io::Error::other("credential broker seccomp filter is too large"))?;
    let program = SocketFilterProgram {
        length,
        filters: filters.as_ptr(),
    };
    // SAFETY: the kernel copies the fixed-length classic-BPF program during
    // the syscall. no_new_privs was set by the authority before exec.
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            std::ptr::addr_of!(program),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn seccomp_filters() -> Vec<SocketFilter> {
    let denied = [
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
    let denied_result = SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1);
    let mut filters = vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    for syscall in denied {
        filters.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filters.push(statement(BPF_RET_K, denied_result));
    }
    filters.extend([
        jump(BPF_JMP_JEQ_K, libc::SYS_socket as u32, 0, 8),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_SOCKET_DOMAIN_OFFSET),
        jump(BPF_JMP_JEQ_K, libc::AF_INET as u32, 2, 0),
        jump(BPF_JMP_JEQ_K, libc::AF_INET6 as u32, 1, 0),
        statement(BPF_RET_K, denied_result),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_SOCKET_TYPE_OFFSET),
        statement(BPF_ALU_AND_K, SOCKET_TYPE_MASK),
        jump(BPF_JMP_JEQ_K, libc::SOCK_STREAM as u32, 1, 0),
        statement(BPF_RET_K, denied_result),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    filters
}

const fn statement(code: u16, value: u32) -> SocketFilter {
    SocketFilter {
        code,
        jump_true: 0,
        jump_false: 0,
        value,
    }
}

const fn jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> SocketFilter {
    SocketFilter {
        code,
        jump_true,
        jump_false,
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_policy_handles_files_and_only_tcp_connect_443() {
        assert_eq!(filesystem_access_for_abi(4), (1_u64 << 15) - 1);
        assert_eq!(filesystem_access_for_abi(5), (1_u64 << 16) - 1);
        assert_eq!(scopes_for_abi(5), 0);
        assert_eq!(
            scopes_for_abi(6),
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
        );
    }

    #[test]
    fn seccomp_policy_denies_non_stream_sockets_listeners_and_exec() {
        let filters = seccomp_filters();
        for syscall in [
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_socketpair,
            libc::SYS_execve,
            libc::SYS_prctl,
            libc::SYS_ptrace,
            libc::SYS_kill,
            libc::SYS_pidfd_send_signal,
            libc::SYS_io_uring_setup,
            libc::SYS_fsconfig,
            libc::SYS_fsopen,
            libc::SYS_open_tree,
        ] {
            assert!(
                filters.iter().any(|filter| {
                    filter.code == BPF_JMP_JEQ_K && filter.value == syscall as u32
                })
            );
        }
        assert!(
            filters
                .iter()
                .any(|filter| { filter.code == BPF_ALU_AND_K && filter.value == SOCKET_TYPE_MASK })
        );
        let socket = filters
            .iter()
            .position(|filter| {
                filter.code == BPF_JMP_JEQ_K && filter.value == libc::SYS_socket as u32
            })
            .unwrap();
        assert_eq!(
            &filters[(socket + 2)..(socket + 4)],
            &[
                jump(BPF_JMP_JEQ_K, libc::AF_INET as u32, 2, 0),
                jump(BPF_JMP_JEQ_K, libc::AF_INET6 as u32, 1, 0),
            ]
        );
        assert_eq!(
            filters.last(),
            Some(&statement(BPF_RET_K, SECCOMP_RET_ALLOW))
        );
    }
}
