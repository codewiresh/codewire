//! Shared Linux confinement primitives for single-purpose local runtime workers.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;

use rustix::fs::{Mode, OFlags, open};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_HANDLED_ACCESS_FS_V3: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_DATA_SYSCALL_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGUMENT_0_OFFSET: u32 = 16;
const SECCOMP_DATA_ARGUMENT_1_OFFSET: u32 = 24;
const SECCOMP_DATA_ARGUMENT_2_OFFSET: u32 = 32;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

pub(crate) struct PreparedFilesystemDomain(OwnedFd);

impl PreparedFilesystemDomain {
    #[cfg(test)]
    pub(crate) fn descriptor_for_test(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub(crate) fn restrict_self(&self) -> io::Result<()> {
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, self.0.as_raw_fd(), 0_u32) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(crate) fn prepare_virtiofsd_filesystem_domain(
    source_fd: RawFd,
    socket_directory: &Path,
    executable: &Path,
    read_only: bool,
) -> io::Result<PreparedFilesystemDomain> {
    let ruleset = create_filesystem_ruleset()?;
    // Guest execution reads file data through FUSE; it never requires the
    // host daemon itself to execute anything from the selected source.
    let source_access = if read_only {
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    } else {
        LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SYM
            | LANDLOCK_ACCESS_FS_REFER
            | LANDLOCK_ACCESS_FS_TRUNCATE
    };
    add_path_beneath_rule(&ruleset, source_fd, source_access)?;

    let socket_directory = open(
        socket_directory,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    add_path_beneath_rule(
        &ruleset,
        socket_directory.as_raw_fd(),
        LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_TRUNCATE,
    )?;

    add_opened_rule(
        &ruleset,
        executable,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
    )?;
    add_opened_rule(
        &ruleset,
        Path::new("/usr/lib"),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    )?;
    add_opened_rule(
        &ruleset,
        Path::new("/etc/ld.so.cache"),
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        LANDLOCK_ACCESS_FS_READ_FILE,
    )?;
    // virtiofsd validates even an explicit --rlimit-nofile against this
    // kernel ceiling before publishing its vhost-user socket.
    add_opened_rule(
        &ruleset,
        Path::new("/proc/sys/fs/nr_open"),
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        LANDLOCK_ACCESS_FS_READ_FILE,
    )?;
    Ok(PreparedFilesystemDomain(ruleset))
}

fn create_filesystem_ruleset() -> io::Result<OwnedFd> {
    let attributes = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_HANDLED_ACCESS_FS_V3,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attributes,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0_u32,
        )
    };
    if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
}

fn add_opened_rule(ruleset: &OwnedFd, path: &Path, flags: OFlags, access: u64) -> io::Result<()> {
    let descriptor = open(path, flags, Mode::empty())?;
    add_path_beneath_rule(ruleset, descriptor.as_raw_fd(), access)
}

fn add_path_beneath_rule(
    ruleset: &OwnedFd,
    parent_fd: RawFd,
    allowed_access: u64,
) -> io::Result<()> {
    let attributes = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const attributes,
            0_u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub(crate) fn require_single_threaded_process() -> io::Result<()> {
    let mut tasks = std::fs::read_dir("/proc/self/task")?;
    if tasks.next().transpose()?.is_none() || tasks.next().transpose()?.is_some() {
        return Err(io::Error::other("process is not single threaded"));
    }
    Ok(())
}

/// Permanently discard process capabilities, ambient capability inheritance,
/// ptrace/core-dump visibility, and future privilege gains.
pub(crate) fn lock_process_privileges() -> io::Result<()> {
    lock_process_privileges_inner(true)
}

/// Permanently discard executable privilege gains while retaining ordinary
/// same-UID process observability for a parent that must admit the exec result.
///
/// This variant is for a directly spawned helper: setting `PR_SET_DUMPABLE`
/// before exec would prevent the parent from validating `/proc/<pid>/exe`.
pub(crate) fn lock_exec_process_privileges() -> io::Result<()> {
    lock_process_privileges_inner(false)
}

fn lock_process_privileges_inner(disable_dumpability: bool) -> io::Result<()> {
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
        return Err(io::Error::last_os_error());
    }
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [empty; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if disable_dumpability && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}

/// Enter a Landlock v3 domain with no filesystem rules. Callers must finish
/// loading configuration before this point and operate only on admitted file
/// descriptors afterward.
pub(crate) fn install_deny_all_filesystem_domain() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    create_filesystem_ruleset().and_then(|domain| PreparedFilesystemDomain(domain).restrict_self())
}

pub(crate) fn install_denied_syscalls(
    denied: &[libc::c_long],
    architecture_denied: &[libc::c_long],
) -> io::Result<()> {
    let mut filter = base_filter();
    append_denials(&mut filter, denied.iter().chain(architecture_denied));
    filter.push(bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    install_filter(&mut filter)
}

/// Make `setgroups(2)` an identity-preserving successful no-op.
///
/// A direct-share virtiofsd maps every guest GID to the daemon's existing
/// effective GID and runs without capabilities. Linux may nevertheless attach
/// the parent directory's GID to a create request through the FUSE
/// supplementary-group extension, and virtiofsd unconditionally calls
/// `setgroups(2)` when that extension is present. The call cannot change the
/// intended identity, but would fail with `EPERM` after capabilities are
/// discarded. Returning success without executing it preserves the already
/// locked host identity and prevents the daemon from changing its inherited
/// supplementary groups through any future request.
pub(crate) fn install_identity_preserving_setgroups_filter() -> io::Result<()> {
    let mut filter = base_filter();
    filter.extend([
        bpf_equal(libc::SYS_setgroups as u32, 0, 1),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    install_filter(&mut filter)
}

/// Install a deny list plus an argument filter allowing newly created sockets
/// only for IPv4/IPv6 TCP or UDP, including an exact protocol check. Already-
/// inherited AF_UNIX capabilities remain usable for ordinary read/write and
/// sendmsg operations.
pub(crate) fn install_inet_socket_only_syscalls(
    denied: &[libc::c_long],
    architecture_denied: &[libc::c_long],
) -> io::Result<()> {
    install_inet_socket_syscalls(denied, architecture_denied, false)
}

/// Install a deny list while allowing newly created sockets only for IPv4 or
/// IPv6 TCP. This is used by one-shot HTTPS control-plane workers which finish
/// DNS resolution before confinement and have no reason to retain UDP or Unix
/// socket creation authority.
pub(crate) fn install_inet_stream_only_syscalls(
    denied: &[libc::c_long],
    architecture_denied: &[libc::c_long],
) -> io::Result<()> {
    let mut filter = base_filter();
    append_denials(&mut filter, denied.iter().chain(architecture_denied));
    filter.extend([
        bpf_equal(libc::SYS_socket as u32, 0, 11),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_0_OFFSET),
        bpf_equal(libc::AF_INET as u32, 1, 0),
        bpf_equal(libc::AF_INET6 as u32, 0, 7),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_1_OFFSET),
        bpf_statement(
            BPF_ALU_AND_K,
            !((libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32),
        ),
        bpf_equal(libc::SOCK_STREAM as u32, 0, 4),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_2_OFFSET),
        bpf_equal(0, 1, 0),
        bpf_equal(libc::IPPROTO_TCP as u32, 0, 1),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]);
    install_filter(&mut filter)
}

/// Install the same INET socket filter while also permitting only
/// `socketpair(AF_UNIX, SOCK_STREAM, 0)`. This gives an isolated transport a
/// way to hand an accepted stream to its parent without admitting arbitrary
/// local socket creation.
pub(crate) fn install_inet_and_unix_stream_pair_syscalls(
    denied: &[libc::c_long],
    architecture_denied: &[libc::c_long],
) -> io::Result<()> {
    install_inet_socket_syscalls(denied, architecture_denied, true)
}

fn install_inet_socket_syscalls(
    denied: &[libc::c_long],
    architecture_denied: &[libc::c_long],
    allow_unix_stream_pair: bool,
) -> io::Result<()> {
    let mut filter = base_filter();
    append_denials(&mut filter, denied.iter().chain(architecture_denied));
    filter.extend([
        bpf_equal(libc::SYS_socket as u32, 0, 15),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_0_OFFSET),
        bpf_equal(libc::AF_INET as u32, 1, 0),
        bpf_equal(libc::AF_INET6 as u32, 0, 11),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_1_OFFSET),
        bpf_statement(
            BPF_ALU_AND_K,
            !((libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32),
        ),
        bpf_equal(libc::SOCK_STREAM as u32, 1, 0),
        bpf_equal(libc::SOCK_DGRAM as u32, 3, 7),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_2_OFFSET),
        bpf_equal(0, 4, 0),
        bpf_equal(libc::IPPROTO_TCP as u32, 3, 4),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_2_OFFSET),
        bpf_equal(0, 1, 0),
        bpf_equal(libc::IPPROTO_UDP as u32, 0, 1),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ]);
    if allow_unix_stream_pair {
        filter.extend([
            bpf_equal(libc::SYS_socketpair as u32, 0, 9),
            bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_0_OFFSET),
            bpf_equal(libc::AF_UNIX as u32, 0, 6),
            bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_1_OFFSET),
            bpf_statement(
                BPF_ALU_AND_K,
                !((libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32),
            ),
            bpf_equal(libc::SOCK_STREAM as u32, 0, 3),
            bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_2_OFFSET),
            bpf_equal(0, 0, 1),
            bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
            bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
            bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]);
    } else {
        filter.push(bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    }
    install_filter(&mut filter)
}

fn base_filter() -> Vec<libc::sock_filter> {
    let mut filter = vec![
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        bpf_equal(AUDIT_ARCH_NATIVE, 1, 0),
        bpf_statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_SYSCALL_OFFSET),
    ];
    // x32 uses the x86_64 audit architecture with a bit added to every
    // syscall number. Reject it before comparing the native deny list so it
    // cannot select an unfiltered alternate syscall table.
    #[cfg(target_arch = "x86_64")]
    filter.extend([
        bpf_greater_or_equal(X32_SYSCALL_BIT, 0, 1),
        bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ]);
    filter
}

fn append_denials<'a>(
    filter: &mut Vec<libc::sock_filter>,
    denied: impl Iterator<Item = &'a libc::c_long>,
) {
    for syscall in denied {
        filter.push(bpf_equal(*syscall as u32, 0, 1));
        filter.push(bpf_statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
}

fn install_filter(filter: &mut [libc::sock_filter]) -> io::Result<()> {
    let length = u16::try_from(filter.len())
        .map_err(|_| io::Error::other("seccomp filter exceeds kernel length"))?;
    let program = libc::sock_fprog {
        len: length,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 1_u32, 0_u32, &raw const program) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const fn bpf_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn bpf_equal(value: u32, equal: u8, unequal: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: equal,
        jf: unequal,
        k: value,
    }
}

#[cfg(target_arch = "x86_64")]
const fn bpf_greater_or_equal(value: u32, greater_or_equal: u8, less: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JGE_K,
        jt: greater_or_equal,
        jf: less,
        k: value,
    }
}
