//! How a front-door process confines itself on Linux, the local VM's
//! (#3999) and cw-egress's (#4001) alike: no new privileges, no filesystem,
//! and a syscall filter that refuses new sockets, connections, processes and
//! identity changes on top of the shared floor. It works only with the
//! descriptors it already holds and those passed to it.

use codewire_confinement::linux::{
    install_denied_syscalls, install_deny_all_filesystem_domain, lock_process_privileges,
};
use codewire_confinement::syscall_floor::DENIED_SYSCALL_FLOOR;

/// What a front door refuses after it starts, beyond the shared floor. The
/// process makes no connection, opens no file and starts nothing.
const FRONT_DOOR_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_connect,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_name_to_handle_at,
    libc::SYS_capset,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
];
#[cfg(target_arch = "x86_64")]
const FRONT_DOOR_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const FRONT_DOOR_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

/// The shared floor and the front door's own denials.
pub fn front_door_denied_syscalls() -> Vec<libc::c_long> {
    [DENIED_SYSCALL_FLOOR, FRONT_DOOR_DENIED_SYSCALLS].concat()
}

/// Confines the calling process for good. The syscall filter binds the
/// calling thread and the threads it starts later, so the caller makes sure
/// no other thread exists yet.
pub fn confine_front_door() -> std::io::Result<()> {
    lock_process_privileges()
        .and_then(|()| install_deny_all_filesystem_domain())
        .and_then(|()| {
            install_denied_syscalls(
                &front_door_denied_syscalls(),
                FRONT_DOOR_ARCH_DENIED_SYSCALLS,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_front_door_denies_the_shared_floor_and_its_own_calls() {
        let denied = front_door_denied_syscalls();
        for call in DENIED_SYSCALL_FLOOR.iter().chain([
            &libc::SYS_socket,
            &libc::SYS_connect,
            &libc::SYS_clone,
            &libc::SYS_clone3,
        ]) {
            assert!(denied.contains(call), "{call}");
        }
    }

    /// The front door's own denials, exactly: the descriptors it is handed
    /// (its hand-off and each credential session, #4001) need no call these
    /// refuse, so any change to the list is a change to its boundary, made
    /// here on purpose.
    #[test]
    fn the_front_doors_own_denials_are_pinned() {
        assert_eq!(
            FRONT_DOOR_DENIED_SYSCALLS,
            &[
                libc::SYS_socket,
                libc::SYS_connect,
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_name_to_handle_at,
                libc::SYS_capset,
                libc::SYS_setuid,
                libc::SYS_setgid,
                libc::SYS_setreuid,
                libc::SYS_setregid,
                libc::SYS_setresuid,
                libc::SYS_setresgid,
                libc::SYS_setfsuid,
                libc::SYS_setfsgid,
                libc::SYS_setgroups,
            ]
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            FRONT_DOOR_ARCH_DENIED_SYSCALLS,
            &[libc::SYS_fork, libc::SYS_vfork]
        );
        #[cfg(target_arch = "aarch64")]
        assert!(FRONT_DOOR_ARCH_DENIED_SYSCALLS.is_empty());
    }
}
