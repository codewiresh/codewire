//! The shared syscall floor is `codewire-confinement`'s, so cw-egress's
//! front door denies the same calls (#4001).

pub use codewire_confinement::syscall_floor::DENIED_SYSCALL_FLOOR;
