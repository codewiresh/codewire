//! Process confinement primitives for Codewire's single-purpose host workers.
//!
//! On Linux: the single-thread check, the capability and privilege locks,
//! Landlock filesystem domains and seccomp deny lists. On macOS: Seatbelt
//! profiles and the single-thread check. The local runtime's workers and
//! cw-egress's confined worker and broker share them (#4000).

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "linux")]
pub mod linux;
