//! The incarnation of the process that admits environment runtime leases
//! (#4523). An orchestration process picks a random key at start and writes a
//! heartbeat for it while it lives. Every runtime lease it admits records the
//! key, so a lease whose owner has long stopped writing one has no living
//! owner. A process that never sets one records none, and its leases are never
//! taken for abandoned.

use std::sync::OnceLock;

static INCARNATION: OnceLock<i64> = OnceLock::new();

/// Records this process's incarnation, once, before it admits a lease.
/// Returns false if one was already set.
pub fn set_incarnation(key: i64) -> bool {
    INCARNATION.set(key).is_ok()
}

/// This process's incarnation, if it holds one.
pub fn incarnation() -> Option<i64> {
    INCARNATION.get().copied()
}
