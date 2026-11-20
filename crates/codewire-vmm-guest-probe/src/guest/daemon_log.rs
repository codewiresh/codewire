//! The guest daemon's log. A guest has no console and no file the host can
//! reach, so the daemon's events go to an in-memory buffer that the host
//! reads with `ReadDaemonLog` (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Diagnosing delivery in a local VM").

use anyhow::{Context as _, Result};
use codewire_daemon::recent_log::RecentLog;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Installs the process's log subscriber and returns the buffer it fills:
/// warnings from every crate and the daemon's own `info` lines, which is what
/// a host-kind daemon's log file holds.
pub(super) fn install() -> Result<RecentLog> {
    let recent_log = RecentLog::new();
    let buffer = recent_log.clone();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || buffer.writer())
                .with_filter(
                    Targets::new()
                        .with_default(LevelFilter::WARN)
                        .with_target("codewire_daemon", LevelFilter::INFO),
                ),
        )
        .try_init()
        .context("install the guest daemon's log subscriber")?;
    Ok(recent_log)
}
