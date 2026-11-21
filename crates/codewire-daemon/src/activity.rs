//! When the Sandbox was last in use, for idle stop (#3384,
//! `docs/dev/IDLE-STOP.md`).
//!
//! One clock per daemon process, which is one per Sandbox. It moves on
//! terminal input or output (sessions, PTYs, the browser terminal), on an
//! inbound SSH or tailnet connection or the data it forwards, and on any
//! minute in which the Sandbox used at least 10% of one vCPU. Orchestration's
//! idle check reads it through `GetActivity`; it can only keep a Sandbox
//! running. Only the time is kept, never what passed.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// Unix seconds of the last activity, 0 before any.
static LAST_ACTIVE: AtomicI64 = AtomicI64::new(0);

/// How often the CPU is sampled.
pub const CPU_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// CPU time in one sample that counts as use: 10% of one vCPU for a minute.
const BUSY_MICROSECONDS: u64 = 6_000_000;

/// The cgroup v2 file whose `usage_usec` counts every process in the
/// workspace container, its Docker containers included.
const CPU_STAT: &str = "/sys/fs/cgroup/cpu.stat";

/// Notes activity now.
pub fn touch() {
    LAST_ACTIVE.store(now(), Ordering::Relaxed);
}

/// Unix seconds of the last activity since the daemon started, if any.
pub fn last_active() -> Option<i64> {
    match LAST_ACTIVE.load(Ordering::Relaxed) {
        0 => None,
        seconds => Some(seconds),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Samples the workspace container's CPU every minute and notes a busy
/// minute as activity. Without the cgroup file (not cgroup v2) it logs once
/// and stops: CPU then never keeps the Sandbox up, and the other signals
/// still do.
pub fn spawn_cpu_sampler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(sample_cpu(
        Path::new(CPU_STAT).to_path_buf(),
        CPU_SAMPLE_INTERVAL,
        &LAST_ACTIVE,
    ))
}

async fn sample_cpu(path: std::path::PathBuf, interval: Duration, clock: &'static AtomicI64) {
    let mut previous = match read_usage(&path).await {
        Some(usage) => usage,
        None => {
            tracing::warn!(path = %path.display(), "idle stop: no cgroup CPU usage to sample");
            return;
        }
    };
    let mut ticks = tokio::time::interval(interval);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let Some(usage) = read_usage(&path).await else {
            continue;
        };
        if busy(previous, usage) {
            clock.store(now(), Ordering::Relaxed);
        }
        previous = usage;
    }
}

async fn read_usage(path: &Path) -> Option<u64> {
    usage_usec(&tokio::fs::read_to_string(path).await.ok()?)
}

/// `usage_usec` from a cgroup v2 `cpu.stat`.
fn usage_usec(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse().ok())
}

/// Whether the CPU used between two samples a minute apart is use.
fn busy(previous: u64, current: u64) -> bool {
    current.saturating_sub(previous) >= BUSY_MICROSECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_usage_from_cpu_stat() {
        let stat = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\nnr_periods 0\n";
        assert_eq!(usage_usec(stat), Some(123_456));
        assert_eq!(usage_usec("user_usec 1\n"), None);
        assert_eq!(usage_usec("usage_usec many\n"), None);
    }

    #[test]
    fn a_tenth_of_one_vcpu_for_a_minute_is_use() {
        assert!(busy(1_000_000, 7_000_000));
        assert!(!busy(1_000_000, 6_999_999));
        // A counter that went back (a new cgroup) is not use.
        assert!(!busy(9_000_000, 1_000_000));
    }

    #[test]
    fn touch_moves_the_clock_forward() {
        touch();
        let first = last_active().expect("touched");
        assert!(first >= now() - 1);
    }

    #[tokio::test]
    async fn a_busy_minute_is_noted_and_an_idle_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cpu.stat");
        std::fs::write(&path, "usage_usec 1000\n").unwrap();
        static CLOCK: AtomicI64 = AtomicI64::new(1);
        let sampler = tokio::spawn(sample_cpu(path.clone(), Duration::from_millis(50), &CLOCK));
        // Idle: a few microseconds a sample.
        std::fs::write(&path, "usage_usec 1500\n").unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(CLOCK.load(Ordering::Relaxed), 1);
        // Busy: seven seconds in a sample.
        std::fs::write(&path, "usage_usec 7001500\n").unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(CLOCK.load(Ordering::Relaxed) > 1);
        sampler.abort();
    }
}
