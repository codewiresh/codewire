//! When the Sandbox was last in use, for idle stop (#3384,
//! `docs/dev/IDLE-STOP.md`).
//!
//! One clock per daemon process, which is one per Sandbox. It moves on
//! terminal input or output (sessions, PTYs, the browser terminal), on an
//! inbound SSH or tailnet connection or the data it forwards, and on any
//! minute in which the workspace container used at least 10% of one vCPU. A
//! second clock moves on any such minute of the whole guest kernel, which
//! under Kata is this Sandbox's VM alone and so counts its Docker container
//! too. Orchestration's idle check reads them through `GetActivity`; they can
//! only keep a Sandbox running. Only the time is kept, never what passed.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// Unix seconds of the last activity, 0 before any.
static LAST_ACTIVE: AtomicI64 = AtomicI64::new(0);

/// Unix seconds of the last busy minute of the whole guest, 0 before any.
static GUEST_LAST_BUSY: AtomicI64 = AtomicI64::new(0);

/// How often the CPU is sampled.
pub const CPU_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// CPU time in one sample that counts as use: 10% of one vCPU for a minute.
const BUSY_MICROSECONDS: u64 = 6_000_000;

/// The cgroup v2 file whose `usage_usec` counts every process in the
/// workspace container. Docker runs in a container of its own, so its
/// containers are not in it.
const CPU_STAT: &str = "/sys/fs/cgroup/cpu.stat";

/// The kernel's CPU times. Under Kata the kernel is the Sandbox's own guest,
/// so they count every container of its Pod; under runc they are the host's.
const PROC_STAT: &str = "/proc/stat";

/// `/proc/stat` counts in USER_HZ ticks, 100 a second on Linux.
const MICROSECONDS_PER_TICK: u64 = 10_000;

/// Notes activity now.
pub fn touch() {
    LAST_ACTIVE.store(now(), Ordering::Relaxed);
}

/// Unix seconds of the last activity since the daemon started, if any. With
/// `include_guest_cpu`, a busy minute of the whole guest counts too.
pub fn last_active(include_guest_cpu: bool) -> Option<i64> {
    latest(
        LAST_ACTIVE.load(Ordering::Relaxed),
        GUEST_LAST_BUSY.load(Ordering::Relaxed),
        include_guest_cpu,
    )
}

fn latest(own: i64, guest: i64, include_guest_cpu: bool) -> Option<i64> {
    match if include_guest_cpu {
        own.max(guest)
    } else {
        own
    } {
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

/// Samples the workspace container's CPU and the whole guest's every minute,
/// each on its own clock. Without a file it logs once and stops sampling it:
/// that CPU then never keeps the Sandbox up, and the other signals still do.
pub fn spawn_cpu_sampler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        tokio::join!(
            sample_cpu(
                Path::new(CPU_STAT).to_path_buf(),
                usage_usec,
                CPU_SAMPLE_INTERVAL,
                &LAST_ACTIVE,
            ),
            sample_cpu(
                Path::new(PROC_STAT).to_path_buf(),
                guest_busy_usec,
                CPU_SAMPLE_INTERVAL,
                &GUEST_LAST_BUSY,
            ),
        );
    })
}

async fn sample_cpu(
    path: std::path::PathBuf,
    parse: fn(&str) -> Option<u64>,
    interval: Duration,
    clock: &'static AtomicI64,
) {
    let mut previous = match read_usage(&path, parse).await {
        Some(usage) => usage,
        None => {
            tracing::warn!(path = %path.display(), "idle stop: no CPU usage to sample");
            return;
        }
    };
    let mut ticks = tokio::time::interval(interval);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let Some(usage) = read_usage(&path, parse).await else {
            continue;
        };
        if busy(previous, usage) {
            clock.store(now(), Ordering::Relaxed);
        }
        previous = usage;
    }
}

async fn read_usage(path: &Path, parse: fn(&str) -> Option<u64>) -> Option<u64> {
    parse(&tokio::fs::read_to_string(path).await.ok()?)
}

/// `usage_usec` from a cgroup v2 `cpu.stat`.
fn usage_usec(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse().ok())
}

/// The microseconds every CPU spent working, from `/proc/stat`'s `cpu` line:
/// user, nice, system, irq and softirq. Idle and I/O wait are not work, and
/// neither is steal, the time the host ran something else.
fn guest_busy_usec(stat: &str) -> Option<u64> {
    let times = stat
        .lines()
        .find_map(|line| line.strip_prefix("cpu "))?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    // user nice system idle iowait irq softirq
    let [user, nice, system, _idle, _iowait, irq, softirq, ..] = times[..] else {
        return None;
    };
    Some((user + nice + system + irq + softirq).saturating_mul(MICROSECONDS_PER_TICK))
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
    fn reads_the_guest_s_work_from_proc_stat() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        let stat = "cpu  100 5 50 9000 20 3 2 7 0 0\ncpu0 50 2 25 4500 10 1 1 3 0 0\nintr 1\n";
        // Idle, I/O wait and steal are not work.
        assert_eq!(guest_busy_usec(stat), Some((100 + 5 + 50 + 3 + 2) * 10_000));
        assert_eq!(guest_busy_usec("cpu0 1 2 3 4 5 6 7\n"), None);
        assert_eq!(guest_busy_usec("cpu  1 2 3\n"), None);
        assert_eq!(guest_busy_usec("cpu  1 2 x 4 5 6 7\n"), None);
    }

    #[test]
    fn the_guest_s_cpu_counts_only_when_asked() {
        assert_eq!(latest(10, 20, false), Some(10));
        assert_eq!(latest(10, 20, true), Some(20));
        assert_eq!(latest(30, 20, true), Some(30));
        assert_eq!(latest(0, 20, false), None);
        assert_eq!(latest(0, 0, true), None);
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
        let first = last_active(false).expect("touched");
        assert!(first >= now() - 1);
    }

    #[tokio::test]
    async fn a_busy_minute_is_noted_and_an_idle_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cpu.stat");
        std::fs::write(&path, "usage_usec 1000\n").unwrap();
        static CLOCK: AtomicI64 = AtomicI64::new(1);
        let sampler = tokio::spawn(sample_cpu(
            path.clone(),
            usage_usec,
            Duration::from_millis(50),
            &CLOCK,
        ));
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
