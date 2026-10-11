//! Keep the guest wall clock on the host's when the VMM asks for it.
//!
//! Virtualization.framework does not count time in which a VM does not run,
//! such as host sleep or a long host stall, so the guest's clocks fall behind
//! the host's. Its PL031 real-time clock reads the host's time. Launch
//! projections and other deadlines compare guest wall time with host time, so
//! when the kernel command line carries `codewire.clock=rtc` the guest follows
//! that RTC: once a second it compares the two and, when they differ by
//! `MAX_SKEW_SECONDS` or more, waits for the RTC's next second and sets the
//! wall clock to it. Monotonic clocks are left alone. Cloud Hypervisor guests
//! keep kvm-clock and never receive the flag.

use std::fs;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};

const FLAG: &str = "codewire.clock=rtc";
const RTC_SECONDS: &str = "/sys/class/rtc/rtc0/since_epoch";
const MAX_SKEW_SECONDS: i64 = 2;
const INTERVAL: Duration = Duration::from_secs(1);
const EDGE_POLL: Duration = Duration::from_millis(10);
const EDGE_WAIT: Duration = Duration::from_millis(1500);

/// Start following the RTC when the kernel command line asks for it.
pub(crate) fn follow_if_requested() -> Result<()> {
    let command_line = fs::read_to_string("/proc/cmdline").context("read kernel command line")?;
    if !requested(&command_line) {
        return Ok(());
    }
    read_rtc().context("the host asked the guest to follow its RTC, which is unreadable")?;
    thread::Builder::new()
        .name("rtc-clock".to_owned())
        .spawn(|| {
            loop {
                // A failed read or set is retried on the next interval.
                let _ = step_if_skewed();
                thread::sleep(INTERVAL);
            }
        })
        .context("start the RTC clock follower")?;
    Ok(())
}

fn requested(command_line: &str) -> bool {
    command_line
        .split_ascii_whitespace()
        .any(|token| token == FLAG)
}

fn skewed(wall_seconds: i64, rtc_seconds: i64) -> bool {
    (wall_seconds - rtc_seconds).abs() >= MAX_SKEW_SECONDS
}

fn read_rtc() -> Result<i64> {
    let text = fs::read_to_string(RTC_SECONDS).context("read the guest RTC")?;
    text.trim().parse().context("parse the guest RTC")
}

fn wall_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

fn step_if_skewed() -> Result<()> {
    let rtc = read_rtc()?;
    if !skewed(wall_seconds(), rtc) {
        return Ok(());
    }
    // The RTC counts whole seconds, so set the wall clock as its next second
    // begins rather than up to a second late.
    let deadline = Instant::now() + EDGE_WAIT;
    let mut next = rtc;
    while next == rtc && Instant::now() < deadline {
        thread::sleep(EDGE_POLL);
        next = read_rtc()?;
    }
    let time = libc::timespec {
        // time_t is i64 on every 64-bit Linux target.
        tv_sec: next,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec; guest init runs as root.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set the guest wall clock");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_flag_requests_rtc_following() {
        assert!(requested(
            "console=ttyS0 rdinit=/init panic=-1 codewire.clock=rtc\n"
        ));
        assert!(!requested("console=ttyS0 rdinit=/init panic=-1\n"));
        assert!(!requested(
            "codewire.clock=rtcx codewire.clock= xcodewire.clock=rtc"
        ));
    }

    #[test]
    fn a_skew_of_two_seconds_either_way_is_corrected() {
        assert!(!skewed(100, 100));
        assert!(!skewed(101, 100));
        assert!(!skewed(99, 100));
        assert!(skewed(102, 100));
        assert!(skewed(42, 100));
    }
}
