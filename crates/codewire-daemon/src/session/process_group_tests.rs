//! How a session's process group ends when its client is gone.

use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};

use super::{GroupEnd, end_process_group};

const GRACE: Duration = Duration::from_millis(300);

/// `script` under `sh`, leading its own process group as a session command
/// does, and the pids it prints, one per line, before it settles.
async fn spawn_group(script: &str, pids: usize) -> (Child, Vec<i32>) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut printed = Vec::new();
    while printed.len() < pids {
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("the script printed its pids")
            .unwrap()
            .expect("the script printed every pid");
        printed.push(line.trim().parse().unwrap());
    }
    (child, printed)
}

/// Running and not a zombie.
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let state = stat.rsplit_once(") ")?.1.chars().next()?;
            Some(state != 'Z' && state != 'X')
        })
        .unwrap_or(false)
}

async fn gone(pid: i32) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while alive(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// Whether `pid` leads its own session, as a `setsid` process does.
fn is_session_leader(pid: i32) -> bool {
    // SAFETY: getsid takes no pointers.
    unsafe { libc::getsid(pid) == pid }
}

fn kill(pid: i32) {
    // SAFETY: kill takes no pointers; a stale pid only fails with ESRCH.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

async fn end(child: &mut Child, end: GroupEnd) -> (std::process::ExitStatus, Duration) {
    let started = Instant::now();
    let leader = child.id();
    let status = end_process_group(leader, end, GRACE, child.wait())
        .await
        .unwrap();
    (status, started.elapsed())
}

#[tokio::test]
async fn a_group_that_exits_on_sigterm_ends_without_waiting_out_the_grace() {
    let (mut child, pids) = spawn_group("sleep 600 & echo $!; wait", 1).await;
    let (status, elapsed) = end(&mut child, GroupEnd::Terminate).await;
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(elapsed < GRACE, "took {elapsed:?}");
    assert!(gone(pids[0]).await, "the group's job outlived SIGTERM");
}

#[tokio::test]
async fn a_group_that_ignores_sigterm_is_killed_after_the_grace() {
    let (mut child, pids) = spawn_group("trap '' TERM; sleep 600 & echo $!; wait", 1).await;
    let (status, elapsed) = end(&mut child, GroupEnd::Terminate).await;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(
        elapsed >= GRACE,
        "SIGKILL came before the grace: {elapsed:?}"
    );
    assert!(gone(pids[0]).await, "the group's job outlived SIGKILL");
}

#[tokio::test]
async fn a_member_its_leader_left_behind_is_killed_after_the_grace() {
    // The leader dies on SIGTERM; its job ignores SIGTERM.
    let (mut child, pids) = spawn_group(
        "(trap '' TERM; exec sh -c 'echo $$; exec sleep 600') & wait",
        1,
    )
    .await;
    let (status, elapsed) = end(&mut child, GroupEnd::Terminate).await;
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(
        elapsed >= GRACE,
        "SIGKILL came before the grace: {elapsed:?}"
    );
    assert!(gone(pids[0]).await, "the left-behind job outlived SIGKILL");
}

#[tokio::test]
async fn a_process_that_left_the_group_is_never_signalled() {
    let (mut child, pids) = spawn_group(
        "setsid sh -c 'echo $$; exec sleep 600' </dev/null & sleep 600 & echo $!; wait",
        2,
    )
    .await;
    // Each line is a pid; the job in the group is the one that is not the
    // session leader of its own session.
    let (detached, member) = if is_session_leader(pids[0]) {
        (pids[0], pids[1])
    } else {
        (pids[1], pids[0])
    };
    assert!(is_session_leader(detached) && !is_session_leader(member));
    let _ = end(&mut child, GroupEnd::Terminate).await;
    let member_gone = gone(member).await;
    let detached_alive = alive(detached);
    kill(detached);
    kill(member);
    assert!(member_gone, "the group's job outlived the group's end");
    assert!(
        detached_alive,
        "a process that left with setsid was signalled"
    );
}

#[test]
fn a_stat_line_names_live_members_of_its_group_only() {
    let line = |state: &str, group: i32| format!("42 (sh ) x) {state} 1 {group} 42 0 -1");
    assert!(super::is_live_member(&line("S", 42), 42));
    assert!(super::is_live_member(&line("R", 42), 42));
    assert!(
        !super::is_live_member(&line("Z", 42), 42),
        "a zombie is not live"
    );
    assert!(!super::is_live_member(&line("S", 43), 42), "another group");
    assert!(!super::is_live_member("garbage", 42));
}

#[tokio::test]
async fn a_hangup_spares_a_job_that_ignores_it_once_its_leader_exits() {
    // The leader exits on SIGHUP; its `nohup`-style job ignores SIGHUP and,
    // like a job surviving a terminal hangup, keeps running.
    let (mut child, pids) = spawn_group(
        "(trap '' HUP; exec sh -c 'echo $$; exec sleep 600') & wait",
        1,
    )
    .await;
    let (status, elapsed) = end(&mut child, GroupEnd::HangUp).await;
    let survived = alive(pids[0]);
    kill(pids[0]);
    assert_eq!(status.signal(), Some(libc::SIGHUP));
    assert!(elapsed < GRACE, "took {elapsed:?}");
    assert!(survived, "a job that ignored the hangup was ended");
}

#[tokio::test]
async fn a_leader_that_ignores_the_hangup_is_terminated() {
    let (mut child, pids) = spawn_group("trap '' HUP; sleep 600 & echo $!; wait", 1).await;
    let (status, elapsed) = end(&mut child, GroupEnd::HangUp).await;
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(
        elapsed >= GRACE,
        "SIGTERM came before the hangup's grace: {elapsed:?}"
    );
    assert!(gone(pids[0]).await, "the group's job outlived SIGTERM");
}
