use tokio::io::AsyncWriteExt as _;

use super::*;

/// A guard around `sh -c SCRIPT`, standing in for a helper the workload
/// controls: it can print anything.
fn helper(script: &str) -> HelperGuard {
    let mut process = tokio::process::Command::new("/bin/sh");
    process
        .args(["-c", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    HelperGuard {
        child: process.spawn().unwrap(),
        _spec: ProcessSpecCleanup::default(),
    }
}

const SHOWN: &str = "\"/home/codewire/rex.sock\"";

#[tokio::test]
async fn a_connected_helper_hands_back_pipes_that_carry_the_forward() {
    let mut connected = answer(helper("echo connected >&2; exec cat"), SHOWN, &[])
        .await
        .map_err(|status| status.message().to_owned())
        .unwrap();
    connected.stdin.write_all(b"both ways").await.unwrap();
    drop(connected.stdin);
    let mut echoed = Vec::new();
    connected.stdout.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"both ways");
}

#[tokio::test]
async fn a_refusal_is_told_in_the_daemons_words_not_the_helpers() {
    let refused = answer(
        helper("echo platform-socket 1 >&2; echo 'the helper says more' >&2"),
        SHOWN,
        &["the first", "the credential bridge's socket"],
    )
    .await
    .err()
    .unwrap();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        refused.message(),
        format!(
            "{SHOWN} is the credential bridge's socket, which belongs to the platform; \
             forwarding cannot reach it"
        )
    );
    let failed = answer(helper("echo not-listening >&2"), SHOWN, &[])
        .await
        .err()
        .unwrap();
    assert_eq!(failed.code(), tonic::Code::Unavailable);
    assert_eq!(failed.message(), format!("nothing is listening on {SHOWN}"));
}

#[tokio::test]
async fn an_unknown_long_or_missing_status_is_refused_cleanly() {
    let long = "x".repeat(MAX_STATUS_BYTES * 4);
    for script in [
        "echo 'Connected' >&2; exec cat".to_owned(),
        "echo 'connected: and some words' >&2; exec cat".to_owned(),
        "echo 'platform-socket 7' >&2".to_owned(),
        format!("echo {long} >&2; exec cat"),
        "printf connected >&2".to_owned(),
        "printf '\\377\\n' >&2".to_owned(),
        "exit 0".to_owned(),
    ] {
        let refused = answer(helper(&script), SHOWN, &[]).await.err().unwrap();
        assert_eq!(refused.code(), tonic::Code::Unavailable, "{script}");
        assert_eq!(
            refused.message(),
            format!("the environment did not answer for {SHOWN} within 10 s"),
            "{script}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_silent_helper_is_ended_at_the_bound() {
    let refused = answer(helper("exec sleep 600"), SHOWN, &[])
        .await
        .err()
        .unwrap();
    assert_eq!(refused.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn dropping_the_guard_ends_the_helpers_whole_group() {
    // The helper leaves a process of its own in its group.
    let mut guard = helper("sleep 600 & echo $! >&2; wait");
    let mut stderr = guard.child.stderr.take().unwrap();
    let line = status_line(&mut stderr).await.unwrap();
    let left: i32 = line.parse().unwrap();
    let group = i32::try_from(guard.child.id().unwrap()).unwrap();
    drop(guard);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while !ended(left) || !ended(group) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the helper's process and its group's leader were ended");
}

/// Whether `pid` has ended: gone, or a zombie. A killed orphan stays a zombie
/// until the test host's init reaps it, and a container's may never do so.
fn ended(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z')),
        Err(_) => true,
    }
}
