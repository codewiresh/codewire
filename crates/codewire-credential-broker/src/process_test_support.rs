//! Isolated synthetic descendant ownership and exact process exit observation.

use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "codex-enrollment")]
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions};
use tokio::io::unix::AsyncFd;
use tokio::process::Command;
use tokio::time::Instant;

pub(crate) async fn isolated_process_fixture(
    test: &'static str,
    body: impl std::future::Future<Output = ()>,
) {
    const MARKER: &str = "CW_TEST_BROKER_DESCENDANT_OWNER";
    if let Some(marker) = std::env::var_os(MARKER) {
        assert_eq!(marker, std::ffi::OsStr::new(test));
        assert_eq!(
            std::env::args().skip(1).collect::<Vec<_>>(),
            ["--exact", test, "--nocapture", "--test-threads=1"]
        );
        assert!(std::env::vars_os().all(|(name, _)| {
            [MARKER, "HOME", "PATH", "SHELL", "TMPDIR"]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed))
        }));
        let children = rustix::process::waitid(
            WaitId::All,
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        );
        assert!(
            matches!(children, Err(rustix::io::Errno::CHILD)),
            "isolated process fixture already owns children: {children:?}"
        );
        // Only the exact reexecuted fixture adopts its synthetic descendants.
        // The parallel test process never becomes a subreaper.
        let enabled = Some(Pid::from_raw(1).unwrap());
        rustix::process::set_child_subreaper(enabled).unwrap();
        assert_eq!(rustix::process::child_subreaper().unwrap(), enabled);

        // Production waits and the original direct-child assertions complete
        // before this fixture reaps any terminal adopted descendant.
        body.await;
        reap_fixture_children(test);
        return;
    }
    drop(body);

    let home = tempfile::Builder::new()
        .prefix("cw-broker-descendant-owner-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(MARKER, test)
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .env("TMPDIR", home.path())
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = match tokio::time::timeout(Duration::from_secs(180), child.wait()).await {
        Ok(Ok(status)) => status,
        outcome => {
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .expect("isolated process fixture cleanup remains unknown")
                .expect("isolated process fixture child was not reaped");
            panic!("isolated process fixture failed (test={test}): {outcome:?}");
        }
    };
    assert!(status.success(), "isolated process fixture failed: {test}");
}

fn reap_fixture_children(test: &str) {
    // Enrollment tests advance Tokio's clock. Reaping must still observe real
    // child completion within a real deadline, never virtual timer progress.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "isolated process fixture still owns children: {test}"
        );
        match rustix::process::waitid(WaitId::All, WaitIdOptions::EXITED | WaitIdOptions::NOHANG) {
            Err(rustix::io::Errno::CHILD) => return,
            Err(rustix::io::Errno::INTR) => continue,
            Ok(Some(status)) => {
                assert!(status.exited() || status.killed() || status.dumped());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("cannot reap isolated process fixture {test}: {error}"),
        }
    }
}

#[cfg(feature = "codex-enrollment")]
pub(crate) fn ready_pid(path: &Path) -> Option<i32> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("cannot read synthetic process PID: {error}"),
    };
    let digits = contents.strip_suffix('\n')?;
    let pid: i32 = digits.parse().expect("complete synthetic process PID");
    assert!(pid > 1);
    assert_eq!(digits, pid.to_string());
    Some(pid)
}

pub(crate) fn observe_process(pid: i32) -> AsyncFd<OwnedFd> {
    let pid = Pid::from_raw(pid).expect("exact synthetic process PID");
    let descriptor = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        .expect("pin exact synthetic process before completion or cancellation");
    AsyncFd::new(descriptor).expect("register synthetic process exit observation")
}

#[cfg(feature = "codex-enrollment")]
pub(crate) fn observe_group(root: &Path) -> [(&'static str, AsyncFd<OwnedFd>); 2] {
    ["wrapper.pid", "native.pid"].map(|name| {
        let pid = ready_pid(&root.join(name)).expect("synthetic process PID is ready");
        (name, observe_process(pid))
    })
}

pub(crate) async fn wait_for_exit(
    process: &AsyncFd<OwnedFd>,
    deadline: Instant,
) -> Result<(), tokio::time::error::Elapsed> {
    let _ready = tokio::time::timeout_at(deadline, process.readable())
        .await?
        .expect("observe exact synthetic process exit");
    Ok(())
}

#[cfg(feature = "codex-enrollment")]
pub(crate) async fn assert_group_exited(processes: [(&'static str, AsyncFd<OwnedFd>); 2]) {
    // Linux closes inherited pipes during exit_files before exit_notify marks
    // a grandchild terminal. EOF and the direct parent's wait can therefore
    // precede the grandchild's observable exit. Pin identities while both are
    // still blocked, then observe actual exit without racing PID reuse or init.
    let deadline = Instant::now() + Duration::from_secs(5);
    for (name, process) in processes {
        wait_for_exit(&process, deadline)
            .await
            .unwrap_or_else(|_| panic!("synthetic group member {name} did not exit"));
    }
}

#[tokio::test]
async fn process_exit_observation_rejects_live_child_and_accepts_its_exit() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let process = observe_process(i32::try_from(child.id().unwrap()).unwrap());
    assert!(
        wait_for_exit(&process, Instant::now() + Duration::from_millis(10))
            .await
            .is_err(),
        "a live process must not satisfy the cleanup observation"
    );
    child.kill().await.unwrap();
    wait_for_exit(&process, Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
}
