//! Exact synthetic process identity and exit observation for enrollment tests.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use rustix::process::Pid;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;
use tokio::time::Instant;

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
