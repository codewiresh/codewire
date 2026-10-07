//! Isolated synthetic checkout descendant ownership; not a production helper.

use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions};
use tokio::process::Command;

pub(crate) async fn isolated_process_fixture(
    test: &'static str,
    body: impl std::future::Future<Output = ()>,
) {
    const MARKER: &str = "CW_TEST_GATEWAY_CHECKOUT_DESCENDANT_OWNER";
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
        .prefix("cw-checkout-descendant-owner-")
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
    // Reaping observes real child completion within a real deadline.
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
