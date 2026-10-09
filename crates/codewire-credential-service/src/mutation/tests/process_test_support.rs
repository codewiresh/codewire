//! Give the exact Linux mutation fixture custody of its synthetic descendants.

use std::future::Future;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, ensure};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use rustix::process::{Pid, WaitId, WaitIdOptions};
#[cfg(target_os = "linux")]
use tokio::process::Command;

pub(super) async fn isolated_process_fixture(
    test: &'static str,
    body: impl Future<Output = Result<()>>,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = test;
        body.await
    }
    #[cfg(target_os = "linux")]
    {
        const MARKER: &str = "CW_TEST_MUTATION_DESCENDANT_OWNER";
        if let Some(marker) = std::env::var_os(MARKER) {
            ensure!(marker == std::ffi::OsStr::new(test));
            ensure!(
                std::env::args().skip(1).collect::<Vec<_>>()
                    == [
                        "--ignored",
                        "--exact",
                        test,
                        "--nocapture",
                        "--test-threads=1"
                    ]
            );
            ensure!(std::env::vars_os().all(|(name, _)| {
                [
                    MARKER,
                    "HOME",
                    "PATH",
                    "SHELL",
                    "TMPDIR",
                    "TEST_DATABASE_URL",
                ]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed))
            }));
            let children = rustix::process::waitid(
                WaitId::All,
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            );
            ensure!(
                matches!(children, Err(rustix::io::Errno::CHILD)),
                "isolated mutation fixture already owns children: {children:?}"
            );
            // The parallel database test process never becomes a subreaper.
            let enabled = Some(Pid::from_raw(1).unwrap());
            rustix::process::set_child_subreaper(enabled)?;
            ensure!(rustix::process::child_subreaper()? == enabled);

            // Preserve the original owner drains and assertions before reaping
            // any terminal descendants of the synthetic wrapper/native pair.
            let result = body.await;
            reap_fixture_children(test);
            return result;
        }
        drop(body);

        let database_url = std::env::var_os("TEST_DATABASE_URL")
            .context("isolated mutation fixture requires its owning TEST_DATABASE_URL")?;
        ensure!(!database_url.is_empty());
        let home = tempfile::Builder::new()
            .prefix("cw-mutation-descendant-owner-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                test,
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(MARKER, test)
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env("TMPDIR", home.path())
            .env("TEST_DATABASE_URL", database_url)
            .current_dir(home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let status = match tokio::time::timeout(Duration::from_secs(180), child.wait()).await {
            Ok(Ok(status)) => status,
            outcome => {
                let _ = child.start_kill();
                tokio::time::timeout(Duration::from_secs(3), child.wait())
                    .await
                    .context("isolated mutation fixture cleanup remains unknown")??;
                anyhow::bail!("isolated mutation fixture failed (test={test}): {outcome:?}");
            }
        };
        ensure!(status.success(), "isolated mutation fixture failed: {test}");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn reap_fixture_children(test: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "isolated mutation fixture still owns children: {test}"
        );
        match rustix::process::waitid(WaitId::All, WaitIdOptions::EXITED | WaitIdOptions::NOHANG) {
            Err(rustix::io::Errno::CHILD) => return,
            Err(rustix::io::Errno::INTR) => continue,
            Ok(Some(status)) => {
                assert!(status.exited() || status.killed() || status.dumped());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("cannot reap isolated mutation fixture {test}: {error}"),
        }
    }
}
