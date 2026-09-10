use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;

#[tokio::test]
async fn ssh_group_reap_waits_for_descendant_stderr_eof_before_runtime_cleanup() {
    let temporary = tempfile::tempdir().unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let runtime = create_repository_ssh_runtime(temporary.path(), Arc::clone(&failed)).unwrap();
    let runtime_path = runtime.path.clone().unwrap();

    // The fixed child exits successfully while a descendant keeps FD 2 open.
    // Its isolated process group gives the production finalizer exact signal
    // authority without unsafe pre-exec hooks or ambient process discovery.
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("sleep 30 &")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let child = command.spawn().unwrap();
    let mut child = RepositoryChild::new(child, LocalRepositoryTransport::Ssh);
    assert!(child.construction_valid());
    assert!(
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
    );
    let RepositoryChild::Ssh(group) = &child else {
        panic!("expected SSH repository process group");
    };
    assert!(
        !group.stderr.as_ref().unwrap().is_finished(),
        "the descendant must retain the authority-owned stderr pipe"
    );
    assert!(runtime_path.is_dir());

    assert!(child.stop_and_drain(true).await);
    drop(runtime);
    assert!(!runtime_path.exists());
    assert!(!failed.load(Ordering::Acquire));
}
