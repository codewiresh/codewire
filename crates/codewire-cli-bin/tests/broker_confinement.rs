#[cfg(target_os = "linux")]
#[test]
fn broker_confinement_probe_uses_the_single_threaded_cw_entrypoint() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cw"))
        .arg("__local-credential-broker-confinement-probe")
        .output()
        .expect("run broker confinement probe");
    assert!(
        output.status.success(),
        "broker confinement probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

/// A broker over a file store reads that store and nothing beside it
/// (#5255): the probe reads `probe-entry`, and the stored entry through the
/// broker's own store, and is refused `probe-sibling`, listing the root, and
/// any write in the store.
#[cfg(target_os = "linux")]
#[test]
fn broker_confinement_reads_only_its_file_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("credential root");
    let store = root.path().join("protected-v1");
    std::fs::create_dir(&store).expect("file store");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).expect("store mode");
    std::fs::write(store.join("probe-entry"), b"synthetic").expect("entry");
    // As the authority writes `local/credentials/probe/material-v1`.
    let stored = store.join("local+credentials+probe+material-v1");
    std::fs::write(&stored, b"synthetic").expect("stored entry");
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o600))
        .expect("stored entry mode");
    std::fs::write(root.path().join("probe-sibling"), b"synthetic").expect("sibling");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cw"))
        .arg("__local-credential-broker-confinement-probe")
        .arg("--file-store")
        .arg(&store)
        .output()
        .expect("run broker confinement probe");
    assert!(
        output.status.success(),
        "broker confinement probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!store.join("probe-new").exists());
}
