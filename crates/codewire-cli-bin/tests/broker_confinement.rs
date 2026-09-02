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
