#![cfg(target_os = "linux")]

use std::process::Command;

use tempfile::TempDir;

#[test]
fn init_never_echoes_an_ambient_https_remote_credential() {
    const SYNTHETIC_SECRET: &str = "synthetic-init-origin-token-do-not-print";

    let repository = TempDir::new().unwrap();
    let status = Command::new("/usr/bin/git")
        .arg("init")
        .arg("--quiet")
        .arg(repository.path())
        .status()
        .unwrap();
    assert!(status.success());
    let credential_remote =
        format!("https://user:{SYNTHETIC_SECRET}@example.test/org/repository.git");
    let status = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repository.path())
        .args(["remote", "add", "origin", &credential_remote])
        .status()
        .unwrap();
    assert!(status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_cw"))
        .arg("init")
        .current_dir(repository.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("must not embed URL credentials"));
    assert!(!stdout.contains(SYNTHETIC_SECRET));
    assert!(!stderr.contains(SYNTHETIC_SECRET));
}
