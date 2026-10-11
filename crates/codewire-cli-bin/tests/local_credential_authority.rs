#![cfg(target_os = "macos")]

//! The packaged cw starts its macOS credential authority as a detached,
//! empty-environment child and serves local storage through it.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cw-lc-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fs::canonicalize("/var/tmp").unwrap())
        .unwrap()
}

fn cw(home: &Path, arguments: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", home)
        .env("CW_CONFIG_DIR", home.join("config"))
        .env("PATH", "/usr/bin:/bin")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    if let Some(stdin) = stdin {
        std::io::Write::write_all(&mut input, stdin).unwrap();
    }
    drop(input);
    child.wait_with_output().unwrap()
}

/// Stops the authority this test started, whatever the assertions found.
struct Authority<'a>(&'a Path);

impl Drop for Authority<'_> {
    fn drop(&mut self) {
        let root = self.0.join(".codewire/credentials-v1");
        if root.exists() {
            let _ = cw(
                self.0,
                &[
                    "__local-credential-authority-probe",
                    "--root",
                    root.to_str().unwrap(),
                    "--shutdown",
                ],
                None,
            );
        }
    }
}

#[test]
fn the_packaged_authority_starts_and_stores_a_secret_in_the_file_store() {
    let home = fixture();
    fs::create_dir(home.path().join(".codewire")).unwrap();
    fs::write(
        home.path().join(".codewire/config.toml"),
        "local_credential_store = \"file\"\n",
    )
    .unwrap();
    let _authority = Authority(home.path());
    let stored = cw(
        home.path(),
        &["secrets", "--local", "--user", "set", "CW_SYNTHETIC_TOKEN"],
        Some(b"synthetic-authority-start-value"),
    );
    assert!(
        stored.status.success(),
        "{}",
        String::from_utf8_lossy(&stored.stderr)
    );
    let listed = cw(
        home.path(),
        &["secrets", "--local", "--user", "list", "--output", "json"],
        None,
    );
    assert!(listed.status.success());
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.contains("CW_SYNTHETIC_TOKEN"), "{listed}");
    assert!(!listed.contains("synthetic-authority-start-value"));
    let entries = fs::read_dir(home.path().join(".codewire/credentials-v1/protected-v1"))
        .unwrap()
        .count();
    assert_eq!(entries, 1);
}
