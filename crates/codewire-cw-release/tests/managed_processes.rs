//! Real executables behind a managed entry: a running version keeps its
//! original path and bytes while another becomes the default, and each new
//! invocation follows the selection. Fixture versions are copies of this test
//! binary with distinct trailing bytes. They live below Cargo's target
//! temporary directory because the system temporary directory may be noexec.
#![cfg(unix)]
// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use codewire_cw_release::identity::{CwPayloadIdentity, Platform};
use codewire_cw_release::store::{Admission, Candidate, DEFAULT_LOCK_TIMEOUT, Store, install};
use sha2::{Digest as _, Sha256};

const FIXTURE: &str = "CW_RELEASE_PROCESS_FIXTURE";
const IDENTITY_PREFIX: &str = "FIXTURE exe=";

/// Runs only inside a fixture copy; a no-op in the ordinary test run.
#[test]
fn fixture_process() {
    let Some(mode) = std::env::var_os(FIXTURE) else {
        return;
    };
    // macOS reports the invoked path, the managed entry link; Linux reports
    // the resolved file. The launcher reads this before changing the
    // selection, so resolving it here names the version that was executed.
    let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{IDENTITY_PREFIX}{}", executable.display()).unwrap();
    stdout.flush().unwrap();
    if mode == "wait" {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
    }
}

struct Running {
    child: Child,
    stdin: Option<ChildStdin>,
    _stdout: BufReader<ChildStdout>,
    executable: PathBuf,
}

fn fixture_command(program: &Path, mode: &str) -> Command {
    let mut command = Command::new(program);
    command
        .args([
            "fixture_process",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(FIXTURE, mode)
        .stderr(Stdio::null());
    command
}

fn read_identity(reader: &mut impl BufRead) -> PathBuf {
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "fixture printed no identity"
        );
        // libtest prints `test fixture_process ... ` without a newline first.
        if let Some((_, path)) = line.trim_end().split_once(IDENTITY_PREFIX) {
            return PathBuf::from(path);
        }
    }
}

fn start(program: &Path) -> Running {
    let mut child = fixture_command(program, "wait")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let executable = read_identity(&mut stdout);
    Running {
        stdin: child.stdin.take(),
        child,
        _stdout: stdout,
        executable,
    }
}

fn run_once(program: &Path) -> PathBuf {
    let output = fixture_command(program, "once").output().unwrap();
    assert!(output.status.success());
    read_identity(&mut output.stdout.as_slice())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Removes the fixture tree, including its 0555 version directories, even
/// when the test fails.
struct Workspace(tempfile::TempDir);

impl Drop for Workspace {
    fn drop(&mut self) {
        fn writable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_dir() {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
                for entry in fs::read_dir(path).into_iter().flatten().flatten() {
                    writable(&entry.path());
                }
            }
        }
        writable(self.0.path());
    }
}

#[test]
fn a_running_version_keeps_its_bytes_while_new_invocations_follow_the_selection() {
    if std::env::var_os(FIXTURE).is_some() {
        return;
    }
    let platform = Platform::host().expect("tests run on a release platform");
    let base = Workspace(
        tempfile::Builder::new()
            .prefix("managed-processes-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap(),
    );
    let bin = base.0.path().join("bin");
    let inputs = base.0.path().join("inputs");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&inputs).unwrap();
    let entry = bin.join("cw");
    let root = base.0.path().join("share/codewire/cli");
    let this = fs::read(std::env::current_exe().unwrap()).unwrap();
    let candidate = |tag: &str| {
        let mut bytes = this.clone();
        bytes.extend_from_slice(format!("\0cw-release-fixture-{tag}").as_bytes());
        let path = inputs.join(tag);
        fs::write(&path, &bytes).unwrap();
        let sha256 = digest(&bytes);
        let identity = CwPayloadIdentity {
            schema_version: 2,
            protocol_version: 1,
            record_version: 1,
            package_version: format!("1.0.0-{tag}"),
            target: platform.release_target().as_str().into(),
            source_revision: "0".repeat(40),
            source_tree_sha256: "1".repeat(64),
            rustc: "rustc 1.93.0 (synthetic fixture)".into(),
            sha256: sha256.clone(),
            size: bytes.len() as u64,
        };
        Candidate {
            executable: path,
            admission: Admission::Pinned { identity, sha256 },
        }
    };

    let installed = install(&root, &entry, &candidate("a"), DEFAULT_LOCK_TIMEOUT).unwrap();
    let store = installed.store;
    let a = installed.published.sha256;
    let mut running_a = start(&entry);
    assert_eq!(running_a.executable, store.version_executable(&a));

    let (published, selected) = store.publish_and_select(&candidate("b"), Some(1)).unwrap();
    let b = published.sha256;
    assert_eq!(
        (selected.generation, selected.previous.as_deref()),
        (2, Some(a.as_str()))
    );

    // The running A process is untouched: alive, same executable path and bytes.
    assert!(running_a.child.try_wait().unwrap().is_none());
    #[cfg(target_os = "linux")]
    assert_eq!(
        fs::read_link(format!("/proc/{}/exe", running_a.child.id())).unwrap(),
        store.version_executable(&a)
    );
    assert_eq!(digest(&fs::read(store.version_executable(&a)).unwrap()), a);

    // A new invocation through the managed entry runs B.
    assert_eq!(run_once(&entry), store.version_executable(&b));

    // Rollback makes A the default for new invocations again.
    let rolled_back = store.rollback(None, Some(2)).unwrap();
    assert_eq!(
        (rolled_back.generation, rolled_back.current.as_str()),
        (3, a.as_str())
    );
    assert_eq!(run_once(&entry), store.version_executable(&a));

    // B stays stored, verifiable and runnable at its digest path.
    store.verify(&b).unwrap();
    assert_eq!(
        run_once(&store.version_executable(&b)),
        store.version_executable(&b)
    );
    assert!(Store::locate(&store.version_executable(&b)).is_some());

    drop(running_a.stdin.take());
    assert!(running_a.child.wait().unwrap().success());
}
