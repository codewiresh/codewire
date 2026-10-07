#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use codewire_local_vmm::supervisor_client::NativeSupervisorClient;

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cw-ns-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fs::canonicalize("/var/tmp").unwrap())
        .unwrap()
}

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cw"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin");
    command
}

fn arguments(root: &Path) -> Vec<std::ffi::OsString> {
    let mut args = vec!["__native-supervisor".into()];
    for (flag, value) in [
        ("--root", root.join("state")),
        ("--artifact-root", root.join("artifacts")),
        ("--artifact-lock", root.join("artifacts.lock")),
        ("--mesh-data-dir", root.join("mesh")),
        ("--platform-config-dir", root.join("platform")),
        ("--credential-authority-root", root.join("credentials")),
    ] {
        args.push(flag.into());
        args.push(value.into_os_string());
    }
    args
}

#[test]
fn every_supervisor_path_is_required_without_state_effects() {
    for missing in 0..6 {
        let home = fixture();
        let mut args = arguments(home.path());
        args.drain(1 + missing * 2..3 + missing * 2);
        let output = command(home.path()).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!home.path().join("state").exists());
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn local_vm_roles_are_hidden_and_other_host_effect_entrypoints_stay_unavailable() {
    let home = fixture();
    let help = command(home.path()).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    // The local VM roles and the storage-only credential authority are hidden
    // macOS entrypoints; credential-bearing brokers stay unavailable.
    for hidden in [
        "__native-supervisor",
        "__local-credential-authority",
        "__native-runner",
        "__native-network-worker",
        "__native-egress-broker",
        "__native-mesh-transport",
        "__native-mesh-enrollment-broker",
    ] {
        assert!(!help.contains(hidden), "{hidden}");
    }
    for entrypoint in ["__local-credential-broker"] {
        let output = command(home.path())
            .args([entrypoint, "--help"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{entrypoint}");
    }
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

struct OwnedSupervisor<'a> {
    child: Child,
    fixture: &'a mut tempfile::TempDir,
}

impl OwnedSupervisor<'_> {
    fn retain(&mut self, reason: &str) {
        self.fixture.disable_cleanup(true);
        eprintln!(
            "supervisor fixture retained at {}: {reason}",
            self.fixture.path().display()
        );
    }
}

impl Drop for OwnedSupervisor<'_> {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => {
                self.retain("child ownership is unknown; no signal sent");
                return;
            }
        }
        if codewire_local_vmm::darwin::process::observe_owned_child(&mut self.child).is_err() {
            self.retain("child observation is uncertain; no signal sent");
            return;
        }
        if self.child.kill().is_err() {
            self.retain("owned child cleanup signal failed");
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        self.retain("child exit is unproven after cleanup");
    }
}

#[tokio::test]
async fn packaged_supervisor_serves_private_metadata_and_reopens_after_exit() {
    let mut home = fixture();
    let path = home.path().to_owned();
    let socket = path.join("state/supervisor.sock");
    for _ in 0..2 {
        let deadline = Instant::now() + Duration::from_secs(15);
        let process = command(&path)
            .args(arguments(&path))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = OwnedSupervisor {
            child: process,
            fixture: &mut home,
        };
        let deadline = tokio::time::Instant::from_std(deadline);
        let mut client = tokio::time::timeout_at(deadline, async {
            loop {
                assert!(
                    child.child.try_wait().unwrap().is_none(),
                    "packaged supervisor exited before readiness"
                );
                if let Ok(client) = NativeSupervisorClient::connect(&socket).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("packaged supervisor readiness exceeded its bound");
        assert!(
            tokio::time::Instant::now() < deadline,
            "readiness completed after its deadline"
        );
        assert!(
            tokio::time::timeout_at(deadline, client.list())
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "list completed after its deadline"
        );
        assert_eq!(
            tokio::time::timeout_at(deadline, client.start("dev"))
                .await
                .unwrap()
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "start of an unknown environment completed after its deadline"
        );
        drop(client);
        assert!(path.join("state/supervisor.db").is_file());
        for untouched in [
            "mesh",
            "platform",
            "credentials",
            "artifacts",
            "artifacts.lock",
        ] {
            assert!(
                !path.join(untouched).exists(),
                "unexpected effect on {untouched}"
            );
        }
        // This fixture remains the exclusive waiter of this freshly spawned
        // child. Verify the no-autoreap premise before signaling that owned PID;
        // this is test cleanup, not a product process-adoption capability. The
        // detached supervisor has no graceful signal path: a killed one leaves
        // its socket, which the next supervisor replaces under its lock.
        codewire_local_vmm::darwin::process::observe_owned_child(&mut child.child).unwrap();
        // SAFETY: the validated owned child remains unreaped with this sole waiter.
        assert_eq!(
            unsafe { libc::kill(child.child.id() as libc::pid_t, libc::SIGKILL) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "supervisor exit exceeded its bound"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
