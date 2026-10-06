#![cfg(target_os = "linux")]

//! Controlled loopback roles and kernel process evidence. Managed release A/B
//! admission and the real update journey remain separate acceptance.
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::process::Command;

#[path = "support/cw_fixture.rs"]
mod cw_fixture;

const ISOLATED_CASE: &str = "CW_RETAINED_MESH_ISOLATED_CASE";

fn reap_until(deadline: Instant) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        let pid = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) };
        if pid < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ECHILD) => return true,
                Some(libc::EINTR) => continue,
                _ => return false,
            }
        }
        if pid == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

struct CaseChild(std::process::Child);

impl Drop for CaseChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    eprintln!("isolated Mesh test child closure unknown; retain its artifacts");
                    return;
                }
            }
        }
    }
}

fn isolated_case(name: &str) -> bool {
    if let Some(case) = std::env::var_os(ISOLATED_CASE) {
        assert_eq!(case, name);
        // Only this exact one-test process adopts the retained helpers. Never
        // change the parallel Cargo test parent's process-wide child custody.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let mut observed = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut observed) },
            0
        );
        assert_eq!(observed, 1);
        assert_eq!(
            unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) },
            -1,
            "no children before the isolated case launches"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        return true;
    }
    let root = tempfile::Builder::new()
        .prefix("retained-mesh-test-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
        .keep();
    let output = |name: &str| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap()
    };
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(ISOLATED_CASE, name)
        .envs(
            ["HOME", "TMPDIR", "CARGO_TARGET_TMPDIR"]
                .into_iter()
                .filter_map(|key| std::env::var_os(key).map(|value| (key, value))),
        )
        .stdin(Stdio::null())
        .stdout(output("stdout"))
        .stderr(output("stderr"));
    let mut child = CaseChild(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(540);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "isolated Mesh case exceeded its bound; retain {}",
            root.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = |name: &str| {
        let path = root.join(name);
        assert!(fs::metadata(&path).unwrap().len() <= 64 * 1024);
        fs::read_to_string(path).unwrap()
    };
    let stdout = read("stdout");
    let stderr = read("stderr");
    assert!(
        status.success() && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{stdout}\n{stderr}\nretained isolated Mesh logs {}",
        root.display()
    );
    fs::remove_dir_all(root).unwrap();
    false
}

struct Fixture {
    root: PathBuf,
    a: PathBuf,
    b: PathBuf,
    mesh_addr: String,
    derp_addr: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("retained-mesh-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
            .keep();
        let a = root.join("a-cw");
        let b = root.join("b-cw");
        for path in [&a, &b] {
            cw_fixture::prepare(path);
        }
        fs::create_dir(root.join("empty-path")).unwrap();
        fs::write(root.join("unrelated-sentinel"), b"preserve").unwrap();
        let listeners = [
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        ];
        let mesh_addr = listeners[0].local_addr().unwrap().to_string();
        let derp_addr = listeners[1].local_addr().unwrap().to_string();
        Self {
            root,
            a,
            b,
            mesh_addr,
            derp_addr,
        }
    }

    fn configure(&self, command: &mut std::process::Command) {
        command
            .env_clear()
            // Preserve the parent's HOME; all state goes through checked scoped
            // overrides. The helper roles themselves receive no HOME or auth.
            .envs(std::env::var_os("HOME").map(|home| ("HOME", home)))
            .env("CW_CONFIG_DIR", self.root.join("platform"))
            .env("CW_MESH_DATA_DIR", self.root.join("mesh"))
            .env("PATH", self.root.join("empty-path"))
            .current_dir(&self.root)
            .stdin(Stdio::null());
    }

    async fn run(&self, binary: &Path, args: &[&str]) -> Output {
        let mut child = std::process::Command::new(binary);
        self.configure(&mut child);
        child.args(args);
        let mut child = Command::from(child);
        child.kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(40), child.output())
            .await
            .expect("bounded synthetic CLI command")
            .unwrap()
    }

    async fn up(&self, binary: &Path, overrides: &[&str]) -> Value {
        let mesh_url = format!("http://{}", self.mesh_addr);
        let derp_url = format!("http://{}", self.derp_addr);
        let mut args = vec![
            "mesh",
            "up",
            "--base-url",
            &mesh_url,
            "--listen",
            &self.mesh_addr,
            "--derp-url",
            &derp_url,
            "--derp-listen",
            &self.derp_addr,
            "--output",
            "json",
        ];
        args.extend_from_slice(overrides);
        success_json(self.run(binary, &args).await)
    }

    fn runtime(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("mesh/mesh_runtime.json")).unwrap())
            .unwrap()
    }

    async fn down(&self, binary: &Path) {
        let output = success_json(
            self.run(binary, &["mesh", "down", "--output", "json"])
                .await,
        );
        assert_eq!(output["stopped"], true);
        assert!(!self.root.join("mesh/mesh_runtime.json").exists());
        assert!(!self.root.join("mesh/mesh_owner.json").exists());
        assert_eq!(
            fs::read(self.root.join("unrelated-sentinel")).unwrap(),
            b"preserve"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Use the product's fenced cleanup; never signal a persisted numeric PID.
        // Unknown interrupted custody preserves this exact root and executables.
        let mut command = std::process::Command::new(&self.b);
        self.configure(&mut command);
        command
            .args(["mesh", "down", "--output", "json"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let clean = match command.spawn() {
            Ok(mut child) => {
                let deadline = Instant::now() + Duration::from_secs(40);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break status.success(),
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(20))
                        }
                        _ => {
                            let _ = child.kill();
                            let _ = child.wait();
                            break false;
                        }
                    }
                }
            }
            Err(_) => false,
        };
        if clean
            && !std::thread::panicking()
            && !self.root.join("mesh/mesh_runtime.json").exists()
            && !self.root.join("mesh/mesh-starting.json").exists()
        {
            if std::env::var_os(ISOLATED_CASE).is_some() {
                assert!(
                    reap_until(Instant::now() + Duration::from_secs(5)),
                    "normal isolated Mesh custody did not prove ECHILD; retain {}",
                    self.root.display()
                );
            }
            fs::remove_dir_all(&self.root).unwrap();
        } else {
            eprintln!(
                "retained failed or unknown synthetic helper root: {}",
                self.root.display()
            );
            assert!(
                std::thread::panicking() || std::env::var_os(ISOLATED_CASE).is_none(),
                "normal isolated product cleanup was not confirmed; retain {}",
                self.root.display()
            );
        }
    }
}

fn success_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn pin(custody: &Value) -> OwnedFd {
    let pid = custody["pid"].as_u64().unwrap() as libc::pid_t;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    // This handle is an observation witness only. Product custody controls signals.
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn terminal(handle: &OwnedFd) -> bool {
    let mut item = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&mut item, 1, 0) } >= 0);
    item.revents & libc::POLLIN != 0
}

fn assert_no_new_privileges(custody: &Value, handle: &OwnedFd) {
    assert!(!terminal(handle));
    let pid = custody["pid"].as_u64().unwrap();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert!(status.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(key, value)| key == "NoNewPrivs" && value.trim() == "1")
    }));
    assert!(!terminal(handle));
}

#[tokio::test]
async fn embedded_roles_without_helper_path_reuse_live_a_from_b_then_launch_selected_b() {
    if !isolated_case(
        "embedded_roles_without_helper_path_reuse_live_a_from_b_then_launch_selected_b",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let first = fixture.up(&fixture.a, &[]).await;
    assert_eq!(first["started"], true);
    let original = fixture.runtime();
    assert_eq!(original["binary"], fixture.a.to_str().unwrap());
    assert_eq!(original["derp"]["binary"], fixture.a.to_str().unwrap());
    assert_eq!(original["custody"]["role"], "embedded_mesh");
    assert_eq!(original["derp"]["custody"]["role"], "embedded_derp");
    for custody in [&original["custody"], &original["derp"]["custody"]] {
        assert!(custody["start_ticks"].as_u64().unwrap() > 0);
        assert_eq!(custody["boot_id"].as_str().unwrap().len(), 36);
        assert_eq!(custody["executable"]["path"], fixture.a.to_str().unwrap());
    }
    let mesh = pin(&original["custody"]);
    let derp = pin(&original["derp"]["custody"]);
    assert_no_new_privileges(&original["custody"], &mesh);
    assert_no_new_privileges(&original["derp"]["custody"], &derp);
    // Use the checked-in DERP client over TLS, with public fixture trust for
    // the local self-signed certificate. Plain DERP must be refused.
    use codewire_tailnet::derp_transport::{
        DerpTarget, DerpTransport, connect_derp_transport_resolved,
    };
    let address: std::net::SocketAddr = fixture.derp_addr.parse().unwrap();
    let secret = codewire_tailnet::wg::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let mut target = DerpTarget {
        host: address.ip().to_string(),
        port: address.port(),
        transport: DerpTransport::Tls { skip_verify: true },
    };
    let encrypted = tokio::time::timeout(
        Duration::from_secs(5),
        connect_derp_transport_resolved(&target, vec![address], &secret),
    )
    .await
    .unwrap()
    .unwrap();
    drop(encrypted);
    target.transport = DerpTransport::Plain;
    let plaintext = tokio::time::timeout(
        Duration::from_secs(2),
        connect_derp_transport_resolved(&target, vec![address], &secret),
    )
    .await
    .unwrap();
    assert!(plaintext.is_err());
    let owner: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("mesh/mesh_owner.json")).unwrap())
            .unwrap();
    let org = owner["organization_id"].as_str().unwrap();
    let output = fixture
        .run(
            &fixture.a,
            &["network", "create", "retained-proof", "--org", org],
        )
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for binary in [&fixture.a, &fixture.b, &fixture.a] {
        assert_eq!(fixture.up(binary, &[]).await["started"], false);
        assert_eq!(fixture.runtime(), original);
        assert!(!terminal(&mesh) && !terminal(&derp));
        let current = fixture.run(binary, &["network", "current"]).await;
        assert!(current.status.success());
        assert_eq!(
            String::from_utf8(current.stdout).unwrap().trim(),
            "retained-proof"
        );
        let status = success_json(
            fixture
                .run(binary, &["mesh", "status", "--output", "json"])
                .await,
        );
        assert_eq!(status["local"]["state"], "running");
    }
    fixture.down(&fixture.b).await;
    assert!(terminal(&mesh) && terminal(&derp));
    assert_eq!(fixture.up(&fixture.b, &[]).await["started"], true);
    let next = fixture.runtime();
    assert_eq!(next["binary"], fixture.b.to_str().unwrap());
    assert_eq!(next["derp"]["binary"], fixture.b.to_str().unwrap());
    assert_ne!(
        next["custody"]["launch_nonce"],
        original["custody"]["launch_nonce"]
    );
    fixture.down(&fixture.b).await;
}

#[tokio::test]
async fn concurrent_start_and_down_serialize_and_invalid_present_override_has_no_effects() {
    if !isolated_case(
        "concurrent_start_and_down_serialize_and_invalid_present_override_has_no_effects",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let (a, b) = tokio::join!(fixture.up(&fixture.a, &[]), fixture.up(&fixture.b, &[]));
    assert_ne!(a["started"], b["started"]);
    let original = fixture.runtime();
    let mesh = pin(&original["custody"]);
    let derp = pin(&original["derp"]["custody"]);
    let (a, b) = tokio::join!(
        fixture.run(&fixture.a, &["mesh", "down", "--output", "json"]),
        fixture.run(&fixture.b, &["mesh", "down", "--output", "json"])
    );
    let a = success_json(a);
    let b = success_json(b);
    assert_ne!(a["stopped"], b["stopped"]);
    assert!(terminal(&mesh) && terminal(&derp));
    let mut command = std::process::Command::new(&fixture.a);
    fixture.configure(&mut command);
    command
        .env("CW_MESH_DATA_DIR", "")
        .args(["mesh", "up", "--output", "json"]);
    let mut command = Command::from(command);
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(5), command.output())
        .await
        .expect("bounded invalid configuration refusal")
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CW_MESH_DATA_DIR"));
    assert!(!fixture.root.join("mesh/mesh_runtime.json").exists());
    assert!(!fixture.root.join("mesh/mesh-starting.json").exists());
    assert_eq!(
        fs::read(fixture.root.join("unrelated-sentinel")).unwrap(),
        b"preserve"
    );
}

#[tokio::test]
#[ignore = "requires CODEWIRE_TEST_MESH_BINARY and CODEWIRE_TEST_DERP_BINARY from standalone builds"]
async fn explicit_standalone_overrides_are_pinned_and_reused_by_a_different_cw() {
    let fixture = Fixture::new();
    let mesh = fs::canonicalize(
        std::env::var_os("CODEWIRE_TEST_MESH_BINARY").expect("standalone Mesh fixture"),
    )
    .unwrap();
    let derp = fs::canonicalize(
        std::env::var_os("CODEWIRE_TEST_DERP_BINARY").expect("standalone DERP fixture"),
    )
    .unwrap();
    let overrides = [
        "--binary",
        mesh.to_str().unwrap(),
        "--derp-binary",
        derp.to_str().unwrap(),
    ];
    assert_eq!(fixture.up(&fixture.a, &overrides).await["started"], true);
    let original = fixture.runtime();
    assert_eq!(original["custody"]["role"], "external_mesh");
    assert_eq!(original["derp"]["custody"]["role"], "external_derp");
    assert_eq!(original["binary"], mesh.to_str().unwrap());
    assert_eq!(original["derp"]["binary"], derp.to_str().unwrap());
    assert_eq!(fixture.up(&fixture.b, &overrides).await["started"], false);
    assert_eq!(fixture.runtime(), original);
    fixture.down(&fixture.b).await;
}
