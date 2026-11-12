#![cfg(any(target_os = "linux", target_os = "macos"))]

//! The local Mesh owner with its real embedded roles, on Linux and macOS
//! (#3797). Every case runs in its own test process, which on Linux becomes
//! the subreaper of what it starts, so its cleanup can be proved by reaping.

// A test reports failure by panicking, so it may unwrap.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::process::Command;

#[path = "support/cw_fixture.rs"]
mod cw_fixture;

const ISOLATED_CASE: &str = "CW_RETAINED_MESH_ISOLATED_CASE";

/// Linux only: reap every child this subreaper inherited, proving none is
/// left. macOS has no subreaper, so there the cases observe exits instead.
#[cfg(target_os = "linux")]
fn reap_until(deadline: Instant) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        // SAFETY: a null status pointer is allowed, and WNOHANG returns at
        // once. It reaps only this process's own children.
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
        #[cfg(target_os = "linux")]
        {
            // SAFETY: the option takes one integer and no pointer. It changes
            // only this one-test process.
            let subreaper = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
            assert_eq!(subreaper, 0);
            // SAFETY: a null status pointer is allowed, and WNOHANG returns at
            // once.
            let child =
                unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) };
            assert_eq!(child, -1, "no children before the isolated case launches");
        }
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

/// The lowest port the kernel assigns on its own, to `bind(:0)` and to every
/// outgoing connection.
fn ephemeral_port_floor() -> u16 {
    #[cfg(target_os = "linux")]
    {
        let range = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
        range.split_whitespace().next().unwrap().parse().unwrap()
    }
    #[cfg(target_os = "macos")]
    {
        49152
    }
}

/// A free loopback address the owner binds later by itself. A port from
/// `bind(:0)` comes from the ephemeral range, so once released any outgoing
/// connection in the parallel test run can take it before the owner binds it,
/// and the owner then exits at startup (#3992). Ports below that range are only
/// ever taken by an explicit bind.
fn unassigned_loopback_address(other: Option<&str>) -> String {
    use rand::RngCore as _;
    const FIRST: u16 = 10_000;
    let span = u32::from(ephemeral_port_floor() - FIRST);
    for _ in 0..64 {
        let port = FIRST + u16::try_from(rand::rngs::OsRng.next_u32() % span).unwrap();
        let address = format!("127.0.0.1:{port}");
        if Some(address.as_str()) != other && std::net::TcpListener::bind(&address).is_ok() {
            return address;
        }
    }
    panic!("no free loopback port below the ephemeral range");
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
        let root = fs::canonicalize(root).unwrap();
        let a = root.join("a-cw");
        let b = root.join("b-cw");
        for path in [&a, &b] {
            cw_fixture::prepare(path);
        }
        fs::create_dir(root.join("empty-path")).unwrap();
        fs::write(root.join("unrelated-sentinel"), b"preserve").unwrap();
        let mesh_addr = unassigned_loopback_address(None);
        let derp_addr = unassigned_loopback_address(Some(&mesh_addr));
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
        let mut command = std::process::Command::new(binary);
        self.configure(&mut command);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut command = Command::from(command);
        command.kill_on_drop(true);
        let child = cw_fixture::spawn_written(|| command.spawn()).unwrap();
        tokio::time::timeout(Duration::from_secs(40), child.wait_with_output())
            .await
            .expect("bounded synthetic CLI command")
            .unwrap()
    }

    async fn up(&self, binary: &Path) -> Value {
        let mesh_url = format!("http://{}", self.mesh_addr);
        let derp_url = format!("http://{}", self.derp_addr);
        let args = [
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
        success_json(self.run(binary, &args).await)
    }

    fn runtime(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("mesh/mesh_runtime.json")).unwrap())
            .unwrap()
    }

    async fn down(&self, binary: &Path) -> Value {
        success_json(
            self.run(binary, &["mesh", "down", "--output", "json"])
                .await,
        )
    }

    fn assert_clean(&self) {
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
        // Use the product's cleanup; never signal a persisted numeric PID.
        // Unknown interrupted custody preserves this exact root and executables.
        let mut command = std::process::Command::new(&self.b);
        self.configure(&mut command);
        command
            .args(["mesh", "down", "--output", "json"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let clean = match cw_fixture::spawn_written(|| command.spawn()) {
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
            #[cfg(target_os = "linux")]
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

/// The owner's recorded birth: the test's only witness of that process.
fn owner_identity(runtime: &Value) -> codewire_local_vmm::ProcessIdentity {
    serde_json::from_value(runtime["owner"]["process"].clone()).unwrap()
}

/// Whether `pid` still names a process. An observation only: the test reaps
/// its inherited children first on Linux, where an exited one would linger.
fn exists(pid: u32) -> bool {
    // SAFETY: a null status pointer is allowed, and WNOHANG returns at once.
    // It can reap only a child of this process.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::waitpid(
            pid as libc::pid_t,
            std::ptr::null_mut(),
            libc::WNOHANG | libc::__WALL,
        );
    }
    // SAFETY: signal 0 delivers nothing; the call only reports whether the
    // process exists.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "{what} within 5 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_owner_serves_mesh_and_derp_and_any_cw_reaches_it_only_through_its_socket() {
    if !isolated_case(
        "the_owner_serves_mesh_and_derp_and_any_cw_reaches_it_only_through_its_socket",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let first = fixture.up(&fixture.a).await;
    assert_eq!(first["started"], true);
    let original = fixture.runtime();
    assert_eq!(original["binary"], fixture.a.to_str().unwrap());
    assert_eq!(original["derp"]["binary"], fixture.a.to_str().unwrap());
    let owner = owner_identity(&original);
    assert_eq!(owner.pid, original["pid"].as_u64().unwrap() as u32);
    assert_eq!(owner.executable, fixture.a);
    let derp_pid = original["derp"]["pid"].as_u64().unwrap() as u32;
    assert!(codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap());
    assert!(exists(derp_pid));
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
    let context: Value =
        serde_json::from_slice(&fs::read(fixture.root.join("mesh/mesh_owner.json")).unwrap())
            .unwrap();
    let org = context["organization_id"].as_str().unwrap();
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
    // Another cw (an update) finds the same running owner and stops it.
    for binary in [&fixture.a, &fixture.b, &fixture.a] {
        assert_eq!(fixture.up(binary).await["started"], false);
        assert_eq!(fixture.runtime(), original);
        let current = success_json(
            fixture
                .run(binary, &["network", "current", "--output", "json"])
                .await,
        );
        assert_eq!(current["network_id"], "retained-proof");
        let status = success_json(
            fixture
                .run(binary, &["mesh", "status", "--output", "json"])
                .await,
        );
        assert_eq!(status["local"]["state"], "running");
    }
    let stopped = fixture.down(&fixture.b).await;
    assert_eq!(
        (&stopped["stopped"], &stopped["state"]),
        (&Value::from(true), &Value::from("stopped"))
    );
    fixture.assert_clean();
    eventually("the owner exits", || {
        !codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap()
    })
    .await;
    eventually("its DERP child exits", || !exists(derp_pid)).await;
    assert_eq!(fixture.up(&fixture.b).await["started"], true);
    let next = fixture.runtime();
    assert_eq!(next["binary"], fixture.b.to_str().unwrap());
    assert_ne!(
        next["owner"]["launch_nonce"],
        original["owner"]["launch_nonce"]
    );
    fixture.down(&fixture.b).await;
    fixture.assert_clean();
}

#[tokio::test]
async fn a_killed_owner_takes_its_derp_child_and_leaves_a_stale_record_that_is_not_signalled() {
    if !isolated_case(
        "a_killed_owner_takes_its_derp_child_and_leaves_a_stale_record_that_is_not_signalled",
    ) {
        return;
    }
    let fixture = Fixture::new();
    assert_eq!(fixture.up(&fixture.a).await["started"], true);
    let runtime = fixture.runtime();
    let owner = owner_identity(&runtime);
    let derp_pid = runtime["derp"]["pid"].as_u64().unwrap() as u32;
    // A crash: the test kills the owner it just observed alive by its birth.
    assert!(codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap());
    // SAFETY: kill takes no pointer. The birth check above shows the PID still
    // names the owner this test started.
    let killed = unsafe { libc::kill(owner.pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(killed, 0);
    eventually("the killed owner exits", || {
        !exists(owner.pid)
            || !codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap()
    })
    .await;
    eventually("its DERP child ends with it", || !exists(derp_pid)).await;
    // A stale record is refused by up and cleared by down, with no signal.
    let refused = fixture
        .run(&fixture.b, &["mesh", "up", "--output", "json"])
        .await;
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("cw mesh down"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let cleared = fixture.down(&fixture.b).await;
    assert_eq!(
        (&cleared["stopped"], &cleared["state"]),
        (&Value::from(false), &Value::from("stale"))
    );
    fixture.assert_clean();
}

#[tokio::test]
async fn concurrent_start_and_down_serialize_and_an_invalid_state_path_has_no_effects() {
    if !isolated_case(
        "concurrent_start_and_down_serialize_and_an_invalid_state_path_has_no_effects",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let (a, b) = tokio::join!(fixture.up(&fixture.a), fixture.up(&fixture.b));
    assert_ne!(a["started"], b["started"]);
    let owner = owner_identity(&fixture.runtime());
    let (a, b) = tokio::join!(
        fixture.run(&fixture.a, &["mesh", "down", "--output", "json"]),
        fixture.run(&fixture.b, &["mesh", "down", "--output", "json"])
    );
    let a = success_json(a);
    let b = success_json(b);
    assert_ne!(a["stopped"], b["stopped"]);
    eventually("the owner exits", || {
        !codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap()
    })
    .await;
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
async fn an_owner_whose_executable_was_replaced_in_place_is_still_reached_and_stopped() {
    if !isolated_case(
        "an_owner_whose_executable_was_replaced_in_place_is_still_reached_and_stopped",
    ) {
        return;
    }
    let fixture = Fixture::new();
    assert_eq!(fixture.up(&fixture.a).await["started"], true);
    let owner = owner_identity(&fixture.runtime());
    // A rebuild or update writes a new file at the same path; the running
    // owner keeps its old image.
    let replacement = fixture.root.join("replacement-cw");
    cw_fixture::prepare(&replacement);
    fs::rename(&replacement, &fixture.a).unwrap();
    let status = success_json(
        fixture
            .run(&fixture.b, &["mesh", "status", "--output", "json"])
            .await,
    );
    assert_eq!(status["local"]["state"], "running");
    let stopped = fixture.down(&fixture.b).await;
    assert_eq!(stopped["state"], "stopped");
    fixture.assert_clean();
    eventually("the owner exits", || {
        !codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap()
    })
    .await;
}

#[tokio::test]
async fn an_owner_with_an_open_mesh_request_still_stops() {
    if !isolated_case("an_owner_with_an_open_mesh_request_still_stops") {
        return;
    }
    let fixture = Fixture::new();
    assert_eq!(fixture.up(&fixture.a).await["started"], true);
    let owner = owner_identity(&fixture.runtime());
    // A request whose body never finishes arriving stays in flight, as an
    // attached environment's coordinator stream does; a graceful drain alone
    // would wait for it forever.
    let mut open = std::net::TcpStream::connect(&fixture.mesh_addr).unwrap();
    std::io::Write::write_all(
        &mut open,
        b"POST /codewire.v1.MeshNetworkService/ListMeshNetworks HTTP/1.1\r\nHost: mesh\r\n\
          Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n{",
    )
    .unwrap();
    let stopped = fixture.down(&fixture.b).await;
    assert_eq!(stopped["state"], "stopped");
    fixture.assert_clean();
    eventually("the owner exits", || {
        !codewire_local_vmm::process_peer::recorded_birth_alive(&owner).unwrap()
    })
    .await;
    drop(open);
}
