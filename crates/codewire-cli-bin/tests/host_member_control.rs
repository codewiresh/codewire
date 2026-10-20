#![cfg(target_os = "linux")]
//! Two independent cw endpoints on one Linux host. This proves direct UDP and
//! actual TLS DERP terminal execution; it does not claim NAT traversal.
//! The topology is the existing native_mesh_transport Mesh/TLS-DERP/STUN route.
use codewire_client::{ClientConfig, CodewireClient, StaticTokenProvider};
use codewire_derp::{Relay, self_signed_tls_config, serve_stun, serve_tls};
use codewire_mesh::{Config, LocalMeshAuthorizationConfig, StunServerConfig};
use codewire_server_core::auth::hash_api_key;
use codewire_tailnet::derp::NodePrivate;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[path = "host_member_control/managed.rs"]
mod managed;

#[path = "support/cw_fixture.rs"]
mod cw_fixture;

const ORG: &str = "org-host-member-proof";
const NETWORK: &str = "network-host-member-proof";
const NODE: &str = "target-host-member-proof";
const API_KEY: &str = "cw_synthetic-host-member-proof";
const MAX_HELPER_DIAGNOSTIC: usize = 16 * 1024;

fn diagnostic_open_at(parent: &File, name: &std::ffi::CStr, flags: i32) -> std::io::Result<File> {
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn same_diagnostic_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
}

fn private_diagnostic_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o700
}

fn sealed_diagnostic_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() <= MAX_HELPER_DIAGNOSTIC as u64
}

/// Diagnostic intake never grants readiness or process custody. Hold the
/// selected private directory chain and the exact regular leaf while reading;
/// replacing a name, adding a link or changing bytes makes the intake fail.
struct AdmittedHelperDiagnostic {
    root_path: PathBuf,
    root: File,
    mesh: File,
    parent: File,
    log: File,
    original: fs::Metadata,
}
impl AdmittedHelperDiagnostic {
    fn open(root_path: &Path) -> std::io::Result<Self> {
        if !root_path.is_absolute() || fs::canonicalize(root_path)? != root_path {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(root_path)?;
        if !private_diagnostic_directory(&root.metadata()?)
            || !same_diagnostic_inode(&fs::symlink_metadata(root_path)?, &root.metadata()?)
        {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        let mesh = diagnostic_open_at(&root, c"mesh", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !private_diagnostic_directory(&mesh.metadata()?) {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        let parent = diagnostic_open_at(&mesh, c"members", libc::O_RDONLY | libc::O_DIRECTORY)?;
        for directory in [&root, &mesh, &parent] {
            if !private_diagnostic_directory(&directory.metadata()?) {
                return Err(std::io::Error::other("helper diagnostic admission refused"));
            }
        }
        let log = diagnostic_open_at(&parent, c"member-helper.log", libc::O_RDONLY)?;
        let original = log.metadata()?;
        if !sealed_diagnostic_file(&original) {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        let value = Self {
            root_path: root_path.to_owned(),
            root,
            mesh,
            parent,
            log,
            original,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> std::io::Result<()> {
        let root_named = fs::symlink_metadata(&self.root_path)?;
        let root_held = self.root.metadata()?;
        if fs::canonicalize(&self.root_path)? != self.root_path
            || !private_diagnostic_directory(&root_named)
            || !same_diagnostic_inode(&root_named, &root_held)
        {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        for (parent, name, held) in [
            (&self.root, c"mesh", &self.mesh),
            (&self.mesh, c"members", &self.parent),
        ] {
            let named = diagnostic_open_at(parent, name, libc::O_PATH)?.metadata()?;
            let held = held.metadata()?;
            if !private_diagnostic_directory(&named) || !same_diagnostic_inode(&named, &held) {
                return Err(std::io::Error::other("helper diagnostic admission refused"));
            }
        }
        for current in [
            self.log.metadata()?,
            diagnostic_open_at(&self.parent, c"member-helper.log", libc::O_PATH)?.metadata()?,
        ] {
            if !sealed_diagnostic_file(&current)
                || !same_diagnostic_inode(&self.original, &current)
                || self.original.nlink() != current.nlink()
                || self.original.len() != current.len()
                || self.original.mtime() != current.mtime()
                || self.original.mtime_nsec() != current.mtime_nsec()
                || self.original.ctime() != current.ctime()
                || self.original.ctime_nsec() != current.ctime_nsec()
            {
                return Err(std::io::Error::other("helper diagnostic admission refused"));
            }
        }
        Ok(())
    }

    fn read(&mut self) -> std::io::Result<String> {
        let deadline = Instant::now() + Duration::from_secs(1);
        self.validate()?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut self.log)
            .take(MAX_HELPER_DIAGNOSTIC as u64 + 1)
            .read_to_end(&mut bytes)?;
        self.validate()?;
        if bytes.len() > MAX_HELPER_DIAGNOSTIC || Instant::now() > deadline {
            return Err(std::io::Error::other("helper diagnostic admission refused"));
        }
        closed_helper_diagnostic(&bytes)
            .map(str::to_owned)
            .ok_or_else(|| std::io::Error::other("helper diagnostic admission refused"))
    }
}

fn closed_helper_diagnostic(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let fields = line.strip_prefix("local Mesh helper failed: member Mesh ")?;
    let (phase, fields) = fields.split_once(" setup failed: class=")?;
    if !["peer", "dial"].contains(&phase) {
        return None;
    }
    let (class, rpc) = fields.split_once(" rpc=")?;
    let admitted = match class {
        "connect" => [
            "canceled",
            "unknown",
            "invalid_argument",
            "deadline_exceeded",
            "not_found",
            "already_exists",
            "permission_denied",
            "resource_exhausted",
            "failed_precondition",
            "aborted",
            "out_of_range",
            "unimplemented",
            "internal",
            "unavailable",
            "data_loss",
            "unauthenticated",
        ]
        .contains(&rpc),
        "credential"
        | "json"
        | "url"
        | "setup_timeout"
        | "invalid_setup_response"
        | "derp_map_too_large" => rpc == "none",
        _ => false,
    };
    admitted.then_some(line)
}

fn member_up_failure_context(root: &Path, args: &[&str]) -> String {
    if !args.starts_with(&["member", "up"]) {
        return String::new();
    }
    let diagnostic = AdmittedHelperDiagnostic::open(root)
        .and_then(|mut log| log.read())
        .unwrap_or_else(|_| "closed setup diagnostic unavailable".into());
    format!("\n[member helper] {diagnostic}")
}

fn private(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn pidfd(pid: u32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn terminal(fd: &OwnedFd) -> bool {
    let mut value = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&mut value, 1, 0) } >= 0);
    value.revents & libc::POLLIN != 0
}

/// Only the dedicated fixture's own direct/adopted children may be signaled.
/// No global PID census, command substring or saved numeric PID is authority.
struct OwnedChild {
    fd: OwnedFd,
    proc: File,
    birth: u64,
}
fn proc_bytes(directory: &File, name: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    let name = std::ffi::CString::new(name)?;
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    unsafe { File::from_raw_fd(raw) }
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("owned proc metadata exceeds bound"));
    }
    Ok(bytes)
}
fn birth_and_parent(directory: &File) -> std::io::Result<(u64, u32)> {
    let bytes = proc_bytes(directory, "stat", 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(std::io::Error::other)?;
    let fields = text
        .rsplit_once(") ")
        .ok_or_else(|| std::io::Error::other("owned stat shape"))?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(std::io::Error::other("owned stat shape"));
    }
    Ok((
        fields[19].parse().map_err(std::io::Error::other)?,
        fields[1].parse().map_err(std::io::Error::other)?,
    ))
}
impl OwnedChild {
    fn capture(pid: u32, expected_image: Option<&Path>) -> std::io::Result<Self> {
        let proc = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))?;
        let (birth, parent) = birth_and_parent(&proc)?;
        if birth == 0
            || parent != std::process::id()
            || proc.metadata()?.uid() != unsafe { libc::geteuid() }
        {
            return Err(std::io::Error::other(
                "process is not an owned fixture child",
            ));
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        if let Some(image) = expected_image {
            let raw = unsafe {
                libc::openat(
                    proc.as_raw_fd(),
                    c"exe".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let actual = unsafe { File::from_raw_fd(raw) }.metadata()?;
            let expected = fs::symlink_metadata(image)?;
            if (actual.dev(), actual.ino(), actual.len())
                != (expected.dev(), expected.ino(), expected.len())
            {
                return Err(std::io::Error::other(format!(
                    "owned process image changed: pid={pid} birth={birth} parent={parent} euid={} \
                     expected_dev={} expected_ino={} expected_len={} \
                     actual_dev={} actual_ino={} actual_len={}",
                    unsafe { libc::geteuid() },
                    expected.dev(),
                    expected.ino(),
                    expected.len(),
                    actual.dev(),
                    actual.ino(),
                    actual.len(),
                )));
            }
        }
        let value = Self { fd, proc, birth };
        value.validate()?;
        Ok(value)
    }
    fn capture_launch(pid: u32, image: &Path, deadline: Instant) -> std::io::Result<Self> {
        let owned = Self::capture(pid, None)?;
        owned.wait_for_launch_image(pid, image, deadline)?;
        Ok(owned)
    }
    fn wait_for_launch_image(
        &self,
        pid: u32,
        image: &Path,
        deadline: Instant,
    ) -> std::io::Result<()> {
        // vfork completion can precede installation of the new mm/exe.
        // Keep the original custody and both image files throughout this wait;
        // only the actual inherited parent image may be pending, never accepted.
        let parent = std::process::id();
        let euid = unsafe { libc::geteuid() };
        let expected_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(image)?;
        let inherited_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")?;
        let expected = expected_file.metadata()?;
        let inherited = inherited_file.metadata()?;
        if !expected.is_file() || !inherited.is_file() {
            return Err(std::io::Error::other("owned launch image is not regular"));
        }
        let identity = |metadata: &fs::Metadata| (metadata.dev(), metadata.ino(), metadata.len());
        loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned launch image admission exceeded bound",
                ));
            }
            if terminal(&self.fd) {
                return Err(std::io::Error::other(
                    "owned launch exited before image admission",
                ));
            }
            self.validate()?;
            if parent != std::process::id() || euid != unsafe { libc::geteuid() } {
                return Err(std::io::Error::other("owned launch observer changed"));
            }
            let raw = unsafe {
                libc::openat(
                    self.proc.as_raw_fd(),
                    c"exe".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Reopen each time: an exe file opened during the inherited phase
            // remains that old file even after the child completes exec.
            let actual = unsafe { File::from_raw_fd(raw) }.metadata()?;
            let named = fs::symlink_metadata(image)?;
            if !named.is_file()
                || identity(&named) != identity(&expected)
                || identity(&expected_file.metadata()?) != identity(&expected)
                || identity(&inherited_file.metadata()?) != identity(&inherited)
            {
                return Err(std::io::Error::other("owned launch image path changed"));
            }
            self.validate()?;
            if parent != std::process::id() || euid != unsafe { libc::geteuid() } {
                return Err(std::io::Error::other("owned launch observer changed"));
            }
            if terminal(&self.fd) {
                return Err(std::io::Error::other(
                    "owned launch exited before image admission",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned launch image admission exceeded bound",
                ));
            }
            if identity(&actual) == identity(&expected) {
                return Ok(());
            }
            if identity(&actual) != identity(&inherited) {
                return Err(std::io::Error::other(format!(
                    "owned process image changed: pid={pid} birth={} parent={parent} euid={euid} \
                     expected_dev={} expected_ino={} expected_len={} \
                     actual_dev={} actual_ino={} actual_len={}",
                    self.birth,
                    expected.dev(),
                    expected.ino(),
                    expected.len(),
                    actual.dev(),
                    actual.ino(),
                    actual.len(),
                )));
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
        }
    }
    fn validate(&self) -> std::io::Result<()> {
        let (birth, parent) = birth_and_parent(&self.proc)?;
        if birth != self.birth
            || parent != std::process::id()
            || self.proc.metadata()?.uid() != unsafe { libc::geteuid() }
        {
            return Err(std::io::Error::other("owned process birth changed"));
        }
        Ok(())
    }
    fn signal(&self, signal: i32) -> std::io::Result<()> {
        if terminal(&self.fd) {
            return Ok(());
        }
        self.validate()?;
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

fn owned_children() -> std::io::Result<Vec<OwnedChild>> {
    let mut ids = std::collections::BTreeSet::new();
    let mut tasks = 0;
    for task in fs::read_dir("/proc/self/task")? {
        let task = task?;
        tasks += 1;
        if tasks > 32 {
            return Err(std::io::Error::other(
                "fixture task inventory exceeded bound",
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(task.path())?;
        let bytes = proc_bytes(&directory, "children", 8192)?;
        let text = std::str::from_utf8(&bytes).map_err(std::io::Error::other)?;
        for pid in text.split_whitespace() {
            ids.insert(pid.parse::<u32>().map_err(std::io::Error::other)?);
            if ids.len() > 128 {
                return Err(std::io::Error::other(
                    "fixture child inventory exceeded bound",
                ));
            }
        }
    }
    ids.into_iter()
        .map(|pid| OwnedChild::capture(pid, None))
        .collect()
}

fn salvage_owned_family(deadline: Instant) -> std::io::Result<bool> {
    assert!(subreaper(1));
    let escalation = Instant::now() + Duration::from_secs(2);
    loop {
        // All clone-child exit signals participate in the closure proof.
        loop {
            let value =
                unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) };
            if value < 0 {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(libc::ECHILD) {
                    Ok(true)
                } else {
                    Err(error)
                };
            }
            if value == 0 {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        let signal = if Instant::now() < escalation {
            libc::SIGTERM
        } else {
            libc::SIGKILL
        };
        // A descendant orphaned by an owned parent becomes an adopted child
        // in a later iteration. Each signal uses its newly verified pidfd.
        for child in owned_children()? {
            child.signal(signal)?;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Endpoint {
    root: PathBuf,
    binary: PathBuf,
    origin: String,
    expected_path: Option<&'static str>,
    path_witnesses: std::sync::Mutex<Vec<Value>>,
    extra_environment: std::collections::BTreeMap<String, String>,
}
impl Endpoint {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("CW_CONFIG_DIR", self.root.join("config"))
            .env("CW_HOST_DATA_DIR", self.root.join("hosts"))
            .env("CW_MESH_DATA_DIR", self.root.join("mesh"))
            .env("CODEWIRE_MESH_URL", &self.origin)
            .env("CODEWIRE_MESH_AUTH_TOKEN", API_KEY)
            .envs(&self.extra_environment)
            .current_dir(self.root.join("workspace"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
    async fn run(&self, args: &[&str], input: Option<&str>) -> Output {
        let mut command = self.command(args);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = cw_fixture::spawn_written(|| command.spawn()).unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .await
                .unwrap();
        }
        let output = tokio::time::timeout(Duration::from_secs(45), child.wait_with_output())
            .await
            .expect("bounded exact cw command")
            .unwrap();
        self.record_path_witnesses(args, &output);
        output
    }
    fn record_path_witnesses(&self, args: &[&str], output: &Output) {
        if let Some(expected) = self.expected_path {
            let selected = args.first() == Some(&"--member")
                || (args.first() == Some(&"member")
                    && args
                        .get(1)
                        .is_some_and(|verb| ["info", "observe"].contains(verb)));
            if selected {
                let mut count = 0;
                for line in std::str::from_utf8(&output.stderr).unwrap().lines() {
                    if let Some(raw) = line.strip_prefix("[cw] member transport ") {
                        let witness: Value = serde_json::from_str(raw).unwrap();
                        assert_eq!(witness["schema"], "codewire.host-member-path/v1");
                        let scope = witness["scope_sha256"].as_str().unwrap();
                        assert!(
                            scope.len() == 64
                                && scope
                                    .bytes()
                                    .all(|byte| byte.is_ascii_digit()
                                        || (b'a'..=b'f').contains(&byte))
                        );
                        assert_eq!(witness["qualified"], true, "{raw}");
                        assert_eq!(witness["before"]["transport"], expected);
                        assert_eq!(witness["after"]["transport"], expected);
                        assert_eq!(witness["inbound_derp_counter_available"], false);
                        assert_eq!(witness["nat_traversal_claim"], false);
                        if expected == "direct_udp" {
                            assert_eq!(witness["before"]["direct_verified"], true);
                            assert_eq!(witness["after"]["direct_verified"], true);
                            assert!(
                                witness["after"]["direct_wg_sent"].as_u64().unwrap()
                                    > witness["before"]["direct_wg_sent"].as_u64().unwrap()
                            );
                            assert!(
                                witness["after"]["direct_wg_received"].as_u64().unwrap()
                                    > witness["before"]["direct_wg_received"].as_u64().unwrap()
                            );
                            assert_eq!(
                                witness["after"]["fallback_wg_sent"],
                                witness["before"]["fallback_wg_sent"]
                            );
                            assert_eq!(
                                witness["after"]["peer_relay_wg_sent"],
                                witness["before"]["peer_relay_wg_sent"]
                            );
                        } else {
                            assert!(witness["before"]["direct_wg_sent"].is_null());
                            assert!(witness["after"]["direct_wg_sent"].is_null());
                        }
                        let mut retained = self.path_witnesses.lock().unwrap();
                        assert!(retained.len() < 2048, "bounded actual route witnesses");
                        retained.push(witness);
                        count += 1;
                    }
                }
                // Administrative/parse refusals need not touch the network;
                // every successful typed terminal command must have evidence
                // from its own connection, not an earlier Info connection.
                if output.status.success() {
                    assert!(
                        count > 0,
                        "successful member command lacks own path witness"
                    );
                }
            }
        }
    }
    async fn json(&self, args: &[&str], input: Option<&str>) -> Value {
        let output = self.run(args, input).await;
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stderr),
            member_up_failure_context(&self.root, args)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
struct Services {
    origin: String,
    mesh: tokio::task::JoinHandle<()>,
    derp: tokio::task::JoinHandle<()>,
    stun: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Services {
    fn drop(&mut self) {
        self.mesh.abort();
        self.derp.abort();
        if let Some(stun) = &self.stun {
            stun.abort();
        }
    }
}
async fn services(direct: bool) -> Services {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let derp = listener.local_addr().unwrap();
    let relay = Relay::new(NodePrivate::generate(&mut OsRng));
    let tls = self_signed_tls_config(&[]).unwrap();
    let derp_task = tokio::spawn(async move {
        serve_tls(listener, relay, tls).await.unwrap();
    });
    let (stun, stun_task) = if direct {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        (
            Some(address),
            Some(tokio::spawn(async move {
                serve_stun(socket).await.unwrap();
            })),
        )
    } else {
        (None, None)
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let config = Config {
        bind_addr: address,
        base_url: origin.clone(),
        derp_url: Some(format!("http://{derp}")),
        stun_servers: stun
            .map(|s| {
                vec![StunServerConfig {
                    host: s.ip().to_string(),
                    port: s.port(),
                }]
            })
            .unwrap_or_default(),
        database_url: None,
        mesh_authorization: None,
        local_authorization: Some(LocalMeshAuthorizationConfig {
            organization_id: ORG.into(),
            api_key_hash: hash_api_key(API_KEY),
        }),
    };
    let app = codewire_mesh::router(config);
    let mesh = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Services {
        origin,
        mesh,
        derp: derp_task,
        stun: stun_task,
    }
}
fn endpoints(root: &Path, binaries: &Path, origin: &str, direct: bool) -> (Endpoint, Endpoint) {
    let mut entries = Vec::new();
    for label in ["target", "caller"] {
        let endpoint = root.join(label);
        private(&endpoint);
        for leaf in ["home", "config", "hosts", "mesh", "workspace"] {
            private(&endpoint.join(leaf));
        }
        entries.push(Endpoint {
            root: endpoint,
            binary: binaries.join(format!("{label}-cw")),
            origin: origin.into(),
            expected_path: (label == "caller").then_some(if direct {
                "direct_udp"
            } else {
                "derp"
            }),
            path_witnesses: std::sync::Mutex::new(Vec::new()),
            extra_environment: std::collections::BTreeMap::new(),
        });
    }
    (entries.remove(0), entries.remove(0))
}
async fn add(
    caller: &Endpoint,
    alias: &str,
    env: &str,
    target: &str,
    wg: &str,
    grant: &str,
    derp: bool,
) {
    let mut args = vec![
        "member",
        "add",
        alias,
        "--mesh-url",
        &caller.origin,
        "--org",
        ORG,
        "--network",
        NETWORK,
        "--environment",
        env,
        "--node",
        NODE,
        "--target-key",
        target,
        "--target-wg-key",
        wg,
        "--grant-id",
        grant,
        "--grant-revision",
        "1",
        "--require-transport",
        if derp { "derp" } else { "direct_udp" },
    ];
    if derp {
        args.push("--derp-only");
    }
    let output = caller.run(&args, None).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn journey(
    root: &Path,
    binaries: &Path,
    direct: bool,
) -> (Value, Endpoint, Endpoint, OwnedChild, OwnedChild) {
    let server = services(direct).await;
    let client = CodewireClient::new(
        ClientConfig::new(&server.origin)
            .unwrap()
            .with_mesh_url(&server.origin)
            .unwrap(),
        StaticTokenProvider::new(API_KEY).unwrap(),
    )
    .unwrap();
    client
        .create_mesh_network(codewire_client::CreateMeshNetworkRequest {
            org_id: ORG.into(),
            network_id: NETWORK.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let enrollment = client
        .create_mesh_node_enrollment(codewire_client::CreateMeshNodeEnrollmentRequest {
            org_id: ORG.into(),
            network_id: NETWORK.into(),
            node_name: NODE.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .enrollment_code;
    let (target, caller) = endpoints(root, binaries, &server.origin, direct);
    fs::write(
        target.root.join("workspace/sentinel"),
        b"unrelated-preserved",
    )
    .unwrap();
    let created = target
        .json(
            &[
                "create",
                "--local",
                "--type",
                "host",
                "--name",
                "target",
                "--path",
                target.root.join("workspace").to_str().unwrap(),
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let env = created["id"].as_str().unwrap();
    let target_identity = target
        .json(&["member", "identity", "--output", "json"], None)
        .await;
    let caller_identity = caller
        .json(&["member", "identity", "--output", "json"], None)
        .await;
    let target_key = target_identity["control_key"].as_str().unwrap();
    let wg = target_identity["wg_key"].as_str().unwrap();
    let caller_key = caller_identity["control_key"].as_str().unwrap();
    let grant = Uuid::new_v4().to_string();
    let granted = target
        .json(
            &[
                "control",
                "grant",
                "--environment",
                env,
                "--grant-id",
                &grant,
                "--org",
                ORG,
                "--network",
                NETWORK,
                "--caller-key",
                caller_key,
                "--target-key",
                target_key,
                "--allow",
                "read,launch,input,stop",
                "--expected-book-revision",
                "0",
                "--expected-grant-revision",
                "0",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(granted["book_revision"], 1);
    let mut up = vec![
        "member",
        "up",
        env,
        "--mesh-url",
        &server.origin,
        "--org",
        ORG,
        "--network",
        NETWORK,
        "--enrollment-stdin",
        "--output",
        "json",
    ];
    if !direct {
        up.push("--derp-only");
    }
    let ready = target.json(&up, Some(&enrollment)).await;
    assert_eq!(ready["environment_id"], env);
    let helper =
        OwnedChild::capture(ready["pid"].as_u64().unwrap() as u32, Some(&target.binary)).unwrap();
    // The socket gets this daemon's own PID from its private retained record;
    // this witness observes only and never supplies signaling authority.
    let daemon_socket = target.root.join("hosts").join(env).join("daemon.sock");
    let stream = tokio::net::UnixStream::connect(&daemon_socket)
        .await
        .unwrap();
    let daemon = OwnedChild::capture(
        stream.peer_cred().unwrap().pid().unwrap() as u32,
        Some(&target.binary),
    )
    .unwrap();
    drop(stream);
    let sentinel = target
        .json(
            &[
                "run",
                env,
                "--name",
                "local-sentinel",
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sh",
                "-c",
                r#"printf '%s\n' "$$"; exec /bin/sleep 180"#,
            ],
            None,
        )
        .await;
    let sentinel_sid = sentinel["session_id"].as_str().unwrap();
    let sentinel_pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let output = target
                .run(&["logs", env, "--session", sentinel_sid, "--raw"], None)
                .await;
            assert!(output.status.success());
            if let Ok(pid) = std::str::from_utf8(&output.stdout)
                .unwrap()
                .trim()
                .parse::<u32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // This child belongs to the daemon. Its pidfd is observation only; cleanup
    // uses the explicit public local Stop for the exact session.
    let sentinel_process = pidfd(sentinel_pid);
    add(&caller, "target", env, target_key, wg, &grant, !direct).await;
    let path = if direct { "direct_udp" } else { "derp" };
    let info = caller
        .json(
            &[
                "member",
                "info",
                "target",
                "--expect-transport",
                path,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(info["environment_id"], env);
    assert_eq!(info["path_before"]["transport"], path);
    assert_eq!(info["path_after"]["transport"], path);
    if direct {
        assert_eq!(info["path_after"]["direct_verified"], true);
        assert!(
            info["path_after"]["direct_wg_sent"].as_u64().unwrap()
                > info["path_before"]["direct_wg_sent"].as_u64().unwrap()
        );
        assert!(
            info["path_after"]["direct_wg_received"].as_u64().unwrap()
                > info["path_before"]["direct_wg_received"].as_u64().unwrap()
        );
    }
    let request = Uuid::new_v4().to_string();
    let command =
        r#"printf 'member-start\n'; IFS= read -r line; printf '%s\n' "$line"; printf end-marker"#;
    let launched = caller
        .json(
            &[
                "--member",
                "target",
                "run",
                "--request-id",
                &request,
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sh",
                "-c",
                command,
            ],
            None,
        )
        .await;
    let sid = launched[0]["session_id"].as_str().unwrap();
    assert_eq!(sid, format!("session-{request}"));
    assert_eq!(launched[0]["launch_generation"], 1);
    let duplicate = caller
        .json(
            &[
                "--member",
                "target",
                "run",
                "--request-id",
                &request,
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sh",
                "-c",
                command,
            ],
            None,
        )
        .await;
    assert_eq!(duplicate[0]["session_id"], sid);
    let input = Uuid::new_v4().to_string();
    let sent = caller
        .run(
            &[
                "--member",
                "target",
                "send",
                "--request-id",
                &input,
                "--expected-launch-generation",
                "1",
                sid,
                "real-member-input",
            ],
            None,
        )
        .await;
    assert!(
        sent.status.success(),
        "{}",
        String::from_utf8_lossy(&sent.stderr)
    );
    let waited = caller
        .json(
            &[
                "--member",
                "target",
                "wait",
                sid,
                "--timeout",
                "20s",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(
        waited["stdout"],
        "member-start\nreal-member-input\nend-marker"
    );
    assert_eq!(waited["session"]["exit_code"], 0);
    let list = caller
        .json(&["--member", "target", "ls", "--output", "json"], None)
        .await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["session_id"], sid);
    let stale = caller
        .run(
            &[
                "--member",
                "target",
                "stop",
                "--expected-launch-generation",
                "2",
                "--session",
                sid,
            ],
            None,
        )
        .await;
    assert!(!stale.status.success());
    let mismatch = caller
        .run(
            &[
                "--member",
                "target",
                "run",
                "--request-id",
                &request,
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/false",
            ],
            None,
        )
        .await;
    assert!(!mismatch.status.success());
    assert!(!terminal(&helper.fd));
    assert!(!terminal(&daemon.fd));
    assert!(!terminal(&sentinel_process));
    // Retained logs larger than one daemon page, a unique final marker, and
    // stdout/stderr byte handling all travel through the actual terminal API.
    let large = caller
        .json(
            &[
                "--member",
                "target",
                "run",
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sh",
                "-c",
                r"head -c 300000 /dev/zero | tr '\000' x; printf '\nlarge-final-marker\n'",
            ],
            None,
        )
        .await;
    let large_sid = large[0]["session_id"].as_str().unwrap();
    caller
        .json(
            &[
                "--member",
                "target",
                "wait",
                large_sid,
                "--timeout",
                "45s",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let logs = caller
        .run(
            &[
                "--member",
                "target",
                "logs",
                "--session",
                large_sid,
                "--tail",
                "1",
            ],
            None,
        )
        .await;
    assert!(logs.status.success());
    assert_eq!(logs.stdout, b"large-final-marker\n");
    let held = caller
        .json(
            &[
                "--member",
                "target",
                "run",
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sh",
                "-c",
                "printf held; sleep 120",
            ],
            None,
        )
        .await;
    let held_sid = held[0]["session_id"].as_str().unwrap();
    let stop_id = Uuid::new_v4().to_string();
    let stopped = caller
        .json(
            &[
                "--member",
                "target",
                "stop",
                "--request-id",
                &stop_id,
                "--expected-launch-generation",
                "1",
                "--session",
                held_sid,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(stopped[0]["cleanup_unknown"], false);
    let replacement = target
        .json(
            &["restart", env, "--session", held_sid, "--output", "json"],
            None,
        )
        .await;
    assert_eq!(replacement[0]["launch_generation"], 2);
    assert!(
        !caller
            .run(
                &[
                    "--member",
                    "target",
                    "send",
                    "--expected-launch-generation",
                    "1",
                    held_sid,
                    "must-not-reach-replacement"
                ],
                None
            )
            .await
            .status
            .success()
    );
    let local = target.json(&["ls", env, "--output", "json"], None).await;
    assert!(
        local
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["session_id"] == held_sid
                && record["launch_generation"] == 2
                && record["state"] == "Running")
    );
    target
        .json(
            &["stop", env, "--session", held_sid, "--output", "json"],
            None,
        )
        .await;
    let delegated = caller
        .json(
            &[
                "--member",
                "target",
                "run",
                "--no-tty",
                "--detach",
                "--output",
                "json",
                "--",
                "/bin/sleep",
                "180",
            ],
            None,
        )
        .await;
    let delegated_sid = delegated[0]["session_id"].as_str().unwrap();
    assert_eq!(
        fs::read(target.root.join("workspace/sentinel")).unwrap(),
        b"unrelated-preserved"
    );
    let revoked = target
        .json(
            &[
                "control",
                "revoke",
                "--environment",
                env,
                "--grant-id",
                &grant,
                "--expected-book-revision",
                "1",
                "--expected-grant-revision",
                "1",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(revoked["book_revision"], 2);
    assert!(
        !caller
            .run(&["--member", "target", "ls", "--output", "json"], None)
            .await
            .status
            .success()
    );
    let observed = caller
        .json(
            &["member", "observe", "target", &request, "--output", "json"],
            None,
        )
        .await;
    assert_eq!(observed["session_id"], sid);
    assert_eq!(observed["phase"], "HOST_CONTROL_REQUEST_PHASE_COMPLETED");
    assert!(
        !caller
            .run(
                &[
                    "--member",
                    "target",
                    "run",
                    "--no-tty",
                    "--detach",
                    "--",
                    "/bin/true"
                ],
                None
            )
            .await
            .status
            .success()
    );
    // Remote managed/PTY/general lifecycle commands are refused before routes.
    for args in [
        vec!["--member", "target", "restart", "--session", sid],
        // A member never stops or restarts a whole environment.
        vec!["--member", "target", "stop", env],
        vec!["--member", "target", "restart", env],
        vec!["--member", "target", "attach", sid],
        vec![
            "--member",
            "target",
            "run",
            "--agent",
            "codex",
            "--prompt",
            "never launch",
        ],
    ] {
        assert!(!caller.run(&args, None).await.status.success());
    }
    assert!(!terminal(&helper.fd));
    assert!(!terminal(&daemon.fd));
    assert!(!terminal(&sentinel_process));
    target
        .json(&["member", "down", "--output", "json"], None)
        .await;
    assert!(terminal(&helper.fd));
    assert!(!terminal(&daemon.fd));
    // A read/refusal never recreates the disappeared coordinate owner.
    assert!(
        !caller
            .run(&["member", "info", "target", "--output", "json"], None)
            .await
            .status
            .success()
    );
    assert!(
        !target
            .root
            .join("mesh/members/member-runtime.json")
            .exists()
    );
    // A separate explicit enrollment creates a new helper incarnation. Crash
    // it through its captured owned-child pidfd, then exercise public cleanup
    // of the retained terminal record. Delegated target sessions stay alive.
    let enrollment = client
        .create_mesh_node_enrollment(codewire_client::CreateMeshNodeEnrollmentRequest {
            org_id: ORG.into(),
            network_id: NETWORK.into(),
            node_name: NODE.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .enrollment_code;
    let recreated = target.json(&up, Some(&enrollment)).await;
    let crashed = OwnedChild::capture(
        recreated["pid"].as_u64().unwrap() as u32,
        Some(&target.binary),
    )
    .unwrap();
    crashed.signal(libc::SIGKILL).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !terminal(&crashed.fd) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    target
        .json(&["member", "down", "--output", "json"], None)
        .await;
    assert!(
        !target
            .root
            .join("mesh/members/member-runtime.json")
            .exists()
    );
    assert!(!terminal(&daemon.fd));
    assert!(!terminal(&sentinel_process));
    let remaining = target.json(&["ls", env, "--output", "json"], None).await;
    assert!(
        remaining
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["session_id"] == delegated_sid
                && record["state"] == "Running"
                && record["launch_generation"] == 1)
    );
    assert!(
        !caller
            .run(
                &["member", "observe", "target", &request, "--output", "json"],
                None
            )
            .await
            .status
            .success()
    );
    assert!(
        !target
            .root
            .join("mesh/members/member-runtime.json")
            .exists()
    );
    target
        .json(
            &["stop", env, "--session", delegated_sid, "--output", "json"],
            None,
        )
        .await;
    target
        .json(
            &["stop", env, "--session", sentinel_sid, "--output", "json"],
            None,
        )
        .await;
    assert!(terminal(&sentinel_process));
    target
        .json(&["stop", env, "--local", "--output", "json"], None)
        .await;
    // The daemon releases its ownership lock before its Tokio runtime and
    // process finish exiting. Observe the original pidfd within the existing
    // journey deadline; lock availability alone is not kernel exit proof.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !terminal(&daemon.fd) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("stopped host daemon did not exit through its original pidfd");
    assert!(terminal(&daemon.fd));
    let witnesses = caller.path_witnesses.lock().unwrap().clone();
    assert!(witnesses.iter().all(|value| value["environment_id"] == env
        && value["scope_sha256"] == witnesses[0]["scope_sha256"]));
    for (action, id) in [
        (2, request.as_str()),
        (2, input.as_str()),
        (2, stop_id.as_str()),
        (3, request.as_str()),
    ] {
        assert!(
            witnesses.iter().any(|value| value["action"] == action
                && value["request_id"] == id
                && value["qualified"] == true),
            "actual typed mutation/observation lacks its own request path evidence"
        );
    }
    for action in [5, 6] {
        assert!(
            witnesses.iter().any(|value| value["action"] == action
                && value["session_id"] == sid
                && value["qualified"] == true),
            "actual exact-session read lacks correlated path evidence"
        );
    }
    let report = json!({"transport":path,"co_located_not_nat":true,"info":info,"environment_id":env,"launch_request":request,"session_id":sid,
        "actual_exchange_path_witnesses":witnesses,"inbound_derp_counter_available":false,
        "ordinary_command":true,"duplicate_single_admission":true,"input_acknowledged":true,"retained_output_large_final_marker":true,
        "stale_generation_refused":true,"request_conflict_refused":true,"revocation_refused_new_reads_and_effects":true,"own_observe_after_revoke":true,
        "managed_pty_lifecycle_refused":true,"sentinel_preserved":true,"unrelated_local_session_preserved":true,
        "actual_local_replacement_stale_control_refused":true,"actual_helper_crash_cleanup":true,"delegated_target_session_survives_helper_death":true,"helper_and_daemon_terminal":true});
    drop(server);
    (report, target, caller, helper, daemon)
}

fn subreaper(value: i32) -> bool {
    let mut observed = 0;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut observed) },
        0
    );
    observed == value
}
fn reap_all_until(deadline: Instant) -> bool {
    loop {
        let result =
            unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) };
        if result < 0 {
            return std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
        }
        if result == 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn host_members_two_real_endpoints_direct_and_tls_derp() {
    // Each journey owns a separate subreaper process, rather than changing the
    // Cargo test parent's process-wide custody while other tests may execute.
    for transport in ["direct", "derp"] {
        let root = tempfile::tempdir().unwrap().keep();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Cargo runs an integration test in its package directory. Stage
        // executable payloads under the repository's owned .tmp, not /tmp
        // (which may be noexec), and never rely on a precreated package .tmp.
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let artifact_parent = repository.join(".tmp");
        match fs::create_dir(&artifact_parent) {
            Ok(()) => {
                fs::set_permissions(&artifact_parent, fs::Permissions::from_mode(0o700)).unwrap()
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("owned artifact parent: {error}"),
        }
        let metadata = fs::symlink_metadata(&artifact_parent).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o022, 0);
        let artifacts = tempfile::Builder::new()
            .prefix("host-member-binaries-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&artifact_parent)
            .unwrap()
            .keep();
        for label in ["target", "caller"] {
            let path = artifacts.join(format!("{label}-cw"));
            cw_fixture::prepare(&path);
            assert_eq!(fs::symlink_metadata(&path).unwrap().nlink(), 1);
        }
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("child.stdout"))
            .unwrap();
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("child.stderr"))
            .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "host_member_isolated_kernel_journey",
                "--nocapture",
            ])
            .env_clear()
            .env("CW_MEMBER_CASE_ROOT", &root)
            .env("CW_MEMBER_CASE_BINARIES", &artifacts)
            .env("CW_MEMBER_CASE_TRANSPORT", transport)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(std::env::current_dir().unwrap())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap();
        let handle =
            OwnedChild::capture(child.id(), Some(&std::env::current_exe().unwrap())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(280);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                // The isolated fixture handles TERM by failing its journey
                // and closing only its adopted owned families. Timeout never
                // grants authority over another process or a cleanup success.
                handle.signal(libc::SIGTERM).unwrap();
                let grace = Instant::now() + Duration::from_secs(20);
                while child.try_wait().unwrap().is_none() && Instant::now() < grace {
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert!(
                    child.try_wait().unwrap().is_some(),
                    "isolated custody did not return; exact roots and process retained {} {}",
                    root.display(),
                    artifacts.display()
                );
                panic!(
                    "isolated member journey exceeded bound; roots retained {} {}",
                    root.display(),
                    artifacts.display()
                );
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let status = child.wait().unwrap();
        let stdout = bounded_read(&root.join("child.stdout"));
        let stderr = bounded_read(&root.join("child.stderr"));
        assert!(
            status.success(),
            "{}\n{}\nretained roots {} {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
            root.display(),
            artifacts.display()
        );
        let report: Value =
            serde_json::from_slice(&fs::read(root.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["kernel_echild"], true);
        assert_eq!(report["cleanup_salvage"], false);
        println!(
            "observed host member {transport}: {}",
            serde_json::to_string(&report).unwrap()
        );
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&artifacts).unwrap();
    }
}

#[test]
#[ignore = "invoked explicitly by the exact isolated two-endpoint parent fixture"]
fn host_member_isolated_kernel_journey() {
    use futures::FutureExt;
    let root = PathBuf::from(std::env::var_os("CW_MEMBER_CASE_ROOT").unwrap());
    let binaries = PathBuf::from(std::env::var_os("CW_MEMBER_CASE_BINARIES").unwrap());
    for directory in [&root, &binaries] {
        let meta = fs::symlink_metadata(directory).unwrap();
        assert!(
            meta.is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 == 0o700
        );
        assert_eq!(fs::canonicalize(directory).unwrap(), *directory);
    }
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    assert!(subreaper(1));
    assert!(
        Path::new("/proc/thread-self/children").exists(),
        "kernel child custody unavailable before launch"
    );
    let direct = match std::env::var("CW_MEMBER_CASE_TRANSPORT").unwrap().as_str() {
        "direct" => true,
        "derp" => false,
        _ => panic!("closed member transport case"),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let result=runtime.block_on(async {
        let mut terminate=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            result=tokio::time::timeout(Duration::from_secs(240),std::panic::AssertUnwindSafe(journey(&root,&binaries,direct)).catch_unwind())=>result.ok().and_then(Result::ok),
            _=terminate.recv()=>None,
        }
    });
    drop(runtime);
    assert!(subreaper(1));
    let clean = reap_all_until(Instant::now() + Duration::from_secs(5));
    if result.is_none() || !clean {
        // Salvage closes only the isolated test's proven kernel descendants;
        // it never turns a failed public outcome into positive product proof.
        let salvaged = salvage_owned_family(Instant::now() + Duration::from_secs(10));
        fs::write(root.join("cleanup-failure.json"),serde_json::to_vec_pretty(&json!({"product_success":false,"cleanup_salvage":true,"kernel_echild":salvaged.as_ref().is_ok_and(|value|*value),"roots_retained":true})).unwrap()).unwrap();
        panic!(
            "actual journey or normal cleanup failed; roots retained {}; salvage ECHILD {:?}",
            root.display(),
            salvaged
        );
    }
    let (mut report, _target, _caller, helper, daemon) = result.unwrap();
    assert!(terminal(&helper.fd) && terminal(&daemon.fd));
    report["kernel_echild"] = json!(true);
    report["cleanup_salvage"] = json!(false);
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn bounded_read(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() <= 4 * 1024 * 1024,
        "bounded fixture diagnostics; exact roots retained"
    );
    bytes
}

#[cfg(test)]
mod member_diagnostic_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    const CLOSED_LINE: &str = "local Mesh helper failed: member Mesh peer setup failed: class=connect rpc=permission_denied\n";
    const CANARY: &str = "cw-member-helper-log-private-canary";

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private(&root.path().join("mesh"));
        private(&root.path().join("mesh/members"));
        let mut log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("mesh/members/member-helper.log"))
            .unwrap();
        log.write_all(CLOSED_LINE.as_bytes()).unwrap();
        root
    }

    #[test]
    fn member_diagnostic_exposes_only_closed_setup_fields_for_failed_member_up() {
        let root = fixture();
        let expected = format!("\n[member helper] {}", CLOSED_LINE.trim_end());
        assert_eq!(
            member_up_failure_context(root.path(), &["member", "up", "--local", "host"]),
            expected
        );
        for args in [
            &["member", "down"][..],
            &["--member", "peer", "run"],
            &["create"],
        ] {
            assert!(
                member_up_failure_context(Path::new("/missing-synthetic-root"), args).is_empty()
            );
        }
        let path = root.path().join("mesh/members/member-helper.log");
        fs::write(&path, format!("{CLOSED_LINE}{CANARY}\n")).unwrap();
        let refused = member_up_failure_context(root.path(), &["member", "up"]);
        assert_eq!(
            refused,
            "\n[member helper] closed setup diagnostic unavailable"
        );
        assert!(!refused.contains(CANARY));
    }

    #[test]
    fn member_diagnostic_closed_grammar_refuses_unknown_fields_and_private_text() {
        assert_eq!(
            closed_helper_diagnostic(CLOSED_LINE.as_bytes()),
            Some(CLOSED_LINE.trim_end())
        );
        for class in [
            "credential",
            "json",
            "url",
            "setup_timeout",
            "invalid_setup_response",
            "derp_map_too_large",
        ] {
            let line = format!(
                "local Mesh helper failed: member Mesh dial setup failed: class={class} rpc=none"
            );
            assert_eq!(
                closed_helper_diagnostic(line.as_bytes()),
                Some(line.as_str())
            );
        }
        for line in [
            CLOSED_LINE.replace("permission_denied", "none"),
            CLOSED_LINE.replace("peer", CANARY),
            CLOSED_LINE.replace("connect", CANARY),
            CLOSED_LINE.replace("permission_denied", CANARY),
            CLOSED_LINE.replace(
                "class=connect rpc=permission_denied",
                "class=url rpc=permission_denied",
            ),
            format!("{CLOSED_LINE}message={CANARY}"),
            CLOSED_LINE.replace('\n', &format!(" details={CANARY}\n")),
            format!("{CLOSED_LINE}\n"),
            CLOSED_LINE.replace('\n', "\r\n"),
        ] {
            assert!(closed_helper_diagnostic(line.as_bytes()).is_none());
        }
        assert!(closed_helper_diagnostic(&[0xff]).is_none());
    }

    #[test]
    fn member_diagnostic_refuses_missing_oversize_and_invalid_utf8_logs() {
        let root = fixture();
        let path = root.path().join("mesh/members/member-helper.log");
        fs::remove_file(&path).unwrap();
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(MAX_HELPER_DIAGNOSTIC as u64 + 1).unwrap();
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        fs::write(&path, [0xff]).unwrap();
        assert!(
            AdmittedHelperDiagnostic::open(root.path())
                .unwrap()
                .read()
                .is_err()
        );
    }

    #[test]
    fn member_diagnostic_refuses_links_special_files_and_nonprivate_modes() {
        let root = fixture();
        let path = root.path().join("mesh/members/member-helper.log");
        let other = root.path().join("owned-other");
        fs::rename(&path, &other).unwrap();
        symlink(&other, &path).unwrap();
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&other, &path).unwrap();
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // NONBLOCK opens the FIFO without waiting for a writer; the regular
        // file admission then refuses it before attempting any read.
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&other, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for directory in [
            root.path().to_owned(),
            root.path().join("mesh"),
            root.path().join("mesh/members"),
        ] {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn member_diagnostic_refuses_symlinked_root_and_parent() {
        let root = fixture();
        let linked = root.path().join("linked-root");
        symlink(root.path(), &linked).unwrap();
        assert!(AdmittedHelperDiagnostic::open(&linked).is_err());
        for name in ["mesh", "mesh/members"] {
            let path = root.path().join(name);
            let moved = root.path().join("moved-parent");
            fs::rename(&path, &moved).unwrap();
            symlink(&moved, &path).unwrap();
            assert!(AdmittedHelperDiagnostic::open(root.path()).is_err());
            fs::remove_file(&path).unwrap();
            fs::rename(&moved, path).unwrap();
        }
    }

    #[test]
    fn member_diagnostic_revalidates_held_leaf_and_each_named_parent_before_read() {
        for name in ["mesh/members/member-helper.log", "mesh/members", "mesh"] {
            let root = fixture();
            let mut admitted = AdmittedHelperDiagnostic::open(root.path()).unwrap();
            let path = root.path().join(name);
            let moved = root.path().join("moved");
            fs::rename(&path, &moved).unwrap();
            if moved.is_file() {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap()
                    .write_all(CLOSED_LINE.as_bytes())
                    .unwrap();
            } else {
                private(&path);
            }
            assert!(admitted.read().is_err(), "replacement must not be read");
        }
        let root = fixture();
        let mut admitted = AdmittedHelperDiagnostic::open(root.path()).unwrap();
        // Allocate the rename destination exclusively; an unallocated
        // sibling name could otherwise replace an unrelated empty directory.
        let moved = tempfile::tempdir().unwrap();
        fs::set_permissions(moved.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(root.path(), moved.path()).unwrap();
        private(root.path());
        assert!(admitted.read().is_err());
        fs::remove_dir(root.path()).unwrap();
        fs::rename(moved.path(), root.path()).unwrap();
    }

    #[test]
    fn member_diagnostic_refuses_post_admission_bytes_or_link_count_changes() {
        let root = fixture();
        let path = root.path().join("mesh/members/member-helper.log");
        let mut admitted = AdmittedHelperDiagnostic::open(root.path()).unwrap();
        // A same-size rewrite must be refused by timestamp/ctime identity,
        // even when its new text would pass the closed grammar.
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&path, CLOSED_LINE.replace("peer", "dial")).unwrap();
        assert!(admitted.read().is_err());
        let mut admitted = AdmittedHelperDiagnostic::open(root.path()).unwrap();
        fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(admitted.read().is_err());
    }
}
