//! Actual admitted Codex/Claude on the existing two-member fixture topology.
//! This is selected explicitly; default unit/terminal runs need no agent assets.
use super::*;
use tokio::io::{AsyncReadExt, BufReader};

const INPUT_KEYS: &[&str] = &[
    "schema",
    "cw",
    "cw_sha256",
    "component_manifest",
    "component_sha256",
    "agents_manifest",
    "agents_sha256",
    "broker",
    "broker_receipt",
];
const ALLOW: &str = "read,launch,input,stop,managed-launch,managed-message,managed-steer,managed-interrupt,managed-stop,managed-restart,managed-read";
const PROMPT: &str = "Reply with a short fixture acknowledgement. Do not use tools.";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

fn json_file(path: &Path, maximum: u64) -> Value {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    let before = file.metadata().unwrap();
    assert!(
        before.is_file()
            && before.uid() == unsafe { libc::geteuid() }
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= maximum
    );
    let mut bytes = Vec::new();
    Read::read_to_end(&mut Read::take(&mut file, maximum + 1), &mut bytes).unwrap();
    assert!(bytes.len() as u64 <= maximum);
    let after = file.metadata().unwrap();
    let named = fs::symlink_metadata(path).unwrap();
    for metadata in [&after, &named] {
        assert!(
            same_diagnostic_inode(&before, metadata)
                && metadata.is_file()
                && metadata.nlink() == 1
                && before.len() == metadata.len()
                && before.mtime_nsec() == metadata.mtime_nsec()
                && before.mtime() == metadata.mtime()
                && before.ctime() == metadata.ctime()
                && before.ctime_nsec() == metadata.ctime_nsec()
        );
    }
    serde_json::from_slice(&bytes).unwrap()
}

fn inputs() -> Value {
    let path = std::env::var_os("CW_MEMBER_MANAGED_INPUTS")
        .expect("explicit admitted member-managed inputs are required");
    let value = json_file(Path::new(&path), 1024 * 1024);
    closed_inputs(&value);
    value
}
fn closed_inputs(value: &Value) {
    let object = value.as_object().expect("closed member asset object");
    assert_eq!(object.len(), INPUT_KEYS.len());
    assert!(INPUT_KEYS.iter().all(|key| object.contains_key(*key)));
    assert_eq!(value["schema"], "codewire.member-managed-inputs/v1");
    for key in &INPUT_KEYS[1..] {
        assert!(value[*key].as_str().is_some());
    }
}

fn asset_command(mode: &str, value: &Value) -> Command {
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-B"])
        .arg(repository().join("scripts/dev/fixtures/host-member-managed-assets.py"))
        .arg(mode)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in &INPUT_KEYS[1..] {
        command
            .arg(format!("--{}", key.replace('_', "-")))
            .arg(value[*key].as_str().unwrap());
    }
    command
}

fn asset_run(mut command: Command) -> Value {
    // Before any service/agent: only a bounded fixed Python admission/stager.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut child = command.spawn().unwrap();
    let owned = OwnedChild::capture_launch(
        child.id(),
        &fs::canonicalize("/usr/bin/python3").unwrap(),
        deadline,
    )
    .unwrap();
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            owned.signal(libc::SIGKILL).unwrap();
            child.wait().unwrap();
            panic!("bounded admitted asset operation timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "asset admission/staging refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 1024 * 1024 && output.stderr.len() <= 16 * 1024);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stage(value: &Value, artifacts: &Path) -> Value {
    let mut command = asset_command("stage", value);
    command.arg("--stage-root").arg(artifacts);
    asset_run(command)
}

fn new_artifact_directory(parent: &Path) -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix("host-member-binaries-")
        .tempdir_in(parent)
        .unwrap();
    // Only this newly allocated fixture directory is changed. Admission still
    // independently checks its canonical path, owner, exact mode, and custody.
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn cleanup_assets(artifacts: &Path, dev: u64, ino: u64) {
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-B"])
        .arg(repository().join("scripts/dev/fixtures/host-member-managed-assets.py"))
        .args(["cleanup", "--stage-root"])
        .arg(artifacts)
        .arg("--root-device")
        .arg(dev.to_string())
        .arg("--root-inode")
        .arg(ino.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert_eq!(asset_run(command)["cleanup"], "identified-owned-tree-only");
}

#[test]
#[ignore = "requires explicitly admitted real agent payloads and protected broker; selected product journey"]
fn host_members_managed_two_real_endpoints_direct_and_tls_derp() {
    let value = inputs();
    assert_eq!(
        asset_run(asset_command("admit", &value))["status"],
        "admitted"
    );
    for transport in ["direct", "derp"] {
        let root = tempfile::tempdir().unwrap().keep();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact_parent = repository().join(".tmp");
        let metadata = fs::symlink_metadata(&artifact_parent).unwrap();
        assert!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0
                && !metadata.file_type().is_symlink()
        );
        let artifacts = new_artifact_directory(&artifact_parent).keep();
        let artifact_identity = fs::symlink_metadata(&artifacts).unwrap();
        for label in ["target", "caller"] {
            let path = artifacts.join(format!("{label}-cw"));
            fs::copy(value["cw"].as_str().unwrap(), &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
            assert_eq!(fs::symlink_metadata(&path).unwrap().nlink(), 1);
        }
        let staged = stage(&value, &artifacts);
        assert_eq!(staged["status"], "staged");
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
                "managed::managed_member_isolated_kernel_journey",
                "--nocapture",
            ])
            .env_clear()
            .env("CW_MEMBER_CASE_ROOT", &root)
            .env("CW_MEMBER_CASE_BINARIES", &artifacts)
            .env("CW_MEMBER_CASE_TRANSPORT", transport)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap();
        let owned =
            OwnedChild::capture(child.id(), Some(&std::env::current_exe().unwrap())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(280);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                owned.signal(libc::SIGTERM).unwrap();
                let grace = Instant::now() + Duration::from_secs(20);
                while child.try_wait().unwrap().is_none() && Instant::now() < grace {
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert!(
                    child.try_wait().unwrap().is_some(),
                    "unknown managed family; roots retained {} {}",
                    root.display(),
                    artifacts.display()
                );
                panic!(
                    "managed journey exceeded bound; roots retained {} {}",
                    root.display(),
                    artifacts.display()
                );
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "{}\n{}\nroots retained {} {}",
            String::from_utf8_lossy(&bounded_read(&root.join("child.stdout"))),
            String::from_utf8_lossy(&bounded_read(&root.join("child.stderr"))),
            root.display(),
            artifacts.display()
        );
        let report = json_file(&root.join("report.json"), 2 * 1024 * 1024);
        assert_eq!(report["kernel_echild"], true);
        assert_eq!(report["cleanup_salvage"], false);
        println!("observed managed member {transport}: {}", report);
        fs::remove_dir_all(&root).unwrap();
        cleanup_assets(&artifacts, artifact_identity.dev(), artifact_identity.ino());
    }
}

struct Actor {
    fd: OwnedFd,
    proc: File,
    image: File,
    path: PathBuf,
    pid: u32,
    birth: u64,
    parent: u32,
}
impl Actor {
    fn capture(pid: u32, birth: u64, parent: u32, path: &Path) -> Self {
        let fd = pidfd(pid);
        assert!(!terminal(&fd));
        let proc = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .unwrap();
        let image = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        let value = Self {
            fd,
            proc,
            image,
            path: path.to_owned(),
            pid,
            birth,
            parent,
        };
        value.verify();
        value
    }
    fn verify(&self) {
        assert!(
            !terminal(&self.fd),
            "original actor died before its explicit stop"
        );
        assert_eq!(
            birth_and_parent(&self.proc).unwrap(),
            (self.birth, self.parent)
        );
        assert_eq!(self.proc.metadata().unwrap().uid(), unsafe {
            libc::geteuid()
        });
        let expected = self.image.metadata().unwrap();
        assert!(
            expected.is_file()
                && expected.nlink() == 1
                && expected.uid() == unsafe { libc::geteuid() }
                && expected.mode() & 0o022 == 0
        );
        let image = fs::metadata(format!("/proc/{}/exe", self.pid)).unwrap();
        let named = fs::symlink_metadata(&self.path).unwrap();
        for current in [&image, &named] {
            assert!(
                same_diagnostic_inode(&expected, current)
                    && current.len() == expected.len()
                    && current.mtime() == expected.mtime()
                    && current.mtime_nsec() == expected.mtime_nsec()
            );
        }
        assert_eq!(
            fs::read_link(format!("/proc/{}/exe", self.pid)).unwrap(),
            self.path
        );
        assert_eq!(
            birth_and_parent(&self.proc).unwrap(),
            (self.birth, self.parent)
        );
        assert!(
            !terminal(&self.fd),
            "actor exited during identity observation"
        );
    }
    fn proof(&self) -> Value {
        json!({"pid":self.pid,"start_ticks":self.birth,"parent":self.parent,
        "executable":self.path,"dev":self.image.metadata().unwrap().dev(),"inode":self.image.metadata().unwrap().ino()})
    }
}

struct Conversation {
    session: String,
    driver: String,
    agent: &'static str,
    generation: u64,
    thread: String,
    actors: Vec<Actor>,
    peer: Value,
}

fn driver_dir(target: &Endpoint, env: &str, driver: &str) -> PathBuf {
    assert_eq!(Uuid::parse_str(driver).unwrap().to_string(), driver);
    target
        .root
        .join("hosts")
        .join(env)
        .join("agents")
        .join(driver)
}

async fn inbox(caller: &Endpoint, session: &str) -> Value {
    caller
        .json(
            &["--member", "target", "inbox", session, "--output", "json"],
            None,
        )
        .await
}

async fn until<F>(caller: &Endpoint, session: &str, accept: F) -> Value
where
    F: Fn(&Value) -> bool,
{
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let value = inbox(caller, session).await;
            if accept(&value) {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("bounded actual native observation")
}

async fn idle(caller: &Endpoint, session: &str) -> Value {
    until(caller, session, |v| {
        v["driver"]["phase"] == "idle" && v["driver"]["active_message_id"].is_null()
    })
    .await
}

async fn message(
    caller: &Endpoint,
    id: &str,
    expected: &str,
    claude_interrupt: Option<&Value>,
) -> Value {
    let output = caller
        .run(
            &[
                "--member",
                "target",
                "wait",
                "--message",
                id,
                "--timeout",
                "30s",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("public native message result");
    check_outcome(&value, id, expected, claude_interrupt);
    if expected == "completed" {
        assert!(output.status.success());
    }
    value
}
fn check_outcome(value: &Value, id: &str, expected: &str, claude_interrupt: Option<&Value>) {
    assert_eq!(value["id"], id);
    assert_eq!(value["state"], expected);
    if let Some(interrupt) = claude_interrupt {
        assert_eq!(interrupt["state"], "completed");
        assert_eq!(interrupt["action"], "interrupt");
        assert_eq!(interrupt["native_acknowledged"], true);
        assert_eq!(interrupt["expected_active_message_id"], id);
        assert_eq!(interrupt["driver_id"], value["driver_id"]);
        assert_eq!(interrupt["target_session_id"], value["target_session_id"]);
        assert_eq!(value["action"], "message");
        assert!(value["native_acknowledged"].is_boolean());
    } else {
        assert_eq!(value["native_acknowledged"], true);
    }
}

async fn send(caller: &Endpoint, session: &str, text: &str) -> Value {
    caller
        .json(
            &[
                "--member", "target", "msg", session, text, "--output", "json",
            ],
            None,
        )
        .await
}

async fn turn(caller: &Endpoint, conversation: &Conversation) -> Value {
    let queued = send(caller, &conversation.session, PROMPT).await;
    let result = message(caller, queued["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(result["driver_id"], conversation.driver);
    assert_eq!(result["member_launch_generation"], conversation.generation);
    assert_eq!(
        idle(caller, &conversation.session).await["driver"]["native_thread_id"],
        conversation.thread
    );
    assert!(
        result["result"]
            .as_str()
            .unwrap()
            .contains(if conversation.agent == "codex" {
                "CWCODEX149"
            } else {
                "CWCLAUDE"
            })
    );
    result
}

async fn launch(
    caller: &Endpoint,
    target: &Endpoint,
    env: &str,
    staged: &Value,
    agent: &'static str,
    name: &str,
    parent: Option<&Conversation>,
) -> (Conversation, Value) {
    let request = Uuid::new_v4().to_string();
    let mut args = vec![
        "--member",
        "target",
        "run",
        "--agent",
        agent,
        "--name",
        name,
        "--model",
        if agent == "codex" {
            "codewire-synthetic"
        } else {
            "claude-sonnet-4-6"
        },
        "--detach",
        "--request-id",
        &request,
        "--prompt",
        PROMPT,
        "--output",
        "json",
    ];
    if let Some(parent) = parent {
        args.extend(["--parent", &parent.session]);
    }
    let value = caller.json(&args, None).await;
    assert_eq!(value["request"]["request_id"], request);
    let session = value["session"]["session_id"].as_str().unwrap().to_owned();
    assert_eq!(session, format!("session-{request}"));
    let driver = value["conversation"]["driver_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(driver, request);
    let first = message(
        caller,
        value["initial_message"]["id"].as_str().unwrap(),
        "completed",
        None,
    )
    .await;
    let view = idle(caller, &session).await;
    let thread = view["driver"]["native_thread_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!thread.is_empty());
    let mut conversation = Conversation {
        session,
        driver,
        agent,
        generation: 1,
        thread,
        actors: Vec::new(),
        peer: Value::Null,
    };
    retain(target, env, staged, &mut conversation);
    (conversation, first)
}

fn retain(target: &Endpoint, env: &str, staged: &Value, conversation: &mut Conversation) {
    let dir = driver_dir(target, env, &conversation.driver);
    let identity = json_file(&dir.join("peer-current.json"), 64 * 1024);
    assert_eq!(identity["driver_id"], conversation.driver);
    assert_eq!(identity["session_id"], conversation.session);
    assert_eq!(identity["environment_id"], env);
    assert_eq!(
        Uuid::parse_str(identity["instance_id"].as_str().unwrap())
            .unwrap()
            .to_string(),
        identity["instance_id"]
    );
    let receipt = json_file(
        &dir.join(format!(
            "peer-{}.json",
            identity["instance_id"].as_str().unwrap()
        )),
        64 * 1024,
    );
    assert_eq!(receipt["identity"], identity);
    assert_eq!(receipt["cleanup_unknown"], true);
    assert!(receipt["finished_at"].is_null());
    let pid = identity["driver_pid"].as_u64().unwrap() as u32;
    let driver_proc = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}"))
        .unwrap();
    let (_, parent) = birth_and_parent(&driver_proc).unwrap();
    let driver = Actor::capture(
        pid,
        identity["driver_start_ticks"].as_u64().unwrap(),
        parent,
        &target.binary,
    );
    let guardian_pid = receipt["guardian_pid"].as_u64().unwrap() as u32;
    let guardian = Actor::capture(
        guardian_pid,
        receipt["guardian_start_ticks"].as_u64().unwrap(),
        pid,
        &target.binary,
    );
    let provider_pid = receipt["provider_pid"].as_u64().unwrap() as u32;
    let provider_proc = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/proc/{provider_pid}"))
        .unwrap();
    let (birth, provider_parent) = birth_and_parent(&provider_proc).unwrap();
    assert_eq!(provider_parent, guardian_pid);
    let provider_path = Path::new(staged["payload"].as_str().unwrap()).join(
        staged["agents"][conversation.agent]["entry"]
            .as_str()
            .unwrap(),
    );
    let provider = Actor::capture(provider_pid, birth, guardian_pid, &provider_path);
    let args = proc_bytes(&provider.proc, "cmdline", 16 * 1024).unwrap();
    let required_argument: &[u8] = if conversation.agent == "codex" {
        b"app-server"
    } else {
        b"--input-format"
    };
    assert!(
        args.split(|b| *b == 0)
            .any(|part| part == required_argument)
    );
    conversation.actors = vec![driver, guardian, provider];
    conversation.peer = receipt;
}

async fn parent_once(
    caller: &Endpoint,
    source: &Value,
    worker: &Conversation,
    parent: &Conversation,
) -> Value {
    let inbox = until(caller, &parent.session, |v| {
        v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["source"]["message_id"] == source["id"])
    })
    .await;
    let rows = inbox["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["source"]["message_id"] == source["id"])
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    let row = rows[0];
    assert_eq!(row["source"]["session_id"], worker.session);
    assert_eq!(row["source"]["driver_id"], worker.driver);
    assert_eq!(row["action"], "notification");
    let result = message(caller, row["id"].as_str().unwrap(), "completed", None).await;
    idle(caller, &parent.session).await;
    result
}

fn held_owner_tuple(value: &Value, conversation: &Conversation) {
    assert_eq!(value["session"]["session_id"], conversation.session);
    assert_eq!(
        value["session"]["launch_generation"].as_u64(),
        Some(conversation.generation)
    );
    assert_eq!(value["driver"]["driver_id"], conversation.driver);
    assert_eq!(value["driver"]["agent"], conversation.agent);
    assert_eq!(value["driver"]["native_thread_id"], conversation.thread);
}

fn clean_stopped_session(value: &Value, session: &str, generation: u64) {
    let rows = value.as_array().expect("public stopped session results");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["session_id"], session);
    assert_eq!(row["launch_generation"].as_u64(), Some(generation));
    assert_eq!(row["cleanup_unknown"], false);
    // Managed shutdown lets the controlled driver exit normally; ordinary
    // daemon Stop records Stopped. Both require the original known family.
    assert!(
        row["state"] == "Stopped"
            || (row["state"] == "Exited" && row["exit_code"].as_i64() == Some(0))
    );
}

fn caller_active(value: &Value, session: &str, driver: &str) -> bool {
    value["session"]["session_id"] == session
        && value["session"]["launch_generation"].as_u64() == Some(1)
        && value["driver"]["driver_id"] == driver
        && value["driver"]["agent"] == "codex"
        && value["driver"]["native_thread_id"]
            .as_str()
            .is_some_and(|thread| !thread.is_empty())
        && value["driver"]["phase"] == "busy"
        && value["driver"]["current_turn_id"].as_str().is_some()
        && value["messages"].as_array().unwrap().iter().any(|message| {
            message["id"] == value["driver"]["active_message_id"]
                && message["state"] == "running"
                && message["native_acknowledged"] == true
                && message["turn_id"] == value["driver"]["current_turn_id"]
        })
}

async fn held(caller: &Endpoint, conversation: &Conversation, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
    let mut since = None;
    let mut pinned = None;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "bounded original held turn"
        );
        let value = inbox(caller, &conversation.session).await;
        let records = value["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["id"] == id)
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        let record = records[0];
        held_owner_tuple(&value, conversation);
        assert!(
            !["completed", "error", "interrupted", "unknown"]
                .contains(&record["state"].as_str().unwrap())
        );
        let mut active = value["driver"]["phase"] == "busy"
            && value["driver"]["active_message_id"] == id
            && record["state"] == "running";
        if conversation.agent == "codex" && active {
            active = record["native_acknowledged"] == true
                && value["driver"]["current_turn_id"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty());
            if active {
                let turn = value["driver"]["current_turn_id"].clone();
                assert_eq!(record["turn_id"], turn);
                if let Some(pin) = &pinned {
                    assert_eq!(&turn, pin);
                }
                pinned = Some(turn);
            }
        }
        if active {
            let start = *since.get_or_insert_with(tokio::time::Instant::now);
            if start.elapsed() >= Duration::from_secs(2) {
                return value;
            }
        } else {
            since = None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn interrupt(caller: &Endpoint, conversation: &Conversation) -> Value {
    let hold = send(
        caller,
        &conversation.session,
        &format!(
            "CW_FIXTURE_HOLD {}\nWait.",
            &Uuid::new_v4().simple().to_string()[..8]
        ),
    )
    .await;
    let id = hold["id"].as_str().unwrap();
    let view = held(caller, conversation, id).await;
    let queued = caller
        .json(
            &[
                "--member",
                "target",
                "interrupt",
                &conversation.session,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let control = message(caller, queued["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(control["expected_active_message_id"], id);
    assert_eq!(
        control["expected_turn_id"],
        view["driver"]["current_turn_id"]
    );
    let done = message(
        caller,
        id,
        "interrupted",
        (conversation.agent == "claude").then_some(&control),
    )
    .await;
    if conversation.agent == "codex" {
        assert_eq!(done["turn_id"], view["driver"]["current_turn_id"]);
    }
    assert_eq!(
        idle(caller, &conversation.session).await["driver"]["native_thread_id"],
        conversation.thread
    );
    done
}

async fn assert_refused(caller: &Endpoint, args: &[&str]) {
    assert!(
        !caller.run(args, None).await.status.success(),
        "expected typed refusal"
    );
}

fn ready_frame(ready: &Value, environment: &str) {
    let keys = [
        "schema",
        "environment_id",
        "codex_base_url",
        "anthropic_base_url",
        "capability",
        "upstream",
        "protected_store",
    ];
    let object = ready.as_object().unwrap();
    assert_eq!(object.len(), keys.len());
    assert!(keys.iter().all(|key| object.contains_key(*key)));
    assert_eq!(ready["schema"], "codewire.host-agent-smoke/v1");
    assert_eq!(ready["environment_id"], environment);
    assert_eq!(ready["upstream"], "synthetic");
    assert_eq!(ready["protected_store"], "process_lifetime");
    let codex_url = ready["codex_base_url"].as_str().unwrap();
    let port = codex_url
        .strip_prefix("http://127.0.0.1:")
        .unwrap()
        .strip_suffix("/codex/v1")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    assert!(port > 0);
    assert_eq!(codex_url, format!("http://127.0.0.1:{port}/codex/v1"));
    assert_eq!(
        ready["anthropic_base_url"],
        format!("http://127.0.0.1:{port}/anthropic")
    );
    let capability = ready["capability"].as_str().unwrap();
    assert!(
        capability.len() == 69
            && capability.starts_with("cwhm_")
            && capability.as_bytes()[5..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    );
}

async fn wait_terminal(fd: &OwnedFd, bound: Duration) -> bool {
    tokio::time::timeout(bound, async {
        while !terminal(fd) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

async fn actual(root: &Path, artifacts: &Path, direct: bool) -> Value {
    let staged = json_file(&artifacts.join("managed-assets.json"), 1024 * 1024);
    assert_eq!(staged["status"], "staged");
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
    let (mut target, caller) = endpoints(root, artifacts, &server.origin, direct);
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
    let env = created["id"].as_str().unwrap().to_owned();
    let initial = daemon(&target, &env).await;
    target
        .json(&["stop", "--local", &env, "--output", "json"], None)
        .await;
    assert!(
        wait_terminal(&initial.fd, Duration::from_secs(10)).await,
        "original setup daemon death remained unknown after public Stop"
    );
    assert!(terminal(&initial.fd));
    private(&target.root.join("authority"));
    let mut command = Command::new(staged["broker_path"].as_str().unwrap());
    command
        .args([
            "--root",
            target.root.join("authority").to_str().unwrap(),
            "--environment",
            &env,
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", target.root.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let mut broker = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let broker_owned = OwnedChild::capture_launch(
        broker.id().unwrap(),
        Path::new(staged["broker_path"].as_str().unwrap()),
        ready_deadline,
    )
    .unwrap();
    let mut reader = BufReader::new(broker.stdout.take().unwrap());
    let ready = tokio::time::timeout_at(tokio::time::Instant::from_std(ready_deadline), async {
        let mut value = Vec::new();
        loop {
            assert!(value.len() < 2048, "bounded private ready frame");
            let byte = reader.read_u8().await.unwrap();
            value.push(byte);
            if byte == b'\n' {
                break value;
            }
        }
    })
    .await
    .unwrap();
    let ready: Value = serde_json::from_slice(&ready).unwrap();
    ready_frame(&ready, &env);
    let codex_url = ready["codex_base_url"].as_str().unwrap();
    let anthropic_url = ready["anthropic_base_url"].as_str().unwrap();
    let capability = ready["capability"].as_str().unwrap();
    let codex_home = target.root.join("home/.codex");
    private(&codex_home);
    let config = format!(
        "model_provider = \"codewire_host_fixture\"\nmodel = \"codewire-synthetic\"\n[model_providers.codewire_host_fixture]\nname = \"Codewire protected synthetic host\"\nbase_url = {}\nwire_api = \"responses\"\nenv_key = \"CW_HOST_AGENT_CAPABILITY\"\nrequires_openai_auth = false\nsupports_websockets = false\nrequest_max_retries = 0\nstream_max_retries = 0\nstream_idle_timeout_ms = 660000\n",
        serde_json::to_string(codex_url).unwrap()
    );
    fs::write(codex_home.join("config.toml"), config).unwrap();
    fs::set_permissions(
        codex_home.join("config.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for (key, value) in [
        (
            "PATH",
            format!("{}:/usr/bin:/bin", staged["agent_bin"].as_str().unwrap()),
        ),
        ("CODEX_HOME", codex_home.display().to_string()),
        ("CW_HOST_AGENT_CAPABILITY", capability.into()),
        ("ANTHROPIC_AUTH_TOKEN", capability.into()),
        ("ANTHROPIC_BASE_URL", anthropic_url.into()),
        ("HTTP_PROXY", "http://127.0.0.1:1".into()),
        ("HTTPS_PROXY", "http://127.0.0.1:1".into()),
        ("ALL_PROXY", "http://127.0.0.1:1".into()),
        ("NO_PROXY", "127.0.0.1,localhost".into()),
        ("no_proxy", "127.0.0.1,localhost".into()),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1".into()),
        ("CLAUDE_CODE_DISABLE_AUTO_UPDATER", "1".into()),
        ("ANTHROPIC_API_KEY", "".into()),
        ("CLAUDE_CODE_OAUTH_TOKEN", "".into()),
        ("ANTHROPIC_MAX_RETRIES", "0".into()),
    ] {
        target.extra_environment.insert(key.into(), value);
    }
    for (name, expected) in [
        ("codex", "codex-cli 0.160.0"),
        ("claude", "2.1.288 (Claude Code)"),
    ] {
        let mut version = Command::new(Path::new(staged["agent_bin"].as_str().unwrap()).join(name));
        version
            .arg("--version")
            .env_clear()
            .env("HOME", target.root.join("home"))
            .env("PATH", "/usr/bin:/bin");
        let output = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::process::Command::from(version)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            std::str::from_utf8(&output.stdout).unwrap().trim(),
            expected
        );
    }
    target
        .json(&["start", "--local", &env, "--output", "json"], None)
        .await;
    let daemon = daemon(&target, &env).await;
    assert_ne!(daemon.birth, initial.birth);
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
    target
        .json(
            &[
                "control",
                "grant",
                "--environment",
                &env,
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
                ALLOW,
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
    let mut up = vec![
        "member",
        "up",
        &env,
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
    let helper =
        OwnedChild::capture(ready["pid"].as_u64().unwrap() as u32, Some(&target.binary)).unwrap();
    add(&caller, "target", &env, target_key, wg, &grant, !direct).await;
    let mut checks = vec!["admitted-real-agents/protected-broker/retained-host-setup".to_owned()];
    let (lead, first) = launch(&caller, &target, &env, &staged, "codex", "lead", None).await;
    let second = turn(&caller, &lead).await;
    assert_ne!(first["turn_id"], second["turn_id"]);
    let marker = format!(
        ".cwnm-{}-tool-marker",
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let token = format!(
        "CW_TOOL_MARKER_{}",
        Uuid::new_v4().simple().to_string()[..16].to_uppercase()
    );
    let task = send(
        &caller,
        &lead.session,
        &format!("CW_FIXTURE_TOOL printf %s {token} > {marker}\nUse the offered shell tool once."),
    )
    .await;
    message(&caller, task["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(
        fs::read_to_string(target.root.join("workspace").join(&marker)).unwrap(),
        token
    );
    checks.push("codex/two-native-acknowledged-turns/tool/same-thread".into());
    let (mut worker, worker_first) = launch(
        &caller,
        &target,
        &env,
        &staged,
        "claude",
        "worker",
        Some(&lead),
    )
    .await;
    parent_once(&caller, &worker_first, &worker, &lead).await;
    let worker_second = turn(&caller, &worker).await;
    parent_once(&caller, &worker_second, &worker, &lead).await;
    checks.push("claude/continuation/same-target-parent/adopted-once".into());
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "steer",
            &worker.session,
            "unsupported",
            "--output",
            "json",
        ],
    )
    .await;
    let interrupted = interrupt(&caller, &lead).await;
    assert_eq!(interrupted["driver_id"], lead.driver);
    let interrupted = interrupt(&caller, &worker).await;
    parent_once(&caller, &interrupted, &worker, &lead).await;
    checks.push("codex/claude-exact-native-interrupt/unsupported-steer-refused".into());
    let nonce = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let hold = send(
        &caller,
        &lead.session,
        &format!("CW_FIXTURE_UPDATE_STEERABLE {nonce}\nWait for native steering."),
    )
    .await;
    let active = held(&caller, &lead, hold["id"].as_str().unwrap()).await;
    let turn_id = active["driver"]["current_turn_id"].as_str().unwrap();
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "steer",
            &lead.session,
            "wrong",
            "--turn-id",
            "wrong-turn",
            "--output",
            "json",
        ],
    )
    .await;
    let steered = caller
        .json(
            &[
                "--member",
                "target",
                "steer",
                &lead.session,
                &format!("CW_FIXTURE_UPDATE_STEER {nonce}\nFinish now."),
                "--turn-id",
                turn_id,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    until(&caller, &lead.session, |v| {
        v["messages"].as_array().unwrap().iter().any(|m| {
            m["id"] == steered["id"] && m["native_acknowledged"] == true && m["state"] == "running"
        })
    })
    .await;
    assert_eq!(
        inbox(&caller, &lead.session).await["driver"]["current_turn_id"],
        turn_id
    );
    let (release, _) = launch(&caller, &target, &env, &staged, "codex", "release", None).await;
    let released = send(
        &caller,
        &release.session,
        &format!("CW_FIXTURE_UPDATE_RELEASE {nonce}\nRelease once."),
    )
    .await;
    let ack = message(&caller, released["id"].as_str().unwrap(), "completed", None).await;
    assert!(
        ack["result"]
            .as_str()
            .unwrap()
            .contains(&format!("CW_UPDATE_RELEASE_ACK {nonce}"))
    );
    message(&caller, steered["id"].as_str().unwrap(), "completed", None).await;
    let done = message(&caller, hold["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(done["turn_id"], turn_id);
    assert!(
        done["result"]
            .as_str()
            .unwrap()
            .contains(&format!("CW_UPDATE_STEERED {nonce}"))
    );
    assert!(
        !done["result"]
            .as_str()
            .unwrap()
            .contains("CW_UPDATE_HOLD_EXPIRED")
    );
    idle(&caller, &lead.session).await;
    checks.push("same-Codex-turn/steer-native-ack-before-independent-release".into());
    for c in [&lead, &worker, &release] {
        for actor in &c.actors {
            actor.verify();
        }
    }
    let stopped = caller
        .json(
            &[
                "--member",
                "target",
                "stop",
                "--session",
                &worker.session,
                "--expected-launch-generation",
                "1",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    clean_stopped_session(&stopped, &worker.session, worker.generation);
    for actor in &worker.actors {
        assert!(terminal(&actor.fd));
    }
    let dir = driver_dir(&target, &env, &worker.driver);
    let clean = json_file(
        &dir.join(format!(
            "peer-{}.json",
            worker.peer["identity"]["instance_id"].as_str().unwrap()
        )),
        64 * 1024,
    );
    assert_eq!(clean["cleanup_unknown"], false);
    assert!(clean["finished_at"].as_str().is_some());
    let restarted = caller
        .json(
            &[
                "--member",
                "target",
                "restart",
                "--session",
                &worker.session,
                "--expected-launch-generation",
                "1",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(restarted[0]["launch_generation"], 2);
    worker.generation = 2;
    let continued = turn(&caller, &worker).await;
    parent_once(&caller, &continued, &worker, &lead).await;
    retain(&target, &env, &staged, &mut worker);
    let old = message(
        &caller,
        worker_first["id"].as_str().unwrap(),
        "completed",
        None,
    )
    .await;
    assert_eq!(old["member_launch_generation"], 1);
    let before = inbox(&caller, &worker.session).await;
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "msg",
            &worker.session,
            "stale",
            "--expected-launch-generation",
            "1",
            "--output",
            "json",
        ],
    )
    .await;
    assert_eq!(inbox(&caller, &worker.session).await, before);
    checks.push("known-guardian-ECHILD/driver-death-before-restart-CAS/same-thread/terminal-A-history/stale-refused".into());
    // The heavily escaped legal prompt forces an actual multi-frame retained
    // message read, without changing the synthetic provider response grammar.
    let large = "\u{1}".repeat(60 * 1024);
    let queued = send(&caller, &release.session, &large).await;
    let retained = message(&caller, queued["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(retained["text"], large);
    assert!(serde_json::to_vec(&retained).unwrap().len() > 256 * 1024);
    checks.push("actual-bounded-segmented-retained-native-message".into());
    caller_loss(&caller, &target, &env, &staged, &release, &mut checks).await;
    let before = inbox(&caller, &lead.session).await;
    let id = Uuid::new_v4().to_string();
    let once = caller
        .json(
            &[
                "--member",
                "target",
                "msg",
                &lead.session,
                PROMPT,
                "--request-id",
                &id,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    message(&caller, once["id"].as_str().unwrap(), "completed", None).await;
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "msg",
            &lead.session,
            "different",
            "--request-id",
            &id,
            "--output",
            "json",
        ],
    )
    .await;
    let after = inbox(&caller, &lead.session).await;
    assert_eq!(
        after["messages"].as_array().unwrap().len(),
        before["messages"].as_array().unwrap().len() + 1
    );
    checks.push("request-UUID/collision/no-second-message".into());
    target
        .json(
            &[
                "control",
                "revoke",
                "--environment",
                &env,
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
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "inbox",
            &lead.session,
            "--output",
            "json",
        ],
    )
    .await;
    assert_refused(
        &caller,
        &[
            "--member",
            "target",
            "msg",
            &lead.session,
            "never issued",
            "--output",
            "json",
        ],
    )
    .await;
    let observed = caller
        .json(
            &["member", "observe", "target", &id, "--output", "json"],
            None,
        )
        .await;
    assert_eq!(observed["request_id"], id);
    for c in [&lead, &worker, &release] {
        for actor in &c.actors {
            actor.verify();
        }
    }
    assert!(!terminal(&daemon.fd) && !terminal(&helper.fd));
    assert_eq!(
        fs::read(target.root.join("workspace/sentinel")).unwrap(),
        b"unrelated-preserved"
    );
    checks.push(
        "revocation/no-new-reads-or-effects/original-observe/actors-and-sentinel-preserved".into(),
    );
    // The target owner explicitly admits a new current revision for cleanup.
    // Original identities stay bound; the revoked alias is never reused.
    let fresh = target
        .json(
            &[
                "control",
                "grant",
                "--environment",
                &env,
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
                ALLOW,
                "--expected-book-revision",
                "2",
                "--expected-grant-revision",
                "2",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(fresh["book_revision"], 3);
    let mut alias = vec![
        "member",
        "add",
        "target-renewed",
        "--mesh-url",
        &caller.origin,
        "--org",
        ORG,
        "--network",
        NETWORK,
        "--environment",
        &env,
        "--node",
        NODE,
        "--target-key",
        target_key,
        "--target-wg-key",
        wg,
        "--grant-id",
        &grant,
        "--grant-revision",
        "3",
        "--require-transport",
        if direct { "direct_udp" } else { "derp" },
    ];
    if !direct {
        alias.push("--derp-only");
    }
    assert!(caller.run(&alias, None).await.status.success());
    for c in [&lead, &worker, &release] {
        let stopped = caller
            .json(
                &[
                    "--member",
                    "target-renewed",
                    "stop",
                    "--session",
                    &c.session,
                    "--output",
                    "json",
                ],
                None,
            )
            .await;
        assert_eq!(stopped[0]["cleanup_unknown"], false);
        for actor in &c.actors {
            assert!(terminal(&actor.fd));
        }
    }
    target
        .json(&["member", "down", "--output", "json"], None)
        .await;
    assert!(terminal(&helper.fd));
    assert!(!terminal(&daemon.fd));
    target
        .json(&["stop", "--local", &env, "--output", "json"], None)
        .await;
    assert!(terminal(&daemon.fd));
    broker.stdin.take();
    tokio::time::timeout(Duration::from_secs(10), broker.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(terminal(&broker_owned.fd));
    drop(reader);
    drop(server);
    checks.push("explicit-known-owned-cleanup/no-owner-autostart".into());
    let witnesses = caller.path_witnesses.lock().unwrap().clone();
    assert!(
        witnesses
            .iter()
            .all(|w| w["environment_id"] == env && w["qualified"] == true)
    );
    let report = json!({"schema":"codewire.actual-member-managed-journey/v1","transport":if direct{"direct_udp"}else{"derp"},
        "environment_id":env,"checks":checks,"actual_exchange_path_witnesses":witnesses,
        "conversations":[conversation_proof(&lead),conversation_proof(&worker),conversation_proof(&release)],
        "assets":staged,"claims":{"actual_agents":true,"upstream":"synthetic","live_provider":false,"os_keyring":false,
        "egress_mediation":false,"nat_traversal":false,"compiled_component_reuse":true,"current_source_release_proof":false,
        "caller_wait_cancellation":true,"lost_mutate_reply_actual":false},"rpc_loss_component":"frozen-01 daemon-member/wire partial-loss component receipts"});
    assert!(!report.to_string().contains("cwhm_"));
    report
}

async fn daemon(target: &Endpoint, env: &str) -> OwnedChild {
    let stream =
        tokio::net::UnixStream::connect(target.root.join("hosts").join(env).join("daemon.sock"))
            .await
            .unwrap();
    OwnedChild::capture(
        stream.peer_cred().unwrap().pid().unwrap() as u32,
        Some(&target.binary),
    )
    .unwrap()
}

fn conversation_proof(c: &Conversation) -> Value {
    json!({"session_id":c.session,"driver_id":c.driver,"agent":c.agent,"launch_generation":c.generation,
        "native_thread_id":c.thread,"actors":c.actors.iter().map(Actor::proof).collect::<Vec<_>>()})
}

async fn caller_loss(
    caller: &Endpoint,
    target: &Endpoint,
    env: &str,
    staged: &Value,
    release: &Conversation,
    checks: &mut Vec<String>,
) {
    let nonce = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let request = Uuid::new_v4().to_string();
    let prompt = format!("CW_FIXTURE_UPDATE_STEERABLE {nonce}\nWait for the native steer.");
    let args = [
        "--member",
        "target",
        "run",
        "--agent",
        "codex",
        "--model",
        "codewire-synthetic",
        "--name",
        "cancelled-wait",
        "--request-id",
        &request,
        "--prompt",
        &prompt,
    ];
    let command = caller.command(&args);
    let witness_deadline = Instant::now() + Duration::from_secs(35);
    let mut process = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let owned = OwnedChild::capture_launch(process.id().unwrap(), &caller.binary, witness_deadline)
        .unwrap();
    let mut stderr = BufReader::new(process.stderr.take().unwrap());
    let stdout = process.stdout.take().unwrap();
    let session = format!("session-{request}");
    let witness =
        tokio::time::timeout_at(tokio::time::Instant::from_std(witness_deadline), async {
            let mut log = Vec::new();
            loop {
                let mut bytes = Vec::new();
                loop {
                    assert!(
                        log.len() + bytes.len() < 128 * 1024,
                        "bounded caller transport frame"
                    );
                    let byte = stderr.read_u8().await.unwrap();
                    bytes.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                let line = std::str::from_utf8(&bytes).unwrap();
                log.extend_from_slice(&bytes);
                if let Some(raw) = line.trim_end().strip_prefix("[cw] member transport ") {
                    let value: Value = serde_json::from_str(raw).unwrap();
                    if value["action"] == 2 && value["request_id"] == request {
                        assert_eq!(value["qualified"], true);
                        return log;
                    }
                }
            }
        })
        .await
        .expect("original managed caller's own Mutate witness");
    let active = until(caller, &session, |v| caller_active(v, &session, &request)).await;
    let original_id = active["driver"]["active_message_id"].clone();
    let original_turn = active["driver"]["current_turn_id"].clone();
    assert!(!terminal(&owned.fd));
    owned.signal(libc::SIGKILL).unwrap();
    let status = process.wait().await.unwrap();
    caller.record_path_witnesses(
        &args,
        &Output {
            status,
            stdout: Vec::new(),
            stderr: witness,
        },
    );
    drop(stdout);
    drop(stderr);
    let observed = caller
        .json(
            &["member", "observe", "target", &request, "--output", "json"],
            None,
        )
        .await;
    assert_eq!(observed["session_id"], session);
    assert_eq!(observed["driver_id"], request);
    assert_eq!(observed["message_id"], original_id);
    let thread = active["driver"]["native_thread_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut cancelled = Conversation {
        session,
        driver: request.clone(),
        agent: "codex",
        generation: 1,
        thread,
        actors: Vec::new(),
        peer: Value::Null,
    };
    retain(target, env, staged, &mut cancelled);
    // Cancellation of the caller's completion wait does not interrupt/replay
    // the independently owned native turn. Explicit matched interrupt closes it.
    let queued = caller
        .json(
            &[
                "--member",
                "target",
                "interrupt",
                &cancelled.session,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let control = message(caller, queued["id"].as_str().unwrap(), "completed", None).await;
    assert_eq!(control["expected_active_message_id"], original_id);
    assert_eq!(control["expected_turn_id"], original_turn);
    let original = message(
        caller,
        control["expected_active_message_id"].as_str().unwrap(),
        "interrupted",
        None,
    )
    .await;
    assert_eq!(original["target_session_id"], cancelled.session);
    assert_eq!(original["turn_id"], original_turn);
    let next = turn(caller, &cancelled).await;
    assert_eq!(next["driver_id"], request);
    let release_turn = turn(caller, release).await;
    assert_eq!(release_turn["driver_id"], release.driver);
    let stopped = caller
        .json(
            &[
                "--member",
                "target",
                "stop",
                "--session",
                &cancelled.session,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    assert_eq!(stopped[0]["cleanup_unknown"], false);
    for actor in &cancelled.actors {
        assert!(terminal(&actor.fd));
    }
    checks.push(
        "caller-wait-killed-after-own-Mutate-witness/original-observe/no-native-replay".into(),
    );
}

#[test]
#[ignore = "invoked only by the exact managed parent fixture"]
fn managed_member_isolated_kernel_journey() {
    use futures::FutureExt;
    let root = PathBuf::from(std::env::var_os("CW_MEMBER_CASE_ROOT").unwrap());
    let artifacts = PathBuf::from(std::env::var_os("CW_MEMBER_CASE_BINARIES").unwrap());
    for directory in [&root, &artifacts] {
        let metadata = fs::symlink_metadata(directory).unwrap();
        assert!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o700
        );
        assert_eq!(fs::canonicalize(directory).unwrap(), *directory);
    }
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    assert!(subreaper(1));
    assert!(Path::new("/proc/thread-self/children").exists());
    let direct = match std::env::var("CW_MEMBER_CASE_TRANSPORT").unwrap().as_str() {
        "direct" => true,
        "derp" => false,
        _ => panic!("closed transport case"),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let result=runtime.block_on(async{let mut terminate=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select!{result=tokio::time::timeout(Duration::from_secs(240),std::panic::AssertUnwindSafe(actual(&root,&artifacts,direct)).catch_unwind())=>result.ok().and_then(Result::ok),_=terminate.recv()=>None,}});
    drop(runtime);
    assert!(subreaper(1));
    let clean = reap_all_until(Instant::now() + Duration::from_secs(5));
    if result.is_none() || !clean {
        let salvaged = salvage_owned_family(Instant::now() + Duration::from_secs(10));
        fs::write(
            root.join("cleanup-failure.json"),
            serde_json::to_vec_pretty(&json!({"product_success":false,"cleanup_salvage":true,
            "kernel_echild":salvaged.as_ref().is_ok_and(|v|*v),"roots_retained":true}))
            .unwrap(),
        )
        .unwrap();
        panic!(
            "managed product/normal cleanup failed; roots retained {}; salvage ECHILD {:?}",
            root.display(),
            salvaged
        );
    }
    let mut report = result.unwrap();
    report["kernel_echild"] = json!(true);
    report["cleanup_salvage"] = json!(false);
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

#[test]
fn managed_fixture_new_artifact_root_passes_exact_private_stage_guard() {
    fs::create_dir_all(repository().join(".tmp")).unwrap();
    let parent = tempfile::tempdir_in(repository().join(".tmp")).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = parent.path().join("unrelated-sentinel");
    fs::write(&sentinel, b"preserved").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let unsafe_directory = tempfile::tempdir_in(parent.path()).unwrap();
    fs::set_permissions(unsafe_directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let artifacts = new_artifact_directory(parent.path());
    let program = r#"
import importlib.util, os, stat, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('managed_private_guard', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
host = module.host_fixture()
unsafe, private = (Path(value) for value in sys.argv[2:])
before = host.stable(unsafe.lstat())
try:
    host.admit_scratch(unsafe)
except host.Failure as error:
    assert str(error) == 'unsafe directory permissions'
else:
    raise AssertionError('0755 stage root was admitted')
assert host.stable(unsafe.lstat()) == before
before = host.stable(private.lstat())
assert private.lstat().st_uid == os.geteuid()
assert stat.S_IMODE(private.lstat().st_mode) == 0o700
assert host.admit_scratch(private) == private
assert host.stable(private.lstat()) == before
print('0755-refused/production-0700-admitted/unchanged')
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", program])
        .arg(repository().join("scripts/dev/fixtures/host-member-managed-assets.py"))
        .arg(unsafe_directory.path())
        .arg(artifacts.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exact private stage guard: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"0755-refused/production-0700-admitted/unchanged\n"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserved");
}

#[test]
fn managed_fixture_closed_inputs_refuse_missing_extra_nonstring_and_wrong_schema() {
    let mut value = json!({"schema":"codewire.member-managed-inputs/v1","cw":"/owned/cw","cw_sha256":"pin",
        "component_manifest":"/owned/manifest","component_sha256":"pin","agents_manifest":"/owned/agents",
        "agents_sha256":"pin","broker":"/owned/broker","broker_receipt":"/owned/receipt"});
    closed_inputs(&value);
    for field in INPUT_KEYS {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(*field);
        assert!(std::panic::catch_unwind(|| closed_inputs(&bad)).is_err());
    }
    value["other"] = json!(true);
    assert!(std::panic::catch_unwind(|| closed_inputs(&value)).is_err());
    value.as_object_mut().unwrap().remove("other");
    for field in INPUT_KEYS {
        let mut bad = value.clone();
        bad[*field] = json!(false);
        assert!(std::panic::catch_unwind(|| closed_inputs(&bad)).is_err());
    }
}

#[test]
fn managed_fixture_private_file_refuses_fifo_link_mode_and_bounds() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("record.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(json_file(&path, 64), json!({}));
    let linked = root.path().join("link");
    std::os::unix::fs::symlink(&path, &linked).unwrap();
    assert!(std::panic::catch_unwind(|| json_file(&linked, 64)).is_err());
    fs::remove_file(&linked).unwrap();
    fs::hard_link(&path, &linked).unwrap();
    assert!(std::panic::catch_unwind(|| json_file(&path, 64)).is_err());
    fs::remove_file(&linked).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(std::panic::catch_unwind(|| json_file(&path, 64)).is_err());
    fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(std::panic::catch_unwind(|| json_file(&path, 64)).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(std::panic::catch_unwind(|| json_file(&path, 1)).is_err());
}

#[test]
fn managed_fixture_native_ack_is_not_manufactured_for_claude_interrupt() {
    let message = json!({"id":"original","state":"interrupted","action":"message","driver_id":"driver",
        "target_session_id":"session","native_acknowledged":false});
    let control = json!({"state":"completed","action":"interrupt","native_acknowledged":true,
        "expected_active_message_id":"original","driver_id":"driver","target_session_id":"session"});
    check_outcome(&message, "original", "interrupted", Some(&control));
    assert_eq!(message["native_acknowledged"], false);
    assert!(
        std::panic::catch_unwind(|| check_outcome(&message, "original", "interrupted", None))
            .is_err()
    );
    for field in [
        "state",
        "action",
        "native_acknowledged",
        "expected_active_message_id",
        "driver_id",
        "target_session_id",
    ] {
        let mut bad = control.clone();
        bad[field] = json!("wrong");
        assert!(
            std::panic::catch_unwind(|| check_outcome(
                &message,
                "original",
                "interrupted",
                Some(&bad)
            ))
            .is_err()
        );
    }
}

#[test]
fn managed_fixture_ready_is_closed_synthetic_and_exact_loopback() {
    let value = json!({"schema":"codewire.host-agent-smoke/v1","environment_id":"owned",
        "codex_base_url":"http://127.0.0.1:42424/codex/v1",
        "anthropic_base_url":"http://127.0.0.1:42424/anthropic",
        "capability":format!("cwhm_{}", "0".repeat(64)),
        "upstream":"synthetic","protected_store":"process_lifetime"});
    ready_frame(&value, "owned");
    for key in value.as_object().unwrap().keys() {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(std::panic::catch_unwind(|| ready_frame(&bad, "owned")).is_err());
    }
    for (key, replacement) in [
        ("schema", "other"),
        ("environment_id", "another"),
        ("upstream", "live"),
        ("protected_store", "persistent"),
        ("codex_base_url", "http://localhost:42424/codex/v1"),
        ("codex_base_url", "http://127.0.0.1:042424/codex/v1"),
        ("anthropic_base_url", "http://127.0.0.1:42425/anthropic"),
        ("capability", "unknown"),
    ] {
        let mut bad = value.clone();
        bad[key] = json!(replacement);
        assert!(std::panic::catch_unwind(|| ready_frame(&bad, "owned")).is_err());
    }
    let mut bad = value;
    bad["auth"] = json!(true);
    assert!(std::panic::catch_unwind(|| ready_frame(&bad, "owned")).is_err());
}

#[test]
#[ignore = "fixed source-bound child for the two original-pidfd kernel fixtures"]
fn managed_fixture_pidfd_wait_child() {
    assert_eq!(
        std::env::var("CW_MEMBER_PIDFD_WAIT_CHILD").as_deref(),
        Ok("1")
    );
    println!("CW_MEMBER_PIDFD_WAIT_READY");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let mut release = [0];
    std::io::stdin().read_exact(&mut release).unwrap();
    assert_eq!(release, [b'X']);
}

async fn pidfd_wait_child() -> (tokio::process::Child, OwnedChild) {
    let image = std::env::current_exe().unwrap();
    let mut child = tokio::process::Command::new(&image)
        .args([
            "--ignored",
            "--exact",
            "managed::managed_fixture_pidfd_wait_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env_clear()
        .env("CW_MEMBER_PIDFD_WAIT_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        for _ in 0..4096 {
            let byte = child.stdout.as_mut().unwrap().read_u8().await.unwrap();
            line.push(byte);
            assert!(line.len() <= 1024);
            if byte == b'\n' {
                if line.ends_with(b"CW_MEMBER_PIDFD_WAIT_READY\n") {
                    return;
                }
                line.clear();
            }
        }
        panic!("fixed pidfd child did not publish its ready marker");
    })
    .await
    .unwrap();
    let owned = OwnedChild::capture(child.id().unwrap(), Some(&image)).unwrap();
    assert!(!terminal(&owned.fd));
    (child, owned)
}

#[tokio::test]
async fn managed_fixture_original_pidfd_waits_for_delayed_exit() {
    let (mut child, owned) = pidfd_wait_child().await;
    owned.validate().unwrap();
    let mut input = child.stdin.take().unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        input.write_all(b"X").await.unwrap();
    });
    let waited = wait_terminal(&owned.fd, Duration::from_secs(2)).await;
    release.await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert!(terminal(&owned.fd));
    assert!(waited, "one immediate pidfd poll misses the delayed exit");
}

#[tokio::test]
async fn managed_fixture_original_pidfd_wait_refuses_live_or_other_pidfd() {
    let (mut live_child, live) = pidfd_wait_child().await;
    let (mut other_child, other) = pidfd_wait_child().await;
    other_child
        .stdin
        .take()
        .unwrap()
        .write_all(b"X")
        .await
        .unwrap();
    let other_status = tokio::time::timeout(Duration::from_secs(2), other_child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(other_status.success());
    assert!(terminal(&other.fd));
    live.validate().unwrap();
    assert!(!terminal(&live.fd));
    let refused = !wait_terminal(&live.fd, Duration::from_millis(80)).await;
    live.validate().unwrap();
    assert!(!terminal(&live.fd));
    live_child
        .stdin
        .take()
        .unwrap()
        .write_all(b"X")
        .await
        .unwrap();
    let live_status = tokio::time::timeout(Duration::from_secs(2), live_child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(live_status.success());
    assert!(terminal(&live.fd));
    assert!(
        refused,
        "another terminal pidfd cannot prove original death"
    );
}

#[test]
fn managed_fixture_actual_actor_birth_path_and_terminal_refusals_do_not_signal() {
    // A controlled kernel child proves the observer itself; it is never an
    // agent substitute and is not part of the managed product receipt.
    fs::create_dir_all(repository().join(".tmp")).unwrap();
    let root = tempfile::tempdir_in(repository().join(".tmp")).unwrap();
    let image = root.path().join("owned-sleep");
    fs::copy("/usr/bin/sleep", &image).unwrap();
    fs::set_permissions(&image, fs::Permissions::from_mode(0o500)).unwrap();
    let launch_deadline = Instant::now() + Duration::from_secs(30);
    let mut command = Command::new(&image);
    command
        .arg("30")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cw_fixture::spawn_written(|| command.spawn()).unwrap();
    let owned = OwnedChild::capture_launch(child.id(), &image, launch_deadline).unwrap();
    let actor = Actor::capture(child.id(), owned.birth, std::process::id(), &image);
    for (birth, parent) in [
        (owned.birth + 1, std::process::id()),
        (owned.birth, std::process::id() + 1),
    ] {
        assert!(
            std::panic::catch_unwind(|| Actor::capture(child.id(), birth, parent, &image)).is_err()
        );
        actor.verify();
        assert!(!terminal(&owned.fd));
    }
    let other = root.path().join("other");
    fs::copy(&image, &other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o500)).unwrap();
    // Equal bytes at another inode cannot identify the running child. Keep
    // the failed admission's bounded kernel identity useful for diagnosis.
    let mismatch = OwnedChild::capture(child.id(), Some(&other))
        .err()
        .expect("a different executable inode must be refused")
        .to_string();
    let actual_image = fs::symlink_metadata(&image).unwrap();
    let expected_image = fs::symlink_metadata(&other).unwrap();
    assert_eq!(fs::read(&image).unwrap(), fs::read(&other).unwrap());
    assert_ne!(actual_image.ino(), expected_image.ino());
    let launch_mismatch = owned
        .wait_for_launch_image(child.id(), &other, launch_deadline)
        .expect_err("launch admission must also refuse the different executable inode");
    assert_eq!(launch_mismatch.to_string(), mismatch);
    assert_eq!(
        owned
            .wait_for_launch_image(child.id(), &image, Instant::now())
            .expect_err("an expired launch deadline cannot admit the child")
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(
        std::panic::catch_unwind(|| Actor::capture(
            child.id(),
            owned.birth,
            std::process::id(),
            &other
        ))
        .is_err()
    );
    actor.verify();
    assert!(!terminal(&owned.fd));
    owned.signal(libc::SIGTERM).unwrap();
    child.wait().unwrap();
    assert!(terminal(&owned.fd));
    assert_eq!(
        owned
            .wait_for_launch_image(child.id(), &image, launch_deadline)
            .expect_err("the original terminal pidfd cannot admit a launch")
            .to_string(),
        "owned launch exited before image admission"
    );
    assert!(std::panic::catch_unwind(|| actor.verify()).is_err());
    assert!(fs::symlink_metadata(&other).unwrap().is_file());
    // Check diagnostics only after the original child has been reaped, so a
    // regression here cannot leave the controlled process running.
    let fields = mismatch
        .strip_prefix("owned process image changed: ")
        .expect("image refusal must retain fixed numeric identity")
        .split_whitespace()
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (key, value.parse::<u64>().unwrap())
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(mismatch.len() <= 512);
    assert_eq!(fields.len(), 10);
    for (key, value) in [
        ("pid", u64::from(child.id())),
        ("birth", owned.birth),
        ("parent", u64::from(std::process::id())),
        ("euid", u64::from(unsafe { libc::geteuid() })),
        ("expected_dev", expected_image.dev()),
        ("expected_ino", expected_image.ino()),
        ("expected_len", expected_image.len()),
        ("actual_dev", actual_image.dev()),
        ("actual_ino", actual_image.ino()),
        ("actual_len", actual_image.len()),
    ] {
        assert_eq!(fields.get(key), Some(&value), "missing identity {key}");
    }
}

#[test]
fn managed_fixture_held_owner_uses_public_session_driver_tuple() {
    let conversation = Conversation {
        session: "session-11111111-1111-4111-8111-111111111111".into(),
        driver: "11111111-1111-4111-8111-111111111111".into(),
        agent: "codex",
        generation: 7,
        thread: "22222222-2222-4222-8222-222222222222".into(),
        actors: Vec::new(),
        peer: Value::Null,
    };
    // Member inbox publishes owner metadata beside bounded message summaries.
    // The summaries intentionally do not contain full-record identity fields.
    let projection = json!({
        "session": {
            "session_id": conversation.session,
            "launch_generation": conversation.generation,
        },
        "driver": {
            "driver_id": conversation.driver,
            "agent": conversation.agent,
            "native_thread_id": conversation.thread,
        },
        "messages": [{
            "id": "33333333-3333-4333-8333-333333333333",
            "action": "message",
            "state": "running",
            "native_acknowledged": true,
            "turn_id": "44444444-4444-4444-8444-444444444444",
            "expected_turn_id": null,
            "created_at": "2026-10-04T14:03:42Z",
            "member_launch_generation": 7,
            "notification": null,
            "source": null,
        }],
    });
    assert!(projection["messages"][0].get("driver_id").is_none());
    assert!(projection["messages"][0].get("target_session_id").is_none());
    held_owner_tuple(&projection, &conversation);
    for (path, foreign) in [
        ("/session/session_id", json!("session-other")),
        ("/session/launch_generation", json!(8)),
        ("/driver/driver_id", json!("other-driver")),
        ("/driver/agent", json!("claude")),
        ("/driver/native_thread_id", json!("other-thread")),
    ] {
        for replacement in [foreign, Value::Null] {
            let mut wrong = projection.clone();
            *wrong.pointer_mut(path).unwrap() = replacement;
            // The original message ID is insufficient with a foreign owner.
            assert_eq!(wrong["messages"], projection["messages"]);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    held_owner_tuple(&wrong, &conversation);
                }))
                .is_err()
            );
        }
    }
}

#[test]
fn managed_fixture_stop_requires_one_original_clean_terminal_session() {
    let session = "session-11111111-1111-4111-8111-111111111111";
    let stopped = json!([{
        "session_id": session, "launch_generation": 1,
        "cleanup_unknown": false, "state": "Stopped", "exit_code": null,
    }]);
    clean_stopped_session(&stopped, session, 1);
    let mut exited = stopped.clone();
    exited[0]["state"] = json!("Exited");
    exited[0]["exit_code"] = json!(0);
    clean_stopped_session(&exited, session, 1);
    for (field, wrong) in [
        ("session_id", json!("session-other")),
        ("session_id", Value::Null),
        ("launch_generation", json!(2)),
        ("launch_generation", json!(true)),
        ("launch_generation", Value::Null),
        ("cleanup_unknown", json!(true)),
        ("cleanup_unknown", Value::Null),
        ("state", json!("Failed")),
        ("state", json!("Interrupted")),
        ("state", json!("Unknown")),
        ("state", json!("Starting")),
        ("state", json!("Running")),
        ("state", json!("Stopping")),
        ("state", Value::Null),
        ("exit_code", json!(1)),
        ("exit_code", Value::Null),
    ] {
        let mut wrong_result = exited.clone();
        wrong_result[0][field] = wrong;
        assert!(
            std::panic::catch_unwind(|| clean_stopped_session(&wrong_result, session, 1)).is_err()
        );
    }
    for wrong_result in [Value::Null, json!([]), json!([stopped[0], stopped[0]])] {
        assert!(
            std::panic::catch_unwind(|| clean_stopped_session(&wrong_result, session, 1)).is_err()
        );
    }
}

#[test]
fn managed_fixture_caller_active_uses_public_owner_and_native_turn_pair() {
    let driver = "11111111-1111-4111-8111-111111111111";
    let session = format!("session-{driver}");
    let value = json!({
        "session": {"session_id": session, "launch_generation": 1},
        "driver": {"driver_id": driver, "agent": "codex", "native_thread_id": "thread",
            "phase": "busy", "current_turn_id": "turn", "active_message_id": "message"},
        "messages": [{"id": "message", "action": "message", "state": "running",
            "native_acknowledged": true, "turn_id": "turn", "expected_turn_id": null,
            "member_launch_generation": 1, "notification": null, "source": null}],
    });
    assert!(value["messages"][0].get("driver_id").is_none());
    assert!(value["messages"][0].get("target_session_id").is_none());
    assert!(caller_active(&value, &session, driver));
    for (path, wrong) in [
        ("/session/session_id", json!("session-other")),
        ("/session/launch_generation", json!(2)),
        ("/driver/driver_id", json!("other-driver")),
        ("/driver/agent", json!("claude")),
        ("/driver/native_thread_id", json!("")),
        ("/driver/phase", json!("idle")),
        ("/driver/active_message_id", json!("other-message")),
        ("/driver/current_turn_id", json!("other-turn")),
        ("/messages/0/id", json!("other-message")),
        ("/messages/0/state", json!("completed")),
        ("/messages/0/native_acknowledged", json!(false)),
        ("/messages/0/turn_id", json!("other-turn")),
    ] {
        for replacement in [wrong, Value::Null] {
            let mut refused = value.clone();
            *refused.pointer_mut(path).unwrap() = replacement;
            assert!(!caller_active(&refused, &session, driver), "{path}");
        }
    }
    let mut empty = value;
    empty["messages"] = json!([]);
    assert!(!caller_active(&empty, &session, driver));
}
