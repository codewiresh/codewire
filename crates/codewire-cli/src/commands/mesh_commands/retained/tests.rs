use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

/// Own cleanup from the instant spawn succeeds, including failed admission.
/// Only this unreaped Child grants authority; persisted PIDs are never used.
struct KernelChild(std::process::Child);

impl std::ops::Deref for KernelChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for KernelChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for KernelChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                _ => break,
            }
        }
        if std::thread::panicking() {
            eprintln!("owned Mesh kernel fixture child cleanup remains unknown");
        } else {
            panic!("owned Mesh kernel fixture child cleanup remains unknown");
        }
    }
}

/// A real ELF child blocked on its owned stdin. This proves kernel custody,
/// not DERP service behavior; the CLI-bin fixture covers the actual roles.
struct KernelFixture {
    child: KernelChild,
    custody: ProcessCustody,
    handle: PinnedProcess,
}

impl KernelFixture {
    fn new() -> Self {
        let executable = ExecutableIdentity::admit(Path::new("/usr/bin/head")).unwrap();
        let configuration = HelperConfiguration::Derp {
            url: "http://127.0.0.1:18091".to_owned(),
            listen_addr: "127.0.0.1:18091".to_owned(),
        };
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut command = ProcessCommand::new(&executable.path);
        command
            .arg0(&executable.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_environment(&mut command, &configuration, &nonce);
        let mut child = KernelChild(command.spawn().unwrap());
        let original = PinnedProcess::open(child.id()).unwrap();
        let birth = process_birth(&original.proc_directory).unwrap();
        let arguments = vec![executable.path.display().to_string()];
        let expected_arguments = format!("{}\0", executable.path.display()).into_bytes();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(child.try_wait().unwrap().is_none() && !original.exited().unwrap());
            assert_eq!(process_birth(&original.proc_directory).unwrap(), birth);
            let image = open_at(
                &original.proc_directory,
                "exe",
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0,
            )
            .unwrap()
            .metadata()
            .unwrap();
            let ready = image.dev() == executable.dev
                && image.ino() == executable.ino
                && image.len() == executable.size
                && read_proc(&original.proc_directory, "cmdline", MAX_COMMAND).unwrap()
                    == expected_arguments;
            assert_eq!(process_birth(&original.proc_directory).unwrap(), birth);
            if ready {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned kernel fixture startup not ready"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let (custody, handle) = ProcessCustody::capture(
            &child,
            executable,
            HelperRole::ExternalDerp,
            arguments,
            configuration,
            nonce,
        )
        .unwrap();
        assert_eq!(custody.start_ticks, birth);
        original.validate(&custody).unwrap();
        Self {
            child,
            custody,
            handle,
        }
    }
    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

/// This derives a synthetic HostMember record from a real, owned kernel birth.
/// It exercises terminal recovery policy only; it never claims the head child
/// is a cw helper or uses the synthetic role as live signaling authority.
fn member_recovery_record(fixture: &KernelFixture) -> ProcessCustody {
    let mut custody = fixture.custody.clone();
    custody.role = HelperRole::HostMember;
    custody.configuration = HelperConfiguration::HostMember {
        directory: PathBuf::from("/synthetic/members"),
        environment_id: uuid::Uuid::new_v4().to_string(),
        host_root: PathBuf::from("/synthetic/host"),
        origin: "http://127.0.0.1:18090".into(),
        org: "synthetic-org".into(),
        network: "synthetic-network".into(),
        control_key: "12".repeat(32),
        wg_key: "34".repeat(32),
        derp_only: true,
    };
    custody.arguments = ProcessCustody::expected_arguments(
        &custody.executable.path,
        custody.role,
        &custody.configuration,
    )
    .unwrap();
    custody
}

#[tokio::test]
async fn member_recovery_real_crash_proves_terminal_birth_before_and_after_reap() {
    let mut fixture = KernelFixture::new();
    let member = member_recovery_record(&fixture);
    assert!(!member.member_terminal().unwrap());
    fixture.child.kill().unwrap();
    assert!(fixture.handle.wait(Duration::from_secs(2)).await.unwrap());
    // A held same-birth terminal pidfd and then actual old-PID absence both
    // permit record retirement, without reissuing any target request.
    assert!(member.member_terminal().unwrap());
    fixture.child.wait().unwrap();
    assert!(member.member_terminal().unwrap());
}

#[test]
fn member_recovery_changed_birth_never_signals_the_actual_unrelated_process() {
    let mut original = KernelFixture::new();
    let mut member = member_recovery_record(&original);
    original.child.kill().unwrap();
    original.child.wait().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let mut replacement = KernelFixture::new();
    assert_ne!(member.start_ticks, replacement.custody.start_ticks);
    // A persisted numeric collision is modeled explicitly; the current birth
    // is a real distinct child, not a claim that the kernel reused a PID here.
    member.pid = replacement.child.id();
    assert!(member.member_terminal().unwrap());
    assert!(replacement.alive());
    replacement.handle.validate(&replacement.custody).unwrap();
    let mut unknown = member.clone();
    unknown.boot_id.clear();
    assert!(unknown.member_terminal().is_err());
    assert!(replacement.alive());
}

#[test]
fn member_recovery_missing_or_diverged_image_and_bad_record_refuse() {
    let mut fixture = KernelFixture::new();
    let member = member_recovery_record(&fixture);
    for kind in [
        "missing-image",
        "changed-image",
        "missing-birth",
        "foreign-uid",
        "role",
    ] {
        let mut invalid = member.clone();
        match kind {
            "missing-image" => {
                invalid.executable.path = PathBuf::from("/nonexistent/synthetic-member-image");
                invalid.arguments = ProcessCustody::expected_arguments(
                    &invalid.executable.path,
                    invalid.role,
                    &invalid.configuration,
                )
                .unwrap();
            }
            "changed-image" => invalid.executable.sha256 = "00".repeat(32),
            "missing-birth" => invalid.start_ticks = 0,
            "foreign-uid" => invalid.uid += 1,
            "role" => invalid.role = HelperRole::EmbeddedMesh,
            _ => unreachable!(),
        }
        assert!(invalid.member_terminal().is_err(), "{kind}");
        assert!(fixture.alive(), "{kind}");
    }
    assert!(!member.member_terminal().unwrap());
}

#[test]
fn member_record_cleanup_retains_original_inode_and_refuses_replacement() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("member"), true)
        .unwrap()
        .unwrap();
    let name = "member-runtime.json";
    directory.write(name, br#"{"safe":true}"#).unwrap();
    let captured = directory.hold_member_record(name).unwrap().unwrap();
    directory.validate_member_record(&captured).unwrap();
    let original_inode = captured.file.metadata().unwrap().ino();
    // Atomic byte-identical replacement is still a different ownership event.
    directory.write(name, captured.bytes()).unwrap();
    assert_ne!(
        fs::symlink_metadata(directory.path.join(name))
            .unwrap()
            .ino(),
        original_inode
    );
    assert!(directory.validate_member_record(&captured).is_err());
    assert!(directory.remove_member_record(&captured).is_err());
    assert_eq!(directory.read(name).unwrap().unwrap(), captured.bytes());
    let fresh = directory.hold_member_record(name).unwrap().unwrap();
    directory.remove_member_record(&fresh).unwrap();
    assert!(directory.read(name).unwrap().is_none());
    assert!(directory.hold_member_record("mesh_runtime.json").is_err());
}

fn paths(root: &Path) -> ResolvePaths {
    ResolvePaths {
        mesh_data_dir: root.join("mesh"),
        platform_config_dir: root.join("unused-platform"),
    }
}

fn args() -> MeshUpArgs {
    MeshUpArgs {
        binary: None,
        derp_binary: None,
        base_url: DEFAULT_LOCAL_MESH_URL.to_owned(),
        listen: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_owned(),
        derp_url: DEFAULT_LOCAL_DERP_URL.to_owned(),
        derp_listen: DEFAULT_LOCAL_DERP_LISTEN_ADDR.to_owned(),
        no_derp: false,
        output: OutputFormat::Json,
    }
}

#[tokio::test]
async fn owned_pidfd_cleanup_preserves_an_unbound_child() {
    let mut owned = KernelFixture::new();
    let mut sentinel = KernelFixture::new();
    owned.handle.terminate().await.unwrap();
    assert!(!owned.alive());
    assert!(sentinel.alive());
    sentinel.handle.validate(&sentinel.custody).unwrap();
}

#[test]
fn changed_birth_boot_role_arguments_executable_and_nonce_never_adopt() {
    let mut fixture = KernelFixture::new();
    for kind in [
        "birth",
        "boot",
        "uid",
        "role",
        "arguments",
        "executable",
        "nonce",
        "schema",
    ] {
        let mut bad = fixture.custody.clone();
        match kind {
            "birth" => bad.start_ticks += 1,
            "boot" => bad.boot_id = "00000000-0000-4000-8000-000000000000".to_owned(),
            "uid" => bad.uid += 1,
            "role" => bad.role = HelperRole::EmbeddedDerp,
            "arguments" => bad.arguments.push("foreign".to_owned()),
            "executable" => {
                bad.executable = ExecutableIdentity::admit(Path::new("/usr/bin/true")).unwrap()
            }
            "nonce" => bad.launch_nonce = uuid::Uuid::new_v4().to_string(),
            "schema" => bad.schema_version += 1,
            _ => unreachable!(),
        }
        assert!(
            bad.pin(
                fixture.child.id(),
                fixture.custody.executable.path.to_str().unwrap()
            )
            .is_err(),
            "{kind}"
        );
        assert!(fixture.alive(), "{kind} changed the owned process");
    }
}

#[test]
fn a_recycled_numeric_identity_cannot_adopt_a_foreign_same_image() {
    let mut original = KernelFixture::new();
    let mut foreign = KernelFixture::new();
    let mut stale = original.custody.clone();
    stale.pid = foreign.child.id();
    // Even if coarse start ticks happen to coincide, the independently chosen
    // launch nonce refuses this genuinely different kernel process.
    stale.start_ticks = foreign.custody.start_ticks;
    assert!(
        stale
            .pin(foreign.child.id(), stale.executable.path.to_str().unwrap())
            .is_err()
    );
    assert!(original.alive());
    assert!(foreign.alive());
}

#[test]
fn missing_birth_and_role_metadata_refuse_before_signal() {
    let mut fixture = KernelFixture::new();
    for key in ["start_ticks", "role", "launch_nonce", "executable"] {
        let mut value = serde_json::to_value(&fixture.custody).unwrap();
        value.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<ProcessCustody>(value).is_err());
        assert!(fixture.alive());
    }
}

#[test]
fn terminal_custody_is_not_automatically_replaced_or_recovered() {
    let mut fixture = KernelFixture::new();
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    assert!(
        fixture
            .custody
            .pin(
                fixture.custody.pid,
                fixture.custody.executable.path.to_str().unwrap()
            )
            .is_err()
    );
}

#[test]
fn read_only_state_lookup_creates_neither_directory_nor_lock() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(load_local_mesh_runtime(&missing).unwrap().is_none());
    assert!(!missing.exists());
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap().is_none());
    assert!(!directory.path.join(LOCK).exists());
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap().is_none());
    assert!(directory.write(LOCAL_MESH_RUNTIME_FILE, b"{}").is_err());
    assert!(!directory.path.join(LOCAL_MESH_RUNTIME_FILE).exists());
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn state_symlink_hardlink_fifo_and_oversize_refuse_without_changing_sentinels() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, b"preserve").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let record = directory.path.join(LOCAL_MESH_RUNTIME_FILE);
    for kind in ["symlink", "hardlink", "fifo", "oversize"] {
        match kind {
            "symlink" => symlink(&sentinel, &record).unwrap(),
            "hardlink" => fs::hard_link(&sentinel, &record).unwrap(),
            "fifo" => {
                let path = std::ffi::CString::new(record.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "oversize" => {
                fs::write(&record, vec![0; MAX_STATE + 1]).unwrap();
                fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let start = Instant::now();
        assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).is_err(), "{kind}");
        assert!(
            directory
                .write(LOCAL_MESH_RUNTIME_FILE, b"replacement")
                .is_err(),
            "{kind}"
        );
        assert!(
            directory.remove(LOCAL_MESH_RUNTIME_FILE, None).is_err(),
            "{kind}"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
        fs::remove_file(&record).unwrap();
    }
}

#[test]
fn symlink_or_public_directory_is_never_chmodded_or_adopted() {
    let root = tempfile::tempdir().unwrap();
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
    let link = root.path().join("link");
    symlink(&foreign, &link).unwrap();
    assert!(StateDir::open(&link, true).is_err());
    assert!(StateDir::open(&foreign, true).is_err());
    assert_eq!(fs::metadata(&foreign).unwrap().mode() & 0o777, 0o755);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn shared_mesh_configuration_read_refuses_link_without_following_target() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, b"mesh_url = 'http://127.0.0.1:18090'\n").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path.join("config.toml");
    symlink(&sentinel, &link).unwrap();
    assert!(config::load_mesh_config(&directory.path).is_err());
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"mesh_url = 'http://127.0.0.1:18090'\n"
    );
}

#[test]
fn shared_mesh_configuration_write_preserves_link_target_on_refusal() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    fs::write(&sentinel, original).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path.join("config.toml");
    symlink(&sentinel, &link).unwrap();
    assert!(
        config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
            .is_err()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), original);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn shared_mesh_configuration_defaults_only_for_absent_private_state() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(
        config::load_mesh_config(&missing)
            .unwrap()
            .mesh_url
            .is_none()
    );
    assert!(!missing.exists());
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    assert!(
        config::load_mesh_config(&directory.path)
            .unwrap()
            .mesh_url
            .is_none()
    );
    assert!(fs::read_dir(&directory.path).unwrap().next().is_none());
    for bytes in [b"\xff".as_slice(), b"mesh_url = [".as_slice()] {
        directory.write("config.toml", bytes).unwrap();
        assert!(config::load_mesh_config(&directory.path).is_err());
        assert_eq!(directory.read("config.toml").unwrap().unwrap(), bytes);
    }
    assert!(!directory.path.join(LOCK).exists());
}

#[test]
fn shared_mesh_configuration_refuses_hardlink_fifo_and_overbound_entries() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    fs::write(&sentinel, original).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let path = directory.path.join("config.toml");
    for kind in ["hardlink", "fifo", "overbound"] {
        match kind {
            "hardlink" => fs::hard_link(&sentinel, &path).unwrap(),
            "fifo" => {
                let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "overbound" => {
                fs::write(&path, vec![b' '; MAX_STATE + 1]).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let identity = stamp(&fs::symlink_metadata(&path).unwrap());
        let start = Instant::now();
        assert!(config::load_mesh_config(&directory.path).is_err(), "{kind}");
        assert!(
            config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
                .is_err(),
            "{kind}"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(identity == stamp(&fs::symlink_metadata(&path).unwrap()));
        assert_eq!(fs::read(&sentinel).unwrap(), original);
        fs::remove_file(&path).unwrap();
    }
}

#[test]
fn shared_mesh_configuration_never_repairs_public_or_read_only_directories() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    directory.write("config.toml", original).unwrap();
    for mode in [0o755, 0o500] {
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(mode)).unwrap();
        let read = config::load_mesh_config(&directory.path);
        assert_eq!(read.is_ok(), mode == 0o500);
        assert!(
            config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
                .is_err()
        );
        assert_eq!(fs::metadata(&directory.path).unwrap().mode() & 0o777, mode);
        assert_eq!(
            fs::read(directory.path.join("config.toml")).unwrap(),
            original
        );
        assert!(!directory.path.join(LOCK).exists());
    }
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn shared_mesh_configuration_atomically_replaces_and_preserves_bytes_on_refusal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mesh");
    config::save_mesh_connection(&path, "http://127.0.0.1:18090", "cw_original").unwrap();
    let before = fs::metadata(path.join("config.toml")).unwrap();
    config::save_mesh_connection(&path, "http://127.0.0.1:18091", "cw_selected").unwrap();
    let metadata = fs::metadata(path.join("config.toml")).unwrap();
    assert_ne!(before.ino(), metadata.ino());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        config::load_mesh_config(&path).unwrap().mesh_url.as_deref(),
        Some("http://127.0.0.1:18091")
    );
    let original = fs::read(path.join("config.toml")).unwrap();
    let too_large = "x".repeat(MAX_STATE + 1);
    assert!(config::save_mesh_connection(&path, "http://127.0.0.1:18090", &too_large).is_err());
    assert_eq!(fs::read(path.join("config.toml")).unwrap(), original);
    assert_eq!(
        fs::metadata(path.join("config.toml")).unwrap().ino(),
        metadata.ino()
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
}

#[tokio::test]
async fn startup_and_down_share_one_exact_control_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owned");
    let first = StateDir::open(&path, true).unwrap().unwrap();
    let lock = first.lock().await.unwrap();
    let second = StateDir::open(&path, false).unwrap().unwrap();
    let task = tokio::spawn(async move { second.lock().await });
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(!task.is_finished());
    drop(lock);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn legacy_or_interrupted_startup_preserves_record_and_foreign_process() {
    let root = tempfile::tempdir().unwrap();
    let paths = paths(root.path());
    let directory = StateDir::open(&paths.mesh_data_dir, true).unwrap().unwrap();
    let mut sentinel = KernelFixture::new();
    let legacy = LocalMeshRuntime {
        pid: sentinel.child.id(),
        base_url: DEFAULT_LOCAL_MESH_URL.to_owned(),
        listen_addr: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_owned(),
        binary: sentinel.custody.executable.path.display().to_string(),
        log_path: directory
            .path
            .join(LOCAL_MESH_LOG_FILE)
            .display()
            .to_string(),
        started_at: "synthetic".to_owned(),
        derp: None,
        custody: None,
    };
    save_local_mesh_runtime(&paths.mesh_data_dir, &legacy).unwrap();
    let original = directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap();
    assert!(up(&paths, args()).await.is_err());
    assert!(down(&paths).await.is_err());
    assert_eq!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap(), original);
    assert!(sentinel.alive());
    directory.write(STARTING, b"{\"unresolved\":true}").unwrap();
    assert!(up(&paths, args()).await.is_err());
    assert!(down(&paths).await.is_err());
    assert_eq!(
        directory.read(STARTING).unwrap().unwrap(),
        b"{\"unresolved\":true}"
    );
    assert!(sentinel.alive());
    assert_eq!(local_mesh_status(&paths.mesh_data_dir).state, "unknown");
}

#[tokio::test]
async fn replaced_control_lock_is_not_repaired_or_used_for_effects() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    let lock = directory.lock().await.unwrap();
    fs::rename(
        directory.path.join(LOCK),
        directory.path.join("retained-lock"),
    )
    .unwrap();
    let replacement = directory.path.join(LOCK);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&replacement)
        .unwrap();
    let inode = fs::symlink_metadata(&replacement).unwrap().ino();
    assert!(lock.check(&directory).is_err());
    assert_eq!(fs::symlink_metadata(&replacement).unwrap().ino(), inode);
    assert!(directory.path.join("retained-lock").exists());
}

#[test]
fn defaults_are_exact_current_executable_and_explicit_override_is_preserved() {
    let current = fs::canonicalize(env::current_exe().unwrap()).unwrap();
    assert_eq!(locate_codewire_mesh_binary(None).unwrap(), current);
    assert_eq!(locate_codewire_derp_binary(None).unwrap(), current);
    let explicit = PathBuf::from("/absolute/selected-helper");
    assert_eq!(
        locate_codewire_mesh_binary(Some(&explicit)).unwrap(),
        explicit
    );
    assert_eq!(
        locate_codewire_derp_binary(Some(&explicit)).unwrap(),
        explicit
    );
}

#[test]
fn helper_executable_refuses_setuid_and_setgid_without_launch() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("controlled-head");
    fs::copy("/usr/bin/head", &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let original = fs::read(&path).unwrap();
    assert!(ExecutableIdentity::admit(&path).is_ok());
    for mode in [0o4700, 0o2700] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(ExecutableIdentity::admit(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
    }
    // This is only file admission evidence: no privileged child is executed.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
}
