use super::*;
use std::os::unix::fs::PermissionsExt;

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
            eprintln!("owned kernel fixture child cleanup remains unknown");
        } else {
            panic!("owned kernel fixture child cleanup remains unknown");
        }
    }
}

/// A real ELF child blocked on its owned stdin. This proves kernel custody,
/// not member behaviour; the CLI-bin fixture covers the actual role.
struct KernelFixture {
    child: KernelChild,
    custody: ProcessCustody,
    handle: PinnedProcess,
}

impl KernelFixture {
    fn new() -> Self {
        let executable = ExecutableIdentity::admit(Path::new("/usr/bin/head")).unwrap();
        let configuration = HelperConfiguration::Fixture;
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
            HelperRole::Fixture,
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
    custody.configuration = HelperConfiguration::HostMember(MemberConfiguration {
        directory: PathBuf::from("/synthetic/members"),
        environment_id: uuid::Uuid::new_v4().to_string(),
        host_root: PathBuf::from("/synthetic/host"),
        origin: "http://127.0.0.1:18090".into(),
        org: "synthetic-org".into(),
        network: "synthetic-network".into(),
        control_key: "12".repeat(32),
        wg_key: "34".repeat(32),
        derp_only: true,
    });
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
            "role" => invalid.role = HelperRole::Fixture,
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
            "role" => bad.role = HelperRole::HostMember,
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
