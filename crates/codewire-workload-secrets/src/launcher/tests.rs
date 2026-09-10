use super::*;
use crate::seal_environment_projection;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Stdio};

const CHILD_MODE: &str = "CW_SYNTHETIC_LAUNCH_TEST_SOCKET";
const CHILD_TEST: &str = "launcher::tests::synthetic_launcher_child";
const CHILD_STATUS: &str = "CW_SYNTHETIC_LAUNCH_STATUS_SOCKET";
const CHILD_EXEC_FAIL: &str = "CW_SYNTHETIC_LAUNCH_EXEC_FAIL";

#[test]
fn exec_budget_respects_current_stack_and_fixed_linux_floor() {
    assert_eq!(exec_budget_for_stack(Some(64 * 1024)), 96 * 1024);
    assert_eq!(exec_budget_for_stack(Some(1024 * 1024)), 224 * 1024);
    assert_eq!(
        exec_budget_for_stack(Some(8 * 1024 * 1024)),
        MAX_LAUNCH_EXEC_BYTES
    );
    assert_eq!(
        exec_budget_for_stack(None),
        MAX_LAUNCH_EXEC_BYTES - 32 * 1024
    );
}

#[test]
fn synthetic_launcher_child() {
    let Some(socket) = std::env::var_os(CHILD_MODE) else {
        return;
    };
    // This test process becomes the final workload; no parent helper receives
    // material. The shell's command contains only variable names, not values.
    let command = [
        "/bin/sh".into(),
        "-c".into(),
        "test ! -e /proc/self/fd/3 || exit 92; printf 'CW_CHILD_VALUE:%s' \"$APP_TOKEN\"".into(),
    ];
    let result = if let Some(status) = std::env::var_os(CHILD_STATUS) {
        let channel = connect_to_parent(Path::new(&socket)).unwrap();
        let status = UnixStream::connect(status).unwrap();
        let command = if std::env::var_os(CHILD_EXEC_FAIL).is_some() {
            vec!["/cw-synthetic-no-such-executable".into()]
        } else {
            command.to_vec()
        };
        exec_from_channel_with_status(channel, &command, status)
    } else {
        run_environment_launcher(Path::new(&socket), &command)
    };
    assert!(result.is_err());
    std::process::exit(71);
}

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 2,
        selection_sha256: [3; 32],
        deadline_unix_ms: now_unix_ms().unwrap() + 5_000,
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    channel: UnixStream,
    child: Option<Child>,
    status: Option<UnixStream>,
}
impl Harness {
    fn new() -> Self {
        Self::configured(None)
    }
    fn configured(status_mode: Option<bool>) -> Self {
        Self::with_base_value(status_mode, "public-base-placeholder")
    }
    fn with_base_value(status_mode: Option<bool>, value: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("launch.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let status_path = directory.path().join("status.sock");
        let status_listener = status_mode.map(|_| UnixListener::bind(&status_path).unwrap());
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env_clear()
            .env(CHILD_MODE, &socket)
            .env("APP_TOKEN", value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(fail) = status_mode {
            command.env(CHILD_STATUS, &status_path);
            if fail {
                command.env(CHILD_EXEC_FAIL, "1");
            }
        }
        let child = command.spawn().unwrap();
        // Bound acceptance too: a launcher regression must not hang the suite.
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let channel = loop {
            match listener.accept() {
                Ok((channel, _)) => break channel,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("synthetic launcher connection failed: {error}"),
            }
        };
        channel
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        channel
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let status = status_listener.map(|listener| {
            listener.set_nonblocking(true).unwrap();
            let status = loop {
                match listener.accept() {
                    Ok((status, _)) => break status,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::yield_now()
                    }
                    Err(error) => panic!("synthetic launch status connection failed: {error}"),
                }
            };
            status
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            status
        });
        Self {
            _directory: directory,
            channel,
            child: Some(child),
            status,
        }
    }
    fn send_projection(&mut self) {
        self.send_projection_with_overrides(&BTreeSet::new(), b"CW_SYNTHETIC_VALUE");
    }
    fn send_projection_with_overrides(&mut self, overrides: &BTreeSet<String>, value: &[u8]) {
        let context = context();
        self.channel
            .write_all(&encode_context(&context).unwrap())
            .unwrap();
        self.channel
            .write_all(&encode_override_names(overrides).unwrap())
            .unwrap();
        let mut recipient = [0; 32];
        self.channel.read_exact(&mut recipient).unwrap();
        let projection =
            EnvironmentProjection::from_entries([("APP_TOKEN".into(), value.to_vec().into())])
                .unwrap();
        let sealed =
            seal_environment_projection(projection, &context, recipient, now_unix_ms().unwrap())
                .unwrap();
        self.channel
            .write_all(&(sealed.len() as u32).to_be_bytes())
            .unwrap();
        self.channel.write_all(&sealed).unwrap();
        let mut ready = [0];
        self.channel.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [LAUNCH_READY]);
    }
    fn output(&mut self) -> std::process::Output {
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn final_launcher_decrypts_overrides_base_and_closes_channel_before_exec() {
    let mut harness = Harness::new();
    harness.send_projection();
    harness.channel.write_all(&[LAUNCH_COMMIT]).unwrap();
    let output = harness.output();
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .ends_with(b"CW_CHILD_VALUE:CW_SYNTHETIC_VALUE")
    );
    assert!(
        !output
            .stdout
            .windows(b"public-base-placeholder".len())
            .any(|part| part == b"public-base-placeholder")
    );
}

#[test]
fn bootstrap_status_closes_only_after_projection_commit_and_final_exec_admission() {
    let mut harness = Harness::configured(Some(false));
    harness.send_projection();
    let status = harness.status.as_mut().unwrap();
    status.set_nonblocking(true).unwrap();
    assert_eq!(
        status.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    status.set_nonblocking(false).unwrap();
    harness.channel.write_all(&[LAUNCH_COMMIT]).unwrap();
    let mut bytes = Vec::new();
    harness
        .status
        .as_mut()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, [LAUNCH_EXEC_PENDING]);
    let output = harness.output();
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .ends_with(b"CW_CHILD_VALUE:CW_SYNTHETIC_VALUE")
    );
}

#[test]
fn bootstrap_status_is_value_blind_on_projection_rejection_and_final_exec_failure() {
    for exec_failure in [false, true] {
        let mut harness = Harness::configured(Some(exec_failure));
        harness.send_projection();
        if exec_failure {
            harness.channel.write_all(&[LAUNCH_COMMIT]).unwrap();
        } else {
            harness.channel.shutdown(std::net::Shutdown::Both).unwrap();
        }
        let mut bytes = Vec::new();
        harness
            .status
            .as_mut()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        if exec_failure {
            assert_eq!(bytes, [LAUNCH_EXEC_PENDING, LAUNCH_EXEC_FAILED]);
        } else {
            assert_eq!(bytes, [LAUNCH_EXEC_FAILED]);
        }
        let output = harness.output();
        assert_eq!(output.status.code(), Some(71));
        assert!(
            !output
                .stdout
                .windows(b"CW_SYNTHETIC_VALUE".len())
                .any(|bytes| bytes == b"CW_SYNTHETIC_VALUE")
        );
        assert!(
            !output
                .stderr
                .windows(b"CW_SYNTHETIC_VALUE".len())
                .any(|bytes| bytes == b"CW_SYNTHETIC_VALUE")
        );
    }
}

#[test]
fn cancellation_after_ready_never_executes_child() {
    let mut harness = Harness::new();
    harness.send_projection();
    harness.channel.shutdown(std::net::Shutdown::Both).unwrap();
    let output = harness.output();
    assert_eq!(output.status.code(), Some(71));
    assert!(
        !output
            .stdout
            .windows(b"CW_CHILD_VALUE:".len())
            .any(|part| part == b"CW_CHILD_VALUE:")
    );
}

#[test]
fn oversized_ciphertext_is_denied_before_allocation_or_exec() {
    let mut harness = Harness::new();
    harness
        .channel
        .write_all(&encode_context(&context()).unwrap())
        .unwrap();
    harness
        .channel
        .write_all(&encode_override_names(&BTreeSet::new()).unwrap())
        .unwrap();
    let mut recipient = [0; 32];
    harness.channel.read_exact(&mut recipient).unwrap();
    harness
        .channel
        .write_all(&((MAX_LAUNCH_CIPHERTEXT_BYTES + 1) as u32).to_be_bytes())
        .unwrap();
    let output = harness.output();
    assert_eq!(output.status.code(), Some(71));
}

#[test]
fn combined_exec_limit_counts_existing_environment_arguments_and_per_string_bounds() {
    let projection =
        EnvironmentProjection::from_entries([("APP_TOKEN".into(), b"synthetic".to_vec().into())])
            .unwrap();
    let environment = merged_environment(
        [
            ("APP_TOKEN".into(), "placeholder".into()),
            ("UNCHANGED".into(), "public".into()),
        ],
        &projection,
        &BTreeSet::new(),
    );
    assert_eq!(environment[&OsString::from("APP_TOKEN")], "synthetic");
    validate_exec_size(&["/bin/true".into()], &environment).unwrap();
    assert!(
        validate_exec_size(
            &["/bin/true".into(), "x".repeat(128 * 1024).into()],
            &environment
        )
        .is_err()
    );
    let many_arguments: Vec<_> =
        std::iter::repeat_n(OsString::from("x".repeat(64 * 1024)), 16).collect();
    assert!(validate_exec_size(&many_arguments, &environment).is_err());
    let mut huge = environment;
    for index in 0..16 {
        huge.insert(
            format!("PUBLIC_{index}").into(),
            "x".repeat(64 * 1024).into(),
        );
    }
    assert!(validate_exec_size(&["/bin/true".into()], &huge).is_err());
}

#[test]
fn context_is_exact_and_expired_or_malformed_handshakes_fail_closed() {
    let context = context();
    let encoded = encode_context(&context).unwrap();
    assert_eq!(decode_context(&encoded).unwrap(), context);
    let mut altered = encoded;
    altered[0] ^= 1;
    assert!(decode_context(&altered).is_err());
    altered = encoded;
    altered[64..].copy_from_slice(&now_unix_ms().unwrap().to_be_bytes());
    assert!(decode_context(&altered).is_err());
    altered = encoded;
    altered[..8].copy_from_slice(b"CWLAUNCH");
    assert!(decode_context(&altered).is_err());
}

#[test]
fn explicit_values_and_empty_values_survive_fresh_launch_projections() {
    for explicit in ["explicit-command-database", ""] {
        for projected in [
            b"CW_SYNTHETIC_ONE".as_slice(),
            b"CW_SYNTHETIC_TWO".as_slice(),
        ] {
            let mut harness = Harness::with_base_value(None, explicit);
            harness
                .send_projection_with_overrides(&BTreeSet::from(["APP_TOKEN".into()]), projected);
            harness.channel.write_all(&[LAUNCH_COMMIT]).unwrap();
            let output = harness.output();
            assert!(output.status.success());
            assert!(
                output
                    .stdout
                    .ends_with(format!("CW_CHILD_VALUE:{explicit}").as_bytes())
            );
            assert!(
                !output
                    .stdout
                    .windows(projected.len())
                    .any(|part| part == projected)
            );
        }
    }
    for projected in [
        b"CW_SYNTHETIC_ONE".as_slice(),
        b"CW_SYNTHETIC_TWO".as_slice(),
    ] {
        let mut harness = Harness::new();
        harness.send_projection_with_overrides(&BTreeSet::new(), projected);
        harness.channel.write_all(&[LAUNCH_COMMIT]).unwrap();
        let output = harness.output();
        assert!(output.status.success());
        assert!(output.stdout.ends_with(projected));
    }
}

#[test]
fn names_only_provenance_keeps_image_below_app_and_command_above_app() {
    let projection = EnvironmentProjection::from_entries([
        ("APP_TOKEN".into(), b"selected-app".to_vec().into()),
        ("TERM".into(), b"selected-terminal".to_vec().into()),
    ])
    .unwrap();
    let base = [
        (
            OsString::from("APP_TOKEN"),
            OsString::from("explicit-command"),
        ),
        ("TERM".into(), "explicit-terminal".into()),
        ("PROJECT_ONLY".into(), "declared-project".into()),
        ("IMAGE_ONLY".into(), "image-default".into()),
    ];
    let names = BTreeSet::from(["APP_TOKEN".into(), "TERM".into()]);
    let encoded = encode_override_names(&names).unwrap();
    assert_eq!(&encoded[4..], b"APP_TOKEN\0TERM\0");
    let overrides = decode_override_names(&encoded[4..]).unwrap();
    let explicit = merged_environment(base.clone(), &projection, &overrides);
    assert_eq!(explicit[&OsString::from("APP_TOKEN")], "explicit-command");
    assert_eq!(explicit[&OsString::from("TERM")], "explicit-terminal");
    assert_eq!(
        explicit[&OsString::from("PROJECT_ONLY")],
        "declared-project"
    );
    assert_eq!(explicit[&OsString::from("IMAGE_ONLY")], "image-default");
    let image = merged_environment(base, &projection, &BTreeSet::new());
    assert_eq!(image[&OsString::from("APP_TOKEN")], "selected-app");
}

#[test]
fn override_names_are_bounded_canonical_and_never_silently_repaired() {
    for invalid in [
        b"NO_TERMINATOR".as_slice(),
        b"A\0A\0",
        b"B\0A\0",
        b"\0",
        b"A=VALUE\0",
        b"\xff\0",
    ] {
        assert!(decode_override_names(invalid).is_err());
    }
    assert!(encode_override_names(&BTreeSet::from([String::new()])).is_err());
    assert!(encode_override_names(&BTreeSet::from(["A=B".into()])).is_err());
    assert!(encode_override_names(&BTreeSet::from(["A\0B".into()])).is_err());
    assert!(encode_override_names(&BTreeSet::from(["A".repeat(MAX_LAUNCH_EXEC_BYTES)])).is_err());
    // Command environments are not limited to the projection's 256 entries.
    let names = (0..300).map(|n| format!("EXPLICIT_{n:04}")).collect();
    let encoded = encode_override_names(&names).unwrap();
    assert_eq!(decode_override_names(&encoded[4..]).unwrap().len(), 300);
}

#[test]
fn invalid_or_missing_override_names_fail_before_recipient_or_child_exec() {
    for names in [
        b"A\0A\0".as_slice(),
        b"NOT_IN_BASE\0",
        b"APP_TOKEN",
        b"\xff\0",
    ] {
        let mut harness = Harness::new();
        harness
            .channel
            .write_all(&encode_context(&context()).unwrap())
            .unwrap();
        harness
            .channel
            .write_all(&(names.len() as u32).to_be_bytes())
            .unwrap();
        harness.channel.write_all(names).unwrap();
        assert_eq!(harness.channel.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(harness.output().status.code(), Some(71));
    }
    for declared_length in [1, u32::MAX] {
        let mut harness = Harness::new();
        harness
            .channel
            .write_all(&encode_context(&context()).unwrap())
            .unwrap();
        harness
            .channel
            .write_all(&declared_length.to_be_bytes())
            .unwrap();
        harness.channel.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(harness.channel.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(harness.output().status.code(), Some(71));
    }
}
