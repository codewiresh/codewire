use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use super::*;

const CANARY: &str = "synthetic-application-secret-canary-must-not-be-logged";

fn runtime_root() -> (tempfile::TempDir, PrivateRoot) {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("runtime");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&fs::canonicalize(&root).unwrap()).unwrap();
    (parent, root)
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

fn failure_fields(code: &str) -> [(&'static str, LogField<'_>); 4] {
    [
        ("operation", LogField::Id(Uuid::nil())),
        ("effect", LogField::Name("start_vm")),
        ("cause", LogField::Name("vm_start")),
        ("error_code", LogField::Code(code)),
    ]
}

#[test]
fn child_log_is_owner_only_bounded_and_rotated_once_it_is_half_full() {
    let (_parent, root) = runtime_root();
    let logs = root.path().join(LOG_DIRECTORY);
    let current = logs.join(SUPERVISOR_LOG);
    let previous = logs.join(format!("{SUPERVISOR_LOG}.1"));

    let log = DiagnosticLog::adopt(open_child_log(&root, SUPERVISOR_LOG).unwrap()).unwrap();
    assert_eq!(mode(&logs), 0o700);
    assert_eq!(mode(&current), 0o600);
    assert!(!previous.exists(), "an empty log is not rotated");

    // Fill past the bound: the log stops growing instead of exceeding it.
    let line = event_line(0, "operation_failed", &failure_fields("guest_start_failed"));
    let lines = MAXIMUM_LOG_BYTES / u64::try_from(line.len()).unwrap() + 16;
    for _ in 0..lines {
        log.record("operation_failed", &failure_fields("guest_start_failed"));
    }
    let full = fs::read(&current).unwrap();
    assert!(u64::try_from(full.len()).unwrap() <= MAXIMUM_LOG_BYTES);
    assert!(u64::try_from(full.len()).unwrap() > MAXIMUM_LOG_BYTES - 1024);
    drop(log);

    // The next spawn finds it past half its bound, keeps it as `.1` and
    // starts an empty one, both 0600.
    let log = DiagnosticLog::adopt(open_child_log(&root, SUPERVISOR_LOG).unwrap()).unwrap();
    assert_eq!(fs::read(&previous).unwrap(), full);
    assert_eq!(mode(&previous), 0o600);
    assert_eq!(fs::metadata(&current).unwrap().len(), 0);
    assert_eq!(mode(&current), 0o600);
    log.record("supervisor_started", &[]);
    let restarted = fs::read_to_string(&current).unwrap();
    assert!(restarted.starts_with("time_unix_ms="), "{restarted}");
    assert!(
        restarted.ends_with(" event=supervisor_started\n"),
        "{restarted}"
    );

    // A small log is kept and appended to: the spawn after it rotates
    // nothing, and two files, each bounded, are all a log ever keeps.
    drop(log);
    open_child_log(&root, SUPERVISOR_LOG).unwrap();
    let mut names = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["supervisor.log", "supervisor.log.1"]);
    assert_eq!(fs::read(&previous).unwrap(), full);
    assert_eq!(fs::read_to_string(&current).unwrap(), restarted);
}

/// #5144: a child that fails and is started again in a loop keeps its first
/// failure. Before, every spawn moved the log to the one `.1`, so the second
/// restart dropped the failed child's lines.
#[test]
fn a_restart_loop_keeps_the_first_failures_lines() {
    let (_parent, root) = runtime_root();
    let logs = root.path().join(LOG_DIRECTORY);
    for spawn in 0..200_u64 {
        let log = DiagnosticLog::adopt(open_child_log(&root, SUPERVISOR_LOG).unwrap()).unwrap();
        log.record("supervisor_started", &[("pid", LogField::Count(spawn))]);
        if spawn == 0 {
            log.record(
                "operation_failed",
                &failure_fields("start_network_stack_failed"),
            );
        }
        log.record(
            "supervisor_halted",
            &[("reason", LogField::Name("drain_error"))],
        );
    }
    let current = fs::read_to_string(logs.join(SUPERVISOR_LOG)).unwrap();
    assert!(!logs.join(format!("{SUPERVISOR_LOG}.1")).exists());
    assert!(
        current.contains("error_code=start_network_stack_failed"),
        "{current}"
    );
    assert_eq!(current.matches("event=supervisor_started").count(), 200);
    assert_eq!(current.matches("event=supervisor_halted").count(), 200);

    // However long the loop runs, the two files stay within their bounds.
    let line = event_line(
        0,
        "supervisor_halted",
        &[("reason", LogField::Name("drain_error"))],
    );
    let per_spawn = ROTATE_AT_BYTES / u64::try_from(line.len()).unwrap() / 4;
    for _ in 0..12 {
        let log = DiagnosticLog::adopt(open_child_log(&root, SUPERVISOR_LOG).unwrap()).unwrap();
        for _ in 0..per_spawn {
            log.record(
                "supervisor_halted",
                &[("reason", LogField::Name("drain_error"))],
            );
        }
    }
    for name in [SUPERVISOR_LOG.to_owned(), format!("{SUPERVISOR_LOG}.1")] {
        assert!(
            fs::metadata(logs.join(&name)).unwrap().len() <= MAXIMUM_LOG_BYTES,
            "{name}"
        );
    }
}

#[test]
fn spawned_child_output_reaches_its_log_instead_of_dev_null() {
    let (_parent, root) = runtime_root();
    let name = runner_log_name(Uuid::new_v4());
    let (stdout, stderr) = child_stdio(&root, &name);
    let status = crate::test_child(
        Command::new("/bin/sh")
            .args(["-c", "echo child-stdout; echo child-stderr >&2"])
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr),
    )
    .status()
    .unwrap();
    assert!(status.success());
    let path = root.path().join(LOG_DIRECTORY).join(&name);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "child-stdout\nchild-stderr\n"
    );
    assert_eq!(mode(&path), 0o600);
}

/// A failed create's runner log is kept under the environment's name, whole,
/// and what the runner still writes follows it there.
#[test]
fn a_failed_creates_runner_log_is_kept_under_its_name() {
    let (_parent, root) = runtime_root();
    let logs = root.path().join(LOG_DIRECTORY);
    let kept = logs.join("runner-failed-create-app.log");
    assert_eq!(
        failed_create_log_name("app"),
        "runner-failed-create-app.log"
    );

    let first = Uuid::new_v4();
    let mut runner = open_child_log(&root, &runner_log_name(first)).unwrap();
    runner.write_all(b"event=vm_start_failed first\n").unwrap();
    keep_failed_create_log(&root, first, "app");
    assert!(!logs.join(runner_log_name(first)).exists());
    assert_eq!(mode(&kept), 0o600);
    // The runner is still being stopped, and its last lines are kept too.
    runner.write_all(b"event=vm_stopped first\n").unwrap();
    assert_eq!(
        fs::read_to_string(&kept).unwrap(),
        "event=vm_start_failed first\nevent=vm_stopped first\n"
    );
    // The delete that follows finds nothing left under the runner's name.
    remove_log(&root, &runner_log_name(first));
    assert!(kept.exists());

    // The next failed create of that name replaces it.
    let second = Uuid::new_v4();
    open_child_log(&root, &runner_log_name(second))
        .unwrap()
        .write_all(b"event=vm_start_failed second\n")
        .unwrap();
    keep_failed_create_log(&root, second, "app");
    assert_eq!(
        fs::read_to_string(&kept).unwrap(),
        "event=vm_start_failed second\n"
    );

    // One that never started a runner leaves no earlier create's log to be
    // read as its own.
    keep_failed_create_log(&root, Uuid::new_v4(), "app");
    assert!(!kept.exists());
}

#[test]
fn unsafe_log_files_are_refused() {
    let (_parent, root) = runtime_root();
    let logs = root.path().join(LOG_DIRECTORY);
    open_child_log(&root, SUPERVISOR_LOG).unwrap();
    let current = logs.join(SUPERVISOR_LOG);

    // A log another user could read is never opened or adopted.
    fs::set_permissions(&current, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(open_child_log(&root, SUPERVISOR_LOG).is_err());
    assert!(DiagnosticLog::adopt(File::open(&current).unwrap()).is_none());
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();

    // Neither is a second name for it, nor a symlink in its place.
    let alias = logs.join("alias");
    fs::hard_link(&current, &alias).unwrap();
    assert!(DiagnosticLog::adopt(File::options().append(true).open(&current).unwrap()).is_none());
    fs::remove_file(&alias).unwrap();
    let elsewhere = root.path().join("elsewhere.log");
    fs::write(&elsewhere, b"").unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&current).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &current).unwrap();
    assert!(open_child_log(&root, SUPERVISOR_LOG).is_err());

    // Nor a pipe, which is what an interactive or test stderr usually is.
    let (reader, _writer) = std::io::pipe().unwrap();
    assert!(DiagnosticLog::adopt(File::from(std::os::fd::OwnedFd::from(reader))).is_none());
}

#[test]
fn event_fields_are_closed_and_never_carry_secret_values() {
    let line = event_line(
        7,
        "operation_failed",
        &[
            ("kind", LogField::Name("update_environment_sources")),
            ("operation", LogField::Id(Uuid::nil())),
            ("checkpoint", LogField::Count(8)),
            ("runner_error", LogField::Code(CANARY)),
            (
                "error_code",
                LogField::Code("environment_sources_guest_start_failed"),
            ),
            ("cause", LogField::Name("Not A Token")),
        ],
    );
    assert_eq!(
        line,
        "time_unix_ms=7 event=operation_failed kind=update_environment_sources \
         operation=00000000-0000-0000-0000-000000000000 checkpoint=8 runner_error=invalid \
         error_code=environment_sources_guest_start_failed cause=invalid\n"
    );
    assert!(!line.contains(CANARY));
    let oversized = "a".repeat(MAXIMUM_TOKEN_BYTES + 1);
    assert!(event_line(0, "x", &[("code", LogField::Code(&oversized))]).contains("code=invalid"));
}

#[test]
fn a_digest_is_written_only_as_a_sha256() {
    let digest = "0a".repeat(32);
    assert_eq!(
        event_line(0, "cw_runtime_move", &[("from", LogField::Digest(&digest))]),
        format!("time_unix_ms=0 event=cw_runtime_move from={digest}\n")
    );
    for other in [
        CANARY,
        "0A".repeat(32).as_str(),
        &digest[1..],
        "z".repeat(64).as_str(),
    ] {
        assert!(
            event_line(0, "x", &[("from", LogField::Digest(other))]).ends_with(" from=invalid\n"),
            "{other}"
        );
    }
}
