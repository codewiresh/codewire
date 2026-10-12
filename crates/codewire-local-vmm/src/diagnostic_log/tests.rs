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
fn child_log_is_owner_only_bounded_and_rotated_at_the_next_spawn() {
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

    // The next spawn keeps that log as `.1` and starts an empty one, both 0600.
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

    // Two files, each bounded, are all a log ever keeps.
    open_child_log(&root, SUPERVISOR_LOG).unwrap();
    let mut names = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["supervisor.log", "supervisor.log.1"]);
    assert_eq!(fs::read_to_string(&previous).unwrap(), restarted);
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
