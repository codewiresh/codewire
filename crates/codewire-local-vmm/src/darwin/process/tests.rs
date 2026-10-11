use super::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = "darwin::process::tests::observation_child";
const PHASE: &str = "CW_PROCESS_OBSERVATION_PHASE";
const UUID: &[u8; 37] = b"dcb8c370-2cf9-492e-b2ba-8c42769a1465\0";

#[test]
fn boot_uuid_requires_exact_length_hyphens_nul_and_nonnil_value() {
    let expected = BootSessionId::from_sysctl(UUID, 37).unwrap();
    let mut uppercase = *UUID;
    uppercase.make_ascii_uppercase();
    assert_eq!(
        BootSessionId::from_sysctl(&uppercase, 37).unwrap(),
        expected
    );
    for length in [0, 1, 16, 32, 36, 38, usize::MAX] {
        assert!(BootSessionId::from_sysctl(UUID, length).is_err());
    }
    for (index, byte) in [(0, 0), (0, b'g'), (8, b'0'), (13, b'_'), (36, b'x')] {
        let mut malformed = *UUID;
        malformed[index] = byte;
        assert!(BootSessionId::from_sysctl(&malformed, 37).is_err());
    }
    assert!(BootSessionId::from_sysctl(b"00000000-0000-0000-0000-000000000000\0", 37).is_err());
    assert_eq!(expected.as_bytes()[0], 0xdc);
}

#[test]
fn syscall_results_preserve_failure_and_reject_nonzero_success_shapes() {
    assert!(syscall_result(0).is_ok());
    // SAFETY: __error returns this test thread's errno location, not shared state.
    unsafe { *libc::__error() = libc::EPERM };
    assert_eq!(
        syscall_result(-1).unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    for result in [-2, 1, 96] {
        assert_eq!(
            syscall_result(result).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn process_observation_rejects_boot_change_zero_start_and_exit() {
    let boot = BootSessionId::from_sysctl(UUID, 37).unwrap();
    // SAFETY: V0 contains only initialized integer fields and byte arrays.
    let mut usage: libc::rusage_info_v0 = unsafe { std::mem::zeroed() };
    assert!(matches!(
        admit_observation(1, boot, boot, &usage),
        Err(ObservationError::MalformedProcess)
    ));
    usage.ri_proc_start_abstime = 42;
    let expected = admit_observation(1, boot, boot, &usage).unwrap();
    usage.ri_uuid = [255; 16];
    usage.ri_user_time = 123;
    assert_eq!(admit_observation(1, boot, boot, &usage).unwrap(), expected);
    assert_eq!(expected.start_abstime(), 42);
    usage.ri_proc_exit_abstime = 43;
    assert!(matches!(
        admit_observation(1, boot, boot, &usage),
        Err(ObservationError::ProcessExited)
    ));
    let other = BootSessionId([1; 16]);
    assert!(matches!(
        admit_observation(1, boot, other, &usage),
        Err(ObservationError::BootChanged)
    ));
    for pid in [0, u32::MAX] {
        assert!(matches!(
            observe_pid(pid),
            Err(ObservationError::MalformedProcess)
        ));
    }
}

#[test]
fn current_process_observation_is_stable_and_native() {
    let first = observe_current().unwrap();
    let second = observe_current().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.pid(), std::process::id());
    assert_eq!(first.boot_session(), BootSessionId::current().unwrap());
    assert_ne!(first.start_abstime(), 0);
    assert_ne!(*first.boot_session().as_bytes(), [0; 16]);
}

#[test]
fn a_process_birth_matches_its_identity_without_reading_the_executable() {
    let pid = std::process::id();
    let birth = ProcessBirth::observe(pid).unwrap();
    assert_eq!(birth, ProcessBirth::observe(pid).unwrap());
    assert_eq!(birth.pid(), pid);
    let identity = ProcessIdentity::capture(pid).unwrap();
    assert!(birth.is(&identity));
    // Another birth, or the same birth under another file, is not this one.
    let mut other = identity.clone();
    other.start_time_ticks += 1;
    assert!(!birth.is(&other));
    let mut moved = identity;
    moved.executable_file.inode += 1;
    assert!(!birth.is(&moved));
    assert!(ProcessBirth::observe(0).is_err());
}

#[test]
fn a_rewritten_executable_is_not_the_same_birth() {
    use std::os::unix::fs::PermissionsExt as _;
    // A same-user process can change the file and restore its mode, size and
    // links; only its change time records that it happened.
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("sleeper");
    std::fs::copy("/bin/sleep", &executable).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(&executable).arg("30").spawn().unwrap();
    let pid = child.id();
    let birth = ProcessBirth::observe(pid).unwrap();
    assert_eq!(birth, ProcessBirth::observe(pid).unwrap());
    std::thread::sleep(Duration::from_millis(20));
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let after = ProcessBirth::observe(pid);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_ne!(after.unwrap(), birth);
}

fn child_command(phase: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            HELPER,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(PHASE, phase);
    command
}

struct Fixture {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    pending: Vec<u8>,
    remaining: usize,
    deadline: Instant,
}

impl Fixture {
    fn start(phase: &str) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut child = child_command(phase)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        // Own the child before fallible setup so failure cleanup is available.
        let fixture = Self {
            child,
            input,
            output,
            pending: Vec::new(),
            remaining: 8192,
            deadline,
        };
        fixture.check_deadline();
        for fd in [fixture.input.as_raw_fd(), fixture.output.as_raw_fd()] {
            // SAFETY: both descriptors remain owned; only nonblocking mode changes.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        fixture
    }

    fn check_deadline(&self) {
        assert!(Instant::now() < self.deadline, "fixture deadline");
    }

    fn ready(&self, fd: RawFd, events: libc::c_short) {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .expect("fixture deadline");
            let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: one initialized pollfd remains live for the bounded call.
            let result = unsafe { libc::poll(&mut poll, 1, timeout) };
            if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            assert!(result > 0, "fixture pipe poll failed/timed out: {result}");
            assert_eq!(poll.revents & libc::POLLNVAL, 0);
            self.check_deadline();
            return;
        }
    }

    fn marker(&mut self) -> String {
        loop {
            self.check_deadline();
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                assert!(end < 512, "oversized fixture frame");
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                let line = String::from_utf8(line).unwrap();
                if line.starts_with("CW_OBSERVATION ") {
                    self.check_deadline();
                    return line;
                }
                continue;
            }
            assert!(self.pending.len() < 512, "oversized fixture frame");
            assert!(self.remaining > 0, "oversized fixture output");
            self.ready(self.output.as_raw_fd(), libc::POLLIN);
            let mut bytes = [0; 128];
            match self.output.read(&mut bytes) {
                Ok(0) => panic!("fixture EOF before required marker"),
                Ok(count) => {
                    self.remaining = self.remaining.checked_sub(count).expect("output limit");
                    self.pending.extend_from_slice(&bytes[..count]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("fixture read failed: {error}"),
            }
        }
    }

    fn send(&mut self, marker: u8) {
        loop {
            self.ready(self.input.as_raw_fd(), libc::POLLOUT);
            match self.input.write(&[marker]) {
                Ok(1) => {
                    self.check_deadline();
                    return;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => panic!("fixture marker write failed: {result:?}"),
            }
        }
    }

    fn finish(&mut self) {
        loop {
            self.check_deadline();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.check_deadline();
                assert!(status.success(), "fixture failed: {status}");
                return;
            }
            assert!(Instant::now() < self.deadline, "fixture failed to exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fixture waits for this retained child. Never signal if wait
        // reports uncertainty; never reconstruct a Child from a recovered PID.
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Err(error) => {
                eprintln!("owned fixture wait uncertain: {error}");
                return;
            }
            Ok(None) => {}
        }
        if let Err(error) = self.child.kill() {
            eprintln!("owned fixture cleanup kill failed: {error}");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                result => {
                    eprintln!("owned fixture cleanup incomplete: {result:?}");
                    return;
                }
            }
        }
    }
}

fn report(phase: &str, observation: ProcessBirthObservation) -> String {
    format!(
        "CW_OBSERVATION {phase} {} {} {}\n",
        observation.pid(),
        uuid::Uuid::from_bytes(*observation.boot_session().as_bytes()),
        observation.start_abstime()
    )
}

#[test]
fn owned_child_matches_self_report_and_keeps_birth_across_exec() {
    let mut fixture = Fixture::start("before");
    let first_report = fixture.marker();
    let first = observe_owned_child(&mut fixture.child).unwrap();
    assert_eq!(first_report, report("before", first));
    fixture.send(b'E');
    let second_report = fixture.marker();
    let second = observe_owned_child(&mut fixture.child).unwrap();
    assert_eq!(second_report, report("after", second));
    assert_eq!(first, second);
    fixture.send(b'Q');
    fixture.finish();
    assert!(matches!(
        observe_child_with(&mut fixture.child, |_| panic!("queried reaped PID")),
        Err(ObservationError::ProcessExited)
    ));
}

#[test]
fn autoreap_disposition_is_rejected_in_an_isolated_process() {
    let mut fixture = Fixture::start("disposition");
    assert_eq!(fixture.marker(), "CW_OBSERVATION disposition-rejected\n");
    fixture.send(b'Q');
    fixture.finish();
}

#[test]
fn expired_deadline_rejects_buffered_marker_and_successful_cached_exit() {
    let mut fixture = Fixture::start("after");
    let marker = fixture.marker();
    let observation = observe_owned_child(&mut fixture.child).unwrap();
    assert_eq!(marker, report("after", observation));
    fixture.send(b'Q');
    fixture.finish();
    fixture.deadline = Instant::now() - Duration::from_secs(1);
    fixture.pending = b"CW_OBSERVATION buffered\n".to_vec();
    for action in [
        Fixture::finish as fn(&mut Fixture),
        |fixture| {
            fixture.marker();
        },
        |fixture| fixture.send(b'Q'),
    ] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut fixture)))
                .is_err()
        );
    }
}

fn require_marker(expected: u8) {
    let mut marker = [0];
    std::io::stdin().read_exact(&mut marker).unwrap();
    assert_eq!(marker, [expected]);
}

fn flush_report(message: &str) {
    let mut stdout = std::io::stdout().lock();
    // A leading newline separates the exact frame from the libtest progress line.
    stdout.write_all(b"\n").unwrap();
    stdout.write_all(message.as_bytes()).unwrap();
    stdout.flush().unwrap();
}

#[test]
#[ignore = "fixed child invoked only by bounded owned-parent tests"]
fn observation_child() {
    match std::env::var(PHASE).unwrap().as_str() {
        "before" => {
            flush_report(&report("before", observe_current().unwrap()));
            require_marker(b'E');
            let error = child_command("after").exec();
            panic!("fixed test executable exec failed: {error}");
        }
        "after" => {
            flush_report(&report("after", observe_current().unwrap()));
            require_marker(b'Q');
        }
        "disposition" => {
            // This isolated process owns no children. Never alter SIGCHLD in
            // the parallel parent test runner, or spawn with autoreap enabled.
            for (handler, flags) in [(libc::SIG_IGN, 0), (libc::SIG_DFL, libc::SA_NOCLDWAIT)] {
                let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = handler;
                action.sa_flags = flags;
                // SAFETY: valid initialized action/output; only this isolated
                // no-children fixture changes its own disposition.
                assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &action, &mut previous) },
                    0
                );
                let result = ChildWaitDisposition::current();
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &previous, std::ptr::null_mut()) },
                    0
                );
                assert!(matches!(
                    result,
                    Err(ObservationError::IncompatibleChildWait)
                ));
            }
            flush_report("CW_OBSERVATION disposition-rejected\n");
            require_marker(b'Q');
        }
        phase => panic!("unexpected fixture phase: {phase}"),
    }
}

const PARENT_EXIT_CHILD: &str = "darwin::process::tests::parent_exit_child";
const PARENT_EXIT_MODE: &str = "CW_PARENT_EXIT_CHILD";

#[test]
fn captured_identity_is_the_current_birth_and_is_never_adopted() {
    let identity = ProcessIdentity::capture(std::process::id()).unwrap();
    let birth = observe_current().unwrap();
    assert_eq!(identity.pid, std::process::id());
    assert_eq!(identity.boot_id, birth.boot_session().to_hyphenated());
    assert_eq!(identity.start_time_ticks, birth.start_abstime());
    assert_eq!(
        identity.executable,
        std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
    );
    assert_eq!(identity.executable_sha256.len(), 64);
    assert!(matches!(
        LiveProcess::recover(&identity),
        Err(RecoveryError::Unowned)
    ));
    let mut other = identity;
    other.start_time_ticks += 1;
    assert!(matches!(
        LiveProcess::recover(&other),
        Err(RecoveryError::IdentityMismatch)
    ));
}

fn readable(fd: RawFd) -> bool {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized entry; zero timeout.
    unsafe { libc::poll(&mut pollfd, 1, 0) == 1 }
}

#[tokio::test]
async fn owned_child_exit_is_observed_and_a_reaped_child_is_never_signaled() {
    let sleep = std::path::Path::new("/bin/sleep");
    let mut child = crate::test_child(&mut Command::new(sleep))
        .arg("30")
        .spawn()
        .unwrap();
    assert!(matches!(
        LiveProcess::capture_child(child.id(), std::path::Path::new("/bin/cat")),
        Err(RecoveryError::UnexpectedSpawnedExecutable)
    ));
    let process = LiveProcess::capture_child(child.id(), sleep).unwrap();
    let liveness = process.duplicate_wait_descriptor().unwrap();
    assert!(!process.is_exited().unwrap());
    assert!(!readable(liveness.as_raw_fd()));
    process.signal(Signal::KILL).unwrap();
    assert!(process.wait_exited(Duration::from_secs(5)).await.unwrap());
    assert!(readable(liveness.as_raw_fd()));
    // Exited but unreaped: signaling has no effect, as with a Linux pidfd.
    process.signal(Signal::KILL).unwrap();
    child.wait().unwrap();
    assert!(process.is_exited().unwrap());
    assert!(matches!(
        process.signal(Signal::KILL),
        Err(RecoveryError::ProcessExited)
    ));
    assert!(matches!(
        LiveProcess::recover(process.identity()),
        Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch)
    ));
}

#[test]
fn spawned_child_exits_when_its_parent_exits() {
    // sh starts the fixed child in the background, reports its PID, then
    // becomes `sleep`, which stays the child's parent until killed here.
    let mut parent = Command::new("/bin/sh")
        .args([
            "-c",
            "\"$0\" \"$@\" & echo \"$!\"; exec /bin/sleep 30",
            std::env::current_exe().unwrap().to_str().unwrap(),
            "--exact",
            PARENT_EXIT_CHILD,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(PARENT_EXIT_MODE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut output = parent.stdout.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    while !String::from_utf8_lossy(&seen).contains("CW_PARENT_EXIT ready\n") {
        assert!(Instant::now() < deadline, "child never became ready");
        let mut buffer = [0_u8; 256];
        let read = output.read(&mut buffer).unwrap();
        assert_ne!(read, 0, "child exited before becoming ready");
        seen.extend_from_slice(&buffer[..read]);
    }
    // The unreaped direct child is owned here, so std's kill is exact.
    parent.kill().unwrap();
    parent.wait().unwrap();
    // Only the background child still holds the pipe: EOF means it exited.
    let descriptor = output.as_raw_fd();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut pollfd = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized entry for a bounded wait.
        let ready = unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis() as libc::c_int) };
        assert_eq!(ready, 1, "child outlived its parent");
        let mut buffer = [0_u8; 256];
        if output.read(&mut buffer).unwrap() == 0 {
            break;
        }
    }
}

#[test]
#[ignore = "fixed child invoked only by spawned_child_exits_when_its_parent_exits"]
fn parent_exit_child() {
    if std::env::var_os(PARENT_EXIT_MODE).is_none() {
        return;
    }
    exit_with_parent().unwrap();
    flush_report("CW_PARENT_EXIT ready\n");
    std::thread::sleep(Duration::from_secs(20));
    panic!("parent exit was not observed");
}

#[test]
fn spawned_child_inherits_no_descriptor_beyond_stdio_after_the_sweep() {
    // An inheritable pipe end stands in for a descriptor another thread has
    // created but not yet marked close-on-exec when a child is spawned.
    let mut ends = [0; 2];
    // SAFETY: a two-element output array.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: both are fresh descriptors that only this test owns.
    let (read, _write) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: a scalar fcntl on an owned descriptor.
    assert_eq!(
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let inherited = |sweep: bool| {
        let mut command = Command::new("/bin/test");
        command
            .arg("-e")
            .arg(format!("/dev/fd/{}", read.as_raw_fd()));
        if sweep {
            // SAFETY: the sweep makes only getdtablesize and fcntl calls.
            unsafe {
                command.pre_exec(|| {
                    mark_inherited_descriptors_close_on_exec();
                    Ok(())
                });
            }
        }
        command.status().unwrap().success()
    };
    assert!(
        inherited(false),
        "control: an inheritable descriptor reaches the child"
    );
    assert!(!inherited(true));
}
