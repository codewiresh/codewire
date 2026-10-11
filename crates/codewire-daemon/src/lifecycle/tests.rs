use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::execution::RuncExecution;
use crate::{CredentialBridgeConfig, DaemonAuthToken, LaunchProjectionConfig};

const FIXTURE_ARG: &str = "codewire-lifecycle-fixture=";

fn config() -> Config {
    Config {
        listen_addr: "unused".into(),
        workspace_root: "/workspace".into(),
        home_root: "/home/codewire".into(),
        auth_token: DaemonAuthToken::new("synthetic-lifecycle-token").unwrap(),
        process_execution: ProcessExecution::Runc(RuncExecution {
            helper_path: "/init".into(),
            process_directory: "/run/codewire/exec".into(),
            container_id: "codewire-workspace".into(),
            process_wrapper: vec!["/run/codewire-runtime/init".into(), "workspace-exec".into()],
            default_shell: "/bin/sh".into(),
            base_environment: vec!["SYNTHETIC_SELECTED_VALUE=must-not-be-inherited".into()],
            uid: 1000,
            gid: 1000,
            additional_gids: Vec::new(),
        }),
        credential_bridge: Some(CredentialBridgeConfig {
            transport: CredentialBridgeTransport::Local,
            environment_id: uuid::Uuid::from_u128(17),
            environment_generation: 3,
            ingress_socket: "/run/codewire/credentials.sock".into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        }),
        managed_credential_clients: Default::default(),
        // No host is connected. Lifecycle control must not request projection.
        host: None,
        launch_projection: Some(LaunchProjectionConfig {
            selection_sha256: [7; 32],
            native: None,
        }),
        session_working_dir: None,
    }
}

fn fixture(mode: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("mode"), mode).unwrap();
    directory
}

fn fixture_command(directory: PathBuf) -> impl FnOnce() -> Command + Send + 'static {
    let executable = std::env::current_exe().unwrap();
    move || {
        let mut command = Command::new(executable);
        command.args([
            "--exact",
            "lifecycle::tests::synthetic_poweroff_child",
            "--nocapture",
            "--skip",
        ]);
        // --skip is an inert libtest filter carrying a synthetic fixture path;
        // it never matches the exact selected test. No child environment input.
        command.arg(format!("{FIXTURE_ARG}{}", directory.display()));
        // Prove the common launcher clears even explicitly configured inputs.
        command.env("SYNTHETIC_AMBIENT_VALUE", "must-not-reach-helper");
        command
    }
}

#[test]
fn synthetic_poweroff_child() {
    let Some(directory) =
        std::env::args().find_map(|arg| arg.strip_prefix(FIXTURE_ARG).map(PathBuf::from))
    else {
        return;
    };
    assert_eq!(std::env::vars_os().count(), 0);
    assert_eq!(std::env::current_dir().unwrap(), Path::new("/"));
    for descriptor in 0..=2 {
        assert_eq!(
            fs::read_link(format!("/proc/self/fd/{descriptor}")).unwrap(),
            Path::new("/dev/null")
        );
    }
    let mode = fs::read_to_string(directory.join("mode")).unwrap();
    fs::write(directory.join("ready"), std::process::id().to_string()).unwrap();
    match mode.as_str() {
        "success" => {}
        "failure" => std::process::exit(19),
        "block" => loop {
            std::thread::park();
        },
        _ => panic!("unknown synthetic lifecycle mode"),
    }
}

#[test]
fn production_command_is_fixed_and_has_no_request_arguments() {
    let command = poweroff_command();
    assert_eq!(command.get_program(), "/init");
    assert_eq!(command.get_args().collect::<Vec<_>>(), ["poweroff"]);
}

#[tokio::test]
async fn local_guest_control_succeeds_without_a_projection_host_or_ambient_environment() {
    static PERMITS: Semaphore = Semaphore::const_new(1);
    let directory = fixture("success");
    let config = config();
    poweroff_with_command(
        &config,
        &PERMITS,
        fixture_command(directory.path().to_owned()),
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
    .unwrap();
    assert!(directory.path().join("ready").is_file());
    assert_eq!(PERMITS.available_permits(), 1);

    let mut without_projection = config;
    without_projection.launch_projection = None;
    poweroff_with_command(
        &without_projection,
        &PERMITS,
        fixture_command(directory.path().to_owned()),
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn unsupported_runtime_and_identity_never_build_or_spawn_a_command() {
    static PERMITS: Semaphore = Semaphore::const_new(1);
    let mut invalid = Vec::new();
    let mut native = config();
    native.process_execution = ProcessExecution::Native;
    invalid.push(native);
    let mut hosted = config();
    hosted.credential_bridge.as_mut().unwrap().transport = CredentialBridgeTransport::Hosted;
    invalid.push(hosted);
    let mut missing = config();
    missing.credential_bridge = None;
    invalid.push(missing);
    let mut wrong_id = config();
    wrong_id.credential_bridge.as_mut().unwrap().environment_id = uuid::Uuid::nil();
    invalid.push(wrong_id);
    for generation in [0, u64::MAX] {
        let mut wrong_generation = config();
        wrong_generation
            .credential_bridge
            .as_mut()
            .unwrap()
            .environment_generation = generation;
        invalid.push(wrong_generation);
    }
    for changed_field in 0..5 {
        let mut changed = config();
        let ProcessExecution::Runc(runc) = &mut changed.process_execution else {
            unreachable!()
        };
        match changed_field {
            0 => runc.helper_path = "/other/init".into(),
            1 => runc.container_id = "other-workspace".into(),
            2 => runc.process_wrapper.push("extra".into()),
            3 => runc.uid = 1001,
            4 => runc.gid = 1001,
            _ => unreachable!(),
        }
        invalid.push(changed);
    }
    for config in invalid {
        let error = poweroff_with_command(
            &config,
            &PERMITS,
            || panic!("unsupported runtime must not build a command"),
            POWEROFF_HELPER_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(PERMITS.available_permits(), 1);
    }
}

async fn ready_child(directory: &Path) -> (libc::pid_t, OwnedFd) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Ok(pid) = fs::read_to_string(directory.join("ready"))
                && let Ok(pid) = pid.parse::<libc::pid_t>()
            {
                // This PID comes only from our exact private synthetic child.
                let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                assert!(descriptor >= 0, "synthetic child must still be alive");
                return (pid, unsafe { OwnedFd::from_raw_fd(descriptor as i32) });
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("synthetic helper readiness")
}

fn assert_child_reaped(pid: libc::pid_t, descriptor: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
    assert_ne!(poll.revents & libc::POLLIN, 0);
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[tokio::test]
async fn cancelled_request_retains_permit_until_exact_child_is_dead_and_reaped() {
    static PERMITS: Semaphore = Semaphore::const_new(1);
    let directory = fixture("block");
    let command = fixture_command(directory.path().to_owned());
    let task = tokio::spawn(async move {
        poweroff_with_command(&config(), &PERMITS, command, POWEROFF_HELPER_TIMEOUT).await
    });
    let (pid, descriptor) = ready_child(directory.path()).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(PERMITS.available_permits(), 0);
    let constructed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&constructed);
    let error = poweroff_with_command(
        &config(),
        &PERMITS,
        move || {
            observed.store(true, Ordering::Release);
            poweroff_command()
        },
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    assert!(!constructed.load(Ordering::Acquire));
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if PERMITS.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled request's retained worker must drain");
    assert_child_reaped(pid, &descriptor);
    assert!(!PERMITS.is_closed());
}

#[tokio::test]
async fn deadline_kills_and_reaps_before_returning_timeout() {
    static PERMITS: Semaphore = Semaphore::const_new(1);
    let directory = fixture("block");
    let command = fixture_command(directory.path().to_owned());
    let task = tokio::spawn(async move {
        poweroff_with_command(&config(), &PERMITS, command, POWEROFF_HELPER_TIMEOUT).await
    });
    let (pid, descriptor) = ready_child(directory.path()).await;
    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    assert_child_reaped(pid, &descriptor);
    assert_eq!(PERMITS.available_permits(), 1);
}

#[tokio::test]
async fn helper_failure_spawn_failure_and_expired_budget_are_not_success() {
    static PERMITS: Semaphore = Semaphore::const_new(1);
    let directory = fixture("failure");
    let failure = poweroff_with_command(
        &config(),
        &PERMITS,
        fixture_command(directory.path().to_owned()),
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.code(), tonic::Code::Internal);
    let absent = directory.path().join("absent-helper");
    let failure = poweroff_with_command(
        &config(),
        &PERMITS,
        move || Command::new(absent),
        POWEROFF_HELPER_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.code(), tonic::Code::Unavailable);
    let failure = poweroff_with_command(
        &config(),
        &PERMITS,
        || panic!("expired worker must not build a command"),
        Duration::ZERO,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.code(), tonic::Code::DeadlineExceeded);
    assert_eq!(PERMITS.available_permits(), 1);
}
