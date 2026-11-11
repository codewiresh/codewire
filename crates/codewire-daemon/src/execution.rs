use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use portable_pty::CommandBuilder;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize as _;

#[cfg(test)]
use crate::config::DAEMON_AUTH_TOKEN_ENV;
use crate::env::is_internal_environment_name;

#[cfg(target_os = "linux")]
mod bootstrap;
mod projection;
#[cfg(target_os = "linux")]
pub(crate) use bootstrap::StartupProjectionIngress;
#[cfg(target_os = "linux")]
pub use bootstrap::{BOOTSTRAP_FINISH, BOOTSTRAP_PROJECTION_SOCKET_NAME, BootstrapPhase};
#[cfg(target_os = "linux")]
pub use codewire_workload_secrets::launcher::run_environment_launcher;
use projection::LaunchRendezvous;

/// Own the PTY child during launch awaits, before its normal monitor exists.
/// Dropping a request must not strand a helper waiting for projection commit.
pub(crate) struct PtyLaunchGuard(Option<Box<dyn portable_pty::Child + Send + Sync>>);

impl PtyLaunchGuard {
    pub(crate) fn new(child: Box<dyn portable_pty::Child + Send + Sync>) -> Self {
        Self(Some(child))
    }
    pub(crate) fn process_id(&self) -> Option<u32> {
        self.0.as_ref().and_then(|child| child.process_id())
    }
    pub(crate) fn release(mut self) -> Box<dyn portable_pty::Child + Send + Sync> {
        self.0.take().expect("PTY launch child is owned")
    }
    pub(crate) async fn terminate_confirmed(&mut self, timeout: std::time::Duration) -> bool {
        self.terminate_confirmed_spending(&crate::confirm::CheckBudget::new(timeout))
            .await
    }

    /// [`Self::terminate_confirmed`], spending a cleanup's shared checks.
    pub(crate) async fn terminate_confirmed_spending(
        &mut self,
        budget: &crate::confirm::CheckBudget,
    ) -> bool {
        let Some(child) = self.0.as_mut() else {
            return true;
        };
        // A failed signal is not proof either way: the exact child may have
        // already exited. Only a successful reap establishes completion.
        let _ = child.kill();
        let reaped = crate::confirm::check_spending(budget, || match child.try_wait() {
            Ok(Some(_)) => Some(true),
            Err(_) => Some(false),
            Ok(None) => None,
        })
        .await
        .unwrap_or(false);
        if reaped {
            self.0 = None;
        }
        reaped
    }
}
impl Drop for PtyLaunchGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            // This drainer owns the exact child even if the requesting future
            // or Tokio runtime is dropped; it cannot unlink another launch.
            let _ = std::thread::Builder::new()
                .name("cw-launch-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

const MAX_PROCESS_SPEC_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessExecution {
    Native,
    Runc(RuncExecution),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuncExecution {
    pub helper_path: PathBuf,
    pub process_directory: PathBuf,
    pub container_id: String,
    pub process_wrapper: Vec<String>,
    pub default_shell: String,
    pub base_environment: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
    /// The pinned network namespace the workload container joins, which
    /// `ForwardTcp` connects inside (#3025).
    pub network_namespace: PathBuf,
}

impl ProcessExecution {
    pub fn default_shell(&self, native: impl FnOnce() -> String) -> String {
        match self {
            Self::Native => native(),
            Self::Runc(config) => config.default_shell.clone(),
        }
    }

    pub fn base_environment(
        &self,
        native: impl IntoIterator<Item = (String, String)>,
    ) -> Vec<(String, String)> {
        match self {
            Self::Native => native.into_iter().collect(),
            Self::Runc(config) => config
                .base_environment
                .iter()
                .filter_map(|entry| {
                    let (key, value) = entry.split_once('=')?;
                    Some((key.to_owned(), value.to_owned()))
                })
                .collect(),
        }
    }
}

pub struct PreparedProcess {
    program: OsString,
    arguments: Vec<OsString>,
    current_directory: PathBuf,
    environment: Vec<(String, String)>,
    pending_process_spec: Option<PathBuf>,
    launch: Option<LaunchRendezvous>,
    /// Set just before the launcher is told to execute (#2769).
    launch_committed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for PreparedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedProcess")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .field("current_directory", &self.current_directory)
            .field(
                "environment_keys",
                &self
                    .environment
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<Vec<_>>(),
            )
            .field("pending_process_spec", &self.pending_process_spec)
            .finish()
    }
}

impl PreparedProcess {
    pub fn prepare(
        execution: &ProcessExecution,
        command: &[String],
        working_directory: &str,
        environment: &[String],
        terminal: bool,
        width: u16,
        height: u16,
    ) -> io::Result<Self> {
        if command.is_empty() || command[0].is_empty() {
            return Err(invalid_input("process command is empty"));
        }
        match execution {
            ProcessExecution::Native => Ok(Self {
                program: OsString::from(&command[0]),
                arguments: command[1..].iter().map(OsString::from).collect(),
                current_directory: PathBuf::from(working_directory),
                environment: split_environment(environment),
                pending_process_spec: None,
                launch: None,
                launch_committed: Default::default(),
            }),
            ProcessExecution::Runc(config) => prepare_runc(
                config,
                command,
                working_directory,
                environment,
                terminal,
                width,
                height,
            ),
        }
    }

    pub fn tokio_command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.arguments)
            .current_dir(&self.current_directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (key, value) in &self.environment {
            command.env(key, value);
        }
        command
    }

    pub fn pty_command(&self) -> CommandBuilder {
        let mut command = CommandBuilder::new(&self.program);
        command.args(&self.arguments);
        command.cwd(&self.current_directory);
        command.env_clear();
        if self.pending_process_spec.is_some() {
            // portable-pty always injects SHELL when it materializes a Unix
            // Command, even after env_clear. Bind that unavoidable helper-only
            // value to the sealed executable; the helper validates and clears
            // it before execing runc.
            command.env("SHELL", &self.program);
        } else {
            for (key, value) in &self.environment {
                command.env(key, value);
            }
        }
        command
    }

    /// The helper opens/unlinks the spec. Retain its unique cleanup path until
    /// this owner drops, including cancellation before the helper first runs.
    pub fn spawned(&mut self) {}

    /// Whether the launcher was told to execute (#2769). After that, a
    /// failure or cancellation is never a denial: the program may have
    /// started.
    pub(crate) fn launch_committed(&self) -> bool {
        self.launch_committed
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Complete the exact-child rendezvous before the caller marks it Running.
    /// Cancellation drops the relay future and its existing bridge budget guard.
    pub(crate) async fn project_spawned(&mut self, pid: Option<u32>) -> io::Result<()> {
        if let Some(launch) = self.launch.take() {
            launch
                .deliver(pid.ok_or_else(|| invalid_input("launcher PID unavailable"))?)
                .await?;
        }
        Ok(())
    }
}

impl Drop for PreparedProcess {
    fn drop(&mut self) {
        for (_, value) in &mut self.environment {
            value.zeroize();
        }
        if let Some(path) = self.pending_process_spec.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn prepare_runc(
    config: &RuncExecution,
    command: &[String],
    working_directory: &str,
    environment: &[String],
    terminal: bool,
    width: u16,
    height: u16,
) -> io::Result<PreparedProcess> {
    validate_runc_config(config)?;
    if !working_directory.starts_with('/') {
        return Err(invalid_input(
            "runc process working directory is not absolute",
        ));
    }
    let mut args = config.process_wrapper.clone();
    args.extend_from_slice(command);
    let process_spec = RuncProcessSpec {
        terminal,
        console_size: terminal.then_some(ConsoleSize { height, width }),
        user: ProcessUser {
            uid: config.uid,
            gid: config.gid,
            additional_gids: config.additional_gids.clone(),
        },
        args,
        env: environment
            .iter()
            .filter(|entry| !is_internal_environment_entry(entry))
            .cloned()
            .collect(),
        cwd: working_directory.to_owned(),
        capabilities: ProcessCapabilities::default(),
        no_new_privileges: true,
    };
    let bytes = serde_json::to_vec(&process_spec)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.is_empty() || bytes.len() > MAX_PROCESS_SPEC_BYTES {
        return Err(invalid_input("runc process specification is too large"));
    }
    validate_process_directory(&config.process_directory)?;
    let path = config
        .process_directory
        .join(format!("{}.json", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

    Ok(PreparedProcess {
        program: config.helper_path.as_os_str().to_owned(),
        arguments: vec![
            OsString::from("runc-exec"),
            OsString::from(&config.container_id),
            path.as_os_str().to_owned(),
        ],
        current_directory: PathBuf::from("/"),
        environment: Vec::new(),
        pending_process_spec: Some(path),
        launch: None,
        launch_committed: Default::default(),
    })
}

fn validate_runc_config(config: &RuncExecution) -> io::Result<()> {
    if !config.helper_path.is_absolute()
        || !config.process_directory.is_absolute()
        || config.process_wrapper.is_empty()
        || !config.process_wrapper[0].starts_with('/')
        || config.process_wrapper.iter().any(String::is_empty)
        || config.default_shell.is_empty()
        || !config.default_shell.starts_with('/')
        || config.container_id.is_empty()
        || config.container_id.len() > 64
        || !config
            .container_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid_input("invalid runc execution configuration"));
    }
    Ok(())
}

/// Create the owner-private process directory when it is missing, then apply
/// the same check every launch applies. Idempotent across daemon restarts; an
/// existing directory is never replaced or loosened.
pub(crate) fn ensure_process_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_process_directory(path)
}

fn validate_process_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_input("runc process directory is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runc process directory is not owner-private",
            ));
        }
    }
    Ok(())
}

fn split_environment(environment: &[String]) -> Vec<(String, String)> {
    environment
        .iter()
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            if is_internal_environment_name(key) {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn is_internal_environment_entry(entry: &str) -> bool {
    entry
        .split_once('=')
        .is_some_and(|(key, _)| is_internal_environment_name(key))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuncProcessSpec {
    terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    console_size: Option<ConsoleSize>,
    user: ProcessUser,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    capabilities: ProcessCapabilities,
    no_new_privileges: bool,
}

#[derive(Serialize)]
struct ConsoleSize {
    height: u16,
    width: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessUser {
    uid: u32,
    gid: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_gids: Vec<u32>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessCapabilities {
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
    ambient: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[derive(Clone, Debug)]
    struct CleanupChild {
        reaped: bool,
        wait_error: bool,
    }

    impl portable_pty::ChildKiller for CleanupChild {
        fn kill(&mut self) -> io::Result<()> {
            Err(io::Error::other("synthetic signal failure"))
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(self.clone())
        }
    }

    impl portable_pty::Child for CleanupChild {
        fn try_wait(&mut self) -> io::Result<Option<portable_pty::ExitStatus>> {
            if self.wait_error {
                return Err(io::Error::other("synthetic reap failure"));
            }
            Ok(self
                .reaped
                .then(|| portable_pty::ExitStatus::with_exit_code(0)))
        }

        fn wait(&mut self) -> io::Result<portable_pty::ExitStatus> {
            Err(io::Error::other("synthetic child has no OS process"))
        }

        fn process_id(&self) -> Option<u32> {
            None
        }
    }

    #[tokio::test]
    async fn launch_cleanup_accepts_confirmed_reap_even_when_signal_races_exit() {
        let mut child = PtyLaunchGuard::new(Box::new(CleanupChild {
            reaped: true,
            wait_error: false,
        }));
        assert!(child.terminate_confirmed(std::time::Duration::ZERO).await);
        assert!(child.0.is_none());
    }

    #[tokio::test]
    async fn launch_cleanup_timeout_is_not_reap_confirmation() {
        let mut child = PtyLaunchGuard::new(Box::new(CleanupChild {
            reaped: false,
            wait_error: false,
        }));
        assert!(!child.terminate_confirmed(std::time::Duration::ZERO).await);
        assert!(child.0.is_some(), "the exact child remains guarded");
    }

    #[tokio::test]
    async fn launch_cleanup_wait_error_is_not_reap_confirmation() {
        let mut child = PtyLaunchGuard::new(Box::new(CleanupChild {
            reaped: false,
            wait_error: true,
        }));
        assert!(
            !child
                .terminate_confirmed(std::time::Duration::from_secs(1))
                .await
        );
        assert!(child.0.is_some(), "the exact child remains guarded");
    }

    #[test]
    fn process_directory_is_created_private_once_and_never_loosened_or_followed() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("processes");
        ensure_process_directory(&directory).unwrap();
        let mode = fs::symlink_metadata(&directory)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let marker = directory.join("pending.json");
        fs::write(&marker, b"{}").unwrap();
        ensure_process_directory(&directory).unwrap();
        assert!(
            marker.exists(),
            "an existing directory is reused, not replaced"
        );

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            ensure_process_directory(&directory).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let link = parent.path().join("linked");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert_eq!(
            ensure_process_directory(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            ensure_process_directory(&parent.path().join("missing/processes"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn runc_process_values_live_only_in_owner_private_tmpfs_spec() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let execution = ProcessExecution::Runc(RuncExecution {
            helper_path: PathBuf::from("/init"),
            process_directory: directory.path().to_owned(),
            container_id: "codewire-workspace".into(),
            process_wrapper: vec!["/run/codewire-runtime/init".into(), "workspace-exec".into()],
            default_shell: "/bin/bash".into(),
            base_environment: vec!["PATH=/usr/bin:/bin".into()],
            uid: 1000,
            gid: 1000,
            additional_gids: vec![27],
            network_namespace: "/run/codewire/netns/workspace".into(),
        });
        let secret = "CW_TEST_SECRET=not-on-helper-command";
        let daemon_auth = format!("{DAEMON_AUTH_TOKEN_ENV}=must-not-enter-child");
        let managed_selection = format!(
            "{}=must-not-enter-child",
            crate::config::MANAGED_CREDENTIAL_CLIENTS_ENV
        );
        let prepared = PreparedProcess::prepare(
            &execution,
            &["/bin/sh".into(), "-lc".into(), "id".into()],
            "/workspace",
            &[secret.into(), daemon_auth, managed_selection],
            true,
            120,
            40,
        )
        .unwrap();

        assert_eq!(prepared.program, OsStr::new("/init"));
        assert!(
            prepared
                .arguments
                .iter()
                .all(|argument| !argument.to_string_lossy().contains("not-on-helper-command"))
        );
        assert!(prepared.environment.is_empty());
        assert_eq!(
            prepared.pty_command().get_env("SHELL"),
            Some(OsStr::new("/init"))
        );
        let spec_path = prepared.pending_process_spec.as_ref().unwrap().clone();
        let metadata = fs::symlink_metadata(&spec_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&spec_path).unwrap()).unwrap();
        assert_eq!(value["env"], serde_json::json!([secret]));
        assert_eq!(
            value["args"],
            serde_json::json!([
                "/run/codewire-runtime/init",
                "workspace-exec",
                "/bin/sh",
                "-lc",
                "id"
            ])
        );
        assert_eq!(value["terminal"], true);
        assert_eq!(value["consoleSize"]["width"], 120);
        assert_eq!(value["user"]["uid"], 1000);
        drop(prepared);
        assert!(!spec_path.exists());
    }

    #[test]
    fn native_process_drops_internal_daemon_configuration_from_supplied_environment() {
        let prepared = PreparedProcess::prepare(
            &ProcessExecution::Native,
            &["/usr/bin/env".into()],
            "/",
            &[
                "VISIBLE=value".into(),
                format!("{DAEMON_AUTH_TOKEN_ENV}=must-not-enter-child"),
                format!(
                    "{}=must-not-enter-child",
                    crate::config::MANAGED_CREDENTIAL_CLIENTS_ENV
                ),
            ],
            false,
            0,
            0,
        )
        .unwrap();

        assert_eq!(
            prepared.environment,
            vec![("VISIBLE".into(), "value".into())]
        );
    }

    #[test]
    fn runc_rejects_non_private_process_directories() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let execution = ProcessExecution::Runc(RuncExecution {
            helper_path: PathBuf::from("/init"),
            process_directory: directory.path().to_owned(),
            container_id: "codewire-workspace".into(),
            process_wrapper: vec!["/run/codewire-runtime/init".into(), "workspace-exec".into()],
            default_shell: "/bin/sh".into(),
            base_environment: Vec::new(),
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
            network_namespace: "/run/codewire/netns/workspace".into(),
        });
        let error =
            PreparedProcess::prepare(&execution, &["/bin/sh".into()], "/", &[], false, 0, 0)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
