use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use portable_pty::CommandBuilder;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::config::DAEMON_AUTH_TOKEN_ENV;

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

    /// Once the helper has been spawned it owns opening and unlinking the
    /// tmpfs process specification. Before that point Drop removes it on every
    /// failure path.
    pub fn spawned(&mut self) {
        self.pending_process_spec = None;
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
            .filter(|entry| !is_daemon_auth_environment_entry(entry))
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
            if key == DAEMON_AUTH_TOKEN_ENV {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn is_daemon_auth_environment_entry(entry: &str) -> bool {
    entry
        .split_once('=')
        .is_some_and(|(key, _)| key == DAEMON_AUTH_TOKEN_ENV)
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
        });
        let secret = "CW_TEST_SECRET=not-on-helper-command";
        let daemon_auth = format!("{DAEMON_AUTH_TOKEN_ENV}=must-not-enter-child");
        let prepared = PreparedProcess::prepare(
            &execution,
            &["/bin/sh".into(), "-lc".into(), "id".into()],
            "/workspace",
            &[secret.into(), daemon_auth],
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
    fn native_process_drops_daemon_auth_token_from_supplied_environment() {
        let prepared = PreparedProcess::prepare(
            &ProcessExecution::Native,
            &["/usr/bin/env".into()],
            "/",
            &[
                "VISIBLE=value".into(),
                format!("{DAEMON_AUTH_TOKEN_ENV}=must-not-enter-child"),
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
        });
        let error =
            PreparedProcess::prepare(&execution, &["/bin/sh".into()], "/", &[], false, 0, 0)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
