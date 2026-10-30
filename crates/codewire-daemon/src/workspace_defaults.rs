//! The saved project defaults and Git author a bound daemon writes on every
//! bind, before it records its host key (#3684). The saved configuration is
//! the single source of truth: `~/.codewire/environment.json` is not a file to
//! edit by hand, and a workspace edit to it does not survive the next bind.
//!
//! The outcome is the `workspace_defaults` health diagnostic. Setup skips its
//! own write only when that diagnostic is healthy for the binding's
//! generation, so any failure here falls back to setup's exec, with that
//! exec's errors and warnings. A diagnostic names the step that failed, never
//! a key or a value.

use std::collections::BTreeMap;
use std::fmt;
use std::process::Stdio;
use std::time::Duration;

use codewire_daemon_proto::WORKSPACE_DEFAULTS_DIAGNOSTIC;
use codewire_daemon_proto::daemon::v1;

use crate::Config;
use crate::private_files::{ensure_private_directory, write_atomically};

/// How long the Git author may take. The daemon has not recorded its host key
/// yet, so a stuck `git` must not hold access back.
const GIT_AUTHOR_TIMEOUT: Duration = Duration::from_secs(10);

/// What the binding carries for the daemon to write.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceDefaults {
    pub environment: BTreeMap<String, String>,
    pub git: Option<GitAuthor>,
}

/// The creator's Git author.
#[derive(Clone, PartialEq, Eq)]
pub struct GitAuthor {
    pub email: String,
    pub name: String,
}

impl fmt::Debug for WorkspaceDefaults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the project's values nor the creator's identity.
        formatter
            .debug_struct("WorkspaceDefaults")
            .finish_non_exhaustive()
    }
}

/// [`apply`]'s result, for the daemon's health report.
#[derive(Clone, Debug, PartialEq)]
pub struct DefaultsOutcome(pub(crate) v1::HealthDiagnostic);

/// Writes `defaults` and reports how that went for `generation`, the
/// binding's operation generation.
pub async fn apply(
    config: &Config,
    generation: u64,
    defaults: &WorkspaceDefaults,
) -> DefaultsOutcome {
    apply_in(config, generation, defaults, std::env::vars()).await
}

/// [`apply`] over an explicit daemon environment instead of this process's
/// own, as [`crate::env::build_process_env_in`]: a test passes a synthetic one,
/// so `git config --global` can never reach the real home it runs in.
async fn apply_in(
    config: &Config,
    generation: u64,
    defaults: &WorkspaceDefaults,
    daemon_environment: impl IntoIterator<Item = (String, String)>,
) -> DefaultsOutcome {
    let failed = |step: &str| {
        DefaultsOutcome(v1::HealthDiagnostic {
            name: WORKSPACE_DEFAULTS_DIAGNOSTIC.to_owned(),
            healthy: false,
            message: format!("{step} failed"),
        })
    };
    if let Err(error) = write_environment(config, &defaults.environment) {
        tracing::warn!(kind = ?error.kind(), "workspace defaults: could not write the project defaults");
        return failed("project defaults");
    }
    if let Some(git) = &defaults.git
        && let Err(error) =
            set_git_author(config, &defaults.environment, git, daemon_environment).await
    {
        tracing::warn!(
            reason = error,
            "workspace defaults: could not set the Git author"
        );
        return failed("Git author");
    }
    DefaultsOutcome(v1::HealthDiagnostic {
        name: WORKSPACE_DEFAULTS_DIAGNOSTIC.to_owned(),
        healthy: true,
        message: codewire_daemon_proto::workspace_defaults_message(generation),
    })
}

/// `~/.codewire/environment.json`, as `load_persisted_environment` reads it:
/// the same bytes setup's script writes, owner-only.
fn write_environment(
    config: &Config,
    environment: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let directory = config.home_root.join(".codewire");
    ensure_private_directory(&directory, 0o700)?;
    let mut contents = serde_json::to_string_pretty(environment)?;
    contents.push('\n');
    write_atomically(
        &directory.join("environment.json"),
        contents.as_bytes(),
        0o600,
    )
}

/// `git config --global` in the environment a launched session gets, with the
/// project's values as explicit overrides, as setup's exec launches it: a
/// project's `HOME`, `GIT_CONFIG_GLOBAL` or `XDG_CONFIG_HOME` is honoured.
async fn set_git_author(
    config: &Config,
    environment: &BTreeMap<String, String>,
    git: &GitAuthor,
    daemon_environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(), &'static str> {
    let extra: Vec<String> = environment
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    let process = crate::env::build_process_env_in(config, &extra, "", daemon_environment)
        .map_err(|_| "no session environment")?;
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            r#"git config --global user.email "$1" && git config --global user.name "$2""#,
            "codewire-git-identity",
            &git.email,
            &git.name,
        ])
        .env_clear()
        .envs(
            process
                .entries
                .iter()
                .filter_map(|entry| entry.split_once('=')),
        )
        .current_dir(&config.home_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(GIT_AUTHOR_TIMEOUT, command.status())
        .await
        .map_err(|_| "timed out")?
        .map_err(|_| "could not start")?;
    if status.success() {
        Ok(())
    } else {
        Err("git refused")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    fn config(home_root: std::path::PathBuf) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".into(),
            workspace_root: home_root.clone(),
            home_root,
            auth_token: crate::DaemonAuthToken::new("daemon-defaults-test-token").unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        }
    }

    fn defaults(git: Option<GitAuthor>) -> WorkspaceDefaults {
        WorkspaceDefaults {
            environment: BTreeMap::from([
                ("APP_MODE".to_owned(), "synthetic".to_owned()),
                ("B".to_owned(), "two".to_owned()),
            ]),
            git,
        }
    }

    fn author() -> GitAuthor {
        GitAuthor {
            email: "dev@example.invalid".to_owned(),
            name: "Synthetic Dev".to_owned(),
        }
    }

    /// [`apply_in`] with a synthetic daemon environment whose `HOME` is the
    /// test's own directory, never the home the test runs in.
    async fn apply_at(
        config: &Config,
        generation: u64,
        defaults: &WorkspaceDefaults,
    ) -> v1::HealthDiagnostic {
        let environment = [
            ("HOME".to_owned(), config.home_root.display().to_string()),
            (
                "PATH".to_owned(),
                std::env::var("PATH").expect("the test has a PATH"),
            ),
        ];
        apply_in(config, generation, defaults, environment).await.0
    }

    fn git_value(home: &std::path::Path, key: &str) -> String {
        let output = std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(home.join(".gitconfig"))
            .arg(key)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[tokio::test]
    async fn the_project_defaults_and_git_author_are_written_as_setup_writes_them() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let config = config(home.clone());
        let outcome = apply_at(&config, 7, &defaults(Some(author()))).await;
        assert!(outcome.healthy, "{outcome:?}");
        assert_eq!(outcome.name, WORKSPACE_DEFAULTS_DIAGNOSTIC);
        assert_eq!(
            codewire_daemon_proto::workspace_defaults_generation(&outcome.message),
            Some(7)
        );
        // The script's bytes: pretty JSON and the heredoc's newline.
        let path = home.join(".codewire/environment.json");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\n  \"APP_MODE\": \"synthetic\",\n  \"B\": \"two\"\n}\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(home.join(".codewire"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // The daemon's own reader sees them.
        assert_eq!(
            crate::env::load_persisted_environment(&config),
            ["APP_MODE=synthetic", "B=two"]
        );
        assert_eq!(git_value(&home, "user.email"), "dev@example.invalid");
        assert_eq!(git_value(&home, "user.name"), "Synthetic Dev");
    }

    /// The owner's rule: the saved configuration wins on every bind.
    #[tokio::test]
    async fn a_workspace_edit_does_not_survive_the_next_bind() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let config = config(home.clone());
        fs::create_dir_all(home.join(".codewire")).unwrap();
        let path = home.join(".codewire/environment.json");
        fs::write(&path, "{\"EDITED\":\"by hand\"}").unwrap();
        assert!(apply_at(&config, 8, &defaults(None)).await.healthy);
        assert_eq!(
            crate::env::load_persisted_environment(&config),
            ["APP_MODE=synthetic", "B=two"]
        );
    }

    /// An empty map is still written, as the script writes `{}`; no resolved
    /// author leaves Git alone and is still healthy, as setup only warns.
    #[tokio::test]
    async fn an_empty_project_writes_its_empty_defaults_and_no_author_is_healthy() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let outcome = apply_at(
            &config(home.clone()),
            9,
            &WorkspaceDefaults {
                environment: BTreeMap::new(),
                git: None,
            },
        )
        .await;
        assert!(outcome.healthy);
        assert_eq!(
            fs::read_to_string(home.join(".codewire/environment.json")).unwrap(),
            "{}\n"
        );
        assert!(!home.join(".gitconfig").exists());
    }

    /// A project's `GIT_CONFIG_GLOBAL` is honoured, as in a launched session.
    #[tokio::test]
    async fn the_git_author_sees_the_projects_environment() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let elsewhere = home.join("elsewhere.gitconfig");
        let mut project = defaults(Some(author()));
        project.environment.insert(
            "GIT_CONFIG_GLOBAL".to_owned(),
            elsewhere.display().to_string(),
        );
        assert!(apply_at(&config(home.clone()), 7, &project).await.healthy);
        assert!(elsewhere.exists(), "the project's global config was used");
        assert!(!home.join(".gitconfig").exists());
    }

    /// A failed write reports the step and no value, and nothing is
    /// attempted after it.
    #[tokio::test]
    async fn a_failed_write_reports_the_step_and_never_a_value() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        // `.codewire` is a file, so the directory can't be made.
        fs::write(home.join(".codewire"), "not a directory").unwrap();
        let outcome = apply_at(&config(home.clone()), 7, &defaults(Some(author()))).await;
        assert!(!outcome.healthy);
        assert_eq!(outcome.message, "project defaults failed");
        assert_eq!(
            codewire_daemon_proto::workspace_defaults_generation(&outcome.message),
            None
        );
        assert!(!home.join(".gitconfig").exists());
    }

    /// A Git author that can't be set is unhealthy, so setup's exec decides.
    #[tokio::test]
    async fn a_failed_git_author_is_reported_by_step() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let mut project = defaults(Some(author()));
        // A path whose parent is missing makes `git config` refuse.
        project.environment.insert(
            "GIT_CONFIG_GLOBAL".to_owned(),
            home.join("missing/dir/gitconfig").display().to_string(),
        );
        let outcome = apply_at(&config(home), 7, &project).await;
        assert!(!outcome.healthy);
        assert_eq!(outcome.message, "Git author failed");
    }

    #[test]
    fn debug_never_shows_a_value() {
        let shown = format!("{:?}", defaults(Some(author())));
        for secret in ["synthetic", "dev@example", "Synthetic Dev", "APP_MODE"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
