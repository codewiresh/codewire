use std::time::Duration;

use anyhow::Context;
use codewire_mesh::{Config, DATABASE_URL_ENV, prelaunch_retire_legacy_auth, serve};
use tracing_subscriber::EnvFilter;

const PRELAUNCH_RETIRE_LEGACY_AUTH_COMMAND: &str = "prelaunch-retire-legacy-auth";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessMode {
    Serve,
    PrelaunchRetireLegacyAuth,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match process_mode(&args)? {
        ProcessMode::Serve => {
            let config = Config::from_sources(&args, |key| std::env::var(key).ok())?;
            serve(config, shutdown_signal()).await
        }
        ProcessMode::PrelaunchRetireLegacyAuth => {
            let database_url = std::env::var(DATABASE_URL_ENV)
                .with_context(|| format!("{DATABASE_URL_ENV} is required"))?;
            let report = prelaunch_retire_legacy_auth(&database_url).await?;
            tracing::info!(
                outcome = ?report.outcome,
                sessions = report.counts.sessions,
                oauth_state = report.counts.oauth_state,
                oidc_sessions = report.counts.oidc_sessions,
                oidc_device_flows = report.counts.oidc_device_flows,
                oidc_users = report.counts.oidc_users,
                device_codes = report.counts.device_codes,
                github_app = report.counts.github_app,
                users = report.counts.users,
                node_tokens = report.counts.node_tokens,
                "Mesh legacy auth/session/device retirement completed"
            );
            Ok(())
        }
    }
}

fn process_mode(args: &[String]) -> anyhow::Result<ProcessMode> {
    if args
        .first()
        .is_some_and(|arg| arg == PRELAUNCH_RETIRE_LEGACY_AUTH_COMMAND)
    {
        anyhow::ensure!(
            args.len() == 1,
            "{PRELAUNCH_RETIRE_LEGACY_AUTH_COMMAND} accepts no arguments"
        );
        Ok(ProcessMode::PrelaunchRetireLegacyAuth)
    } else {
        Ok(ProcessMode::Serve)
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_server_mode_for_normal_flags() -> anyhow::Result<()> {
        assert_eq!(process_mode(&[])?, ProcessMode::Serve);
        assert_eq!(
            process_mode(&["--base-url=https://mesh.test".to_string()])?,
            ProcessMode::Serve
        );
        Ok(())
    }

    #[test]
    fn prelaunch_command_is_exact_and_argument_free() -> anyhow::Result<()> {
        assert_eq!(
            process_mode(&[PRELAUNCH_RETIRE_LEGACY_AUTH_COMMAND.to_string()])?,
            ProcessMode::PrelaunchRetireLegacyAuth
        );
        assert!(
            process_mode(&[
                PRELAUNCH_RETIRE_LEGACY_AUTH_COMMAND.to_string(),
                "unexpected".to_string(),
            ])
            .is_err()
        );
        Ok(())
    }
}
