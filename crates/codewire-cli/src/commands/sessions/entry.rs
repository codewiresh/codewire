//! The entries of `cw run` and `cw shell`, moved from the parent module with
//! no change in behaviour.

use super::*;

pub(crate) async fn handle_environment_run_command(
    globals: &Globals,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    let named = args.environment.clone();
    match crate::command_line::name_hint_after(launch_run(globals, args, None)).await {
        Err(error) => {
            Err(crate::commands::explain_not_running(globals, named.as_deref(), error).await)
        }
        done => done,
    }
}

pub(crate) async fn handle_environment_shell_command(
    globals: &Globals,
    args: EnvironmentShellArgs,
) -> anyhow::Result<()> {
    let environment = super::super::flat::select_environment(
        "shell",
        args.environment.clone(),
        args.in_environment.clone(),
        &[],
    )?;
    let named = environment.clone();
    match shell(globals, args, environment).await {
        Err(error) => {
            Err(crate::commands::explain_not_running(globals, named.as_deref(), error).await)
        }
        done => done,
    }
}

async fn shell(
    globals: &Globals,
    args: EnvironmentShellArgs,
    environment: Option<String>,
) -> anyhow::Result<()> {
    if args.stdio {
        // The OpenSSH ProxyCommand: a `cw-local-` alias, or any reference
        // under --local, is a local VM; everything else is the cloud.
        let alias = environment.as_deref().and_then(SshAlias::parse);
        if let Some(alias) = alias {
            alias.check_placement(globals.placement)?;
            if alias.is_local(globals.placement) {
                let environment = local_ssh_target(alias).await?;
                return super::super::native::native_pipe_ssh(&environment).await;
            }
        }
        if globals.placement == Some(EnvironmentPlacement::Local) {
            return super::super::native::native_shell_stdio(None).await;
        }
        return handle_shell_stdio(globals, environment.as_deref()).await;
    }
    if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
        super::super::core::init_tailnet_debug_log();
    }
    if !args.durable {
        // A plain shell everywhere: a hosted environment's over its tailnet,
        // a local VM's or trusted host's on its own path, each a session
        // that ends with the shell or 10 minutes after the last client left.
        let target = resolve_environment_session_target(globals, environment.as_deref()).await?;
        let status = if let EnvironmentSessionTarget::Platform {
            org_id,
            environment_id,
            client,
            ..
        } = &target
        {
            super::super::tailnet_shell::run(client, org_id, environment_id).await?
        } else {
            match plain_shell(globals, target).await? {
                Some(status) => status,
                None => return launch_durable_shell(globals, environment).await,
            }
        };
        if status != 0 {
            // As `ssh` does: the shell's own status, no message.
            std::process::exit(status);
        }
        return Ok(());
    }
    launch_durable_shell(globals, environment).await
}

/// A local VM lists its sessions only while it runs: say so, in the words
/// every session command uses, instead of the supervisor's state refusal.
pub(super) async fn stopped_environment_sessions(
    target: &EnvironmentSessionTarget,
) -> Option<anyhow::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let EnvironmentSessionTarget::NativeLocal { target, .. } = target {
        let environment = native_environment(&target.name).await.ok()??;
        // One in `error` says why, and what to do about that (#5359).
        let in_error = crate::commands::native::error_view::ErrorView::of(&environment).refusal();
        if in_error.is_some() {
            return in_error;
        }
        let name = crate::progress::terminal_text(&target.name);
        let state = refusal::local_state(environment.state);
        return refusal::state_error(crate::output::VmLocation::Local, &name, state, None);
    }
    let _ = target;
    None
}
