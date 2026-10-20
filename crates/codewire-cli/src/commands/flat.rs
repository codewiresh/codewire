//! The flat environment grammar: `cw ls`, `cw info`, `cw create`, `cw start`,
//! `cw stop`, `cw restart`, `cw rm`, `cw update`, `cw ports`, `cw logs` and the
//! advanced operations. Each route only selects its environment, session and
//! scope, then calls the handler the former `cw env` namespace used, so
//! permissions, protection, confirmations and cleanup stay with that handler.
//! The global `--local` / `--cloud` arrives as `Globals::placement`.

use super::*;

/// `cw env ...`: retired. Only the updater hand-off below is accepted.
#[derive(Debug, Args)]
pub(crate) struct RetiredEnvArgs {
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..,
        value_name = "ARGS"
    )]
    pub(crate) arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct HelpArgs {
    #[arg(
        long,
        conflicts_with = "command",
        help = "List every command, including administration commands"
    )]
    pub(crate) all: bool,
    #[arg(
        value_name = "COMMAND",
        help = "Command to describe, for example `stop` or `runtime update`"
    )]
    pub(crate) command: Vec<String>,
}

/// The environment operation a flat command names one-to-one. `ls`, `stop`,
/// `restart`, `logs`, `update` and `ports` first select their scope, so
/// they, like every other command, come back unchanged.
pub(crate) fn direct_environment_command(
    command: crate::Command,
) -> Result<EnvCommand, Box<crate::Command>> {
    use crate::Command;
    Ok(match command {
        Command::Info(args) => EnvCommand::Info(args),
        Command::Create(args) => EnvCommand::Create(args),
        Command::Start(args) => EnvCommand::Start(args),
        Command::Rm(args) => EnvCommand::Rm(args),
        Command::Cp(args) => EnvCommand::Cp(args),
        Command::Runtime(args) => EnvCommand::Runtime(args),
        Command::Agent(args) => EnvCommand::Agent(args),
        Command::Daemon(args) => EnvCommand::Daemon(args),
        Command::Resize(args) => EnvCommand::Resize(args),
        Command::Report(args) => EnvCommand::Report(args),
        Command::Extend(args) => EnvCommand::Extend(args),
        Command::Access(args) => EnvCommand::Access(args),
        Command::Share(args) => EnvCommand::Share(args),
        Command::Protect(args) => EnvCommand::Protect(args),
        Command::Unprotect(args) => EnvCommand::Unprotect(args),
        Command::CancelDelete(args) => EnvCommand::CancelDelete(args),
        Command::Prune(args) => EnvCommand::Prune(args),
        Command::Nuke(args) => EnvCommand::Nuke(args),
        Command::RefreshSkills(args) => EnvCommand::RefreshSkills(args),
        other => return Err(Box::new(other)),
    })
}

/// Run one environment operation with the global placement.
pub(crate) async fn operation(globals: &Globals, command: EnvCommand) -> anyhow::Result<()> {
    handle_env_command(globals, globals.placement, command).await
}

/// The environment named by the positional ENV or `--in ENV`, which mean the
/// same thing; both is an error. A second positional once named a session
/// and is refused with the `--session` spelling before any lookup.
pub(crate) fn select_environment(
    command: &str,
    positional: Option<String>,
    flag: Option<String>,
    retired_session: &[String],
) -> anyhow::Result<Option<String>> {
    if let Some(session) = retired_session.first() {
        let environment = positional.as_deref().unwrap_or("ENV");
        anyhow::bail!(
            "`cw {command} ENV SESSION` no longer selects a session; use `cw {command} {environment} --session {session}`"
        );
    }
    match (positional, flag) {
        (Some(_), Some(_)) => anyhow::bail!(
            "name the environment once: `cw {command} ENV` or `cw {command} --in ENV`, not both"
        ),
        (positional, flag) => Ok(positional.or(flag)),
    }
}

fn missing_environment(command: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "missing environment: `cw {command} ENV` acts on a whole environment; `cw {command} --session SESSION` acts on one session in the selected environment"
    )
}

/// Session-only flags never widen to a whole environment.
fn ensure_whole_environment(
    globals: &Globals,
    command: &str,
    scope: &SessionScopeArgs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        globals.member.is_none(),
        "with --member, `cw {command}` needs --session SESSION; a member never controls a whole environment"
    );
    anyhow::ensure!(
        scope.request_id.is_none()
            && scope.expected_launch_generation.is_none()
            && scope.cleanup_request_id.is_none(),
        "--request-id, --expected-launch-generation and --cleanup-request-id apply to one --session"
    );
    Ok(())
}

/// The selectors the session handlers already understand: SESSION, or ENV
/// SESSION, built here from explicit flags so no value is reinterpreted.
fn session_target(
    environment: Option<String>,
    session: String,
    scope: SessionScopeArgs,
) -> SessionTargetArgs {
    SessionTargetArgs {
        request_id: scope.request_id,
        expected_launch_generation: scope.expected_launch_generation,
        cleanup_request_id: scope.cleanup_request_id,
        target: environment.into_iter().chain([session]).collect(),
        output: scope.output,
    }
}

/// `cw stop ENV` stops the environment (today's takedown); `--session`
/// stops one session (today's cancellation). Never one through the other.
pub(crate) async fn handle_stop(globals: &Globals, args: StopArgs) -> anyhow::Result<()> {
    let StopArgs { mut scope, all } = args;
    let environment = select_environment(
        "stop",
        scope.environment.take(),
        scope.in_environment.take(),
        &scope.retired_session,
    )?;
    let Some(session) = scope.session.take() else {
        anyhow::ensure!(
            !all,
            "--all stops a session's running descendants; add --session SESSION"
        );
        ensure_whole_environment(globals, "stop", &scope)?;
        let environment = environment.ok_or_else(|| missing_environment("stop"))?;
        return operation(
            globals,
            EnvCommand::Stop(EnvTargetArgs {
                environment,
                output: scope.output,
            }),
        )
        .await;
    };
    handle_stop_command(globals, session_target(environment, session, scope), all).await
}

/// `cw restart ENV` restarts a local environment; `--session` restarts one
/// retained session. Cloud environment restart stays unsupported.
pub(crate) async fn handle_restart(
    globals: &Globals,
    mut scope: SessionScopeArgs,
) -> anyhow::Result<()> {
    let environment = select_environment(
        "restart",
        scope.environment.take(),
        scope.in_environment.take(),
        &scope.retired_session,
    )?;
    let Some(session) = scope.session.take() else {
        ensure_whole_environment(globals, "restart", &scope)?;
        let environment = environment.ok_or_else(|| missing_environment("restart"))?;
        return operation(
            globals,
            EnvCommand::Restart(EnvTargetArgs {
                environment,
                output: scope.output,
            }),
        )
        .await;
    };
    handle_restart_command(globals, session_target(environment, session, scope)).await
}

/// `cw logs [ENV] --session S` shows session output; `--setup` shows a cloud
/// environment's setup logs. The source is always explicit for scripts.
pub(crate) async fn handle_logs(globals: &Globals, args: LogsArgs) -> anyhow::Result<()> {
    let LogsArgs {
        environment,
        retired_session,
        in_environment,
        session,
        setup,
        follow,
        tail,
        raw,
    } = args;
    let environment = select_environment("logs", environment, in_environment, &retired_session)?;
    if !setup {
        return handle_logs_command(
            globals,
            SessionLogs {
                environment,
                session,
                follow,
                tail,
                raw,
            },
        )
        .await;
    }
    anyhow::ensure!(
        globals.member.is_none(),
        "--setup is not available with --member; name the --session"
    );
    anyhow::ensure!(
        tail.is_none() && !raw,
        "--tail and --raw apply to session output, not to --setup logs"
    );
    anyhow::ensure!(
        globals.placement != Some(EnvironmentPlacement::Local),
        "setup logs are kept for cloud environments; a local environment shows its setup as `cw start` or `cw create` runs"
    );
    let environment = match environment {
        Some(environment) => environment,
        None => current_cloud_environment().ok_or_else(|| {
            anyhow::anyhow!(
                "missing environment: `cw logs ENV --setup` shows that environment's setup logs"
            )
        })?,
    };
    // Without a placement, a local VM's name is answered as local rather
    // than looked up, and missed, in the cloud.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if globals.placement.is_none() && native_environment(&environment).await?.is_some() {
        anyhow::bail!(
            "{environment} is a local VM, whose setup shows as `cw start` or `cw create` runs; setup logs are kept for cloud environments (`cw --cloud logs {environment} --setup`)"
        );
    }
    operation(
        globals,
        EnvCommand::Logs(EnvLogsArgs {
            environment,
            follow,
        }),
    )
    .await
}

/// The selected environment when it is a cloud environment.
fn current_cloud_environment() -> Option<String> {
    let paths = ResolvePaths::from_env(&OsEnv).ok()?;
    let target = config::current_target(&paths.mesh_data_dir).ok()?;
    (target.kind == "env")
        .then(|| trimmed_str(&target.target_ref).map(str::to_owned))
        .flatten()
}

/// `cw ls` lists environments; `cw ls ENV` lists that environment's sessions.
pub(crate) async fn handle_ls(globals: &Globals, args: ListArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::terminal::list(globals, args).await;
    }
    let Some(environment) = args.environment else {
        return handle_environment_inventory(
            globals,
            globals.placement,
            EnvListArgs {
                environment_type: args.environment_type,
                state: args.state,
                all: args.all,
                output: args.output,
            },
        )
        .await;
    };
    anyhow::ensure!(
        args.environment_type.is_none() && args.state.is_none() && !args.all,
        "--type, --state and --all filter the environment inventory; run `cw ls` without ENV to use them"
    );
    handle_environment_sessions_list(globals, &environment, args.output).await
}

/// `cw update ENV` changes an environment; the CLI updater is `cw upgrade`.
pub(crate) async fn handle_update(
    globals: &Globals,
    args: UpdateEnvironmentArgs,
) -> anyhow::Result<()> {
    operation(globals, EnvCommand::Update(update_operation(args)?)).await
}

/// The environment update `cw update` names, refused before any effect when
/// it carries a CLI-updater flag or no environment.
pub(crate) fn update_operation(args: UpdateEnvironmentArgs) -> anyhow::Result<EnvUpdateArgs> {
    let updater = args.upgrade_flags.names();
    anyhow::ensure!(
        updater.is_empty(),
        "`cw update ENV` changes an environment and takes no {}; `cw upgrade` upgrades the CLI and restarts local VMs (see `cw upgrade --help`)",
        updater.join(", ")
    );
    let environment = select_environment("update", args.environment, args.in_environment, &[])?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing environment: `cw update ENV` changes an environment's secrets and credential profile; `cw upgrade` upgrades the CLI"
            )
        })?;
    let mut update = args.update;
    update.environment = environment;
    Ok(update)
}

/// A parsed flat environment command as the router dispatches it: its
/// `--local` and `--cloud` flags and its operation.
#[cfg(test)]
pub(crate) fn env_operation(cli: crate::Cli) -> (bool, bool, EnvCommand) {
    let (local, platform) = (cli.local, cli.cloud);
    let operation = match cli.command {
        crate::Command::Update(args) => EnvCommand::Update(update_operation(args).unwrap()),
        command => direct_environment_command(command)
            .unwrap_or_else(|command| panic!("not an environment operation: {command:?}")),
    };
    (local, platform, operation)
}

/// `cw ports [ENV]` lists; `--publish` or `--unpublish` changes one mapping.
pub(crate) async fn handle_ports(globals: &Globals, args: PortsArgs) -> anyhow::Result<()> {
    let environment = select_environment("ports", args.environment, args.in_environment, &[])?;
    let port_operation = match (args.publish, args.unpublish) {
        (Some(port), None) => PortOperation::Publish {
            port,
            host_port: args.host_port,
            label: args.label,
            access: args.access,
        },
        (None, Some(port)) => {
            anyhow::ensure!(
                args.access.is_none(),
                "--access applies to --publish; an unpublished port has no access level"
            );
            PortOperation::Unpublish {
                port,
                host_port: args.host_port,
                label: args.label,
            }
        }
        (None, None) => {
            anyhow::ensure!(
                args.host_port.is_none() && args.label.is_none() && args.access.is_none(),
                "--host-port, --label and --access apply to --publish PORT or --unpublish PORT"
            );
            PortOperation::List
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("publish or unpublish one port per call")
        }
    };
    operation(
        globals,
        EnvCommand::Port(EnvPortTarget {
            environment,
            operation: port_operation,
            output: args.output,
        }),
    )
    .await
}

/// Help for `cw help`, `cw help --all` and `cw help COMMAND...`, all
/// rendered from the one parser.
pub(crate) fn handle_help(args: HelpArgs) -> anyhow::Result<()> {
    if args.command.is_empty() {
        crate::cli_command_with(args.all).print_help()?;
        return Ok(());
    }
    let command = crate::cli_command();
    let visible = command
        .get_subcommands()
        .any(|candidate| !candidate.is_hide_set() && candidate.get_name() == args.command[0]);
    anyhow::ensure!(
        visible,
        "no command `cw {}`; `cw help --all` lists every command",
        args.command[0]
    );
    let argv = std::iter::once("cw".to_owned())
        .chain(args.command.iter().cloned())
        .chain(["--help".to_owned()]);
    match command.try_get_matches_from(argv) {
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            error.print()?;
            Ok(())
        }
        Err(error) => Err(anyhow::anyhow!(
            "no command `cw {}`: {}",
            args.command.join(" "),
            error.kind()
        )),
        Ok(_) => anyhow::bail!("no help for `cw {}`", args.command.join(" ")),
    }
}

/// The exact command line a `cw upgrade` (and every earlier updater since
/// #2870) runs with the version it selected, to let that version restart
/// the local VMs still on the previous cw: first `--help` as a probe (exit
/// 0 means supported), then `--after-update [--yes]`. Kept as the hand-off
/// protocol in both directions, so an older retained cw that a rollback
/// selects still receives the argv it knows.
///
/// Retire this once every installation older than the release that removed
/// `cw env` has been replaced; nothing else of the former namespace remains.
const UPDATER_HANDOFF_PROBE: &[&str] = &["env", "--local", "upgrade", "--help"];
const UPDATER_HANDOFF: &[&str] = &["env", "--local", "upgrade", "--after-update"];
const UPDATER_HANDOFF_YES: &[&str] = &["env", "--local", "upgrade", "--after-update", "--yes"];

/// What the hidden `env` route does with its exact command line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetiredEnvRoute {
    HandoffProbe,
    Handoff { yes: bool },
    Refused(String),
}

pub(crate) fn retired_env_route(
    raw: &[std::ffi::OsString],
    placement: Option<EnvironmentPlacement>,
    arguments: &[String],
) -> RetiredEnvRoute {
    let tail: Option<Vec<&str>> = raw.iter().skip(1).map(|value| value.to_str()).collect();
    match tail.as_deref() {
        Some(tail) if tail == UPDATER_HANDOFF_PROBE => RetiredEnvRoute::HandoffProbe,
        Some(tail) if tail == UPDATER_HANDOFF => RetiredEnvRoute::Handoff { yes: false },
        Some(tail) if tail == UPDATER_HANDOFF_YES => RetiredEnvRoute::Handoff { yes: true },
        _ => RetiredEnvRoute::Refused(format!(
            "`cw env` was removed; use {}",
            retired_env_replacement(placement, arguments)
        )),
    }
}

pub(crate) async fn handle_retired_env(
    raw: &[std::ffi::OsString],
    placement: Option<EnvironmentPlacement>,
    args: RetiredEnvArgs,
) -> anyhow::Result<()> {
    match retired_env_route(raw, placement, &args.arguments) {
        RetiredEnvRoute::HandoffProbe => {
            println!(
                "Internal updater hand-off: restart local VMs still on a previous cw.\nUse `cw upgrade --vms`."
            );
            Ok(())
        }
        RetiredEnvRoute::Handoff { yes } => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                upgrade_native_environments(yes, true).await
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = yes;
                anyhow::bail!("local VMs are not available on this platform")
            }
        }
        RetiredEnvRoute::Refused(message) => anyhow::bail!(message),
    }
}

/// The flat spelling of a retired `cw env` command line.
pub(crate) fn retired_env_replacement(
    placement: Option<EnvironmentPlacement>,
    arguments: &[String],
) -> String {
    let prefix = match placement {
        Some(EnvironmentPlacement::Local) => "cw --local",
        Some(EnvironmentPlacement::Platform) => "cw --cloud",
        None => "cw",
    };
    let Some((command, rest)) = arguments.split_first() else {
        return "the top-level environment commands (`cw help`)".to_owned();
    };
    let quoted = |values: &[String]| {
        values
            .iter()
            .map(|value| {
                if value.is_empty() || value.contains(char::is_whitespace) {
                    format!("{value:?}")
                } else {
                    value.clone()
                }
            })
            .map(|value| format!(" {value}"))
            .collect::<String>()
    };
    let flat = match command.as_str() {
        "list" | "ls" => format!("{prefix} ls{}", quoted(rest)),
        "upgrade" => "cw upgrade --vms".to_owned(),
        "logs" => format!("{prefix} logs{} --setup", quoted(rest)),
        "port" => retired_port_replacement(prefix, rest),
        "agent" | "runtime" | "create" | "info" | "update" | "resize" | "report" | "stop"
        | "start" | "restart" | "refresh-skills" | "rm" | "prune" | "nuke" | "cp" | "protect"
        | "unprotect" | "cancel-delete" | "extend" | "access" | "share" | "daemon" => {
            format!("{prefix} {command}{}", quoted(rest))
        }
        _ => return "the top-level environment commands (`cw help --all`)".to_owned(),
    };
    format!("`{flat}`")
}

fn retired_port_replacement(prefix: &str, rest: &[String]) -> String {
    let mut environment = "ENV".to_owned();
    let mut values = Vec::new();
    let mut iter = rest.iter().skip(1);
    while let Some(value) = iter.next() {
        match value.as_str() {
            "-e" | "--env" => {
                if let Some(name) = iter.next() {
                    environment = name.clone();
                }
            }
            flag if flag.starts_with("--env=") => environment = flag["--env=".len()..].to_owned(),
            _ => values.push(value.clone()),
        }
    }
    let port = values
        .iter()
        .find(|value| !value.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "PORT".to_owned());
    match rest.first().map(String::as_str) {
        Some("add") => format!("{prefix} ports {environment} --publish {port}"),
        Some("rm") => format!("{prefix} ports {environment} --unpublish {port}"),
        _ => format!("{prefix} ports {environment}"),
    }
}
