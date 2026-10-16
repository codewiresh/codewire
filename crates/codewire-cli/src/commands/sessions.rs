use super::*;
use crate::terminal_attach::RawModeGuard;
use tokio::io::AsyncReadExt as _;
#[cfg(unix)]
pub(crate) mod agents;

#[cfg(target_os = "linux")]
pub(crate) async fn run_host_agent_control(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    agents::host_control::run_from(arguments).await
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct EnvironmentSessionView {
    pub(crate) session_id: String,
    pub(crate) name: String,
    pub(crate) parent_session_id: String,
    pub(crate) cleanup_unknown: bool,
    #[serde(skip)]
    pub(crate) started_at: String,
    pub(crate) launch_generation: u64,
    pub(crate) state: String,
    pub(crate) command: Vec<String>,
    pub(crate) working_dir: String,
    pub(crate) pty: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) output_end_offset: u64,
    pub(crate) output_start_offset: u64,
    pub(crate) status_message: String,
}

#[derive(Clone, Debug)]
struct EnvironmentSessionOutput {
    chunks: Vec<Vec<u8>>,
    next_offset: u64,
    history_gap: bool,
    eof: bool,
}

#[derive(Clone)]
enum EnvironmentSessionTarget {
    #[cfg(unix)]
    Host {
        target: config::CurrentTargetConfig,
        environment: HostEnvironment,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    NativeLocal {
        target: config::CurrentTargetConfig,
        environment_id: String,
        working_dir: String,
    },
    Platform {
        target: config::CurrentTargetConfig,
        org_id: String,
        environment_id: String,
        client: Box<codewire_client::CodewireClient>,
    },
}

impl EnvironmentSessionTarget {
    async fn stop(&self, session_id: &str) -> anyhow::Result<EnvironmentSessionView> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => Ok(host_environment_session_view(
                host_stop_client(environment)
                    .await?
                    .stop(session_id)
                    .await?,
            )),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => Ok(platform_environment_session_view(
                native_environment_session_client(environment_id)
                    .await?
                    .stop(session_id)
                    .await?,
            )),
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let response = client
                    .stop_session(codewire_client::StopSessionRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session_id.into(),
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                response
                    .session
                    .into_option()
                    .map(platform_environment_session_view)
                    .context("StopSession returned no session")
            }
        }
    }

    async fn send_input(&self, session_id: &str, data: Vec<u8>) -> anyhow::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => host_session_client(environment)
                .await?
                .send_input(session_id, data)
                .await
                .map_err(Into::into),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => {
                native_environment_session_client(environment_id)
                    .await?
                    .send_input(session_id, data)
                    .await
                    .map_err(Into::into)
            }
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                client
                    .send_session_input(codewire_client::SendSessionInputRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session_id.into(),
                        data,
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                Ok(())
            }
        }
    }
    fn ensure_ready_for_run(&self) -> anyhow::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Host { .. } => Ok(()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { .. } => Ok(()),
            Self::Platform { .. } => Ok(()),
        }
    }

    async fn list(&self) -> anyhow::Result<Vec<EnvironmentSessionView>> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => Ok(host_session_client(environment)
                .await?
                .list()
                .await?
                .into_iter()
                .map(host_environment_session_view)
                .collect()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => {
                Ok(native_environment_session_client(environment_id)
                    .await?
                    .list()
                    .await
                    .map_err(anyhow::Error::from)?
                    .into_iter()
                    .map(platform_environment_session_view)
                    .collect())
            }
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => Ok(client
                .list_sessions(codewire_client::ListSessionsRequest {
                    org_id: org_id.clone(),
                    environment_id: environment_id.clone(),
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?
                .sessions
                .into_iter()
                .map(platform_environment_session_view)
                .collect()),
        }
    }

    async fn read_output(
        &self,
        session_id: &str,
        offset: u64,
    ) -> anyhow::Result<EnvironmentSessionOutput> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => {
                let response = host_session_client(environment)
                    .await?
                    .read_output(
                        codewire_daemon_proto::daemon::v1::ReadSessionOutputRequest {
                            session_id: session_id.into(),
                            offset,
                            limit: 0,
                            allow_history_gap: true,
                        },
                    )
                    .await?;
                Ok(EnvironmentSessionOutput {
                    chunks: response.chunks.into_iter().map(|c| c.data).collect(),
                    next_offset: response.next_offset,
                    history_gap: response.history_gap,
                    eof: response.eof,
                })
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => {
                let response = native_environment_session_client(environment_id)
                    .await?
                    .read_output(session_id, offset, 0)
                    .await?;
                Ok(EnvironmentSessionOutput {
                    chunks: response
                        .chunks
                        .into_iter()
                        .map(|chunk| chunk.data)
                        .collect(),
                    next_offset: response.next_offset,
                    history_gap: response.history_gap,
                    eof: response.eof,
                })
            }
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let response = client
                    .read_session_output(codewire_client::ReadSessionOutputRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session_id.to_string(),
                        offset,
                        limit: 0,
                        allow_history_gap: true,
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                Ok(EnvironmentSessionOutput {
                    chunks: response
                        .chunks
                        .into_iter()
                        .map(|chunk| chunk.data)
                        .collect(),
                    next_offset: response.next_offset,
                    history_gap: response.history_gap,
                    eof: response.eof,
                })
            }
        }
    }

    async fn launch(
        &self,
        command: Vec<String>,
        working_dir: String,
        env: BTreeMap<String, String>,
        pty: bool,
        name: String,
        parent_session_id: String,
    ) -> anyhow::Result<EnvironmentSessionView> {
        let (columns, rows) = session_terminal_size(pty)?;
        let term = env::var("TERM").unwrap_or_default();
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => {
                let session = host_session_client(environment)
                    .await?
                    .launch(codewire_daemon_proto::daemon::v1::LaunchSessionRequest {
                        command,
                        working_dir,
                        env: env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
                        pty,
                        term,
                        width: i32::from(columns),
                        height: i32::from(rows),
                        name,
                        parent_session_id: (!parent_session_id.is_empty())
                            .then_some(parent_session_id),
                    })
                    .await?;
                Ok(host_environment_session_view(session))
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => {
                let session = native_environment_session_client(environment_id)
                    .await?
                    .launch(codewire_client::LaunchSessionRequest {
                        command,
                        working_dir,
                        env: env.into_iter().collect(),
                        pty,
                        term,
                        columns: u32::from(columns),
                        rows: u32::from(rows),
                        name,
                        parent_session_id: (!parent_session_id.is_empty())
                            .then_some(parent_session_id),
                        ..Default::default()
                    })
                    .await?;
                Ok(platform_environment_session_view(session))
            }
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let response = client
                    .launch_session(codewire_client::LaunchSessionRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        command,
                        working_dir,
                        env: env.into_iter().collect(),
                        pty,
                        term,
                        columns: u32::from(columns),
                        rows: u32::from(rows),
                        name,
                        parent_session_id: (!parent_session_id.is_empty())
                            .then_some(parent_session_id),
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                response
                    .session
                    .into_option()
                    .map(platform_environment_session_view)
                    .ok_or_else(|| anyhow::anyhow!("LaunchSession returned no session"))
            }
        }
    }

    async fn get(&self, session_id: &str) -> anyhow::Result<EnvironmentSessionView> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => Ok(host_environment_session_view(
                host_session_client(environment)
                    .await?
                    .get(session_id)
                    .await?,
            )),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => Ok(platform_environment_session_view(
                native_environment_session_client(environment_id)
                    .await?
                    .get(session_id)
                    .await?,
            )),
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let response = client
                    .get_session(codewire_client::GetSessionRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session_id.to_string(),
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                response
                    .session
                    .into_option()
                    .map(platform_environment_session_view)
                    .ok_or_else(|| anyhow::anyhow!("GetSession returned no session"))
            }
        }
    }

    async fn restart(&self, session_id: &str) -> anyhow::Result<EnvironmentSessionView> {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => Ok(host_environment_session_view(
                host_stop_client(environment)
                    .await?
                    .restart(session_id)
                    .await?,
            )),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { environment_id, .. } => Ok(platform_environment_session_view(
                native_environment_session_client(environment_id)
                    .await?
                    .restart(session_id)
                    .await?,
            )),
            Self::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let response = client
                    .restart_session(codewire_client::RestartSessionRequest {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session_id.to_string(),
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                response
                    .session
                    .into_option()
                    .map(platform_environment_session_view)
                    .ok_or_else(|| anyhow::anyhow!("RestartSession returned no session"))
            }
        }
    }

    fn current_target(&self) -> &config::CurrentTargetConfig {
        match self {
            #[cfg(unix)]
            Self::Host { target, .. } => target,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { target, .. } => target,
            Self::Platform { target, .. } => target,
        }
    }

    fn default_working_dir(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Host { environment, .. } => environment.path.to_string_lossy().into_owned(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::NativeLocal { working_dir, .. } => working_dir.clone(),
            // Empty: the hosted daemon starts the session in the environment's
            // declared working directory.
            Self::Platform { .. } => String::new(),
        }
    }
}

async fn resolve_environment_session_target(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<EnvironmentSessionTarget> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    #[cfg(unix)]
    if let Some(requested) = environment.and_then(trimmed_str) {
        if let Some(environment) = resolve_host_reference(globals, requested, None).await? {
            return Ok(EnvironmentSessionTarget::Host {
                target: environment.current_target(),
                environment,
            });
        }
    } else if let Some(environment) = selected_host_environment()? {
        return Ok(EnvironmentSessionTarget::Host {
            target: environment.current_target(),
            environment,
        });
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(requested) = environment.and_then(trimmed_str)
        && let Ok(target) = config::current_target(&paths.mesh_data_dir)
        && target.kind == "local"
        && target.target_ref != "local"
        && let Some(environment) = native_environment(&target.target_ref).await?
        && native_session_request_matches(&environment, requested)
    {
        return Ok(native_session_target(environment));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if environment.and_then(trimmed_str).is_none() {
        if let Ok(target) = config::current_target(&paths.mesh_data_dir)
            && !(target.kind == "local" && target.target_ref == "local")
        {
            if target.kind != "local" {
                return environment_session_target_from_current(globals, &paths, &env, target)
                    .await;
            }
            if let Some(environment) = native_environment(&target.target_ref).await? {
                return Ok(native_session_target(environment));
            }
        }
        if let Some(environment) = native_selected_environment().await? {
            return Ok(native_session_target(environment));
        }
    }
    let target = match environment.and_then(trimmed_str) {
        Some(environment) => {
            resolve_named_execution_target(globals, &paths, &env, environment, None).await?
        }
        None => config::current_target(&paths.mesh_data_dir)?,
    };
    environment_session_target_from_current(globals, &paths, &env, target).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn native_session_request_matches(
    environment: &codewire_local_vmm::control::v1::Environment,
    requested: &str,
) -> bool {
    if uuid::Uuid::parse_str(requested).is_ok() {
        environment.id == requested
    } else {
        environment.name == requested || environment.id == requested
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native_session_target(
    environment: codewire_local_vmm::control::v1::Environment,
) -> EnvironmentSessionTarget {
    let working_dir = native_environment_session_working_dir(&environment);
    let name = environment.name;
    let environment_id = environment.id;
    EnvironmentSessionTarget::NativeLocal {
        target: config::CurrentTargetConfig {
            kind: "local".to_string(),
            target_ref: name.clone(),
            name: name.clone(),
        },
        environment_id,
        working_dir,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn native_environment_session_working_dir(
    environment: &codewire_local_vmm::control::v1::Environment,
) -> String {
    trimmed_str(&environment.working_directory)
        .unwrap_or(LOCAL_WORKSPACE_PATH)
        .to_owned()
}

async fn environment_session_target_from_current(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    target: config::CurrentTargetConfig,
) -> anyhow::Result<EnvironmentSessionTarget> {
    match target.kind.as_str() {
        #[cfg(unix)]
        "host" => {
            let environment = host_environment(&target.target_ref)?
                .context("selected host environment no longer exists")?;
            Ok(EnvironmentSessionTarget::Host {
                target,
                environment,
            })
        }
        "local" => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let environment = native_environment(&target.target_ref)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no local environment selected; use `cw use --local ENV` or pass ENV"
                    )
                })?;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            return Ok(native_session_target(environment));
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            anyhow::bail!("native local environments currently require Linux or macOS")
        }
        "env" => {
            let platform = resolve_platform(globals, paths, env)?;
            let orgs = organization_client(&platform)?.list_orgs().await?;
            let environment_id = target.target_ref.clone();
            Ok(EnvironmentSessionTarget::Platform {
                target,
                org_id: current_org_id(&platform, &orgs)?,
                environment_id,
                client: Box::new(codewire_client(&platform)?),
            })
        }
        _ => anyhow::bail!(
            "no environment selected; use `cw use ENV` or pass ENV to the session command"
        ),
    }
}

fn platform_environment_session_view(
    session: codewire_client::EnvironmentSession,
) -> EnvironmentSessionView {
    EnvironmentSessionView {
        session_id: session.session_id,
        name: session.name,
        parent_session_id: session.parent_session_id.unwrap_or_default(),
        cleanup_unknown: session.cleanup_unknown,
        launch_generation: session.launch_generation,
        started_at: session
            .started_at
            .into_option()
            .map(|t| format!("{}:{}", t.seconds, t.nanos))
            .unwrap_or_default(),
        state: platform_environment_session_state_name(session.state.as_known()).to_string(),
        command: session.command,
        working_dir: session.working_dir,
        pty: session.pty,
        exit_code: session.exit_code,
        output_end_offset: session.output_end_offset,
        output_start_offset: session.output_start_offset,
        status_message: session.status_message,
    }
}

#[cfg(unix)]
pub(super) fn host_environment_session_view(
    session: codewire_daemon_proto::daemon::v1::SessionRecord,
) -> EnvironmentSessionView {
    use codewire_daemon_proto::daemon::v1::SessionLifecycleState as State;
    let state = match State::try_from(session.state).ok() {
        Some(State::Starting) => "Starting",
        Some(State::Running) => "Running",
        Some(State::Stopping) => "Stopping",
        Some(State::Stopped) => "Stopped",
        Some(State::Exited) => "Exited",
        Some(State::Failed) => "Failed",
        Some(State::Interrupted) => "Interrupted",
        _ => "Unknown",
    };
    EnvironmentSessionView {
        session_id: session.session_id,
        name: session.name,
        parent_session_id: session.parent_session_id.unwrap_or_default(),
        cleanup_unknown: session.cleanup_unknown,
        launch_generation: session.launch_generation,
        started_at: session
            .started_at
            .map(|t| format!("{}:{}", t.seconds, t.nanos))
            .unwrap_or_default(),
        state: state.into(),
        command: session.command,
        working_dir: session.working_dir,
        pty: session.pty,
        exit_code: session.exit_code,
        output_end_offset: session.output_end_offset,
        output_start_offset: session.output_start_offset,
        status_message: session.status_message,
    }
}

async fn resolve_parent_session(
    target: &EnvironmentSessionTarget,
    requested: Option<&str>,
) -> anyhow::Result<String> {
    let Some(requested) = requested else {
        return Ok(String::new());
    };
    match select_environment_session(target, Some(requested)).await? {
        SessionSelection::Select(parent) => Ok(parent.session_id),
        SessionSelection::Create => anyhow::bail!("parent session does not exist"),
    }
}

fn split_session_target(values: &[String]) -> anyhow::Result<(Option<&str>, &str)> {
    match values {
        [session] => Ok((None, session)),
        [environment, session] => Ok((Some(environment), session)),
        _ => anyhow::bail!("expected SESSION, or ENV SESSION"),
    }
}

async fn resolve_selected_session(
    globals: &Globals,
    values: &[String],
) -> anyhow::Result<(EnvironmentSessionTarget, EnvironmentSessionView)> {
    let (environment, requested) = split_session_target(values)?;
    let target = resolve_environment_session_target(globals, environment).await?;
    let session = match select_environment_session(&target, Some(requested)).await? {
        SessionSelection::Select(session) => *session,
        SessionSelection::Create => anyhow::bail!("session does not exist"),
    };
    Ok((target, session))
}

fn managed_session(session: &EnvironmentSessionView) -> bool {
    #[cfg(unix)]
    return agents::is_managed_session(session);
    #[cfg(not(unix))]
    session.command.iter().any(|arg| arg == "_agent-driver")
}

pub(crate) async fn handle_send_command(globals: &Globals, args: SendArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::terminal::send(globals, args).await;
    }
    anyhow::ensure!(
        args.request_id.is_none() && args.expected_launch_generation.is_none(),
        "member mutation flags require --member"
    );
    let (values, data) = if let Some(key) = args.key.as_deref() {
        let data = match key {
            "ctrl-c" => vec![3],
            "ctrl-d" => vec![4],
            "enter" => vec![b'\r'],
            "escape" => vec![27],
            "tab" => vec![b'\t'],
            _ => anyhow::bail!("unsupported terminal key"),
        };
        (args.target_and_text, data)
    } else {
        let mut values = args.target_and_text;
        if !(2..=3).contains(&values.len()) {
            anyhow::bail!("expected SESSION TEXT, or ENV SESSION TEXT");
        }
        let mut data = values.pop().expect("validated text argument").into_bytes();
        if !args.no_newline {
            data.push(b'\n');
        }
        (values, data)
    };
    if data.is_empty() || data.len() > 64 * 1024 {
        anyhow::bail!("session input must contain 1–65536 bytes");
    }
    let (target, session) = resolve_selected_session(globals, &values).await?;
    if managed_session(&session) {
        anyhow::bail!("managed agents receive tasks through cw msg or cw steer");
    }
    if args.key.is_some() && !session.pty {
        anyhow::bail!("--key requires a PTY session; it is a terminal control byte");
    }
    target
        .send_input(&session.session_id, data)
        .await
        .context("input delivery was not confirmed; do not automatically resend")?;
    println!("Input written to {}", session.session_id);
    Ok(())
}

pub(crate) async fn handle_stop_command(globals: &Globals, args: StopArgs) -> anyhow::Result<()> {
    let StopArgs { session: args, all } = args;
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        anyhow::ensure!(!all, "--all is not supported with --member");
        anyhow::ensure!(
            args.cleanup_request_id.is_none(),
            "--cleanup-request-id requires a managed platform Stop"
        );
        return super::member_control::managed::stop(globals, args).await;
    }
    let (target, session) = resolve_selected_session(globals, &args.target).await?;
    let platform_managed =
        matches!(target, EnvironmentSessionTarget::Platform { .. }) && managed_session(&session);
    anyhow::ensure!(
        platform_managed
            || (args.request_id.is_none()
                && args.expected_launch_generation.is_none()
                && args.cleanup_request_id.is_none()),
        "request and generation flags require --member or a managed platform session"
    );
    let (parent, confirmed) = stop_one(&target, &session, Some(&args)).await?;
    let mut stopped = vec![parent];
    let mut unconfirmed = (!confirmed).then(|| stopped[0].status_message.clone());
    // A parent owns its descendants. With --all, or when asked at a terminal,
    // stop every one still running, level by level.
    let mut owners = std::collections::BTreeSet::from([session.session_id.clone()]);
    let mut failure = None;
    let children = running_children(&target.list().await?, &owners);
    let environment = (args.target.len() == 2).then(|| args.target[0].as_str());
    let stop_children = children.is_empty() || all || confirm_stop_children(&children)?;
    if !stop_children {
        print_environment_sessions(&stopped, args.output)?;
        for line in running_children_hints(&children, &session, environment) {
            eprintln!("{line}");
        }
    } else {
        let mut children = children;
        while !children.is_empty() {
            for child in children {
                owners.insert(child.session_id.clone());
                match stop_one(&target, &child, None).await {
                    Ok((view, confirmed)) => {
                        if !confirmed {
                            unconfirmed.get_or_insert_with(|| view.status_message.clone());
                        }
                        stopped.push(view);
                    }
                    Err(error) => {
                        let name = session_label(&child);
                        failure.get_or_insert(error.context(format!("stop child session {name}")));
                    }
                }
            }
            children = running_children(&target.list().await?, &owners);
        }
        print_environment_sessions(&stopped, args.output)?;
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if let Some(status) = unconfirmed {
        anyhow::bail!("session stop is not confirmed: {status}");
    }
    Ok(())
}

fn session_label(session: &EnvironmentSessionView) -> &str {
    if session.name.is_empty() {
        &session.session_id
    } else {
        &session.name
    }
}

/// Ask at a terminal whether to stop the running children too; never asks
/// without one, so scripts and agents keep children unless they pass --all.
fn confirm_stop_children(children: &[EnvironmentSessionView]) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(false);
    }
    let names: Vec<&str> = children.iter().map(session_label).collect();
    let noun = if children.len() == 1 {
        "session"
    } else {
        "sessions"
    };
    eprint!(
        "Also stop {} running child {noun} ({})? [Y/n] ",
        children.len(),
        names.join(", ")
    );
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

pub(super) fn running_children_hints(
    children: &[EnvironmentSessionView],
    parent: &EnvironmentSessionView,
    environment: Option<&str>,
) -> Vec<String> {
    let scope = environment.map(|e| format!("{e} ")).unwrap_or_default();
    let mut lines: Vec<String> = children
        .iter()
        .map(|child| {
            format!(
                "cw: child session {} is still running",
                session_label(child)
            )
        })
        .collect();
    lines.push(format!(
        "cw: stop them with `cw stop --all {scope}{}`",
        session_label(parent)
    ));
    lines
}

/// Stop one session through its placement's owner. False when a plain
/// session's stop is not confirmed; managed stops confirm themselves.
async fn stop_one(
    target: &EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
    request: Option<&SessionTargetArgs>,
) -> anyhow::Result<(EnvironmentSessionView, bool)> {
    #[cfg(unix)]
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) && managed_session(session) {
        let stopped = agents::platform_host::control_session(
            target.clone(),
            session,
            request.and_then(|args| args.request_id.as_deref()),
            request.and_then(|args| args.expected_launch_generation),
            request.and_then(|args| args.cleanup_request_id),
            codewire_client::platform_agents::EnvironmentAgentAction::Stop,
        )
        .await?;
        return Ok((stopped, true));
    }
    if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) && managed_session(session) {
        return Ok((agents::stop_native_managed(target, session).await?, true));
    }
    let _ = request;
    let stopped = target.stop(&session.session_id).await?;
    let confirmed = session_is_terminal(&stopped) && !stopped.cleanup_unknown;
    Ok((stopped, confirmed))
}

/// Running sessions whose parent is one of `owners` and that are not owners
/// themselves, so a session whose stop failed is never revisited.
pub(super) fn running_children(
    sessions: &[EnvironmentSessionView],
    owners: &std::collections::BTreeSet<String>,
) -> Vec<EnvironmentSessionView> {
    sessions
        .iter()
        .filter(|s| {
            owners.contains(&s.parent_session_id)
                && !owners.contains(&s.session_id)
                && !session_is_terminal(s)
        })
        .cloned()
        .collect()
}

pub(crate) async fn handle_restart_command(
    globals: &Globals,
    args: SessionTargetArgs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.cleanup_request_id.is_none(),
        "--cleanup-request-id requires Stop"
    );
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::managed::action(
            globals,
            args,
            codewire_daemon_proto::daemon::v1::HostManagedAction::Restart,
        )
        .await;
    }
    let (target, session) = resolve_selected_session(globals, &args.target).await?;
    #[cfg(unix)]
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) && managed_session(&session) {
        let restarted = agents::platform_host::control_session(
            target,
            &session,
            args.request_id.as_deref(),
            args.expected_launch_generation,
            None,
            codewire_client::platform_agents::EnvironmentAgentAction::Restart,
        )
        .await?;
        return print_environment_sessions(std::slice::from_ref(&restarted), args.output);
    }
    anyhow::ensure!(
        globals.member.is_none()
            && args.request_id.is_none()
            && args.expected_launch_generation.is_none(),
        "request and generation flags require --member or a managed platform session"
    );
    if session.cleanup_unknown {
        anyhow::bail!("session cleanup is unknown; restart is fenced");
    }
    if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) && managed_session(&session) {
        let restarted = agents::restart_native_managed(&target, &session).await?;
        return print_environment_sessions(std::slice::from_ref(&restarted), args.output);
    }
    let restarted = target.restart(&session.session_id).await?;
    print_environment_sessions(std::slice::from_ref(&restarted), args.output)
}

pub(crate) async fn handle_wait_command(globals: &Globals, args: WaitArgs) -> anyhow::Result<()> {
    if let Some(message) = &args.message
        && !args.target.is_empty()
    {
        anyhow::bail!(
            "a message ID already names its session; run `cw wait --message {message}` without ENV or SESSION"
        );
    }
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        if args.message.is_some() {
            return super::member_control::managed::wait(globals, args).await;
        }
        return super::member_control::terminal::wait(globals, args).await;
    }
    let timeout = tailnet_ssh::parse_duration(&args.timeout)
        .map_err(|e| anyhow::anyhow!("invalid wait timeout: {e}"))?;
    if timeout.is_zero() {
        anyhow::bail!("wait timeout must be greater than zero");
    }
    if let Some(message) = args.message {
        #[cfg(unix)]
        return agents::wait_agent_message(globals, &message, timeout, args.output).await;
        #[cfg(not(unix))]
        anyhow::bail!("managed message waiting currently requires Linux or macOS");
    }
    let (target, initial) = resolve_selected_session(globals, &args.target).await?;
    let future = async {
        let mut offset = 0;
        let mut history_gap = false;
        let mut output = Vec::new();
        let mut started_at = initial.started_at.clone();
        loop {
            let replay = target.read_output(&initial.session_id, offset).await?;
            if replay.history_gap {
                history_gap = true;
                if matches!(args.output, OutputFormat::Text) {
                    eprintln!("[cw] older output unavailable; showing retained output");
                }
            }
            for chunk in replay.chunks {
                match args.output {
                    OutputFormat::Text => {
                        write_session_output(&mut std::io::stdout(), &chunk, true)?
                    }
                    OutputFormat::Json => {
                        output.extend_from_slice(&chunk);
                        if output.len() > 4 * 1024 * 1024 {
                            output.drain(..output.len() - 4 * 1024 * 1024);
                            history_gap = true;
                        }
                    }
                }
            }
            offset = replay.next_offset;
            let current = target.get(&initial.session_id).await?;
            if !started_at.is_empty() && current.started_at != started_at {
                anyhow::bail!(
                    "session restarted during wait; completion of the selected run is unknown"
                );
            }
            if started_at.is_empty() {
                started_at = current.started_at.clone();
            }
            if session_is_terminal(&current) && replay.eof && offset >= current.output_end_offset {
                match args.output {
                    OutputFormat::Json => println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"session":current,"output":String::from_utf8_lossy(&output),"history_gap":history_gap,"eof":true})
                        )?
                    ),
                    OutputFormat::Text => {}
                }
                if current.cleanup_unknown {
                    anyhow::bail!(
                        "session cleanup remains unknown: {}",
                        current.status_message
                    );
                }
                ensure_environment_session_succeeded(&current)?;
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    tokio::time::timeout(timeout, future)
        .await
        .context("wait timed out; no completion confirmed")?
}

#[cfg(unix)]
async fn attach_host_environment_session(
    environment: &HostEnvironment,
    session: &EnvironmentSessionView,
    offset: u64,
    interactive: bool,
    raw_output: bool,
    ansi: &mut LogsAnsiFilter,
) -> anyhow::Result<AttachExit> {
    use codewire_daemon_proto::daemon::v1::session_attach_message::Payload;
    let client = host_session_client(environment).await?;
    let mut attachment = client.attach(&session.session_id, offset).await?;
    let input = attachment.input_handle();
    let interactive =
        interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if interactive && managed_session(session) {
        anyhow::bail!("use cw msg or cw steer for managed agents; cw logs reads their output");
    }
    let _raw = interactive.then(RawModeGuard::enable).transpose()?;
    let mut decoder = AttachNavigationDecoder::default();
    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 4096];
    let mut cursor = offset;
    let mut stdin_open = interactive;
    loop {
        tokio::select! {
            event=attachment.next_event()=>{
                let Some(event)=event? else{return Ok(AttachExit::StreamEnded{output_offset:cursor});};
                match event.payload {
                    Some(Payload::Output(chunk))=>{
                        if raw_output {
                            write_session_output(&mut std::io::stdout(), &chunk.data, true)?;
                        } else {
                            write_session_output(&mut std::io::stdout(), &ansi.strip(&chunk.data), true)?;
                        }
                        cursor=chunk.next_offset;
                    }
                    Some(Payload::HistoryGap(gap))=>{
                        eprintln!("[cw] older output unavailable; showing retained output");
                        cursor=gap.retained_start_offset;
                        *ansi=LogsAnsiFilter::default();
                    }
                    Some(Payload::Status(status)) if (4..=7).contains(&status.state)=>return Ok(AttachExit::Terminal),
                    _=>{},
                }
            }
            n=stdin.read(&mut buf),if stdin_open=>{
                let n=n?;
                if n==0{stdin_open=false;continue;}
                let (action,bytes)=decoder.feed(&buf[..n]);
                if !bytes.is_empty(){client.send_input(&session.session_id,bytes).await?;}
                if let Some(action)=action{input.detach().await?;return Ok(action);}
            }
        }
    }
}

pub(crate) fn platform_environment_session_state_name(
    state: Option<codewire_client::EnvironmentSessionState>,
) -> &'static str {
    use codewire_client::EnvironmentSessionState;

    match state {
        Some(EnvironmentSessionState::Unspecified) => "Unspecified",
        Some(EnvironmentSessionState::Starting) => "Starting",
        Some(EnvironmentSessionState::Running) => "Running",
        Some(EnvironmentSessionState::Stopping) => "Stopping",
        Some(EnvironmentSessionState::Stopped) => "Stopped",
        Some(EnvironmentSessionState::Exited) => "Exited",
        Some(EnvironmentSessionState::Failed) => "Failed",
        Some(EnvironmentSessionState::Interrupted) => "Interrupted",
        None => "Unknown",
    }
}

enum SessionSelection {
    Create,
    Select(Box<EnvironmentSessionView>),
}

async fn select_environment_session(
    target: &EnvironmentSessionTarget,
    requested: Option<&str>,
) -> anyhow::Result<SessionSelection> {
    let sessions = target.list().await?;
    if let Some(requested) = requested.and_then(trimmed_str) {
        return requested_environment_session(&sessions, requested)
            .cloned()
            .map(|session| SessionSelection::Select(Box::new(session)))
            .ok_or_else(|| anyhow::anyhow!("session {requested:?} not found"));
    }
    match sessions.as_slice() {
        [] => Ok(SessionSelection::Create),
        [session] => Ok(SessionSelection::Select(Box::new(session.clone()))),
        _ => select_session_from_picker(&sessions)
            .map(|session| SessionSelection::Select(Box::new(session))),
    }
}

pub(crate) fn requested_environment_session<'a>(
    sessions: &'a [EnvironmentSessionView],
    requested: &str,
) -> Option<&'a EnvironmentSessionView> {
    let by_id = sessions
        .iter()
        .find(|session| session.session_id == requested);
    let canonical_id = requested.strip_prefix("session-").unwrap_or(requested);
    if uuid::Uuid::parse_str(canonical_id).is_ok() {
        by_id
    } else {
        by_id.or_else(|| sessions.iter().find(|session| session.name == requested))
    }
}

fn select_session_from_picker(
    sessions: &[EnvironmentSessionView],
) -> anyhow::Result<EnvironmentSessionView> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        anyhow::bail!(
            "multiple sessions in the selected environment; use `cw attach ENV SESSION` or `cw attach --session SESSION`"
        );
    }
    eprintln!("Select a session:");
    for (index, session) in sessions.iter().enumerate() {
        eprintln!(
            "  {}) {} {}",
            index + 1,
            session.session_id,
            session_command_label(session)
        );
    }
    eprint!("Session number: ");
    std::io::stderr().flush()?;
    let mut selected = String::new();
    std::io::stdin().read_line(&mut selected)?;
    let selected = selected
        .trim()
        .parse::<usize>()
        .context("parse selected session number")?;
    sessions
        .get(selected.saturating_sub(1))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("session selection is out of range"))
}

fn should_create_session() -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(false);
    }
    eprint!("No sessions in the selected environment. Create a shell session? [y/N] ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn session_terminal_size(pty: bool) -> anyhow::Result<(u16, u16)> {
    if pty {
        terminal_attach::terminal_size()
    } else {
        Ok((0, 0))
    }
}

fn environment_run_allocates_tty(args: &EnvironmentRunArgs) -> bool {
    environment_run_allocates_tty_for_streams(
        args,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

pub(crate) fn environment_run_allocates_tty_for_streams(
    args: &EnvironmentRunArgs,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> bool {
    if args.no_tty || matches!(args.output, OutputFormat::Json) {
        return false;
    }
    args.tty || (stdin_is_terminal && stdout_is_terminal)
}

fn session_command_label(session: &EnvironmentSessionView) -> String {
    if managed_session(session) {
        "managed agent".into()
    } else {
        session.command.join(" ")
    }
}

pub(super) fn print_environment_sessions(
    sessions: &[EnvironmentSessionView],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(sessions)?),
        OutputFormat::Text if sessions.is_empty() => println!("No sessions"),
        OutputFormat::Text => print!("{}", format_environment_sessions(sessions, "")),
    }
    Ok(())
}

/// Aligned session rows under a header. A child names its parent session
/// from the same environment; COMMAND, the widest column, comes last.
pub(super) fn format_environment_sessions(
    sessions: &[EnvironmentSessionView],
    indent: &str,
) -> String {
    let parent = |session: &EnvironmentSessionView| match session.parent_session_id.as_str() {
        "" => "-".to_owned(),
        id => sessions
            .iter()
            .find(|candidate| candidate.session_id == id && !candidate.name.is_empty())
            .map_or_else(|| id.to_owned(), |candidate| candidate.name.clone()),
    };
    let rows: Vec<[String; 5]> =
        std::iter::once(["NAME", "STATE", "PARENT", "SESSION", "COMMAND"].map(String::from))
            .chain(sessions.iter().map(|session| {
                [
                    if session.name.is_empty() {
                        "-".to_owned()
                    } else {
                        session.name.clone()
                    },
                    session.state.clone(),
                    parent(session),
                    session.session_id.clone(),
                    session_command_label(session),
                ]
            }))
            .collect();
    let widths: [usize; 4] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    });
    let mut output = String::new();
    for row in &rows {
        output.push_str(indent);
        for (cell, width) in row.iter().zip(widths) {
            output.push_str(&format!("{cell:<width$}  "));
        }
        output.push_str(&row[4]);
        output.push('\n');
    }
    output
}

pub(crate) async fn handle_environment_run_command(
    globals: &Globals,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        if args.agent.is_some() {
            return super::member_control::managed::run(globals, args).await;
        }
        return super::member_control::terminal::run(globals, args).await;
    }
    anyhow::ensure!(args.request_id.is_none(), "--request-id requires --member");
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    if args.agent.is_some() {
        #[cfg(unix)]
        return agents::handle_agent_run_command(globals, target, args).await;
        #[cfg(not(unix))]
        anyhow::bail!("managed conversations currently require a trusted Linux or macOS host");
    }
    let parent_session_id = resolve_parent_session(&target, args.parent.as_deref()).await?;
    let pty = environment_run_allocates_tty(&args);
    let working_dir = args.workdir.unwrap_or_else(|| target.default_working_dir());
    target.ensure_ready_for_run()?;
    let session = target
        .launch(
            args.command,
            working_dir,
            parse_env_overrides(&args.env)?,
            pty,
            args.name.unwrap_or_default(),
            parent_session_id,
        )
        .await?;
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&session)?);
        return Ok(());
    } else {
        eprintln!("Launched session {}", session.session_id);
    }
    if args.detach {
        return Ok(());
    }
    if let Some(session) = attach_environment_session(globals, target, session).await? {
        ensure_environment_session_succeeded(&session)?;
    }
    Ok(())
}

pub(crate) async fn handle_environment_shell_command(
    globals: &Globals,
    args: EnvironmentShellArgs,
) -> anyhow::Result<()> {
    if args.stdio {
        return handle_shell_stdio(globals, args.environment.as_deref()).await;
    }
    handle_environment_run_command(
        globals,
        EnvironmentRunArgs {
            request_id: None,
            name: None,
            parent: None,
            agent: None,
            model: None,
            effort: None,
            prompt: None,
            environment: args.environment,
            workdir: None,
            env: Vec::new(),
            tty: true,
            no_tty: false,
            detach: false,
            output: OutputFormat::Text,
            // No command: the daemon starts the workspace user's own login
            // shell (their passwd shell in a local VM, `$SHELL` or bash in a
            // hosted Sandbox), so line editing and their rc files work.
            command: Vec::new(),
        },
    )
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachExit {
    Detached,
    PreviousSession,
    NextSession,
    PreviousEnvironment,
    NextEnvironment,
    OpenWorkspaces,
    Restart,
    Terminal,
    StreamEnded { output_offset: u64 },
    StreamInterrupted { output_offset: u64 },
}

const ATTACH_RECONNECT_LIMIT: u8 = 3;
pub(crate) const ATTACH_RECONNECT_BASE_DELAY: Duration = Duration::from_millis(250);

#[derive(Default)]
pub(crate) struct AttachmentReconnectBudget {
    last_output_offset: u64,
    consecutive_interruptions: u8,
}

impl AttachmentReconnectBudget {
    pub(crate) fn retry_delay(&mut self, output_offset: u64) -> anyhow::Result<Duration> {
        if output_offset > self.last_output_offset {
            self.consecutive_interruptions = 0;
        }
        self.last_output_offset = output_offset;
        self.consecutive_interruptions = self.consecutive_interruptions.saturating_add(1);
        if self.consecutive_interruptions > ATTACH_RECONNECT_LIMIT {
            anyhow::bail!(
                "environment session attachment was interrupted {} times without output progress",
                ATTACH_RECONNECT_LIMIT
            );
        }
        Ok(ATTACH_RECONNECT_BASE_DELAY * u32::from(self.consecutive_interruptions))
    }
}

#[derive(Default)]
pub(crate) struct AttachNavigationDecoder {
    pending_prefix: bool,
}

impl AttachNavigationDecoder {
    pub(crate) fn feed(&mut self, input: &[u8]) -> (Option<AttachExit>, Vec<u8>) {
        let mut forward = Vec::with_capacity(input.len());
        for byte in input {
            if self.pending_prefix {
                self.pending_prefix = false;
                let action = match byte {
                    b'h' => Some(AttachExit::PreviousSession),
                    b'l' => Some(AttachExit::NextSession),
                    b'k' => Some(AttachExit::PreviousEnvironment),
                    b'j' => Some(AttachExit::NextEnvironment),
                    b'w' => Some(AttachExit::OpenWorkspaces),
                    b'r' => Some(AttachExit::Restart),
                    b'd' => Some(AttachExit::Detached),
                    b'b' => {
                        forward.push(0x02);
                        None
                    }
                    _ => {
                        forward.extend_from_slice(&[0x02, *byte]);
                        None
                    }
                };
                if action.is_some() {
                    return (action, forward);
                }
            } else if *byte == 0x02 {
                self.pending_prefix = true;
            } else {
                forward.push(*byte);
            }
        }
        (None, forward)
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        if self.pending_prefix {
            self.pending_prefix = false;
            vec![0x02]
        } else {
            Vec::new()
        }
    }
}

async fn attach_environment_session(
    globals: &Globals,
    mut target: EnvironmentSessionTarget,
    mut session: EnvironmentSessionView,
) -> anyhow::Result<Option<EnvironmentSessionView>> {
    let mut output_offset = 0;
    let mut reconnect_budget = AttachmentReconnectBudget::default();
    loop {
        let exit = match &target {
            #[cfg(unix)]
            EnvironmentSessionTarget::Host { environment, .. } => {
                attach_host_environment_session(
                    environment,
                    &session,
                    output_offset,
                    session.pty,
                    true,
                    &mut LogsAnsiFilter::default(),
                )
                .await?
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { environment_id, .. } => {
                let client = native_environment_session_client(environment_id).await?;
                let attachment = client.attach(&session.session_id, output_offset).await?;
                attach_platform_environment_session(attachment, session.pty, true).await?
            }
            EnvironmentSessionTarget::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let attachment = client
                    .attach_session(codewire_client::AttachSessionOpen {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session.session_id.clone(),
                        output_offset,
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                attach_platform_environment_session(attachment, session.pty, true).await?
            }
        };
        match exit {
            AttachExit::Detached => return Ok(None),
            AttachExit::Terminal => return target.get(&session.session_id).await.map(Some),
            AttachExit::StreamEnded {
                output_offset: next_offset,
            } => {
                let refreshed = target.get(&session.session_id).await?;
                if session_is_terminal(&refreshed) {
                    return Ok(Some(refreshed));
                }
                session = refreshed;
                output_offset = next_offset;
            }
            AttachExit::StreamInterrupted {
                output_offset: next_offset,
            } => {
                let refreshed = target.get(&session.session_id).await?;
                if session_is_terminal(&refreshed) {
                    return Ok(Some(refreshed));
                }
                let delay = reconnect_budget.retry_delay(next_offset)?;
                session = refreshed;
                output_offset = next_offset;
                tokio::time::sleep(delay).await;
            }
            AttachExit::Restart => {
                let current = target.get(&session.session_id).await?;
                if !session_is_terminal(&current) {
                    anyhow::bail!("Ctrl+B r is available only after the selected session exits");
                }
                session = target.restart(&session.session_id).await?;
                output_offset = 0;
            }
            AttachExit::PreviousSession | AttachExit::NextSession => {
                session = adjacent_session(
                    &target.list().await?,
                    &session.session_id,
                    matches!(exit, AttachExit::NextSession),
                )?;
                output_offset = 0;
            }
            AttachExit::PreviousEnvironment | AttachExit::NextEnvironment => {
                target = adjacent_environment_target(
                    globals,
                    target.current_target(),
                    matches!(exit, AttachExit::NextEnvironment),
                )
                .await?;
                session = select_or_create_environment_session(&target).await?;
                output_offset = 0;
            }
            AttachExit::OpenWorkspaces => {
                show_workspace_list(globals).await?;
                return Ok(None);
            }
        }
    }
}

async fn attach_platform_environment_session(
    mut attachment: codewire_client::EnvironmentSessionAttachment,
    interactive: bool,
    raw_output: bool,
) -> anyhow::Result<AttachExit> {
    let input = attachment.input_handle();
    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = [0_u8; 4096];
    let mut stdout = std::io::stdout();
    let interactive =
        interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let _raw = interactive
        .then(RawModeGuard::enable)
        .transpose()
        .context("enabling raw mode")?;
    let mut decoder = AttachNavigationDecoder::default();
    let mut output_offset = 0;
    let mut stdin_closed = !interactive;
    let mut output_open = true;
    let mut terminal = false;
    loop {
        if !output_open && stdin_closed {
            return Ok(if terminal {
                AttachExit::Terminal
            } else {
                AttachExit::StreamEnded { output_offset }
            });
        }
        tokio::select! {
            event = attachment.next_output(), if output_open => {
                let event = match event {
                    Ok(Some(event)) => event,
                    Ok(None) => {
                        if terminal && interactive {
                            output_open = false;
                            continue;
                        }
                        return Ok(AttachExit::StreamEnded { output_offset });
                    }
                    Err(error) if error.is_retryable_transport_interruption() => {
                        return Ok(AttachExit::StreamInterrupted { output_offset });
                    }
                    Err(error) => return Err(display_client_error(error)),
                };
                match event.event {
                    Some(codewire_client::attach_session_response::Event::HistoryGap(gap)) => {
                        eprintln!("\r\n[cw] older output unavailable; replaying recent history");
                        output_offset = gap.retained_start_offset;
                    }
                    Some(codewire_client::attach_session_response::Event::Output(output)) => {
                        write_session_output(&mut stdout, &output.data, raw_output)?;
                        output_offset = output.next_offset;
                    }
                    Some(codewire_client::attach_session_response::Event::Status(status))
                        if status.session.as_option().is_some_and(platform_session_is_terminal) => {
                        terminal = true;
                        if !interactive {
                            return Ok(AttachExit::Terminal);
                        }
                        eprintln!("\r\n[cw] session exited; Ctrl+B r restarts, Ctrl+B d detaches");
                    }
                    Some(codewire_client::attach_session_response::Event::Status(_)) => {}
                    None => {}
                }
            }
            read = stdin.read(&mut stdin_buf), if !stdin_closed => {
                let read = read.context("read terminal input")?;
                if read == 0 {
                    let pending = decoder.finish();
                    if !pending.is_empty() {
                        input.send(codewire_client::AttachSessionRequest {
                            input: Some(codewire_client::attach_session_request::Input::Stdin(pending)),
                            ..Default::default()
                        }).await.map_err(display_client_error)?;
                    }
                    stdin_closed = true;
                    continue;
                }
                let (action, forward) = decoder.feed(&stdin_buf[..read]);
                if !forward.is_empty() {
                    input.send(codewire_client::AttachSessionRequest {
                        input: Some(codewire_client::attach_session_request::Input::Stdin(forward)),
                        ..Default::default()
                    }).await.map_err(display_client_error)?;
                }
                if let Some(action) = action {
                    if matches!(action, AttachExit::Detached) && output_open {
                        input.send(codewire_client::AttachSessionRequest {
                            input: Some(codewire_client::attach_session_request::Input::Detach(Box::default())),
                            ..Default::default()
                        }).await.map_err(display_client_error)?;
                    }
                    return Ok(action);
                }
            }
        }
    }
}

fn session_is_terminal(session: &EnvironmentSessionView) -> bool {
    matches!(
        session.state.as_str(),
        "Stopped" | "Exited" | "Failed" | "Interrupted"
    )
}

pub(crate) fn ensure_environment_session_succeeded(
    session: &EnvironmentSessionView,
) -> anyhow::Result<()> {
    match session.exit_code {
        Some(0) if session.state == "Exited" && !session.cleanup_unknown => Ok(()),
        Some(0) => anyhow::bail!(
            "session is {} with cleanup_unknown={}; completion is not confirmed",
            session.state,
            session.cleanup_unknown
        ),
        Some(code) => anyhow::bail!("session exited with code {code}"),
        None => {
            let status_suffix = if session.status_message.is_empty() {
                String::new()
            } else {
                format!(": {}", session.status_message)
            };
            anyhow::bail!(
                "session reached terminal state {} without an exit code{}",
                session.state,
                status_suffix
            )
        }
    }
}

pub(super) fn write_session_output(
    stdout: &mut std::io::Stdout,
    data: &[u8],
    raw_output: bool,
) -> anyhow::Result<()> {
    if raw_output {
        stdout.write_all(data)?;
    } else {
        stdout.write_all(&strip_ansi_escapes(data))?;
    }
    stdout.flush()?;
    Ok(())
}

pub(crate) fn adjacent_session(
    sessions: &[EnvironmentSessionView],
    current_session_id: &str,
    forward: bool,
) -> anyhow::Result<EnvironmentSessionView> {
    if sessions.is_empty() {
        anyhow::bail!("no sessions in the selected environment");
    }
    let current = sessions
        .iter()
        .position(|session| session.session_id == current_session_id)
        .ok_or_else(|| anyhow::anyhow!("attached session is no longer available"))?;
    let next = if forward {
        (current + 1) % sessions.len()
    } else {
        (current + sessions.len() - 1) % sessions.len()
    };
    Ok(sessions[next].clone())
}

async fn select_or_create_environment_session(
    target: &EnvironmentSessionTarget,
) -> anyhow::Result<EnvironmentSessionView> {
    match select_environment_session(target, None).await? {
        SessionSelection::Select(session) => Ok(*session),
        SessionSelection::Create if should_create_session()? => {
            target
                .launch(
                    Vec::new(),
                    target.default_working_dir(),
                    BTreeMap::new(),
                    true,
                    String::new(),
                    String::new(),
                )
                .await
        }
        SessionSelection::Create => anyhow::bail!(
            "no sessions in the selected environment; use `cw shell ENV` or `cw run ENV -- COMMAND`"
        ),
    }
}

async fn adjacent_environment_target(
    globals: &Globals,
    current: &config::CurrentTargetConfig,
    forward: bool,
) -> anyhow::Result<EnvironmentSessionTarget> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let targets = attachment_environment_targets(globals, &paths, &env)
        .await?
        .into_iter()
        .map(|(target, _)| target)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        anyhow::bail!("no environments are available for attachment navigation");
    }
    let current_index = targets
        .iter()
        .position(|target| target.kind == current.kind && target.target_ref == current.target_ref)
        .ok_or_else(|| anyhow::anyhow!("attached environment is no longer available"))?;
    let next_index = if forward {
        (current_index + 1) % targets.len()
    } else {
        (current_index + targets.len() - 1) % targets.len()
    };
    environment_session_target_from_current(globals, &paths, &env, targets[next_index].clone())
        .await
}

/// Every accessible environment, sorted, with whether it is running.
async fn attachment_environment_targets(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<Vec<(config::CurrentTargetConfig, bool)>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut targets = native_environments()
        .await?
        .into_iter()
        .map(|environment| {
            let running = environment.state
                == codewire_local_vmm::control::v1::EnvironmentState::Running as i32;
            let target = config::CurrentTargetConfig {
                kind: "local".to_string(),
                target_ref: environment.name.clone(),
                name: environment.name,
            };
            (target, running)
        })
        .collect::<Vec<_>>();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut targets = Vec::new();
    #[cfg(unix)]
    targets.extend(
        host_environments()?
            .into_iter()
            .map(|e| (e.current_target(), e.state == "running")),
    );

    match resolve_platform(globals, paths, env) {
        Ok(platform) => {
            let orgs = organization_client(&platform)?.list_orgs().await?;
            let org_id = current_org_id(&platform, &orgs)?;
            let environments = codewire_client(&platform)?
                .list_environments(codewire_client::ListEnvironmentsRequest {
                    org_id,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?
                .environments;
            targets.extend(environments.into_iter().map(|environment| {
                let running = environment.state.as_known()
                    == Some(codewire_client::EnvironmentState::Running);
                let target = config::CurrentTargetConfig {
                    kind: "env".to_string(),
                    target_ref: environment.id.clone(),
                    name: trimmed_str(&environment.name)
                        .unwrap_or(&environment.id)
                        .to_string(),
                };
                (target, running)
            }));
        }
        Err(error) if targets.is_empty() => return Err(error),
        Err(_) => {}
    }

    targets.sort_by(|(left, _), (right, _)| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.target_ref.cmp(&right.target_ref))
    });
    Ok(targets)
}

fn platform_session_is_terminal(session: &codewire_client::EnvironmentSession) -> bool {
    matches!(
        session.state.as_known(),
        Some(
            codewire_client::EnvironmentSessionState::Stopped
                | codewire_client::EnvironmentSessionState::Exited
                | codewire_client::EnvironmentSessionState::Failed
                | codewire_client::EnvironmentSessionState::Interrupted
        )
    )
}

fn strip_ansi_escapes(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut escape = false;
    let mut csi = false;
    for byte in data {
        if escape {
            if *byte == b'[' {
                csi = true;
            } else {
                escape = false;
            }
            continue;
        }
        if csi {
            if (0x40..=0x7e).contains(byte) {
                csi = false;
                escape = false;
            }
            continue;
        }
        if *byte == 0x1b {
            escape = true;
            continue;
        }
        output.push(*byte);
    }
    output
}

pub(crate) async fn handle_list_command(globals: &Globals, args: ListArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::terminal::list(globals, args).await;
    }
    if args.all || args.environment.is_none() {
        let paths = ResolvePaths::from_env(&OsEnv)?;
        let targets = attachment_environment_targets(globals, &paths, &OsEnv).await?;
        let mut rows = Vec::new();
        let mut inventories = Vec::new();
        let mut incomplete = false;
        for (current, running) in targets {
            let mut sessions = Vec::new();
            let mut error = None;
            if running {
                let result = match environment_session_target_from_current(
                    globals,
                    &paths,
                    &OsEnv,
                    current.clone(),
                )
                .await
                {
                    Ok(target) => target.list().await,
                    Err(error) => Err(error),
                };
                match result {
                    Ok(listed) => sessions = listed,
                    Err(failure) => {
                        incomplete = true;
                        error = Some(failure.to_string());
                    }
                }
            }
            rows.push(serde_json::json!({
                "environment_id": current.target_ref,
                "environment": current.name,
                "placement": if current.kind == "env" { "platform" } else { "local" },
                "type": if current.kind == "host" { "host" } else { "sandbox" },
                "running": running,
                "sessions": sessions,
                "error": error,
            }));
            inventories.push(sessions);
        }
        match args.output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
            OutputFormat::Text => {
                if rows.is_empty() {
                    println!("No environments");
                }
                for (row, sessions) in rows.iter().zip(&inventories) {
                    println!(
                        "{} ({}/{}){}",
                        row["environment"].as_str().unwrap_or(""),
                        row["placement"].as_str().unwrap_or(""),
                        row["type"].as_str().unwrap_or(""),
                        if row["running"] == true {
                            ""
                        } else {
                            " not running"
                        }
                    );
                    if let Some(error) = row["error"].as_str() {
                        println!("  unavailable: {error}");
                    } else if row["running"] == true && sessions.is_empty() {
                        println!("  No sessions");
                    } else if !sessions.is_empty() {
                        print!("{}", format_environment_sessions(sessions, "  "));
                    }
                }
            }
        }
        if incomplete {
            anyhow::bail!(
                "session inventory is partial; unavailable environments are listed above"
            );
        }
        return Ok(());
    }
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let sessions = target.list().await?;
    print_environment_sessions(&sessions, args.output)?;
    Ok(())
}

pub(crate) async fn handle_attach_command(
    globals: &Globals,
    args: AttachArgs,
) -> anyhow::Result<()> {
    let (target, requested) = resolve_attach_or_logs_target(
        globals,
        args.environment,
        args.selected_session.or(args.session),
    )
    .await?;
    let session = match select_environment_session(&target, requested.as_deref()).await? {
        SessionSelection::Select(session) => *session,
        SessionSelection::Create => select_or_create_environment_session(&target).await?,
    };
    let _ = attach_environment_session(globals, target, session).await?;
    Ok(())
}

pub(crate) async fn handle_logs_command(globals: &Globals, args: LogsArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::terminal::logs(globals, args).await;
    }
    let (target, requested) =
        resolve_attach_or_logs_target(globals, args.environment, args.session).await?;
    let session = match select_environment_session(&target, requested.as_deref()).await? {
        SessionSelection::Select(session) => *session,
        SessionSelection::Create => anyhow::bail!("no sessions in the selected environment"),
    };
    // Freeze the initial boundary: a running writer must not keep ordinary logs
    // chasing a moving EOF. The daemon retains 4 MiB and compacts at 8 MiB;
    // allow that whole window while bounding faulty or unexpectedly large replay.
    const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
    const MAX_REPLAY_PAGES: usize = 128;
    let end_offset = session.output_end_offset;
    let mut output_offset = 0;
    let mut replay_bytes = 0usize;
    let mut drained = false;
    let mut tail_buffer = args.tail.map(|_| Vec::new());
    let mut ansi = LogsAnsiFilter::default();
    let mut stdout = std::io::stdout();
    for _ in 0..MAX_REPLAY_PAGES {
        let output = target
            .read_output(&session.session_id, output_offset)
            .await?;
        anyhow::ensure!(
            output.next_offset >= output_offset,
            "session output replay moved backwards"
        );
        if output.history_gap {
            eprintln!("[cw] older output unavailable; showing recent history");
            // A gap breaks both the previous line and its escape-code context.
            if let Some(buffer) = &mut tail_buffer {
                buffer.clear();
            }
            ansi = LogsAnsiFilter::default();
        }
        for chunk in output.chunks {
            replay_bytes = replay_bytes
                .checked_add(chunk.len())
                .context("session output replay size overflow")?;
            anyhow::ensure!(
                replay_bytes <= MAX_REPLAY_BYTES,
                "session output replay exceeds the bounded retained-history budget"
            );
            if let Some(buffer) = &mut tail_buffer {
                if args.tail != Some(0) {
                    buffer.extend_from_slice(&chunk);
                    let start = session_output_tail_start(buffer, args.tail);
                    buffer.drain(..start);
                }
            } else if args.raw {
                write_session_output(&mut stdout, &chunk, true)?;
            } else {
                write_session_output(&mut stdout, &ansi.strip(&chunk), true)?;
            }
        }
        anyhow::ensure!(
            output.next_offset > output_offset || output_offset >= end_offset,
            "session output replay did not advance to the selected end offset {end_offset}"
        );
        output_offset = output.next_offset;
        if output_offset >= end_offset {
            drained = true;
            break;
        }
        anyhow::ensure!(
            !output.eof,
            "session output ended before the selected end offset {end_offset}"
        );
    }
    anyhow::ensure!(drained, "session output replay exceeded its page budget");
    if let Some(buffer) = tail_buffer {
        let buffer = tail_session_output(&buffer, args.tail);
        if args.raw {
            write_session_output(&mut stdout, &buffer, true)?;
        } else {
            write_session_output(&mut stdout, &ansi.strip(&buffer), true)?;
        }
    }
    if args.follow && !session_is_terminal(&session) {
        follow_session_output(&target, &session, output_offset, args.raw, ansi).await?;
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct LogsAnsiFilter {
    escape: bool,
    csi: bool,
}

impl LogsAnsiFilter {
    pub(super) fn strip(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        for &byte in data {
            if self.csi {
                if (0x40..=0x7e).contains(&byte) {
                    self.csi = false;
                }
            } else if self.escape {
                self.escape = false;
                self.csi = byte == b'[';
            } else if byte == 0x1b {
                self.escape = true;
            } else {
                output.push(byte);
            }
        }
        output
    }
}

/// A single positional value may name a session in the selected environment.
/// The two-value ENV SESSION form and attach --session remain explicit.
async fn resolve_attach_or_logs_target(
    globals: &Globals,
    environment: Option<String>,
    session: Option<String>,
) -> anyhow::Result<(EnvironmentSessionTarget, Option<String>)> {
    if session.is_none()
        && let Some(requested) = environment.as_deref()
        && let Ok(current) = resolve_environment_session_target(globals, None).await
        && let Ok(sessions) = current.list().await
        && requested_environment_session(&sessions, requested).is_some()
    {
        if resolve_environment_session_target(globals, Some(requested))
            .await
            .is_ok()
        {
            anyhow::bail!(
                "{requested:?} names both an environment and a session; use ENV SESSION explicitly"
            );
        }
        return Ok((current, environment));
    }
    let target = resolve_environment_session_target(globals, environment.as_deref()).await?;
    Ok((target, session))
}

pub(crate) fn tail_session_output(data: &[u8], tail: Option<u32>) -> Vec<u8> {
    data[session_output_tail_start(data, tail)..].to_vec()
}

pub(super) fn session_output_tail_start(data: &[u8], tail: Option<u32>) -> usize {
    let Some(tail) = tail else {
        return 0;
    };
    if tail == 0 {
        return data.len();
    }
    let end = data.len() - usize::from(data.last() == Some(&b'\n'));
    let mut remaining = tail;
    for index in (0..end).rev() {
        if data[index] == b'\n' {
            remaining -= 1;
            if remaining == 0 {
                return index + 1;
            }
        }
    }
    0
}

async fn follow_session_output(
    target: &EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
    mut output_offset: u64,
    raw_output: bool,
    ansi: LogsAnsiFilter,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    let mut ansi = ansi;
    #[cfg(not(unix))]
    let _ = ansi;
    let mut reconnect_budget = AttachmentReconnectBudget::default();
    loop {
        let exit = match target {
            #[cfg(unix)]
            EnvironmentSessionTarget::Host { environment, .. } => {
                attach_host_environment_session(
                    environment,
                    session,
                    output_offset,
                    false,
                    raw_output,
                    &mut ansi,
                )
                .await?
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { environment_id, .. } => {
                let client = native_environment_session_client(environment_id).await?;
                attach_platform_environment_session(
                    client.attach(&session.session_id, output_offset).await?,
                    false,
                    raw_output,
                )
                .await?
            }
            EnvironmentSessionTarget::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                let attachment = client
                    .attach_session(codewire_client::AttachSessionOpen {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session.session_id.clone(),
                        output_offset,
                        ..Default::default()
                    })
                    .await
                    .map_err(display_client_error)?;
                attach_platform_environment_session(attachment, false, raw_output).await?
            }
        };
        match exit {
            AttachExit::Terminal => return Ok(()),
            AttachExit::StreamEnded {
                output_offset: next_offset,
            } => {
                let refreshed = target.get(&session.session_id).await?;
                if session_is_terminal(&refreshed) {
                    return Ok(());
                }
                output_offset = next_offset;
            }
            AttachExit::StreamInterrupted {
                output_offset: next_offset,
            } => {
                let refreshed = target.get(&session.session_id).await?;
                if session_is_terminal(&refreshed) {
                    return Ok(());
                }
                let delay = reconnect_budget.retry_delay(next_offset)?;
                output_offset = next_offset;
                tokio::time::sleep(delay).await;
            }
            _ => unreachable!("non-interactive attachment produced navigation"),
        }
    }
}
