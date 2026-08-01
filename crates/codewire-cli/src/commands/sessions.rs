use super::*;
use crate::terminal_attach::RawModeGuard;
use tokio::io::AsyncReadExt as _;

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct EnvironmentSessionView {
    pub(crate) session_id: String,
    pub(crate) state: String,
    pub(crate) command: Vec<String>,
    pub(crate) working_dir: String,
    pub(crate) pty: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) output_end_offset: u64,
    pub(crate) status_message: String,
}

#[derive(Clone, Debug)]
struct EnvironmentSessionOutput {
    chunks: Vec<Vec<u8>>,
    next_offset: u64,
}

#[derive(Clone)]
enum EnvironmentSessionTarget {
    Local {
        target: config::CurrentTargetConfig,
        instance: Box<config::LocalInstanceConfig>,
    },
    Platform {
        target: config::CurrentTargetConfig,
        org_id: String,
        environment_id: String,
        client: Box<codewire_client::CodewireClient>,
    },
}

impl EnvironmentSessionTarget {
    fn ensure_ready_for_run(&self) -> anyhow::Result<()> {
        match self {
            Self::Local { instance, .. } => ensure_local_environment_runtime_ready(instance),
            Self::Platform { .. } => Ok(()),
        }
    }

    async fn list(&self) -> anyhow::Result<Vec<EnvironmentSessionView>> {
        match self {
            Self::Local { instance, .. } => Ok(local_environment_session_client(instance)
                .await?
                .list()
                .await
                .map_err(anyhow::Error::from)?
                .into_iter()
                .map(local_environment_session_view)
                .collect()),
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
            Self::Local { instance, .. } => {
                let response = local_environment_session_client(instance)
                    .await?
                    .read_output(codewire_daemon::client::v1::ReadSessionOutputRequest {
                        session_id: session_id.to_string(),
                        offset,
                        limit: 0,
                    })
                    .await?;
                Ok(EnvironmentSessionOutput {
                    chunks: response
                        .chunks
                        .into_iter()
                        .map(|chunk| chunk.data)
                        .collect(),
                    next_offset: response.next_offset,
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
    ) -> anyhow::Result<EnvironmentSessionView> {
        let (columns, rows) = session_terminal_size(pty)?;
        let term = env::var("TERM").unwrap_or_default();
        match self {
            Self::Local { instance, .. } => {
                let session = local_environment_session_client(instance)
                    .await?
                    .launch(codewire_daemon::client::v1::LaunchSessionRequest {
                        command,
                        working_dir,
                        env: env
                            .into_iter()
                            .map(|(key, value)| format!("{key}={value}"))
                            .collect(),
                        pty,
                        term,
                        width: i32::from(columns),
                        height: i32::from(rows),
                    })
                    .await?;
                Ok(local_environment_session_view(session))
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
            Self::Local { instance, .. } => Ok(local_environment_session_view(
                local_environment_session_client(instance)
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
            Self::Local { instance, .. } => Ok(local_environment_session_view(
                local_environment_session_client(instance)
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
            Self::Local { target, .. } | Self::Platform { target, .. } => target,
        }
    }

    fn default_working_dir(&self) -> String {
        match self {
            Self::Local { instance, .. } => local_environment_session_working_dir(instance),
            Self::Platform { .. } => LOCAL_WORKSPACE_PATH.to_string(),
        }
    }
}

async fn resolve_environment_session_target(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<EnvironmentSessionTarget> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let target = match environment.and_then(trimmed_str) {
        Some(environment) => {
            resolve_named_execution_target(globals, &paths, &env, environment, None).await?
        }
        None => config::current_target(&paths.mesh_data_dir)?,
    };
    environment_session_target_from_current(globals, &paths, &env, target).await
}

async fn environment_session_target_from_current(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    target: config::CurrentTargetConfig,
) -> anyhow::Result<EnvironmentSessionTarget> {
    match target.kind.as_str() {
        "local" => {
            let instance = lookup_local_instance_for_target(&paths.mesh_data_dir, &target)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no local environment selected; use `cw use --local ENV` or pass ENV"
                    )
                })?;
            Ok(EnvironmentSessionTarget::Local {
                target,
                instance: Box::new(instance),
            })
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

pub(crate) async fn local_environment_daemon_client(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    let endpoint = format!("http://127.0.0.1:{}", local_daemon_host_port(instance)?);
    codewire_daemon::client::SessionClient::connect(endpoint, local_daemon_auth_token(instance)?)
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) async fn local_environment_session_client(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<codewire_daemon::client::SessionClient> {
    let mut last_error = None;
    for attempt in 0..LOCAL_DAEMON_READY_ATTEMPTS {
        match local_environment_daemon_client(instance).await {
            Ok(client) => match client.require_ready().await {
                Ok(()) => return Ok(client),
                Err(error) => last_error = Some(anyhow::Error::from(error)),
            },
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < LOCAL_DAEMON_READY_ATTEMPTS {
            tokio::time::sleep(LOCAL_DAEMON_READY_RETRY_INTERVAL).await;
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("local environment daemon did not become ready")))
    .context("wait for local environment daemon session readiness")
}

fn local_environment_session_view(
    session: codewire_daemon::client::v1::SessionRecord,
) -> EnvironmentSessionView {
    EnvironmentSessionView {
        session_id: session.session_id,
        state: codewire_daemon::client::v1::SessionLifecycleState::try_from(session.state)
            .map(|state| format!("{state:?}"))
            .unwrap_or_else(|_| "Unknown".to_string()),
        command: session.command,
        working_dir: session.working_dir,
        pty: session.pty,
        exit_code: session.exit_code,
        output_end_offset: session.output_end_offset,
        status_message: session.status_message,
    }
}

pub(crate) fn local_environment_session_working_dir(
    instance: &config::LocalInstanceConfig,
) -> String {
    trimmed_str(&instance.workdir)
        .unwrap_or(LOCAL_WORKSPACE_PATH)
        .to_string()
}

fn platform_environment_session_view(
    session: codewire_client::EnvironmentSession,
) -> EnvironmentSessionView {
    EnvironmentSessionView {
        session_id: session.session_id,
        state: platform_environment_session_state_name(session.state.as_known()).to_string(),
        command: session.command,
        working_dir: session.working_dir,
        pty: session.pty,
        exit_code: session.exit_code,
        output_end_offset: session.output_end_offset,
        status_message: session.status_message,
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
    Select(EnvironmentSessionView),
}

async fn select_environment_session(
    target: &EnvironmentSessionTarget,
    requested: Option<&str>,
) -> anyhow::Result<SessionSelection> {
    let sessions = target.list().await?;
    if let Some(requested) = requested.and_then(trimmed_str) {
        return sessions
            .into_iter()
            .find(|session| session.session_id == requested)
            .map(SessionSelection::Select)
            .ok_or_else(|| anyhow::anyhow!("session {requested:?} not found"));
    }
    match sessions.as_slice() {
        [] => Ok(SessionSelection::Create),
        [session] => Ok(SessionSelection::Select(session.clone())),
        _ => select_session_from_picker(&sessions).map(SessionSelection::Select),
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
            session.command.join(" ")
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

fn print_environment_sessions(
    sessions: &[EnvironmentSessionView],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(sessions)?),
        OutputFormat::Text if sessions.is_empty() => println!("No sessions"),
        OutputFormat::Text => {
            for session in sessions {
                println!(
                    "{}\t{}\t{}",
                    session.session_id,
                    session.state,
                    session.command.join(" ")
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn handle_environment_run_command(
    globals: &Globals,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let pty = environment_run_allocates_tty(&args);
    let working_dir = args.workdir.unwrap_or_else(|| target.default_working_dir());
    target.ensure_ready_for_run()?;
    let session = target
        .launch(
            args.command,
            working_dir,
            parse_env_overrides(&args.env)?,
            pty,
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
            environment: args.environment,
            workdir: None,
            env: Vec::new(),
            tty: true,
            no_tty: false,
            detach: false,
            output: OutputFormat::Text,
            command: vec!["/bin/sh".to_string()],
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
    loop {
        let exit = match &target {
            EnvironmentSessionTarget::Local { instance, .. } => {
                let client = local_environment_session_client(instance).await?;
                let attachment = client
                    .attach(session.session_id.clone(), output_offset)
                    .await?;
                attach_local_environment_session(attachment, session.pty, true).await?
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

async fn attach_local_environment_session(
    mut attachment: codewire_daemon::client::SessionAttachment,
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
            event = attachment.next_event(), if output_open => {
                let Some(event) = event? else {
                    if terminal && interactive {
                        output_open = false;
                        continue;
                    }
                    return Ok(AttachExit::StreamEnded { output_offset });
                };
                match event.payload {
                    Some(codewire_daemon::client::v1::session_attach_message::Payload::Output(output)) => {
                        write_session_output(&mut stdout, &output.data, raw_output)?;
                        output_offset = output.next_offset;
                    }
                    Some(codewire_daemon::client::v1::session_attach_message::Payload::Status(status))
                        if daemon_session_is_terminal(status.state) => {
                        terminal = true;
                        if !interactive {
                            return Ok(AttachExit::Terminal);
                        }
                        eprintln!("\r\n[cw] session exited; Ctrl+B r restarts, Ctrl+B d detaches");
                    }
                    _ => {}
                }
            }
            read = stdin.read(&mut stdin_buf), if !stdin_closed => {
                let read = read.context("read terminal input")?;
                if read == 0 {
                    let pending = decoder.finish();
                    if !pending.is_empty() {
                        input.send_input(pending).await?;
                    }
                    stdin_closed = true;
                    continue;
                }
                let (action, forward) = decoder.feed(&stdin_buf[..read]);
                if !forward.is_empty() {
                    input.send_input(forward).await?;
                }
                if let Some(action) = action {
                    if matches!(action, AttachExit::Detached) && output_open {
                        input.detach().await?;
                    }
                    return Ok(action);
                }
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
                let Some(event) = event.map_err(display_client_error)? else {
                    if terminal && interactive {
                        output_open = false;
                        continue;
                    }
                    return Ok(AttachExit::StreamEnded { output_offset });
                };
                match event.event {
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
        Some(0) => Ok(()),
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

fn write_session_output(
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
        SessionSelection::Select(session) => Ok(session),
        SessionSelection::Create if should_create_session()? => {
            target
                .launch(
                    vec!["/bin/sh".to_string()],
                    target.default_working_dir(),
                    BTreeMap::new(),
                    true,
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
    let paths = ResolvePaths::from_env(&env);
    let targets = attachment_environment_targets(globals, &paths, &env).await?;
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

async fn attachment_environment_targets(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<Vec<config::CurrentTargetConfig>> {
    let local = config::load_local_instances_config(&paths.mesh_data_dir)?;
    let mut targets = local
        .instances
        .iter()
        .map(|(key, instance)| config::CurrentTargetConfig {
            kind: "local".to_string(),
            target_ref: key.clone(),
            name: local_instance_display_name(key, instance).to_string(),
        })
        .collect::<Vec<_>>();

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
                config::CurrentTargetConfig {
                    kind: "env".to_string(),
                    target_ref: environment.id.clone(),
                    name: trimmed_str(&environment.name)
                        .unwrap_or(&environment.id)
                        .to_string(),
                }
            }));
        }
        Err(error) if targets.is_empty() => return Err(error),
        Err(_) => {}
    }

    targets.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.target_ref.cmp(&right.target_ref))
    });
    if targets.is_empty() {
        anyhow::bail!("no environments are available for attachment navigation");
    }
    Ok(targets)
}

fn daemon_session_is_terminal(state: i32) -> bool {
    matches!(
        codewire_daemon::client::v1::SessionLifecycleState::try_from(state),
        Ok(codewire_daemon::client::v1::SessionLifecycleState::Stopped
            | codewire_daemon::client::v1::SessionLifecycleState::Exited
            | codewire_daemon::client::v1::SessionLifecycleState::Failed
            | codewire_daemon::client::v1::SessionLifecycleState::Interrupted)
    )
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
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let sessions = target.list().await?;
    print_environment_sessions(&sessions, args.output)?;
    Ok(())
}

pub(crate) async fn handle_attach_command(
    globals: &Globals,
    args: AttachArgs,
) -> anyhow::Result<()> {
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let requested = args.selected_session.or(args.session);
    let session = match select_environment_session(&target, requested.as_deref()).await? {
        SessionSelection::Select(session) => session,
        SessionSelection::Create => select_or_create_environment_session(&target).await?,
    };
    let _ = attach_environment_session(globals, target, session).await?;
    Ok(())
}

pub(crate) async fn handle_logs_command(globals: &Globals, args: LogsArgs) -> anyhow::Result<()> {
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let session = match select_environment_session(&target, args.session.as_deref()).await? {
        SessionSelection::Select(session) => session,
        SessionSelection::Create => anyhow::bail!("no sessions in the selected environment"),
    };
    let output = target.read_output(&session.session_id, 0).await?;
    let data = output.chunks.concat();
    let data = tail_session_output(&data, args.tail);
    let mut stdout = std::io::stdout();
    write_session_output(&mut stdout, &data, args.raw)?;
    if args.follow && !session_is_terminal(&session) {
        follow_session_output(&target, &session, output.next_offset, args.raw).await?;
    }
    Ok(())
}

pub(crate) fn tail_session_output(data: &[u8], tail: Option<u32>) -> Vec<u8> {
    let Some(tail) = tail else {
        return data.to_vec();
    };
    if tail == 0 {
        return Vec::new();
    }
    let lines = data
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let start = lines
        .len()
        .saturating_sub(usize::try_from(tail).unwrap_or(usize::MAX));
    lines.into_iter().skip(start).flatten().copied().collect()
}

async fn follow_session_output(
    target: &EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
    mut output_offset: u64,
    raw_output: bool,
) -> anyhow::Result<()> {
    loop {
        let exit = match target {
            EnvironmentSessionTarget::Local { instance, .. } => {
                let client = local_environment_session_client(instance).await?;
                attach_local_environment_session(
                    client
                        .attach(session.session_id.clone(), output_offset)
                        .await?,
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
            _ => unreachable!("non-interactive attachment produced navigation"),
        }
    }
}
