use super::*;
use crate::terminal_attach::{RawModeGuard, SessionScreen};
use codewire_client::hosted_shell::{InputNotice, InputStream};
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
        let (columns, rows) = session_terminal_size(pty);
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
                        end_after_detached_seconds: 0,
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

    /// The session as the server reports it, or `None` when the network is
    /// why it can't say.
    async fn get_unless_unreachable(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<EnvironmentSessionView>> {
        match self.get(session_id).await {
            Ok(session) => Ok(Some(session)),
            Err(error) if super::tailnet_shell::is_network_failure(&error) => Ok(None),
            Err(error) => Err(error),
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

/// The environment a session operation addresses. With an explicit
/// `--local` or `--cloud` a named environment is looked up only there and
/// the selected environment must be there; it never falls back elsewhere.
/// Commands that do not read a placement reach here with none.
async fn resolve_environment_session_target(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<EnvironmentSessionTarget> {
    let Some(placement) = globals.placement else {
        return resolve_unplaced_session_target(globals, environment).await;
    };
    let target = match environment.and_then(trimmed_str) {
        Some(requested) => {
            let env = OsEnv;
            let paths = ResolvePaths::from_env(&env)?;
            let target =
                resolve_named_execution_target(globals, &paths, &env, requested, Some(placement))
                    .await?;
            environment_session_target_from_current(globals, &paths, &env, target).await?
        }
        None => resolve_unplaced_session_target(globals, None).await?,
    };
    let cloud = matches!(target, EnvironmentSessionTarget::Platform { .. });
    match placement {
        EnvironmentPlacement::Platform if !cloud => anyhow::bail!(
            "the selected environment {} is not a cloud environment; name one with ENV or `--in ENV`, or drop --cloud",
            target.current_target().name
        ),
        EnvironmentPlacement::Local if cloud => anyhow::bail!(
            "the selected environment {} is a cloud environment; name a local one with ENV or `--in ENV`, or drop --local",
            target.current_target().name
        ),
        _ => Ok(target),
    }
}

/// A saved managed-message location is also its placement authority. Resolve
/// it only in that placement so an unrelated local supervisor or cloud lookup
/// cannot intercept a wait before the indexed environment is reached.
pub(crate) fn globals_for_message_placement(
    globals: &Globals,
    placement: EnvironmentPlacement,
) -> Globals {
    let mut located = globals.clone();
    located.placement = Some(placement);
    located
}

async fn resolve_unplaced_session_target(
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
    // The selected local VM, named again, is answered without asking the
    // cloud. A local supervisor that cannot be asked only skips this: the
    // lookup below still finds a cloud environment (#3560).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(requested) = environment.and_then(trimmed_str)
        && let Ok(target) = config::current_target(&paths.mesh_data_dir)
        && target.kind == "local"
        && target.target_ref != "local"
        && let Ok(Some(environment)) = native_environment(&target.target_ref).await
        && native_session_request_matches(&environment, requested)
    {
        return Ok(native_session_target(environment));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if environment.and_then(trimmed_str).is_none()
        && let Ok(target) = config::current_target(&paths.mesh_data_dir)
        && !(target.kind == "local" && target.target_ref == "local")
    {
        if target.kind != "local" {
            return environment_session_target_from_current(globals, &paths, &env, target).await;
        }
        if let Some(environment) = native_environment(&target.target_ref).await? {
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
                    if target.target_ref == "local" {
                        no_environment_selected()
                    } else {
                        anyhow::anyhow!(
                            "the selected local VM {} no longer exists: select another with `cw use ENV`, or name one with `--in ENV`",
                            target.name
                        )
                    }
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
                org_id: resolve_org_id(&platform, &orgs, globals.org.as_deref())?,
                environment_id,
                client: Box::new(codewire_client(&platform)?),
            })
        }
        _ => Err(no_environment_selected()),
    }
}

/// The repair for a session command with no environment named or selected.
fn no_environment_selected() -> anyhow::Error {
    anyhow::anyhow!(
        "no environment selected: select one with `cw use ENV`, or name it with `--in ENV`"
    )
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

/// An existing session named by flags: the environment (positional ENV or
/// `--in ENV`, else the selected one) and `--session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionSelector {
    pub(crate) environment: Option<String>,
    pub(crate) session: String,
}

impl SessionSelector {
    /// `[ENV] SESSION`, the form the session handlers and member control
    /// resolve. Built from explicit flags, so no value is reinterpreted.
    pub(crate) fn values(&self) -> Vec<String> {
        self.environment
            .iter()
            .cloned()
            .chain([self.session.clone()])
            .collect()
    }
}

/// The session a command names with `[ENV | --in ENV] --session S`. Both
/// environment forms, a retired second positional or a missing `--session`
/// fail here, before any lookup.
pub(crate) fn select_session(
    command: &str,
    positional: Option<String>,
    flag: Option<String>,
    retired_session: &[String],
    session: Option<String>,
) -> anyhow::Result<SessionSelector> {
    let environment = super::flat::select_environment(command, positional, flag, retired_session)?;
    let session = session
        .and_then(|session| trimmed_str(&session).map(str::to_owned))
        .ok_or_else(|| missing_session(command, environment.as_deref()))?;
    Ok(SessionSelector {
        environment,
        session,
    })
}

fn missing_session(command: &str, environment: Option<&str>) -> anyhow::Error {
    match environment {
        Some(environment) => anyhow::anyhow!(
            "missing session: `cw {command} {environment} --session SESSION` (`cw ls {environment}` lists its sessions)"
        ),
        None => anyhow::anyhow!(
            "missing session: `cw {command} ENV --session SESSION`, or `cw {command} --session SESSION` in the selected environment"
        ),
    }
}

/// `cw interrupt`'s selectors as the session handler's target.
pub(crate) fn selector_target(
    command: &str,
    args: SessionSelectorArgs,
) -> anyhow::Result<SessionTargetArgs> {
    let selection = select_session(
        command,
        args.environment,
        args.in_environment,
        &args.retired_session,
        args.session,
    )?;
    Ok(SessionTargetArgs {
        request_id: args.request_id,
        expected_launch_generation: args.expected_launch_generation,
        cleanup_request_id: None,
        target: selection.values(),
        output: args.output,
    })
}

/// What `cw send` writes, and to which session.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SendRequest {
    pub(crate) selection: SessionSelector,
    pub(crate) data: Vec<u8>,
}

/// `cw send [ENV] TEXT` or `cw send [ENV] --key KEY`: the number of values
/// alone decides whether the first names the environment.
pub(crate) fn send_request(args: &SendArgs) -> anyhow::Result<SendRequest> {
    if !args.retired.is_empty() {
        let environment = args.first.as_deref().unwrap_or("ENV");
        let session = args.second.as_deref().unwrap_or("SESSION");
        anyhow::bail!(
            "`cw send ENV SESSION TEXT` no longer selects a session; use `cw send {environment} --session {session} TEXT`"
        );
    }
    let values: Vec<String> = args.first.iter().chain(&args.second).cloned().collect();
    let (environment, text) = match (args.key.is_some(), values.as_slice()) {
        (false, []) => anyhow::bail!(
            "missing TEXT: `cw send ENV --session SESSION TEXT`, or `--key KEY` for one key"
        ),
        (false, [text]) => (None, Some(text.clone())),
        (false, [environment, text]) => (Some(environment.clone()), Some(text.clone())),
        (true, []) => (None, None),
        (true, [environment]) => (Some(environment.clone()), None),
        (true, _) => anyhow::bail!(
            "--key sends one key and no TEXT: `cw send ENV --session SESSION --key KEY`"
        ),
        (false, _) => unreachable!("at most two values parse"),
    };
    let selection = select_session(
        "send",
        environment,
        args.in_environment.clone(),
        &[],
        args.session.clone(),
    )?;
    let data = match (args.key.as_deref(), text) {
        (Some(key), _) => match key {
            "ctrl-c" => vec![3],
            "ctrl-d" => vec![4],
            "enter" => vec![b'\r'],
            "escape" => vec![27],
            "tab" => vec![b'\t'],
            _ => anyhow::bail!("unsupported terminal key"),
        },
        (None, Some(text)) => {
            let mut data = text.into_bytes();
            if !args.no_newline {
                data.push(b'\n');
            }
            data
        }
        (None, None) => unreachable!("text is required without --key"),
    };
    anyhow::ensure!(
        !data.is_empty() && data.len() <= 64 * 1024,
        "session input must contain 1–65536 bytes"
    );
    Ok(SendRequest { selection, data })
}

/// The session `cw wait` follows; `--message` alone names its own.
pub(crate) fn wait_selection(args: &WaitArgs) -> anyhow::Result<Option<SessionSelector>> {
    if let Some(message) = &args.message {
        anyhow::ensure!(
            args.environment.is_none()
                && args.in_environment.is_none()
                && args.session.is_none()
                && args.retired_session.is_empty(),
            "a message ID already names its session; run `cw wait --message {message}` without ENV or SESSION"
        );
        return Ok(None);
    }
    select_session(
        "wait",
        args.environment.clone(),
        args.in_environment.clone(),
        &args.retired_session,
        args.session.clone(),
    )
    .map(Some)
}

/// A managed conversation's driver owns its input, on every client OS: the
/// local driver (`_agent-driver`) and a cloud Sandbox's platform driver
/// (`__platform-agent-driver`), which a client on any OS can reach.
fn managed_session(session: &EnvironmentSessionView) -> bool {
    session
        .command
        .iter()
        .any(|arg| arg == "_agent-driver" || arg == "__platform-agent-driver")
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
    let SendRequest { selection, data } = send_request(&args)?;
    let (target, session) = resolve_selected_session(globals, &selection.values()).await?;
    if managed_session(&session) {
        let name = if session.name.is_empty() {
            &session.session_id
        } else {
            &session.name
        };
        anyhow::bail!(
            "{name} is a managed agent conversation and takes no raw input; send it a task with `cw msg ENV --session {name} TEXT`"
        );
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

/// Stop one session (`cw stop [ENV] --session S`): today's explicit session
/// cancellation, never an environment takedown.
pub(crate) async fn handle_stop_command(
    globals: &Globals,
    args: SessionTargetArgs,
    all: bool,
) -> anyhow::Result<()> {
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
    let scope = environment.map(|e| format!(" {e}")).unwrap_or_default();
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
        "cw: stop them with `cw stop{scope} --session {} --all`",
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
    let selection = wait_selection(&args)?;
    if let Some(message) = &args.message
        && globals.placement.is_some()
    {
        anyhow::bail!(
            "a message ID already names its session and environment; run `cw wait --message {message}` without --local or --cloud"
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
    let selection = selection.context("wait needs --session or --message")?;
    let (target, initial) = resolve_selected_session(globals, &selection.values()).await?;
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
    screen: &mut SessionScreen,
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
    let mut stdin = crate::terminal_attach::terminal_input().await;
    let mut buf = [0u8; 4096];
    let mut cursor = offset;
    let mut stdin_open = interactive;
    // The session's PTY follows this terminal's size, from the start. A lost
    // resize is cosmetic, and the next input reports a closed stream.
    let mut window = crate::terminal_attach::WindowSizeWatch::new(interactive && session.pty);
    if let Some((columns, rows)) = window.current() {
        let _ = input.resize(i32::from(columns), i32::from(rows)).await;
    }
    loop {
        tokio::select! {
            size = window.changed() => {
                if let Some((columns, rows)) = size {
                    let _ = input.resize(i32::from(columns), i32::from(rows)).await;
                }
            }
            event=attachment.next_event()=>{
                let Some(event)=event? else{return Ok(AttachExit::StreamEnded{output_offset:cursor});};
                match event.payload {
                    Some(Payload::Output(chunk))=>{
                        if raw_output {
                            screen.observe(&chunk.data);
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
            .ok_or_else(|| {
                let environment = &target.current_target().name;
                anyhow::anyhow!(
                    "session {requested:?} not found in {environment} (`cw ls {environment}` lists its sessions)"
                )
            });
    }
    match sessions.as_slice() {
        [] => Ok(SessionSelection::Create),
        [session] => Ok(SessionSelection::Select(Box::new(session.clone()))),
        _ => {
            let environment = target.current_target().name.clone();
            let repair = format!(
                "{environment} has {} sessions; name one: `cw attach {environment} --session SESSION` (`cw ls {environment}` lists them)",
                sessions.len()
            );
            select_session_from_picker(&environment, &sessions, "to attach to", repair)
                .await
                .map(|session| SessionSelection::Select(Box::new(session)))
        }
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

/// The searchable session picker on an interactive terminal. `verb` says
/// what the choice is for, as in "Choose a session to attach to".
async fn select_session_from_picker(
    environment: &str,
    sessions: &[EnvironmentSessionView],
    verb: &str,
    script_repair: String,
) -> anyhow::Result<EnvironmentSessionView> {
    use crate::output::{Capabilities, OutputMode, Picker, PickerOutcome, PickerRow, run_picker};
    let rows = sessions
        .iter()
        .map(|session| {
            let name = if session.name.is_empty() {
                "-".to_owned()
            } else {
                session.name.clone()
            };
            let command = session_command_label(session);
            let search = format!("{name} {} {command}", session.session_id);
            PickerRow::new(
                vec![
                    name,
                    session.state.to_lowercase(),
                    session_mode(session).to_owned(),
                    command,
                    session.session_id.clone(),
                ],
                search,
            )
        })
        .collect();
    let picker = Picker::new(
        format!("Choose a session {verb} in {environment}"),
        ["NAME", "STATE", "MODE", "COMMAND", "SESSION"]
            .map(str::to_owned)
            .to_vec(),
        rows,
    )
    .with_no_match("No matching sessions. Backspace to clear the filter.");
    let caps = Capabilities::from_process(OutputMode::Text);
    let outcome = tokio::task::spawn_blocking(move || run_picker(picker, &caps))
        .await
        .context("ask which session")??;
    match outcome {
        PickerOutcome::Chosen(index) => Ok(sessions[index].clone()),
        PickerOutcome::Canceled => anyhow::bail!("canceled; no session chosen"),
        PickerOutcome::Unavailable => Err(anyhow::anyhow!(script_repair)),
    }
}

fn should_create_session(environment: &str) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(false);
    }
    eprint!("{environment} has no sessions. Start a shell in it? [y/N] ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// A PTY session's first size: this terminal's, or a conventional 80x24 when
/// this command has none (a script that starts an agent to attach to later;
/// each attach sends its own terminal's size).
fn session_terminal_size(pty: bool) -> (u16, u16) {
    if !pty {
        return (0, 0);
    }
    terminal_attach::terminal_size()
        .ok()
        .filter(|(columns, rows)| *columns > 0 && *rows > 0)
        .unwrap_or(DEFAULT_PTY_SIZE)
}

/// Columns and rows of a PTY session started without a terminal.
const DEFAULT_PTY_SIZE: (u16, u16) = (80, 24);

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

/// The session's recorded mode: a managed agent conversation, or a normal
/// terminal or command session.
pub(super) fn session_mode(session: &EnvironmentSessionView) -> &'static str {
    if managed_session(session) {
        "managed"
    } else {
        "normal"
    }
}

/// Session rows as JSON, each with its recorded `mode`.
pub(crate) fn sessions_json(
    sessions: &[EnvironmentSessionView],
) -> anyhow::Result<serde_json::Value> {
    sessions
        .iter()
        .map(|session| {
            let mut value = serde_json::to_value(session)?;
            if let Some(object) = value.as_object_mut() {
                object.insert("mode".into(), session_mode(session).into());
            }
            Ok(value)
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(serde_json::Value::Array)
}

pub(super) fn print_environment_sessions(
    sessions: &[EnvironmentSessionView],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&sessions_json(sessions)?)?
        ),
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
    let rows: Vec<[String; 6]> = std::iter::once(
        ["NAME", "STATE", "MODE", "PARENT", "SESSION", "COMMAND"].map(String::from),
    )
    .chain(sessions.iter().map(|session| {
        [
            if session.name.is_empty() {
                "-".to_owned()
            } else {
                session.name.clone()
            },
            session.state.clone(),
            session_mode(session).to_owned(),
            parent(session),
            session.session_id.clone(),
            session_command_label(session),
        ]
    }))
    .collect();
    let widths: [usize; 5] = std::array::from_fn(|column| {
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
        output.push_str(&row[5]);
        output.push('\n');
    }
    output
}

pub(crate) async fn handle_environment_run_command(
    globals: &Globals,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    launch_run(globals, args, None).await
}

/// `cw run` and `cw shell`. `name_base` names a session that has no
/// `--name` when the command's own name would not (`shell`, not `sh`).
async fn launch_run(
    globals: &Globals,
    mut args: EnvironmentRunArgs,
    name_base: Option<&str>,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        anyhow::ensure!(
            args.native_agent.is_none(),
            "member run starts commands only; claude and codex open a terminal UI, which member control does not admit"
        );
        if args.agent.is_some() {
            return super::member_control::managed::run(globals, args).await;
        }
        return super::member_control::terminal::run(globals, args).await;
    }
    anyhow::ensure!(args.request_id.is_none(), "--request-id requires --member");
    let caps = super::lifecycle_output::capabilities(args.output);
    let can_ask = run_can_ask(&args, &caps);
    let bare = check_run_request(&args, can_ask)?;
    if bare {
        // Collect the last missing launch choice before a walkthrough can
        // create an environment. Canceling the agent menu creates nothing.
        args.native_agent =
            Some(choose_native_agent("a new or existing environment", &caps).await?);
    }
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let selected = if args.environment.as_deref().and_then(trimmed_str).is_none() {
        Some(config::current_target(&paths.mesh_data_dir)?)
    } else {
        None
    };
    let mut missing = selected
        .as_ref()
        .is_some_and(|selected| selected.kind == "local" && selected.target_ref == "local");
    if can_ask && let Some(selected) = &selected {
        if matches!(globals.placement, Some(EnvironmentPlacement::Platform))
            && selected.kind == "local"
            || matches!(globals.placement, Some(EnvironmentPlacement::Local))
                && selected.kind == "env"
        {
            missing = true;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !missing && selected.kind == "local" {
            missing = !native_state_exists()?
                || native_environment(&selected.target_ref).await?.is_none();
            if missing {
                eprintln!(
                    "The selected local environment no longer exists. Choose another environment or create one."
                );
            }
        }
    }
    let mut target = if missing {
        anyhow::ensure!(can_ask, "{}", no_environment_selected());
        check_run_setup_request(&args)?;
        let (selected, organization) =
            super::launch_setup::choose_run_environment(globals, &args).await?;
        environment_session_target_from_current(
            &globals.with_org(organization),
            &paths,
            &OsEnv,
            selected,
        )
        .await?
    } else {
        resolve_environment_session_target(globals, args.environment.as_deref()).await?
    };
    if can_ask
        && !missing
        && args.environment.as_deref().and_then(trimmed_str).is_none()
        && let EnvironmentSessionTarget::Platform {
            client,
            org_id,
            environment_id,
            ..
        } = &target
    {
        let missing_cloud = match client
            .get_environment(codewire_client::GetEnvironmentRequest {
                org_id: org_id.clone(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
        {
            Ok(response) => {
                let environment = response
                    .environment
                    .as_option()
                    .context("platform returned no environment")?;
                environment.state.as_known() == Some(codewire_client::EnvironmentState::Destroyed)
            }
            Err(error) if error.code() == codewire_client::ErrorCode::NotFound => true,
            Err(error) => return Err(display_client_error(error)),
        };
        if missing_cloud {
            eprintln!(
                "The selected cloud environment no longer exists. Choose another environment or create one."
            );
            check_run_setup_request(&args)?;
            let (selected, organization) =
                super::launch_setup::choose_run_environment(globals, &args).await?;
            target = environment_session_target_from_current(
                &globals.with_org(organization),
                &paths,
                &OsEnv,
                selected,
            )
            .await?;
        }
    }
    if args.agent.is_some() {
        #[cfg(unix)]
        return agents::handle_agent_run_command(globals, target, args).await;
        #[cfg(not(unix))]
        anyhow::bail!("managed conversations currently require a trusted Linux or macOS host");
    }
    let place = SessionPlace::of(&target);
    let agent = args.native_agent;
    let pty = match agent {
        // An agent's terminal UI needs a terminal even when this command's
        // own streams are not one, or when it prints JSON and detaches.
        Some(_) => !args.no_tty,
        None => environment_run_allocates_tty(&args),
    };
    let command = match agent {
        Some(agent) => std::iter::once(agent.command().to_owned())
            .chain(std::mem::take(&mut args.command))
            .collect(),
        None => std::mem::take(&mut args.command),
    };
    let sessions = match target.list().await {
        Ok(sessions) => sessions,
        Err(error) => return Err(stopped_environment_sessions(&target).await.unwrap_or(error)),
    };
    let name = match args.name.take() {
        Some(name) => {
            if let Some(existing) = sessions.iter().find(|session| session.name == name) {
                return Err(duplicate_session_name(&place, existing));
            }
            name
        }
        None => unique_session_name(
            name_base
                .map(str::to_owned)
                .unwrap_or_else(|| session_name_base(&command)),
            &sessions,
        ),
    };
    let parent_session_id = resolve_parent_session(&target, args.parent.as_deref()).await?;
    let working_dir = args.workdir.unwrap_or_else(|| target.default_working_dir());
    target.ensure_ready_for_run()?;
    let session = target
        .launch(
            command,
            working_dir,
            parse_env_overrides(&args.env)?,
            pty,
            name,
            parent_session_id,
        )
        .await?;
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&session)?);
        return Ok(());
    }
    let started = place.started(&session, agent);
    if args.detach {
        let style = caps.stdout_style();
        println!("{} {started}", style.status(crate::output::Status::Done));
        println!(
            "{} {}",
            style.status(crate::output::Status::Next),
            place.reconnect(&session)
        );
        return Ok(());
    }
    let interactive =
        session.pty && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let style = caps.stderr_style();
    eprintln!("{} {started}", style.status(crate::output::Status::Done));
    if interactive {
        eprintln!("  {}", place.detach_hint(&session, style));
    }
    if let Some(session) = attach_environment_session(globals, target, session).await? {
        ensure_environment_session_succeeded(&session)?;
    }
    Ok(())
}

/// Prompt only when the requested output mode and process terminals allow
/// it, and never with `--yes`, as `cw create --yes` never prompts.
pub(crate) fn run_can_ask(args: &EnvironmentRunArgs, caps: &crate::output::Capabilities) -> bool {
    !args.yes && matches!(args.output, OutputFormat::Text) && caps.interactive && caps.live
}

/// Creating a sandbox can satisfy a new session request. A parent session
/// or an agent outside the sandbox capability set requires an existing
/// target, selected through the normal explicit or saved-selection path.
fn check_run_setup_request(args: &EnvironmentRunArgs) -> anyhow::Result<()> {
    let requires_existing = args.parent.is_some()
        || args
            .agent
            .as_deref()
            .is_some_and(|agent| !matches!(agent, "codex" | "claude"));
    anyhow::ensure!(
        !requires_existing,
        "this run requires an existing supported environment; select it with --in ENV or cw use ENV before running it"
    );
    Ok(())
}

/// Refuse missing script input or an invalid session name before any lookup.
/// Returns whether the run still needs an agent choice.
pub(crate) fn check_run_request(args: &EnvironmentRunArgs, can_ask: bool) -> anyhow::Result<bool> {
    let bare = args.native_agent.is_none() && args.agent.is_none() && args.command.is_empty();
    anyhow::ensure!(
        !bare || can_ask,
        "`cw run` needs an agent or a command: `cw run claude --in ENV`, `cw run codex --in ENV`, or `cw run --in ENV -- COMMAND`"
    );
    if let Some(name) = &args.name {
        anyhow::ensure!(
            codewire_daemon_proto::valid_session_name(name),
            "--name {name:?} is not a session name: 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or digit"
        );
    }
    Ok(bare)
}

/// Where a session runs, for what `run` and `attach` print: the
/// environment's name, its location, and the placement flag that finds it
/// again.
struct SessionPlace {
    environment: String,
    location: &'static str,
    placement: &'static str,
}

impl SessionPlace {
    fn of(target: &EnvironmentSessionTarget) -> Self {
        let (location, placement) = match target {
            #[cfg(unix)]
            EnvironmentSessionTarget::Host { .. } => ("host", ""),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { .. } => ("local VM", "--local "),
            EnvironmentSessionTarget::Platform { .. } => ("cloud", "--cloud "),
        };
        Self {
            environment: crate::commands::progress::terminal_text(&target.current_target().name),
            location,
            placement,
        }
    }

    /// `cw --local attach app --session coding`.
    fn reconnect(&self, session: &EnvironmentSessionView) -> String {
        format!(
            "cw {}attach {} --session {}",
            self.placement,
            self.environment,
            session_reference(session)
        )
    }

    /// `Started Claude Code in app/coding · local VM`.
    fn started(&self, session: &EnvironmentSessionView, agent: Option<NativeAgent>) -> String {
        let what = match agent {
            Some(agent) => format!("{} in", agent.title()),
            None => "session".to_owned(),
        };
        format!(
            "Started {what} {}/{} · {}",
            self.environment,
            session_reference(session),
            self.location
        )
    }

    /// The key named here is the one [`AttachNavigationDecoder`] detaches
    /// on: a lowercase `d`, like the other prefix keys (#3185).
    fn detach_hint(&self, session: &EnvironmentSessionView, style: crate::output::Style) -> String {
        style.paint(
            crate::output::Role::Dim,
            &format!(
                "Detach: Ctrl-B, then d · Reconnect: {}",
                self.reconnect(session)
            ),
        )
    }
}

/// A session's name when it has one, else its canonical ID.
fn session_reference(session: &EnvironmentSessionView) -> String {
    crate::commands::progress::terminal_text(if session.name.is_empty() {
        &session.session_id
    } else {
        &session.name
    })
}

fn duplicate_session_name(
    place: &SessionPlace,
    existing: &EnvironmentSessionView,
) -> anyhow::Error {
    let name = &existing.name;
    let environment = &place.environment;
    let placement = place.placement;
    if session_is_terminal(existing) {
        anyhow::anyhow!(
            "{environment} already has a session named {name} ({}); `--name` never reuses one: restart it with `cw {placement}restart {environment} --session {name}`, or choose another --name",
            existing.state.to_lowercase()
        )
    } else {
        anyhow::anyhow!(
            "{environment} already has a session named {name} ({}); `--name` never reuses one: attach with `cw {placement}attach {environment} --session {name}`, or choose another --name",
            existing.state.to_lowercase()
        )
    }
}

/// A session name from the command's file name: `npm` for `npm test`,
/// `session` when nothing usable remains.
pub(crate) fn session_name_base(command: &[String]) -> String {
    let program = command
        .first()
        .map(|program| program.rsplit('/').next().unwrap_or(program))
        .unwrap_or_default();
    let base: String = program
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take(48)
        .collect();
    if base.is_empty() {
        "session".to_owned()
    } else {
        base
    }
}

/// `base`, or `base-2`, `base-3`, ... : the first name no retained session
/// in the environment has.
pub(crate) fn unique_session_name(base: String, sessions: &[EnvironmentSessionView]) -> String {
    let taken = |name: &str| sessions.iter().any(|session| session.name == name);
    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|index| format!("{base}-{index}"))
        .find(|name| !taken(name))
        .expect("an unused suffix exists")
}

/// Bare `cw run` on a terminal: which agent to open.
async fn choose_native_agent(
    environment: &str,
    caps: &crate::output::Capabilities,
) -> anyhow::Result<NativeAgent> {
    use crate::output::{Picker, PickerOutcome, PickerRow, run_picker};
    let rows = NativeAgent::ALL
        .iter()
        .map(|agent| {
            PickerRow::new(
                vec![agent.command().to_owned(), agent.title().to_owned()],
                format!("{} {}", agent.command(), agent.title()),
            )
        })
        .collect();
    let picker = Picker::new(
        format!("Open an agent in {environment}"),
        vec!["AGENT".to_owned(), "OPENS".to_owned()],
        rows,
    )
    .with_no_match("No matching agents. Backspace to clear the filter.");
    let caps = *caps;
    match tokio::task::spawn_blocking(move || run_picker(picker, &caps))
        .await
        .context("ask which agent to open")??
    {
        PickerOutcome::Chosen(index) => Ok(NativeAgent::ALL[index]),
        PickerOutcome::Canceled => anyhow::bail!("canceled; nothing started"),
        PickerOutcome::Unavailable => anyhow::bail!(
            "`cw run` needs an agent or a command: `cw run claude --in ENV`, `cw run codex --in ENV`, or `cw run --in ENV -- COMMAND`"
        ),
    }
}

pub(crate) async fn handle_environment_shell_command(
    globals: &Globals,
    args: EnvironmentShellArgs,
) -> anyhow::Result<()> {
    let environment =
        super::flat::select_environment("shell", args.environment, args.in_environment, &[])?;
    if args.stdio {
        // The OpenSSH ProxyCommand: a `cw-local-` alias, or any reference
        // under --local, is a local VM; everything else is the cloud.
        let alias = environment.as_deref().and_then(SshAlias::parse);
        if let Some(alias) = alias {
            alias.check_placement(globals.placement)?;
            if alias.is_local(globals.placement) {
                let environment = local_ssh_target(alias).await?;
                return super::native::native_pipe_ssh(&environment).await;
            }
        }
        if globals.placement == Some(EnvironmentPlacement::Local) {
            return super::native::native_shell_stdio(None).await;
        }
        return handle_shell_stdio(globals, environment.as_deref()).await;
    }
    if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
        super::core::init_tailnet_debug_log();
    }
    if !args.durable {
        // A hosted environment gets a normal shell over its tailnet; local
        // VMs and trusted hosts keep their own direct paths below.
        let target = resolve_environment_session_target(globals, environment.as_deref()).await?;
        if let EnvironmentSessionTarget::Platform {
            org_id,
            environment_id,
            client,
            ..
        } = &target
        {
            let status = super::tailnet_shell::run(client, org_id, environment_id).await?;
            if status != 0 {
                // As `ssh` does: the shell's own status, no message.
                std::process::exit(status);
            }
            return Ok(());
        }
    }
    launch_run(
        globals,
        EnvironmentRunArgs {
            org: None,
            request_id: None,
            native_agent: None,
            environment,
            name: None,
            parent: None,
            agent: None,
            model: None,
            effort: None,
            prompt: None,
            workdir: None,
            env: Vec::new(),
            tty: true,
            no_tty: false,
            detach: false,
            yes: false,
            output: OutputFormat::Text,
            command: login_shell_command(),
        },
        Some("shell"),
    )
    .await
}

/// The workspace user's own shell as a login shell: `$SHELL` in the
/// workspace (the user's passwd shell in a local VM), so line editing,
/// history and the user's rc files work. A bare `/bin/sh` is dash on the
/// workspace image and has none of them.
pub(crate) fn login_shell_command() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exec \"${SHELL:-/bin/sh}\" -l".to_string(),
    ]
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
    StreamEnded {
        output_offset: u64,
    },
    StreamInterrupted {
        output_offset: u64,
    },
    /// The tailnet came back while on the API; reattach over it from here.
    TailnetBack {
        output_offset: u64,
    },
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

/// Attach to a hosted environment's session over its tailnet first: direct
/// UDP, then peer relay, then DERP (#3827). The API carries it only when the
/// tailnet cannot, and the line before the session says which path it took
/// and why. `CW_SSH_TRANSPORT=tailnet` refuses the API fallback;
/// `CW_SSH_TRANSPORT=websocket` skips the tailnet.
pub(crate) async fn attach_platform_session(
    client: &codewire_client::CodewireClient,
    open: codewire_client::AttachSessionOpen,
    tailnet: &mut Option<codewire_client::tailnet_session::EnvironmentTailnet>,
) -> anyhow::Result<codewire_client::EnvironmentSessionAttachment> {
    let (attachment, via) = codewire_client::hosted_shell::attach(client, open, tailnet)
        .await
        .map_err(super::tailnet_shell::display_hosted_shell_error)?;
    eprintln!("{}", via_line(&via));
    Ok(attachment)
}

/// Attach over the API, once the server has answered: only then is the
/// session reached, whatever the stream says about itself (#3895).
async fn attach_over_api(
    client: &codewire_client::CodewireClient,
    open: codewire_client::AttachSessionOpen,
) -> anyhow::Result<codewire_client::EnvironmentSessionAttachment> {
    codewire_client::hosted_shell::attach_over_api(client, open)
        .await
        .map_err(display_client_error)
}

/// The line before a hosted session that says which path it took.
pub(crate) fn via_line(via: &codewire_client::hosted_shell::Via) -> String {
    match via {
        codewire_client::hosted_shell::Via::Tailnet(report) => tailnet_path_line(report.clone()),
        codewire_client::hosted_shell::Via::Api {
            tailnet_unavailable,
        } => format!("  via API · tailnet unavailable: {tailnet_unavailable}"),
    }
}

pub(crate) fn tailnet_path_line(
    report: Option<codewire_client::tailnet_session::TailnetPathReport>,
) -> String {
    match report {
        Some(report) => match report.reason {
            None => format!("  via {}", report.path.label()),
            Some(reason) => format!(
                "  via {} · direct UDP unavailable: {reason}",
                report.path.label()
            ),
        },
        None => "  via the tailnet".into(),
    }
}

async fn attach_environment_session(
    globals: &Globals,
    mut target: EnvironmentSessionTarget,
    mut session: EnvironmentSessionView,
) -> anyhow::Result<Option<EnvironmentSessionView>> {
    let mut output_offset = 0;
    let mut reconnect_budget = AttachmentReconnectBudget::default();
    let mut pacing = super::tailnet_shell::ReconnectPacing::default();
    // Survives reconnects, which resume the same output, so the program's
    // screen is given back only when this terminal leaves it.
    let mut screen = SessionScreen::new(std::io::stdout().is_terminal());
    // One tailnet connection to a hosted environment, kept for every
    // reattachment while it lives (#3827).
    let mut tailnet = None;
    let mut retry_after = codewire_client::hosted_shell::TAILNET_RETRY_FIRST;
    // This shell's input stream, kept across its reattachments (#3993).
    let mut input_stream = InputStream::default();
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
                    &mut screen,
                )
                .await?
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { environment_id, .. } => {
                let client = native_environment_session_client(environment_id).await?;
                let attachment = client.attach(&session.session_id, output_offset).await?;
                attach_platform_environment_session(
                    attachment,
                    output_offset,
                    &mut input_stream,
                    session.pty,
                    true,
                    &mut screen,
                    std::future::pending(),
                )
                .await?
            }
            EnvironmentSessionTarget::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                match attach_platform_session(
                    client,
                    codewire_client::AttachSessionOpen {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session.session_id.clone(),
                        output_offset,
                        input_stream: input_stream.open().0,
                        input_offset: input_stream.open().1,
                        ..Default::default()
                    },
                    &mut tailnet,
                )
                .await
                {
                    Ok(attachment) => {
                        pacing.attached();
                        if tailnet.is_some() {
                            retry_after = codewire_client::hosted_shell::TAILNET_RETRY_FIRST;
                        }
                        let on_fallback = codewire_client::hosted_shell::on_api_fallback(&tailnet)?;
                        let back = async {
                            if !on_fallback {
                                return std::future::pending().await;
                            }
                            tailnet = Some(
                                codewire_client::hosted_shell::tailnet_again(
                                    client,
                                    org_id,
                                    environment_id,
                                    retry_after,
                                )
                                .await,
                            );
                        };
                        attach_platform_environment_session(
                            attachment,
                            output_offset,
                            &mut input_stream,
                            session.pty,
                            true,
                            &mut screen,
                            back,
                        )
                        .await?
                    }
                    Err(error)
                        if pacing.reconnecting()
                            && super::tailnet_shell::is_network_failure(&error) =>
                    {
                        tracing::debug!(error = %format!("{error:#}"), "reattach failed");
                        AttachExit::StreamInterrupted { output_offset }
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        if !matches!(
            exit,
            AttachExit::StreamEnded { .. }
                | AttachExit::StreamInterrupted { .. }
                | AttachExit::TailnetBack { .. }
        ) {
            screen.release();
        }
        match exit {
            AttachExit::Detached => {
                // The terminal is out of raw mode again: say where the
                // session went and how to come back.
                let place = SessionPlace::of(&target);
                eprintln!(
                    "Detached from {}/{}; it keeps running. Reconnect: {}",
                    place.environment,
                    session_reference(&session),
                    place.reconnect(&session)
                );
                return Ok(None);
            }
            AttachExit::Terminal => return target.get(&session.session_id).await.map(Some),
            AttachExit::StreamEnded {
                output_offset: next_offset,
            }
            | AttachExit::StreamInterrupted {
                output_offset: next_offset,
            } => {
                let interrupted = matches!(exit, AttachExit::StreamInterrupted { .. });
                output_offset = next_offset;
                let refreshed = target.get_unless_unreachable(&session.session_id).await?;
                let unreachable = refreshed.is_none();
                if let Some(refreshed) = refreshed {
                    if session_is_terminal(&refreshed) {
                        return Ok(Some(refreshed));
                    }
                    session = refreshed;
                }
                if interrupted || unreachable {
                    let delay = if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
                        pacing.lost(next_offset).ok_or_else(|| {
                            anyhow::anyhow!(
                                "the connection to the environment was lost for 10 minutes; the session keeps running. Reconnect: {}",
                                SessionPlace::of(&target).reconnect(&session)
                            )
                        })?
                    } else {
                        reconnect_budget.retry_delay(next_offset)?
                    };
                    tokio::time::sleep(delay).await;
                }
            }
            AttachExit::TailnetBack {
                output_offset: next_offset,
            } => {
                output_offset = next_offset;
                // Longer next time, if this attachment lands on the API again.
                retry_after = codewire_client::hosted_shell::next_retry(retry_after);
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

/// Carry one attachment opened at `start_offset`. It ends early if
/// `tailnet_back` completes.
/// Passes an attachment's status to its input stream (#3993): on the first
/// one, sends the resend and the held keys and says what happened to the keys
/// typed during a drop. False when the attachment closed meanwhile.
async fn send_stream_status(
    input: &codewire_client::EnvironmentSessionAttachmentInput,
    input_stream: &mut InputStream,
    status: &codewire_client::AttachSessionStatus,
) -> bool {
    let written = status
        .session
        .as_option()
        .and_then(|session| session.input_end_offset);
    let (requests, notices) = input_stream.status(written, std::time::Instant::now());
    for notice in notices {
        match notice {
            InputNotice::Resent(keys) => {
                eprint!("\r\n[cw] resent {keys} key(s) typed during the drop\r\n");
            }
            InputNotice::Lost(keys) => {
                eprint!("\r\n[cw] {keys} key(s) typed during the drop were lost\r\n");
            }
        }
    }
    for request in requests {
        if input.send(request).await.is_err() {
            return false;
        }
    }
    true
}

async fn attach_platform_environment_session(
    mut attachment: codewire_client::EnvironmentSessionAttachment,
    start_offset: u64,
    input_stream: &mut InputStream,
    interactive: bool,
    raw_output: bool,
    screen: &mut SessionScreen,
    tailnet_back: impl std::future::Future<Output = ()>,
) -> anyhow::Result<AttachExit> {
    tokio::pin!(tailnet_back);
    let input = attachment.input_handle();
    let mut stdin = crate::terminal_attach::terminal_input().await;
    let mut stdin_buf = [0_u8; 4096];
    let mut stdout = std::io::stdout();
    let interactive =
        interactive && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let _raw = interactive
        .then(RawModeGuard::enable)
        .transpose()
        .context("enabling raw mode")?;
    let mut decoder = AttachNavigationDecoder::default();
    let mut output_offset = start_offset;
    let mut stdin_closed = !interactive;
    let mut output_open = true;
    let mut terminal = false;
    // `interactive` is set only for a PTY session on a terminal. Its PTY
    // follows this terminal's size; a lost resize is cosmetic.
    let mut window = crate::terminal_attach::WindowSizeWatch::new(interactive);
    let resize = |(columns, rows): (u16, u16)| codewire_client::AttachSessionRequest {
        input: Some(codewire_client::attach_session_request::Input::Resize(
            Box::new(codewire_client::AttachSessionResize {
                columns: u32::from(columns),
                rows: u32::from(rows),
                ..Default::default()
            }),
        )),
        ..Default::default()
    };
    if let Some(size) = window.current() {
        let _ = input.send(resize(size)).await;
    }
    // Keys wait for this attachment's first status, which says whether the
    // server keeps input offsets (#3993).
    input_stream.attaching();
    loop {
        if !output_open && stdin_closed {
            return Ok(if terminal {
                AttachExit::Terminal
            } else {
                AttachExit::StreamEnded { output_offset }
            });
        }
        tokio::select! {
            () = &mut tailnet_back, if output_open => {
                return Ok(AttachExit::TailnetBack { output_offset });
            }
            size = window.changed(), if output_open => {
                if let Some(size) = size {
                    let _ = input.send(resize(size)).await;
                }
            }
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
                        if raw_output {
                            screen.observe(&output.data);
                        }
                        write_session_output(&mut stdout, &output.data, raw_output)?;
                        output_offset = output.next_offset;
                    }
                    Some(codewire_client::attach_session_response::Event::Status(status))
                        if status.session.as_option().is_some_and(platform_session_is_terminal) => {
                        send_stream_status(&input, input_stream, &status).await;
                        terminal = true;
                        if !interactive {
                            return Ok(AttachExit::Terminal);
                        }
                        screen.release();
                        eprint!("[cw] session exited; Ctrl+B r restarts, Ctrl+C leaves\r\n");
                    }
                    Some(codewire_client::attach_session_response::Event::Status(status)) => {
                        let sent = send_stream_status(&input, input_stream, &status).await;
                        if !sent {
                            return Ok(AttachExit::StreamInterrupted { output_offset });
                        }
                    }
                    None => {}
                }
            }
            read = stdin.read(&mut stdin_buf), if !stdin_closed => {
                let read = read.context("read terminal input")?;
                if read == 0 {
                    let pending = decoder.finish();
                    if !pending.is_empty()
                        && let Some(request) = input_stream.typed(pending, std::time::Instant::now())
                    {
                        input.send(request).await.map_err(display_client_error)?;
                    }
                    stdin_closed = true;
                    continue;
                }
                let (action, forward) = decoder.feed(&stdin_buf[..read]);
                if terminal {
                    // The program is gone and its attachment closed, so
                    // keystrokes have nowhere to go. Ctrl-C, Ctrl-D and
                    // Ctrl+B d leave; the session no longer runs.
                    if forward.iter().any(|byte| matches!(byte, 0x03 | 0x04))
                        || action == Some(AttachExit::Detached)
                    {
                        return Ok(AttachExit::Terminal);
                    }
                    if let Some(action) = action {
                        return Ok(action);
                    }
                    continue;
                }
                if !forward.is_empty()
                    && let Some(request) = input_stream.typed(forward, std::time::Instant::now())
                {
                    input.send(request).await.map_err(display_client_error)?;
                }
                if let Some(action) = action {
                    if matches!(action, AttachExit::Detached) && output_open {
                        // Detaching is local: an attachment that closed
                        // meanwhile needs no notice.
                        let _ = input.send(codewire_client::AttachSessionRequest {
                            input: Some(codewire_client::attach_session_request::Input::Detach(Box::default())),
                            ..Default::default()
                        }).await;
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
        SessionSelection::Create
            if should_create_session(&crate::commands::progress::terminal_text(
                &target.current_target().name,
            ))? =>
        {
            target
                .launch(
                    login_shell_command(),
                    target.default_working_dir(),
                    BTreeMap::new(),
                    true,
                    // Only an environment without sessions gets here.
                    "shell".to_owned(),
                    String::new(),
                )
                .await
        }
        SessionSelection::Create => {
            let environment = &target.current_target().name;
            anyhow::bail!(
                "{environment} has no sessions; start one with `cw shell {environment}`, `cw run claude --in {environment}` or `cw run --in {environment} -- COMMAND`"
            )
        }
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

pub(crate) fn platform_session_is_terminal(session: &codewire_client::EnvironmentSession) -> bool {
    codewire_client::hosted_shell::session_has_ended(session)
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

/// The sessions of the environment `target` names, as `cw ls` counts them.
pub(crate) async fn list_target_sessions(
    globals: &Globals,
    target: config::CurrentTargetConfig,
) -> anyhow::Result<Vec<EnvironmentSessionView>> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    environment_session_target_from_current(globals, &paths, &OsEnv, target)
        .await?
        .list()
        .await
}

/// `cw ls ENV`: that environment's sessions with their recorded mode.
pub(crate) async fn handle_environment_sessions_list(
    globals: &Globals,
    environment: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let target = resolve_environment_session_target(globals, Some(environment)).await?;
    let sessions = match target.list().await {
        Ok(sessions) => sessions,
        Err(error) => return Err(stopped_environment_sessions(&target).await.unwrap_or(error)),
    };
    print_environment_sessions(&sessions, output)
}

/// A local VM lists its sessions only while it runs: say so, with the
/// repair, instead of the supervisor's state refusal.
async fn stopped_environment_sessions(target: &EnvironmentSessionTarget) -> Option<anyhow::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let EnvironmentSessionTarget::NativeLocal { target, .. } = target {
        let environment = native_environment(&target.name).await.ok()??;
        if environment.state != codewire_local_vmm::control::v1::EnvironmentState::Running as i32 {
            let name = &target.name;
            return Some(anyhow::anyhow!(
                "{name} is {}; its sessions are listed while it runs (`cw start {name}`)",
                native_state_label(environment.state)
            ));
        }
    }
    let _ = target;
    None
}

pub(crate) async fn handle_attach_command(
    globals: &Globals,
    args: AttachArgs,
) -> anyhow::Result<()> {
    let environment = super::flat::select_environment(
        "attach",
        args.environment,
        args.in_environment,
        &args.retired_session,
    )?;
    let requested = args
        .session
        .and_then(|session| trimmed_str(&session).map(str::to_owned));
    anyhow::ensure!(
        environment.is_some() || requested.is_some(),
        "missing environment: `cw attach ENV` attaches to its session; `cw attach --session SESSION` attaches in the selected environment"
    );
    let target = resolve_environment_session_target(globals, environment.as_deref())
        .await
        .map_err(|error| match (&environment, &requested) {
            // A positional is always an environment; say how to name a
            // session instead, without looking one up.
            (Some(environment), None) => error.context(format!(
                "`cw attach {environment}` names an environment; for a session in the selected environment use `cw attach --session {environment}`"
            )),
            _ => error,
        })?;
    let place = SessionPlace::of(&target);
    let session = match requested.as_deref() {
        Some(requested) => match select_environment_session(&target, Some(requested)).await? {
            SessionSelection::Select(session) => *session,
            SessionSelection::Create => anyhow::bail!("session {requested:?} not found"),
        },
        None => select_attach_session(&target, &place).await?,
    };
    let caps = crate::output::Capabilities::from_process(crate::output::OutputMode::Text);
    let style = caps.stderr_style();
    eprintln!(
        "{} Attaching to {}/{} · {}",
        style.status(crate::output::Status::Next),
        place.environment,
        session_reference(&session),
        place.location
    );
    if session.pty && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        eprintln!("  {}", place.detach_hint(&session, style));
    }
    let _ = attach_environment_session(globals, target, session).await?;
    Ok(())
}

/// `cw attach ENV` without `--session`: its only session, named on screen;
/// a choice among several on a terminal; for a script, the `--session`
/// repair. With none, a terminal may start a shell.
async fn select_attach_session(
    target: &EnvironmentSessionTarget,
    place: &SessionPlace,
) -> anyhow::Result<EnvironmentSessionView> {
    let environment = &place.environment;
    let sessions = match target.list().await {
        Ok(sessions) => sessions,
        Err(error) => return Err(stopped_environment_sessions(target).await.unwrap_or(error)),
    };
    match sessions.as_slice() {
        [] => select_or_create_environment_session(target).await,
        [session] => {
            eprintln!(
                "{environment} has one session, {}.",
                session_reference(session)
            );
            Ok(session.clone())
        }
        _ => {
            let repair = format!(
                "{environment} has {} sessions; name one: `cw attach {environment} --session SESSION` (`cw ls {environment}` lists them)",
                sessions.len()
            );
            select_session_from_picker(environment, &sessions, "to attach to", repair).await
        }
    }
}

/// `cw logs [ENV] [--session S]` after its selectors were checked.
#[derive(Debug)]
pub(crate) struct SessionLogs {
    pub(crate) environment: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) follow: bool,
    pub(crate) tail: Option<u32>,
    pub(crate) raw: bool,
}

pub(crate) async fn handle_logs_command(
    globals: &Globals,
    args: SessionLogs,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::member_control::terminal::logs(globals, args).await;
    }
    let target = resolve_environment_session_target(globals, args.environment.as_deref()).await?;
    let session = match args.session.as_deref() {
        Some(requested) => match select_environment_session(&target, Some(requested)).await? {
            SessionSelection::Select(session) => *session,
            SessionSelection::Create => anyhow::bail!("session {requested:?} not found"),
        },
        None => select_logs_session(&target).await?,
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

/// Without --session, an interactive call shows the only session (naming
/// it) or offers a choice; a script must name the source.
async fn select_logs_session(
    target: &EnvironmentSessionTarget,
) -> anyhow::Result<EnvironmentSessionView> {
    let environment = target.current_target().name.clone();
    anyhow::ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "name the log source: `cw logs {environment} --session SESSION`, or `--setup` for setup logs"
    );
    let sessions = target.list().await?;
    match sessions.as_slice() {
        [] => anyhow::bail!(
            "{environment} has no sessions; its setup logs: `cw logs {environment} --setup`"
        ),
        [session] => {
            eprintln!(
                "Showing session {} in {environment}.",
                session_label(session)
            );
            Ok(session.clone())
        }
        _ => {
            let repair = format!(
                "name the log source: `cw logs {environment} --session SESSION`, or `--setup` for setup logs"
            );
            select_session_from_picker(&environment, &sessions, "to show", repair).await
        }
    }
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
    let mut pacing = super::tailnet_shell::ReconnectPacing::default();
    let mut input_stream = InputStream::default();
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
                    &mut SessionScreen::new(false),
                )
                .await?
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { environment_id, .. } => {
                let client = native_environment_session_client(environment_id).await?;
                attach_platform_environment_session(
                    client.attach(&session.session_id, output_offset).await?,
                    output_offset,
                    &mut input_stream,
                    false,
                    raw_output,
                    &mut SessionScreen::new(false),
                    std::future::pending(),
                )
                .await?
            }
            EnvironmentSessionTarget::Platform {
                org_id,
                environment_id,
                client,
                ..
            } => {
                match attach_over_api(
                    client,
                    codewire_client::AttachSessionOpen {
                        org_id: org_id.clone(),
                        environment_id: environment_id.clone(),
                        session_id: session.session_id.clone(),
                        output_offset,
                        input_stream: input_stream.open().0,
                        input_offset: input_stream.open().1,
                        ..Default::default()
                    },
                )
                .await
                {
                    Ok(attachment) => {
                        pacing.attached();
                        attach_platform_environment_session(
                            attachment,
                            output_offset,
                            &mut input_stream,
                            false,
                            raw_output,
                            &mut SessionScreen::new(false),
                            std::future::pending(),
                        )
                        .await?
                    }
                    Err(error)
                        if pacing.reconnecting()
                            && super::tailnet_shell::is_network_failure(&error) =>
                    {
                        tracing::debug!(error = %format!("{error:#}"), "reattach failed");
                        AttachExit::StreamInterrupted { output_offset }
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        match exit {
            AttachExit::Terminal => return Ok(()),
            AttachExit::StreamEnded {
                output_offset: next_offset,
            }
            | AttachExit::StreamInterrupted {
                output_offset: next_offset,
            } => {
                let interrupted = matches!(exit, AttachExit::StreamInterrupted { .. });
                output_offset = next_offset;
                let refreshed = target.get_unless_unreachable(&session.session_id).await?;
                let unreachable = refreshed.is_none();
                if refreshed.is_some_and(|refreshed| session_is_terminal(&refreshed)) {
                    return Ok(());
                }
                if interrupted || unreachable {
                    let delay = if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
                        pacing.lost(next_offset).ok_or_else(|| {
                            anyhow::anyhow!(
                                "the connection to the environment was lost for 10 minutes; the session keeps running. Reconnect: {}",
                                SessionPlace::of(target).reconnect(session)
                            )
                        })?
                    } else {
                        reconnect_budget.retry_delay(next_offset)?
                    };
                    tokio::time::sleep(delay).await;
                }
            }
            _ => unreachable!("non-interactive attachment produced navigation"),
        }
    }
}

#[cfg(test)]
mod attach_offset_tests {
    use super::*;

    fn platform_target(address: std::net::SocketAddr) -> EnvironmentSessionTarget {
        let config = codewire_client::ClientConfig::new(format!("http://{address}"))
            .expect("server URL")
            .with_unary_timeout(Duration::from_millis(200));
        let client = codewire_client::CodewireClient::with_http(
            config,
            codewire_client::StaticTokenProvider::new("synthetic-token").expect("token"),
            reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("client"),
        )
        .expect("client");
        EnvironmentSessionTarget::Platform {
            target: config::CurrentTargetConfig::default(),
            org_id: "org".into(),
            environment_id: "env".into(),
            client: Box::new(client),
        }
    }

    #[tokio::test]
    async fn a_session_read_with_no_answer_does_not_end_the_attachment() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let silent = platform_target(listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });
        assert!(
            silent
                .get_unless_unreachable("session")
                .await
                .expect("no answer is not a failure")
                .is_none()
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_session_read_with_no_server_does_not_end_the_attachment() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let refused = platform_target(listener.local_addr().expect("address"));
        drop(listener);
        assert!(
            refused
                .get_unless_unreachable("session")
                .await
                .expect("no server is not a failure")
                .is_none()
        );
    }

    fn output(
        next_offset: u64,
    ) -> Result<codewire_client::AttachSessionResponse, codewire_client::ClientError> {
        Ok(codewire_client::AttachSessionResponse {
            event: Some(codewire_client::attach_session_response::Event::Output(
                Box::new(codewire_client::EnvironmentSessionOutputChunk {
                    next_offset,
                    ..Default::default()
                }),
            )),
            ..Default::default()
        })
    }

    async fn carry(
        outputs: tokio::sync::mpsc::Receiver<
            Result<codewire_client::AttachSessionResponse, codewire_client::ClientError>,
        >,
        start_offset: u64,
        tailnet_back: impl std::future::Future<Output = ()>,
    ) -> AttachExit {
        attach_platform_environment_session(
            codewire_client::EnvironmentSessionAttachment::from_output(outputs),
            start_offset,
            &mut InputStream::default(),
            false,
            false,
            &mut SessionScreen::new(false),
            tailnet_back,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn an_attachment_that_ends_before_any_output_keeps_the_offset_it_opened_at() {
        // Reporting 0 here would replay the session's whole history to the
        // terminal on the next attachment.
        let (sender, outputs) = tokio::sync::mpsc::channel(1);
        drop(sender);
        assert_eq!(
            carry(outputs, 42, std::future::pending()).await,
            AttachExit::StreamEnded { output_offset: 42 }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_attachment_on_the_api_moves_at_its_output_offset_when_the_tailnet_is_back() {
        let (sender, outputs) = tokio::sync::mpsc::channel(1);
        sender.send(output(50)).await.unwrap();
        let back = tokio::time::sleep(Duration::from_secs(5));
        assert_eq!(
            carry(outputs, 42, back).await,
            AttachExit::TailnetBack { output_offset: 50 }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_attachment_on_the_api_moves_at_the_offset_it_opened_at() {
        let (_sender, outputs) = tokio::sync::mpsc::channel(1);
        let back = tokio::time::sleep(Duration::from_secs(5));
        assert_eq!(
            carry(outputs, 42, back).await,
            AttachExit::TailnetBack { output_offset: 42 }
        );
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod run_output_tests {
    use super::*;

    fn local_vm(name: &str) -> EnvironmentSessionTarget {
        EnvironmentSessionTarget::NativeLocal {
            target: config::CurrentTargetConfig {
                kind: "local".into(),
                target_ref: name.into(),
                name: name.into(),
            },
            environment_id: format!("{name}-id"),
            working_dir: "/workspace".into(),
        }
    }

    fn session(name: &str, state: &str) -> EnvironmentSessionView {
        EnvironmentSessionView {
            session_id: "session-11111111-1111-4111-8111-111111111111".into(),
            name: name.into(),
            parent_session_id: String::new(),
            cleanup_unknown: false,
            started_at: String::new(),
            launch_generation: 1,
            state: state.into(),
            command: vec!["claude".into()],
            working_dir: "/workspace".into(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    #[test]
    fn run_and_attach_name_the_session_and_the_way_back() {
        let place = SessionPlace::of(&local_vm("app"));
        let coding = session("coding", "Running");
        assert_eq!(
            place.reconnect(&coding),
            "cw --local attach app --session coding"
        );
        assert_eq!(
            place.started(&coding, Some(NativeAgent::Claude)),
            "Started Claude Code in app/coding · local VM"
        );
        assert_eq!(
            place.started(&coding, None),
            "Started session app/coding · local VM"
        );
        let plain = crate::output::Style::new(false, crate::output::Charset::Unicode);
        assert_eq!(
            place.detach_hint(&coding, plain),
            "Detach: Ctrl-B, then d · Reconnect: cw --local attach app --session coding"
        );
        // An unnamed session is named by its ID.
        assert_eq!(
            place.reconnect(&session("", "Running")),
            "cw --local attach app --session session-11111111-1111-4111-8111-111111111111"
        );
        // Names reach the terminal without control characters.
        let hostile = SessionPlace::of(&local_vm("a\x1b[2Jb"));
        assert!(!hostile.reconnect(&coding).contains('\x1b'));
    }

    #[test]
    fn a_pty_session_always_starts_with_a_size() {
        assert_eq!(session_terminal_size(false), (0, 0));
        // This terminal's size, or 80x24 when the command has none.
        let (columns, rows) = session_terminal_size(true);
        assert!(columns > 0 && rows > 0);
        assert_eq!(DEFAULT_PTY_SIZE, (80, 24));
    }

    #[test]
    fn a_taken_name_is_refused_with_the_way_to_reach_that_session() {
        let place = SessionPlace::of(&local_vm("app"));
        assert_eq!(
            duplicate_session_name(&place, &session("coding", "Running")).to_string(),
            "app already has a session named coding (running); `--name` never reuses one: attach with `cw --local attach app --session coding`, or choose another --name"
        );
        assert_eq!(
            duplicate_session_name(&place, &session("coding", "Exited")).to_string(),
            "app already has a session named coding (exited); `--name` never reuses one: restart it with `cw --local restart app --session coding`, or choose another --name"
        );
    }
}
