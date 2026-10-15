//! Platform managed CLI calls. Each conversation keeps one original scope;
//! local wait indexes contain metadata only, never live requests or tokens.
use super::*;
use buffa::Message as _;
use codewire_client::platform_agents as rpc;
use sha2::Digest as _;

/// Recovery references retain the original request identity before dispatch.
/// Only its digest is saved: prompts and selected environment values stay out
/// of the local operation index.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestReference {
    version: u32,
    org_id: String,
    environment_id: String,
    scope: rpc::EnvironmentAgentScope,
    request_id: String,
    request_sha256: String,
    action: String,
    session_id: String,
    driver_id: String,
    launch_generation: u64,
}

fn save_request_at(
    directory: &Path,
    request: &rpc::MutateEnvironmentAgentRequest,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        codewire_daemon_proto::platform_managed::valid_uuid(&request.request_id),
        "managed request UUID must be canonical and nonnil"
    );
    let encoded = request.encode_to_vec();
    anyhow::ensure!(
        encoded.len() <= 256 * 1024,
        "managed request exceeds its bound"
    );
    let (action, session_id, driver_id, generation) = match request.operation.as_ref() {
        Some(rpc::mutate_environment_agent_request::Operation::Launch(_)) => (
            "Launch".to_owned(),
            format!("session-{}", request.request_id),
            request.request_id.clone(),
            1,
        ),
        Some(rpc::mutate_environment_agent_request::Operation::Control(control)) => (
            format!(
                "{:?}",
                control
                    .action
                    .as_known()
                    .context("managed action is unknown")?
            ),
            control.session_id.clone(),
            control.driver_id.clone(),
            control.expected_launch_generation,
        ),
        None => anyhow::bail!("managed operation is required"),
    };
    let reference = RequestReference {
        version: 1,
        org_id: request.org_id.clone(),
        environment_id: request.environment_id.clone(),
        scope: request
            .expected_scope
            .as_option()
            .context("original managed scope is required")?
            .clone(),
        request_id: request.request_id.clone(),
        request_sha256: format!("{:x}", sha2::Sha256::digest(&encoded)),
        action,
        session_id,
        driver_id,
        launch_generation: generation,
    };
    private_directory(directory)?;
    let _lock = StateLock::try_acquire(&directory.join(format!("{}.lock", request.request_id)))?
        .context("managed request reference is being written; no request was sent")?;
    let path = directory.join(format!("{}.json", request.request_id));
    if let Some(saved) = read_optional::<RequestReference>(&path)? {
        anyhow::ensure!(
            saved == reference,
            "managed request UUID already names a different original request; observe its outcome"
        );
        return Ok(());
    }
    write_private_json(&path, &reference)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageLocation {
    version: u32,
    org_id: String,
    environment_id: String,
    scope: rpc::EnvironmentAgentScope,
    session_id: String,
    driver_id: String,
    launch_generation: u64,
    message_id: String,
}
struct Endpoint {
    org_id: String,
    environment_id: String,
    client: codewire_client::CodewireClient,
    scope: rpc::EnvironmentAgentScope,
}
struct Conversation {
    endpoint: Endpoint,
    session: codewire_client::EnvironmentSession,
    driver_id: String,
    /// Continued here from an earlier Pod by this command: its driver is
    /// already starting, so a Restart has nothing left to do.
    resumed: bool,
}
fn request_id(value: Option<&str>) -> anyhow::Result<String> {
    let id = value
        .map(canonical_uuid)
        .transpose()?
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    anyhow::ensure!(
        codewire_daemon_proto::platform_managed::valid_uuid(&id),
        "request UUID must be canonical and nonnil"
    );
    Ok(id)
}
fn platform(
    target: &EnvironmentSessionTarget,
) -> anyhow::Result<(&str, &str, &codewire_client::CodewireClient)> {
    match target {
        EnvironmentSessionTarget::Platform {
            org_id,
            environment_id,
            client,
            ..
        } => Ok((org_id, environment_id, client)),
        _ => anyhow::bail!("this managed command requires a platform environment"),
    }
}
async fn capture(
    target: &EnvironmentSessionTarget,
) -> anyhow::Result<(Endpoint, Vec<rpc::EnvironmentAgentSupport>)> {
    let (org, env, client) = platform(target)?;
    let response = client
        .get_environment_agent_info(rpc::GetEnvironmentAgentInfoRequest {
            org_id: org.into(),
            environment_id: env.into(),
            ..Default::default()
        })
        .await?;
    Ok((
        Endpoint {
            org_id: org.into(),
            environment_id: env.into(),
            client: client.clone(),
            scope: response
                .scope
                .into_option()
                .context("platform agent info omitted original scope")?,
        },
        response.agents,
    ))
}
impl Endpoint {
    async fn find(&self, reference: &str) -> anyhow::Result<codewire_client::EnvironmentSession> {
        if let Some(session) = self.find_in_scope(reference).await? {
            return Ok(session);
        }
        if self.earlier(reference).await?.is_some() {
            anyhow::bail!(stopped_with_environment(&self.environment_id, reference));
        }
        anyhow::bail!("managed platform session {reference:?} was not found in the original scope")
    }
    /// [`Self::find`], continuing a conversation of an earlier Pod of this
    /// environment here first (#2705), and whether it did. The platform
    /// chooses that Pod, proves it gone and refuses plainly when the
    /// conversation cannot continue.
    async fn find_or_resume(
        &self,
        reference: &str,
    ) -> anyhow::Result<(codewire_client::EnvironmentSession, bool)> {
        if let Some(session) = self.find_in_scope(reference).await? {
            return Ok((session, false));
        }
        let Some(earlier) = self.earlier(reference).await? else {
            anyhow::bail!(
                "managed platform session {reference:?} was not found in the original scope"
            )
        };
        self.resume(reference, &earlier).await?;
        let session = self
            .find_in_scope(reference)
            .await?
            .context("the resumed managed conversation is not listed in the environment")?;
        Ok((session, true))
    }
    async fn resume(
        &self,
        reference: &str,
        earlier: &codewire_client::EnvironmentSession,
    ) -> anyhow::Result<()> {
        let driver_id = earlier
            .session_id
            .strip_prefix("session-")
            .filter(|id| codewire_daemon_proto::platform_managed::valid_uuid(id))
            .context("managed session has invalid identity")?;
        anyhow::ensure!(
            earlier.launch_generation > 0,
            "managed session generation is unknown"
        );
        let control = rpc::EnvironmentAgentControl {
            action: rpc::EnvironmentAgentAction::Resume.into(),
            session_id: earlier.session_id.clone(),
            driver_id: driver_id.into(),
            expected_launch_generation: earlier.launch_generation,
            ..Default::default()
        };
        eprintln!(
            "Managed conversation {reference:?} stopped with its environment; resuming it here."
        );
        let id = request_id(None)?;
        self.mutate(
            &id,
            rpc::mutate_environment_agent_request::Operation::Control(Box::new(control)),
            None,
        )
        .await?;
        Ok(())
    }
    async fn find_in_scope(
        &self,
        reference: &str,
    ) -> anyhow::Result<Option<codewire_client::EnvironmentSession>> {
        let mut after = String::new();
        // Bounded complete pages. No name fallback after a canonical identity
        // mismatch, and no selection of a newer scope during pagination.
        for _ in 0..128 {
            let response = self
                .client
                .list_environment_agents(rpc::ListEnvironmentAgentsRequest {
                    org_id: self.org_id.clone(),
                    environment_id: self.environment_id.clone(),
                    expected_scope: Some(self.scope.clone()).into(),
                    after_session_id: after.clone(),
                    ..Default::default()
                })
                .await?;
            for session in response.sessions {
                if session.session_id == reference || session.name == reference {
                    anyhow::ensure!(
                        session.launch_generation > 0,
                        "managed session generation is unknown"
                    );
                    return Ok(Some(session));
                }
            }
            if response.next_after_session_id.is_empty() {
                break;
            }
            anyhow::ensure!(
                response.next_after_session_id > after,
                "platform agent pagination did not advance"
            );
            after = response.next_after_session_id;
        }
        Ok(None)
    }
    /// The managed conversation `reference` names in an earlier incarnation
    /// of this environment: the session list still shows it, but the current
    /// scope does not, because a Stop/Start ended its Pod (#2705).
    async fn earlier(
        &self,
        reference: &str,
    ) -> anyhow::Result<Option<codewire_client::EnvironmentSession>> {
        let sessions = self
            .client
            .list_sessions(codewire_client::ListSessionsRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?
            .sessions;
        Ok(sessions.into_iter().find(|session| {
            (session.session_id == reference || session.name == reference)
                && is_platform_driver(&session.command)
        }))
    }
    async fn mutate(
        &self,
        id: &str,
        operation: rpc::mutate_environment_agent_request::Operation,
        output: Option<OutputFormat>,
    ) -> anyhow::Result<rpc::EnvironmentAgentOperation> {
        let request = rpc::MutateEnvironmentAgentRequest {
            org_id: self.org_id.clone(),
            environment_id: self.environment_id.clone(),
            request_id: id.into(),
            expected_scope: Some(self.scope.clone()).into(),
            operation: Some(operation),
            ..Default::default()
        };
        save_request_at(
            &ResolvePaths::from_env(&OsEnv)?
                .platform_config_dir
                .join("platform-managed-operations-v1"),
            &request,
        )?;
        let result = self.client.mutate_environment_agent(request).await;
        let response = result.map_err(|e| {
            // Refused before admission: nothing was saved or started.
            if resume_refused(&e.source) {
                return anyhow::anyhow!("the conversation cannot continue: {}", e.source.message());
            }
            anyhow::anyhow!(
                "{e}; use cw env agent observe {} --request-id {id}; no retry was sent",
                self.environment_id
            )
        })?;
        let operation = response
            .operation
            .into_option()
            .context("platform omitted the saved agent operation")?;
        if let Some(output) = output {
            print_operation(&operation, output)?;
        }
        // A refusal is definite: nothing was started or changed, so there is
        // nothing to observe and the request can simply be made again.
        anyhow::ensure!(
            operation.phase.as_known() != Some(rpc::EnvironmentAgentPhase::Rejected),
            "request {id} was refused; nothing was started or changed"
        );
        anyhow::ensure!(
            operation.phase.as_known() == Some(rpc::EnvironmentAgentPhase::Completed),
            "request {id} remains {}; use cw env agent observe {} --request-id {id}; no replay was sent",
            phase_name(&operation.phase),
            self.environment_id
        );
        Ok(operation)
    }
}
async fn conversation(
    target: &EnvironmentSessionTarget,
    reference: &str,
) -> anyhow::Result<Conversation> {
    conversation_with(target, reference, false).await
}
/// A conversation a new message or a restart continues: one of an earlier
/// Pod of this environment is resumed here first (#2705).
async fn resumed_conversation(
    target: &EnvironmentSessionTarget,
    reference: &str,
) -> anyhow::Result<Conversation> {
    conversation_with(target, reference, true).await
}
async fn conversation_with(
    target: &EnvironmentSessionTarget,
    reference: &str,
    resume: bool,
) -> anyhow::Result<Conversation> {
    let (endpoint, _) = capture(target).await?;
    let (session, resumed) = if resume {
        endpoint.find_or_resume(reference).await?
    } else {
        (endpoint.find(reference).await?, false)
    };
    let driver_id = session
        .session_id
        .strip_prefix("session-")
        .context("managed session has invalid identity")?;
    anyhow::ensure!(
        codewire_daemon_proto::platform_managed::valid_uuid(driver_id),
        "managed driver UUID is invalid"
    );
    Ok(Conversation {
        driver_id: driver_id.into(),
        endpoint,
        session,
        resumed,
    })
}
impl Conversation {
    async fn read(&self, message: Option<&str>, generation: u64) -> anyhow::Result<Value> {
        let response = self
            .endpoint
            .client
            .read_environment_agent(rpc::ReadEnvironmentAgentRequest {
                org_id: self.endpoint.org_id.clone(),
                environment_id: self.endpoint.environment_id.clone(),
                expected_scope: Some(self.endpoint.scope.clone()).into(),
                session_id: self.session.session_id.clone(),
                driver_id: self.driver_id.clone(),
                expected_launch_generation: generation,
                kind: if message.is_some() {
                    rpc::EnvironmentAgentRecordKind::Message
                } else {
                    rpc::EnvironmentAgentRecordKind::Current
                }
                .into(),
                message_id: message.unwrap_or_default().into(),
                limit: 20,
                ..Default::default()
            })
            .await?;
        serde_json::from_slice(&response.record_json).context("platform managed record is invalid")
    }
    fn location(&self, message: &str, generation: u64) -> MessageLocation {
        MessageLocation {
            version: 1,
            org_id: self.endpoint.org_id.clone(),
            environment_id: self.endpoint.environment_id.clone(),
            scope: self.endpoint.scope.clone(),
            session_id: self.session.session_id.clone(),
            driver_id: self.driver_id.clone(),
            launch_generation: generation,
            message_id: message.into(),
        }
    }
    fn control(
        &self,
        action: rpc::EnvironmentAgentAction,
        text: String,
    ) -> rpc::EnvironmentAgentControl {
        rpc::EnvironmentAgentControl {
            action: action.into(),
            session_id: self.session.session_id.clone(),
            driver_id: self.driver_id.clone(),
            expected_launch_generation: self.session.launch_generation,
            text,
            ..Default::default()
        }
    }
}
/// A Resume the platform refused before admitting it, with its reason.
fn resume_refused(error: &codewire_client::ClientError) -> bool {
    error.code() == codewire_client::ErrorCode::FailedPrecondition
        && error.reason() == Some("PLATFORM_AGENT_RESUME_REFUSED")
}
/// The managed driver a platform Sandbox runs; the Sandbox is always Linux.
fn is_platform_driver(command: &[String]) -> bool {
    command
        .get(1)
        .is_some_and(|arg| arg == "__platform-agent-driver")
}
/// Said when a conversation, or a message in it, belongs to an earlier Pod
/// of the environment and is not continued in its current one (#2705). A new
/// message or a restart resumes it here, or says plainly why it cannot.
fn stopped_with_environment(environment: &str, reference: &str) -> String {
    format!(
        "managed conversation {reference:?} stopped with its environment; \
         `cw msg {environment} {reference} TEXT` or `cw restart {environment} {reference}` \
         continues it here"
    )
}
fn location_path(message: &str) -> anyhow::Result<PathBuf> {
    Ok(ResolvePaths::from_env(&OsEnv)?
        .platform_config_dir
        .join("platform-managed-messages-v1")
        .join(format!("{}.json", canonical_uuid(message)?)))
}
fn save_location(location: &MessageLocation) -> anyhow::Result<()> {
    let path = location_path(&location.message_id)?;
    private_directory(
        path.parent()
            .context("managed message index has no parent")?,
    )?;
    if let Some(saved) = read_optional::<MessageLocation>(&path)? {
        anyhow::ensure!(
            saved.version == location.version
                && saved.org_id == location.org_id
                && saved.environment_id == location.environment_id
                && saved.scope == location.scope
                && saved.session_id == location.session_id
                && saved.driver_id == location.driver_id
                && saved.launch_generation == location.launch_generation
                && saved.message_id == location.message_id,
            "managed platform message index changed its original binding"
        );
    }
    write_private_json(&path, location)
}
/// The lowercase phase name shown to people, never a Rust debug rendering.
fn phase_name(phase: &codewire_client::EnumValue<rpc::EnvironmentAgentPhase>) -> &'static str {
    match phase.as_known() {
        Some(rpc::EnvironmentAgentPhase::Admitted) => "admitted",
        Some(rpc::EnvironmentAgentPhase::Issued) => "issued",
        Some(rpc::EnvironmentAgentPhase::Completed) => "completed",
        Some(rpc::EnvironmentAgentPhase::Rejected) => "rejected",
        _ => "unknown",
    }
}

fn agent_name(agent: &codewire_client::EnumValue<rpc::EnvironmentAgentKind>) -> &'static str {
    match agent.as_known() {
        Some(rpc::EnvironmentAgentKind::Codex) => "codex",
        Some(rpc::EnvironmentAgentKind::Claude) => "claude",
        _ => "unknown",
    }
}

fn print_operation(
    op: &rpc::EnvironmentAgentOperation,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(op)?),
        OutputFormat::Text => println!(
            "request {}\tsession {}\tmessage {}\t{}",
            op.request_id,
            op.session_id,
            if op.message_id.is_empty() {
                "-"
            } else {
                &op.message_id
            },
            phase_name(&op.phase)
        ),
    }
    Ok(())
}

pub(super) async fn run(
    target: EnvironmentSessionTarget,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.tty && args.command.is_empty() && args.env.is_empty(),
        "managed platform conversations accept --agent and selected environment sources; omit --tty, COMMAND and --env"
    );
    let agent = match args.agent.as_deref() {
        Some("codex") => AgentKind::Codex,
        Some("claude") => AgentKind::Claude,
        _ => anyhow::bail!("managed platform conversations support --agent codex or claude"),
    };
    let (endpoint, support) = capture(&target).await?;
    let kind = match agent {
        AgentKind::Codex => rpc::EnvironmentAgentKind::Codex,
        AgentKind::Claude => rpc::EnvironmentAgentKind::Claude,
        AgentKind::Noel => anyhow::bail!("{NOEL_HOST_ONLY}"),
    };
    let provider = support
        .iter()
        .find(|a| a.agent.as_known() == Some(kind) && a.proxy_only_qualified)
        .context("selected agent has no qualified provider proxy in this environment; create it with --profile PROFILE for a credential profile that includes this provider, and check `cw env agent info ENV`")?;
    let (parent, parent_generation) = match args.parent.as_deref() {
        Some(reference) => {
            let parent = endpoint.find(reference).await?;
            anyhow::ensure!(!parent.cleanup_unknown, "managed parent cleanup is unknown");
            (parent.session_id, parent.launch_generation)
        }
        None => (String::new(), 0),
    };
    let id = request_id(args.request_id.as_deref())?;
    let initial = args
        .prompt
        .as_ref()
        .map(|_| {
            codewire_daemon_proto::platform_managed::platform_managed_initial_prompt_id(&id)
                .map_err(|_| anyhow::anyhow!("initial managed message UUID is invalid"))
        })
        .transpose()?;
    if let Some(message) = &initial {
        save_location(&MessageLocation {
            version: 1,
            org_id: endpoint.org_id.clone(),
            environment_id: endpoint.environment_id.clone(),
            scope: endpoint.scope.clone(),
            session_id: format!("session-{id}"),
            driver_id: id.clone(),
            launch_generation: 1,
            message_id: message.clone(),
        })?;
    }
    let launch = rpc::EnvironmentAgentLaunch {
        agent: kind.into(),
        model: args
            .model
            .clone()
            .unwrap_or_else(|| agent.default_model().unwrap_or_default().into()),
        effort: agent_effort(agent, args.effort.as_deref())?,
        working_dir: args
            .workdir
            .clone()
            .unwrap_or_else(|| target.default_working_dir()),
        name: args.name.clone().unwrap_or_default(),
        prompt: args.prompt.clone(),
        parent_session_id: parent,
        expected_parent_launch_generation: parent_generation,
        expected_provider_sha256: provider.provider_sha256.clone(),
        expected_provider_size: provider.provider_size,
        expected_provider_version: provider.provider_version.clone(),
        ..Default::default()
    };
    endpoint
        .mutate(
            &id,
            rpc::mutate_environment_agent_request::Operation::Launch(Box::new(launch)),
            Some(args.output),
        )
        .await?;
    if !args.detach
        && let Some(message) = initial
    {
        wait_location(
            read_optional::<MessageLocation>(&location_path(&message)?)?
                .context("initial message index missing")?,
            &endpoint.client,
            Duration::from_secs(1800),
            args.output,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn message(
    target: EnvironmentSessionTarget,
    reference: &str,
    args: &AgentMessageArgs,
    text: &str,
    steer: bool,
) -> anyhow::Result<()> {
    validate_text(text)?;
    // A new message continues a conversation its environment's Stop ended;
    // a steer has no active turn to steer there.
    let conversation = if steer {
        conversation(&target, reference).await?
    } else {
        resumed_conversation(&target, reference).await?
    };
    anyhow::ensure!(
        !conversation.session.cleanup_unknown,
        "managed cleanup is unknown; stop the original generation before sending another message"
    );
    if let Some(expected) = args.expected_launch_generation {
        anyhow::ensure!(
            expected == conversation.session.launch_generation,
            "managed session generation changed"
        );
    }
    let mut control = conversation.control(
        if steer {
            rpc::EnvironmentAgentAction::Steer
        } else {
            rpc::EnvironmentAgentAction::Message
        },
        text.into(),
    );
    control.reply_to = args.reply_to.as_deref().map(canonical_uuid).transpose()?;
    if steer {
        let status = conversation
            .read(None, conversation.session.launch_generation)
            .await?;
        let state: DriverState = serde_json::from_value(
            status
                .get("driver")
                .cloned()
                .context("managed driver status is missing")?,
        )?;
        anyhow::ensure!(
            state.driver_id == conversation.driver_id && state.capabilities.steer,
            "managed driver cannot steer"
        );
        control.expected_active_message_id = Some(
            state
                .active_message_id
                .context("no active message to steer")?,
        );
        let turn = state
            .current_turn_id
            .context("no active native turn to steer")?;
        anyhow::ensure!(
            args.turn_id
                .as_ref()
                .is_none_or(|expected| expected == &turn),
            "active native turn changed"
        );
        control.expected_turn_id = Some(turn);
    } else {
        anyhow::ensure!(args.turn_id.is_none(), "--turn-id applies only to cw steer");
    }
    let id = request_id(args.request_id.as_deref())?;
    let location = conversation.location(&id, conversation.session.launch_generation);
    save_location(&location)?;
    conversation
        .endpoint
        .mutate(
            &id,
            rpc::mutate_environment_agent_request::Operation::Control(Box::new(control)),
            Some(args.output),
        )
        .await?;
    if steer {
        // The pipe settles the request; only the provider decides the steer.
        let record = await_location(
            &location,
            &conversation.endpoint.client,
            ACCEPT_TIMEOUT,
            MessageRecord::decided,
        )
        .await?;
        if let Some(error) = message_failure(&record) {
            return Err(error);
        }
    }
    Ok(())
}

pub(super) async fn action(
    target: EnvironmentSessionTarget,
    reference: &str,
    args: &SessionTargetArgs,
    action: rpc::EnvironmentAgentAction,
) -> anyhow::Result<()> {
    let conversation = if action == rpc::EnvironmentAgentAction::Restart {
        resumed_conversation(&target, reference).await?
    } else {
        conversation(&target, reference).await?
    };
    if conversation.resumed {
        // Resuming started its driver: that was the restart.
        return Ok(());
    }
    anyhow::ensure!(
        action == rpc::EnvironmentAgentAction::Stop || !conversation.session.cleanup_unknown,
        "managed cleanup is unknown; stop the original generation before another action"
    );
    if let Some(expected) = args.expected_launch_generation {
        anyhow::ensure!(
            expected == conversation.session.launch_generation,
            "managed session generation changed"
        );
    }
    let mut control = conversation.control(action, String::new());
    if action == rpc::EnvironmentAgentAction::Interrupt {
        let status = conversation
            .read(None, conversation.session.launch_generation)
            .await?;
        let state: DriverState = serde_json::from_value(
            status
                .get("driver")
                .cloned()
                .context("managed driver status is missing")?,
        )?;
        anyhow::ensure!(
            state.driver_id == conversation.driver_id && state.capabilities.interrupt,
            "managed driver cannot interrupt"
        );
        control.expected_active_message_id = Some(
            state
                .active_message_id
                .context("no active turn to interrupt")?,
        );
        control.expected_turn_id = state.current_turn_id;
    }
    let id = request_id(args.request_id.as_deref())?;
    if action == rpc::EnvironmentAgentAction::Interrupt {
        save_location(&conversation.location(&id, conversation.session.launch_generation))?;
    }
    conversation
        .endpoint
        .mutate(
            &id,
            rpc::mutate_environment_agent_request::Operation::Control(Box::new(control)),
            Some(args.output),
        )
        .await?;
    Ok(())
}

pub(super) async fn inbox(
    target: EnvironmentSessionTarget,
    reference: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let conversation = conversation(&target, reference).await?;
    let value = conversation
        .read(None, conversation.session.launch_generation)
        .await?;
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Text => {
            println!(
                "{}\tgeneration {}",
                conversation.session.session_id, conversation.session.launch_generation
            );
            if let Some(messages) = value.get("messages").and_then(Value::as_array) {
                for message in messages {
                    println!(
                        "{}\t{}",
                        message.get("id").and_then(Value::as_str).unwrap_or("?"),
                        message
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                    );
                }
            }
        }
    }
    Ok(())
}

pub(in crate::commands::sessions) async fn control_session(
    target: EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
    request: Option<&str>,
    expected_generation: Option<u64>,
    cleanup_request: Option<uuid::Uuid>,
    action: rpc::EnvironmentAgentAction,
) -> anyhow::Result<EnvironmentSessionView> {
    let conversation = if action == rpc::EnvironmentAgentAction::Restart {
        resumed_conversation(&target, &session.session_id).await?
    } else {
        conversation(&target, &session.session_id).await?
    };
    if conversation.resumed {
        // Resuming started its driver in this Pod: that was the restart.
        let mut view = session.clone();
        view.launch_generation = conversation.session.launch_generation;
        view.state =
            platform_environment_session_state_name(conversation.session.state.as_known()).into();
        view.cleanup_unknown = conversation.session.cleanup_unknown;
        view.exit_code = conversation.session.exit_code;
        return Ok(view);
    }
    anyhow::ensure!(
        conversation.session.launch_generation == session.launch_generation
            && expected_generation.is_none_or(|g| g == session.launch_generation),
        "managed session generation changed"
    );
    anyhow::ensure!(
        action == rpc::EnvironmentAgentAction::Stop || !session.cleanup_unknown,
        "managed cleanup is unknown; stop the original generation before restarting"
    );
    let id = request_id(request)?;
    anyhow::ensure!(
        cleanup_request.is_none() || action == rpc::EnvironmentAgentAction::Stop,
        "cleanup request is valid only for Stop"
    );
    let mut control = conversation.control(action, String::new());
    control.cleanup_of_request_id = cleanup_request.map(|id| id.to_string());
    let op = conversation
        .endpoint
        .mutate(
            &id,
            rpc::mutate_environment_agent_request::Operation::Control(Box::new(control)),
            None,
        )
        .await?;
    let mut view = session.clone();
    view.launch_generation = op.launch_generation;
    view.state = platform_environment_session_state_name(op.lifecycle.as_known()).into();
    view.cleanup_unknown = op.cleanup_unknown;
    view.exit_code = op.exit_code;
    Ok(view)
}

async fn wait_location(
    location: MessageLocation,
    client: &codewire_client::CodewireClient,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let record = await_location(&location, client, timeout, |r| r.state.is_terminal()).await?;
    print_message_result(&record, output)?;
    if let Some(error) = message_failure(&record) {
        return Err(error);
    }
    Ok(())
}

async fn await_location(
    location: &MessageLocation,
    client: &codewire_client::CodewireClient,
    timeout: Duration,
    until: impl Fn(&MessageRecord) -> bool,
) -> anyhow::Result<MessageRecord> {
    anyhow::ensure!(
        location.version == 1
            && location.launch_generation > 0
            && location.session_id == format!("session-{}", location.driver_id)
            && codewire_daemon_proto::platform_managed::valid_uuid(&location.message_id),
        "managed message index is invalid"
    );
    let deadline = Instant::now() + timeout;
    // The message's own scope, until its conversation is found resumed in
    // the environment's current Pod: that Pod then holds its record, at the
    // message's own generation (#2705).
    let mut scope = location.scope.clone();
    loop {
        let response = match client
            .read_environment_agent(rpc::ReadEnvironmentAgentRequest {
                org_id: location.org_id.clone(),
                environment_id: location.environment_id.clone(),
                expected_scope: Some(scope.clone()).into(),
                session_id: location.session_id.clone(),
                driver_id: location.driver_id.clone(),
                expected_launch_generation: location.launch_generation,
                kind: rpc::EnvironmentAgentRecordKind::Message.into(),
                message_id: location.message_id.clone(),
                limit: 0,
                ..Default::default()
            })
            .await
        {
            Ok(response) => response,
            Err(error) => match moved(location, &scope, client).await {
                Moved::Resumed(current) => {
                    scope = *current;
                    continue;
                }
                Moved::Stopped => anyhow::bail!(
                    "managed message {} was sent before its environment stopped; {}",
                    location.message_id,
                    stopped_with_environment(&location.environment_id, &location.session_id)
                ),
                Moved::No => return Err(error.into()),
            },
        };
        let value: Value = serde_json::from_slice(&response.record_json)?;
        let record: MessageRecord = serde_json::from_value(
            value
                .get("record")
                .cloned()
                .context("managed message record is missing")?,
        )?;
        anyhow::ensure!(
            record.id == location.message_id
                && record.driver_id == location.driver_id
                && record.target_session_id == location.session_id,
            "managed message record changed its original identity"
        );
        if until(&record) {
            return Ok(record);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "managed message {} timed out; outcome is unknown; no replay was sent",
            location.message_id
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
/// Where a message stands whose read in `scope` failed (#2705).
enum Moved {
    /// `scope` is the environment's current one, or that cannot be told: the
    /// read's own error is the answer.
    No,
    /// `scope` names an earlier Pod, and orchestration lists the conversation
    /// in the current Pod at a later generation than the message's: it was
    /// resumed there, and is read in this scope.
    Resumed(Box<rpc::EnvironmentAgentScope>),
    /// `scope` names an earlier Pod, and the current Pod does not list the
    /// conversation: it stopped with its environment and was not resumed.
    Stopped,
}
/// Any failure to tell answers [`Moved::No`], so the read's own error is shown.
async fn moved(
    location: &MessageLocation,
    scope: &rpc::EnvironmentAgentScope,
    client: &codewire_client::CodewireClient,
) -> Moved {
    let Ok(info) = client
        .get_environment_agent_info(rpc::GetEnvironmentAgentInfoRequest {
            org_id: location.org_id.clone(),
            environment_id: location.environment_id.clone(),
            ..Default::default()
        })
        .await
    else {
        return Moved::No;
    };
    let Some(current) = info.scope.into_option() else {
        return Moved::No;
    };
    let pod = |scope: &rpc::EnvironmentAgentScope| {
        scope
            .incarnation
            .as_option()
            .map(|incarnation| incarnation.pod_uid.clone())
    };
    match (pod(&current), pod(scope)) {
        (Some(now), Some(then)) if now != then => {}
        _ => return Moved::No,
    }
    let endpoint = Endpoint {
        org_id: location.org_id.clone(),
        environment_id: location.environment_id.clone(),
        client: client.clone(),
        scope: current,
    };
    match endpoint.find_in_scope(&location.session_id).await {
        Ok(Some(session)) if session.launch_generation > location.launch_generation => {
            Moved::Resumed(Box::new(endpoint.scope))
        }
        Ok(None) => Moved::Stopped,
        Ok(Some(_)) | Err(_) => Moved::No,
    }
}
pub(super) async fn wait(
    globals: &Globals,
    message: &str,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<bool> {
    let Some(location) = read_optional::<MessageLocation>(&location_path(message)?)? else {
        return Ok(false);
    };
    let target =
        resolve_environment_session_target(globals, Some(&location.environment_id)).await?;
    let (org, env, client) = platform(&target)?;
    anyhow::ensure!(
        org == location.org_id && env == location.environment_id,
        "selected platform differs from saved managed message"
    );
    wait_location(location, client, timeout, output).await?;
    Ok(true)
}
pub(crate) async fn handle_metadata(
    globals: &Globals,
    command: EnvAgentCommand,
) -> anyhow::Result<()> {
    let reference = match &command {
        EnvAgentCommand::Info(a) => &a.environment,
        EnvAgentCommand::Observe(a) => &a.environment,
    };
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let selected = resolve_platform(globals, &paths, &OsEnv)?;
    let organizations = organization_client(&selected)?.list_orgs().await?;
    let org = current_org_id(&selected, &organizations)?;
    let environment_client = EnvironmentClient::new(&selected)?;
    let env = if let Ok(id) = uuid::Uuid::parse_str(reference) {
        anyhow::ensure!(
            !id.is_nil() && id.to_string() == *reference,
            "environment UUID must be canonical and nonnil"
        );
        id.to_string()
    } else {
        resolve_environment_id(&environment_client, &org, reference).await?
    };
    let client = codewire_client(&selected)?;
    match command {
        EnvAgentCommand::Info(args) => {
            let response = client
                .get_environment_agent_info(rpc::GetEnvironmentAgentInfoRequest {
                    org_id: org.clone(),
                    environment_id: env.clone(),
                    ..Default::default()
                })
                .await?;
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text if response.agents.is_empty() => println!(
                    "No managed agents are available; create the environment with --profile PROFILE for a credential profile that includes Codex or Anthropic"
                ),
                OutputFormat::Text => {
                    for support in response.agents {
                        println!(
                            "{}\tversion {}\tsteer {}\tinterrupt {}",
                            agent_name(&support.agent),
                            support.provider_version,
                            if support.steer { "yes" } else { "no" },
                            if support.interrupt { "yes" } else { "no" }
                        );
                    }
                }
            }
        }
        EnvAgentCommand::Observe(args) => {
            let response = client
                .observe_environment_agent(rpc::ObserveEnvironmentAgentRequest {
                    org_id: org.clone(),
                    environment_id: env.clone(),
                    request_id: args.request_id.to_string(),
                    ..Default::default()
                })
                .await?;
            print_operation(
                &response
                    .operation
                    .into_option()
                    .context("saved managed operation is missing")?,
                args.output,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
