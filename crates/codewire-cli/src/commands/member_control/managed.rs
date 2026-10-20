//! Managed conversations use the same authenticated principal and target-owned
//! request journal as terminal sessions. Reads reconnect without replaying an
//! action; retained message locators never redirect to another target or birth.
use super::*;
use serde_json::{Value, json};
use std::time::Duration;

const MAX_LOCATORS: usize = store::MAX_MESSAGE_LOCATORS;

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    version: u32,
    binding: wire::Binding,
    session_id: String,
    driver_id: String,
    generation: u64,
    message_id: String,
}
fn canonical_session(value: &str) -> anyhow::Result<&str> {
    wire::canonical_uuid(
        value
            .strip_prefix("session-")
            .context("member requires a canonical session-UUID")?,
    )?;
    Ok(value)
}
/// `[ENV_UUID] --session SESSION`: the exact saved environment, if named,
/// and a canonical session ID.
fn selected_session<'a>(
    environment: Option<&str>,
    session: &'a str,
    bound: &str,
) -> anyhow::Result<&'a str> {
    if let Some(environment) = environment {
        ensure!(
            environment == bound,
            "member environment must be the exact saved UUID"
        );
    }
    canonical_session(session)
}
/// Whether the target recorded this member session as a managed driver.
fn member_managed(session: &v1::SessionRecord) -> bool {
    session
        .command
        .get(1)
        .is_some_and(|value| value == "_agent-driver")
}
fn selected<'a>(values: &'a [String], environment: &str) -> anyhow::Result<&'a str> {
    match values {
        [id] => canonical_session(id),
        [env, id] if env == environment => canonical_session(id),
        _ => anyhow::bail!("expected canonical SESSION, or exact ENV_UUID SESSION"),
    }
}
fn generation(observed: u64, requested: Option<u64>) -> anyhow::Result<u64> {
    ensure!(
        observed > 0 && requested.is_none_or(|v| v > 0 && v == observed),
        "member launch generation changed"
    );
    Ok(observed)
}
fn request_id(requested: Option<String>) -> anyhow::Result<String> {
    let id = requested.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    wire::canonical_uuid(&id)?;
    eprintln!("[cw] member request {id}; recover an unknown reply with cw member observe");
    Ok(id)
}
async fn open(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<(store::Directory, transport::Remote)> {
    let dir = directory(false)?;
    let alias = store::Alias::load(
        &dir,
        globals
            .member
            .as_deref()
            .context("member selection required")?,
    )?;
    ensure!(
        environment.is_none_or(|e| e == alias.binding.environment_id),
        "member environment UUID differs"
    );
    let mut remote = transport::Remote::connect(&dir, alias, globals).await?;
    remote.managed_ready().await?;
    Ok((dir, remote))
}
fn driver(session: &v1::SessionRecord) -> anyhow::Result<String> {
    canonical_session(&session.session_id)?;
    let id = session
        .session_id
        .strip_prefix("session-")
        .expect("checked");
    ensure!(
        session.launch_generation > 0
            && !session.pty
            && session.command.len() == 8
            && session.command[1] == "_agent-driver"
            && session.command[4] == "--driver-id"
            && session.command[5] == id,
        "member session has no target-owned managed receiver"
    );
    Ok(id.into())
}
fn read_request(
    remote: &transport::Remote,
    session: &v1::SessionRecord,
    message: &str,
) -> anyhow::Result<v1::HostControlManagedReadRequest> {
    Ok(v1::HostControlManagedReadRequest {
        scope: Some(remote.alias.binding.scope()),
        session_id: session.session_id.clone(),
        driver_id: driver(session)?,
        expected_launch_generation: session.launch_generation,
        message_id: message.into(),
        limit: 100,
    })
}
fn checked_record(value: Value, session: &v1::SessionRecord, id: &str) -> anyhow::Result<Value> {
    let record = &value["record"];
    ensure!(
        record["version"].as_u64() == Some(1)
            && record["id"].as_str() == Some(id)
            && record["target_session_id"].as_str() == Some(session.session_id.as_str())
            && record["driver_id"].as_str() == Some(driver(session)?.as_str())
            && matches!(
                record["state"].as_str(),
                Some(
                    "requested"
                        | "pipe_written"
                        | "undelivered"
                        | "accepted"
                        | "running"
                        | "completed"
                        | "error"
                        | "interrupted"
                        | "unknown"
                )
            ),
        "member message identity or state differs"
    );
    let original = record["member_launch_generation"]
        .as_u64()
        .context("member message has no original generation proof")?;
    ensure!(
        original > 0
            && original <= session.launch_generation
            && (original == session.launch_generation || message_terminal(record)),
        "old active member message cannot cross incarnations"
    );
    Ok(value["record"].clone())
}
fn message_terminal(record: &Value) -> bool {
    matches!(
        record["state"].as_str(),
        Some("completed" | "error" | "interrupted" | "unknown")
    )
}
async fn message(
    remote: &mut transport::Remote,
    session: &v1::SessionRecord,
    id: &str,
) -> anyhow::Result<Value> {
    wire::canonical_uuid(id)?;
    let request = read_request(remote, session, id)?;
    checked_record(remote.managed_record(request).await?, session, id)
}
async fn inbox_value(
    remote: &mut transport::Remote,
    session: &v1::SessionRecord,
) -> anyhow::Result<Value> {
    remote
        .managed_record(read_request(remote, session, "")?)
        .await
}
fn same_member(original: &wire::Binding, current: &wire::Binding) -> bool {
    original.environment_id == current.environment_id
        && original.org == current.org
        && original.network == current.network
        && original.target_wg == current.target_wg
        && original.caller == current.caller
        && original.target == current.target
        && original.grant_id == current.grant_id
        && original.grant_revision <= current.grant_revision
}
async fn save_locator(
    dir: &store::Directory,
    remote: &transport::Remote,
    session: &v1::SessionRecord,
    id: &str,
    original_generation: u64,
) -> anyhow::Result<()> {
    wire::canonical_uuid(id)?;
    ensure!(
        original_generation > 0 && original_generation <= session.launch_generation,
        "invalid member message birth proof"
    );
    let value = Locator {
        version: 1,
        binding: remote.alias.binding.clone(),
        session_id: session.session_id.clone(),
        driver_id: driver(session)?,
        generation: original_generation,
        message_id: id.into(),
    };
    let name = format!("message-{id}.json");
    let _lock = dir.lock().await?;
    if let Some(saved) = dir.read::<Locator>(&name)? {
        ensure!(
            saved.version == 1
                && same_member(&saved.binding, &value.binding)
                && saved.session_id == value.session_id
                && saved.driver_id == value.driver_id
                && saved.generation == value.generation
                && saved.message_id == id,
            "member message locator changed"
        );
    } else {
        ensure!(
            dir.count("message-")? < MAX_LOCATORS,
            "member message locator capacity exhausted"
        );
        dir.write(&name, &value)?;
    }
    Ok(())
}
async fn await_acceptance(
    remote: &mut transport::Remote,
    session: &v1::SessionRecord,
    id: &str,
) -> anyhow::Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let record = message(remote, session, id).await?;
            ensure!(
                record["member_launch_generation"].as_u64() == Some(session.launch_generation),
                "member native acceptance belongs to another incarnation"
            );
            // Only the provider decides a steer or interrupt.
            let decided = if matches!(record["action"].as_str(), Some("steer" | "interrupt")) {
                record["native_acknowledged"].as_bool() == Some(true)
            } else {
                matches!(record["state"].as_str(), Some("accepted" | "running"))
            };
            if decided || message_terminal(&record) {
                return Ok::<_, anyhow::Error>(record);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .context("member native acceptance unknown; observe original request and never reissue")?
}
fn successful_message(record: &Value) -> anyhow::Result<()> {
    ensure!(
        !matches!(
            record["state"].as_str(),
            Some("error" | "interrupted" | "unknown")
        ),
        "member message did not complete successfully; native outcome is retained"
    );
    Ok(())
}

pub(crate) async fn run(globals: &Globals, args: EnvironmentRunArgs) -> anyhow::Result<()> {
    ensure!(
        !args.tty && args.command.is_empty() && args.env.is_empty(),
        "member managed run has no PTY, COMMAND or environment projection"
    );
    let agent = match args.agent.as_deref() {
        Some("codex") => v1::HostManagedAgent::Codex,
        Some("claude") => v1::HostManagedAgent::Claude,
        _ => anyhow::bail!("member managed agents support only codex and claude"),
    };
    // The same defaults as every other placement: Codex always gets an
    // effort, `medium` unless one is named (#2982).
    use crate::commands::sessions::agents::{
        CLAUDE_DEFAULT_MODEL, CODEX_DEFAULT_EFFORT, CODEX_DEFAULT_MODEL,
    };
    let model = args.model.unwrap_or_else(|| {
        if agent == v1::HostManagedAgent::Codex {
            CODEX_DEFAULT_MODEL.into()
        } else {
            CLAUDE_DEFAULT_MODEL.into()
        }
    });
    let effort = if agent == v1::HostManagedAgent::Codex {
        Some(args.effort.unwrap_or_else(|| CODEX_DEFAULT_EFFORT.into()))
    } else {
        args.effort
    };
    let id = request_id(args.request_id)?;
    let (dir, mut remote) = open(globals, args.environment.as_deref()).await?;
    let (parent, parent_generation) = match args.parent {
        Some(parent) => {
            canonical_session(&parent)?;
            let session = remote.get(&parent).await?;
            driver(&session)?;
            let _ = inbox_value(&mut remote, &session).await?;
            (parent, generation(session.launch_generation, None)?)
        }
        None => (String::new(), 0),
    };
    let request = v1::HostControlMutationRequest {
        request_id: id,
        scope: Some(remote.alias.binding.scope()),
        operation: Some(v1::host_control_mutation_request::Operation::ManagedLaunch(
            v1::HostControlManagedLaunch {
                agent: agent as i32,
                model,
                effort,
                working_dir: args.workdir.unwrap_or_default(),
                name: args.name.unwrap_or_default(),
                prompt: args.prompt,
                parent_session_id: parent,
                expected_parent_launch_generation: parent_generation,
            },
        )),
    };
    let receipt = remote.mutate(&dir, request).await?;
    complete(&receipt)?;
    let session = remote.get(&receipt.session_id).await?;
    driver(&session)?;
    ensure!(
        session.launch_generation == receipt.launch_generation,
        "member launch generation changed"
    );
    if !receipt.message_id.is_empty() {
        save_locator(
            &dir,
            &remote,
            &session,
            &receipt.message_id,
            receipt.launch_generation,
        )
        .await?;
    }
    value(
        json!({"session":super::super::sessions::host_environment_session_view(session.clone()),
        "conversation":{"driver_id":receipt.driver_id},"initial_message":if receipt.message_id.is_empty(){Value::Null}else{json!({"id":receipt.message_id})},
        "request":receipt_value(&receipt)}),
        args.output,
    )?;
    if !args.detach && !matches!(args.output, OutputFormat::Json) && !receipt.message_id.is_empty()
    {
        wait_loop(
            &mut remote,
            &session,
            &receipt.message_id,
            receipt.launch_generation,
            Duration::from_secs(1800),
            args.output,
        )
        .await?;
    }
    Ok(())
}
/// `cw --member M msg|steer [ENV_UUID] --session SESSION TEXT`, dispatched
/// by the session the target recorded: terminal input for a normal session,
/// a durable message for a managed one. Steer is managed-only.
pub(crate) async fn send_message(
    globals: &Globals,
    args: AgentMessageArgs,
    steer: bool,
) -> anyhow::Result<()> {
    let (environment, session, text) = args.target(if steer { "steer" } else { "msg" })?;
    let text = text.to_owned();
    ensure!(
        steer || args.turn_id.is_none(),
        "--turn-id applies only to steer"
    );
    let (dir, mut remote) = open(globals, None).await?;
    let sid =
        selected_session(environment, session, &remote.alias.binding.environment_id)?.to_owned();
    let session = remote.get(&sid).await?;
    if !member_managed(&session) {
        ensure!(
            !steer,
            "member session {sid} is a terminal session; steering applies only to managed conversations. Type into it with `cw msg --session {sid} TEXT`"
        );
        ensure!(
            args.reply_to.is_none(),
            "--reply-to applies only to managed agent conversations"
        );
        return terminal_message(&dir, &mut remote, &session, &text, args).await;
    }
    let driver_id = driver(&session)?;
    let mut control = v1::HostControlManagedControl {
        action: if steer {
            v1::HostManagedAction::Steer
        } else {
            v1::HostManagedAction::Message
        } as i32,
        session_id: sid,
        expected_launch_generation: generation(
            session.launch_generation,
            args.expected_launch_generation,
        )?,
        driver_id,
        text,
        reply_to: args.reply_to,
        ..Default::default()
    };
    if steer {
        let inbox = inbox_value(&mut remote, &session).await?;
        ensure!(
            inbox["driver"]["capabilities"]["steer"].as_bool() == Some(true),
            "member conversation does not support steer"
        );
        control.expected_turn_id = Some(
            args.turn_id
                .or_else(|| {
                    inbox["driver"]["current_turn_id"]
                        .as_str()
                        .map(str::to_owned)
                })
                .context("member has no active steerable turn")?,
        );
        control.expected_active_message_id = Some(
            inbox["driver"]["active_message_id"]
                .as_str()
                .context("member has no active message")?
                .into(),
        );
    }
    let id = request_id(args.request_id)?;
    let receipt = remote
        .mutate(
            &dir,
            v1::HostControlMutationRequest {
                request_id: id.clone(),
                scope: Some(remote.alias.binding.scope()),
                operation: Some(
                    v1::host_control_mutation_request::Operation::ManagedControl(control),
                ),
            },
        )
        .await?;
    complete(&receipt)?;
    save_locator(&dir, &remote, &session, &id, receipt.launch_generation).await?;
    let mut record = await_acceptance(&mut remote, &session, &id).await?;
    let outcome = successful_message(&record);
    if !steer && record.is_object() {
        record["delivery"] = json!("managed");
    }
    value(record, args.output)?;
    outcome
}

/// A normal member session gets the text and the key that submits it as
/// one acknowledged input request, never retried.
async fn terminal_message(
    dir: &store::Directory,
    remote: &mut transport::Remote,
    session: &v1::SessionRecord,
    text: &str,
    args: AgentMessageArgs,
) -> anyhow::Result<()> {
    // A member session never has a terminal (member run requires --no-tty),
    // so the text and its line end are one acknowledged write.
    ensure!(
        !session.pty,
        "member session {} has a terminal; member input is admitted only for --no-tty sessions",
        session.session_id
    );
    let data = crate::commands::terminal_message_bytes(text, false)?.text;
    let generation = generation(session.launch_generation, args.expected_launch_generation)?;
    let id = request_id(args.request_id)?;
    let receipt = remote
        .mutate(
            dir,
            v1::HostControlMutationRequest {
                request_id: id,
                scope: Some(remote.alias.binding.scope()),
                operation: Some(v1::host_control_mutation_request::Operation::Input(
                    v1::HostControlInput {
                        session_id: session.session_id.clone(),
                        expected_launch_generation: generation,
                        data,
                    },
                )),
            },
        )
        .await?;
    complete(&receipt)?;
    ensure!(
        receipt.input_acknowledged,
        "member input acknowledgement unavailable; observe only, never resend"
    );
    match args.output {
        OutputFormat::Json => value(
            json!({"delivery":"terminal","environment":remote.alias.binding.environment_id,
                "session_id":session.session_id,"session":session.name,"submitted":true}),
            OutputFormat::Json,
        ),
        OutputFormat::Text => {
            println!(
                "Sent to terminal {}/{}.",
                remote.alias.binding.environment_id, session.session_id
            );
            Ok(())
        }
    }
}
pub(crate) async fn action(
    globals: &Globals,
    args: SessionTargetArgs,
    action: v1::HostManagedAction,
) -> anyhow::Result<()> {
    let (dir, mut remote) = open(globals, None).await?;
    let sid = selected(&args.target, &remote.alias.binding.environment_id)?.to_owned();
    let session = remote.get(&sid).await?;
    let driver_id = driver(&session)?;
    let mut control = v1::HostControlManagedControl {
        action: action as i32,
        session_id: sid.clone(),
        driver_id,
        expected_launch_generation: generation(
            session.launch_generation,
            args.expected_launch_generation,
        )?,
        ..Default::default()
    };
    if action == v1::HostManagedAction::Interrupt {
        let inbox = inbox_value(&mut remote, &session).await?;
        ensure!(
            inbox["driver"]["capabilities"]["interrupt"].as_bool() == Some(true),
            "member interrupt unsupported"
        );
        control.expected_active_message_id = Some(
            inbox["driver"]["active_message_id"]
                .as_str()
                .context("no active member message")?
                .into(),
        );
        control.expected_turn_id = inbox["driver"]["current_turn_id"]
            .as_str()
            .map(str::to_owned);
    }
    let id = request_id(args.request_id)?;
    let receipt = remote
        .mutate(
            &dir,
            v1::HostControlMutationRequest {
                request_id: id.clone(),
                scope: Some(remote.alias.binding.scope()),
                operation: Some(
                    v1::host_control_mutation_request::Operation::ManagedControl(control),
                ),
            },
        )
        .await?;
    complete(&receipt)?;
    if action == v1::HostManagedAction::Interrupt {
        save_locator(&dir, &remote, &session, &id, receipt.launch_generation).await?;
        let record = await_acceptance(&mut remote, &session, &id).await?;
        value(record.clone(), args.output)?;
        successful_message(&record)
    } else {
        let current = remote.get(&sid).await?;
        ensure!(
            current.launch_generation == receipt.launch_generation && !current.cleanup_unknown,
            "member cleanup or new launch outcome unknown"
        );
        super::super::sessions::print_environment_sessions(
            &[super::super::sessions::host_environment_session_view(
                current,
            )],
            args.output,
        )
    }
}
pub(crate) async fn stop(globals: &Globals, args: SessionTargetArgs) -> anyhow::Result<()> {
    // Ordinary terminal Stop keeps its accepted API and cancellation behavior.
    let dir = directory(false)?;
    let alias = store::Alias::load(
        &dir,
        globals
            .member
            .as_deref()
            .context("member selection required")?,
    )?;
    let sid = selected(&args.target, &alias.binding.environment_id)?;
    let mut remote = transport::Remote::connect(&dir, alias, globals).await?;
    let session = remote.get(sid).await?;
    if session
        .command
        .get(1)
        .is_some_and(|value| value == "_agent-driver")
    {
        action(globals, args, v1::HostManagedAction::Stop).await
    } else {
        terminal::stop(globals, args).await
    }
}
pub(crate) async fn inbox(globals: &Globals, args: InboxArgs) -> anyhow::Result<()> {
    let environment = crate::commands::flat::select_environment(
        "inbox",
        args.environment.clone(),
        args.in_environment.clone(),
        &args.retired_session,
    )?;
    let session = args
        .session
        .as_deref()
        .context("name the session with --session: `cw inbox [ENV] --session SESSION`")?;
    let (dir, mut remote) = open(globals, None).await?;
    let session = remote
        .get(selected_session(
            environment.as_deref(),
            session,
            &remote.alias.binding.environment_id,
        )?)
        .await?;
    generation(session.launch_generation, args.expected_launch_generation)?;
    if !member_managed(&session) {
        let member = globals.member.as_deref().unwrap_or("MEMBER");
        let logs = format!("cw --member {member} logs --session {}", session.session_id);
        return match args.output {
            OutputFormat::Json => value(
                json!({"delivery":"terminal","environment":remote.alias.binding.environment_id,
                    "session_id":session.session_id,"session":session.name,"inbox":null,
                    "logs_command":logs}),
                OutputFormat::Json,
            ),
            OutputFormat::Text => {
                println!(
                    "Member session {} is a terminal session; it has no structured inbox.\n  `cw msg` types into its terminal and records no messages or replies.\n\nRead its output: {logs}",
                    session.session_id
                );
                Ok(())
            }
        };
    }
    let inbox = inbox_value(&mut remote, &session).await?;
    if let Some(messages) = inbox["messages"].as_array() {
        for message in messages {
            let original = message["member_launch_generation"]
                .as_u64()
                .context("member summary has no birth proof")?;
            ensure!(
                original == session.launch_generation || message_terminal(message),
                "old active member summary cannot cross incarnations"
            );
            save_locator(
                &dir,
                &remote,
                &session,
                message["id"].as_str().context("invalid member summary")?,
                original,
            )
            .await?;
        }
    }
    value(
        json!({"delivery":"managed","session":super::super::sessions::host_environment_session_view(session),
        "driver":inbox["driver"],"messages":inbox["messages"]}),
        args.output,
    )
}
pub(crate) async fn wait(globals: &Globals, args: WaitArgs) -> anyhow::Result<()> {
    let id = args
        .message
        .as_deref()
        .context("member managed wait requires --message")?;
    wire::canonical_uuid(id)?;
    let timeout = tailnet_ssh::parse_duration(&args.timeout)
        .map_err(|_| anyhow::anyhow!("invalid message timeout"))?;
    ensure!(!timeout.is_zero(), "message timeout must be positive");
    let (dir, mut remote) = open(globals, None).await?;
    let locator = match dir.read::<Locator>(&format!("message-{id}.json"))? {
        Some(value) => value,
        None => {
            let request = store::RequestRecord::load(&dir, id)?;
            ensure!(
                request.message_id == id && !request.driver_id.is_empty(),
                "request has no managed message locator"
            );
            Locator {
                version: 1,
                binding: request.binding,
                session_id: request.session_id,
                driver_id: request.driver_id,
                generation: request.generation,
                message_id: id.into(),
            }
        }
    };
    ensure!(
        locator.version == 1
            && same_member(&locator.binding, &remote.alias.binding)
            && locator.message_id == id
            && locator.generation > 0
            && locator.session_id == format!("session-{}", locator.driver_id),
        "member locator binding changed"
    );
    let session = remote.get(&locator.session_id).await?;
    driver(&session)?;
    ensure!(
        session.launch_generation >= locator.generation,
        "member message's generation is newer than the driver"
    );
    wait_loop(
        &mut remote,
        &session,
        id,
        locator.generation,
        timeout,
        args.output,
    )
    .await
}
async fn wait_loop(
    remote: &mut transport::Remote,
    session: &v1::SessionRecord,
    id: &str,
    original_generation: u64,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout,async {
        loop {
            let record=message(remote,session,id).await?;
            ensure!(record["member_launch_generation"].as_u64()==Some(original_generation),
                "member message's retained original generation changed");
            if message_terminal(&record) {value(record.clone(),output)?;successful_message(&record)?;return Ok::<_,anyhow::Error>(());}
            let current=remote.get(&session.session_id).await?;
            ensure!(current.launch_generation==session.launch_generation,"member driver incarnation changed during wait");
            ensure!(!matches!(current.state,4..=7),"member driver exited before a confirmed message result; retained outcome remains unknown");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }).await.context("member message outcome unknown after timeout; no action was replayed")?
}
