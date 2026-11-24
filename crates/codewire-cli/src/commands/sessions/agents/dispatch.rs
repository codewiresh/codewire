//! `cw msg`, `cw steer` and `cw inbox`: one text command for both session
//! modes, dispatched by the session's recorded mode, which is resolved before
//! anything is written.
//!
//! - A normal terminal session receives the text and Enter through its
//!   acknowledged terminal input. cw reports the write, never an agent's
//!   acceptance or completion, and never retries an ambiguous write.
//! - A managed conversation receives a durable message through its driver;
//!   cw prints the message ID and its actual state. A managed failure never
//!   falls back to terminal input.
//!
//! JSON output names the mode in a top-level `delivery` key, `terminal` or
//! `managed`; the managed record's own fields are unchanged.

use super::*;
use crate::commands::message_target::MessageTarget;
use crate::commands::progress::terminal_text;
use crate::error_report::with_next_step;
use crate::output::{Capabilities, OutputMode, Status};

/// The byte a terminal UI reads as Enter. Claude Code and Codex read their
/// terminal in raw mode, where Return arrives as a carriage return; a line
/// feed there inserts a newline instead of submitting (observed on Claude
/// Code 2.1.304 and Codex 0.163.0).
pub(super) const TERMINAL_ENTER: &[u8] = b"\r";
/// A session without a terminal reads its input as lines from a pipe.
pub(super) const LINE_END: u8 = b'\n';
/// How long after the text a terminal UI receives Enter, as its own write.
/// Measured on Claude Code 2.1.304 and codex-cli 0.163.0: their paste-burst
/// detection reads an Enter that arrives with or right after the text as a
/// newline. Claude Code did so for long text and Enter in one write; Codex
/// for Enter in the same write or a few to 50 ms after the text. 300 to
/// 500 ms always submitted, short or long.
pub(super) const TERMINAL_ENTER_DELAY: Duration = Duration::from_millis(500);

/// What a normal `cw msg` writes, in order. A terminal session receives the
/// text, then Enter as its own write after [`TERMINAL_ENTER_DELAY`]; a
/// session without a terminal receives one line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TerminalMessage {
    pub(crate) text: Vec<u8>,
    /// `None` when the text already ends the line.
    pub(crate) enter: Option<&'static [u8]>,
}

/// How a normal message's writes ended. A failed text write is an error.
#[derive(Debug)]
pub(super) enum TerminalWrite {
    /// The text and, for a terminal, its Enter were acknowledged.
    Submitted,
    /// The text was acknowledged; its Enter was not.
    EnterUnconfirmed(anyhow::Error),
}

/// Writes `message` with `write`, each part once and in order: the text,
/// then after `delay` its Enter. Nothing is retried.
pub(super) async fn write_terminal_message_with<F, Fut>(
    message: TerminalMessage,
    delay: Duration,
    mut write: F,
) -> anyhow::Result<TerminalWrite>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    write(message.text).await?;
    if let Some(enter) = message.enter {
        tokio::time::sleep(delay).await;
        if let Err(error) = write(enter.to_vec()).await {
            return Ok(TerminalWrite::EnterUnconfirmed(error));
        }
    }
    Ok(TerminalWrite::Submitted)
}

pub(crate) fn terminal_message_bytes(text: &str, pty: bool) -> anyhow::Result<TerminalMessage> {
    anyhow::ensure!(!text.is_empty(), "message text is empty");
    let mut data = text.as_bytes().to_vec();
    if !pty {
        data.push(LINE_END);
    }
    anyhow::ensure!(
        data.len() <= MAX_TEXT_BYTES,
        "message text exceeds the 64 KiB session input limit"
    );
    Ok(TerminalMessage {
        text: data,
        enter: pty.then_some(TERMINAL_ENTER),
    })
}

/// `ENV/SESSION` as people name them.
fn conversation_label(target: &EnvironmentSessionTarget, view: &EnvironmentSessionView) -> String {
    let current = target.current_target();
    let environment = if current.name.trim().is_empty() {
        current.target_ref.as_str()
    } else {
        current.name.as_str()
    };
    format!(
        "{}/{}",
        terminal_text(environment),
        terminal_text(short_id::session_display(view))
    )
}

pub(super) fn environment_name(target: &EnvironmentSessionTarget) -> String {
    let current = target.current_target();
    terminal_text(if current.name.trim().is_empty() {
        &current.target_ref
    } else {
        &current.name
    })
}

fn session_name(view: &EnvironmentSessionView) -> String {
    terminal_text(short_id::session_display(view))
}

/// That `doing` (steering, interrupting) applies only to managed agent
/// conversations, and how to reach the terminal session instead. `steer`
/// and `interrupt` say it in the same words, in both placements
/// (docs/dev/CLI-PARITY.md, N5).
fn terminal_session_refusal(
    target: &EnvironmentSessionTarget,
    view: &EnvironmentSessionView,
    doing: &str,
) -> anyhow::Error {
    anyhow::anyhow!(
        "session {} is a terminal session, not a managed agent conversation; {doing} applies only to managed conversations. Type into it with `cw msg {} --session {} TEXT`, or send raw input with `cw send`",
        conversation_label(target, view),
        environment_name(target),
        session_name(view)
    )
}

/// Refuses `interrupt` for a terminal session of a local or cloud
/// environment, before either placement's agent path is asked.
pub(super) async fn refuse_terminal_interrupt(
    target: &EnvironmentSessionTarget,
    session: &str,
) -> anyhow::Result<()> {
    let agent_path = match target {
        EnvironmentSessionTarget::Platform { .. } => true,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        EnvironmentSessionTarget::NativeLocal { .. } => true,
        _ => false,
    };
    if !agent_path {
        return Ok(());
    }
    match select_environment_session(target, Some(session)).await? {
        SessionSelection::Select(view) if !is_managed_session(&view) => {
            Err(terminal_session_refusal(target, &view, "interrupting"))
        }
        _ => Ok(()),
    }
}

async fn resolve_session(
    globals: &Globals,
    environment: Option<&str>,
    session: &str,
) -> anyhow::Result<(EnvironmentSessionTarget, EnvironmentSessionView)> {
    let target = resolve_environment_session_target(globals, environment).await?;
    let view = match select_environment_session(&target, Some(session)).await? {
        SessionSelection::Select(view) => *view,
        SessionSelection::Create => anyhow::bail!("session {session:?} not found"),
    };
    Ok((target, view))
}

/// `cw msg` and `cw steer`. An environment that isn't running says so in
/// the words every session command uses.
pub(crate) async fn handle_message_command(
    globals: &Globals,
    args: AgentMessageArgs,
    steer: bool,
) -> anyhow::Result<()> {
    let named = args.target().environment.map(str::to_owned);
    match message_command(globals, args, steer).await {
        Err(error) => {
            Err(crate::commands::explain_not_running(globals, named.as_deref(), error).await)
        }
        done => done,
    }
}

async fn message_command(
    globals: &Globals,
    args: AgentMessageArgs,
    steer: bool,
) -> anyhow::Result<()> {
    let command = if steer { "steer" } else { "msg" };
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::super::member_control::managed::send_message(globals, args, steer).await;
    }
    if !steer && args.turn_id.is_some() {
        anyhow::bail!("--turn-id applies only to `cw steer`");
    }
    let message = args.target();
    let (target, view) = message_session(globals, command, &message, args.output).await?;
    let text = message.text.as_str();
    let label = conversation_label(&target, &view);
    if is_managed_session(&view) {
        return deliver_managed(target, view, &args, text, steer, &label).await;
    }
    if steer {
        return Err(terminal_session_refusal(&target, &view, "steering"));
    }
    anyhow::ensure!(
        args.reply_to.is_none(),
        "--reply-to applies only to managed agent conversations; {label} is a terminal session"
    );
    write_terminal_message(&target, &view, text, &label, args.output).await
}

/// The session a message goes to (#5085). `--session` names it. Without
/// it, the one running session is taken; with several, a terminal picks
/// and anything else names them. A message with no text, or a lone word
/// that names an environment, gets the usage with what it could go to.
async fn message_session(
    globals: &Globals,
    command: &str,
    message: &MessageTarget<'_>,
    output: OutputFormat,
) -> anyhow::Result<(EnvironmentSessionTarget, EnvironmentSessionView)> {
    if message.lone_word
        && let Ok(target) =
            resolve_environment_session_target(globals, Some(message.text.as_str())).await
    {
        return Err(message_usage(
            command,
            Some(&target),
            &running_sessions(&target).await,
        ));
    }
    if message.text.trim().is_empty() {
        let target = resolve_environment_session_target(globals, message.environment)
            .await
            .ok();
        let running = match &target {
            Some(target) => running_sessions(target).await,
            None => Vec::new(),
        };
        return Err(message_usage(command, target.as_ref(), &running));
    }
    if let Some(session) = message.session {
        return resolve_session(globals, message.environment, session).await;
    }
    let target = resolve_environment_session_target(globals, message.environment).await?;
    // A listing the environment refuses (a stopped VM) reaches
    // `explain_not_running` as the refusal, not as an empty list.
    let running: Vec<_> = target
        .list()
        .await?
        .into_iter()
        .filter(session_running)
        .collect();
    let environment = environment_name(&target);
    // `cw msg ENV SESSION TEXT` once named the session; a first word that
    // names a running session is refused, never sent to another one.
    let (first, rest) = message
        .text
        .split_once(' ')
        .unwrap_or((message.text.as_str(), ""));
    if running.iter().any(|view| view.name == first) {
        return Err(with_next_step(
            anyhow::anyhow!(
                "the session {first:?} is in {environment}; name it with --session so it isn't sent as text"
            ),
            format!("cw {command} {environment} --session {first} {rest}"),
        ));
    }
    match running.as_slice() {
        [] => Err(with_next_step(
            anyhow::anyhow!("nothing is running in {environment} to send to"),
            format!("cw ls {environment}"),
        )),
        [view] => Ok((target, view.clone())),
        views => {
            let names = views.iter().map(session_name).collect::<Vec<_>>();
            let repair = with_next_step(
                anyhow::anyhow!(
                    "there are {} running sessions in {environment} ({}); name one with --session",
                    views.len(),
                    names.join(", ")
                ),
                format!(
                    "cw {command} {environment} --session {} {}",
                    names[0], message.text
                ),
            );
            if matches!(output, OutputFormat::Json)
                || !Capabilities::from_process(OutputMode::Text).interactive
            {
                return Err(repair);
            }
            let view = super::super::select_session_from_picker(
                &environment,
                views,
                "to send to",
                crate::error_report::sentence(&repair),
            )
            .await?;
            Ok((target, view))
        }
    }
}

/// The sessions a message can go to now: the running ones. An environment
/// whose sessions can't be listed has none to offer.
async fn running_sessions(target: &EnvironmentSessionTarget) -> Vec<EnvironmentSessionView> {
    target
        .list()
        .await
        .map(|sessions| sessions.into_iter().filter(session_running).collect())
        .unwrap_or_default()
}

/// `cw msg` with nothing to send: how to send, and to what (#5085).
fn message_usage(
    command: &str,
    target: Option<&EnvironmentSessionTarget>,
    running: &[EnvironmentSessionView],
) -> anyhow::Error {
    let environment = target.map_or_else(|| "ENV".to_owned(), environment_name);
    let sessions = if running.is_empty() {
        String::new()
    } else {
        let names = running.iter().map(session_name).collect::<Vec<_>>();
        format!("; {environment}'s running sessions: {}", names.join(", "))
    };
    let session = match running {
        [_] | [] => String::new(),
        [view, ..] => format!(" --session {}", session_name(view)),
    };
    with_next_step(
        anyhow::anyhow!(
            "say what to send: `cw {command} [ENV] [--session SESSION] TEXT`{sessions}"
        ),
        format!("cw {command} {environment}{session} continue"),
    )
}

/// Writes the text and Enter to a normal session's terminal, once.
async fn write_terminal_message(
    target: &EnvironmentSessionTarget,
    view: &EnvironmentSessionView,
    text: &str,
    label: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let message = terminal_message_bytes(text, view.pty)?;
    anyhow::ensure!(
        session_running(view),
        "session {label} is {}; it cannot receive input. Start it with `cw restart {} --session {}`",
        view.state.to_ascii_lowercase(),
        environment_name(target),
        session_name(view)
    );
    let (environment, session) = (environment_name(target), session_name(view));
    let written = write_terminal_message_with(message, TERMINAL_ENTER_DELAY, |data| {
        target.send_input(&view.session_id, data)
    })
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "the write to {label} was not confirmed ({error:#}); it may or may not have reached the terminal and was not retried. Check with `cw attach {environment} --session {session}` before resending."
        )
    })?;
    let submitted = matches!(written, TerminalWrite::Submitted);
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "delivery": "terminal",
                "environment": environment,
                "session": view.name,
                "session_id": view.session_id,
                "submitted": submitted,
            }))?
        ),
        OutputFormat::Text if submitted => println!("Sent to terminal {label}."),
        OutputFormat::Text => {}
    }
    if let TerminalWrite::EnterUnconfirmed(error) = written {
        return Err(error.context(format!(
            "Text written to {label}; Enter not confirmed. Check with `cw attach {environment} --session {session}` before resending."
        )));
    }
    Ok(())
}

/// The existing managed delivery for each placement.
async fn deliver_managed(
    target: EnvironmentSessionTarget,
    view: EnvironmentSessionView,
    args: &AgentMessageArgs,
    text: &str,
    steer: bool,
    label: &str,
) -> anyhow::Result<()> {
    validate_text(text)?;
    let reply_to = args.reply_to.as_deref().map(canonical_uuid).transpose()?;
    if let Some(turn) = &args.turn_id {
        validate_token("turn ID", turn)?;
    }
    match target {
        EnvironmentSessionTarget::Platform { .. } => {
            platform_host::message(target, &view.session_id, args, text, steer, label).await
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        EnvironmentSessionTarget::NativeLocal { .. } => {
            native_host::message(
                target,
                &view.session_id,
                text,
                reply_to,
                args.turn_id.clone(),
                steer,
                args.output,
                label,
            )
            .await
        }
        EnvironmentSessionTarget::Host { environment, .. } => {
            let managed = managed_conversation(&environment, view)?;
            ensure_accepting(&managed)?;
            let record = host_message_record(
                &managed,
                uuid::Uuid::new_v4().to_string(),
                text,
                reply_to,
                steer,
                args.turn_id.clone(),
            )?;
            let record = deliver_cli_message(&managed, record).await?;
            print_message_delivery(&record, args.output, steer, label)?;
            match message_failure(&record) {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }
    }
}

/// A managed result with the top-level `delivery` key, its own fields kept
/// unchanged and in their order.
#[derive(serde::Serialize)]
pub(super) struct Delivered<'a, T: serde::Serialize> {
    pub(super) delivery: &'static str,
    #[serde(flatten)]
    pub(super) fields: &'a T,
}

/// A managed message's ID and actual state. A steer keeps its own output.
pub(super) fn print_message_delivery(
    record: &MessageRecord,
    output: OutputFormat,
    steer: bool,
    label: &str,
) -> anyhow::Result<()> {
    if steer {
        return print_message_summary(record, output);
    }
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&Delivered {
                delivery: "managed",
                fields: record,
            })?
        ),
        OutputFormat::Text => {
            print!(
                "{}",
                format_managed_message(&record.id, Some(&state_label(record)), label)
            );
            if let Some(error) = &record.error {
                eprintln!("{error}");
            }
        }
    }
    Ok(())
}

/// `✓ Message ID accepted`, the conversation, and how to wait for it.
pub(super) fn format_managed_message(id: &str, state: Option<&str>, label: &str) -> String {
    let style = Capabilities::from_process(OutputMode::Text).stdout_style();
    let status = match state {
        Some("accepted" | "running" | "completed") => Status::Done,
        Some("error" | "unknown" | "interrupted" | "undelivered") => Status::Failed,
        _ => Status::Attention,
    };
    let mut out = format!(
        "{} Message {} {}\n  Conversation  {label} (managed)\n",
        style.status(status),
        terminal_text(id),
        state
            .map(terminal_text)
            .unwrap_or_else(|| "sent; its state could not be read".into()),
    );
    if status != Status::Failed {
        out.push_str(&format!(
            "{} cw wait --message {}\n",
            style.status(Status::Next),
            terminal_text(id)
        ));
    }
    out
}

pub(crate) async fn handle_inbox_command(globals: &Globals, args: InboxArgs) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::super::member_control::managed::inbox(globals, args).await;
    }
    let selection = select_session(
        "inbox",
        args.environment.clone(),
        args.in_environment.clone(),
        &args.retired_session,
        args.session.clone(),
    )?;
    let (target, view) = resolve_session(
        globals,
        selection.environment.as_deref(),
        &selection.session,
    )
    .await?;
    if !is_managed_session(&view) {
        return print_terminal_inbox(globals, &target, &view, args.output);
    }
    match target {
        EnvironmentSessionTarget::Platform { .. } => {
            platform_host::inbox(target, &view.session_id, args.output).await
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        EnvironmentSessionTarget::NativeLocal { .. } => {
            native_host::inbox(target, &view.session_id, args.output).await
        }
        EnvironmentSessionTarget::Host { environment, .. } => {
            host_inbox(managed_conversation(&environment, view)?, args.output)
        }
    }
}

/// A terminal session has no structured inbox: say so, and give the exact
/// commands that read and reattach it. Never an empty managed inbox.
fn print_terminal_inbox(
    globals: &Globals,
    target: &EnvironmentSessionTarget,
    view: &EnvironmentSessionView,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let placement = match globals.placement {
        Some(EnvironmentPlacement::Platform) => "--cloud ",
        Some(EnvironmentPlacement::Local) => "--local ",
        None => "",
    };
    let (environment, session) = (environment_name(target), session_name(view));
    let logs = format!("cw {placement}logs {environment} --session {session}");
    let attach = format!("cw {placement}attach {environment} --session {session}");
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "delivery": "terminal",
                "environment": environment,
                "session": view.name,
                "session_id": view.session_id,
                "inbox": null,
                "logs_command": logs,
                "attach_command": attach,
            }))?
        ),
        OutputFormat::Text => print!(
            "{}",
            format_terminal_inbox(&conversation_label(target, view), &logs, &attach)
        ),
    }
    Ok(())
}

pub(super) fn format_terminal_inbox(label: &str, logs: &str, attach: &str) -> String {
    let style = Capabilities::from_process(OutputMode::Text).stdout_style();
    let next = style.status(Status::Next);
    format!(
        "{label} is a terminal session; it has no structured inbox.\n  `cw msg` types into its terminal and records no messages or replies.\n\n{next} Read its output: {logs}\n{next} Reattach:        {attach}\n"
    )
}

/// A trusted host's managed conversation: its messages and their results.
fn host_inbox(managed: ManagedConversation, output: OutputFormat) -> anyhow::Result<()> {
    let state = read_optional::<DriverState>(&managed.dir.join("state.json"))?;
    let mut messages = list_messages(&managed.dir)?;
    let total = messages.len();
    if total > INBOX_LIMIT {
        messages = messages.split_off(total - INBOX_LIMIT);
    }
    match output {
        OutputFormat::Json => {
            let views: Vec<Value> = messages
                .iter()
                .map(|record| message_view(&managed.environment, record))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "delivery": "managed",
                    "environment_id": managed.environment.id,
                    "session_id": managed.session.session_id,
                    "session_state": managed.session.state,
                    "driver_id": managed.config.driver_id,
                    "agent": managed.config.agent.name(),
                    "model": managed.config.model,
                    "effort": managed.config.effort,
                    "parent": managed.config.parent,
                    "driver": state,
                    "messages_total": total,
                    "messages": views,
                }))?
            );
        }
        OutputFormat::Text => {
            match &state {
                Some(state) => println!(
                    "{}\t{}\t{}\tsession {}\tdriver {}\tturn {}\tqueued {}\tsteer {}\tinterrupt {}",
                    session_label(&managed.session),
                    managed.config.agent.name(),
                    managed.config.model,
                    managed.session.state,
                    serde_json::to_value(state.phase)?
                        .as_str()
                        .unwrap_or("unknown"),
                    state
                        .current_turn_id
                        .as_deref()
                        .or(state.active_message_id.as_deref())
                        .unwrap_or("-"),
                    state.queued,
                    if state.capabilities.steer {
                        "yes"
                    } else {
                        "no"
                    },
                    if state.capabilities.interrupt {
                        "yes"
                    } else {
                        "no"
                    },
                ),
                None => println!(
                    "{}\t{}\t{}\tsession {}\tdriver has not reported state",
                    session_label(&managed.session),
                    managed.config.agent.name(),
                    managed.config.model,
                    managed.session.state
                ),
            }
            if let Some(error) = state.as_ref().and_then(|state| state.last_error.as_deref()) {
                println!("last error: {error}");
            }
            if messages.is_empty() {
                println!("No messages");
            }
            if total > messages.len() {
                println!("({} older messages omitted)", total - messages.len());
            }
            for record in &messages {
                let summary = record
                    .error
                    .as_deref()
                    .or(record.result.as_deref())
                    .unwrap_or(record.text.as_str());
                let summary = summary.lines().next().unwrap_or_default();
                let (summary, truncated) = truncate_utf8(summary, 80);
                println!(
                    "{}\t{}\t{}\t{}\t{}{}{}",
                    record.id,
                    record.action.name(),
                    state_label(record),
                    record.created_at,
                    summary,
                    if truncated { "…" } else { "" },
                    noel::resumed_note(record)
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(name: &str) -> EnvironmentSessionView {
        EnvironmentSessionView {
            name: name.to_owned(),
            parent_session_id: String::new(),
            started_at: String::new(),
            cleanup_unknown: false,
            launch_generation: 1,
            session_id: format!("session-{name}"),
            state: "Running".to_owned(),
            command: vec!["codex".to_owned()],
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    /// Bare `cw msg` (#5085): how to send, then what it could go to.
    #[test]
    fn a_message_with_no_text_says_how_to_send_and_to_what() {
        let shown = |error: anyhow::Error| {
            (
                crate::error_report::sentence(&error),
                crate::error_report::next_step(&error),
            )
        };
        assert_eq!(
            shown(message_usage("msg", None, &[])),
            (
                "say what to send: `cw msg [ENV] [--session SESSION] TEXT`".to_owned(),
                Some("cw msg ENV continue".to_owned())
            )
        );
        assert_eq!(
            shown(message_usage("msg", None, &[running("redteam")])).1,
            Some("cw msg ENV continue".to_owned())
        );
        let (message, step) = shown(message_usage(
            "msg",
            None,
            &[running("redteam"), running("lead")],
        ));
        assert!(
            message.ends_with("; ENV's running sessions: redteam, lead"),
            "{message}"
        );
        assert_eq!(
            step.as_deref(),
            Some("cw msg ENV --session redteam continue")
        );
    }

    #[test]
    fn terminal_messages_end_with_the_key_their_input_submits_on() {
        assert_eq!(
            terminal_message_bytes("Add tests", true).unwrap(),
            TerminalMessage {
                text: b"Add tests".to_vec(),
                enter: Some(b"\r"),
            }
        );
        assert_eq!(
            terminal_message_bytes("Add tests", false).unwrap(),
            TerminalMessage {
                text: b"Add tests\n".to_vec(),
                enter: None,
            }
        );
        assert!(TERMINAL_ENTER_DELAY >= Duration::from_millis(300));
        assert!(terminal_message_bytes("", true).is_err());
        let limit = "x".repeat(MAX_TEXT_BYTES - 1);
        assert!(terminal_message_bytes(&limit, false).is_ok());
        let over = "x".repeat(MAX_TEXT_BYTES);
        let error = terminal_message_bytes(&over, false)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&MAX_TEXT_BYTES.to_string()), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_message_writes_its_text_then_enter_separately_and_once() {
        let writes = std::sync::Mutex::new(Vec::new());
        let started = tokio::time::Instant::now();
        let record = |data: Vec<u8>| {
            writes.lock().unwrap().push((data, started.elapsed()));
            async { Ok(()) }
        };
        let outcome = write_terminal_message_with(
            terminal_message_bytes("Add tests", true).unwrap(),
            TERMINAL_ENTER_DELAY,
            record,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TerminalWrite::Submitted));
        let writes = writes.into_inner().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].0, b"Add tests");
        assert_eq!(writes[1].0, b"\r");
        assert!(writes[1].1 - writes[0].1 >= TERMINAL_ENTER_DELAY);

        // A line-reading session gets one write.
        let mut lines = Vec::new();
        write_terminal_message_with(
            terminal_message_bytes("Add tests", false).unwrap(),
            TERMINAL_ENTER_DELAY,
            |data| {
                lines.push(data);
                async { Ok(()) }
            },
        )
        .await
        .unwrap();
        assert_eq!(lines, [b"Add tests\n".to_vec()]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_write_is_reported_and_never_retried() {
        // The text fails: an error, and no Enter follows.
        let mut attempts = 0;
        let error = write_terminal_message_with(
            terminal_message_bytes("Add tests", true).unwrap(),
            TERMINAL_ENTER_DELAY,
            |_| {
                attempts += 1;
                async { anyhow::bail!("connection reset") }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(error.to_string().contains("connection reset"));

        // The Enter fails: the text stands, the Enter is not sent again.
        let mut sent = Vec::new();
        let outcome = write_terminal_message_with(
            terminal_message_bytes("Add tests", true).unwrap(),
            TERMINAL_ENTER_DELAY,
            |data| {
                let enter = data == b"\r";
                sent.push(data);
                async move {
                    anyhow::ensure!(!enter, "connection reset");
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TerminalWrite::EnterUnconfirmed(_)));
        assert_eq!(sent, [b"Add tests".to_vec(), b"\r".to_vec()]);
    }

    #[test]
    fn a_terminal_inbox_gives_the_exact_logs_and_attach_commands() {
        let text = format_terminal_inbox(
            "app/coding",
            "cw logs app --session coding",
            "cw attach app --session coding",
        );
        assert!(
            text.starts_with("app/coding is a terminal session; it has no structured inbox.\n")
        );
        assert!(text.contains("Read its output: cw logs app --session coding\n"));
        assert!(text.contains("Reattach:        cw attach app --session coding\n"));
        assert!(!text.contains("No messages"));
    }

    #[test]
    fn a_managed_message_names_its_id_state_and_wait() {
        let text = format_managed_message("6c3f", Some("accepted"), "app/review");
        assert!(text.contains("Message 6c3f accepted\n  Conversation  app/review (managed)\n"));
        assert!(text.ends_with("cw wait --message 6c3f\n"));
        let failed = format_managed_message("6c3f", Some("error"), "app/review");
        assert!(!failed.contains("cw wait"));
        let unread = format_managed_message("6c3f", None, "app/review");
        assert!(unread.contains("Message 6c3f sent; its state could not be read"));
    }
}
