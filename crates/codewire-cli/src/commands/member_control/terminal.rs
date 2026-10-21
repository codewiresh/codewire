//! First remote slice: ordinary durable commands, acknowledged stdin, retained
//! output and exact-generation Stop. No PTY, provider or managed mailbox API.
use super::super::sessions::{
    LogsAnsiFilter, host_environment_session_view, print_environment_sessions,
    session_output_tail_start, write_session_output,
};
use super::*;

async fn open(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<(store::Directory, transport::Remote)> {
    let selected = globals
        .member
        .as_deref()
        .context("member selection required")?;
    let dir = directory(false)?;
    let alias = store::Alias::load(&dir, selected)?;
    if let Some(environment) = environment {
        ensure!(
            environment == alias.binding.environment_id,
            "member environment must be the exact saved UUID"
        );
    }
    let remote = transport::Remote::connect(&dir, alias, globals).await?;
    Ok((dir, remote))
}
fn target<'a>(values: &'a [String], env: &str) -> anyhow::Result<&'a str> {
    let id = match values {
        [id] => id,
        [environment, id] => {
            ensure!(
                environment == env,
                "member environment must be the exact saved UUID"
            );
            id
        }
        _ => anyhow::bail!("expected --session SESSION, with ENV the exact saved UUID"),
    };
    let uuid = id
        .strip_prefix("session-")
        .context("member session requires its exact canonical session ID")?;
    wire::canonical_uuid(uuid)?;
    Ok(id)
}
fn request_id(value: Option<String>) -> anyhow::Result<String> {
    let id = value.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    wire::canonical_uuid(&id)?;
    eprintln!("[cw] member request {id}; recover an unknown reply with cw member observe");
    Ok(id)
}
fn generation(observed: u64, expected: Option<u64>) -> anyhow::Result<u64> {
    ensure!(
        observed > 0 && expected.is_none_or(|value| value > 0 && value == observed),
        "member session generation differs from expected generation"
    );
    Ok(expected.unwrap_or(observed))
}
fn terminal(session: &v1::SessionRecord) -> bool {
    matches!(session.state, 4..=7)
}
fn guard(session: &v1::SessionRecord, id: &str, generation: u64) -> anyhow::Result<()> {
    ensure!(
        session.session_id == id && session.launch_generation == generation,
        "member retained session incarnation changed"
    );
    Ok(())
}

pub(crate) async fn run(globals: &Globals, args: EnvironmentRunArgs) -> anyhow::Result<()> {
    ensure!(
        args.no_tty
            && !args.tty
            && args.agent.is_none()
            && args.parent.is_none()
            && args.env.is_empty(),
        "member run requires --no-tty; managed agents, parents and environment projection are not admitted"
    );
    ensure!(!args.command.is_empty(), "member command required");
    let id = request_id(args.request_id)?;
    let (dir, mut remote) = open(globals, args.environment.as_deref()).await?;
    let receipt = remote
        .mutate(
            &dir,
            v1::HostControlMutationRequest {
                request_id: id,
                scope: Some(remote.alias.binding.scope()),
                operation: Some(v1::host_control_mutation_request::Operation::Launch(
                    v1::HostControlLaunch {
                        command: args.command,
                        working_dir: args.workdir.unwrap_or_default(),
                        name: args.name.unwrap_or_default(),
                        ..Default::default()
                    },
                )),
            },
        )
        .await?;
    complete(&receipt)?;
    let session = remote.get(&receipt.session_id).await?;
    guard(&session, &receipt.session_id, receipt.launch_generation)?;
    print_environment_sessions(
        &[host_environment_session_view(session.clone())],
        args.output,
    )?;
    if args.detach || matches!(args.output, OutputFormat::Json) {
        return Ok(());
    }
    follow(&mut remote, &session, Duration::from_secs(1800)).await
}
pub(crate) async fn list(globals: &Globals, args: ListArgs) -> anyhow::Result<()> {
    ensure!(
        !args.all && args.environment_type.is_none() && args.state.is_none(),
        "member ls lists the pinned environment's sessions; --all, --type and --state are not admitted"
    );
    let (_, mut remote) = open(globals, args.environment.as_deref()).await?;
    let mut sessions = Vec::new();
    let mut cursor = String::new();
    let mut done = false;
    for _ in 0..128 {
        let page = remote.list(cursor.clone()).await?;
        sessions.extend(page.sessions.into_iter().map(host_environment_session_view));
        if page.next_session_id.is_empty() {
            done = true;
            break;
        }
        ensure!(
            page.next_session_id > cursor,
            "member list cursor did not advance"
        );
        cursor = page.next_session_id;
    }
    ensure!(done, "member list exceeds bounded session inventory");
    print_environment_sessions(&sessions, args.output)
}
pub(crate) async fn send(globals: &Globals, args: SendArgs) -> anyhow::Result<()> {
    ensure!(
        args.key.is_none(),
        "member terminal control keys require a PTY and are not admitted"
    );
    let SendRequest { selection, data } = send_request(&args)?;
    let values = selection.values();
    let id = request_id(args.request_id)?;
    let (dir, mut remote) = open(globals, None).await?;
    let sid = target(&values, &remote.alias.binding.environment_id)?;
    let session = remote.get(sid).await?;
    ensure!(
        !session.command.iter().any(|arg| arg == "_agent-driver"),
        "member managed controls are not admitted"
    );
    let generation = generation(session.launch_generation, args.expected_launch_generation)?;
    let receipt = remote
        .mutate(
            &dir,
            v1::HostControlMutationRequest {
                request_id: id,
                scope: Some(remote.alias.binding.scope()),
                operation: Some(v1::host_control_mutation_request::Operation::Input(
                    v1::HostControlInput {
                        session_id: sid.into(),
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
        "member input acknowledgement unavailable; observe only"
    );
    println!("Input written to {sid}");
    Ok(())
}
pub(crate) async fn stop(globals: &Globals, args: SessionTargetArgs) -> anyhow::Result<()> {
    let id = request_id(args.request_id)?;
    let (dir, mut remote) = open(globals, None).await?;
    let sid = target(&args.target, &remote.alias.binding.environment_id)?;
    let session = remote.get(sid).await?;
    ensure!(
        !session.command.iter().any(|arg| arg == "_agent-driver"),
        "member managed cleanup is not admitted"
    );
    let generation = generation(session.launch_generation, args.expected_launch_generation)?;
    let receipt = remote
        .mutate(
            &dir,
            v1::HostControlMutationRequest {
                request_id: id,
                scope: Some(remote.alias.binding.scope()),
                operation: Some(v1::host_control_mutation_request::Operation::Stop(
                    v1::HostControlStop {
                        session_id: sid.into(),
                        expected_launch_generation: generation,
                    },
                )),
            },
        )
        .await?;
    complete(&receipt)?;
    let stopped = remote.get(sid).await?;
    guard(&stopped, sid, generation)?;
    ensure!(
        terminal(&stopped) && !stopped.cleanup_unknown,
        "member stop cleanup unknown; observe original request"
    );
    print_environment_sessions(&[host_environment_session_view(stopped)], args.output)
}
/// `wait` asks the member only for the session's state, never its output, so
/// its cost does not grow with what the session printed. Read the output with
/// `logs`: a terminal record means the daemon already joined the output tasks.
pub(crate) async fn wait(globals: &Globals, args: WaitArgs) -> anyhow::Result<()> {
    ensure!(
        args.message.is_none(),
        "member managed message wait is not admitted"
    );
    let timeout = tailnet_ssh::parse_duration(&args.timeout)
        .map_err(|e| anyhow::anyhow!("invalid wait timeout: {e}"))?;
    ensure!(!timeout.is_zero(), "wait timeout must be positive");
    let selection = wait_selection(&args)?.context("member wait needs --session")?;
    let values = selection.values();
    let (_, mut remote) = open(globals, None).await?;
    let sid = target(&values, &remote.alias.binding.environment_id)?;
    let initial = remote.get(sid).await?;
    let current = until_terminal(&initial, timeout, async || remote.get(sid).await).await?;
    ensure!(!current.cleanup_unknown, "member terminal cleanup unknown");
    let view = host_environment_session_view(current.clone());
    match args.output {
        OutputFormat::Json => value(serde_json::json!({ "session": view }), args.output)?,
        OutputFormat::Text => {
            print_environment_sessions(&[view], args.output)?;
            if let Some(member) = globals.member.as_deref() {
                eprintln!("[cw] read its output with cw --member {member} logs --session {sid}");
            }
        }
    }
    ensure!(
        current.exit_code == Some(0),
        "session exited with code {:?}",
        current.exit_code
    );
    Ok(())
}

const WAIT_POLL: Duration = Duration::from_millis(200);

/// Polls only the session record until the selected launch is terminal.
async fn until_terminal(
    initial: &v1::SessionRecord,
    timeout: Duration,
    mut get: impl AsyncFnMut() -> anyhow::Result<v1::SessionRecord>,
) -> anyhow::Result<v1::SessionRecord> {
    tokio::time::timeout(timeout, async {
        let mut current = initial.clone();
        loop {
            guard(&current, &initial.session_id, initial.launch_generation)?;
            if terminal(&current) {
                return Ok(current);
            }
            tokio::time::sleep(WAIT_POLL).await;
            current = get().await?;
        }
    })
    .await
    .context("member wait timed out; outcome unknown, command not replayed")?
}

/// A foreground `run` streams the session's output until it exits.
async fn follow(
    remote: &mut transport::Remote,
    initial: &v1::SessionRecord,
    timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, async {
        let mut offset = 0;
        loop {
            let page = remote.output(&initial.session_id, offset).await?;
            if page.history_gap {
                eprintln!("[cw] older member output unavailable");
            }
            for chunk in page.chunks {
                write_session_output(&mut std::io::stdout(), &chunk.data, true)?;
            }
            let advanced = page.next_offset > offset;
            offset = page.next_offset;
            let current = remote.get(&initial.session_id).await?;
            guard(&current, &initial.session_id, initial.launch_generation)?;
            if terminal(&current) && offset >= current.output_end_offset {
                ensure!(!current.cleanup_unknown, "member terminal cleanup unknown");
                ensure!(
                    current.exit_code == Some(0),
                    "session exited with code {:?}",
                    current.exit_code
                );
                return Ok::<_, anyhow::Error>(());
            }
            if !advanced {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    })
    .await
    .context("member wait timed out; outcome unknown, command not replayed")?
}
pub(crate) async fn logs(globals: &Globals, args: SessionLogs) -> anyhow::Result<()> {
    let Some(session) = args.session.clone() else {
        anyhow::bail!("member logs requires --session with the exact session ID");
    };
    let values: Vec<String> = args.environment.iter().cloned().chain([session]).collect();
    let (_, mut remote) = open(globals, None).await?;
    let sid = target(&values, &remote.alias.binding.environment_id)?;
    let initial = remote.get(sid).await?;
    let end = initial.output_end_offset;
    let mut offset = 0;
    let mut bytes = 0;
    let mut tail = args.tail.map(|_| Vec::new());
    let mut ansi = LogsAnsiFilter::default();
    loop {
        let page = remote.output(sid, offset).await?;
        if page.history_gap {
            eprintln!("[cw] older member output unavailable");
            ansi = LogsAnsiFilter::default();
            if let Some(tail) = &mut tail {
                tail.clear();
            }
        }
        for chunk in page.chunks {
            bytes += chunk.data.len();
            ensure!(
                bytes <= 16 * 1024 * 1024,
                "member retained replay exceeds bound"
            );
            if let Some(tail) = &mut tail {
                if args.tail != Some(0) {
                    tail.extend(chunk.data);
                    let start = session_output_tail_start(tail, args.tail);
                    tail.drain(..start);
                }
            } else {
                let data = if args.raw {
                    chunk.data
                } else {
                    ansi.strip(&chunk.data)
                };
                write_session_output(&mut std::io::stdout(), &data, true)?;
            }
        }
        ensure!(
            page.next_offset > offset || offset >= end,
            "member replay did not advance"
        );
        offset = page.next_offset;
        if offset >= end {
            break;
        }
    }
    if let Some(tail) = tail {
        let data = if args.raw { tail } else { ansi.strip(&tail) };
        write_session_output(&mut std::io::stdout(), &data, true)?;
    }
    if args.follow {
        loop {
            let page = remote.output(sid, offset).await?;
            if page.history_gap {
                eprintln!("[cw] older member output unavailable");
                ansi = LogsAnsiFilter::default();
            }
            for chunk in page.chunks {
                let data = if args.raw {
                    chunk.data
                } else {
                    ansi.strip(&chunk.data)
                };
                write_session_output(&mut std::io::stdout(), &data, true)?;
            }
            let advanced = page.next_offset > offset;
            offset = page.next_offset;
            let current = remote.get(sid).await?;
            guard(&current, sid, initial.launch_generation)?;
            if terminal(&current) && offset >= current.output_end_offset {
                break;
            }
            if !advanced {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: i32, generation: u64) -> v1::SessionRecord {
        v1::SessionRecord {
            session_id: format!("session-{}", uuid::Uuid::nil()),
            launch_generation: generation,
            state,
            exit_code: (state == 5).then_some(0),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn wait_on_a_finished_session_reads_nothing_more() {
        let mut reads = 0;
        let done = until_terminal(&record(5, 1), Duration::from_secs(1), async || {
            reads += 1;
            anyhow::bail!("a finished session needs no further read")
        })
        .await
        .unwrap();
        assert_eq!((done.state, reads), (5, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_polls_only_the_session_record_until_it_is_terminal() {
        let mut states = vec![2, 2, 5].into_iter();
        let mut reads = 0;
        let done = until_terminal(&record(2, 1), Duration::from_secs(5), async || {
            reads += 1;
            Ok(record(states.next().unwrap(), 1))
        })
        .await
        .unwrap();
        assert_eq!((done.state, done.exit_code, reads), (5, Some(0), 3));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_refuses_a_replaced_launch() {
        let error = until_terminal(&record(2, 1), Duration::from_secs(5), async || {
            Ok(record(5, 2))
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "member retained session incarnation changed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_timeout_reports_an_unknown_outcome() {
        let mut reads = 0;
        let error = until_terminal(&record(2, 1), Duration::from_secs(1), async || {
            reads += 1;
            Ok(record(2, 1))
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "member wait timed out; outcome unknown, command not replayed"
        );
        assert!((4..=5).contains(&reads), "{reads}");
    }
}
