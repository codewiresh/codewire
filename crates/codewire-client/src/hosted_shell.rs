//! A hosted environment's shell that survives the network (#3827): the
//! connection logic of plain `cw shell`, without the terminal, so every
//! client runs the same loop (#3825).
//!
//! The shell is an unnamed daemon session launched with a 10-minute grace:
//! after a drop (sleep, a Wi-Fi change) it is reattached from its output
//! offset and nothing is lost; it ends with `exit`, and the daemon ends it
//! once no client has been attached for 10 minutes, so abandoned shells don't
//! pile up. Each attachment goes over the environment's tailnet first (direct
//! UDP, then peer relay, then DERP) and over the API only when the tailnet
//! cannot carry it.
//!
//! A client brings a [`ShellTerminal`]: where keys come from, where output
//! goes, and how its user is told what the connection does.

use std::future::Future;
use std::time::{Duration, Instant};

use crate::tailnet_session::{EnvironmentTailnet, TailnetPathReport};
use crate::{
    AttachSessionOpen, AttachSessionRequest, AttachSessionResize, ClientError, CodewireClient,
    EnvironmentSession, EnvironmentSessionAttachment, EnvironmentSessionState,
    LaunchSessionRequest, SshTransportMode, attach_session_request, attach_session_response,
};
pub use input_stream::{InputNotice, InputStream};
use restart::ServerAnswer as _;

/// How long the shell keeps running with no client attached (owner,
/// 2026-11-01, on #3827), and so how long a client keeps trying to reattach
/// after a drop.
pub const SHELL_GRACE: Duration = Duration::from_secs(10 * 60);

/// How soon a shell on the API fallback tries the tailnet again, and how far
/// apart the tries grow. The API is the last resort (owner, 2026-11-01, on
/// #3827), and a fallback can come from a failure that has already cleared:
/// a long network cut lands here as soon as the network returns (#3895).
pub const TAILNET_RETRY_FIRST: Duration = Duration::from_secs(5);
const TAILNET_RETRY_LIMIT: Duration = Duration::from_secs(60);

/// How long a first tailnet connection waits for direct UDP before it says
/// which path it is on; every connection starts on DERP and usually moves to
/// direct UDP within this time.
pub const TAILNET_DIRECT_WAIT: Duration = Duration::from_secs(2);

/// Far longer than the server takes: it answers on opening, and its heartbeat
/// is 15 s.
const API_ATTACH_ANSWER_WAIT: Duration = Duration::from_secs(30);

/// Why a hosted shell or an attachment failed.
#[derive(Debug, thiserror::Error)]
pub enum HostedShellError {
    /// The server's answer, for the client to word.
    #[error(transparent)]
    Client(ClientError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The path an attachment took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// The tailnet; its path, if it could be read.
    Tailnet(Option<TailnetPathReport>),
    /// The API, and why not the tailnet.
    Api { tailnet_unavailable: String },
}

/// What a hosted shell tells its user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellNotice {
    /// An attachment opened, over this path.
    Attached(Via),
    /// The connection dropped; reconnecting to the same shell. Once per drop.
    Reconnecting,
    /// After a reattach: the keys typed during the drop were sent again, or
    /// were lost (#3993).
    Input(InputNotice),
    /// The environment is restarting, such as when its runtime is replaced
    /// (#4342); the shell waits for it. Once per restart.
    Restarting,
}

/// The local end of a hosted shell: where its keys come from, where its
/// output goes, and what its user is told.
pub trait ShellTerminal {
    type Keys: TerminalKeys;
    type Sizes: TerminalSizes;
    type Output: TerminalOutput;

    /// Take the terminal for one attachment. Dropping the parts, keys first,
    /// gives it back, between attachments as well as at the end.
    #[allow(clippy::type_complexity)]
    fn attach(
        &mut self,
    ) -> impl Future<Output = anyhow::Result<AttachedTerminal<Self::Keys, Self::Sizes, Self::Output>>>;

    fn notice(&mut self, notice: ShellNotice);
}

/// The terminal during one attachment, in parts that run independently.
pub struct AttachedTerminal<K, S, O> {
    pub keys: K,
    pub sizes: S,
    pub output: O,
}

pub trait TerminalKeys {
    /// The next keys, or `None` once no more can come.
    fn read(&mut self) -> impl Future<Output = Option<Vec<u8>>>;
}

pub trait TerminalSizes {
    /// The size now, if the terminal has one.
    fn current(&mut self) -> Option<(u16, u16)>;

    /// The next size it changed to, if it can say.
    fn changed(&mut self) -> impl Future<Output = Option<(u16, u16)>>;
}

pub trait TerminalOutput {
    /// Show the shell's output.
    fn write(&mut self, data: &[u8]) -> impl Future<Output = std::io::Result<()>>;
}

/// The shell to launch: its command, environment and terminal.
pub struct ShellLaunch {
    pub command: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
    pub term: String,
    pub columns: u16,
    pub rows: u16,
}

/// Launch the shell and run it to its end. Returns its exit status.
pub async fn run(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    launch: ShellLaunch,
    terminal: &mut impl ShellTerminal,
) -> Result<i32, HostedShellError> {
    let ask = || restart::ask_environment(client, org_id, environment_id);
    let request = LaunchSessionRequest {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        command: launch.command,
        env: launch.env.into_iter().collect(),
        pty: true,
        term: launch.term,
        columns: launch.columns.into(),
        rows: launch.rows.into(),
        end_after_detached_seconds: SHELL_GRACE.as_secs() as u32,
        ..Default::default()
    };
    // Started while the environment restarts, the shell waits for it (#4342).
    let launched = restart::through_restart(
        &ask,
        || terminal.notice(ShellNotice::Restarting),
        || async {
            client
                .launch_session(request.clone())
                .await
                .map_err(HostedShellError::Client)
        },
    )
    .await?;
    let session_id = launched
        .session
        .as_option()
        .map(|session| session.session_id.clone())
        .ok_or_else(|| anyhow::anyhow!("the launched shell has no session id"))?;

    let mut tailnet = None;
    let mut output_offset = 0;
    let mut input_stream = InputStream::default();
    let mut dropped_at: Option<Instant> = None;
    let mut attempt = 0_u32;
    let mut retry_after = TAILNET_RETRY_FIRST;
    loop {
        let (stream, input_offset) = input_stream.open();
        let open = AttachSessionOpen {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            session_id: session_id.clone(),
            output_offset,
            input_stream: stream,
            input_offset,
            ..Default::default()
        };
        let pumped = match attach(client, open, &mut tailnet).await {
            Ok((attachment, via)) => {
                terminal.notice(ShellNotice::Attached(via));
                dropped_at = None;
                attempt = 0;
                if tailnet.is_some() {
                    retry_after = TAILNET_RETRY_FIRST;
                }
                let on_fallback = on_api_fallback(&tailnet)?;
                let back = async {
                    if !on_fallback {
                        return std::future::pending().await;
                    }
                    tailnet_again(client, org_id, environment_id, retry_after).await
                };
                pump(attachment, output_offset, &mut input_stream, terminal, back).await?
            }
            Err(error) => {
                // A restart is waited out and doesn't count as a lost network
                // (#4342): its time can outlast SHELL_GRACE, and the
                // environment's daemon starts after it, so the next reattach
                // is paced as after a drop.
                if restart::failed_for_restart(&ask, &error).await {
                    terminal.notice(ShellNotice::Restarting);
                    restart::wait_for_restart(&ask).await?;
                    dropped_at = Some(Instant::now());
                    attempt = attempt.max(1);
                    continue;
                }
                // After a drop only the network is worth trying again; any
                // other answer, such as the session gone, is the server's.
                let network = error
                    .server_answer()
                    .is_none_or(restart::is_network_failure);
                if dropped_at.is_none() || !network {
                    return Err(error);
                }
                tracing::debug!(error = %error_chain(&error), "reattach failed");
                Pumped::Interrupted { output_offset }
            }
        };
        match pumped {
            Pumped::Ended(Ok(status)) => return Ok(status),
            Pumped::Ended(Err(reason)) => {
                return Err(anyhow::anyhow!("the shell ended: {reason}").into());
            }
            Pumped::Interrupted {
                output_offset: next,
            } => {
                output_offset = next;
                let since = *dropped_at.get_or_insert_with(Instant::now);
                if since.elapsed() >= SHELL_GRACE {
                    return Err(anyhow::anyhow!(
                        "the connection to the environment was lost for 10 minutes; the shell has ended"
                    )
                    .into());
                }
                if attempt == 0 {
                    terminal.notice(ShellNotice::Reconnecting);
                }
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt.min(8)))).await;
            }
            Pumped::TailnetBack {
                output_offset: next,
                tailnet: connected,
            } => {
                output_offset = next;
                tailnet = Some(connected);
                // Longer next time, if this attachment lands on the API again.
                retry_after = next_retry(retry_after);
            }
        }
    }
}

fn error_chain(error: &HostedShellError) -> String {
    match error {
        HostedShellError::Client(error) => error.to_string(),
        HostedShellError::Other(error) => format!("{error:#}"),
    }
}

/// Attach to a hosted environment's session over its tailnet first: direct
/// UDP, then peer relay, then DERP (#3827). The API carries it only when the
/// tailnet cannot, and the result says which path it took and why.
/// `CW_SSH_TRANSPORT=tailnet` refuses the API fallback;
/// `CW_SSH_TRANSPORT=websocket` skips the tailnet.
pub async fn attach(
    client: &CodewireClient,
    open: AttachSessionOpen,
    tailnet: &mut Option<EnvironmentTailnet>,
) -> Result<(EnvironmentSessionAttachment, Via), HostedShellError> {
    let mode = SshTransportMode::from_env()?;
    let fallback = if mode == SshTransportMode::WebSocket {
        "CW_SSH_TRANSPORT=websocket".to_owned()
    } else {
        if tailnet.as_ref().is_some_and(EnvironmentTailnet::is_closed) {
            *tailnet = None;
        }
        let mut reason = None;
        if tailnet.is_none() {
            match EnvironmentTailnet::connect(client, &open.org_id, &open.environment_id).await {
                Ok(connected) => {
                    connected.wait_for_direct(TAILNET_DIRECT_WAIT).await.ok();
                    *tailnet = Some(connected);
                }
                Err(error) if mode == SshTransportMode::Tailnet => {
                    return Err(error
                        .context("tailnet attach (CW_SSH_TRANSPORT=tailnet)")
                        .into());
                }
                Err(error) => reason = Some(format!("{error:#}")),
            }
        }
        if let Some(connected) = tailnet.as_ref() {
            match connected.attach(open.clone()).await {
                Ok(attachment) => {
                    return Ok((attachment, Via::Tailnet(connected.path().ok())));
                }
                Err(error) if mode == SshTransportMode::Tailnet => {
                    return Err(HostedShellError::Client(error));
                }
                Err(error) => {
                    *tailnet = None;
                    reason = Some(error.message().to_owned());
                }
            }
        }
        reason.unwrap_or_else(|| "the tailnet is unavailable".into())
    };
    let attachment = attach_over_api(client, open)
        .await
        .map_err(HostedShellError::Client)?;
    Ok((
        attachment,
        Via::Api {
            tailnet_unavailable: fallback,
        },
    ))
}

/// Attach over the API, once the server has answered: only then is the
/// session reached, whatever the stream says about itself (#3895).
pub async fn attach_over_api(
    client: &CodewireClient,
    open: AttachSessionOpen,
) -> Result<EnvironmentSessionAttachment, ClientError> {
    let mut attachment = client.attach_session(open).await?;
    attachment.wait_for_answer(API_ATTACH_ANSWER_WAIT).await?;
    Ok(attachment)
}

/// Whether an attachment that has just opened came in over the API because
/// the tailnet failed, rather than because `CW_SSH_TRANSPORT` asked for it.
pub fn on_api_fallback(tailnet: &Option<EnvironmentTailnet>) -> anyhow::Result<bool> {
    Ok(tailnet.is_none() && SshTransportMode::from_env()? == SshTransportMode::Auto)
}

/// The tailnet, tried until it connects: after `first`, then at growing
/// intervals.
pub async fn tailnet_again(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    first: Duration,
) -> EnvironmentTailnet {
    keep_trying(first, || async {
        let connected = EnvironmentTailnet::connect(client, org_id, environment_id).await?;
        connected.wait_for_direct(TAILNET_DIRECT_WAIT).await.ok();
        anyhow::Ok(connected)
    })
    .await
}

/// Runs `attempt` after `first`, then at growing intervals, until it succeeds.
async fn keep_trying<T, F, Attempt>(first: Duration, mut attempt: F) -> T
where
    F: FnMut() -> Attempt,
    Attempt: Future<Output = anyhow::Result<T>>,
{
    let mut delay = first;
    loop {
        tokio::time::sleep(delay).await;
        match attempt().await {
            Ok(value) => return value,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "tailnet retry failed");
            }
        }
        delay = next_retry(delay);
    }
}

pub fn next_retry(delay: Duration) -> Duration {
    (delay * 2).min(TAILNET_RETRY_LIMIT)
}

/// Whether a session has ended, by its state.
pub fn session_has_ended(session: &EnvironmentSession) -> bool {
    matches!(
        session.state.as_known(),
        Some(
            EnvironmentSessionState::Stopped
                | EnvironmentSessionState::Exited
                | EnvironmentSessionState::Failed
                | EnvironmentSessionState::Interrupted
        )
    )
}

/// How one attachment ended.
#[derive(Debug, PartialEq)]
enum Pumped<T> {
    /// The shell ended; its exit status, or the session's reason.
    Ended(Result<i32, String>),
    /// The connection dropped; reattach from here.
    Interrupted { output_offset: u64 },
    /// The tailnet came back while on the API; reattach over it from here.
    TailnetBack { output_offset: u64, tailnet: T },
}

/// Carry one attachment: keys in, output out, resizes; every byte passes
/// through. It ends early if `tailnet_back` completes.
async fn pump<T>(
    mut attachment: EnvironmentSessionAttachment,
    mut output_offset: u64,
    input_stream: &mut InputStream,
    terminal: &mut impl ShellTerminal,
    tailnet_back: impl Future<Output = T>,
) -> Result<Pumped<T>, HostedShellError> {
    tokio::pin!(tailnet_back);
    let input = attachment.input_handle();
    let AttachedTerminal {
        mut keys,
        mut sizes,
        mut output,
    } = terminal.attach().await?;
    if let Some((columns, rows)) = sizes.current() {
        let _ = input.send(resize(columns, rows)).await;
    }
    input_stream.attaching();
    let mut keys_open = true;
    let pumped = loop {
        tokio::select! {
            tailnet = &mut tailnet_back => break Pumped::TailnetBack { output_offset, tailnet },
            read = keys.read(), if keys_open => match read {
                None => keys_open = false,
                Some(keys) => {
                    if let Some(request) = input_stream.typed(keys, Instant::now())
                        && input.send(request).await.is_err()
                    {
                        break Pumped::Interrupted { output_offset };
                    }
                }
            },
            size = sizes.changed() => {
                if let Some((columns, rows)) = size {
                    let _ = input.send(resize(columns, rows)).await;
                }
            }
            event = attachment.next_output() => match event {
                Ok(Some(response)) => match response.event {
                    Some(attach_session_response::Event::Output(chunk)) => {
                        output.write(&chunk.data).await.map_err(anyhow::Error::from)?;
                        output_offset = chunk.next_offset;
                    }
                    Some(attach_session_response::Event::HistoryGap(gap)) => {
                        output_offset = gap.retained_start_offset;
                    }
                    Some(attach_session_response::Event::Status(status)) => {
                        let written = status.session.as_option().and_then(|session| session.input_end_offset);
                        let (requests, notices) = input_stream.status(written, Instant::now());
                        let mut sent = true;
                        for request in requests {
                            sent &= input.send(request).await.is_ok();
                        }
                        for notice in notices {
                            terminal.notice(ShellNotice::Input(notice));
                        }
                        if !sent {
                            break Pumped::Interrupted { output_offset };
                        }
                        if let Some(session) = status.session.as_option()
                            && session_has_ended(session)
                        {
                            break Pumped::Ended(match session.exit_code {
                                Some(code) => Ok(code),
                                None => Err(session.status_message.clone()),
                            });
                        }
                    }
                    None => {}
                },
                Ok(None) => break Pumped::Interrupted { output_offset },
                Err(error) if error.is_retryable_transport_interruption() => {
                    break Pumped::Interrupted { output_offset };
                }
                Err(error) => return Err(HostedShellError::Client(error)),
            },
        }
    };
    drop(keys);
    drop(sizes);
    drop(output);
    Ok(pumped)
}

fn resize(columns: u16, rows: u16) -> AttachSessionRequest {
    AttachSessionRequest {
        input: Some(attach_session_request::Input::Resize(Box::new(
            AttachSessionResize {
                columns: columns.into(),
                rows: rows.into(),
                ..Default::default()
            },
        ))),
        ..Default::default()
    }
}

#[path = "hosted_shell/input_stream.rs"]
mod input_stream;
#[path = "hosted_shell/restart.rs"]
pub mod restart;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_tailnet_is_tried_at_growing_intervals_until_it_connects() {
        let started = tokio::time::Instant::now();
        let mut tries = Vec::new();
        let value = keep_trying(TAILNET_RETRY_FIRST, || {
            tries.push(started.elapsed().as_secs());
            let attempt = tries.len();
            async move {
                if attempt < 6 {
                    anyhow::bail!("not yet");
                }
                Ok(attempt)
            }
        })
        .await;
        assert_eq!(value, 6);
        assert_eq!(tries, [5, 15, 35, 75, 135, 195], "capped at one a minute");
    }

    /// A terminal with no keys and no size, which discards output.
    struct Detached;

    impl ShellTerminal for Detached {
        type Keys = Detached;
        type Sizes = Detached;
        type Output = Detached;

        async fn attach(
            &mut self,
        ) -> anyhow::Result<AttachedTerminal<Detached, Detached, Detached>> {
            Ok(AttachedTerminal {
                keys: Detached,
                sizes: Detached,
                output: Detached,
            })
        }

        fn notice(&mut self, _: ShellNotice) {}
    }

    impl TerminalKeys for Detached {
        async fn read(&mut self) -> Option<Vec<u8>> {
            None
        }
    }

    impl TerminalSizes for Detached {
        fn current(&mut self) -> Option<(u16, u16)> {
            None
        }

        async fn changed(&mut self) -> Option<(u16, u16)> {
            std::future::pending().await
        }
    }

    impl TerminalOutput for Detached {
        async fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn output(next_offset: u64) -> Result<crate::AttachSessionResponse, crate::ClientError> {
        Ok(crate::AttachSessionResponse {
            event: Some(attach_session_response::Event::Output(Box::new(
                crate::EnvironmentSessionOutputChunk {
                    next_offset,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_shell_on_the_api_moves_at_its_output_offset_when_the_tailnet_is_back() {
        let (sender, outputs) = tokio::sync::mpsc::channel(4);
        sender.send(output(7)).await.unwrap();
        let back = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "tailnet"
        };
        let attachment = EnvironmentSessionAttachment::from_output(outputs);
        let pumped = pump(
            attachment,
            0,
            &mut InputStream::default(),
            &mut Detached,
            back,
        )
        .await
        .unwrap();
        assert_eq!(
            pumped,
            Pumped::TailnetBack {
                output_offset: 7,
                tailnet: "tailnet",
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_shell_with_no_tailnet_to_return_to_stays_until_its_connection_drops() {
        let (sender, outputs) = tokio::sync::mpsc::channel(4);
        sender.send(output(7)).await.unwrap();
        let carrier = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(600)).await;
            sender.send(output(9)).await.unwrap();
        });
        let attachment = EnvironmentSessionAttachment::from_output(outputs);
        let back = std::future::pending::<()>();
        let pumped = pump(
            attachment,
            0,
            &mut InputStream::default(),
            &mut Detached,
            back,
        )
        .await
        .unwrap();
        carrier.await.unwrap();
        assert_eq!(pumped, Pumped::Interrupted { output_offset: 9 });
    }

    #[test]
    fn a_failed_switch_waits_longer_before_the_next() {
        assert_eq!(next_retry(TAILNET_RETRY_FIRST), Duration::from_secs(10));
        assert_eq!(next_retry(TAILNET_RETRY_LIMIT), TAILNET_RETRY_LIMIT);
    }
}
