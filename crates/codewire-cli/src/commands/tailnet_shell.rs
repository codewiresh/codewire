//! Plain `cw shell ENV` on a hosted environment (owner, 2026-11-01, on
//! #3827): a normal shell, like `ssh`, over the environment's tailnet: direct
//! UDP whenever it can work, then peer relay, then DERP.
//!
//! The shell is an unnamed daemon session launched with a 10-minute grace:
//! after a drop (sleep, a Wi-Fi change) this `cw shell` reattaches from its
//! output offset and nothing is lost; it ends with `exit`, and the daemon
//! ends it once no client has been attached for 10 minutes, so abandoned
//! shells don't pile up. No session name, started line or detach hint is
//! shown, and every key, Ctrl+B included, reaches the shell.
//! `cw shell --durable` keeps a named session that outlives the client.

use std::future::Future;
use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use codewire_client::tailnet_session::EnvironmentTailnet;
use codewire_client::{
    AttachSessionOpen, AttachSessionRequest, AttachSessionResize, CodewireClient,
    EnvironmentSessionAttachment, SshTransportMode, attach_session_request,
    attach_session_response,
};
use tokio::io::AsyncWriteExt as _;

use super::sessions::{
    TAILNET_DIRECT_WAIT, attach_platform_session, login_shell_command, platform_session_is_terminal,
};
use crate::terminal_attach::{RawModeGuard, WindowSizeWatch, terminal_input, terminal_size};

/// How long the shell keeps running with no client attached (owner,
/// 2026-11-01, on #3827), and so how long this `cw shell` keeps trying to
/// reattach after a drop.
pub(crate) const SHELL_GRACE: Duration = Duration::from_secs(10 * 60);

/// How soon a shell on the API fallback tries the tailnet again, and how far
/// apart the tries grow. The API is the last resort (owner, 2026-11-01, on
/// #3827), and a fallback can come from a failure that has already cleared:
/// a long network cut lands here as soon as the network returns (#3895).
pub(crate) const TAILNET_RETRY_FIRST: Duration = Duration::from_secs(5);
const TAILNET_RETRY_LIMIT: Duration = Duration::from_secs(60);

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

/// Launch the shell and run it to its end. Returns its exit status.
pub(crate) async fn run(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<i32> {
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (columns, rows) = interactive
        .then(terminal_size)
        .and_then(Result::ok)
        .unwrap_or((80, 24));
    let term = std::env::var("TERM")
        .ok()
        .filter(|term| !term.is_empty())
        .unwrap_or_else(|| "xterm-256color".into());
    let launched = client
        .launch_session(codewire_client::LaunchSessionRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            command: login_shell_command(),
            pty: true,
            term,
            columns: columns.into(),
            rows: rows.into(),
            end_after_detached_seconds: SHELL_GRACE.as_secs() as u32,
            ..Default::default()
        })
        .await
        .map_err(super::platform_commands::display_client_error)?;
    let session_id = launched
        .session
        .as_option()
        .map(|session| session.session_id.clone())
        .ok_or_else(|| anyhow::anyhow!("the launched shell has no session id"))?;

    let mut tailnet = None;
    let mut output_offset = 0;
    let mut dropped_at: Option<Instant> = None;
    let mut attempt = 0_u32;
    let mut retry_after = TAILNET_RETRY_FIRST;
    loop {
        let open = AttachSessionOpen {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            session_id: session_id.clone(),
            output_offset,
            ..Default::default()
        };
        let pumped = match attach_platform_session(client, open, &mut tailnet).await {
            Ok(attachment) => {
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
                pump(attachment, output_offset, interactive, back).await?
            }
            Err(error) if dropped_at.is_some() => {
                tracing::debug!(error = %format!("{error:#}"), "reattach failed");
                Pumped::Interrupted { output_offset }
            }
            Err(error) => return Err(error),
        };
        match pumped {
            Pumped::Ended(Ok(status)) => return Ok(status),
            Pumped::Ended(Err(reason)) => anyhow::bail!("the shell ended: {reason}"),
            Pumped::Interrupted {
                output_offset: next,
            } => {
                output_offset = next;
                let since = *dropped_at.get_or_insert_with(Instant::now);
                if since.elapsed() >= SHELL_GRACE {
                    anyhow::bail!(
                        "the connection to the environment was lost for 10 minutes; the shell has ended"
                    );
                }
                if attempt == 0 {
                    eprintln!("[cw] connection lost; reconnecting to the same shell");
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

/// Whether an attachment that has just opened came in over the API because
/// the tailnet failed, rather than because `CW_SSH_TRANSPORT` asked for it.
pub(crate) fn on_api_fallback(tailnet: &Option<EnvironmentTailnet>) -> anyhow::Result<bool> {
    Ok(tailnet.is_none() && SshTransportMode::from_env()? == SshTransportMode::Auto)
}

/// The tailnet, tried until it connects: after `first`, then at growing
/// intervals.
pub(crate) async fn tailnet_again(
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

pub(crate) fn next_retry(delay: Duration) -> Duration {
    (delay * 2).min(TAILNET_RETRY_LIMIT)
}

/// Carry one attachment: keys in, output out, resizes; every byte passes
/// through. It ends early if `tailnet_back` completes.
async fn pump<T>(
    mut attachment: EnvironmentSessionAttachment,
    mut output_offset: u64,
    interactive: bool,
    tailnet_back: impl Future<Output = T>,
) -> anyhow::Result<Pumped<T>> {
    tokio::pin!(tailnet_back);
    let input = attachment.input_handle();
    let raw = interactive.then(RawModeGuard::enable).transpose()?;
    let mut window = WindowSizeWatch::new(interactive);
    if let Some((columns, rows)) = window.current() {
        let _ = input.send(resize(columns, rows)).await;
    }
    let mut stdin = terminal_input().await;
    let mut stdout = tokio::io::stdout();
    let mut buffer = [0_u8; 4096];
    let mut stdin_open = true;
    let pumped = loop {
        tokio::select! {
            tailnet = &mut tailnet_back => break Pumped::TailnetBack { output_offset, tailnet },
            read = stdin.read(&mut buffer), if stdin_open => match read {
                Ok(0) | Err(_) => stdin_open = false,
                Ok(read) => {
                    let request = AttachSessionRequest {
                        input: Some(attach_session_request::Input::Stdin(buffer[..read].to_vec())),
                        ..Default::default()
                    };
                    if input.send(request).await.is_err() {
                        break Pumped::Interrupted { output_offset };
                    }
                }
            },
            size = window.changed() => {
                if let Some((columns, rows)) = size {
                    let _ = input.send(resize(columns, rows)).await;
                }
            }
            event = attachment.next_output() => match event {
                Ok(Some(response)) => match response.event {
                    Some(attach_session_response::Event::Output(chunk)) => {
                        stdout.write_all(&chunk.data).await?;
                        stdout.flush().await?;
                        output_offset = chunk.next_offset;
                    }
                    Some(attach_session_response::Event::HistoryGap(gap)) => {
                        output_offset = gap.retained_start_offset;
                    }
                    Some(attach_session_response::Event::Status(status)) => {
                        if let Some(session) = status.session.as_option()
                            && platform_session_is_terminal(session)
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
                Err(error) => return Err(super::platform_commands::display_client_error(error)),
            },
        }
    };
    drop(raw);
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

    fn output(
        next_offset: u64,
    ) -> Result<codewire_client::AttachSessionResponse, codewire_client::ClientError> {
        Ok(codewire_client::AttachSessionResponse {
            event: Some(attach_session_response::Event::Output(Box::new(
                codewire_client::EnvironmentSessionOutputChunk {
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
        let pumped = pump(attachment, 0, false, back).await.unwrap();
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
        let pumped = pump(attachment, 0, false, back).await.unwrap();
        carrier.await.unwrap();
        assert_eq!(pumped, Pumped::Interrupted { output_offset: 9 });
    }

    #[test]
    fn a_failed_switch_waits_longer_before_the_next() {
        assert_eq!(next_retry(TAILNET_RETRY_FIRST), Duration::from_secs(10));
        assert_eq!(next_retry(TAILNET_RETRY_LIMIT), TAILNET_RETRY_LIMIT);
    }
}
