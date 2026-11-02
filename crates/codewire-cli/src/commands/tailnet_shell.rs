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

use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use codewire_client::{
    AttachSessionOpen, AttachSessionRequest, AttachSessionResize, CodewireClient,
    EnvironmentSessionAttachment, attach_session_request, attach_session_response,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::sessions::{attach_platform_session, login_shell_command, platform_session_is_terminal};
use crate::terminal_attach::{RawModeGuard, WindowSizeWatch, terminal_input, terminal_size};

/// How long the shell keeps running with no client attached (owner,
/// 2026-11-01, on #3827), and so how long this `cw shell` keeps trying to
/// reattach after a drop.
pub(crate) const SHELL_GRACE: Duration = Duration::from_secs(10 * 60);

/// How one attachment ended.
enum Pumped {
    /// The shell ended; its exit status, or the session's reason.
    Ended(Result<i32, String>),
    /// The connection dropped; reattach from here.
    Interrupted { output_offset: u64 },
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
                pump(attachment, output_offset, interactive).await?
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
        }
    }
}

/// Carry one attachment: keys in, output out, resizes; every byte passes
/// through.
async fn pump(
    mut attachment: EnvironmentSessionAttachment,
    mut output_offset: u64,
    interactive: bool,
) -> anyhow::Result<Pumped> {
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
