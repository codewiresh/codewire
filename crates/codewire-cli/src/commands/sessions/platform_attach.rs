//! A session's attachment to a local VM's or hosted environment's session
//! service: its output to this terminal, this terminal's keys to it.

use super::*;

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

/// Carry one attachment opened at `start_offset`. It ends early if
/// `tailnet_back` completes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn attach_platform_environment_session(
    mut attachment: codewire_client::EnvironmentSessionAttachment,
    start_offset: u64,
    input_stream: &mut InputStream,
    interactive: bool,
    kind: AttachKind,
    raw_output: bool,
    screen: &mut SessionScreen,
    tailnet_back: impl std::future::Future<Output = ()>,
    lost_output: &mut u64,
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
    let mut decoder = AttachNavigationDecoder::new(kind.plain());
    let mut output_offset = start_offset;
    let mut stdin_closed = !interactive;
    let mut output_open = true;
    let mut terminal = false;
    // `interactive` is set only for a PTY session on a terminal. Its PTY
    // follows this terminal's size; a lost resize is cosmetic.
    let mut sizes = reattach::PtySizes::new(
        crate::terminal_attach::WindowSizeWatch::new(interactive),
        screen,
    );
    if let Some(size) = sizes.first() {
        let _ = input.send(reattach::resize_request(size)).await;
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
            size = sizes.changed(), if output_open => {
                if let Some(size) = size {
                    let _ = input.send(reattach::resize_request(size)).await;
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
                        *lost_output += gap.retained_start_offset.saturating_sub(output_offset);
                        output_offset = gap.retained_start_offset;
                    }
                    Some(codewire_client::attach_session_response::Event::Output(output)) => {
                        if raw_output {
                            screen.observe(&output.data);
                        }
                        sizes.output(output.next_offset);
                        write_session_output(&mut stdout, &output.data, raw_output)?;
                        output_offset = output.next_offset;
                    }
                    Some(codewire_client::attach_session_response::Event::Status(status))
                        if status.session.as_option().is_some_and(platform_session_is_terminal) => {
                        send_stream_status(&input, input_stream, &status).await;
                        terminal = true;
                        // A shell or foreground run ends with its program, as
                        // `ssh` does; only `cw attach` offers a restart.
                        if kind.ends_with_program(interactive) {
                            return Ok(AttachExit::Terminal);
                        }
                        screen.release();
                        eprint!("[cw] session exited; Ctrl+B r restarts, Ctrl+C leaves\r\n");
                    }
                    Some(codewire_client::attach_session_response::Event::Status(status)) => {
                        let sent = send_stream_status(&input, input_stream, &status).await;
                        sizes.answered(
                            status.session.as_option().map_or(0, |session| session.output_end_offset),
                        );
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
                        reattach::send_keys(&input, request).await?;
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
                    reattach::send_keys(&input, request).await?;
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
