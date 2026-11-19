//! The line a local credential command shows while its store hasn't answered
//! (#5271; the CLI design's "a dependency that does not answer"). Within a
//! second it says what it waits for, so a hidden unlock prompt or a stuck
//! keyring is visible instead of a silent wait.

use std::future::Future;
use std::io::Write;
use std::time::{Duration, Instant};

use crate::output::{Capabilities, Charset, OutputMode};

const SHOW_AFTER: Duration = Duration::from_secs(1);
const REDRAW_EVERY: Duration = Duration::from_millis(250);

/// What the store is, as the person knows it.
fn store() -> &'static str {
    if cfg!(target_os = "macos") {
        "your login keychain"
    } else {
        "your keyring (Secret Service)"
    }
}

/// `call`, with the waiting line on stderr once it has taken a second. Where
/// stderr can redraw a line, the line counts the time and is cleared when the
/// store answers; otherwise it is one plain line. With `--output json` there
/// is none.
pub(super) async fn waiting_on_store<T>(json: bool, call: impl Future<Output = T>) -> T {
    if json {
        return call.await;
    }
    let caps = Capabilities::from_process(OutputMode::Text);
    let screen = Screen {
        live: caps.live,
        ascii: caps.charset == Charset::Ascii,
    };
    waiting_on(&mut std::io::stderr(), screen, call).await
}

/// What the waiting line may draw on.
#[derive(Clone, Copy)]
pub(super) struct Screen {
    pub(super) live: bool,
    pub(super) ascii: bool,
}

pub(super) async fn waiting_on<T>(
    out: &mut (impl Write + Send),
    screen: Screen,
    call: impl Future<Output = T>,
) -> T {
    let started = Instant::now();
    tokio::pin!(call);
    tokio::select! {
        result = &mut call => return result,
        () = tokio::time::sleep(SHOW_AFTER) => {}
    }
    if !screen.live {
        // A failed write to stderr only leaves the line unsaid.
        let _ = writeln!(out, "{}", plain_line());
        return call.await;
    }
    let mut redraw = tokio::time::interval(REDRAW_EVERY);
    let mut frame = 0;
    loop {
        tokio::select! {
            result = &mut call => {
                // As above: a failed write only leaves the line on screen.
                let _ = write!(out, "\r\x1b[K");
                let _ = out.flush();
                return result;
            }
            _ = redraw.tick() => {
                // As above: a failed write only skips one redraw.
                let _ = write!(out, "{}", waiting_line(started.elapsed(), frame, screen.ascii));
                let _ = out.flush();
                frame += 1;
            }
        }
    }
}

pub(super) fn plain_line() -> String {
    format!("Waiting for {} to answer; unlock it if it asks.", store())
}

/// The redrawn line: a turning circle, what is awaited, and the time waited.
fn waiting_line(waited: Duration, frame: usize, ascii: bool) -> String {
    const UNICODE: [&str; 4] = ["◐", "◓", "◑", "◒"];
    const ASCII: [&str; 4] = ["|", "/", "-", "\\"];
    let glyph = if ascii { ASCII } else { UNICODE }[frame % 4];
    let dot = if ascii { "-" } else { "·" };
    let seconds = waited.as_secs();
    format!(
        "\r  {glyph} Waiting for {} to answer {dot} unlock it if it asks {}:{:02}\x1b[K",
        store(),
        seconds / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests;
