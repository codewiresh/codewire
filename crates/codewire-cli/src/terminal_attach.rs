use std::io::IsTerminal as _;
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::Context as _;

pub(crate) fn terminal_size() -> anyhow::Result<(u16, u16)> {
    let output = ProcessCommand::new("stty")
        .arg("size")
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .context("run stty size")?;
    if !output.status.success() {
        anyhow::bail!(
            "stty size failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_stty_size(&String::from_utf8(output.stdout)?)
}

fn parse_stty_size(raw: &str) -> anyhow::Result<(u16, u16)> {
    let mut parts = raw.split_whitespace();
    let rows: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing terminal rows"))?
        .parse()
        .context("parse terminal rows")?;
    let cols: u16 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing terminal cols"))?
        .parse()
        .context("parse terminal cols")?;
    if parts.next().is_some() {
        anyhow::bail!("unexpected stty size output {raw:?}");
    }
    Ok((cols, rows))
}

/// The controlling terminal's size as (columns, rows), read from stdin.
#[cfg(unix)]
fn window_size() -> Option<(u16, u16)> {
    // SAFETY: TIOCGWINSZ fills exactly one `winsize`, which lives for the call.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: stdin is an open descriptor for the process's lifetime, and the
    // request writes only into `size`.
    let status = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) };
    (status == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
}

#[cfg(not(unix))]
fn window_size() -> Option<(u16, u16)> {
    terminal_size()
        .ok()
        .filter(|(columns, rows)| *columns > 0 && *rows > 0)
}

/// The terminal's keys, through one handle for the whole process. A tokio
/// stdin read runs on a blocking thread; when an attachment ends, its read is
/// still in flight, and on a fresh handle the next keys it returns would be
/// lost with the old one. Every attachment, and every reattachment after a
/// drop, borrows this handle, so those keys reach the next attachment.
pub(crate) async fn terminal_input() -> tokio::sync::MutexGuard<'static, tokio::io::Stdin> {
    static INPUT: std::sync::OnceLock<tokio::sync::Mutex<tokio::io::Stdin>> =
        std::sync::OnceLock::new();
    INPUT
        .get_or_init(|| tokio::sync::Mutex::new(tokio::io::stdin()))
        .lock()
        .await
}

/// Follows the attached terminal's size for a session's PTY: the size when
/// the attachment opens, then each change (SIGWINCH), never the same size
/// twice in a row. Disabled, it reports nothing and never wakes.
pub(crate) struct WindowSizeWatch {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
    enabled: bool,
    last: Option<(u16, u16)>,
}

impl WindowSizeWatch {
    pub(crate) fn new(enabled: bool) -> Self {
        #[cfg(unix)]
        let signal = enabled
            .then(|| {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
            })
            .flatten();
        Self {
            #[cfg(unix)]
            signal,
            enabled,
            last: None,
        }
    }

    /// The current size when it differs from the last one reported.
    pub(crate) fn current(&mut self) -> Option<(u16, u16)> {
        if !self.enabled {
            return None;
        }
        let size = window_size()?;
        self.report(size)
    }

    fn report(&mut self, size: (u16, u16)) -> Option<(u16, u16)> {
        (self.last != Some(size)).then(|| {
            self.last = Some(size);
            size
        })
    }

    /// Waits for the terminal to change size and returns the new size, or
    /// `None` when the change left it as last reported.
    pub(crate) async fn changed(&mut self) -> Option<(u16, u16)> {
        #[cfg(unix)]
        if let Some(signal) = self.signal.as_mut() {
            if signal.recv().await.is_some() {
                return self.current();
            }
            self.signal = None;
        }
        std::future::pending().await
    }
}

/// Modes a session's program may leave set when it exits or is detached
/// mid-frame: attributes, a hidden cursor, autowrap, cursor and keypad
/// application modes, mouse and focus reporting, bracketed paste, and the
/// kitty and modifyOtherKeys keyboard protocols. Each resets to the default.
const SESSION_MODE_RESET: &[u8] = b"\x1b[0m\x1b[?25h\x1b[?7h\x1b[?1l\x1b>\
\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1004l\x1b[?2004l\x1b[<u\x1b[>4m";
const ALTERNATE_SCREEN_ENTER: [&[u8]; 3] = [b"\x1b[?1049h", b"\x1b[?1047h", b"\x1b[?47h"];
const ALTERNATE_SCREEN_LEAVE: [&[u8]; 3] = [b"\x1b[?1049l", b"\x1b[?1047l", b"\x1b[?47l"];

/// Gives the terminal back from an attached session's program, as tmux does
/// on detach: leaves its alternate screen, resets the modes it set, erases
/// its last frame below the cursor and starts a fresh line. It acts once per
/// stretch of output, so a reconnect that resumes the same output keeps the
/// program's screen.
pub(crate) struct SessionScreen {
    enabled: bool,
    drawn: bool,
    alternate: bool,
    tail: Vec<u8>,
}

impl SessionScreen {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            drawn: false,
            alternate: false,
            tail: Vec::new(),
        }
    }

    /// Records output written to the terminal.
    pub(crate) fn observe(&mut self, data: &[u8]) {
        if !self.enabled || data.is_empty() {
            return;
        }
        self.drawn = true;
        // A sequence may span two chunks, so the end of the last one is
        // scanned again; the last switch seen decides the screen.
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(data);
        let last = |patterns: &[&[u8]]| {
            patterns
                .iter()
                .filter_map(|pattern| {
                    window
                        .windows(pattern.len())
                        .rposition(|candidate| candidate == *pattern)
                })
                .max()
        };
        match (last(&ALTERNATE_SCREEN_ENTER), last(&ALTERNATE_SCREEN_LEAVE)) {
            (Some(enter), Some(leave)) => self.alternate = enter > leave,
            (Some(_), None) => self.alternate = true,
            (None, Some(_)) => self.alternate = false,
            (None, None) => {}
        }
        let keep = window.len().min(ALTERNATE_SCREEN_ENTER[0].len() - 1);
        self.tail = window.split_off(window.len() - keep);
    }

    /// The bytes that give the terminal back, or none when nothing was drawn
    /// since the last release.
    fn release_bytes(&mut self) -> Vec<u8> {
        if !self.drawn {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        if self.alternate {
            bytes.extend_from_slice(b"\x1b[?1049l");
        }
        bytes.extend_from_slice(SESSION_MODE_RESET);
        bytes.extend_from_slice(b"\x1b[J\r\n");
        self.drawn = false;
        self.alternate = false;
        self.tail.clear();
        bytes
    }

    pub(crate) fn release(&mut self) {
        use std::io::Write as _;
        let bytes = self.release_bytes();
        if bytes.is_empty() {
            return;
        }
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(&bytes);
        let _ = stdout.flush();
    }
}

impl Drop for SessionScreen {
    fn drop(&mut self) {
        self.release();
    }
}

pub(crate) struct RawModeGuard {
    state: String,
    restore: fn(&str),
}

impl RawModeGuard {
    pub(crate) fn enable() -> anyhow::Result<Self> {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("stdin is not a terminal");
        }
        let state = stty_capture(&["-g"])?;
        stty_status(&["raw", "-echo"])?;
        Ok(Self {
            state,
            restore: restore_terminal,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        (self.restore)(&self.state);
    }
}

fn restore_terminal(state: &str) {
    let _ = ProcessCommand::new("stty")
        .arg(state.trim())
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stty_capture(args: &[&str]) -> anyhow::Result<String> {
    let output = ProcessCommand::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run stty {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "stty {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn stty_status(args: &[&str]) -> anyhow::Result<()> {
    let output = ProcessCommand::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run stty {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "stty {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_size_is_reported_once_per_change() {
        let mut watch = WindowSizeWatch::new(false);
        assert_eq!(watch.current(), None, "disabled watches report nothing");
        assert_eq!(watch.report((80, 24)), Some((80, 24)));
        assert_eq!(watch.report((80, 24)), None);
        assert_eq!(watch.report((120, 40)), Some((120, 40)));
        assert_eq!(watch.report((80, 24)), Some((80, 24)));
    }

    #[test]
    fn a_session_screen_gives_the_terminal_back_once() {
        let mut screen = SessionScreen::new(true);
        assert!(screen.release_bytes().is_empty(), "nothing drawn yet");
        screen.observe(b"\x1b[?25lmenu");
        let bytes = screen.release_bytes();
        assert!(!bytes.starts_with(b"\x1b[?1049l"), "{bytes:?}");
        assert!(bytes.starts_with(SESSION_MODE_RESET), "{bytes:?}");
        assert!(bytes.ends_with(b"\x1b[J\r\n"), "{bytes:?}");
        assert!(screen.release_bytes().is_empty(), "released once");
        assert!(SessionScreen::new(false).release_bytes().is_empty());
    }

    #[test]
    fn a_session_screen_leaves_the_alternate_screen_its_program_entered() {
        let mut screen = SessionScreen::new(true);
        // The switch is split across two chunks.
        screen.observe(b"vim\x1b[?10");
        screen.observe(b"49hframe");
        assert!(screen.release_bytes().starts_with(b"\x1b[?1049l"));

        screen.observe(b"\x1b[?1049hframe\x1b[?1049lbye");
        assert!(!screen.release_bytes().starts_with(b"\x1b[?1049l"));

        screen.observe(b"\x1b[?1049l\x1b[?47h");
        assert!(screen.release_bytes().starts_with(b"\x1b[?1049l"));
    }

    #[tokio::test]
    async fn every_attachment_reads_the_same_stdin_handle() {
        // A read left in flight by one attachment must hand its bytes to the
        // next, so both borrow one handle (the keys after a reconnect, #3827).
        async fn handle() -> *const tokio::io::Stdin {
            let input = terminal_input().await;
            &*input
        }
        assert_eq!(handle().await, handle().await);
    }

    #[test]
    fn stty_size_is_rows_then_columns() {
        assert_eq!(parse_stty_size("24 80\n").unwrap(), (80, 24));
        assert!(parse_stty_size("24").is_err());
        assert!(parse_stty_size("24 80 extra").is_err());
    }
}
