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

/// The terminal's keys, through one reader for the whole process. When an
/// attachment ends, a read of stdin is still in flight; every attachment, and
/// every reattachment after a drop, borrows this reader, so the keys that
/// read returns reach the next attachment.
pub(crate) async fn terminal_input() -> tokio::sync::MutexGuard<'static, TerminalInput> {
    static INPUT: std::sync::OnceLock<tokio::sync::Mutex<TerminalInput>> =
        std::sync::OnceLock::new();
    INPUT
        .get_or_init(|| tokio::sync::Mutex::new(TerminalInput::new()))
        .lock()
        .await
}

/// Stdin, read on a thread of its own. A read of a terminal can't be
/// cancelled, so a tokio stdin read on the runtime's blocking pool would keep
/// the runtime, and `cw`, from exiting until the next key (#3886); this
/// thread ends with the process. It starts at the first read: an attachment
/// that takes no input leaves stdin to whoever else is reading it.
pub(crate) struct TerminalInput {
    keys: Option<tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>>,
    /// The part of the last chunk a smaller buffer didn't take.
    pending: Vec<u8>,
}

impl TerminalInput {
    fn new() -> Self {
        Self {
            keys: None,
            pending: Vec::new(),
        }
    }

    /// The next keys, as `AsyncReadExt::read` returns them: 0 at end of
    /// input. Cancel safe: a read dropped before it completes loses nothing.
    pub(crate) async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            let keys = self.keys.get_or_insert_with(start_reading_stdin);
            match keys.recv().await {
                Some(Ok(chunk)) => self.pending = chunk,
                Some(Err(error)) => return Err(error),
                None => return Ok(0),
            }
        }
        let taken = buffer.len().min(self.pending.len());
        buffer[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        Ok(taken)
    }
}

fn start_reading_stdin() -> tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, keys) = tokio::sync::mpsc::channel(1);
    let reader = std::thread::Builder::new()
        .name("cw-terminal-input".to_owned())
        .spawn(move || read_stdin(&sender));
    if let Err(error) = reader {
        // The closed channel reads as end of input; the attachment carries on
        // without keys, as it does when stdin closes.
        tracing::debug!(%error, "starting the terminal input thread");
    }
    keys
}

fn read_stdin(sender: &tokio::sync::mpsc::Sender<std::io::Result<Vec<u8>>>) {
    use std::io::Read as _;
    let mut buffer = [0_u8; 4096];
    loop {
        let chunk = match std::io::stdin().read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => Ok(buffer[..read].to_vec()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => Err(error),
        };
        let failed = chunk.is_err();
        if sender.blocking_send(chunk).is_err() || failed {
            return;
        }
    }
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
        async fn handle() -> *const TerminalInput {
            let input = terminal_input().await;
            &*input
        }
        assert_eq!(handle().await, handle().await);
    }

    #[tokio::test]
    async fn terminal_input_hands_over_a_chunk_across_reads_and_cancelled_reads() {
        let (sender, keys) = tokio::sync::mpsc::channel(4);
        let mut input = TerminalInput {
            keys: Some(keys),
            pending: Vec::new(),
        };
        sender.send(Ok(b"hello".to_vec())).await.unwrap();
        let mut buffer = [0_u8; 3];
        assert_eq!(input.read(&mut buffer).await.unwrap(), 3);
        assert_eq!(&buffer, b"hel");
        // A read given up before any key arrives takes nothing with it.
        let mut wide = [0_u8; 8];
        assert_eq!(input.read(&mut wide).await.unwrap(), 2);
        assert_eq!(&wide[..2], b"lo");
        let abandoned =
            tokio::time::timeout(std::time::Duration::from_millis(10), input.read(&mut wide)).await;
        assert!(abandoned.is_err(), "no keys yet");
        sender.send(Ok(b"next".to_vec())).await.unwrap();
        assert_eq!(input.read(&mut wide).await.unwrap(), 4);
        assert_eq!(&wide[..4], b"next");
        drop(sender);
        assert_eq!(input.read(&mut wide).await.unwrap(), 0, "end of input");
    }

    /// Names the child half of the test below.
    #[cfg(unix)]
    const UNREAD_CHILD_ENV: &str = "CW_TERMINAL_INPUT_UNREAD_CHILD";

    /// The child half: borrow the input as an attachment that takes no keys
    /// does, then read stdin directly. A no-op unless started by the test
    /// below.
    #[cfg(unix)]
    #[test]
    fn unread_terminal_input_child_process() {
        if std::env::var_os(UNREAD_CHILD_ENV).is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            drop(terminal_input().await);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut rest).unwrap();
        println!("REST {rest:?}");
    }

    #[cfg(unix)]
    #[test]
    fn an_attachment_that_takes_no_keys_leaves_stdin_unread() {
        use std::io::Write as _;
        // As in `while read line; do cw run ...; done < file`: the lines
        // after this command belong to the script.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "terminal_attach::tests::unread_terminal_input_child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(UNREAD_CHILD_ENV, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"the next line\n").unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        assert!(stdout.contains(r#"REST "the next line\n""#), "{stdout}");
    }

    /// Names the child half of the test below.
    #[cfg(unix)]
    const INPUT_CHILD_ENV: &str = "CW_TERMINAL_INPUT_CHILD";

    /// The child half: on a real terminal, as `main` runs a command, read
    /// keys, leave a read in flight, and return. A no-op unless started by
    /// the test below.
    #[cfg(unix)]
    #[test]
    fn terminal_input_child_process() {
        if std::env::var_os(INPUT_CHILD_ENV).is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut input = terminal_input().await;
            let mut buffer = [0_u8; 64];
            let read = input.read(&mut buffer).await.unwrap();
            println!("KEYS {:?}", String::from_utf8_lossy(&buffer[..read]));
            // As when the shell ends: its pump stops with a read pending.
            let pending = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                input.read(&mut buffer),
            );
            assert!(pending.await.is_err(), "no keys were typed");
        });
        drop(runtime);
        println!("RETURNED");
    }

    #[cfg(unix)]
    #[test]
    fn a_command_returns_without_another_key_while_a_terminal_read_is_in_flight() {
        use std::io::{Read as _, Write as _};
        use std::time::{Duration, Instant};

        let pty = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open a pseudo-terminal");
        let mut command = portable_pty::CommandBuilder::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "terminal_attach::tests::terminal_input_child_process",
            "--nocapture",
            "--test-threads=1",
            "--quiet",
        ]);
        command.cwd(std::env::current_dir().unwrap());
        command.env(INPUT_CHILD_ENV, "1");
        let mut child = pty.slave.spawn_command(command).expect("start the child");
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader().unwrap();
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read @ 1..) = reader.read(&mut buffer) {
                sink.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        let mut writer = pty.master.take_writer().unwrap();
        writer.write_all(b"exit\r").unwrap();
        writer.flush().unwrap();

        // Nothing more is typed: the child must return on its own.
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        let Some(status) = status else {
            child.kill().unwrap();
            panic!("the child waited for another key after its command ended:\n{text}");
        };
        assert!(status.success(), "{status}:\n{text}");
        assert!(text.contains("KEYS \"exit\\n\""), "{text}");
        assert!(text.contains("RETURNED"), "{text}");
    }

    #[test]
    fn stty_size_is_rows_then_columns() {
        assert_eq!(parse_stty_size("24 80\n").unwrap(), (80, 24));
        assert!(parse_stty_size("24").is_err());
        assert!(parse_stty_size("24 80 extra").is_err());
    }
}
