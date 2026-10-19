//! The shared runner for interactive widgets: raw key input from stdin,
//! frames drawn in place on stderr, and the terminal restored on every exit
//! path.

use std::io::Write;

use super::caps::{Capabilities, Charset};
use super::keys::Key;
use super::style::{Line, Role, Style};

/// Rows shown when the terminal height is unknown.
const DEFAULT_MAX_ROWS: usize = 10;

/// Clears from the cursor to the end of the screen.
const CLEAR_DOWN: &str = "\x1b[J";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";
const WRAP_OFF: &str = "\x1b[?7l";
const WRAP_ON: &str = "\x1b[?7h";

/// What one key did to a widget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Step<T> {
    Continue,
    Done(T),
    Canceled,
}

/// How an interactive run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Interaction<T> {
    Done(T),
    /// Escape, Ctrl-C or closed input.
    Canceled,
    /// No interactive terminal that can redraw; nothing was drawn.
    Unavailable,
}

/// A widget the runner can drive.
pub(super) trait Widget {
    type Output;

    /// Lines the frame draws besides its rows, used to fit the rows to the
    /// terminal height.
    const CHROME_LINES: usize;

    fn on_key(&mut self, key: Key) -> Step<Self::Output>;

    /// The frame as lines without line endings, each cut to `columns - 1`
    /// characters, with at most `max_rows` rows.
    fn frame(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String>;
}

/// The first and one-past-last row shown for a cursor in a list of `len`,
/// keeping the cursor visible.
pub(super) fn window(cursor: usize, len: usize, max_rows: usize) -> (usize, usize) {
    let max_rows = max_rows.max(1);
    let start = cursor.saturating_sub(max_rows - 1);
    (start, (start + max_rows).min(len))
}

/// `  4–8 of 30` under a list that does not fit.
pub(super) fn range_line(style: Style, start: usize, end: usize, len: usize) -> Line {
    let dash = match style.charset() {
        Charset::Unicode => "–",
        Charset::Ascii => "-",
    };
    Line::new().styled(Role::Dim, format!("  {}{dash}{end} of {len}", start + 1))
}

/// A widget's lines on the terminal. Each frame replaces the last one in
/// place; restoring erases the lines and shows the cursor again. Dropping a
/// drawn screen restores it, so an error or panic leaves nothing behind.
pub(super) struct Screen<W: Write> {
    out: W,
    drawn: usize,
    active: bool,
}

impl<W: Write> Screen<W> {
    pub(super) fn new(out: W) -> Self {
        Self {
            out,
            drawn: 0,
            active: false,
        }
    }

    /// Back to column 0 of the first drawn line.
    fn home(&self) -> String {
        match self.drawn {
            0 | 1 => "\r".to_owned(),
            lines => format!("\r\x1b[{}A", lines - 1),
        }
    }

    pub(super) fn draw(&mut self, lines: &[String]) -> std::io::Result<()> {
        let mut frame = String::new();
        if !self.active {
            frame.push_str(HIDE_CURSOR);
            frame.push_str(WRAP_OFF);
            self.active = true;
        }
        frame.push_str(&self.home());
        frame.push_str(CLEAR_DOWN);
        // Raw mode does not return the carriage on a line feed.
        frame.push_str(&lines.join("\r\n"));
        self.drawn = lines.len();
        self.out.write_all(frame.as_bytes())?;
        self.out.flush()
    }

    pub(super) fn restore(&mut self) -> std::io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let frame = format!("{}{CLEAR_DOWN}{SHOW_CURSOR}{WRAP_ON}", self.home());
        self.active = false;
        self.drawn = 0;
        self.out.write_all(frame.as_bytes())?;
        self.out.flush()
    }
}

impl<W: Write> Drop for Screen<W> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// A source of decoded keys. `None` means the input closed.
pub(super) trait KeyInput {
    fn read_keys(&mut self) -> std::io::Result<Option<Vec<Key>>>;
}

/// Draws, reads keys and applies them until the widget finishes, the user
/// cancels or the input closes.
pub(super) fn drive<T: Widget, I: KeyInput, W: Write>(
    widget: &mut T,
    input: &mut I,
    screen: &mut Screen<W>,
    style: Style,
    columns: u16,
    max_rows: usize,
) -> std::io::Result<Interaction<T::Output>> {
    loop {
        screen.draw(&widget.frame(style, columns, max_rows))?;
        let Some(keys) = input.read_keys()? else {
            return Ok(Interaction::Canceled);
        };
        for key in keys {
            match widget.on_key(key) {
                Step::Continue => {}
                Step::Done(output) => return Ok(Interaction::Done(output)),
                Step::Canceled => return Ok(Interaction::Canceled),
            }
        }
    }
}

/// Runs `widget` on the process's terminal: raw input from stdin and frames
/// on stderr. [`Interaction::Unavailable`] without touching the terminal
/// unless the session is interactive and can redraw (`TERM=dumb` cannot).
/// The terminal mode is restored and the widget's lines are erased on every
/// exit path, including errors and panics. Blocks on terminal input; the
/// width and height are read once when it opens.
#[cfg(unix)]
pub(super) fn run<T: Widget>(
    widget: &mut T,
    caps: &Capabilities,
) -> anyhow::Result<Interaction<T::Output>> {
    if !(caps.interactive && caps.live) {
        return Ok(Interaction::Unavailable);
    }
    let size = crate::terminal_attach::terminal_size().ok();
    let columns = size
        .map(|(columns, _)| columns)
        .filter(|columns| *columns > 0)
        .unwrap_or(caps.columns);
    let max_rows = size
        .map(|(_, rows)| rows)
        .filter(|rows| *rows > 0)
        .or(caps.rows)
        .map_or(DEFAULT_MAX_ROWS, |rows| {
            usize::from(rows).saturating_sub(T::CHROME_LINES + 1)
        });
    let mut input = unix_input::StdinKeys::new()?;
    // Declared before the screen so the screen is erased first and the
    // terminal mode restored last, also while unwinding.
    let _raw = crate::terminal_attach::RawModeGuard::enable()?;
    let mut screen = Screen::new(std::io::stderr());
    let outcome = drive(
        widget,
        &mut input,
        &mut screen,
        caps.stderr_style(),
        columns,
        max_rows,
    );
    let restored = screen.restore();
    let outcome = outcome?;
    restored?;
    Ok(outcome)
}

#[cfg(not(unix))]
pub(super) fn run<T: Widget>(
    _widget: &mut T,
    _caps: &Capabilities,
) -> anyhow::Result<Interaction<T::Output>> {
    Ok(Interaction::Unavailable)
}

#[cfg(unix)]
mod unix_input {
    use std::fs::File;
    use std::io::{ErrorKind, Read as _};
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::time::Duration;

    use super::KeyInput;
    use crate::output::keys::{Key, decode_keys, needs_more_input};

    /// How long a lone ESC (or another unfinished sequence) waits for the
    /// rest of an arrow key before it counts on its own.
    const ESCAPE_WAIT: Duration = Duration::from_millis(50);

    /// Unbuffered raw reads from stdin, so a wait for the rest of a sequence
    /// sees exactly the bytes the terminal has sent.
    pub(super) struct StdinKeys {
        file: File,
    }

    impl StdinKeys {
        pub(super) fn new() -> std::io::Result<Self> {
            let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
            Ok(Self {
                file: File::from(fd),
            })
        }

        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                match self.file.read(buf) {
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    result => return result,
                }
            }
        }

        fn readable_within(&self, wait: Duration) -> std::io::Result<bool> {
            let mut poll = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
            loop {
                // SAFETY: `poll` reads and writes exactly the one valid
                // `pollfd` passed for the duration of the call.
                let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
                if ready >= 0 {
                    return Ok(ready > 0);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    impl KeyInput for StdinKeys {
        fn read_keys(&mut self) -> std::io::Result<Option<Vec<Key>>> {
            let mut buf = [0u8; 256];
            let read = self.read(&mut buf)?;
            if read == 0 {
                return Ok(None);
            }
            let mut bytes = buf[..read].to_vec();
            while needs_more_input(&bytes) && self.readable_within(ESCAPE_WAIT)? {
                let read = self.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..read]);
            }
            Ok(Some(decode_keys(&bytes)))
        }
    }
}

/// Test support shared by the widget tests.
#[cfg(test)]
pub(super) mod script {
    use std::collections::VecDeque;

    use super::KeyInput;
    use crate::output::keys::Key;

    /// Keys delivered one read at a time, then closed input.
    pub(in crate::output) struct Script(pub(in crate::output) VecDeque<Vec<Key>>);

    impl KeyInput for Script {
        fn read_keys(&mut self) -> std::io::Result<Option<Vec<Key>>> {
            Ok(self.0.pop_front())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MapEnv;
    use crate::output::caps::{OutputMode, TerminalFacts};

    #[test]
    fn windows_keep_the_cursor_visible() {
        assert_eq!(window(0, 3, 10), (0, 3));
        assert_eq!(window(0, 30, 5), (0, 5));
        assert_eq!(window(4, 30, 5), (0, 5));
        assert_eq!(window(7, 30, 5), (3, 8));
        assert_eq!(window(29, 30, 5), (25, 30));
        assert_eq!(window(2, 30, 0), (2, 3));
        assert_eq!(window(0, 0, 5), (0, 0));
    }

    #[test]
    fn a_panic_while_drawn_still_erases_the_widget() {
        let mut out = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut screen = Screen::new(&mut out);
            screen
                .draw(&["one".to_owned(), "two".to_owned(), "three".to_owned()])
                .unwrap();
            panic!("render failed");
        }));
        assert!(result.is_err());
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "\x1b[?25l\x1b[?7l\r\x1b[Jone\r\ntwo\r\nthree\r\x1b[2A\x1b[J\x1b[?25h\x1b[?7h"
        );
    }

    #[test]
    fn an_undrawn_screen_writes_nothing() {
        let mut out = Vec::new();
        {
            let mut screen = Screen::new(&mut out);
            screen.restore().unwrap();
        }
        assert!(out.is_empty());
    }

    /// A widget that never draws or finishes, to prove `run` gives up before
    /// touching the terminal.
    struct Inert;

    impl Widget for Inert {
        type Output = ();
        const CHROME_LINES: usize = 0;

        fn on_key(&mut self, _key: Key) -> Step<()> {
            unreachable!("no key is read without an interactive terminal")
        }

        fn frame(&self, _style: Style, _columns: u16, _max_rows: usize) -> Vec<String> {
            unreachable!("nothing is drawn without an interactive terminal")
        }
    }

    #[test]
    fn non_interactive_sessions_never_get_a_widget() {
        let all = TerminalFacts {
            stdin_tty: true,
            stdout_tty: true,
            stderr_tty: true,
            columns: Some(80),
            rows: Some(24),
        };
        let cases = [
            (
                OutputMode::Text,
                TerminalFacts {
                    stdin_tty: false,
                    ..all
                },
                vec![],
            ),
            (
                OutputMode::Text,
                TerminalFacts {
                    stderr_tty: false,
                    ..all
                },
                vec![],
            ),
            (OutputMode::Machine, all, vec![]),
            (OutputMode::Text, all, vec![("TERM", "dumb")]),
        ];
        for (mode, facts, vars) in cases {
            let caps = Capabilities::detect(mode, &facts, &MapEnv::new(vars));
            let outcome = run(&mut Inert, &caps).unwrap();
            assert_eq!(outcome, Interaction::Unavailable, "{mode:?} {facts:?}");
        }
    }
}
