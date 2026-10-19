//! One live progress row on stderr: only the active row animates, finished
//! rows become quiet permanent lines.

use std::io::Write;
use std::time::{Duration, Instant};

use crate::commands::progress::{format_duration, terminal_text};

use super::caps::{Capabilities, Motion, OutputMode};
use super::spinner::{FRAME_INTERVAL, REDUCED_INTERVAL, Spinner};
use super::style::{Line, Role, Status, Style};

/// Clears the current terminal line.
const CLEAR_LINE: &str = "\r\x1b[2K";
/// Auto-wrap off while the live row is drawn, so a row wider than the
/// terminal is clipped instead of wrapped where `CLEAR_LINE` cannot reach.
const WRAP_OFF: &str = "\x1b[?7l";
const WRAP_ON: &str = "\x1b[?7h";

type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

struct Active {
    label: String,
    detail: Option<String>,
    started: Instant,
}

/// Progress for a sequence of stages.
///
/// - Live (text mode, stderr a terminal): the active stage is one redrawn
///   row with a spinner and its elapsed time; finished stages print
///   permanent lines above it.
/// - Plain (text mode, not live): one escape-free line when a stage begins
///   and one when it ends. Details are omitted.
/// - Machine mode: nothing at all.
///
/// Labels pass through the control-character sanitizer.
pub(crate) struct StatusLine<W: Write> {
    out: W,
    mode: OutputMode,
    live: bool,
    motion: Motion,
    style: Style,
    width: usize,
    spinner: Spinner,
    clock: Clock,
    active: Option<Active>,
    drawn: Option<String>,
}

impl<W: Write> StatusLine<W> {
    pub(crate) fn new(out: W, caps: &Capabilities) -> Self {
        Self::with_clock(out, caps, Instant::now)
    }

    pub(crate) fn with_clock(
        out: W,
        caps: &Capabilities,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            out,
            mode: caps.mode,
            live: caps.live,
            motion: caps.motion,
            style: caps.stderr_style(),
            width: usize::from(caps.columns).saturating_sub(1).max(1),
            spinner: Spinner::new(caps),
            clock: Box::new(clock),
            active: None,
            drawn: None,
        }
    }

    /// Starts the active stage, replacing any open one without a line.
    pub(crate) fn begin(&mut self, label: &str) -> std::io::Result<()> {
        if self.mode == OutputMode::Machine {
            return Ok(());
        }
        let label = terminal_text(label);
        self.active = Some(Active {
            label: label.clone(),
            detail: None,
            started: (self.clock)(),
        });
        if self.live {
            self.redraw()
        } else {
            let line = Line::new()
                .plain("  ")
                .status(self.style, Status::Active)
                .plain(format!(" {label}"));
            self.permanent(&line)
        }
    }

    /// Sets or clears the detail shown beside the active stage on the live
    /// row, such as what a booting guest is doing.
    pub(crate) fn detail(&mut self, detail: Option<&str>) -> std::io::Result<()> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        active.detail = detail.map(terminal_text).filter(|text| !text.is_empty());
        if self.live { self.redraw() } else { Ok(()) }
    }

    /// Advances the spinner and elapsed time. Draws only when the row's text
    /// changed, so reduced motion redraws at most once a second.
    pub(crate) fn tick(&mut self) -> std::io::Result<()> {
        if self.live && self.active.is_some() {
            self.redraw()
        } else {
            Ok(())
        }
    }

    /// How often to call [`StatusLine::tick`]: `None` when nothing moves.
    pub(crate) fn tick_interval(&self) -> Option<Duration> {
        if !self.live || self.active.is_none() {
            return None;
        }
        match self.motion {
            Motion::Animated => Some(FRAME_INTERVAL),
            Motion::Reduced => Some(REDUCED_INTERVAL),
            Motion::Off => None,
        }
    }

    /// Ends the active stage with a confirmed outcome.
    pub(crate) fn done(&mut self, label: &str) -> std::io::Result<()> {
        self.finish(Status::Done, label)
    }

    /// Ends the active stage with a pending or partial result.
    pub(crate) fn attention(&mut self, label: &str) -> std::io::Result<()> {
        self.finish(Status::Attention, label)
    }

    /// Ends the active stage with a failure.
    pub(crate) fn fail(&mut self, label: &str) -> std::io::Result<()> {
        self.finish(Status::Failed, label)
    }

    /// Writes a permanent line above the active stage, which keeps running.
    pub(crate) fn note(&mut self, status: Status, text: &str) -> std::io::Result<()> {
        if self.mode == OutputMode::Machine {
            return Ok(());
        }
        let line = Line::new()
            .plain("  ")
            .status(self.style, status)
            .plain(format!(" {}", terminal_text(text)));
        self.permanent(&line)?;
        if self.live && self.active.is_some() {
            self.redraw()
        } else {
            Ok(())
        }
    }

    /// Removes the live row and drops the active stage without a line, for
    /// example before an agent's own terminal UI takes over.
    pub(crate) fn clear(&mut self) -> std::io::Result<()> {
        self.active = None;
        self.erase()?;
        self.out.flush()
    }

    fn finish(&mut self, status: Status, label: &str) -> std::io::Result<()> {
        if self.mode == OutputMode::Machine {
            return Ok(());
        }
        let now = (self.clock)();
        let elapsed = self
            .active
            .take()
            .map(|active| format_duration(now.saturating_duration_since(active.started), true));
        let mut line = Line::new()
            .plain("  ")
            .status(self.style, status)
            .plain(format!(" {}", terminal_text(label)));
        if let Some(elapsed) = elapsed {
            line = line.styled(Role::Dim, format!("  {elapsed}"));
        }
        self.permanent(&line)
    }

    fn permanent(&mut self, line: &Line) -> std::io::Result<()> {
        self.erase()?;
        writeln!(self.out, "{}", line.render(self.style))?;
        self.out.flush()
    }

    fn erase(&mut self) -> std::io::Result<()> {
        if self.drawn.take().is_some() {
            write!(self.out, "{CLEAR_LINE}")?;
        }
        Ok(())
    }

    fn redraw(&mut self) -> std::io::Result<()> {
        let Some(active) = &self.active else {
            return Ok(());
        };
        let elapsed = (self.clock)().saturating_duration_since(active.started);
        let mut line = Line::new()
            .plain("  ")
            .styled(Role::Active, self.spinner.frame(elapsed))
            .plain(format!(" {}", active.label));
        if let Some(detail) = &active.detail {
            line = line.plain(format!("{}{detail}", self.style.separator()));
        }
        let line = line
            .styled(Role::Dim, format!("  {}", format_duration(elapsed, false)))
            .truncate(self.width);
        let text = line.render(self.style);
        if self.drawn.as_deref() == Some(text.as_str()) {
            return Ok(());
        }
        write!(self.out, "{CLEAR_LINE}{WRAP_OFF}{text}{WRAP_ON}")?;
        self.drawn = Some(text);
        self.out.flush()
    }
}

impl<W: Write> Drop for StatusLine<W> {
    /// Never leave a live row behind on an early return or panic.
    fn drop(&mut self) {
        if self.drawn.take().is_some() {
            let _ = write!(self.out, "{CLEAR_LINE}");
            let _ = self.out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::config::MapEnv;
    use crate::output::caps::TerminalFacts;

    const TERMINAL: TerminalFacts = TerminalFacts {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        columns: Some(60),
        rows: Some(24),
    };

    fn caps(mode: OutputMode, facts: TerminalFacts, vars: &[(&str, &str)]) -> Capabilities {
        Capabilities::detect(mode, &facts, &MapEnv::new(vars.iter().copied()))
    }

    fn live_caps(vars: &[(&str, &str)]) -> Capabilities {
        caps(OutputMode::Text, TERMINAL, vars)
    }

    fn plain_caps() -> Capabilities {
        caps(OutputMode::Text, TerminalFacts::default(), &[])
    }

    /// A clock the test moves by hand.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<Instant>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }

        fn reader(&self) -> impl Fn() -> Instant + Send + Sync + 'static {
            let now = Arc::clone(&self.0);
            move || *now.lock().unwrap()
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn plain_output_has_one_escape_free_line_per_begin_and_end() {
        let clock = TestClock::new();
        let mut out = Vec::new();
        {
            let mut line = StatusLine::with_clock(&mut out, &plain_caps(), clock.reader());
            line.begin("Starting the VM").unwrap();
            line.detail(Some("guest kernel")).unwrap();
            assert_eq!(line.tick_interval(), None);
            clock.advance(Duration::from_millis(2_100));
            line.tick().unwrap();
            line.done("VM started").unwrap();
            line.begin("Booting the workspace").unwrap();
            clock.advance(Duration::from_secs(21));
            line.fail("Workspace did not boot").unwrap();
            line.note(Status::Attention, "Environment app has been kept.")
                .unwrap();
        }
        let out = text(&out);
        assert!(!out.contains('\x1b'), "{out:?}");
        assert_eq!(
            out,
            "  ◐ Starting the VM\n  ✓ VM started  2.1s\n  ◐ Booting the workspace\n  ✗ Workspace did not boot  21s\n  ! Environment app has been kept.\n"
        );
    }

    #[test]
    fn machine_mode_writes_nothing() {
        let mut out = Vec::new();
        {
            let caps = caps(OutputMode::Machine, TERMINAL, &[]);
            let mut line = StatusLine::new(&mut out, &caps);
            line.begin("Starting").unwrap();
            line.detail(Some("x")).unwrap();
            line.tick().unwrap();
            assert_eq!(line.tick_interval(), None);
            line.note(Status::Attention, "note").unwrap();
            line.done("Started").unwrap();
            line.fail("Failed").unwrap();
            line.clear().unwrap();
        }
        assert!(out.is_empty(), "{:?}", text(&out));
    }

    #[test]
    fn live_row_redraws_in_place_and_finishes_as_a_permanent_line() {
        let clock = TestClock::new();
        let mut out = Vec::new();
        {
            let mut line =
                StatusLine::with_clock(&mut out, &live_caps(&[("NO_COLOR", "1")]), clock.reader());
            line.begin("Starting the VM").unwrap();
            assert_eq!(line.tick_interval(), Some(FRAME_INTERVAL));
            clock.advance(Duration::from_millis(100));
            line.tick().unwrap();
            clock.advance(Duration::from_millis(1_000));
            line.detail(Some("guest kernel")).unwrap();
            line.done("VM started").unwrap();
            assert_eq!(line.tick_interval(), None);
        }
        assert_eq!(
            text(&out),
            concat!(
                "\r\x1b[2K\x1b[?7l  ◐ Starting the VM  0s\x1b[?7h",
                "\r\x1b[2K\x1b[?7l  ◓ Starting the VM  0s\x1b[?7h",
                "\r\x1b[2K\x1b[?7l  ◒ Starting the VM · guest kernel  1s\x1b[?7h",
                "\r\x1b[2K  ✓ VM started  1.1s\n",
            )
        );
    }

    #[test]
    fn live_row_is_coloured_when_stderr_allows() {
        let clock = TestClock::new();
        let mut out = Vec::new();
        {
            let mut line = StatusLine::with_clock(&mut out, &live_caps(&[]), clock.reader());
            line.begin("Starting").unwrap();
            clock.advance(Duration::from_millis(300));
            line.done("Started").unwrap();
        }
        assert_eq!(
            text(&out),
            concat!(
                "\r\x1b[2K\x1b[?7l  \x1b[36m◐\x1b[0m Starting\x1b[2m  0s\x1b[0m\x1b[?7h",
                "\r\x1b[2K  \x1b[32m✓\x1b[0m Started\x1b[2m  0.3s\x1b[0m\n",
            )
        );
    }

    #[test]
    fn unchanged_rows_are_not_redrawn() {
        let clock = TestClock::new();
        let mut out = Vec::new();
        {
            let caps = live_caps(&[("NO_COLOR", "1"), ("CODEWIRE_REDUCED_MOTION", "1")]);
            let mut line = StatusLine::with_clock(&mut out, &caps, clock.reader());
            line.begin("Waiting").unwrap();
            assert_eq!(line.tick_interval(), Some(REDUCED_INTERVAL));
            for _ in 0..9 {
                clock.advance(Duration::from_millis(100));
                line.tick().unwrap();
            }
            clock.advance(Duration::from_millis(100));
            line.tick().unwrap();
            line.clear().unwrap();
        }
        assert_eq!(
            text(&out),
            concat!(
                "\r\x1b[2K\x1b[?7l  ◐ Waiting  0s\x1b[?7h",
                "\r\x1b[2K\x1b[?7l  ◐ Waiting  1s\x1b[?7h",
                "\r\x1b[2K",
            )
        );
    }

    #[test]
    fn notes_print_above_the_active_row_and_redraw_it() {
        let clock = TestClock::new();
        let mut out = Vec::new();
        {
            let mut line =
                StatusLine::with_clock(&mut out, &live_caps(&[("NO_COLOR", "1")]), clock.reader());
            line.begin("Pulling").unwrap();
            line.note(Status::Attention, "Using a cached image")
                .unwrap();
        }
        assert_eq!(
            text(&out),
            concat!(
                "\r\x1b[2K\x1b[?7l  ◐ Pulling  0s\x1b[?7h",
                "\r\x1b[2K  ! Using a cached image\n",
                "\r\x1b[2K\x1b[?7l  ◐ Pulling  0s\x1b[?7h",
                "\r\x1b[2K",
            )
        );
    }

    #[test]
    fn the_live_row_is_cut_to_the_terminal_width() {
        let mut out = Vec::new();
        {
            let narrow = TerminalFacts {
                columns: Some(20),
                ..TERMINAL
            };
            let caps = caps(OutputMode::Text, narrow, &[("NO_COLOR", "1")]);
            let mut line = StatusLine::new(&mut out, &caps);
            line.begin("Installing dependencies with a long name")
                .unwrap();
        }
        let out = text(&out);
        let row = out
            .strip_prefix("\r\x1b[2K\x1b[?7l")
            .and_then(|rest| rest.split_once("\x1b[?7h"))
            .map(|(row, _)| row)
            .unwrap();
        assert_eq!(row, "  ◐ Installing depe");
        assert_eq!(row.chars().count(), 19);
        assert!(out.ends_with("\r\x1b[2K"), "dropped row is erased: {out:?}");
    }

    #[test]
    fn labels_and_details_cannot_drive_the_terminal() {
        let mut out = Vec::new();
        {
            let caps = live_caps(&[("NO_COLOR", "1")]);
            let mut line = StatusLine::new(&mut out, &caps);
            line.begin("Start\x1b]0;owned\x07ing\nnow").unwrap();
            line.detail(Some("\x1b[31mred\r")).unwrap();
            line.done("Done\x1b[2J").unwrap();
        }
        let out = text(&out);
        let without_framing = out
            .replace("\r\x1b[2K", "")
            .replace("\x1b[?7l", "")
            .replace("\x1b[?7h", "");
        assert!(!without_framing.contains('\x1b'), "{out:?}");
        assert!(!without_framing.contains('\x07'));
        assert!(without_framing.contains("Start ]0;owned ing now"));
        assert!(without_framing.contains("[31mred"));
        assert!(without_framing.contains("✓ Done [2J"));
    }

    #[test]
    fn ascii_terminals_get_ascii_glyphs() {
        let mut out = Vec::new();
        {
            let caps = caps(OutputMode::Text, TERMINAL, &[("TERM", "dumb")]);
            let mut line = StatusLine::new(&mut out, &caps);
            line.begin("Starting").unwrap();
            line.done("Started").unwrap();
            line.begin("Attaching").unwrap();
            line.attention("Attachment pending").unwrap();
        }
        let out = text(&out);
        assert!(out.is_ascii(), "{out:?}");
        assert!(!out.contains('\x1b'));
        assert!(out.starts_with(
            "  | Starting\n  + Started  0.0s\n  | Attaching\n  ! Attachment pending  "
        ));
    }
}
