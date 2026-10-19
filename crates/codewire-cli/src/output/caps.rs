//! What the current terminal allows: colour per stream, live redraw, motion,
//! character set and interactive input.

use std::io::IsTerminal as _;

use crate::config::Env;

use super::style::Style;

/// Set to any non-empty value other than `0` to stop the spinner. The active
/// row then shows a static glyph and only its elapsed time changes, at most
/// once a second.
pub(crate) const REDUCED_MOTION_ENV: &str = "CODEWIRE_REDUCED_MOTION";

/// Width assumed when the terminal does not report one.
const DEFAULT_COLUMNS: u16 = 80;

/// Whether a command writes for people or for programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputMode {
    /// Human text: progress, glyphs and colour where the terminal allows.
    Text,
    /// Machine-readable output such as JSON: no progress, escapes or
    /// decoration on any stream.
    Machine,
}

/// How the active row may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Motion {
    /// The spinner rotates.
    Animated,
    /// A static glyph; only time-based text updates, at most once a second.
    Reduced,
    /// No live row at all.
    Off,
}

/// Which glyphs the terminal can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Charset {
    Unicode,
    Ascii,
}

/// Facts about the process's standard streams, probed once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TerminalFacts {
    pub(crate) stdin_tty: bool,
    pub(crate) stdout_tty: bool,
    pub(crate) stderr_tty: bool,
    pub(crate) columns: Option<u16>,
    pub(crate) rows: Option<u16>,
}

impl TerminalFacts {
    /// Reads the real streams. The size comes from the controlling terminal
    /// on stdin, so it is known only when stdin and stderr are both
    /// terminals.
    pub(crate) fn probe() -> Self {
        let stdin_tty = std::io::stdin().is_terminal();
        let stdout_tty = std::io::stdout().is_terminal();
        let stderr_tty = std::io::stderr().is_terminal();
        let size = (stdin_tty && stderr_tty)
            .then(crate::terminal_attach::terminal_size)
            .and_then(Result::ok)
            .filter(|(columns, rows)| *columns > 0 && *rows > 0);
        Self {
            stdin_tty,
            stdout_tty,
            stderr_tty,
            columns: size.map(|(columns, _)| columns),
            rows: size.map(|(_, rows)| rows),
        }
    }
}

/// The presentation a command may use, decided once from the output mode,
/// the streams and the environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub(crate) mode: OutputMode,
    /// Progress may redraw one line on stderr.
    pub(crate) live: bool,
    pub(crate) motion: Motion,
    pub(crate) color_stdout: bool,
    pub(crate) color_stderr: bool,
    pub(crate) charset: Charset,
    /// Text mode with stdin and stderr both terminals.
    pub(crate) interactive: bool,
    /// Terminal width, or a conventional 80 columns when unknown.
    pub(crate) columns: u16,
    pub(crate) rows: Option<u16>,
}

impl Capabilities {
    /// Capabilities of this process's real streams and environment.
    pub(crate) fn from_process(mode: OutputMode) -> Self {
        Self::detect(mode, &TerminalFacts::probe(), &crate::config::OsEnv)
    }

    /// - `TERM=dumb`: no live redraw, no colour, ASCII.
    /// - Colour on a stream only when that stream is a terminal, `TERM` is
    ///   not `dumb` and `NO_COLOR` is unset or empty.
    /// - Live redraw only in text mode with stderr a terminal.
    /// - Reduced motion from [`REDUCED_MOTION_ENV`].
    /// - ASCII only for `TERM=dumb` or an explicitly non-UTF-8 effective
    ///   locale (`LC_ALL`, then `LC_CTYPE`, then `LANG`; `C` and `POSIX`
    ///   count as non-UTF-8). An unset locale keeps Unicode.
    /// - Machine mode: no progress, colour or interaction.
    pub(crate) fn detect(mode: OutputMode, facts: &TerminalFacts, env: &impl Env) -> Self {
        let dumb = env.var("TERM").is_some_and(|term| term == "dumb");
        let text = mode == OutputMode::Text;
        let no_color = env.var("NO_COLOR").is_some_and(|value| !value.is_empty());
        let color = |tty: bool| text && tty && !dumb && !no_color;
        let live = text && facts.stderr_tty && !dumb;
        let reduced = env
            .var(REDUCED_MOTION_ENV)
            .is_some_and(|value| !value.is_empty() && value != "0");
        let motion = match (live, reduced) {
            (false, _) => Motion::Off,
            (true, true) => Motion::Reduced,
            (true, false) => Motion::Animated,
        };
        let charset = if dumb || !locale_is_utf8(env) {
            Charset::Ascii
        } else {
            Charset::Unicode
        };
        Self {
            mode,
            live,
            motion,
            color_stdout: color(facts.stdout_tty),
            color_stderr: color(facts.stderr_tty),
            charset,
            interactive: text && facts.stdin_tty && facts.stderr_tty,
            columns: facts.columns.unwrap_or(DEFAULT_COLUMNS),
            rows: facts.rows,
        }
    }

    pub(crate) fn is_machine(&self) -> bool {
        self.mode == OutputMode::Machine
    }

    /// Glyphs and colour for the durable result on stdout.
    pub(crate) fn stdout_style(&self) -> Style {
        Style::new(self.color_stdout, self.charset)
    }

    /// Glyphs and colour for progress, prompts and the picker on stderr.
    pub(crate) fn stderr_style(&self) -> Style {
        Style::new(self.color_stderr, self.charset)
    }
}

/// The effective `LC_CTYPE` is the first non-empty of `LC_ALL`, `LC_CTYPE`
/// and `LANG`. Unset means the terminal's own default, which keeps Unicode.
/// Only `C`, `POSIX` or a named codeset other than UTF-8 selects ASCII; a
/// locale without a codeset, such as `en_US`, is not explicitly non-UTF-8.
fn locale_is_utf8(env: &impl Env) -> bool {
    let effective = ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .find_map(|key| env.var(key).filter(|value| !value.is_empty()));
    let Some(locale) = effective else {
        return true;
    };
    let name = locale.split('@').next().unwrap_or(&locale);
    match name.split_once('.') {
        Some((_, codeset)) => {
            let codeset = codeset.to_ascii_lowercase();
            codeset == "utf-8" || codeset == "utf8"
        }
        None => name != "C" && name != "POSIX",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MapEnv;

    const ALL_TTY: TerminalFacts = TerminalFacts {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        columns: Some(120),
        rows: Some(40),
    };

    fn env(vars: &[(&str, &str)]) -> MapEnv {
        MapEnv::new(vars.iter().copied())
    }

    fn text(facts: TerminalFacts, vars: &[(&str, &str)]) -> Capabilities {
        Capabilities::detect(OutputMode::Text, &facts, &env(vars))
    }

    #[test]
    fn a_full_terminal_gets_live_colour_unicode_and_motion() {
        let caps = text(ALL_TTY, &[("TERM", "xterm-256color")]);
        assert!(caps.live);
        assert_eq!(caps.motion, Motion::Animated);
        assert!(caps.color_stdout);
        assert!(caps.color_stderr);
        assert_eq!(caps.charset, Charset::Unicode);
        assert!(caps.interactive);
        assert_eq!((caps.columns, caps.rows), (120, Some(40)));
    }

    #[test]
    fn colour_follows_each_stream_separately() {
        let stdout_redirected = TerminalFacts {
            stdout_tty: false,
            ..ALL_TTY
        };
        let caps = text(stdout_redirected, &[]);
        assert!(!caps.color_stdout);
        assert!(caps.color_stderr);
        assert!(caps.live, "progress still draws on a terminal stderr");

        let stderr_redirected = TerminalFacts {
            stderr_tty: false,
            ..ALL_TTY
        };
        let caps = text(stderr_redirected, &[]);
        assert!(caps.color_stdout);
        assert!(!caps.color_stderr);
        assert!(!caps.live);
        assert_eq!(caps.motion, Motion::Off);
        assert!(!caps.interactive);
    }

    #[test]
    fn redirected_streams_get_no_live_redraw_or_colour() {
        let caps = text(TerminalFacts::default(), &[("TERM", "xterm")]);
        assert!(!caps.live);
        assert_eq!(caps.motion, Motion::Off);
        assert!(!caps.color_stdout && !caps.color_stderr);
        assert!(!caps.interactive);
        assert_eq!(caps.columns, DEFAULT_COLUMNS);
        assert_eq!(caps.rows, None);
    }

    #[test]
    fn dumb_terminal_is_plain_ascii_without_redraw() {
        let caps = text(ALL_TTY, &[("TERM", "dumb"), ("LANG", "en_US.UTF-8")]);
        assert!(!caps.live);
        assert_eq!(caps.motion, Motion::Off);
        assert!(!caps.color_stdout && !caps.color_stderr);
        assert_eq!(caps.charset, Charset::Ascii);
        assert!(caps.interactive, "a dumb terminal is still a terminal");
    }

    #[test]
    fn no_color_disables_colour_only_when_non_empty() {
        let caps = text(ALL_TTY, &[("NO_COLOR", "1")]);
        assert!(!caps.color_stdout && !caps.color_stderr);
        assert!(caps.live, "NO_COLOR does not stop progress");
        assert_eq!(caps.charset, Charset::Unicode);

        let caps = text(ALL_TTY, &[("NO_COLOR", "")]);
        assert!(caps.color_stdout && caps.color_stderr);
    }

    #[test]
    fn reduced_motion_keeps_the_live_row_static() {
        for value in ["1", "true", "yes"] {
            let caps = text(ALL_TTY, &[(REDUCED_MOTION_ENV, value)]);
            assert_eq!(caps.motion, Motion::Reduced, "{value}");
            assert!(caps.live);
        }
        for value in ["", "0"] {
            let caps = text(ALL_TTY, &[(REDUCED_MOTION_ENV, value)]);
            assert_eq!(caps.motion, Motion::Animated, "{value:?}");
        }
        let not_live = TerminalFacts {
            stderr_tty: false,
            ..ALL_TTY
        };
        let caps = text(not_live, &[(REDUCED_MOTION_ENV, "1")]);
        assert_eq!(caps.motion, Motion::Off);
    }

    #[test]
    fn locale_selects_ascii_only_when_explicitly_not_utf8() {
        let cases: &[(&[(&str, &str)], Charset)] = &[
            (&[], Charset::Unicode),
            (&[("LANG", "")], Charset::Unicode),
            (&[("LANG", "C")], Charset::Ascii),
            (&[("LANG", "POSIX")], Charset::Ascii),
            (&[("LANG", "C.UTF-8")], Charset::Unicode),
            (&[("LANG", "en_US.utf8")], Charset::Unicode),
            (&[("LANG", "de_DE.UTF-8@euro")], Charset::Unicode),
            (&[("LANG", "en_US.ISO-8859-1")], Charset::Ascii),
            (&[("LANG", "en_US")], Charset::Unicode),
            (&[("LANG", "C@euro")], Charset::Ascii),
            (
                &[("LANG", "C"), ("LC_ALL", "en_US.UTF-8")],
                Charset::Unicode,
            ),
            (&[("LANG", "en_US.UTF-8"), ("LC_ALL", "C")], Charset::Ascii),
            (
                &[("LANG", "en_US.UTF-8"), ("LC_CTYPE", "POSIX")],
                Charset::Ascii,
            ),
            (
                &[("LC_ALL", "C.UTF-8"), ("LC_CTYPE", "C"), ("LANG", "C")],
                Charset::Unicode,
            ),
            (&[("LC_ALL", ""), ("LANG", "C")], Charset::Ascii),
        ];
        for (vars, expected) in cases {
            assert_eq!(text(ALL_TTY, vars).charset, *expected, "{vars:?}");
        }
    }

    #[test]
    fn machine_mode_has_no_progress_colour_or_interaction() {
        let caps = Capabilities::detect(
            OutputMode::Machine,
            &ALL_TTY,
            &env(&[("TERM", "xterm-256color")]),
        );
        assert!(caps.is_machine());
        assert!(!caps.live);
        assert_eq!(caps.motion, Motion::Off);
        assert!(!caps.color_stdout && !caps.color_stderr);
        assert!(!caps.interactive);
    }

    #[test]
    fn interactive_needs_stdin_and_stderr_terminals() {
        let stdin_redirected = TerminalFacts {
            stdin_tty: false,
            ..ALL_TTY
        };
        assert!(!text(stdin_redirected, &[]).interactive);
        let stdout_redirected = TerminalFacts {
            stdout_tty: false,
            ..ALL_TTY
        };
        assert!(text(stdout_redirected, &[]).interactive);
    }

    #[test]
    fn styles_follow_their_stream() {
        let stdout_redirected = TerminalFacts {
            stdout_tty: false,
            ..ALL_TTY
        };
        let caps = text(stdout_redirected, &[]);
        assert_eq!(caps.stdout_style(), Style::new(false, Charset::Unicode));
        assert_eq!(caps.stderr_style(), Style::new(true, Charset::Unicode));
    }
}
