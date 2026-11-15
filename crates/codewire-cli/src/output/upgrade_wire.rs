//! The wire `cw upgrade` lights after it selects a newer cw: the Codewire
//! wordmark, then a spark that runs from the previous version to the new
//! one, which then turns green.
//!
//! Decoration only, on stderr: nothing is drawn unless stderr is a live
//! terminal, reduced motion draws the lit wire without the run, and the
//! durable result on stdout is unchanged.

use std::io::{self, Write};
use std::time::Duration;

use crate::commands::progress::terminal_text;

use super::caps::{Capabilities, Charset, Motion};
use super::style::{Line, Role, Status, Style};
use super::wordmark::wordmark;

const CLEAR_LINE: &str = "\r\x1b[2K";

/// Cells of wire between the versions on a wide terminal.
const LENGTH: usize = 22;

/// A shorter wire than this is not drawn at all.
const MIN_LENGTH: usize = 6;

/// Cells the spark moves per frame: 11 frames for the full wire.
const STEP: usize = 2;

/// About half a second for the full wire.
const FRAME: Duration = Duration::from_millis(40);

/// Draws the wordmark and runs the spark from `from` to `to` on stderr when
/// stderr is a live terminal, each only where it fits. A failed write leaves
/// the upgrade as it was.
pub(crate) fn play_upgrade_wire(caps: &Capabilities, from: &str, to: &str) {
    let mut out = io::stderr().lock();
    // Decoration: a terminal that refuses it does not fail the upgrade.
    let _ = play_to(caps, from, to, &mut out, std::thread::sleep);
}

/// [`play_upgrade_wire`] into `out`, pausing with `pause`: nothing at all
/// unless `caps` says stderr is a live terminal.
fn play_to(
    caps: &Capabilities,
    from: &str,
    to: &str,
    out: &mut impl Write,
    pause: impl FnMut(Duration),
) -> io::Result<()> {
    if !caps.live {
        return Ok(());
    }
    let style = caps.stderr_style();
    let art = wordmark(caps.columns, style, caps.true_color);
    let wire = Wire::fit(from, to, caps.columns);
    let animated = caps.motion == Motion::Animated;
    draw(out, art.as_deref(), wire.as_ref(), style, animated, pause)
}

/// The wordmark with a blank line under it, then the wire.
fn draw(
    out: &mut impl Write,
    art: Option<&str>,
    wire: Option<&Wire>,
    style: Style,
    animated: bool,
    pause: impl FnMut(Duration),
) -> io::Result<()> {
    if let Some(art) = art {
        writeln!(out, "{art}")?;
    }
    match wire {
        Some(wire) => wire.play(out, style, animated, pause),
        None => out.flush(),
    }
}

/// The two versions and the wire between them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Wire {
    from: String,
    to: String,
    length: usize,
}

impl Wire {
    /// The wire for `columns`, shortened to fit, or `None` when even the
    /// shortest wire would not.
    fn fit(from: &str, to: &str, columns: u16) -> Option<Self> {
        let from = terminal_text(from);
        let to = terminal_text(to);
        // "  FROM " + wire + " TO ✓" and one spare column.
        let fixed = 2 + from.chars().count() + 1 + 1 + to.chars().count() + 2 + 1;
        let length = usize::from(columns).checked_sub(fixed)?.min(LENGTH);
        (length >= MIN_LENGTH).then_some(Self { from, to, length })
    }

    fn play(
        &self,
        out: &mut impl Write,
        style: Style,
        animated: bool,
        mut pause: impl FnMut(Duration),
    ) -> io::Result<()> {
        if animated {
            for lit in (0..self.length).step_by(STEP) {
                write!(
                    out,
                    "{CLEAR_LINE}{}",
                    self.running(lit, style).render(style)
                )?;
                out.flush()?;
                pause(FRAME);
            }
        }
        writeln!(out, "{CLEAR_LINE}{}", self.done(style).render(style))?;
        out.flush()
    }

    /// The spark at cell `lit`: the wire behind it lit, ahead of it dark.
    fn running(&self, lit: usize, style: Style) -> Line {
        let glyphs = Glyphs::of(style.charset());
        Line::new()
            .plain("  ")
            .styled(Role::Dim, self.from.as_str())
            .plain(" ")
            .styled(Role::Active, glyphs.lit.repeat(lit))
            .styled(Role::Attention, glyphs.spark)
            .styled(Role::Dim, glyphs.dark.repeat(self.length - lit - 1))
            .plain(" ")
            .plain(self.to.as_str())
    }

    /// The whole wire lit, ending in an arrow at the new version.
    fn done(&self, style: Style) -> Line {
        let glyphs = Glyphs::of(style.charset());
        Line::new()
            .plain("  ")
            .styled(Role::Dim, self.from.as_str())
            .plain(" ")
            .styled(Role::Active, glyphs.lit.repeat(self.length - 1))
            .styled(Role::Active, glyphs.arrow)
            .plain(" ")
            .styled(Role::Success, self.to.as_str())
            .plain(" ")
            .status(style, Status::Done)
    }
}

struct Glyphs {
    lit: &'static str,
    dark: &'static str,
    spark: &'static str,
    arrow: &'static str,
}

impl Glyphs {
    fn of(charset: Charset) -> Self {
        match charset {
            Charset::Unicode => Self {
                lit: "━",
                dark: "─",
                spark: "●",
                arrow: "▶",
            },
            Charset::Ascii => Self {
                lit: "=",
                dark: "-",
                spark: "*",
                arrow: ">",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn played(wire: &Wire, style: Style, animated: bool) -> (String, Vec<Duration>) {
        let mut out = Vec::new();
        let mut pauses = Vec::new();
        wire.play(&mut out, style, animated, |pause| pauses.push(pause))
            .unwrap();
        (String::from_utf8(out).unwrap(), pauses)
    }

    /// Piped, redirected or under `TERM=dumb`, stderr is not live, and an
    /// upgrade writes no art and no escape at all; at a terminal it does.
    #[test]
    fn nothing_is_drawn_unless_stderr_is_a_live_terminal() {
        use crate::config::MapEnv;
        use crate::output::caps::{OutputMode, TerminalFacts};
        let drawn = |facts: TerminalFacts, vars: &[(&str, &str)]| {
            let caps =
                Capabilities::detect(OutputMode::Text, &facts, &MapEnv::new(vars.iter().copied()));
            let mut out = Vec::new();
            play_to(&caps, "v0.4.18", "v0.4.19", &mut out, |_| {}).unwrap();
            String::from_utf8(out).unwrap()
        };
        let terminal = TerminalFacts {
            stdin_tty: true,
            stdout_tty: true,
            stderr_tty: true,
            columns: Some(120),
            rows: Some(40),
        };
        assert_eq!(drawn(TerminalFacts::default(), &[]), "", "piped");
        assert_eq!(drawn(terminal, &[("TERM", "dumb")]), "", "TERM=dumb");
        assert!(drawn(terminal, &[("TERM", "xterm-256color")]).contains("v0.4.19"));
    }

    fn frames(out: &str) -> Vec<&str> {
        out.split(CLEAR_LINE)
            .filter(|frame| !frame.is_empty())
            .collect()
    }

    #[test]
    fn the_spark_runs_from_the_old_version_to_the_new_one() {
        let wire = Wire::fit("v0.8.2", "v0.9.0", 80).unwrap();
        assert_eq!(wire.length, LENGTH);
        let (out, pauses) = played(&wire, Style::new(false, Charset::Unicode), true);
        let frames = frames(&out);
        assert_eq!(frames.len(), LENGTH / STEP + 1);
        assert_eq!(pauses, vec![FRAME; LENGTH / STEP]);
        assert_eq!(frames[0], "  v0.8.2 ●───────────────────── v0.9.0");
        assert_eq!(frames[5], "  v0.8.2 ━━━━━━━━━━●─────────── v0.9.0");
        assert_eq!(frames[10], "  v0.8.2 ━━━━━━━━━━━━━━━━━━━━●─ v0.9.0");
        assert_eq!(frames[11], "  v0.8.2 ━━━━━━━━━━━━━━━━━━━━━▶ v0.9.0 ✓\n");
        assert!(frames[..11].iter().all(|frame| !frame.contains('\n')));
    }

    #[test]
    fn reduced_motion_draws_only_the_lit_wire() {
        let wire = Wire::fit("v0.8.2", "v0.9.0", 80).unwrap();
        let (out, pauses) = played(&wire, Style::new(false, Charset::Unicode), false);
        assert_eq!(out, "\r\x1b[2K  v0.8.2 ━━━━━━━━━━━━━━━━━━━━━▶ v0.9.0 ✓\n");
        assert!(pauses.is_empty());
    }

    #[test]
    fn an_ascii_terminal_gets_an_ascii_wire() {
        let wire = Wire::fit("v0.8.2", "v0.9.0", 80).unwrap();
        let (out, _) = played(&wire, Style::new(false, Charset::Ascii), true);
        let frames = frames(&out);
        assert_eq!(frames[3], "  v0.8.2 ======*--------------- v0.9.0");
        assert_eq!(frames[11], "  v0.8.2 =====================> v0.9.0 +\n");
        assert!(out.is_ascii());
    }

    #[test]
    fn colour_lights_the_wire_and_turns_the_new_version_green() {
        let wire = Wire::fit("v0.8.2", "v0.9.0", 80).unwrap();
        let (out, _) = played(&wire, Style::new(true, Charset::Unicode), false);
        assert_eq!(
            out,
            "\r\x1b[2K  \x1b[2mv0.8.2\x1b[0m \x1b[36m━━━━━━━━━━━━━━━━━━━━━\x1b[0m\
             \x1b[36m▶\x1b[0m \x1b[32mv0.9.0\x1b[0m \x1b[32m✓\x1b[0m\n"
        );
    }

    #[test]
    fn a_narrow_terminal_gets_a_shorter_wire_or_none() {
        // 2 + 6 + 1 + 1 + 6 + 2 + 1 columns hold everything but the wire.
        assert_eq!(Wire::fit("v0.8.2", "v0.9.0", 19 + 10).unwrap().length, 10);
        assert_eq!(
            Wire::fit("v0.8.2", "v0.9.0", 19 + MIN_LENGTH as u16)
                .unwrap()
                .length,
            MIN_LENGTH
        );
        assert_eq!(
            Wire::fit("v0.8.2", "v0.9.0", 19 + MIN_LENGTH as u16 - 1),
            None
        );
        assert_eq!(Wire::fit("v0.8.2", "v0.9.0", 4), None);
    }

    #[test]
    fn a_short_wire_still_ends_lit() {
        let wire = Wire::fit("v1", "v2", 2 + 2 + 1 + 1 + 2 + 2 + 1 + 7).unwrap();
        assert_eq!(wire.length, 7);
        let (out, pauses) = played(&wire, Style::new(false, Charset::Unicode), true);
        let frames = frames(&out);
        assert_eq!(pauses.len(), 4);
        assert_eq!(frames[3], "  v1 ━━━━━━● v2");
        assert_eq!(frames[4], "  v1 ━━━━━━▶ v2 ✓\n");
    }

    #[test]
    fn control_characters_in_a_version_are_not_drawn() {
        let wire = Wire::fit("v1\x1b[2J", "v2", 80).unwrap();
        assert!(!wire.from.contains('\x1b'));
    }
}
