//! What an attachment to an environment's session does when it resumes the
//! same session after a drop.

use std::time::Duration;

use tokio::time::Instant;

use super::AttachExit;
use crate::terminal_attach::{SessionScreen, WindowSizeWatch};

impl AttachExit {
    /// Whether the next attachment resumes this session's output where this
    /// one stopped, so the program's screen stays this terminal's.
    pub(super) fn resumes_session(self) -> bool {
        matches!(
            self,
            Self::StreamEnded { .. } | Self::StreamInterrupted { .. } | Self::TailnetBack { .. }
        )
    }
}

/// A request that sets the session's PTY to (columns, rows).
pub(super) fn resize_request((columns, rows): (u16, u16)) -> codewire_client::AttachSessionRequest {
    codewire_client::AttachSessionRequest {
        input: Some(codewire_client::attach_session_request::Input::Resize(
            Box::new(codewire_client::AttachSessionResize {
                columns: u32::from(columns),
                rows: u32::from(rows),
                ..Default::default()
            }),
        )),
        ..Default::default()
    }
}

/// How long the real size waits, after the shorter one, for the program to
/// redraw before it is set anyway: a busy program, or one that prints
/// nothing for a resize, still gets two different sizes.
const REDRAW_WAIT: Duration = Duration::from_millis(150);
/// How long the real size waits for the attachment's first status. The
/// input notice printed with that status lands in the program's screen, so
/// the redraw should follow it; a server that sends none still gets its real
/// size.
const ANSWER_WAIT: Duration = Duration::from_secs(1);

/// The sizes an attachment sets on its session's PTY: the terminal's, and,
/// on a reattach while the program holds the alternate screen, one row fewer
/// first (#5090). A reattach resumes the output where it stopped, so what
/// `cw` printed during the drop stays in the program's screen until it
/// redraws, and the kernel signals a size change only when the size differs.
/// Two different sizes make a full-screen program redraw everything; a
/// first attachment, or a program on the normal screen, is left alone.
pub(super) struct PtySizes {
    window: WindowSizeWatch,
    repaint: Repaint,
}

enum Repaint {
    /// The program holds the alternate screen of the session this
    /// attachment resumes; nothing is set yet.
    Wanted,
    /// The shorter size is set, and the real one waits.
    Shrunk {
        real: (u16, u16),
        at: Instant,
        /// The session's output end as the first status reported it.
        answered: Option<u64>,
        redrawn: bool,
    },
    None,
}

impl PtySizes {
    /// `screen` is the one the previous attachment drew on, unless it was
    /// given back, as it is on a detach or a move to another session.
    pub(super) fn new(window: WindowSizeWatch, screen: &SessionScreen) -> Self {
        Self {
            window,
            repaint: if screen.alternate() {
                Repaint::Wanted
            } else {
                Repaint::None
            },
        }
    }

    /// The size to set as the attachment opens.
    pub(super) fn first(&mut self) -> Option<(u16, u16)> {
        let size = self.window.current()?;
        Some(self.opening(size, Instant::now()))
    }

    fn opening(&mut self, (columns, rows): (u16, u16), now: Instant) -> (u16, u16) {
        if !matches!(self.repaint, Repaint::Wanted) || rows < 2 {
            self.repaint = Repaint::None;
            return (columns, rows);
        }
        self.repaint = Repaint::Shrunk {
            real: (columns, rows),
            at: now,
            answered: None,
            redrawn: false,
        };
        (columns, rows - 1)
    }

    /// The attachment brought a status whose session output ends at
    /// `output_end`; the first one carries the input notice.
    pub(super) fn answered(&mut self, output_end: u64) {
        if let Repaint::Shrunk { answered, .. } = &mut self.repaint {
            answered.get_or_insert(output_end);
        }
    }

    /// The session's output now reaches `next_offset`. Only output past the
    /// end the first status reported is taken as the program's redraw at the
    /// shorter size: the daemon acknowledges the resize before it replays
    /// what the session printed during the drop.
    pub(super) fn output(&mut self, next_offset: u64) {
        if let Repaint::Shrunk {
            answered: Some(output_end),
            redrawn,
            ..
        } = &mut self.repaint
        {
            *redrawn |= next_offset > *output_end;
        }
    }

    /// The next size to set: the terminal's after it changes, or the real
    /// size once the program has redrawn at the shorter one.
    pub(super) async fn changed(&mut self) -> Option<(u16, u16)> {
        let due = self.repaint.due();
        tokio::select! {
            size = self.window.changed() => {
                if size.is_some() {
                    // The new size differs from the shorter one, or is it.
                    self.repaint = Repaint::None;
                }
                size
            }
            () = tokio::time::sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                match std::mem::replace(&mut self.repaint, Repaint::None) {
                    Repaint::Shrunk { real, .. } => Some(real),
                    Repaint::Wanted | Repaint::None => None,
                }
            }
        }
    }
}

impl Repaint {
    /// When the real size is due, while one waits.
    fn due(&self) -> Option<Instant> {
        let Self::Shrunk {
            at,
            answered,
            redrawn,
            ..
        } = self
        else {
            return None;
        };
        Some(match (answered, redrawn) {
            (None, _) => *at + ANSWER_WAIT,
            (Some(_), false) => *at + REDRAW_WAIT,
            (Some(_), true) => *at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sizes(screen: SessionScreen) -> PtySizes {
        let sizes = PtySizes::new(WindowSizeWatch::new(false), &screen);
        // Dropped, a drawn screen writes its release to the test's stdout.
        std::mem::forget(screen);
        sizes
    }

    fn alternate_screen() -> SessionScreen {
        let mut screen = SessionScreen::new(true);
        screen.observe(b"\x1b[?1049hthe agent's frame");
        screen
    }

    /// The real size and how long after the shorter one it came.
    async fn real_size(sizes: &mut PtySizes, shrunk_at: Instant) -> (Option<(u16, u16)>, Duration) {
        let size = sizes.changed().await;
        (size, shrunk_at.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn a_reattach_in_the_alternate_screen_sets_one_row_fewer_then_the_real_size() {
        let mut sizes = sizes(alternate_screen());
        let start = Instant::now();
        assert_eq!(sizes.opening((120, 40), start), (120, 39));
        sizes.output(500); // output before the status is not the redraw
        sizes.answered(1000);
        sizes.output(1200);
        assert_eq!(
            real_size(&mut sizes, start).await,
            (Some((120, 40)), Duration::ZERO)
        );
        let after = tokio::time::timeout(Duration::from_secs(60), sizes.changed()).await;
        assert!(after.is_err(), "the real size is set once");
    }

    #[tokio::test(start_paused = true)]
    async fn the_replay_of_what_the_drop_missed_is_not_taken_as_the_redraw() {
        // The daemon acknowledges the shorter size first, then replays the
        // session's output up to the end that acknowledgement reported.
        let mut sizes = sizes(alternate_screen());
        let start = Instant::now();
        sizes.opening((120, 40), start);
        sizes.answered(1000);
        sizes.answered(5000); // a later status does not move the mark
        sizes.output(800);
        sizes.output(1000);
        let waited = tokio::time::timeout(REDRAW_WAIT / 2, sizes.changed()).await;
        assert!(waited.is_err(), "the replay alone sets nothing");
        sizes.output(1001);
        assert_eq!(
            real_size(&mut sizes, start).await,
            (Some((120, 40)), REDRAW_WAIT / 2)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_real_size_waits_at_most_a_moment_for_the_redraw_and_a_second_for_the_status() {
        let mut quiet = sizes(alternate_screen());
        let start = Instant::now();
        quiet.opening((80, 24), start);
        quiet.answered(0);
        assert_eq!(
            real_size(&mut quiet, start).await,
            (Some((80, 24)), REDRAW_WAIT)
        );

        let mut unanswered = sizes(alternate_screen());
        unanswered.opening((80, 24), start);
        unanswered.output(100);
        assert_eq!(
            real_size(&mut unanswered, start).await,
            (Some((80, 24)), ANSWER_WAIT)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_attachment_or_the_normal_screen_sets_only_the_real_size() {
        let mut shell = SessionScreen::new(true);
        shell.observe(b"$ ls\r\n");
        let mut left = alternate_screen();
        left.observe(b"\x1b[?1049l$ ");
        for screen in [SessionScreen::new(true), shell, left] {
            let mut sizes = sizes(screen);
            assert_eq!(sizes.opening((120, 40), Instant::now()), (120, 40));
            sizes.answered(0);
            sizes.output(100);
            let next = tokio::time::timeout(Duration::from_secs(60), sizes.changed()).await;
            assert!(next.is_err(), "nothing more is set");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_one_row_terminal_is_not_shrunk() {
        let mut sizes = sizes(alternate_screen());
        assert_eq!(sizes.opening((80, 1), Instant::now()), (80, 1));
        let next = tokio::time::timeout(Duration::from_secs(60), sizes.changed()).await;
        assert!(next.is_err());
    }
}
