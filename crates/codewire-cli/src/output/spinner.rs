//! The rotating-circle progress indicator.

use std::time::Duration;

use super::caps::{Capabilities, Charset, Motion};

/// One frame per 100 ms, as in the reviewed design.
pub(crate) const FRAME_INTERVAL: Duration = Duration::from_millis(100);

/// The reduced-motion row changes only its elapsed time, once a second.
pub(crate) const REDUCED_INTERVAL: Duration = Duration::from_secs(1);

const CIRCLE: [&str; 4] = ["◐", "◓", "◑", "◒"];
const ASCII: [&str; 4] = ["|", "/", "-", "\\"];

pub(super) fn frames(charset: Charset) -> &'static [&'static str; 4] {
    match charset {
        Charset::Unicode => &CIRCLE,
        Charset::Ascii => &ASCII,
    }
}

/// Chooses the active row's glyph from elapsed time. Only the active row
/// uses it; finished rows show their outcome glyph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Spinner {
    frames: &'static [&'static str; 4],
    animated: bool,
}

impl Spinner {
    pub(crate) fn new(caps: &Capabilities) -> Self {
        Self::with(caps.charset, caps.motion == Motion::Animated)
    }

    pub(crate) fn with(charset: Charset, animated: bool) -> Self {
        Self {
            frames: frames(charset),
            animated,
        }
    }

    /// The frame for `elapsed`: `floor(elapsed / 100 ms) mod 4` when
    /// animated, otherwise always the first frame.
    pub(crate) fn frame(&self, elapsed: Duration) -> &'static str {
        if !self.animated {
            return self.frames[0];
        }
        let step = elapsed.as_millis() / FRAME_INTERVAL.as_millis();
        self.frames[(step % self.frames.len() as u128) as usize]
    }

    pub(crate) fn is_animated(&self) -> bool {
        self.animated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn circle_rotates_every_hundred_milliseconds() {
        let spinner = Spinner::with(Charset::Unicode, true);
        let seen: Vec<_> = [0, 99, 100, 199, 200, 300, 399, 400, 1_050]
            .into_iter()
            .map(|at| spinner.frame(ms(at)))
            .collect();
        assert_eq!(seen, ["◐", "◐", "◓", "◓", "◑", "◒", "◒", "◐", "◑"]);
    }

    #[test]
    fn ascii_fallback_rotates_the_same_way() {
        let spinner = Spinner::with(Charset::Ascii, true);
        let seen: Vec<_> = (0..5).map(|step| spinner.frame(ms(step * 100))).collect();
        assert_eq!(seen, ["|", "/", "-", "\\", "|"]);
    }

    #[test]
    fn a_static_spinner_always_shows_its_first_frame() {
        for charset in [Charset::Unicode, Charset::Ascii] {
            let spinner = Spinner::with(charset, false);
            assert!(!spinner.is_animated());
            let first = frames(charset)[0];
            for at in [0, 100, 250, 999_999] {
                assert_eq!(spinner.frame(ms(at)), first);
            }
        }
    }
}
