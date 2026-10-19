//! Status glyphs, colour roles and width-safe styled lines.

use super::caps::Charset;
use super::spinner;

/// A status mark. Each glyph keeps its meaning without colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// A confirmed outcome.
    Done,
    /// Work in progress. Static here; [`spinner::Spinner`] animates it.
    Active,
    /// A pending or partial result that needs attention.
    Attention,
    Failed,
    /// A connection direction or the next useful command.
    Next,
    /// The highlighted row of a list.
    Selected,
}

impl Status {
    pub(crate) fn glyph(self, charset: Charset) -> &'static str {
        match (self, charset) {
            (Status::Done, Charset::Unicode) => "✓",
            (Status::Done, Charset::Ascii) => "+",
            (Status::Active, charset) => spinner::frames(charset)[0],
            (Status::Attention, _) => "!",
            (Status::Failed, Charset::Unicode) => "✗",
            (Status::Failed, Charset::Ascii) => "x",
            (Status::Next, Charset::Unicode) => "→",
            (Status::Next, Charset::Ascii) => "->",
            (Status::Selected, Charset::Unicode) => "›",
            (Status::Selected, Charset::Ascii) => ">",
        }
    }

    pub(crate) fn role(self) -> Role {
        match self {
            Status::Done => Role::Success,
            Status::Active | Status::Selected => Role::Active,
            Status::Attention => Role::Attention,
            Status::Failed => Role::Failure,
            Status::Next => Role::Next,
        }
    }
}

/// What a piece of text means, which selects its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Success,
    Active,
    Attention,
    Failure,
    Next,
    /// Quiet secondary detail: timing, location, source.
    Dim,
    Strong,
}

impl Role {
    fn sgr(self) -> &'static str {
        match self {
            Role::Success => "\x1b[32m",
            Role::Active | Role::Next => "\x1b[36m",
            Role::Attention => "\x1b[33m",
            Role::Failure => "\x1b[31m",
            Role::Dim => "\x1b[2m",
            Role::Strong => "\x1b[1m",
        }
    }
}

const RESET: &str = "\x1b[0m";

/// Glyphs and colour for one output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Style {
    color: bool,
    charset: Charset,
}

impl Style {
    pub(crate) const fn new(color: bool, charset: Charset) -> Self {
        Self { color, charset }
    }

    pub(crate) fn charset(self) -> Charset {
        self.charset
    }

    pub(crate) fn color(self) -> bool {
        self.color
    }

    pub(crate) fn glyph(self, status: Status) -> &'static str {
        status.glyph(self.charset)
    }

    /// The status glyph in its colour.
    pub(crate) fn status(self, status: Status) -> String {
        self.paint(status.role(), status.glyph(self.charset))
    }

    /// `text` wrapped in the role's SGR sequence when colour is enabled.
    pub(crate) fn paint(self, role: Role, text: &str) -> String {
        if self.color && !text.is_empty() {
            format!("{}{text}{RESET}", role.sgr())
        } else {
            text.to_owned()
        }
    }

    /// Separator between short facts on one line.
    pub(crate) fn separator(self) -> &'static str {
        match self.charset {
            Charset::Unicode => " · ",
            Charset::Ascii => " - ",
        }
    }
}

/// A line built from plain and styled segments, so it can be cut to the
/// terminal width before any escape sequence is added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Line {
    segments: Vec<(Option<Role>, String)>,
}

impl Line {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn plain(mut self, text: impl Into<String>) -> Self {
        self.segments.push((None, text.into()));
        self
    }

    pub(super) fn styled(mut self, role: Role, text: impl Into<String>) -> Self {
        self.segments.push((Some(role), text.into()));
        self
    }

    pub(super) fn status(self, style: Style, status: Status) -> Self {
        self.styled(status.role(), style.glyph(status))
    }

    /// Visible width in characters.
    pub(super) fn width(&self) -> usize {
        self.segments
            .iter()
            .map(|(_, text)| text.chars().count())
            .sum()
    }

    /// Keeps at most `max` characters.
    pub(super) fn truncate(mut self, max: usize) -> Self {
        let mut left = max;
        for (_, text) in &mut self.segments {
            match text.char_indices().nth(left) {
                Some((cut, _)) => {
                    text.truncate(cut);
                    left = 0;
                }
                None => left -= text.chars().count(),
            }
        }
        self.segments.retain(|(_, text)| !text.is_empty());
        self
    }

    pub(super) fn render(&self, style: Style) -> String {
        self.segments
            .iter()
            .map(|(role, text)| match role {
                Some(role) => style.paint(*role, text),
                None => text.clone(),
            })
            .collect()
    }

    /// The text without any styling.
    pub(super) fn text(&self) -> String {
        self.segments
            .iter()
            .map(|(_, text)| text.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyphs_have_unicode_and_ascii_forms() {
        let unicode = [
            (Status::Done, "✓"),
            (Status::Active, "◐"),
            (Status::Attention, "!"),
            (Status::Failed, "✗"),
            (Status::Next, "→"),
            (Status::Selected, "›"),
        ];
        for (status, glyph) in unicode {
            assert_eq!(status.glyph(Charset::Unicode), glyph);
        }
        let ascii = [
            (Status::Done, "+"),
            (Status::Active, "|"),
            (Status::Attention, "!"),
            (Status::Failed, "x"),
            (Status::Next, "->"),
            (Status::Selected, ">"),
        ];
        for (status, glyph) in ascii {
            assert_eq!(status.glyph(Charset::Ascii), glyph);
            assert!(glyph.is_ascii());
        }
    }

    #[test]
    fn colour_is_added_only_when_enabled() {
        let plain = Style::new(false, Charset::Unicode);
        assert_eq!(plain.status(Status::Done), "✓");
        assert_eq!(plain.paint(Role::Dim, "2.1s"), "2.1s");

        let color = Style::new(true, Charset::Unicode);
        assert_eq!(color.status(Status::Done), "\x1b[32m✓\x1b[0m");
        assert_eq!(color.status(Status::Active), "\x1b[36m◐\x1b[0m");
        assert_eq!(color.status(Status::Attention), "\x1b[33m!\x1b[0m");
        assert_eq!(color.status(Status::Failed), "\x1b[31m✗\x1b[0m");
        assert_eq!(color.paint(Role::Dim, "2.1s"), "\x1b[2m2.1s\x1b[0m");
        assert_eq!(color.paint(Role::Strong, ""), "");
    }

    #[test]
    fn separator_follows_charset() {
        assert_eq!(Style::new(false, Charset::Unicode).separator(), " · ");
        assert_eq!(Style::new(false, Charset::Ascii).separator(), " - ");
    }

    #[test]
    fn lines_truncate_before_painting() {
        let style = Style::new(true, Charset::Unicode);
        let line = Line::new()
            .plain("  ")
            .status(style, Status::Active)
            .plain(" Installing dependencies")
            .styled(Role::Dim, "  12s");
        assert_eq!(line.width(), 32);
        let cut = line.clone().truncate(10);
        assert_eq!(cut.text(), "  ◐ Instal");
        assert_eq!(cut.render(style), "  \x1b[36m◐\x1b[0m Instal");
        assert_eq!(line.clone().truncate(100), line);
        assert_eq!(line.truncate(0).render(style), "");
    }
}
