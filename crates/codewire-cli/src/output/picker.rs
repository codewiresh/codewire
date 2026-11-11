//! A searchable single choice on an interactive terminal.
//!
//! [`Picker`] is a pure state machine: [`Picker::handle`] applies one key,
//! [`Picker::visible`] lists the rows that match the filter and
//! [`Picker::render`] draws the current state. [`run_picker`] drives it on
//! the real terminal through the shared runner: raw input from stdin,
//! drawing on stderr, and the terminal mode and screen restored on every
//! exit path.

use crate::commands::progress::terminal_text;

use super::caps::{Capabilities, Charset};
use super::interactive::{self, Interaction, Step, Widget, range_line, window};
use super::keys::Key;
use super::style::{Line, Role, Status, Style};

/// The design's message for a filter that matches nothing. The picker stays
/// open.
pub(crate) const NO_MATCH: &str = "No matching environments. Backspace to clear the filter.";

/// One choice: display cells under the header, and the text a filter
/// matches against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PickerRow {
    cells: Vec<String>,
    search: String,
}

impl PickerRow {
    /// Cells pass through the control-character sanitizer; the filter
    /// matches `search` without regard to case.
    pub(crate) fn new(cells: Vec<String>, search: impl Into<String>) -> Self {
        Self {
            cells: cells.iter().map(|cell| terminal_text(cell)).collect(),
            search: search.into().to_lowercase(),
        }
    }
}

/// What one key did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PickerStep {
    Continue,
    /// The row at this index of the rows the picker was built with.
    Chosen(usize),
    Canceled,
}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PickerOutcome {
    /// The row at this index of the rows the picker was built with.
    Chosen(usize),
    /// Escape, Ctrl-C or closed input. Nothing was selected.
    Canceled,
    /// No interactive terminal (or no unix terminal support). The caller
    /// asks for an explicit choice instead; nothing was drawn.
    Unavailable,
}

#[derive(Clone, Debug)]
pub(crate) struct Picker {
    title: String,
    header: Vec<String>,
    rows: Vec<PickerRow>,
    no_match: String,
    query: String,
    visible: Vec<usize>,
    cursor: usize,
}

impl Picker {
    pub(crate) fn new(title: impl Into<String>, header: Vec<String>, rows: Vec<PickerRow>) -> Self {
        let visible = (0..rows.len()).collect();
        Self {
            title: terminal_text(&title.into()),
            header: header.iter().map(|cell| terminal_text(cell)).collect(),
            rows,
            no_match: NO_MATCH.to_owned(),
            query: String::new(),
            visible,
            cursor: 0,
        }
    }

    /// Replaces the message shown when the filter matches nothing.
    pub(crate) fn with_no_match(mut self, message: impl Into<String>) -> Self {
        self.no_match = terminal_text(&message.into());
        self
    }

    /// Applies one key. Arrows move within the matching rows, typing and
    /// Backspace edit the filter (moving to its first match), Enter chooses
    /// the highlighted row, and Escape or Ctrl-C cancel.
    pub(crate) fn handle(&mut self, key: Key) -> PickerStep {
        match key {
            Key::Up => self.cursor = self.cursor.saturating_sub(1),
            Key::Down => {
                if self.cursor + 1 < self.visible.len() {
                    self.cursor += 1;
                }
            }
            Key::Enter => {
                if let Some(&index) = self.visible.get(self.cursor) {
                    return PickerStep::Chosen(index);
                }
            }
            Key::Escape | Key::CtrlC | Key::CtrlD => return PickerStep::Canceled,
            Key::Backspace => {
                if self.query.pop().is_some() {
                    self.refilter();
                }
            }
            Key::CtrlU => {
                if !self.query.is_empty() {
                    self.query.clear();
                    self.refilter();
                }
            }
            Key::Char(c) => {
                self.query.push(c);
                self.refilter();
            }
            Key::Other => {}
        }
        PickerStep::Continue
    }

    /// Indices, into the original rows, of the rows matching the filter.
    pub(crate) fn visible(&self) -> &[usize] {
        &self.visible
    }

    /// The original index of the highlighted row, if any row matches.
    pub(crate) fn highlighted(&self) -> Option<usize> {
        self.visible.get(self.cursor).copied()
    }

    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    fn refilter(&mut self) {
        let query = self.query.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.search.contains(&query))
            .map(|(index, _)| index)
            .collect();
        self.cursor = 0;
    }

    /// The picker as lines without line endings, each cut to `columns - 1`
    /// characters, showing at most `max_rows` rows around the highlight.
    pub(crate) fn render(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String> {
        let width = usize::from(columns).saturating_sub(1).max(1);
        let widths = self.column_widths();
        let mut lines = vec![
            Line::new().styled(Role::Strong, self.title.clone()),
            if self.query.is_empty() {
                Line::new()
                    .plain("  Filter: ")
                    .styled(Role::Dim, "type to search")
            } else {
                Line::new().plain(format!("  Filter: {}", self.query))
            },
            Line::new(),
            Line::new().plain(format!("  {}", layout(&self.header, &widths))),
        ];
        let (start, end) = window(self.cursor, self.visible.len(), max_rows);
        for position in start..end {
            let row = &self.rows[self.visible[position]];
            let marker = if position == self.cursor {
                Line::new().status(style, Status::Selected)
            } else {
                Line::new().plain(" ")
            };
            lines.push(marker.plain(format!(" {}", layout(&row.cells, &widths))));
        }
        if self.visible.is_empty() {
            lines.push(Line::new().styled(Role::Dim, format!("  {}", self.no_match)));
        } else if end - start < self.visible.len() {
            lines.push(range_line(style, start, end, self.visible.len()));
        }
        lines.push(Line::new());
        let help = match style.charset() {
            Charset::Unicode => "  ↑/↓ move · type to filter · Enter select · Esc cancel",
            Charset::Ascii => "  Up/Down move - type to filter - Enter select - Esc cancel",
        };
        lines.push(Line::new().styled(Role::Dim, help));
        lines
            .into_iter()
            .map(|line| line.truncate(width).render(style))
            .collect()
    }

    /// Widths over the header and every row, so columns stay put while the
    /// filter changes.
    fn column_widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = Vec::new();
        for cells in std::iter::once(&self.header).chain(self.rows.iter().map(|row| &row.cells)) {
            for (index, cell) in cells.iter().enumerate() {
                let len = cell.chars().count();
                match widths.get_mut(index) {
                    Some(width) => *width = (*width).max(len),
                    None => widths.push(len),
                }
            }
        }
        widths
    }
}

fn layout(cells: &[String], widths: &[usize]) -> String {
    let mut text = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            text.push_str("  ");
        }
        text.push_str(cell);
        let pad = widths[index].saturating_sub(cell.chars().count());
        text.extend(std::iter::repeat_n(' ', pad));
    }
    text.trim_end().to_owned()
}

impl Widget for Picker {
    type Output = usize;
    /// Title, filter, blank, header, a range or no-match line, blank and the
    /// key help.
    const CHROME_LINES: usize = 7;

    fn on_key(&mut self, key: Key) -> Step<usize> {
        match self.handle(key) {
            PickerStep::Continue => Step::Continue,
            PickerStep::Chosen(index) => Step::Done(index),
            PickerStep::Canceled => Step::Canceled,
        }
    }

    fn frame(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String> {
        self.render(style, columns, max_rows)
    }
}

/// Runs the picker on the process's terminal: raw input from stdin and
/// drawing on stderr. Returns [`PickerOutcome::Unavailable`] without
/// touching the terminal unless the session is interactive and can redraw
/// (`TERM=dumb` cannot). The terminal mode is restored and the picker's
/// lines are erased on every exit path, including errors and panics.
///
/// This blocks on terminal input; async callers run it on a blocking
/// thread. The width and height are read once when it opens.
pub(crate) fn run_picker(mut picker: Picker, caps: &Capabilities) -> anyhow::Result<PickerOutcome> {
    Ok(match interactive::run(&mut picker, caps)? {
        Interaction::Done(index) => PickerOutcome::Chosen(index),
        Interaction::Canceled => PickerOutcome::Canceled,
        Interaction::Unavailable => PickerOutcome::Unavailable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MapEnv;
    use crate::output::caps::{OutputMode, TerminalFacts};
    use crate::output::interactive::script::Script;
    use crate::output::interactive::{Screen, drive};

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    fn cells(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn row(values: &[&str]) -> PickerRow {
        let search = [values[0], values[1], values[2], values[6]].join(" ");
        PickerRow::new(cells(values), search)
    }

    fn environments() -> Picker {
        Picker::new(
            "Choose an environment",
            cells(&[
                "NAME",
                "LOCATION",
                "STATE",
                "vCPU",
                "RAM",
                "DISK",
                "CREDENTIALS",
            ]),
            vec![
                row(&[
                    "app",
                    "local",
                    "running",
                    "2",
                    "4 GiB",
                    "40 GiB",
                    "platform:work",
                ]),
                row(&[
                    "review",
                    "cloud",
                    "stopped",
                    "4",
                    "8 GiB",
                    "80 GiB",
                    "platform:work",
                ]),
                row(&[
                    "scratch", "local", "stopped", "2", "4 GiB", "40 GiB", "none",
                ]),
            ],
        )
    }

    fn type_text(picker: &mut Picker, text: &str) {
        for c in text.chars() {
            assert_eq!(picker.handle(Key::Char(c)), PickerStep::Continue);
        }
    }

    #[test]
    fn renders_the_designed_picker() {
        assert_eq!(
            environments().render(PLAIN, 100, 10),
            [
                "Choose an environment",
                "  Filter: type to search",
                "",
                "  NAME     LOCATION  STATE    vCPU  RAM    DISK    CREDENTIALS",
                "› app      local     running  2     4 GiB  40 GiB  platform:work",
                "  review   cloud     stopped  4     8 GiB  80 GiB  platform:work",
                "  scratch  local     stopped  2     4 GiB  40 GiB  none",
                "",
                "  ↑/↓ move · type to filter · Enter select · Esc cancel",
            ]
        );
    }

    #[test]
    fn typing_filters_without_regard_to_case() {
        let mut picker = environments();
        type_text(&mut picker, "st");
        assert_eq!(picker.visible(), [1, 2]);
        assert_eq!(picker.query(), "st");
        picker.handle(Key::CtrlU);
        type_text(&mut picker, "LOCAL");
        assert_eq!(picker.visible(), [0, 2]);
        picker.handle(Key::CtrlU);
        type_text(&mut picker, "platform:WORK");
        assert_eq!(picker.visible(), [0, 1]);
        let lines = picker.render(PLAIN, 100, 10);
        assert_eq!(lines[1], "  Filter: platform:WORK");
    }

    #[test]
    fn no_match_keeps_the_picker_open_until_backspace() {
        let mut picker = environments();
        type_text(&mut picker, "zz");
        assert!(picker.visible().is_empty());
        assert_eq!(picker.highlighted(), None);
        assert_eq!(picker.handle(Key::Enter), PickerStep::Continue);
        assert_eq!(picker.handle(Key::Down), PickerStep::Continue);
        let lines = picker.render(PLAIN, 100, 10);
        assert_eq!(lines[4], format!("  {NO_MATCH}"));
        assert_eq!(lines.len(), 7);
        picker.handle(Key::Backspace);
        assert!(picker.visible().is_empty());
        picker.handle(Key::Backspace);
        assert_eq!(picker.visible(), [0, 1, 2]);
        assert_eq!(picker.query(), "");
        assert_eq!(picker.handle(Key::Backspace), PickerStep::Continue);
        assert_eq!(picker.visible(), [0, 1, 2]);
    }

    #[test]
    fn the_cursor_stays_on_a_visible_row() {
        let mut picker = environments();
        picker.handle(Key::Up);
        assert_eq!(picker.highlighted(), Some(0));
        for _ in 0..5 {
            picker.handle(Key::Down);
        }
        assert_eq!(picker.highlighted(), Some(2));
        type_text(&mut picker, "r");
        assert_eq!(picker.visible(), [0, 1, 2]);
        assert_eq!(
            picker.highlighted(),
            Some(0),
            "editing moves to the first match"
        );
        type_text(&mut picker, "ev");
        assert_eq!(picker.visible(), [1]);
        picker.handle(Key::Down);
        picker.handle(Key::Up);
        picker.handle(Key::Up);
        assert_eq!(picker.highlighted(), Some(1));
    }

    #[test]
    fn enter_on_a_filtered_row_returns_its_original_index() {
        let mut picker = environments();
        type_text(&mut picker, "stopped");
        picker.handle(Key::Down);
        assert_eq!(picker.handle(Key::Enter), PickerStep::Chosen(2));

        let mut picker = environments();
        type_text(&mut picker, "SCR");
        assert_eq!(picker.handle(Key::Enter), PickerStep::Chosen(2));
    }

    #[test]
    fn a_single_row_still_waits_for_enter() {
        let mut picker = Picker::new(
            "Choose an environment",
            cells(&["NAME"]),
            vec![PickerRow::new(cells(&["app"]), "app")],
        );
        for key in [Key::Up, Key::Down, Key::Other, Key::Char('a')] {
            assert_eq!(picker.handle(key), PickerStep::Continue);
        }
        let lines = picker.render(PLAIN, 80, 10);
        assert_eq!(lines[4], "› app");
        assert_eq!(picker.handle(Key::Enter), PickerStep::Chosen(0));
    }

    #[test]
    fn escape_and_ctrl_c_cancel() {
        for key in [Key::Escape, Key::CtrlC, Key::CtrlD] {
            let mut picker = environments();
            type_text(&mut picker, "app");
            assert_eq!(picker.handle(key), PickerStep::Canceled);
        }
    }

    #[test]
    fn long_lists_show_a_window_around_the_highlight() {
        let rows = (0..30)
            .map(|index| PickerRow::new(vec![format!("env-{index:02}")], format!("env-{index:02}")))
            .collect();
        let mut picker = Picker::new("Choose", cells(&["NAME"]), rows);
        let lines = picker.render(PLAIN, 80, 5);
        assert_eq!(lines.len(), 4 + 5 + 3);
        assert_eq!(lines[4], "› env-00");
        assert_eq!(lines[9], "  1–5 of 30");
        for _ in 0..7 {
            picker.handle(Key::Down);
        }
        let lines = picker.render(PLAIN, 80, 5);
        assert_eq!(lines[4], "  env-03");
        assert_eq!(lines[8], "› env-07");
        assert_eq!(lines[9], "  4–8 of 30");
        let ascii = picker.render(Style::new(false, Charset::Ascii), 80, 5);
        assert_eq!(ascii[8], "> env-07");
        assert_eq!(ascii[9], "  4-8 of 30");
    }

    #[test]
    fn lines_fit_the_terminal_and_colour_marks_the_highlight() {
        let style = Style::new(true, Charset::Unicode);
        let lines = environments().render(style, 24, 10);
        assert_eq!(lines[0], "\x1b[1mChoose an environment\x1b[0m");
        assert_eq!(lines[1], "  Filter: \x1b[2mtype to searc\x1b[0m");
        assert_eq!(lines[4], "\x1b[36m›\x1b[0m app      local     ru");
        for line in environments().render(PLAIN, 24, 10) {
            assert!(line.chars().count() <= 23, "{line:?}");
        }
    }

    #[test]
    fn ascii_rendering_has_no_unicode() {
        for line in environments().render(Style::new(false, Charset::Ascii), 100, 10) {
            assert!(line.is_ascii(), "{line:?}");
        }
        let mut picker = environments().with_no_match("Nothing here.");
        type_text(&mut picker, "zz");
        assert_eq!(picker.render(PLAIN, 100, 10)[4], "  Nothing here.");
    }

    #[test]
    fn server_strings_are_sanitized() {
        let picker = Picker::new(
            "Choose\x1b[2J",
            cells(&["NAME"]),
            vec![PickerRow::new(cells(&["ap\x1b]0;x\x07p"]), "app")],
        );
        for line in picker.render(PLAIN, 100, 10) {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
    }

    fn run_script(reads: Vec<Vec<Key>>) -> (Interaction<usize>, String) {
        let mut out = Vec::new();
        let outcome = {
            let mut screen = Screen::new(&mut out);
            let mut input = Script(reads.into());
            let mut picker = environments();
            let outcome = drive(&mut picker, &mut input, &mut screen, PLAIN, 100, 10).unwrap();
            screen.restore().unwrap();
            outcome
        };
        (outcome, String::from_utf8(out).unwrap())
    }

    #[test]
    fn driving_redraws_in_place_and_erases_itself() {
        let (outcome, out) = run_script(vec![
            vec![Key::Char('s'), Key::Char('t')],
            vec![Key::Down],
            vec![Key::Enter],
        ]);
        assert_eq!(outcome, Interaction::Done(2));
        assert!(out.starts_with("\x1b[?25l\x1b[?7l\r\x1b[JChoose an environment\r\n"));
        // Three frames of nine, eight and eight lines, each drawn over the last.
        assert_eq!(out.matches("Choose an environment").count(), 3);
        assert_eq!(out.matches("\r\x1b[8A\x1b[J").count(), 1);
        assert_eq!(out.matches("\r\x1b[7A\x1b[J").count(), 2);
        assert!(out.ends_with("\r\x1b[7A\x1b[J\x1b[?25h\x1b[?7h"), "{out:?}");
        // Raw mode does not turn a line feed into a new line by itself.
        assert_eq!(out.matches('\n').count(), out.matches("\r\n").count());
    }

    #[test]
    fn closed_input_cancels() {
        let (outcome, out) = run_script(vec![vec![Key::Char('a')]]);
        assert_eq!(outcome, Interaction::Canceled);
        assert!(out.ends_with("\x1b[?25h\x1b[?7h"));
        let (outcome, _) = run_script(vec![vec![Key::Escape]]);
        assert_eq!(outcome, Interaction::Canceled);
        let (outcome, _) = run_script(vec![vec![Key::CtrlC]]);
        assert_eq!(outcome, Interaction::Canceled);
    }

    #[test]
    fn non_interactive_sessions_never_get_a_picker() {
        let facts = TerminalFacts {
            stdin_tty: false,
            stdout_tty: true,
            stderr_tty: true,
            columns: Some(80),
            rows: Some(24),
        };
        let caps = Capabilities::detect(OutputMode::Text, &facts, &MapEnv::default());
        let outcome = run_picker(environments(), &caps).unwrap();
        assert_eq!(outcome, PickerOutcome::Unavailable);
    }
}
