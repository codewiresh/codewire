//! A multi-select checklist on an interactive terminal, such as the steps
//! `cw upgrade` offers.
//!
//! [`Checklist`] is a pure state machine like the picker; [`run_checklist`]
//! drives it through the same runner, key decoder and terminal restoration.

use crate::commands::progress::terminal_text;

use super::caps::{Capabilities, Charset};
use super::interactive::{self, Interaction, Step, Widget, range_line, window};
use super::keys::Key;
use super::style::{Line, Role, Status, Style};

/// One choice with a label, an optional quiet detail and whether it starts
/// checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChecklistItem {
    label: String,
    detail: Option<String>,
    checked: bool,
}

impl ChecklistItem {
    pub(crate) fn new(label: impl Into<String>, checked: bool) -> Self {
        Self {
            label: terminal_text(&label.into()),
            detail: None,
            checked,
        }
    }

    /// Secondary text shown quietly after the label.
    pub(crate) fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let detail = terminal_text(&detail.into());
        self.detail = (!detail.is_empty()).then_some(detail);
        self
    }
}

/// What one key did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChecklistStep {
    Continue,
    /// Enter: the checked items' indices, in order. May be empty.
    Applied(Vec<usize>),
    Canceled,
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChecklistOutcome {
    /// The checked items' indices, in order. May be empty.
    Applied(Vec<usize>),
    /// Escape, Ctrl-C or closed input. Nothing was applied.
    Canceled,
    /// No interactive terminal (or no unix terminal support). Nothing was
    /// drawn; the caller asks for explicit flags instead.
    Unavailable,
}

#[derive(Clone, Debug)]
pub(crate) struct Checklist {
    title: String,
    items: Vec<ChecklistItem>,
    cursor: usize,
}

impl Checklist {
    pub(crate) fn new(title: impl Into<String>, items: Vec<ChecklistItem>) -> Self {
        Self {
            title: terminal_text(&title.into()),
            items,
            cursor: 0,
        }
    }

    /// Applies one key. Arrows move, Space toggles the highlighted item,
    /// Enter applies the checked items, and Escape or Ctrl-C cancel. Other
    /// keys do nothing.
    pub(crate) fn handle(&mut self, key: Key) -> ChecklistStep {
        match key {
            Key::Up => self.cursor = self.cursor.saturating_sub(1),
            Key::Down => {
                if self.cursor + 1 < self.items.len() {
                    self.cursor += 1;
                }
            }
            Key::Char(' ') => {
                if let Some(item) = self.items.get_mut(self.cursor) {
                    item.checked = !item.checked;
                }
            }
            Key::Enter => return ChecklistStep::Applied(self.checked()),
            Key::Escape | Key::CtrlC | Key::CtrlD => return ChecklistStep::Canceled,
            Key::Backspace | Key::CtrlU | Key::Char(_) | Key::Other => {}
        }
        ChecklistStep::Continue
    }

    /// Indices of the checked items, in order.
    pub(crate) fn checked(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.checked)
            .map(|(index, _)| index)
            .collect()
    }

    /// The index of the highlighted item.
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    /// The checklist as lines without line endings, each cut to
    /// `columns - 1` characters, showing at most `max_rows` items around the
    /// highlight.
    pub(crate) fn render(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String> {
        let width = usize::from(columns).saturating_sub(1).max(1);
        let mut lines = vec![
            Line::new().styled(Role::Strong, self.title.clone()),
            Line::new(),
        ];
        let (start, end) = window(self.cursor, self.items.len(), max_rows);
        for (position, item) in self.items.iter().enumerate().take(end).skip(start) {
            let mut line = if position == self.cursor {
                Line::new().status(style, Status::Selected)
            } else {
                Line::new().plain(" ")
            };
            line = if item.checked {
                line.plain(" [").styled(Role::Active, "x").plain("] ")
            } else {
                line.plain(" [ ] ")
            };
            line = line.plain(item.label.clone());
            if let Some(detail) = &item.detail {
                line = line.styled(Role::Dim, format!(" ({detail})"));
            }
            lines.push(line);
        }
        if end - start < self.items.len() {
            lines.push(range_line(style, start, end, self.items.len()));
        }
        lines.push(Line::new());
        let help = match style.charset() {
            Charset::Unicode => "  ↑/↓ move · Space toggle · Enter apply · Esc cancel",
            Charset::Ascii => "  Up/Down move - Space toggle - Enter apply - Esc cancel",
        };
        lines.push(Line::new().styled(Role::Dim, help));
        lines
            .into_iter()
            .map(|line| line.truncate(width).render(style))
            .collect()
    }
}

impl Widget for Checklist {
    type Output = Vec<usize>;
    /// Title, blank, a range line, blank and the key help.
    const CHROME_LINES: usize = 5;

    fn on_key(&mut self, key: Key) -> Step<Vec<usize>> {
        match self.handle(key) {
            ChecklistStep::Continue => Step::Continue,
            ChecklistStep::Applied(checked) => Step::Done(checked),
            ChecklistStep::Canceled => Step::Canceled,
        }
    }

    fn frame(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String> {
        self.render(style, columns, max_rows)
    }
}

/// Runs the checklist on the process's terminal: raw input from stdin and
/// drawing on stderr. Returns [`ChecklistOutcome::Unavailable`] without
/// touching the terminal unless the session is interactive and can redraw.
/// The terminal mode is restored and the checklist's lines are erased on
/// every exit path, including errors and panics.
///
/// This blocks on terminal input; async callers run it on a blocking
/// thread.
pub(crate) fn run_checklist(
    mut checklist: Checklist,
    caps: &Capabilities,
) -> anyhow::Result<ChecklistOutcome> {
    Ok(match interactive::run(&mut checklist, caps)? {
        Interaction::Done(checked) => ChecklistOutcome::Applied(checked),
        Interaction::Canceled => ChecklistOutcome::Canceled,
        Interaction::Unavailable => ChecklistOutcome::Unavailable,
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

    fn upgrade() -> Checklist {
        Checklist::new(
            "Upgrade Codewire",
            vec![
                ChecklistItem::new("Codewire CLI v0.3.391 → v0.4.0", true),
                ChecklistItem::new("Restart 2 local VMs onto v0.4.0", false)
                    .with_detail("ends the work running in them"),
            ],
        )
    }

    #[test]
    fn renders_boxes_details_and_key_help() {
        assert_eq!(
            upgrade().render(PLAIN, 100, 10),
            [
                "Upgrade Codewire",
                "",
                "› [x] Codewire CLI v0.3.391 → v0.4.0",
                "  [ ] Restart 2 local VMs onto v0.4.0 (ends the work running in them)",
                "",
                "  ↑/↓ move · Space toggle · Enter apply · Esc cancel",
            ]
        );
    }

    #[test]
    fn colour_marks_the_highlight_checks_and_quiet_detail() {
        let lines = upgrade().render(Style::new(true, Charset::Unicode), 100, 10);
        assert_eq!(lines[0], "\x1b[1mUpgrade Codewire\x1b[0m");
        assert_eq!(
            lines[2],
            "\x1b[36m›\x1b[0m [\x1b[36mx\x1b[0m] Codewire CLI v0.3.391 → v0.4.0"
        );
        assert_eq!(
            lines[3],
            "  [ ] Restart 2 local VMs onto v0.4.0\x1b[2m (ends the work running in them)\x1b[0m"
        );
    }

    #[test]
    fn ascii_rendering_keeps_the_boxes() {
        let lines = upgrade().render(Style::new(false, Charset::Ascii), 100, 10);
        assert_eq!(lines[2], "> [x] Codewire CLI v0.3.391 → v0.4.0");
        assert_eq!(
            lines[5],
            "  Up/Down move - Space toggle - Enter apply - Esc cancel"
        );
        for (index, line) in lines.iter().enumerate().filter(|(index, _)| *index != 2) {
            assert!(line.is_ascii(), "{index}: {line:?}");
        }
    }

    #[test]
    fn space_toggles_the_highlighted_item() {
        let mut checklist = upgrade();
        assert_eq!(checklist.checked(), [0]);
        assert_eq!(checklist.handle(Key::Char(' ')), ChecklistStep::Continue);
        assert_eq!(checklist.checked(), Vec::<usize>::new());
        checklist.handle(Key::Down);
        checklist.handle(Key::Char(' '));
        assert_eq!(checklist.checked(), [1]);
        checklist.handle(Key::Up);
        checklist.handle(Key::Char(' '));
        assert_eq!(checklist.checked(), [0, 1]);
        assert_eq!(
            checklist.render(PLAIN, 100, 10)[3],
            "  [x] Restart 2 local VMs onto v0.4.0 (ends the work running in them)"
        );
    }

    #[test]
    fn the_cursor_stays_on_an_item() {
        let mut checklist = upgrade();
        checklist.handle(Key::Up);
        assert_eq!(checklist.cursor(), 0);
        for _ in 0..5 {
            checklist.handle(Key::Down);
        }
        assert_eq!(checklist.cursor(), 1);
    }

    #[test]
    fn other_keys_change_nothing() {
        let mut checklist = upgrade();
        for key in [Key::Char('x'), Key::Backspace, Key::CtrlU, Key::Other] {
            assert_eq!(checklist.handle(key), ChecklistStep::Continue);
        }
        assert_eq!(checklist.checked(), [0]);
        assert_eq!(checklist.cursor(), 0);
    }

    #[test]
    fn enter_applies_the_checked_indices() {
        let mut checklist = upgrade();
        checklist.handle(Key::Down);
        checklist.handle(Key::Char(' '));
        assert_eq!(
            checklist.handle(Key::Enter),
            ChecklistStep::Applied(vec![0, 1])
        );

        let mut checklist = upgrade();
        checklist.handle(Key::Char(' '));
        assert_eq!(checklist.handle(Key::Enter), ChecklistStep::Applied(vec![]));
    }

    #[test]
    fn escape_and_ctrl_c_cancel() {
        for key in [Key::Escape, Key::CtrlC, Key::CtrlD] {
            let mut checklist = upgrade();
            checklist.handle(Key::Char(' '));
            assert_eq!(checklist.handle(key), ChecklistStep::Canceled);
        }
    }

    #[test]
    fn an_empty_checklist_applies_nothing() {
        let mut checklist = Checklist::new("Nothing to do", Vec::new());
        assert_eq!(checklist.handle(Key::Down), ChecklistStep::Continue);
        assert_eq!(checklist.handle(Key::Char(' ')), ChecklistStep::Continue);
        assert_eq!(checklist.handle(Key::Enter), ChecklistStep::Applied(vec![]));
    }

    #[test]
    fn long_checklists_show_a_window_around_the_highlight() {
        let items = (0..12)
            .map(|index| ChecklistItem::new(format!("step {index}"), false))
            .collect();
        let mut checklist = Checklist::new("Steps", items);
        for _ in 0..6 {
            checklist.handle(Key::Down);
        }
        let lines = checklist.render(PLAIN, 80, 4);
        assert_eq!(lines.len(), 2 + 4 + 3);
        assert_eq!(lines[2], "  [ ] step 3");
        assert_eq!(lines[5], "› [ ] step 6");
        assert_eq!(lines[6], "  4–7 of 12");
    }

    #[test]
    fn lines_fit_the_terminal_and_strings_are_sanitized() {
        let checklist = Checklist::new(
            "Upgrade\x1b[2J",
            vec![ChecklistItem::new("CLI\x1b]0;x\x07", true).with_detail("\x07\x1b")],
        );
        let lines = checklist.render(PLAIN, 12, 10);
        for line in &lines {
            assert!(!line.chars().any(char::is_control), "{line:?}");
            assert!(line.chars().count() <= 11, "{line:?}");
        }
        assert_eq!(lines[2], "› [x] CLI ]");
    }

    #[test]
    fn driving_toggles_applies_and_erases_itself() {
        let mut out = Vec::new();
        let outcome = {
            let mut screen = Screen::new(&mut out);
            let mut input =
                Script(vec![vec![Key::Down], vec![Key::Char(' ')], vec![Key::Enter]].into());
            let outcome = drive(&mut upgrade(), &mut input, &mut screen, PLAIN, 100, 10).unwrap();
            screen.restore().unwrap();
            outcome
        };
        assert_eq!(outcome, Interaction::Done(vec![0, 1]));
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("Upgrade Codewire").count(), 3);
        assert!(out.ends_with("\r\x1b[5A\x1b[J\x1b[?25h\x1b[?7h"), "{out:?}");
    }

    #[test]
    fn non_interactive_sessions_never_get_a_checklist() {
        let facts = TerminalFacts {
            stdin_tty: true,
            stdout_tty: true,
            stderr_tty: false,
            columns: Some(80),
            rows: Some(24),
        };
        let caps = Capabilities::detect(OutputMode::Text, &facts, &MapEnv::default());
        assert_eq!(
            run_checklist(upgrade(), &caps).unwrap(),
            ChecklistOutcome::Unavailable
        );
    }
}
