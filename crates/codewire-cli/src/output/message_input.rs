//! A short multi-line message typed in the terminal, for `cw feedback`:
//! Enter starts a new line, Ctrl-D sends, Escape or Ctrl-C cancels.

use crate::commands::progress::terminal_text;

use super::caps::Capabilities;
use super::interactive::{self, Interaction, Step, Widget, window};
use super::keys::Key;
use super::style::{Line, Role, Style};

struct MessageInput {
    label: String,
    value: String,
    max_bytes: usize,
    error: Option<String>,
}

impl Widget for MessageInput {
    type Output = String;
    /// The label, the hint and an error line.
    const CHROME_LINES: usize = 3;

    fn on_key(&mut self, key: Key) -> Step<String> {
        match key {
            Key::Escape | Key::CtrlC => Step::Canceled,
            Key::CtrlD => {
                if self.value.trim().is_empty() {
                    self.error = Some("Type a message first, or press Esc to cancel".into());
                    Step::Continue
                } else {
                    Step::Done(self.value.trim_end().to_owned())
                }
            }
            Key::Enter => self.push('\n'),
            Key::Backspace => {
                self.value.pop();
                self.error = None;
                Step::Continue
            }
            Key::CtrlU => {
                // Clears the line being typed.
                let start = self.value.rfind('\n').map_or(0, |newline| newline + 1);
                self.value.truncate(start);
                self.error = None;
                Step::Continue
            }
            Key::Char(c) if !c.is_control() => self.push(c),
            _ => Step::Continue,
        }
    }

    fn frame(&self, style: Style, columns: u16, max_rows: usize) -> Vec<String> {
        let lines: Vec<&str> = self.value.split('\n').collect();
        // The end of the message stays in view, where typing happens.
        let (start, end) = window(lines.len() - 1, lines.len(), max_rows);
        let mut frame = vec![Line::new().styled(Role::Strong, self.label.clone())];
        for (index, line) in lines[start..end].iter().enumerate() {
            let prefix = if start + index == 0 { "> " } else { "  " };
            frame.push(Line::new().plain(format!("{prefix}{}", terminal_text(line))));
        }
        if let Some(error) = &self.error {
            frame.push(Line::new().styled(Role::Failure, error.clone()));
        }
        frame.push(Line::new().styled(
            Role::Dim,
            format!(
                "{} of {} bytes · Enter new line · Ctrl-D send · Esc cancel",
                self.value.len(),
                self.max_bytes
            ),
        ));
        frame
            .into_iter()
            .map(|line| {
                line.truncate(usize::from(columns.saturating_sub(1)))
                    .render(style)
            })
            .collect()
    }
}

impl MessageInput {
    fn push(&mut self, c: char) -> Step<String> {
        if self.value.len() + c.len_utf8() > self.max_bytes {
            self.error = Some(format!(
                "The message is at its limit of {} bytes",
                self.max_bytes
            ));
        } else {
            self.value.push(c);
            self.error = None;
        }
        Step::Continue
    }
}

/// Reads a message of at most `max_bytes` from the terminal. `None` when the
/// user cancels or the input closes.
pub(crate) fn run_message_input(
    label: &str,
    max_bytes: usize,
    caps: &Capabilities,
) -> anyhow::Result<Option<String>> {
    let mut input = MessageInput {
        label: terminal_text(label),
        value: String::new(),
        max_bytes,
        error: None,
    };
    match interactive::run(&mut input, caps)? {
        Interaction::Done(value) => Ok(Some(value)),
        Interaction::Canceled => Ok(None),
        Interaction::Unavailable => anyhow::bail!("typing a message needs an interactive terminal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::caps::Charset;

    fn input(max_bytes: usize) -> MessageInput {
        MessageInput {
            label: "Feedback".into(),
            value: String::new(),
            max_bytes,
            error: None,
        }
    }

    fn type_text(input: &mut MessageInput, text: &str) {
        for c in text.chars() {
            let key = if c == '\n' { Key::Enter } else { Key::Char(c) };
            assert_eq!(input.on_key(key), Step::Continue);
        }
    }

    #[test]
    fn enter_adds_a_line_and_ctrl_d_sends_the_message() {
        let mut input = input(100);
        type_text(&mut input, "first line\nsecond line\n");
        assert_eq!(
            input.on_key(Key::CtrlD),
            Step::Done("first line\nsecond line".into())
        );
    }

    #[test]
    fn escape_and_ctrl_c_cancel() {
        for key in [Key::Escape, Key::CtrlC] {
            let mut input = input(100);
            type_text(&mut input, "draft");
            assert_eq!(input.on_key(key), Step::Canceled);
        }
    }

    #[test]
    fn an_empty_message_is_not_sent() {
        let mut input = input(100);
        type_text(&mut input, " \n ");
        assert_eq!(input.on_key(Key::CtrlD), Step::Continue);
        assert!(input.error.is_some());
        type_text(&mut input, "x");
        assert!(input.error.is_none());
    }

    #[test]
    fn backspace_and_ctrl_u_edit_and_the_limit_holds() {
        let mut input = input(6);
        type_text(&mut input, "ab\ncd");
        input.on_key(Key::CtrlU);
        assert_eq!(input.value, "ab\n");
        input.on_key(Key::Backspace);
        assert_eq!(input.value, "ab");
        // Three bytes left: "é" (2) fits, then "é" again does not.
        type_text(&mut input, "xé");
        assert_eq!(input.value, "abxé");
        input.on_key(Key::Char('é'));
        assert_eq!(input.value, "abxé");
        assert!(input.error.as_deref().unwrap().contains("limit of 6 bytes"));
    }

    #[test]
    fn the_frame_keeps_the_last_lines_in_view_and_names_the_keys() {
        let mut input = input(1000);
        type_text(&mut input, "1\n2\n3\n4\n5");
        let frame = input.frame(Style::new(false, Charset::Unicode), 80, 2);
        assert!(frame[0].contains("Feedback"));
        assert!(frame[1].ends_with('4') && frame[2].ends_with('5'));
        assert!(frame.last().unwrap().contains("Ctrl-D send · Esc cancel"));
    }
}
