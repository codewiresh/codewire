//! Validated, non-secret metadata entry using the same terminal runner as menus.

use crate::commands::progress::terminal_text;

use super::caps::Capabilities;
use super::interactive::{self, Interaction, Step, Widget};
use super::keys::Key;
use super::style::{Line, Role, Style};

struct TextInput<F> {
    label: String,
    default: Option<String>,
    value: String,
    error: Option<String>,
    validate: F,
}

impl<F: Fn(&str) -> Result<(), String>> Widget for TextInput<F> {
    type Output = String;
    const CHROME_LINES: usize = 4;

    fn on_key(&mut self, key: Key) -> Step<String> {
        match key {
            Key::Escape | Key::CtrlC => Step::Canceled,
            Key::Enter => {
                let value = if self.value.trim().is_empty() {
                    self.default.as_deref().unwrap_or_default()
                } else {
                    self.value.trim()
                };
                match (self.validate)(value) {
                    Ok(()) => Step::Done(value.to_owned()),
                    Err(error) => {
                        self.error = Some(terminal_text(&error));
                        Step::Continue
                    }
                }
            }
            Key::Backspace => {
                self.value.pop();
                self.error = None;
                Step::Continue
            }
            Key::CtrlU => {
                self.value.clear();
                self.error = None;
                Step::Continue
            }
            Key::Char(c) if !c.is_control() && self.value.len() < 4096 => {
                self.value.push(c);
                self.error = None;
                Step::Continue
            }
            _ => Step::Continue,
        }
    }

    fn frame(&self, style: Style, columns: u16, _max_rows: usize) -> Vec<String> {
        let mut label = self.label.clone();
        if let Some(default) = &self.default {
            label.push_str(&format!(" [{default}]"));
        }
        let mut lines = vec![
            Line::new().styled(Role::Strong, label),
            Line::new().plain(format!("> {}", self.value)),
        ];
        if let Some(error) = &self.error {
            lines.push(Line::new().styled(Role::Failure, error));
        }
        lines.push(Line::new().styled(Role::Dim, "Enter continue · Ctrl-U clear · Esc cancel"));
        lines
            .into_iter()
            .map(|line| {
                line.truncate(usize::from(columns.saturating_sub(1)))
                    .render(style)
            })
            .collect()
    }
}

pub(crate) fn run_text_input(
    label: &str,
    default: Option<&str>,
    validate: impl Fn(&str) -> Result<(), String>,
    caps: &Capabilities,
) -> anyhow::Result<Option<String>> {
    let mut input = TextInput {
        label: terminal_text(label),
        default: default.map(terminal_text),
        value: String::new(),
        error: None,
        validate,
    };
    match interactive::run(&mut input, caps)? {
        Interaction::Done(value) => Ok(Some(value)),
        Interaction::Canceled => Ok(None),
        Interaction::Unavailable => anyhow::bail!("text input needs an interactive terminal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(value: &str) -> Result<(), String> {
        if value.is_empty() {
            Err("Enter a name".into())
        } else {
            Ok(())
        }
    }

    #[test]
    fn invalid_input_can_be_corrected_and_default_is_explicit() {
        let mut input = TextInput {
            label: "Name".into(),
            default: None,
            value: String::new(),
            error: None,
            validate: required,
        };
        assert_eq!(input.on_key(Key::Enter), Step::Continue);
        assert_eq!(input.error.as_deref(), Some("Enter a name"));
        assert_eq!(input.on_key(Key::Char('x')), Step::Continue);
        assert_eq!(input.on_key(Key::Enter), Step::Done("x".into()));
        input.value.clear();
        input.default = Some("work".into());
        assert_eq!(input.on_key(Key::Enter), Step::Done("work".into()));
        assert_eq!(input.on_key(Key::Escape), Step::Canceled);
        assert_eq!(input.on_key(Key::CtrlC), Step::Canceled);
    }
}
