//! Shared metadata prompts. Protected values keep their own no-echo reader.

use crate::output::{
    Capabilities, OutputMode, Picker, PickerOutcome, PickerRow, run_picker, run_text_input,
};

use super::OutputFormat;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Choice {
    label: String,
    detail: String,
}

impl Choice {
    pub(crate) fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
        }
    }
}

pub(crate) fn available(output: OutputFormat) -> bool {
    let caps = Capabilities::from_process(if matches!(output, OutputFormat::Json) {
        OutputMode::Machine
    } else {
        OutputMode::Text
    });
    cfg!(unix) && caps.interactive && caps.live
}

pub(crate) fn require_available(output: OutputFormat, repair: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        available(output),
        "missing required input; {repair} (noninteractive and JSON commands never prompt)"
    );
    Ok(())
}

pub(crate) fn choose(title: &str, choices: &[Choice]) -> anyhow::Result<usize> {
    choose_inner(title, choices, true)
}

fn choose_inner(title: &str, choices: &[Choice], echo: bool) -> anyhow::Result<usize> {
    require_available(OutputFormat::Text, "supply an explicit choice")?;
    anyhow::ensure!(!choices.is_empty(), "no choices are available for {title}");
    let rows = choices
        .iter()
        .map(|choice| {
            PickerRow::new(
                vec![choice.label.clone(), choice.detail.clone()],
                format!("{} {}", choice.label, choice.detail),
            )
        })
        .collect();
    let picker = Picker::new(title, Vec::new(), rows)
        .with_no_match("No matching choices. Backspace to clear the filter.");
    match run_picker(picker, &Capabilities::from_process(OutputMode::Text))? {
        PickerOutcome::Chosen(index) => {
            if echo {
                let choice = &choices[index];
                completed(&choice.label, &choice.detail);
            }
            Ok(index)
        }
        PickerOutcome::Canceled => anyhow::bail!("canceled; nothing selected"),
        PickerOutcome::Unavailable => anyhow::bail!("selection needs an interactive terminal"),
    }
}

pub(crate) fn text(
    label: &str,
    default: Option<&str>,
    validate: impl Fn(&str) -> Result<(), String>,
) -> anyhow::Result<String> {
    require_available(OutputFormat::Text, "supply an explicit value")?;
    let value = run_text_input(
        label,
        default,
        validate,
        &Capabilities::from_process(OutputMode::Text),
    )?
    .ok_or_else(|| anyhow::anyhow!("canceled; no value entered"))?;
    completed(label, &value);
    Ok(value)
}

pub(crate) fn confirm(title: &str) -> anyhow::Result<bool> {
    Ok(choose_inner(
        title,
        &[Choice::new("Continue", ""), Choice::new("Cancel", "")],
        false,
    )? == 0)
}

pub(crate) fn required(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err("Enter a value".into())
    } else {
        Ok(())
    }
}

fn completed(label: &str, value: &str) {
    use super::progress::terminal_text;
    use crate::output::{Role, Status};
    let style = Capabilities::from_process(OutputMode::Text).stderr_style();
    let detail = if value.is_empty() {
        String::new()
    } else {
        format!("  {}", terminal_text(value))
    };
    eprintln!(
        "{} {}{}",
        style.status(Status::Done),
        terminal_text(label),
        style.paint(Role::Dim, &detail)
    );
}
