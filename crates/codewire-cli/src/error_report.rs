//! The one shape of a failed command's error (#4609; `codewire-cli-design`,
//! "Errors"): `✗` (red at a colour terminal, `x` in ASCII), the error chain
//! as one line with its first letter capitalised, then, when the error
//! carries one, a `→` line with the next step. Commands return lowercase
//! fragments that compose into the chain and never print `✗` themselves.
//!
//! The skill's target, the outermost message alone with the chain under
//! `-v`, waits until the outer contexts read as user sentences (#4631): many
//! are internal labels such as `list orgs` today.

use std::fmt;

use crate::output::{Capabilities, OutputMode, Status, Style};

/// The one command or flag that helps, carried by an error to the printer.
/// Attach it with [`with_next_step`]; it never appears in the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextStep(String);

impl fmt::Display for NextStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NextStep {}

/// `error`, carrying `step` as its next step.
pub(crate) fn with_next_step(error: anyhow::Error, step: impl Into<String>) -> anyhow::Error {
    error.context(NextStep(step.into()))
}

/// Prints a failed command's error on stderr in the one shape. With
/// `--output json` it prints the chain alone, as before, with no mark.
pub fn report_error(error: &anyhow::Error) {
    if json_requested(std::env::args_os().skip(1)) {
        eprintln!("{error:#}");
        return;
    }
    let caps = Capabilities::from_process(OutputMode::Text);
    eprint!("{}", render(error, caps.stderr_style()));
}

/// The next step `error` carries, wherever it sits in the chain.
pub(crate) fn next_step(error: &anyhow::Error) -> Option<String> {
    error.downcast_ref::<NextStep>().map(|next| next.0.clone())
}

/// `error`'s chain as one sentence, joined by ": ", without its next step.
/// A caller that rebuilds an error from this text attaches the step again
/// with [`with_next_step`].
pub(crate) fn sentence(error: &anyhow::Error) -> String {
    // A context shows in the chain as its own Display, so the step is found
    // through the error (which reaches every context) and its one layer is
    // left out of the sentence.
    let step = next_step(error);
    let mut skipped = false;
    let parts: Vec<String> = error
        .chain()
        .map(ToString::to_string)
        .filter(|part| {
            let is_step = !skipped && step.as_deref() == Some(part.as_str());
            skipped |= is_step;
            !is_step
        })
        .collect();
    parts.join(": ")
}

fn render(error: &anyhow::Error, style: Style) -> String {
    let step = next_step(error);
    let mut text = format!(
        "{} {}\n",
        style.status(Status::Failed),
        capitalised(&sentence(error))
    );
    if let Some(step) = step {
        text.push_str(&format!("{} {step}\n", style.status(Status::Next)));
    }
    text
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Whether the command line asks for JSON output, in any of its spellings.
/// Arguments after `--` are a command's own, not cw's.
pub(crate) fn json_requested(args: impl Iterator<Item = std::ffi::OsString>) -> bool {
    let args: Vec<String> = args
        .map(|arg| arg.to_string_lossy().into_owned())
        .take_while(|arg| arg != "--")
        .collect();
    args.iter().enumerate().any(|(index, arg)| {
        arg == "--json"
            || arg == "--output=json"
            || arg == "-ojson"
            || ((arg == "--output" || arg == "-o")
                && args.get(index + 1).is_some_and(|value| value == "json"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    #[test]
    fn an_error_is_marked_capitalised_and_keeps_its_whole_chain() {
        let error = anyhow::anyhow!("connection refused").context("list orgs");
        assert_eq!(render(&error, PLAIN), "✗ List orgs: connection refused\n");
        assert_eq!(
            render(&error, Style::new(false, Charset::Ascii)),
            "x List orgs: connection refused\n"
        );
        let coloured = render(&error, Style::new(true, Charset::Unicode));
        assert!(coloured.contains("\u{1b}["), "{coloured:?}");
        assert!(coloured.ends_with("List orgs: connection refused\n"));
    }

    #[test]
    fn a_next_step_found_anywhere_in_the_chain_is_its_own_line() {
        let error = with_next_step(anyhow::anyhow!("not signed in"), "cw login")
            .context("cw whoami failed");
        assert_eq!(
            render(&error, PLAIN),
            "✗ Cw whoami failed: not signed in\n→ cw login\n"
        );
        assert_eq!(
            render(&error, Style::new(false, Charset::Ascii)),
            "x Cw whoami failed: not signed in\n-> cw login\n"
        );
    }

    #[test]
    fn json_output_is_recognised_in_every_spelling() {
        let ask = |line: &[&str]| json_requested(line.iter().map(Into::into));
        assert!(ask(&["ls", "--output", "json"]));
        assert!(ask(&["ls", "--output=json"]));
        assert!(ask(&["ls", "-o", "json"]));
        assert!(ask(&["upgrade", "status", "--json"]));
        assert!(!ask(&["ls"]));
        assert!(!ask(&["ls", "--output", "text"]));
        assert!(!ask(&["run", "--", "echo", "json"]));
        assert!(!ask(&["run", "--", "tool", "--output", "json"]));
    }
}
