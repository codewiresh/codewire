//! The one shape of a failed command's error (#4609; `codewire-cli-design`,
//! "Errors"): `✗` (red at a colour terminal, `x` in ASCII), the error chain
//! as one line with its first letter capitalised, then, when the error
//! carries one, a `→` line with the next step, and, when a server's answer
//! named its trace, a dim `trace ID` line (#5633). Commands return lowercase
//! fragments that compose into the chain and never print `✗` themselves.
//!
//! The skill's target, the outermost message alone with the chain under
//! `-v`, waits until the outer contexts read as user sentences (#4631): many
//! are internal labels such as `list orgs` today.

use std::fmt;

use crate::output::{Capabilities, OutputMode, Role, Status, Style};

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

/// A credential the platform refused (#5559): the API key in
/// `CODEWIRE_API_KEY` when one is set, since it takes precedence, otherwise
/// the saved sign-in. Its sentence stands alone; the internal steps around it
/// (`list orgs`) name nothing the user can act on.
#[derive(Debug)]
pub(crate) struct CredentialRefused {
    api_key: bool,
}

impl fmt::Display for CredentialRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.api_key {
            "the API key in CODEWIRE_API_KEY is no longer accepted"
        } else {
            "not signed in: your saved sign-in is no longer accepted"
        })
    }
}

impl std::error::Error for CredentialRefused {}

impl CredentialRefused {
    /// Carried here rather than as a [`NextStep`] context, so every display
    /// of the error starts with its sentence.
    fn step(&self) -> &'static str {
        if self.api_key {
            "set CODEWIRE_API_KEY to a current key, or unset it and run cw login"
        } else {
            "cw login"
        }
    }
}

/// A refused credential's sentence and next step, for a caller that shows
/// a failure in its own shape.
pub(crate) fn refused_recovery(error: &anyhow::Error) -> Option<(String, String)> {
    let refused = error.downcast_ref::<CredentialRefused>()?;
    Some((refused.to_string(), refused.step().to_owned()))
}

/// The error for a request the platform answered `unauthenticated`.
pub(crate) fn credential_refused() -> anyhow::Error {
    let api_key =
        std::env::var(crate::config::CODEWIRE_API_KEY_ENV).is_ok_and(|key| !key.trim().is_empty());
    refused(api_key)
}

fn refused(api_key: bool) -> anyhow::Error {
    anyhow::Error::new(CredentialRefused { api_key })
}

#[cfg(test)]
pub(crate) fn refused_for_tests(api_key: bool) -> anyhow::Error {
    refused(api_key)
}

/// Prints a failed command's error on stderr in the one shape. With
/// `--output json` it prints the chain alone, as before, with no mark.
pub fn report_error(error: &anyhow::Error) {
    if json_requested(std::env::args_os().skip(1)) {
        eprintln!("{error:#}");
        if let Some(id) = trace_id(error) {
            eprintln!("trace {id}");
        }
        return;
    }
    let caps = Capabilities::from_process(OutputMode::Text);
    eprint!("{}", render(error, caps.stderr_style()));
}

/// The next step `error` carries, wherever it sits in the chain.
pub(crate) fn next_step(error: &anyhow::Error) -> Option<String> {
    error
        .downcast_ref::<NextStep>()
        .map(|next| next.0.clone())
        .or_else(|| {
            error
                .downcast_ref::<CredentialRefused>()
                .map(|refused| refused.step().to_owned())
        })
        .or_else(|| error.chain().find_map(signed_out_step).map(str::to_owned))
}

/// `cw login` for a signed-out user, who has no server or no sign-in: one
/// signed-out state everywhere (docs/dev/CLI-PARITY.md, H2). Inside a
/// sandbox the sentence itself says what works there.
fn signed_out_step(cause: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    use crate::config::ConfigError;
    match cause.downcast_ref::<ConfigError>()? {
        ConfigError::NoPlatformServer { .. }
        | ConfigError::NoPlatformToken { sandbox: None, .. } => Some("cw login"),
        _ => None,
    }
}

/// The id of the trace the server's answer named, when `error` came from
/// that answer (docs/CONFIGURATION.md, "Tracing"). The refusals the CLI
/// replaces with its own sentence (a refused sign-in, exhausted credit, an
/// environment that isn't running) keep none: their error says what to do.
pub(crate) fn trace_id(error: &anyhow::Error) -> Option<&str> {
    error.chain().find_map(|cause| {
        if let Some(reworded) = cause.downcast_ref::<crate::reworded::Reworded>() {
            return reworded.trace_id();
        }
        cause
            .downcast_ref::<codewire_client::ClientError>()
            .and_then(codewire_client::ClientError::trace_id)
    })
}

/// `error`'s chain as one sentence, joined by ": ", without its next step.
/// A caller that rebuilds an error from this text attaches the step again
/// with [`with_next_step`].
pub(crate) fn sentence(error: &anyhow::Error) -> String {
    if let Some(refused) = error.downcast_ref::<CredentialRefused>() {
        return refused.to_string();
    }
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

pub(crate) fn render(error: &anyhow::Error, style: Style) -> String {
    let step = next_step(error);
    let mut text = format!(
        "{} {}\n",
        style.status(Status::Failed),
        capitalised(&sentence(error))
    );
    if let Some(step) = step {
        text.push_str(&format!("{} {step}\n", style.status(Status::Next)));
    }
    if let Some(id) = trace_id(error) {
        text.push_str(&style.paint(Role::Dim, &format!("trace {id}")));
        text.push('\n');
    }
    text
}

/// The sentence with its first letter capitalised, unless its first word
/// names a host or a file (`api.example.com is …`), which keeps its case.
fn capitalised(text: &str) -> String {
    if text
        .split_whitespace()
        .next()
        .is_some_and(|word| word.contains('.'))
    {
        return text.to_owned();
    }
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
    fn a_refused_credential_names_which_and_none_of_the_steps_around_it() {
        let sign_in = refused(false).context("list orgs");
        assert_eq!(
            render(&sign_in, PLAIN),
            "✗ Not signed in: your saved sign-in is no longer accepted\n→ cw login\n"
        );
        let api_key = refused(true).context("list orgs");
        assert_eq!(
            render(&api_key, PLAIN),
            "✗ The API key in CODEWIRE_API_KEY is no longer accepted\n\
             → set CODEWIRE_API_KEY to a current key, or unset it and run cw login\n"
        );
    }

    #[test]
    fn a_server_answer_that_names_its_trace_ends_with_its_id() {
        let answered = |trace: Option<&str>| {
            let mut headers = http::HeaderMap::new();
            if let Some(trace) = trace {
                headers.insert("x-codewire-trace-id", trace.parse().unwrap());
            }
            let error =
                connectrpc::ConnectError::not_found("environment not found").with_headers(headers);
            anyhow::Error::from(codewire_client::ClientError::from(error)).context("get walk")
        };
        assert_eq!(
            render(&answered(Some("4bf92f3577b34da6a3ce929d0e0e4736")), PLAIN),
            "✗ Get walk: environment not found\ntrace 4bf92f3577b34da6a3ce929d0e0e4736\n"
        );
        let stepped = with_next_step(answered(Some("4bf92f3577b34da6a3ce929d0e0e4736")), "cw ls");
        assert_eq!(
            render(&stepped, PLAIN),
            "✗ Get walk: environment not found\n→ cw ls\ntrace 4bf92f3577b34da6a3ce929d0e0e4736\n"
        );
        let dim = render(
            &answered(Some("4bf92f3577b34da6a3ce929d0e0e4736")),
            Style::new(true, Charset::Unicode),
        );
        assert!(dim.contains("\u{1b}["), "{dim:?}");
        assert_eq!(
            render(&answered(None), PLAIN),
            "✗ Get walk: environment not found\n"
        );
        assert_eq!(
            render(&anyhow::anyhow!("connection refused"), PLAIN),
            "✗ Connection refused\n"
        );
    }

    #[test]
    fn a_sentence_that_starts_with_a_host_keeps_its_case() {
        assert_eq!(
            render(
                &anyhow::anyhow!("api.anthropic.com is a provider host Codewire connects for you"),
                PLAIN
            ),
            "✗ api.anthropic.com is a provider host Codewire connects for you\n"
        );
        assert_eq!(
            render(&anyhow::anyhow!("no preset named strpe"), PLAIN),
            "✗ No preset named strpe\n"
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
