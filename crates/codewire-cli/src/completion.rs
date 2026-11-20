//! Tab completion of commands, flags and names (#5108). The spec is
//! `docs/journeys/cli-completion.md`; the rules are the `codewire-cli-design`
//! skill's "Completion".
//!
//! This is the one module that uses `clap_complete`'s dynamic engine. Upstream
//! calls that interface unstable, so the workspace manifest pins its version
//! exactly and a breaking change touches this file only.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use clap::{Arg, Command};
use clap_complete::env::{Bash, EnvCompleter, Fish, Powershell, Zsh};
use clap_complete::{ArgValueCompleter, CompleteEnv};

use crate::build_record::CLI_VERSION;
use crate::commands::{CompletionShell, DoctorCheck, DoctorStatus, doctor_check};

/// Not clap's default `COMPLETE`, which a user's environment may already set,
/// turning every `cw` run into a completion request.
pub(crate) const COMPLETE_VAR: &str = "CW_COMPLETE";

/// Answers a completion request and exits, or returns at once when the process
/// is not one. It runs before anything else in `main`: no runtime, no update
/// check, no telemetry, and nothing is read until a completer asks.
pub fn answer_if_requested() {
    // A private role cw starts itself is never a completion request, even when
    // its environment inherited the variable.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|word| is_private_role(&word))
    {
        return;
    }
    if std::env::var_os(COMPLETE_VAR).is_some_and(|value| !value.is_empty() && value != "0") {
        end_the_answer_after(ANSWER_BOUND);
    }
    CompleteEnv::with_factory(command_with_completers)
        .var(COMPLETE_VAR)
        .complete();
}

/// The whole answer's bound. A completer that has not returned by then (a
/// stalled filesystem, a hung server) ends the process with nothing offered:
/// the shell sees no suggestions, never a wait.
const ANSWER_BOUND: Duration = Duration::from_secs(1);

fn is_private_role(first_argument: &std::ffi::OsStr) -> bool {
    first_argument.to_string_lossy().starts_with("__")
}

fn end_the_answer_after(bound: Duration) {
    // A thread that cannot start leaves the answer unbounded, which is no
    // worse than before it existed; there is nowhere to report it.
    let _ = std::thread::Builder::new()
        .name("completion-bound".to_owned())
        .spawn(move || {
            std::thread::sleep(bound);
            std::process::exit(0);
        });
}

/// The command tree as the parser builds it, plus a completer on every
/// argument that takes a name. Only a completion request builds this, so an
/// ordinary run pays nothing for it.
pub(crate) fn command_with_completers() -> Command {
    with_completers(crate::cli_command())
}

fn with_completers(command: Command) -> Command {
    command
        .mut_args(|argument| match completer_for(&argument) {
            Some(completer) => argument.add(completer),
            None => argument,
        })
        .mut_subcommands(with_completers)
}

/// The names an argument takes, by the value name or argument ID its help
/// already gives it (`ENV` in every command).
fn completer_for(argument: &Arg) -> Option<ArgValueCompleter> {
    let value_names = argument.get_value_names().unwrap_or_default();
    let named = |wanted: &str| value_names.iter().any(|name| name.as_str() == wanted);
    if named("ENV") || matches!(argument.get_id().as_str(), "environment" | "in_environment") {
        return Some(ArgValueCompleter::new(environments));
    }
    None
}

/// The text of the file `cw completion --install` writes. Its header line names
/// the `cw` that wrote it, because the shell glue and the binary must come
/// from the same `clap_complete`; `cw doctor` reads it back ([`written_by`]).
pub(crate) fn registration_script(shell: CompletionShell) -> std::io::Result<Vec<u8>> {
    let engine: &dyn EnvCompleter = match shell {
        CompletionShell::Bash => &Bash,
        CompletionShell::Zsh => &Zsh,
        CompletionShell::Fish => &Fish,
        CompletionShell::Powershell => &Powershell,
    };
    let mut glue = Vec::new();
    // `cw` is found on PATH when the shell completes, so a moved or upgraded
    // binary keeps its script.
    engine.write_registration(COMPLETE_VAR, "cw", "cw", "cw", &mut glue)?;
    let header = format!("{HEADER_PREFIX}{CLI_VERSION}\n").into_bytes();
    // zsh autoloads a completion file only when `#compdef` is its first line.
    let at = if glue.starts_with(b"#compdef") {
        glue.iter()
            .position(|byte| *byte == b'\n')
            .map_or(glue.len(), |end| end + 1)
    } else {
        0
    };
    glue.splice(at..at, header);
    Ok(glue)
}

const HEADER_PREFIX: &str = "# cw completion written by cw ";

/// The `cw` version that wrote an installed completion file, `None` for a file
/// it did not write, such as the static script older versions installed. The
/// header is the file's first line, or its second under zsh's `#compdef`.
pub(crate) fn written_by(file: &str) -> Option<&str> {
    file.lines()
        .take(2)
        .find_map(|line| line.strip_prefix(HEADER_PREFIX))
}

/// Older cw versions installed a static script that completes commands and
/// flags only, and the shell glue must come from the same cw as the binary.
pub(crate) fn file_check(shell: CompletionShell, path: &Path, installed: &str) -> DoctorCheck {
    let reinstall = "run `cw completion --install`";
    match written_by(installed) {
        None => doctor_check(
            "completion",
            DoctorStatus::Warn,
            format!(
                "{} at {} completes commands and flags only; {reinstall} for names",
                shell.name(),
                path.display()
            ),
        ),
        Some(version) if version != CLI_VERSION => doctor_check(
            "completion",
            DoctorStatus::Warn,
            format!(
                "{} at {} was written by cw {version}, this is cw {CLI_VERSION}; {reinstall}",
                shell.name(),
                path.display()
            ),
        ),
        Some(_) => doctor_check(
            "completion",
            DoctorStatus::Ok,
            format!("{} at {}", shell.name(), path.display()),
        ),
    }
}

/// The words on the command line before the one being completed, as the shell
/// passed them after `--`. A completer reads them to follow `--local`,
/// `--cloud`, `--in ENV` and the environment already named.
pub(crate) fn words_before_cursor() -> Vec<String> {
    words_before_cursor_of(
        std::env::args_os(),
        std::env::var("_CLAP_COMPLETE_INDEX").ok().as_deref(),
    )
}

fn words_before_cursor_of(
    args: impl IntoIterator<Item = OsString>,
    index: Option<&str>,
) -> Vec<String> {
    let words: Vec<String> = args
        .into_iter()
        .skip_while(|argument| argument != "--")
        .skip(1)
        .map(|word| word.to_string_lossy().into_owned())
        .collect();
    // Bash and zsh pass the cursor's index. fish does not: its glue puts the
    // word being completed last. The first word is the program, and the index
    // counts it.
    let index = index
        .and_then(|index| index.parse::<usize>().ok())
        .unwrap_or_else(|| words.len().saturating_sub(1));
    words.into_iter().take(index).skip(1).collect()
}

mod cache;
pub(crate) use cache::remove as forget_cached_names;
mod cloud;
mod environments;
pub(crate) use environments::environments;

#[cfg(test)]
mod tests;
