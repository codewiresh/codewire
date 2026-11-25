use std::ffi::OsString;

use clap::{Arg, Command};
use clap_complete::ArgValueCompleter;

use super::*;
use crate::commands::DoctorStatus;

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn the_registration_script_names_the_cw_that_wrote_it_and_the_cw_variable() {
    for shell in [
        CompletionShell::Bash,
        CompletionShell::Zsh,
        CompletionShell::Fish,
    ] {
        let script = String::from_utf8(registration_script(shell).unwrap()).unwrap();
        assert_eq!(written_by(&script), Some(CLI_VERSION), "{}", shell.name());
        assert!(script.contains(COMPLETE_VAR), "{}", shell.name());
        assert!(
            !script.contains("COMPLETE=") || script.contains("CW_COMPLETE"),
            "{}: only the cw variable may trigger completion",
            shell.name()
        );
    }
}

#[test]
fn zsh_keeps_compdef_as_its_first_line() {
    let script = String::from_utf8(registration_script(CompletionShell::Zsh).unwrap()).unwrap();
    assert!(script.starts_with("#compdef cw\n"), "{script}");
    assert_eq!(written_by(&script), Some(CLI_VERSION));
}

#[test]
fn a_file_cw_did_not_write_names_no_version() {
    assert_eq!(written_by("#compdef cw\n_cw() {}\n"), None);
    assert_eq!(written_by(""), None);
}

#[test]
fn the_words_before_the_cursor_follow_the_dashes_and_leave_out_the_program() {
    let argv = args(&["cw", "--", "cw", "--cloud", "attach", "fa"]);
    assert_eq!(
        words_before_cursor_of(argv.clone(), Some("3")),
        ["--cloud", "attach"]
    );
    assert_eq!(
        words_before_cursor_of(argv.clone(), Some("1")),
        Vec::<String>::new()
    );
    // fish passes no index: the word being completed is the last.
    assert_eq!(words_before_cursor_of(argv, None), ["--cloud", "attach"]);
}

/// Arguments found by what they say about themselves, not by the rule
/// `completer_for` attaches the completer by: an ID or value name that
/// mentions an environment, or help that asks for one.
fn mentions_an_environment(argument: &Arg) -> bool {
    let help = argument
        .get_help()
        .map(ToString::to_string)
        .unwrap_or_default();
    argument.get_id().as_str().contains("environment")
        || argument
            .get_value_names()
            .unwrap_or_default()
            .iter()
            .any(|name| name.as_str().starts_with("ENV"))
        || help.to_lowercase().contains("environment name")
}

/// Arguments that mention an environment and take something else: free text,
/// or a value that is not an environment's name. Each entry is `command
/// argument-id`. A new argument that is not here and has no completer fails
/// the test below.
const NOT_AN_ENVIRONMENT: &[&str] = &[
    // A name being chosen for an environment that does not exist yet.
    "init name",
    "create name",
    // The kind of environment, not a name.
    "ls environment_type",
    "create environment_type",
    // `[ENV] TEXT`: free text, and `cw msg` offers no environment until #5085
    // splits the argument.
    "msg positionals",
    "steer positionals",
    // The hidden roles cw starts itself, given an ID by the process that runs
    // them; nobody types these.
    "__native-runner environment_id",
    "__native-network-worker environment_id",
    "__native-egress-broker environment_id",
    "__native-mesh-transport environment_id",
    "__native-mesh-enrollment-broker environment_id",
    "__local-credential-broker environment_id",
    "__local-credential-broker environment_generation",
    "__local-credential-broker environment_name",
];

fn walk<'a>(command: &'a Command, visit: &mut impl FnMut(&'a Command, &'a Arg)) {
    for argument in command.get_arguments() {
        visit(command, argument);
    }
    for subcommand in command.get_subcommands() {
        walk(subcommand, visit);
    }
}

#[test]
fn every_argument_that_names_an_environment_has_the_completer() {
    let tree = command_with_completers();
    let (mut with, mut without) = (0, Vec::new());
    walk(&tree, &mut |command, argument| {
        if !mentions_an_environment(argument) {
            return;
        }
        let label = format!("{} {}", command.get_name(), argument.get_id());
        let completed = argument.get::<ArgValueCompleter>().is_some();
        let excused = NOT_AN_ENVIRONMENT.contains(&label.as_str());
        match (completed, excused) {
            (true, false) => with += 1,
            (false, true) => {}
            (true, true) => panic!("{label} is listed as not an environment but has the completer"),
            (false, false) => without.push(label),
        }
    });
    assert!(
        with > 30,
        "found only {with} completed environment arguments"
    );
    assert!(
        without.is_empty(),
        "named an environment, no completer, not listed: {without:?}"
    );
}

#[test]
fn free_text_has_no_completer() {
    let tree = command_with_completers();
    let mut checked = Vec::new();
    walk(&tree, &mut |command, argument| {
        let free_text = argument.is_last_set()
            || command.is_trailing_var_arg_set()
            || argument
                .get_value_names()
                .unwrap_or_default()
                .iter()
                .any(|name| matches!(name.as_str(), "ENV_AND_TEXT" | "TEXT" | "COMMAND"));
        if free_text {
            checked.push(format!("{} {}", command.get_name(), argument.get_id()));
            assert!(
                argument.get::<ArgValueCompleter>().is_none(),
                "{} {} is free text and must complete nothing",
                command.get_name(),
                argument.get_id()
            );
        }
    });
    assert!(
        checked.iter().any(|label| label.starts_with("msg ")),
        "cw msg's message words were not found: {checked:?}"
    );
    assert!(
        checked.iter().any(|label| label.starts_with("exec ")),
        "cw exec's command was not found: {checked:?}"
    );
}

#[test]
fn doctor_says_when_the_installed_completion_needs_a_reinstall() {
    let path = std::path::Path::new("/home/u/.zfunc/_cw");
    let current = String::from_utf8(registration_script(CompletionShell::Zsh).unwrap()).unwrap();
    let ok = file_check(CompletionShell::Zsh, path, &current);
    assert_eq!(ok.status, DoctorStatus::Ok, "{}", ok.detail);

    let older = current.replace(
        &format!("written by cw {CLI_VERSION}"),
        "written by cw 0.0.1",
    );
    let stale = file_check(CompletionShell::Zsh, path, &older);
    assert_eq!(stale.status, DoctorStatus::Warn);
    assert!(
        stale.detail.contains("written by cw 0.0.1")
            && stale.detail.contains(&format!("this is cw {CLI_VERSION}"))
            && stale.detail.contains("`cw completion --install`"),
        "{}",
        stale.detail
    );

    let static_script = file_check(CompletionShell::Zsh, path, "#compdef cw\n_cw() {}\n");
    assert_eq!(static_script.status, DoctorStatus::Warn);
    assert!(
        static_script.detail.contains("commands and flags only")
            && static_script.detail.contains("`cw completion --install`"),
        "{}",
        static_script.detail
    );
}

#[test]
fn the_watchdog_ends_a_stalled_answer_with_success() {
    // The child arms a short watchdog and then stalls for far longer; the
    // parent sees it end well before that, with success and so no suggestions.
    if std::env::var_os("CW_WATCHDOG_TEST_CHILD").is_some() {
        end_the_answer_after(Duration::from_millis(100));
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let started = std::time::Instant::now();
    let status = crate::process::command(std::env::current_exe().unwrap(), &[])
        .args([
            "--exact",
            "completion::tests::the_watchdog_ends_a_stalled_answer_with_success",
        ])
        .env("CW_WATCHDOG_TEST_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_private_role_is_never_a_completion_request() {
    assert!(is_private_role(std::ffi::OsStr::new("__native-runner")));
    assert!(is_private_role(std::ffi::OsStr::new("__hosted-exec")));
    // A completion request passes `--` first, then the words.
    assert!(!is_private_role(std::ffi::OsStr::new("--")));
    assert!(!is_private_role(std::ffi::OsStr::new("attach")));
}
