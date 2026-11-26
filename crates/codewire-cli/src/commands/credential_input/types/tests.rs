use std::path::PathBuf;

use clap::Parser as _;
use codewire_access::CREDENTIAL_TYPES;

use super::*;
use crate::{Cli, Command};

/// The command `argv` parses to, after `route`.
fn routed(argv: &[&str]) -> anyhow::Result<CredentialsCommand> {
    let cli = Cli::try_parse_from(argv).map_err(|error| anyhow::anyhow!("{error}"))?;
    let Command::Credentials(mut args) = cli.command else {
        panic!("a credentials command");
    };
    route(&mut args.command)?;
    Ok(args.command)
}

/// Each verb takes each type in both placements and hands it to that
/// type's own flow.
#[test]
fn both_verbs_hand_every_type_to_its_own_flow() {
    for placement in ["--local", "--cloud"] {
        for verb in ["add", "connect"] {
            for row in &CREDENTIAL_TYPES {
                let argv = [
                    "cw",
                    "credentials",
                    placement,
                    verb,
                    row.word,
                    "--name",
                    "w",
                ];
                match (row.verb, routed(&argv).unwrap()) {
                    (CredentialVerb::Connect, CredentialsCommand::Connect(connect)) => {
                        let provider = connect.provider.expect("a connect flow");
                        assert_eq!(credential_type_of_arg(provider).word, row.word);
                        assert_eq!(connect.credential_type, None);
                        assert_eq!(connect.name.as_deref(), Some("w"));
                    }
                    (CredentialVerb::Add, CredentialsCommand::Add(add)) => {
                        assert_eq!(add.provider.as_deref(), Some(row.word));
                        assert_eq!(add.name.as_deref(), Some("w"));
                    }
                    (_, command) => panic!("{verb} {} ran {command:?}", row.word),
                }
            }
        }
    }
}

/// The picker the owner approved on #6286: every type, in this order.
#[test]
fn the_picker_shows_every_type_as_approved() {
    let rows = CREDENTIAL_TYPES
        .iter()
        .map(|row| (row.label, row.detail))
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            ("Codex", "sign in with your ChatGPT account"),
            ("GitHub", "sign in with your GitHub account"),
            (
                "Claude (sign-in)",
                "your subscription; shows your plan and usage"
            ),
            (
                "Claude (token)",
                "your subscription; lasts a year, for automation, model requests only"
            ),
            (
                "Anthropic API key",
                "paste a key from console.anthropic.com"
            ),
            ("OpenAI API key", "paste a key from platform.openai.com"),
            ("Gemini API key", "paste a key from aistudio.google.com"),
            ("SSH key", "generate one, or import an OpenSSH key file"),
        ]
    );
    let words = CREDENTIAL_TYPES
        .iter()
        .map(|row| row.word)
        .collect::<Vec<_>>();
    assert_eq!(TYPE_HELP, format!("{} or ssh", words[..7].join(", ")));
    assert_eq!(words[7], "ssh");
}

/// A flag the type's flow doesn't take is refused, naming the flag and the
/// type, whichever verb was typed.
#[test]
fn a_flag_the_types_flow_doesnt_take_is_refused() {
    for (argv, refusal) in [
        (
            &["add", "codex", "--key-file", "/k"][..],
            "--key-file doesn't apply to Codex",
        ),
        (
            &["connect", "github", "--key-file", "/k"],
            "--key-file doesn't apply to GitHub",
        ),
        (
            &["add", "claude", "--expires-at", "2027-01-01"],
            "--expires-at doesn't apply to Claude (sign-in)",
        ),
        (
            &["connect", "claude-token", "--expires-at", "2027-01-01"],
            "a Claude token expires one year after it is saved; --expires-at is not accepted",
        ),
        (
            &["add", "claude-token", "--account-hint", "a"],
            "--account-hint doesn't apply to Claude (token)",
        ),
        (
            &["connect", "anthropic", "-y"],
            "--yes doesn't apply to Anthropic API key",
        ),
        (
            &["add", "openai", "--yes"],
            "--yes doesn't apply to OpenAI API key",
        ),
        (
            &["connect", "openai", "--output", "json"],
            "--output doesn't apply to OpenAI API key",
        ),
        (
            &["connect", "anthropic", "--key-file", "/k"],
            "--key-file doesn't apply to Anthropic API key",
        ),
        (&["add", "ssh", "-y"], "--yes doesn't apply to SSH key"),
    ] {
        let argv = [
            &["cw", "credentials", "--local"][..],
            argv,
            &["--name", "w"],
        ]
        .concat();
        let error = routed(&argv).expect_err(&argv.join(" "));
        assert_eq!(error.to_string(), refusal, "{}", argv.join(" "));
    }
}

/// The flags a type's flow takes reach it from either verb.
#[test]
fn the_flags_a_types_flow_takes_reach_it_from_either_verb() {
    let CredentialsCommand::Add(add) = routed(&[
        "cw",
        "credentials",
        "--local",
        "connect",
        "ssh",
        "--name",
        "w",
        "--key-file",
        "/k",
        "--expires-at",
        "2027-01-01",
    ])
    .unwrap() else {
        panic!("connect ssh imports");
    };
    assert_eq!(add.key_file, Some(PathBuf::from("/k")));
    assert_eq!(add.expires_at, Some(1_798_761_600));
    let CredentialsCommand::Connect(connect) = routed(&[
        "cw",
        "credentials",
        "--cloud",
        "add",
        "codex",
        "--name",
        "w",
        "-y",
        "--output",
        "json",
    ])
    .unwrap() else {
        panic!("add codex signs in");
    };
    assert!(connect.yes);
    assert_eq!(connect.output, OutputFormat::Json);
}

/// `claude-subscription` stays `add`'s hidden alias: `route` leaves it to
/// `add`, which turns it into `connect claude-token` itself, and `connect`
/// doesn't take it.
#[test]
fn the_alias_stays_adds_alone() {
    let CredentialsCommand::Add(add) = routed(&[
        "cw",
        "credentials",
        "--local",
        "add",
        CLAUDE_SUBSCRIPTION_ALIAS,
    ])
    .unwrap() else {
        panic!("the alias stays an add");
    };
    assert_eq!(add.provider.as_deref(), Some(CLAUDE_SUBSCRIPTION_ALIAS));
    assert!(
        routed(&[
            "cw",
            "credentials",
            "--local",
            "connect",
            CLAUDE_SUBSCRIPTION_ALIAS
        ])
        .is_err()
    );
}

/// Without a terminal, an SSH key with no key file is refused, naming both
/// ways to add one. Tests never run at a terminal.
#[test]
fn an_ssh_key_without_a_file_or_a_terminal_names_both_ways() {
    for verb in ["add", "connect"] {
        let mut command =
            routed(&["cw", "credentials", "--local", verb, "ssh", "--name", "w"]).unwrap();
        let error = ssh_source(&mut command).unwrap_err();
        assert_eq!(
            error.root_cause().to_string(),
            "SSH key needs a key file without a terminal"
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("`cw credentials generate ssh --name NAME`, or pass `--key-file PATH`")
        );
    }
    let mut command = routed(&[
        "cw",
        "credentials",
        "--local",
        "add",
        "ssh",
        "--name",
        "w",
        "--key-file",
        "/k",
    ])
    .unwrap();
    assert!(!ssh_source(&mut command).unwrap());
}

/// The verbs' one help line names what each flow in the registry does.
#[test]
fn the_verbs_help_names_every_flow() {
    for row in &CREDENTIAL_TYPES {
        let named = match row.flow {
            CredentialFlow::SignIn => "Sign in",
            CredentialFlow::Paste => "paste a key or token",
            CredentialFlow::SshKey => "set up an SSH key",
        };
        assert!(ADD_AND_CONNECT_ABOUT.contains(named), "{}", row.word);
    }
}
