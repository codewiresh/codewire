//! While host-bound secrets are off (`codewire_access::HOST_BOUND_SECRETS`),
//! nothing reaches a binding: the flags and `presets` are refused before any
//! question or call, and stay out of the help (#4003).

use super::*;
use crate::output::{Charset, Style};
use crate::{Cli, Command};

const OFF: &str = "✗ Sending a secret only to its hosts isn't available yet\n";

fn secrets(argv: &[&str]) -> SecretsArgs {
    let Command::Secrets(args) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected secrets");
    };
    args
}

/// No placement: were anything asked or sent, this would prompt for a
/// store or fail on it, never answer the switch's sentence.
fn globals() -> crate::Globals {
    crate::Globals {
        server: None,
        member: None,
        placement: None,
        org: None,
    }
}

async fn refusal(argv: &[&str]) -> String {
    let error = handle_secrets_command_with(&globals(), secrets(argv), false)
        .await
        .unwrap_err();
    crate::error_report::render(&error, Style::new(false, Charset::Unicode))
}

#[tokio::test]
async fn every_binding_flag_and_presets_are_refused_before_anything_is_asked() {
    for argv in [
        &[
            "cw",
            "secrets",
            "--project=myapp",
            "set",
            "KEY",
            "--host",
            "api.fancy.com",
        ][..],
        // Guided: no scope and no key, which would otherwise ask for both.
        &["cw", "secrets", "set", "--host", "api.fancy.com"],
        &["cw", "secrets", "--user", "set", "KEY", "--plain"],
        &[
            "cw", "secrets", "--user", "set", "KEY", "--preset", "stripe",
        ],
        &["cw", "secrets", "--user", "set", "KEY", "--prefix", ""],
        &["cw", "secrets", "presets"],
        &["cw", "secrets", "presets", "--output", "json"],
    ] {
        assert_eq!(refusal(argv).await, OFF, "{argv:?}");
    }
}

#[test]
fn the_binding_flags_and_presets_stay_out_of_the_help() {
    let mut root = Cli::command();
    let secrets = root.find_subcommand_mut("secrets").unwrap();
    let help = secrets.render_long_help().to_string();
    assert!(help.contains("projects"), "{help}");
    assert!(!help.contains("presets"), "{help}");
    let set = secrets.find_subcommand_mut("set").unwrap();
    let help = set.render_long_help().to_string();
    assert!(help.contains("--output"), "{help}");
    for flag in [
        "--host",
        "--remove-host",
        "--header",
        "--scheme",
        "--prefix",
        "--basic",
        "--username",
        "--basic-user",
        "--preset",
        "--plain",
    ] {
        assert!(!help.contains(flag), "{flag} is in the help:\n{help}");
    }
    let list = Cli::command()
        .find_subcommand_mut("secrets")
        .unwrap()
        .find_subcommand_mut("list")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(list.contains("--verbose"), "{list}");
}
