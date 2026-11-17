//! Asking before `revoke` or `delete` changes a credential or a profile, the
//! same in both placements (#4717 C6), by the rule `cw rm` uses: `--yes`
//! goes on, a terminal is asked once, and with no terminal or `--output json`
//! the command refuses at once and names `--yes`.

use std::io::IsTerminal as _;

use super::super::{
    OutputFormat, RemovalConfirmation, prompt_confirm_default_no, removal_confirmation,
};
use super::output::{self, refusal};

/// `cw credentials revoke`: the selector, `--yes`, and the output format.
#[derive(Debug, clap::Args)]
pub(crate) struct CredentialRevokeArgs {
    #[arg(
        value_name = "CREDENTIAL_SELECTOR",
        help = "Credential name, name:<name>, or id:<canonical-uuid>"
    )]
    pub(crate) credential: String,
    #[arg(
        short,
        long,
        help = "Revoke without asking; needed without a terminal or with --output json"
    )]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

/// What the user is asked to allow.
#[derive(Clone, Copy, Debug)]
pub(in crate::commands) enum Change<'a> {
    Revoke,
    /// An active credential is revoked first.
    Delete {
        active: bool,
    },
    /// A credential profile, asked about in its placement's words.
    DeleteProfile {
        question: &'a str,
    },
}

/// True to go on; false when the user said no, after saying it was
/// canceled. Without a terminal, or with `--output json`, and without
/// `--yes`, it fails at once and names `--yes`.
pub(in crate::commands) fn confirm(
    placement: &str,
    name: &str,
    change: Change<'_>,
    yes: bool,
    output: OutputFormat,
) -> anyhow::Result<bool> {
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let json = matches!(output, OutputFormat::Json);
    match removal_confirmation(yes, json, terminal) {
        RemovalConfirmation::Proceed => Ok(true),
        RemovalConfirmation::Refuse => {
            Err(anyhow::anyhow!(unconfirmed(placement, name, change, json)))
        }
        RemovalConfirmation::Ask => {
            let question = match change {
                Change::Revoke => output::revoke_question(placement, name),
                Change::Delete { active } => output::delete_question(placement, name, active),
                Change::DeleteProfile { question } => question.to_owned(),
            };
            let confirmed = prompt_confirm_default_no(&question)?;
            if !confirmed {
                eprintln!("Cancelled; nothing was changed.");
            }
            Ok(confirmed)
        }
    }
}

fn unconfirmed(placement: &str, name: &str, change: Change<'_>, json: bool) -> String {
    match change {
        Change::Revoke => refusal::unconfirmed(placement, "credential", name, "revoke", json),
        Change::Delete { .. } => {
            refusal::unconfirmed(placement, "credential", name, "delete", json)
        }
        Change::DeleteProfile { .. } => refusal::unconfirmed(
            placement,
            "profile",
            name,
            &format!("--profile {name} delete"),
            json,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nobody_to_ask_refuses_in_the_commands_own_words() {
        assert_eq!(
            unconfirmed("local", "work", Change::Delete { active: true }, false),
            "local credential \"work\" was not deleted: `cw credentials --local delete` asks first, and there is no terminal to ask at; add `--yes` to delete it"
        );
        assert_eq!(
            unconfirmed("cloud", "work", Change::Revoke, true),
            "cloud credential \"work\" was not revoked: `cw credentials --cloud revoke --output json` never asks; add `--yes` to revoke it"
        );
        assert_eq!(
            unconfirmed(
                "cloud",
                "daily",
                Change::DeleteProfile { question: "" },
                false
            ),
            "cloud profile \"daily\" was not deleted: `cw credentials --cloud --profile daily delete` asks first, and there is no terminal to ask at; add `--yes` to delete it"
        );
    }

    #[test]
    fn yes_goes_on_and_json_or_no_terminal_refuses() {
        for output in [OutputFormat::Text, OutputFormat::Json] {
            assert!(confirm("cloud", "work", Change::Revoke, true, output).unwrap());
        }
        // A test's stdin may be a terminal; JSON never asks either way.
        let error = confirm("cloud", "work", Change::Revoke, false, OutputFormat::Json)
            .unwrap_err()
            .to_string();
        assert!(error.contains("add `--yes` to revoke it"), "{error}");
    }
}
