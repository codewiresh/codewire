//! What a connect says when its store answers the save with anything but
//! the credential, in the same words in both placements (#4826; #4717 C2 and
//! C4). Neither the store's nor the service's own message reaches the
//! person: a cause is told only by its code and a closed reason.

use std::path::Path;

use clap::ValueEnum as _;
use codewire_credential_broker::provider_oauth::claude::{
    CLAUDE_SIGN_IN_CODE_INVALID, CLAUDE_SIGN_IN_EXPIRED,
};
use codewire_local_credentials::StoreRefusal;

use crate::commands::credential_input::connect::{CredentialConnectProviderArg, connected_noun};
use crate::commands::platform_commands::shell_word;

/// What a store's answer says about a save, by its code alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::commands) enum Answer {
    /// The name is taken.
    AlreadyExists,
    /// The credential to reconnect is gone.
    NotFound,
    /// Any other definite refusal: nothing was saved.
    Refused,
    /// The save may have landed: the connection failed after the request
    /// was sent, the store didn't answer in time, or it says it can't tell.
    Uncertain,
}

/// The save a connect asked for.
#[derive(Clone, Copy)]
pub(in crate::commands) struct Save<'a> {
    /// `local` or `cloud`, as the flag spells it.
    pub(in crate::commands) placement: &'static str,
    pub(in crate::commands) provider: CredentialConnectProviderArg,
    pub(in crate::commands) name: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    NameInUse,
    Deleted,
    Changed,
    GithubConnected,
    ClaudeCodeInvalid,
    ClaudeSignInExpired,
    KeychainLocked,
    KeychainMissing,
    Refused,
    Unknown,
}

const CLAUDE_CODE_INVALID_REASON: &str = "CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID";
const CLAUDE_SIGN_IN_EXPIRED_REASON: &str = "CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED";

/// One classifier for both placements: the local store's reason and the
/// credential service's `ErrorInfo` reason are the same strings for the same
/// cause. A definite answer without a known reason is a plain refusal, never
/// an unknown outcome.
fn classify(answer: Answer, reason: Option<&str>) -> Outcome {
    if answer == Answer::Uncertain {
        return Outcome::Unknown;
    }
    let is = |refusal: StoreRefusal| reason == Some(refusal.reason());
    if is(StoreRefusal::GithubAlreadyConnected) {
        Outcome::GithubConnected
    } else if is(StoreRefusal::RevisionChanged) {
        Outcome::Changed
    } else if is(StoreRefusal::KeychainLocked) {
        Outcome::KeychainLocked
    } else if is(StoreRefusal::KeychainMissing) {
        Outcome::KeychainMissing
    } else if reason == Some(CLAUDE_CODE_INVALID_REASON) {
        Outcome::ClaudeCodeInvalid
    } else if reason == Some(CLAUDE_SIGN_IN_EXPIRED_REASON) {
        Outcome::ClaudeSignInExpired
    } else {
        match answer {
            Answer::AlreadyExists => Outcome::NameInUse,
            Answer::NotFound => Outcome::Deleted,
            Answer::Refused | Answer::Uncertain => Outcome::Refused,
        }
    }
}

/// The error a connect returns for its store's answer. `keychain` is the
/// file `CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN` names, if set.
pub(in crate::commands) fn save_error(
    save: Save<'_>,
    answer: Answer,
    reason: Option<&str>,
    keychain: Option<&Path>,
) -> anyhow::Error {
    let (message, next) = words(save, classify(answer, reason), keychain);
    let error = anyhow::anyhow!(message);
    match next {
        Some(next) => crate::error_report::with_next_step(error, next),
        None => error,
    }
}

fn words(save: Save<'_>, outcome: Outcome, keychain: Option<&Path>) -> (String, Option<String>) {
    let Save {
        placement,
        provider,
        name,
    } = save;
    let what = connected_noun(provider);
    let word = provider
        .to_possible_value()
        .map_or_else(String::new, |value| value.get_name().to_owned());
    let connect = format!(
        "cw credentials --{placement} connect {word} --name {}",
        shell_word(name)
    );
    let list = format!("cw credentials --{placement} list");
    let (store, place) = if placement == "local" {
        ("the local credential store", "on this computer")
    } else {
        ("Codewire", "in your Codewire account")
    };
    match outcome {
        Outcome::NameInUse => (
            format!(
                "a {placement} credential is already named {name:?}, so your {what} wasn't saved"
            ),
            Some(format!(
                "cw credentials --{placement} connect {word} --name NAME"
            )),
        ),
        Outcome::Deleted => (
            format!(
                "the {placement} credential {name:?} was deleted during the sign-in, so your {what} wasn't saved"
            ),
            Some(connect),
        ),
        Outcome::Changed => (
            format!(
                "the {placement} credential {name:?} changed during the sign-in, so your {what} wasn't saved"
            ),
            Some(connect),
        ),
        Outcome::GithubConnected => (
            format!("GitHub is already connected {place}, so your {what} wasn't saved"),
            Some(list),
        ),
        Outcome::ClaudeCodeInvalid => (CLAUDE_SIGN_IN_CODE_INVALID.to_owned(), Some(connect)),
        Outcome::ClaudeSignInExpired => (CLAUDE_SIGN_IN_EXPIRED.to_owned(), Some(connect)),
        Outcome::KeychainLocked => keychain_locked(what, keychain, connect),
        Outcome::KeychainMissing => match keychain {
            Some(path) => (
                format!(
                    "the keychain {} doesn't exist (set by CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN), so your {what} wasn't saved",
                    path.display()
                ),
                Some("unset CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN".to_owned()),
            ),
            None => (
                format!(
                    "your login keychain doesn't exist, so your {what} wasn't saved; create it in Keychain Access, then run this again"
                ),
                Some(connect),
            ),
        },
        Outcome::Refused => (
            format!("{store} refused your {what}, so nothing was saved"),
            Some(list),
        ),
        Outcome::Unknown => (
            format!(
                "{store} didn't confirm saving your {what}, so it may or may not be saved; check the list before connecting again"
            ),
            Some(list),
        ),
    }
}

/// A locked keychain on a Mac is unlocked by `security`; elsewhere the
/// keyring is unlocked from the desktop session, which has no command.
fn keychain_locked(
    what: &str,
    keychain: Option<&Path>,
    connect: String,
) -> (String, Option<String>) {
    if cfg!(target_os = "macos") {
        let (subject, command) = match keychain {
            Some(path) => (
                format!("the keychain {}", path.display()),
                format!(
                    "security unlock-keychain {}",
                    shell_word(&path.to_string_lossy())
                ),
            ),
            None => (
                "your login keychain".to_owned(),
                "security unlock-keychain".to_owned(),
            ),
        };
        (
            format!("{subject} is locked in this session, so your {what} wasn't saved"),
            Some(command),
        )
    } else {
        (
            format!(
                "your keyring is locked, so your {what} wasn't saved; unlock it, then run this again"
            ),
            Some(connect),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(
        placement: &'static str,
        answer: Answer,
        reason: Option<&str>,
    ) -> (String, Option<String>) {
        let error = save_error(
            Save {
                placement,
                provider: CredentialConnectProviderArg::Github,
                name: "work",
            },
            answer,
            reason,
            None,
        );
        let next = crate::error_report::next_step(&error);
        (crate::error_report::sentence(&error), next)
    }

    #[test]
    fn the_same_cause_reads_the_same_in_both_placements() {
        for (answer, reason, local, cloud) in [
            (
                Answer::AlreadyExists,
                None,
                "a local credential is already named \"work\", so your GitHub sign-in wasn't saved",
                "a cloud credential is already named \"work\", so your GitHub sign-in wasn't saved",
            ),
            (
                Answer::AlreadyExists,
                Some("CREDENTIAL_GITHUB_ALREADY_CONNECTED"),
                "GitHub is already connected on this computer, so your GitHub sign-in wasn't saved",
                "GitHub is already connected in your Codewire account, so your GitHub sign-in wasn't saved",
            ),
            (
                Answer::NotFound,
                None,
                "the local credential \"work\" was deleted during the sign-in, so your GitHub sign-in wasn't saved",
                "the cloud credential \"work\" was deleted during the sign-in, so your GitHub sign-in wasn't saved",
            ),
            (
                Answer::Refused,
                Some("CREDENTIAL_REVISION_CHANGED"),
                "the local credential \"work\" changed during the sign-in, so your GitHub sign-in wasn't saved",
                "the cloud credential \"work\" changed during the sign-in, so your GitHub sign-in wasn't saved",
            ),
            (
                Answer::Refused,
                None,
                "the local credential store refused your GitHub sign-in, so nothing was saved",
                "Codewire refused your GitHub sign-in, so nothing was saved",
            ),
        ] {
            assert_eq!(said("local", answer, reason).0, local);
            assert_eq!(said("cloud", answer, reason).0, cloud);
        }
        assert_eq!(
            said(
                "cloud",
                Answer::Refused,
                Some("CREDENTIAL_REVISION_CHANGED")
            )
            .1
            .as_deref(),
            Some("cw credentials --cloud connect github --name work")
        );
    }

    #[test]
    fn only_an_uncertain_answer_leaves_the_outcome_unknown() {
        // A definite code with a reason this cw doesn't know is a refusal.
        assert_eq!(
            said("local", Answer::Refused, Some("SOME_LATER_REASON")).0,
            "the local credential store refused your GitHub sign-in, so nothing was saved"
        );
        // An uncertain answer stays unknown whatever reason it carries.
        let (text, next) = said(
            "local",
            Answer::Uncertain,
            Some("CREDENTIAL_REVISION_CHANGED"),
        );
        assert_eq!(
            text,
            "the local credential store didn't confirm saving your GitHub sign-in, so it may or may not be saved; check the list before connecting again"
        );
        assert_eq!(next.as_deref(), Some("cw credentials --local list"));
    }

    #[test]
    fn a_missing_keychain_names_the_file_the_variable_sets() {
        let error = save_error(
            Save {
                placement: "local",
                provider: CredentialConnectProviderArg::Claude,
                name: "work",
            },
            Answer::Refused,
            Some(StoreRefusal::KeychainMissing.reason()),
            Some(Path::new("/keys/cw.keychain-db")),
        );
        assert_eq!(
            crate::error_report::sentence(&error),
            "the keychain /keys/cw.keychain-db doesn't exist (set by CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN), so your Claude sign-in wasn't saved"
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("unset CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN")
        );
    }
}
