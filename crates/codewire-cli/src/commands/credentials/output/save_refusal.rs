//! What a connect or another credential write says when its store answers
//! with anything but the credential, in the same words in both placements
//! (#4826, #5271; #4717 C2 and C4). Neither the store's nor the service's own message reaches the
//! person: a cause is told only by its code and a closed reason.

use std::path::Path;

use clap::ValueEnum as _;
use codewire_credential_broker::provider_oauth::claude::{
    CLAUDE_SIGN_IN_CODE_INVALID, CLAUDE_SIGN_IN_EXPIRED,
};
use codewire_local_credentials::StoreRefusal;

use crate::commands::credential_input::connect::{
    CredentialConnectProviderArg, connected_noun, provider_id,
};
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

/// The save a command asked for.
#[derive(Clone, Copy)]
pub(in crate::commands) struct Save<'a> {
    /// `local` or `cloud`, as the flag spells it.
    pub(in crate::commands) placement: &'static str,
    pub(in crate::commands) kind: Kind<'a>,
    pub(in crate::commands) name: &'a str,
}

/// The command that saved: its words name what it saves and how to run it
/// again.
#[derive(Clone, Copy)]
pub(in crate::commands) enum Kind<'a> {
    Connect(CredentialConnectProviderArg),
    /// `add PROVIDER` or `generate ssh`, by the command to run again (after
    /// `cw credentials --PLACEMENT`, before `--name`), the provider its name
    /// is unique in, and what it saves.
    Write {
        command: &'a str,
        provider: &'a str,
        what: &'a str,
    },
    /// `rotate NAME`, and what the credential is.
    Rotate {
        what: &'a str,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    NameInUse,
    NameReservesProvider,
    Deleted,
    Changed,
    GithubConnected,
    ClaudeCodeInvalid,
    ClaudeSignInExpired,
    KeychainLocked,
    KeychainMissing,
    KeyringTimedOut,
    Refused,
    Unknown,
}

const CLAUDE_CODE_INVALID_REASON: &str = "CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID";
const CLAUDE_SIGN_IN_EXPIRED_REASON: &str = "CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED";

impl Kind<'_> {
    /// The provider a saved name is unique in (#4928); a rotation saves no
    /// new name.
    fn provider(&self) -> Option<&str> {
        match self {
            Self::Connect(provider) => Some(provider_id(*provider)),
            Self::Write { provider, .. } => Some(provider),
            Self::Rotate { .. } => None,
        }
    }
}

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
    } else if is(StoreRefusal::KeyringTimedOut) {
        Outcome::KeyringTimedOut
    } else if is(StoreRefusal::CredentialNameReservesProvider) {
        Outcome::NameReservesProvider
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
        kind,
        name,
    } = save;
    let named =
        |command: &str, name: &str| format!("cw credentials --{placement} {command} --name {name}");
    // What it saves, the command that runs it again, and the same command
    // for another name.
    let (what, connect, renamed) = match kind {
        Kind::Connect(provider) => {
            let command = format!(
                "connect {}",
                provider
                    .to_possible_value()
                    .map_or_else(String::new, |value| value.get_name().to_owned())
            );
            (
                connected_noun(provider),
                named(&command, &shell_word(name)),
                named(&command, "NAME"),
            )
        }
        Kind::Write { command, what, .. } => (
            what,
            named(command, &shell_word(name)),
            named(command, "NAME"),
        ),
        Kind::Rotate { what } => {
            let again = format!("cw credentials --{placement} rotate {}", shell_word(name));
            (what, again.clone(), again)
        }
    };
    let list = format!("cw credentials --{placement} list");
    let (store, place) = if placement == "local" {
        ("the local credential store", "on this computer")
    } else {
        ("Codewire", "in your Codewire account")
    };
    match outcome {
        // Only the provider: the store answered for a credential this
        // command could not read (cw-security on #4928).
        Outcome::NameInUse => (
            match kind.provider() {
                Some(provider) => {
                    format!("that name is in use in {provider}, so your {what} wasn't saved")
                }
                None => format!("that name is in use, so your {what} wasn't saved"),
            },
            Some(renamed),
        ),
        Outcome::NameReservesProvider => (
            format!(
                "a credential's name can't start with anthropic/, openai/, github/ or ssh/, so your {what} wasn't saved"
            ),
            Some(renamed),
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
        Outcome::KeyringTimedOut => keyring_timed_out(what),
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

/// The store didn't answer within its bound (#5271). The authority never made
/// the value ready, so nothing was saved; the person unlocks or restarts the
/// store and runs the command again.
fn keyring_timed_out(what: &str) -> (String, Option<String>) {
    if cfg!(target_os = "macos") {
        (
            format!(
                "your login keychain didn't answer within 2 minutes, so your {what} wasn't saved; unlock it, then run this again"
            ),
            Some("security unlock-keychain".to_owned()),
        )
    } else {
        (
            format!(
                "your keyring (Secret Service) didn't answer within 2 minutes, so your {what} wasn't saved; unlock it, or restart it, then run this again"
            ),
            Some("systemctl --user restart gnome-keyring-daemon".to_owned()),
        )
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
                kind: Kind::Connect(CredentialConnectProviderArg::Github),
                name: "work",
            },
            answer,
            reason,
            None,
        );
        let next = crate::error_report::next_step(&error);
        (crate::error_report::sentence(&error), next)
    }

    /// The refusal writes the prefixes out; it names exactly the providers a
    /// name is unique within.
    #[test]
    fn a_name_reserving_a_provider_names_every_provider() {
        for placement in ["local", "cloud"] {
            assert_eq!(
                said(
                    placement,
                    Answer::Refused,
                    Some("CREDENTIAL_NAME_RESERVES_PROVIDER")
                )
                .0,
                format!(
                    "a credential's name can't start with {}, so your GitHub sign-in wasn't saved",
                    codewire_access::credential_name_provider_prefixes()
                )
            );
        }
    }

    #[test]
    fn the_same_cause_reads_the_same_in_both_placements() {
        for (answer, reason, local, cloud) in [
            (
                Answer::AlreadyExists,
                None,
                "that name is in use in github, so your GitHub sign-in wasn't saved",
                "that name is in use in github, so your GitHub sign-in wasn't saved",
            ),
            (
                Answer::Refused,
                Some("CREDENTIAL_NAME_RESERVES_PROVIDER"),
                "a credential's name can't start with anthropic/, openai/, github/ or ssh/, so your GitHub sign-in wasn't saved",
                "a credential's name can't start with anthropic/, openai/, github/ or ssh/, so your GitHub sign-in wasn't saved",
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_keyring_that_timed_out_saved_nothing_and_says_what_to_do() {
        let (text, next) = said("local", Answer::Refused, Some("LOCAL_KEYRING_TIMED_OUT"));
        assert_eq!(
            text,
            "your keyring (Secret Service) didn't answer within 2 minutes, so your GitHub sign-in wasn't saved; unlock it, or restart it, then run this again"
        );
        assert_eq!(
            next.as_deref(),
            Some("systemctl --user restart gnome-keyring-daemon")
        );
    }

    #[test]
    fn another_write_is_worded_by_its_own_command() {
        let error = save_error(
            Save {
                placement: "local",
                kind: Kind::Write {
                    command: "add anthropic",
                    provider: "anthropic",
                    what: "Anthropic API key",
                },
                name: "work key",
            },
            Answer::AlreadyExists,
            None,
            None,
        );
        assert_eq!(
            crate::error_report::sentence(&error),
            "that name is in use in anthropic, so your Anthropic API key wasn't saved"
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("cw credentials --local add anthropic --name NAME")
        );
    }

    #[test]
    fn a_missing_keychain_names_the_file_the_variable_sets() {
        let error = save_error(
            Save {
                placement: "local",
                kind: Kind::Connect(CredentialConnectProviderArg::Claude),
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
