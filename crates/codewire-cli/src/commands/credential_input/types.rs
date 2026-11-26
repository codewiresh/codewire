//! What `cw credentials add` and `connect` take (#6286): both take every
//! credential type, by the same words and flags, and show the same picker of
//! them. [`route`] hands a type to the subcommand whose flow runs it (a
//! sign-in or the Claude token to `connect`'s, a key to `add`'s, an SSH key to
//! `add`'s import or to `generate`), so the verb that was typed doesn't change
//! what a type does, and refuses a flag that flow doesn't take.

use std::path::PathBuf;

use clap::builder::{PossibleValue, PossibleValuesParser};
use clap::{Args, ValueEnum as _};
use codewire_access::{CREDENTIAL_TYPES, CredentialFlow, CredentialVerb, credential_type};

use super::connect::{
    CLAUDE_SUBSCRIPTION_ALIAS, CredentialConnectArgs, CredentialConnectProviderArg,
    credential_type_of_arg,
};
use super::{EXPIRES_AT_HELP, NAME_HELP, expiry_arg};
use crate::commands::guided::{self, Choice};
use crate::commands::{CredentialGenerateArgs, CredentialsCommand, OutputFormat};

/// The type positional's help, the same for both verbs: every type's word,
/// in picker order.
pub(in crate::commands) const TYPE_HELP: &str =
    "codex, github, claude, claude-token, anthropic, openai, gemini, antigravity or ssh";
pub(in crate::commands) const KEY_FILE_HELP: &str = "OpenSSH private-key file to import, for ssh";
pub(in crate::commands) const YES_HELP: &str = "Confirm reconnecting an existing named credential";
/// `add`'s and `connect`'s one help line: what each of the registry's flows
/// does, since both verbs run every type's own flow.
pub(in crate::commands) const ADD_AND_CONNECT_ABOUT: &str =
    "Sign in, paste a key or token, or set up an SSH key; asks for anything missing at a terminal";

/// `cw credentials add`'s arguments, the same flags as `connect`'s.
#[derive(Debug, Args)]
pub(crate) struct CredentialAddArgs {
    #[arg(value_name = "PROVIDER", value_parser = type_parser(true), help = TYPE_HELP)]
    pub(crate) provider: Option<String>,
    #[arg(long, value_name = "NAME", help = NAME_HELP)]
    pub(crate) name: Option<String>,
    #[arg(long, value_name = "HINT", hide = true)]
    pub(crate) account_hint: Option<String>,
    #[arg(long, value_name = "DATE", value_parser = expiry_arg, help = EXPIRES_AT_HELP)]
    pub(crate) expires_at: Option<u64>,
    #[arg(long, value_name = "PATH", help = KEY_FILE_HELP)]
    pub(crate) key_file: Option<PathBuf>,
    #[arg(short, long, help = YES_HELP)]
    pub(crate) yes: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(skip)]
    pub(crate) guided: bool,
}

/// The words both verbs take: every type's, with `connect`'s help for a
/// sign-in or token, and for `add` the hidden one-release alias
/// `claude-subscription` (#4945).
pub(in crate::commands) fn type_parser(alias: bool) -> PossibleValuesParser {
    let words = CREDENTIAL_TYPES.iter().map(|row| {
        CredentialConnectProviderArg::from_str(row.word, false)
            .ok()
            .and_then(|provider| provider.to_possible_value())
            .unwrap_or_else(|| PossibleValue::new(row.word))
    });
    let alias = alias.then(|| PossibleValue::new(CLAUDE_SUBSCRIPTION_ALIAS).hide(true));
    PossibleValuesParser::new(words.chain(alias))
}

/// The picker both verbs show when no type is named: every type, its label
/// and detail, as the owner approved it on #6286.
pub(in crate::commands) fn choose_missing_type(
    command: &mut CredentialsCommand,
) -> anyhow::Result<()> {
    let word = match command {
        CredentialsCommand::Add(add) if add.provider.is_none() => &mut add.provider,
        CredentialsCommand::Connect(connect)
            if connect.credential_type.is_none() && connect.provider.is_none() =>
        {
            &mut connect.credential_type
        }
        _ => return Ok(()),
    };
    let choices = CREDENTIAL_TYPES
        .iter()
        .map(|row| Choice::new(row.label, row.detail))
        .collect::<Vec<_>>();
    *word = Some(
        CREDENTIAL_TYPES[guided::choose("Which credential?", &choices)?]
            .word
            .into(),
    );
    Ok(())
}

/// The flags both verbs take, with the type's word.
struct Typed {
    word: Option<String>,
    name: Option<String>,
    account_hint: Option<String>,
    expires_at: Option<u64>,
    key_file: Option<PathBuf>,
    yes: bool,
    output: OutputFormat,
    guided: bool,
}

/// Hands an `add` or `connect` of a type to the subcommand whose flow runs
/// it, refusing a flag that flow doesn't take, by the flag and the type. Any
/// other command is unchanged, as is an `add` of a word no type has (the
/// alias, which `add` turns into its `connect` itself) and a `connect`
/// naming no type.
pub(in crate::commands) fn route(command: &mut CredentialsCommand) -> anyhow::Result<()> {
    let typed = match command {
        CredentialsCommand::Add(add) => Typed {
            word: add.provider.take(),
            name: add.name.take(),
            account_hint: add.account_hint.take(),
            expires_at: add.expires_at,
            key_file: add.key_file.take(),
            yes: add.yes,
            output: add.output,
            guided: add.guided,
        },
        CredentialsCommand::Connect(connect) => {
            let word = connect.credential_type.take().or_else(|| {
                connect
                    .provider
                    .map(|p| credential_type_of_arg(p).word.into())
            });
            if word.is_none() {
                return Ok(());
            }
            Typed {
                word,
                name: connect.name.take(),
                account_hint: connect.account_hint.take(),
                expires_at: connect.expires_at,
                key_file: connect.key_file.take(),
                yes: connect.yes,
                output: connect.output,
                guided: connect.guided,
            }
        }
        _ => return Ok(()),
    };
    let row = typed.word.as_deref().and_then(credential_type);
    let Some(row) = row.filter(|row| row.verb == CredentialVerb::Connect) else {
        if let Some(row) = row {
            anyhow::ensure!(!typed.yes, "--yes doesn't apply to {}", row.label);
            anyhow::ensure!(
                typed.output == OutputFormat::Text,
                "--output doesn't apply to {}",
                row.label
            );
            anyhow::ensure!(
                typed.key_file.is_none() || row.flow == CredentialFlow::SshKey,
                "--key-file doesn't apply to {}",
                row.label
            );
        }
        *command = CredentialsCommand::Add(CredentialAddArgs {
            provider: typed.word,
            name: typed.name,
            account_hint: typed.account_hint,
            expires_at: typed.expires_at,
            key_file: typed.key_file,
            yes: typed.yes,
            output: typed.output,
            guided: typed.guided,
        });
        return Ok(());
    };
    anyhow::ensure!(
        typed.key_file.is_none(),
        "--key-file doesn't apply to {}",
        row.label
    );
    // A Claude token's expiry is always one year, which its refusal says.
    anyhow::ensure!(
        typed.expires_at.is_none() || row.flow != CredentialFlow::Paste,
        "a Claude token expires one year after it is saved; --expires-at is not accepted"
    );
    anyhow::ensure!(
        typed.expires_at.is_none(),
        "--expires-at doesn't apply to {}",
        row.label
    );
    anyhow::ensure!(
        typed.account_hint.is_none(),
        "--account-hint doesn't apply to {}",
        row.label
    );
    *command = CredentialsCommand::Connect(CredentialConnectArgs {
        credential_type: None,
        provider: Some(
            CredentialConnectProviderArg::from_str(row.word, false)
                .expect("each connect type is one of connect's flows"),
        ),
        name: typed.name,
        yes: typed.yes,
        output: typed.output,
        key_file: None,
        expires_at: None,
        account_hint: None,
        guided: typed.guided,
    });
    Ok(())
}

/// An SSH key without `--key-file`: at a terminal, the question whether to
/// generate a key, which is `generate ssh`'s, or import a file; without one,
/// a refusal naming both. Whether it asked.
pub(in crate::commands) fn ssh_source(command: &mut CredentialsCommand) -> anyhow::Result<bool> {
    let CredentialsCommand::Add(add) = command else {
        return Ok(false);
    };
    let ssh = add
        .provider
        .as_deref()
        .and_then(credential_type)
        .is_some_and(|row| row.flow == CredentialFlow::SshKey);
    if !ssh || add.key_file.is_some() {
        return Ok(false);
    }
    if !guided::available(OutputFormat::Text) {
        return Err(crate::error_report::with_next_step(
            anyhow::anyhow!("SSH key needs a key file without a terminal"),
            "`cw credentials generate ssh --name NAME`, or pass `--key-file PATH`",
        ));
    }
    let choice = guided::choose(
        "SSH key",
        &[
            Choice::new(
                "Generate a new key",
                "Codewire makes an Ed25519 key and prints its public key",
            ),
            Choice::new(
                "Import a key file",
                "an OpenSSH private-key file on this computer",
            ),
        ],
    )?;
    add.guided = true;
    if choice == 0 {
        *command = CredentialsCommand::Generate(CredentialGenerateArgs {
            provider: Some("ssh".into()),
            name: add.name.take(),
            expires_at: add.expires_at,
            guided: true,
        });
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
