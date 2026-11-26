//! A local credential's name is unique per provider (#4928): what a command
//! that saves a name needs of an older authority, and how a name is
//! resolved from the store's listing.

use anyhow::Context as _;
use codewire_local_credentials::{CredentialRecord, LocalCredentialClient};

use super::super::CredentialsCommand;
use super::super::credential_input::connect::{CLAUDE_SUBSCRIPTION_ALIAS, provider_id};
use super::super::credential_input::{
    CredentialName, CredentialOperation, NameLookup, NameReading, NamedCredential,
    ParsedCredentialSelector, parse_credential_selector, settle_name,
};
use super::output::{self, authentication_kind_label};

/// The authority a command that saves a name runs against: an older one
/// that can't save the name it gives is replaced, or the command refused
/// while a local VM keeps it serving ([`names_per_provider_needed`]).
pub(super) async fn serving_names_per_provider(
    mut client: LocalCredentialClient,
    operation: &CredentialOperation,
) -> anyhow::Result<LocalCredentialClient> {
    let names_per_provider = codewire_local_credentials::AuthorityFeature::NamesPerProvider;
    if !names_per_provider.served_by(client.info().protocol_version)
        && saves_a_name(operation)
        && let Some(needed_for) = names_per_provider_needed(
            operation,
            &client
                .list_credentials()
                .await
                .context("list local credentials")?,
        )
    {
        drop(client);
        client = super::super::connect_local_credential_authority_serving(
            names_per_provider,
            needed_for,
        )
        .await?;
    }
    Ok(client)
}

/// Whether this command saves a name that another provider's credential
/// already has, which only an authority serving
/// [`AuthorityFeature::NamesPerProvider`] accepts (#4928); and if so, what an
/// older one can't do. Asked only of an older authority. Every other command
/// works with one: names are resolved here, from its listing, and an older
/// store can hold no name two providers share. So an older authority that
/// keeps serving while a local VM runs is replaced, or the command refused,
/// only when the name needs it, never for every new credential.
///
/// [`AuthorityFeature::NamesPerProvider`]: codewire_local_credentials::AuthorityFeature::NamesPerProvider
pub(super) fn names_per_provider_needed(
    operation: &CredentialOperation,
    records: &[CredentialRecord],
) -> Option<&'static str> {
    let (provider, name) = match operation {
        CredentialOperation::Credential(CredentialsCommand::Connect(args)) => (
            provider_id(args.provider?),
            CredentialName::parse(args.name.as_deref()?.trim()),
        ),
        CredentialOperation::Credential(CredentialsCommand::Add(args)) => {
            let provider = match args.provider.as_deref()? {
                CLAUDE_SUBSCRIPTION_ALIAS => "anthropic",
                word => codewire_access::credential_type(word).map_or(word, |row| row.provider),
            };
            (
                provider,
                CredentialName::parse(args.name.as_deref()?.trim()),
            )
        }
        CredentialOperation::Credential(CredentialsCommand::Generate(args))
        | CredentialOperation::GenerateIntoProfile(args, _) => {
            ("ssh", CredentialName::parse(args.name.as_deref()?.trim()))
        }
        CredentialOperation::Credential(CredentialsCommand::Rename(args)) => {
            let renamed = match parse_credential_selector(&args.credential).ok()? {
                ParsedCredentialSelector::Id(id) => records
                    .iter()
                    .find(|record| record.metadata.id == id)?
                    .clone(),
                ParsedCredentialSelector::Name(name) => {
                    select_credential_by_name(records, name, None).ok()?
                }
            };
            return shared_with_another_provider(
                records,
                renamed.metadata.provider.as_str(),
                args.name.trim(),
            )
            .then_some(NAME_ANOTHER_PROVIDER_HAS);
        }
        _ => return None,
    };
    // A reconnect named PROVIDER/NAME keeps the name after the provider.
    let name = name
        .qualified
        .filter(|(prefix, _)| *prefix == provider)
        .map_or(name.text, |(_, name)| name);
    shared_with_another_provider(records, provider, name).then_some(NAME_ANOTHER_PROVIDER_HAS)
}

/// Whether `operation` creates a credential or renames one, the only
/// commands [`names_per_provider_needed`] reads the listing for.
fn saves_a_name(operation: &CredentialOperation) -> bool {
    matches!(
        operation,
        CredentialOperation::Credential(
            CredentialsCommand::Connect(_)
                | CredentialsCommand::Add(_)
                | CredentialsCommand::Generate(_)
                | CredentialsCommand::Rename(_)
        ) | CredentialOperation::GenerateIntoProfile(..)
    )
}

/// What an older authority can't do, after "which can't".
const NAME_ANOTHER_PROVIDER_HAS: &str =
    "give a credential a name another provider's credential has";

fn shared_with_another_provider(records: &[CredentialRecord], provider: &str, name: &str) -> bool {
    records.iter().any(|record| {
        record.metadata.provider.as_str() != provider
            && record.metadata.display_name.eq_ignore_ascii_case(name)
    })
}

/// The credential `selector` names. A name is resolved here, from the
/// store's listing, in its readings (#4928). Within `scope`, the provider a
/// profile slot fixes, a bare name needs no `PROVIDER/`; one that only
/// another provider's credential has is still found, for the slot to refuse
/// in its own words.
pub(super) async fn resolve_credential(
    client: &mut LocalCredentialClient,
    selector: &str,
    scope: Option<&str>,
) -> anyhow::Result<CredentialRecord> {
    match parse_credential_selector(selector)? {
        ParsedCredentialSelector::Id(id) => client
            .get_credential(&id)
            .await
            .with_context(|| format!("get local credential by ID {id}")),
        ParsedCredentialSelector::Name(name) => {
            let records = client
                .list_credentials()
                .await
                .context("list local credentials")?;
            select_credential_by_name(&records, name, scope)
        }
    }
}

pub(super) fn select_credential_by_name(
    records: &[CredentialRecord],
    name: CredentialName<'_>,
    scope: Option<&str>,
) -> anyhow::Result<CredentialRecord> {
    let settle = |scope| settle_name(name.text, local_lookups(records, &name.readings(scope)));
    let found = match settle(scope)? {
        None if scope.is_some() => settle(None)?,
        found => found,
    };
    found.ok_or_else(|| anyhow::anyhow!(output::refusal::not_found("local", name.text)))
}

/// What the listing holds of each reading: a name ignoring case, in its
/// provider when the reading names one.
pub(super) fn local_lookups<'a>(
    records: &[CredentialRecord],
    readings: &[NameReading<'a>],
) -> Vec<(NameReading<'a>, NameLookup<CredentialRecord>)> {
    readings
        .iter()
        .map(|reading| {
            let matches = records
                .iter()
                .filter(|record| {
                    record
                        .metadata
                        .display_name
                        .eq_ignore_ascii_case(reading.name)
                        && reading
                            .provider
                            .is_none_or(|provider| record.metadata.provider.as_str() == provider)
                })
                .cloned()
                .collect();
            (*reading, NameLookup::Matches(matches))
        })
        .collect()
}

impl NamedCredential for CredentialRecord {
    fn credential_id(&self) -> &str {
        self.metadata.id.as_str()
    }

    fn provider_id(&self) -> &str {
        self.metadata.provider.as_str()
    }

    fn credential_name(&self) -> &str {
        &self.metadata.display_name
    }
}

/// A local credential's kind, as messages name it.
pub(super) fn local_kind(record: &CredentialRecord) -> String {
    output::kind_label(
        record.metadata.provider.as_str(),
        authentication_kind_label(record.metadata.authentication_kind),
    )
}
