//! `cw credentials --local delete` (#4717 C6). A credential a profile
//! selects is refused with the exact `unset` that frees it. An active one is
//! asked about once, then revoked and deleted, and what its provider still
//! holds is said after, in the sentences the cloud's delete uses too.

use anyhow::Context as _;
use codewire_access::CredentialStatus;
use codewire_local_credentials::LocalCredentialClient;

use super::super::{CredentialDeleteArgs, OutputFormat};
use super::confirm::{self, Change};
use super::output::{self, ProviderAnswer, refusal};
use super::resolve_credential;

pub(super) async fn delete_credential(
    client: &mut LocalCredentialClient,
    args: CredentialDeleteArgs,
) -> anyhow::Result<()> {
    let record = resolve_credential(
        client,
        args.credential
            .as_deref()
            .context("delete requires a credential selector")?,
    )
    .await?;
    let name = &record.metadata.display_name;
    let profiles = client
        .list_profiles()
        .await
        .context("list local profiles before deleting a credential")?;
    let selected = profiles.iter().find_map(|profile| {
        profile
            .profile
            .entries
            .iter()
            .find(|(_, id)| **id == record.metadata.id)
            .map(|(slot, _)| (profile.profile.name.as_str(), slot.as_str()))
    });
    if let Some((profile, slot)) = selected {
        anyhow::bail!(refusal::in_use("local", name, profile, slot));
    }
    let active = record.metadata.status != CredentialStatus::Revoked;
    let change = Change::Delete { active };
    if !confirm::confirm("local", name, change, args.yes, OutputFormat::Text)? {
        return Ok(());
    }
    if active {
        // Codewire's own revoke failing stops here: nothing is deleted.
        client
            .revoke_credential(&record.metadata.id)
            .await
            .context("revoke local credential before deleting it")?;
    }
    let deleted = client.delete_credential(&record.metadata.id).await;
    if active {
        deleted.context(refusal::revoked_not_deleted("local", name))?;
    } else {
        deleted.context("delete local credential")?;
    }
    output::print_done(&output::deleted("local", name));
    // The local placement does not ask a provider yet (#4717 C6, part b2).
    if let Some(line) = output::after_deleted(
        record.metadata.provider.as_str(),
        output::authentication_kind_label(record.metadata.authentication_kind),
        ProviderAnswer::NotAsked,
    ) {
        eprintln!("{line}");
    }
    Ok(())
}
