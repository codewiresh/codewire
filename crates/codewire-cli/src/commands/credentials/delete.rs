//! `cw credentials --local delete` (#4717 C6). An active credential is
//! asked about once, then revoked and deleted as one step the store refuses
//! before any change while a profile or a local VM's profile revision
//! selects it (#6128); `cw` names what holds it and what frees it, read
//! before the question in the common case, so nobody is asked first. What
//! its provider still holds is said after, in the sentences the cloud's
//! delete uses too.

use std::collections::BTreeMap;
use std::future::Future;

use anyhow::Context as _;
use codewire_access::{CredentialId, CredentialStatus};
use codewire_local_credentials::{
    AuthorityFeature, CredentialRecord, LocalCredentialClient, LocalProviderRevocation,
    LocalProviderRevocationFailure as Failure, LocalProviderRevocationOutcome as Outcome,
};

use super::super::{CredentialDeleteArgs, OutputFormat};
use super::confirm::{self, Change};
use super::output::{self, ProviderAnswer, refusal};
use super::resolve_credential;

pub(super) async fn delete_credential(
    client: &mut LocalCredentialClient,
    args: CredentialDeleteArgs,
) -> anyhow::Result<()> {
    delete_credential_naming_vms(client, args, local_vm_names).await
}

/// [`delete_credential`], with where the local VMs' names come from: a
/// test names its own, never the computer's.
pub(super) async fn delete_credential_naming_vms<N, F>(
    client: &mut LocalCredentialClient,
    args: CredentialDeleteArgs,
    vm_names: N,
) -> anyhow::Result<()>
where
    N: Fn() -> F,
    F: Future<Output = BTreeMap<String, String>>,
{
    let record = resolve_credential(
        client,
        args.credential
            .as_deref()
            .context("delete requires a credential selector")?,
        None,
    )
    .await?;
    let name = &record.metadata.display_name;
    let active = record.metadata.status != CredentialStatus::Revoked;
    let gate = AuthorityFeature::DeleteGate;
    if active && !gate.served_by(client.info().protocol_version) {
        *client = super::super::connect_local_credential_authority_serving(
            gate,
            "check that nothing uses a credential before it revokes it for a delete",
        )
        .await?;
    }
    // Read only, so the common case is refused before the question; the
    // store's gate below stays the guarantee.
    if let Some(refusal) = held(client, &record, &vm_names).await {
        return Err(refusal);
    }
    let change = Change::Delete { active };
    if !confirm::confirm("local", name, change, args.yes, OutputFormat::Text)? {
        return Ok(());
    }
    let deleted = if active {
        client
            .delete_credential_revoking_first(&record.metadata.id)
            .await
            .map(|reported| provider_answer(reported.as_ref()))
    } else {
        client
            .delete_credential(&record.metadata.id)
            .await
            .map(|()| ProviderAnswer::NotAsked)
    };
    let answer = match deleted {
        Ok(answer) => answer,
        Err(status) => return Err(refused(client, &record, status, &vm_names).await),
    };
    output::print_done(&output::deleted("local", name));
    if let Some(line) = output::after_deleted(
        record.metadata.provider.as_str(),
        output::authentication_kind_label(record.metadata.authentication_kind),
        answer,
    ) {
        eprintln!("{line}");
    }
    Ok(())
}

/// What a failed delete says. The store refused before any change while
/// something holds the credential, which [`held`] names. A credential
/// the delete revoked and still lists is finished by running it again; one
/// it no longer lists is pending delete, which the store finishes when it
/// next starts.
async fn refused<N, F>(
    client: &mut LocalCredentialClient,
    record: &CredentialRecord,
    status: tonic::Status,
    vm_names: &N,
) -> anyhow::Error
where
    N: Fn() -> F,
    F: Future<Output = BTreeMap<String, String>>,
{
    let name = &record.metadata.display_name;
    let failed = anyhow::Error::from(status);
    if record.metadata.status != CredentialStatus::Revoked
        && let Ok(listed) = client.list_credentials().await
    {
        match listed
            .iter()
            .find(|now| now.metadata.id == record.metadata.id)
        {
            None => return failed.context(refusal::revoked_pending_removal(name)),
            Some(now) if now.metadata.status == CredentialStatus::Revoked => {
                return failed.context(refusal::revoked_not_deleted(
                    "local",
                    record.metadata.provider.as_str(),
                    name,
                ));
            }
            Some(_) => {}
        }
    }
    held(client, record, vm_names)
        .await
        .unwrap_or_else(|| failed.context("delete local credential"))
}

/// The refusal naming what holds the credential and what frees it: a
/// profile that selects it now, with its `unset`, or local VMs made with an
/// earlier revision, with the `cw update` that moves each on. None when
/// nothing does, or the holders can't be read.
async fn held<N, F>(
    client: &mut LocalCredentialClient,
    record: &CredentialRecord,
    vm_names: &N,
) -> Option<anyhow::Error>
where
    N: Fn() -> F,
    F: Future<Output = BTreeMap<String, String>>,
{
    let name = &record.metadata.display_name;
    match holders(client, &record.metadata.id).await {
        Ok(Holders {
            profile: Some((profile, slot)),
            ..
        }) => Some(anyhow::anyhow!(refusal::in_use(
            "local", name, &profile, &slot
        ))),
        Ok(Holders { vms, .. }) if !vms.is_empty() => {
            let names = vm_names().await;
            let vms: Vec<(String, String)> = vms
                .into_iter()
                .map(|(id, profile)| (names.get(&id).cloned().unwrap_or(id), profile))
                .collect();
            Some(anyhow::anyhow!(refusal::held_by_vms("local", name, &vms)))
        }
        _ => None,
    }
}

/// What holds a credential, for naming in a refused delete; the store
/// decides. A local VM keeps the profile revision it was made with until
/// `cw update` moves it, so an `unset` doesn't free it.
#[derive(Default)]
struct Holders {
    /// A profile whose current revision selects it, and the slot.
    profile: Option<(String, String)>,
    /// Each local VM's environment ID and the name of the profile whose
    /// earlier revision it is bound to.
    vms: Vec<(String, String)>,
}

async fn holders(
    client: &mut LocalCredentialClient,
    id: &CredentialId,
) -> Result<Holders, tonic::Status> {
    let profiles = client.list_profiles().await?;
    let profile_name = |profile_id: &codewire_access::AccessProfileId| {
        profiles
            .iter()
            .find(|profile| profile.profile.id == *profile_id)
            .map(|profile| profile.profile.name.to_string())
    };
    let mut found = Holders {
        profile: profiles.iter().find_map(|profile| {
            profile
                .profile
                .entries
                .iter()
                .find(|(_, selected)| *selected == id)
                .map(|(slot, _)| (profile.profile.name.to_string(), slot.as_str().to_owned()))
        }),
        ..Holders::default()
    };
    for record in client.list_environment_access_bindings().await? {
        let binding = record.binding;
        let revisions = client.list_profile_revisions(&binding.profile_id).await?;
        let selects = revisions.iter().any(|revision| {
            revision.profile.revision == binding.profile_revision
                && revision
                    .profile
                    .entries
                    .values()
                    .any(|selected| selected == id)
        });
        if selects {
            let profile = profile_name(&binding.profile_id).unwrap_or_default();
            found
                .vms
                .push((binding.environment_id.to_string(), profile));
        }
    }
    Ok(found)
}

/// The local VMs' names by environment ID; none when the local VM runtime
/// was never set up or can't be read.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn local_vm_names() -> BTreeMap<String, String> {
    use super::super::native::{native_environments, native_state_exists};
    let listed = async {
        if !native_state_exists()? {
            return anyhow::Ok(Vec::new());
        }
        native_environments().await
    }
    .await;
    listed
        .unwrap_or_default()
        .into_iter()
        .map(|environment| (environment.id, environment.name))
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn local_vm_names() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// Whether an authority at `protocol_version` asks the provider. One from
/// before `ProviderRevocation` revokes without asking, and `cw` says the
/// provider wasn't asked.
pub(super) fn authority_asks_provider(protocol_version: u32) -> bool {
    AuthorityFeature::ProviderRevocation.served_by(protocol_version)
}

/// What the authority reported the provider said; unset means not asked.
/// The same answers as the cloud's (#4908): a token Codewire couldn't read
/// to send means the provider wasn't asked.
pub(super) fn provider_answer(reported: Option<&LocalProviderRevocation>) -> ProviderAnswer {
    use output::NotConfirmedBecause as Because;
    let Some(reported) = reported else {
        return ProviderAnswer::NotAsked;
    };
    match Outcome::try_from(reported.outcome) {
        Ok(Outcome::Confirmed) => ProviderAnswer::Confirmed,
        Ok(Outcome::Failed) => {
            ProviderAnswer::NotConfirmed(match Failure::try_from(reported.failure) {
                Ok(Failure::NotRead) => return ProviderAnswer::NotAsked,
                Ok(Failure::Refused) => {
                    Because::Refused(u16::try_from(reported.http_status).unwrap_or(0))
                }
                Ok(Failure::Unreadable) => Because::Unreadable,
                Ok(Failure::Expired) => Because::Expired,
                _ => Because::Unreachable,
            })
        }
        _ => ProviderAnswer::NotAsked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reported(outcome: Outcome, failure: Failure, http_status: u32) -> LocalProviderRevocation {
        LocalProviderRevocation {
            outcome: outcome.into(),
            failure: failure.into(),
            http_status,
        }
    }

    #[test]
    fn every_reported_outcome_and_failure_maps_to_its_answer() {
        assert!(matches!(provider_answer(None), ProviderAnswer::NotAsked));
        assert!(matches!(
            provider_answer(Some(&reported(Outcome::Confirmed, Failure::Unspecified, 0))),
            ProviderAnswer::Confirmed
        ));
        assert!(matches!(
            provider_answer(Some(&reported(
                Outcome::NotAvailable,
                Failure::Unspecified,
                0
            ))),
            ProviderAnswer::NotAsked
        ));
        assert!(matches!(
            provider_answer(Some(&reported(Outcome::Failed, Failure::NotRead, 0))),
            ProviderAnswer::NotAsked
        ));
        use output::NotConfirmedBecause as Because;
        for (failure, http_status, because) in [
            (Failure::Refused, 400, Because::Refused(400)),
            (Failure::Refused, 70_000, Because::Refused(0)),
            (Failure::Unreadable, 0, Because::Unreadable),
            (Failure::Expired, 0, Because::Expired),
            (Failure::Unavailable, 0, Because::Unreachable),
        ] {
            assert!(
                matches!(
                    provider_answer(Some(&reported(Outcome::Failed, failure, http_status))),
                    ProviderAnswer::NotConfirmed(said) if said == because
                ),
                "{failure:?}"
            );
        }
    }

    #[test]
    fn an_authority_before_provider_revocation_revokes_without_asking() {
        let since = AuthorityFeature::ProviderRevocation.since();
        assert!(!authority_asks_provider(since - 1));
        assert!(authority_asks_provider(since));
        // What such a delete then says of a ChatGPT sign-in.
        let line = output::at_provider("openai", "oauth", ProviderAnswer::NotAsked).unwrap();
        assert!(line.contains("stays valid"), "{line}");
    }
}
