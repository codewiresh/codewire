//! `cw credentials --local delete` (#4717 C6). A credential a profile
//! selects is refused with the exact `unset` that frees it. An active one is
//! asked about once, then revoked and deleted, and what its provider still
//! holds is said after, in the sentences the cloud's delete uses too.

use anyhow::Context as _;
use codewire_access::CredentialStatus;
use codewire_local_credentials::{
    AuthorityFeature, LocalCredentialClient, LocalProviderRevocation,
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
    let record = resolve_credential(
        client,
        args.credential
            .as_deref()
            .context("delete requires a credential selector")?,
        None,
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
    let mut answer = ProviderAnswer::NotAsked;
    if active {
        // Codewire's own revoke failing stops here: nothing is deleted. An
        // authority that serves it also asks the provider (#4717).
        if authority_asks_provider(client.info().protocol_version) {
            let (_, reported) = client
                .revoke_credential_at_provider(&record.metadata.id)
                .await
                .context("revoke local credential before deleting it")?;
            answer = provider_answer(reported.as_ref());
        } else {
            client
                .revoke_credential(&record.metadata.id)
                .await
                .context("revoke local credential before deleting it")?;
        }
    }
    let deleted = client.delete_credential(&record.metadata.id).await;
    if active {
        deleted.context(refusal::revoked_not_deleted(
            "local",
            record.metadata.provider.as_str(),
            name,
        ))?;
    } else {
        deleted.context("delete local credential")?;
    }
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
