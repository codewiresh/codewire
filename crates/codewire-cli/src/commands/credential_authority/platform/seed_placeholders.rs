//! A platform boot's seed placeholders (#4001): one unary call, as the
//! selection's creator, with the selection the boot's delegation opens with.
//! No placeholder is ever logged or put in an error.

use codewire_access::{CapabilitySlot, CredentialPlaceholder};
use codewire_client::{
    ClientError, CodewireClient, CredentialDelegationOpen, EnvironmentCredentialPlaceholdersRequest,
};
use tonic::Status;

use super::client_error;

/// The placeholders the platform answers for `slots`: only slots asked for,
/// each at most once, each a well-formed placeholder.
pub(super) async fn ask(
    client: &CodewireClient,
    selection: CredentialDelegationOpen,
    slots: &[CapabilitySlot],
) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status> {
    let response = client
        .environment_credential_placeholders(EnvironmentCredentialPlaceholdersRequest {
            selection: Some(selection).into(),
            capability_slots: slots.iter().map(|slot| slot.as_str().to_owned()).collect(),
            ..Default::default()
        })
        .await
        .map_err(seed_error)?;
    answered(
        slots,
        response
            .placeholders
            .into_iter()
            .map(|entry| (entry.capability_slot, entry.placeholder)),
    )
}

fn answered(
    slots: &[CapabilitySlot],
    entries: impl Iterator<Item = (String, String)>,
) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status> {
    let invalid = || Status::internal("the platform answered invalid credential placeholders");
    let mut answered: Vec<(CapabilitySlot, CredentialPlaceholder)> = Vec::new();
    for (slot, placeholder) in entries {
        let slot = CapabilitySlot::parse(slot).map_err(|_| invalid())?;
        if !slots.contains(&slot) || answered.iter().any(|(seen, _)| seen == &slot) {
            return Err(invalid());
        }
        let placeholder = CredentialPlaceholder::parse(&placeholder).map_err(|_| invalid())?;
        answered.push((slot, placeholder));
    }
    Ok(answered)
}

/// The platform's rate limit keeps its code, so the boot's log can say so;
/// every other failure maps as the delegation's does.
fn seed_error(error: ClientError) -> Status {
    if error.code() == codewire_client::ErrorCode::ResourceExhausted {
        return Status::resource_exhausted("platform credential placeholders rate limited");
    }
    client_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder() -> String {
        format!("cwp1_{}A", "C".repeat(42))
    }

    fn entry(slot: &str) -> (String, String) {
        (slot.to_owned(), placeholder())
    }

    #[test]
    fn only_requested_slots_are_accepted_once_each() {
        let asked = [CapabilitySlot::anthropic(), CapabilitySlot::github()];
        let both = answered(&asked, [entry("github"), entry("anthropic")].into_iter()).unwrap();
        assert_eq!(
            both.iter()
                .map(|(slot, _)| slot.clone())
                .collect::<Vec<_>>(),
            [CapabilitySlot::github(), CapabilitySlot::anthropic()]
        );
        assert!(answered(&asked, std::iter::empty()).unwrap().is_empty());
        for refused in [
            vec![entry("codex")],
            vec![entry("anthropic"), entry("anthropic")],
            vec![("anthropic".to_owned(), "not-a-placeholder".to_owned())],
        ] {
            let status = answered(&asked, refused.into_iter()).unwrap_err();
            assert_eq!(status.code(), tonic::Code::Internal);
            assert!(!status.message().contains("cwp1_"));
        }
    }
}
