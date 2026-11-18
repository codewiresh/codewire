//! A boot's seed placeholders, when its agent hosts go through the TLS front
//! door (#3999): asked of the credential authority before the boot starts,
//! so the seed carries them beside the front door's CA.

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, ManagedCredentialClient, ManagedCredentialClients,
};

use super::{EnvironmentRecord, Supervisor, SupervisorError, credential_control_error, v1};

/// The seed's code for each Anthropic form that takes a placeholder.
const API_KEY_SLOT: u32 = 1;
const SUBSCRIPTION_TOKEN_SLOT: u32 = 2;

impl Supervisor {
    /// The placeholder for an intercepting boot's selected Anthropic form,
    /// from the binding it starts with: what that generation's broker leases
    /// carry. None unless the boot `intercept`s, without an Anthropic client,
    /// or for the sign-in form, whose login carries one. An API key or
    /// subscription token without its placeholder refuses the start: the
    /// guest drops the managed base URL whenever it intercepts, so its agents
    /// would have no credential at all.
    pub(super) async fn seed_placeholders(
        &self,
        intercept: bool,
        environment: &EnvironmentRecord,
        generation: u64,
        clients: ManagedCredentialClients,
    ) -> Result<Vec<v1::SeedCredentialPlaceholder>, SupervisorError> {
        if !intercept
            || !clients.contains(ManagedCredentialClient::Anthropic)
            || clients.anthropic_sign_in()
        {
            return Ok(Vec::new());
        }
        let selected = environment
            .access_binding
            .as_ref()
            .ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
        let slot = if clients.anthropic_subscription_token() {
            SUBSCRIPTION_TOKEN_SLOT
        } else {
            API_KEY_SLOT
        };
        let placeholders = self
            .access_control_client()
            .await?
            .environment_credential_placeholders(
                selected,
                generation,
                &[CapabilitySlot::anthropic()],
            )
            .await
            .map_err(credential_control_error)?;
        seed_entries(slot, placeholders)
    }
}

/// The seed's one entry for `slot`, from what the authority granted: exactly
/// one placeholder, or the start is refused.
fn seed_entries(
    slot: u32,
    granted: Vec<(CapabilitySlot, CredentialPlaceholder)>,
) -> Result<Vec<v1::SeedCredentialPlaceholder>, SupervisorError> {
    let Ok([(_, placeholder)]) = <[_; 1]>::try_from(granted) else {
        return Err(SupervisorError::EnvironmentAccessUnavailable);
    };
    Ok(vec![v1::SeedCredentialPlaceholder {
        slot,
        placeholder: placeholder.as_str().to_owned(),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder() -> CredentialPlaceholder {
        CredentialPlaceholder::parse(&format!("cwp1_{}A", "C".repeat(42))).unwrap()
    }

    /// An intercepting boot whose selected form the authority grants no
    /// placeholder never starts with no credential at all.
    #[test]
    fn a_boot_starts_only_with_exactly_one_placeholder_for_its_form() {
        assert!(matches!(
            seed_entries(API_KEY_SLOT, Vec::new()),
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
        let two = vec![
            (CapabilitySlot::anthropic(), placeholder()),
            (CapabilitySlot::anthropic(), placeholder()),
        ];
        assert!(seed_entries(API_KEY_SLOT, two).is_err());
        let entries = seed_entries(
            SUBSCRIPTION_TOKEN_SLOT,
            vec![(CapabilitySlot::anthropic(), placeholder())],
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slot, SUBSCRIPTION_TOKEN_SLOT);
        assert_eq!(entries[0].placeholder, placeholder().as_str());
    }
}
