//! What this boot's managed clients hold when its agent hosts go through the
//! TLS front door (#3999): the seed carries the front door's CA exactly then,
//! and beside it the placeholder for each Anthropic form that takes one.

use codewire_access::Interception;

use crate::{PlaceholderSlot, Seed};

/// The boot's interception, or `None` when the seed has no egress CA, which
/// leaves every projection exactly as it was. The selected Anthropic form
/// names the placeholder: the subscription-token form's or the API-key
/// form's. The sign-in form takes none here; its login carries one.
pub(super) fn from_seed(seed: &Seed) -> Option<Interception> {
    seed.egress_ca()?;
    let clients = seed.managed_credential_clients();
    let slot = if clients.anthropic_subscription_token() {
        PlaceholderSlot::AnthropicSubscriptionToken
    } else {
        PlaceholderSlot::AnthropicApiKey
    };
    let placeholder = (!clients.anthropic_sign_in())
        .then(|| {
            seed.credential_placeholders()
                .entries()
                .iter()
                .find(|(entry, _)| *entry == slot)
                .map(|(_, placeholder)| placeholder.clone())
        })
        .flatten();
    Some(Interception::new(placeholder))
}

#[cfg(test)]
mod tests;
