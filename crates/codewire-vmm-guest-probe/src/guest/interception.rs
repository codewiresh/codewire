//! What this boot's managed clients hold when its agent hosts go through the
//! TLS front door (#3999): the seed carries the front door's CA exactly then,
//! and beside it the placeholder for each Anthropic form that takes one, and
//! the `github` slot's while the boot binds GitHub's hosts (#4001).

use codewire_access::Interception;

use super::egress_trust::WORKSPACE_TRUST_BUNDLE_PATH;
use crate::{PlaceholderSlot, Seed};

/// The boot's interception, or `None` when the seed has no egress CA, which
/// leaves every projection exactly as it was. The selected Anthropic form
/// names the placeholder: the subscription-token form's or the API-key
/// form's. The sign-in form takes none here; its login carries one. A GitHub
/// placeholder comes with the workspace's trust bundle, which Git names for
/// `https://github.com/`.
pub(super) fn from_seed(seed: &Seed) -> Option<Interception> {
    seed.egress_ca()?;
    let clients = seed.managed_credential_clients();
    let slot = if clients.anthropic_subscription_token() {
        PlaceholderSlot::AnthropicSubscriptionToken
    } else {
        PlaceholderSlot::AnthropicApiKey
    };
    let find = |wanted: PlaceholderSlot| {
        seed.credential_placeholders()
            .entries()
            .iter()
            .find(|(entry, _)| *entry == wanted)
            .map(|(_, placeholder)| placeholder.clone())
    };
    let placeholder = (!clients.anthropic_sign_in()).then(|| find(slot)).flatten();
    let interception = Interception::new(placeholder);
    let interception = match find(PlaceholderSlot::GitHub) {
        Some(github) => interception.with_github(github, WORKSPACE_TRUST_BUNDLE_PATH),
        None => interception,
    };
    Some(match find(PlaceholderSlot::GeminiApiKey) {
        Some(gemini) => interception.with_gemini(gemini),
        None => interception,
    })
}

#[cfg(test)]
mod tests;
