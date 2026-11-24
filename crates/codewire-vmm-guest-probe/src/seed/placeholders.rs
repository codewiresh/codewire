//! The credential placeholders a boot that intercepts agent hosts gives its
//! agents in place of their credentials (#3999, change 12). A placeholder
//! grants nothing by itself: the TLS front door outside the VM swaps it for
//! the credential on this environment's own requests. They ride in the seed
//! beside the egress CA, only when the CA does, so a selection change, which
//! reboots into a new generation, brings new ones.
//!
//! The region is fixed in the seed: a count, then up to one entry per slot
//! kind, each the kind and the placeholder's 48 ASCII bytes. The rest is
//! zero.

use std::fmt;

use codewire_access::{CREDENTIAL_PLACEHOLDER_LENGTH, CredentialPlaceholder};

use super::SeedError;

/// The slots a placeholder may stand in for. A Claude sign-in's placeholder
/// travels in its delivered login instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlaceholderSlot {
    /// `ANTHROPIC_AUTH_TOKEN`, an Anthropic API key.
    AnthropicApiKey,
    /// `CLAUDE_CODE_OAUTH_TOKEN`, a Claude subscription token.
    AnthropicSubscriptionToken,
    /// The `github` slot: Git's credential helper and `GH_TOKEN`, only while
    /// GitHub's hosts are bound (seed format 12).
    GitHub,
}

impl PlaceholderSlot {
    const ALL: [Self; 3] = [
        Self::AnthropicApiKey,
        Self::AnthropicSubscriptionToken,
        Self::GitHub,
    ];

    fn code(self) -> u8 {
        match self {
            Self::AnthropicApiKey => 1,
            Self::AnthropicSubscriptionToken => 2,
            Self::GitHub => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|slot| slot.code() == code)
    }
}

const ENTRY_LEN: usize = 1 + CREDENTIAL_PLACEHOLDER_LENGTH;
/// The region's fixed size: a count and one entry per slot kind.
pub(super) const PLACEHOLDER_REGION_LEN: usize = 1 + PlaceholderSlot::ALL.len() * ENTRY_LEN;

/// At most one placeholder per slot, in slot order.
#[derive(Clone, Default)]
pub struct SeedPlaceholders(Vec<(PlaceholderSlot, CredentialPlaceholder)>);

impl SeedPlaceholders {
    /// The placeholders for these slots, refusing a slot named twice.
    pub fn new(
        entries: impl IntoIterator<Item = (PlaceholderSlot, CredentialPlaceholder)>,
    ) -> Result<Self, SeedError> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_by_key(|(slot, _)| *slot);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SeedError::InvalidPlaceholders);
        }
        Ok(Self(entries))
    }

    pub fn entries(&self) -> &[(PlaceholderSlot, CredentialPlaceholder)] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn encode_into(&self, region: &mut [u8]) {
        debug_assert_eq!(region.len(), PLACEHOLDER_REGION_LEN);
        region[0] = u8::try_from(self.0.len()).expect("at most one placeholder per slot kind");
        for (index, (slot, placeholder)) in self.0.iter().enumerate() {
            let entry = &mut region[1 + index * ENTRY_LEN..1 + (index + 1) * ENTRY_LEN];
            entry[0] = slot.code();
            entry[1..].copy_from_slice(placeholder.as_str().as_bytes());
        }
    }

    /// The region's placeholders; every byte past the last entry is zero.
    pub(super) fn decode(region: &[u8]) -> Result<Self, SeedError> {
        let count = usize::from(region[0]);
        if count > PlaceholderSlot::ALL.len() {
            return Err(SeedError::InvalidPlaceholders);
        }
        let used = 1 + count * ENTRY_LEN;
        if region[used..].iter().any(|byte| *byte != 0) {
            return Err(SeedError::NonZeroPadding);
        }
        // `used` is one count byte plus whole entries.
        let (entries, _) = region[1..used].as_chunks::<ENTRY_LEN>();
        let entries = entries
            .iter()
            .map(|entry| {
                let slot =
                    PlaceholderSlot::from_code(entry[0]).ok_or(SeedError::InvalidPlaceholders)?;
                let value =
                    std::str::from_utf8(&entry[1..]).map_err(|_| SeedError::InvalidPlaceholders)?;
                let placeholder = CredentialPlaceholder::parse(value)
                    .map_err(|_| SeedError::InvalidPlaceholders)?;
                Ok((slot, placeholder))
            })
            .collect::<Result<Vec<_>, SeedError>>()?;
        Self::new(entries)
    }
}

impl PartialEq for SeedPlaceholders {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|((slot, value), (other_slot, other_value))| {
                    slot == other_slot && value.ct_eq(other_value)
                })
    }
}

impl Eq for SeedPlaceholders {}

impl fmt::Debug for SeedPlaceholders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.0.iter().map(|(slot, _)| slot))
            .finish()
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    /// The wire codes are fixed, and the slots are exactly the registry's
    /// types whose placeholder the environment holds (#6286).
    #[test]
    fn the_slots_and_codes_are_pinned_to_the_registry() {
        let slots = [
            (PlaceholderSlot::AnthropicApiKey, 1, "anthropic"),
            (
                PlaceholderSlot::AnthropicSubscriptionToken,
                2,
                "claude-token",
            ),
            (PlaceholderSlot::GitHub, 3, "github"),
        ];
        assert_eq!(PlaceholderSlot::ALL, slots.map(|(slot, ..)| slot));
        for (slot, code, _) in slots {
            assert_eq!(slot.code(), code);
            assert_eq!(PlaceholderSlot::from_code(code), Some(slot));
        }
        let held: std::collections::BTreeSet<&str> = codewire_access::CREDENTIAL_TYPES
            .iter()
            .filter(|row| {
                matches!(
                    row.agent,
                    codewire_access::AgentHolds::Placeholder(_)
                        | codewire_access::AgentHolds::GitHelper
                )
            })
            .map(|row| row.word)
            .collect();
        assert_eq!(held, slots.map(|(.., word)| word).into());
    }
}
