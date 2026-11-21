//! The placeholders a hosted Sandbox projects on an intercepted epoch (#4001;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception").
//!
//! The set is exactly a local guest's seed's: the `anthropic` slot's, which
//! its API-key and subscription-token forms take as a variable. The sign-in
//! form's and Codex's placeholders travel in their delivered logins, and
//! GitHub keeps its loopback route. The credential service derives the set
//! at an intercepted epoch's admission; orchestration's credential relay
//! carries it from the admission header into the daemon's Open; the daemon
//! projects it. Each reads it with [`ProjectedPlaceholders::from_entries`] or
//! [`ProjectedPlaceholders::from_header`], which accept a whole set or
//! nothing, so no hop forwards part of one.

use std::fmt;

use crate::{AccessError, CapabilitySlot, CredentialPlaceholder};

/// The slots whose placeholders a Sandbox projects, in wire order.
pub const PROJECTED_PLACEHOLDER_SLOTS: [&str; 1] = ["anthropic"];

/// One intercepted epoch's projected placeholders, at most one per slot of
/// [`PROJECTED_PLACEHOLDER_SLOTS`]. `Debug` names the slots, never a value.
#[derive(Clone, Default)]
pub struct ProjectedPlaceholders {
    anthropic: Option<CredentialPlaceholder>,
}

impl ProjectedPlaceholders {
    /// The set of `(slot, placeholder)` entries: each slot projected, at most
    /// once, each placeholder in its exact wire form. Anything else refuses
    /// the whole set.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AccessError> {
        let invalid = AccessError::InvalidField {
            field: "projected credential placeholders",
        };
        let mut set = Self::default();
        for (slot, placeholder) in entries {
            if slot != CapabilitySlot::anthropic().as_str() || set.anthropic.is_some() {
                return Err(invalid);
            }
            set.anthropic =
                Some(CredentialPlaceholder::parse(placeholder).map_err(|_| invalid.clone())?);
        }
        Ok(set)
    }

    /// The set from its admission header's one value: `slot=placeholder`
    /// entries separated by commas, or the empty value for none.
    pub fn from_header(value: &str) -> Result<Self, AccessError> {
        if value.is_empty() {
            return Ok(Self::default());
        }
        let entries = value
            .split(',')
            .map(|entry| entry.split_once('='))
            .collect::<Option<Vec<_>>>()
            .ok_or(AccessError::InvalidField {
                field: "projected credential placeholders",
            })?;
        Self::from_entries(entries)
    }

    /// The `anthropic` slot's placeholder, which the API-key and
    /// subscription-token forms take.
    pub fn with_anthropic(mut self, placeholder: CredentialPlaceholder) -> Self {
        self.anthropic = Some(placeholder);
        self
    }

    pub fn anthropic(&self) -> Option<&CredentialPlaceholder> {
        self.anthropic.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.anthropic.is_none()
    }

    /// Each `(slot, placeholder)`, in wire order.
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, &CredentialPlaceholder)> {
        self.anthropic
            .iter()
            .map(|placeholder| (PROJECTED_PLACEHOLDER_SLOTS[0], placeholder))
    }

    /// The admission header's one value; [`Self::from_header`] reads it back.
    pub fn header_value(&self) -> String {
        self.entries()
            .map(|(slot, placeholder)| format!("{slot}={}", placeholder.as_str()))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether both sets hold the same placeholders, compared in constant
    /// time.
    pub fn ct_eq(&self, other: &Self) -> bool {
        match (&self.anthropic, &other.anthropic) {
            (None, None) => true,
            (Some(left), Some(right)) => left.ct_eq(right),
            _ => false,
        }
    }
}

impl fmt::Debug for ProjectedPlaceholders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.entries().map(|(slot, _)| slot))
            .finish()
    }
}

#[cfg(test)]
mod tests;
