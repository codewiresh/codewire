//! What a request that ended unknown did, from the Store observed after it
//! (#4518). Its effect was dispatched but no receipt came back, so only the
//! selection now in the Store can say whether it took. The Store is observed
//! at the selection before the effect, or at exactly the one the effect
//! selects; anything else, a pending selection or an inconsistent Store, says
//! nothing, and the request stays unresolved.

use super::execute;
use super::model::{RuntimeEffect, RuntimePhase};
use super::owner::RuntimeRequest;
use super::wire::{ExpectedSelection, ObservedSelection};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Resolution {
    /// The Store holds the selection from before the effect.
    Unchanged,
    /// The Store holds the selection the effect makes.
    Applied,
}

impl Resolution {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Applied => "applied",
        }
    }
}

/// The resolution of `request` given the Store `observed` now, or `None`
/// when the request did not end unknown or the observation decides nothing.
pub(super) fn resolution(
    request: &RuntimeRequest,
    observed: &ObservedSelection,
) -> Option<Resolution> {
    if request.phase != RuntimePhase::Unknown || observed.pending || !observed.consistent {
        return None;
    }
    let seen = observed.expected().ok()?;
    let before = execute::expected(request);
    if seen == before {
        return Some(Resolution::Unchanged);
    }
    let target = match request.effect? {
        RuntimeEffect::Bootstrap => request.mutation.bootstrap_identity.as_ref()?,
        RuntimeEffect::Update | RuntimeEffect::Rollback => &request.mutation.target_identity,
        // Neither changes the selection.
        RuntimeEffect::Staging | RuntimeEffect::Cleanup => return None,
    };
    (Some(seen) == selected(&before, &target.sha256)).then_some(Resolution::Applied)
}

/// The selection a successful selecting effect leaves, as the role's
/// `selected_reply` checks it: selecting the current one changes nothing.
fn selected(before: &ExpectedSelection, target: &str) -> Option<ExpectedSelection> {
    let changed = before.current.as_deref() != Some(target);
    Some(ExpectedSelection {
        generation: before.generation.checked_add(u64::from(changed))?,
        current: Some(target.to_owned()),
        previous: if changed {
            before.current.clone()
        } else {
            before.previous.clone()
        },
    })
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod tests;
