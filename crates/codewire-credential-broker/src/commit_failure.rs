//! A refresh publication that did not succeed (#5539).

use crate::BrokerRefreshError;

/// A publication that did not succeed. It hands the attempt's permit back
/// when the placement can still record the attempt's failure with it, so a
/// failed publish ends that one refresh rather than the epoch (#5539).
pub struct CommitFailure<P> {
    /// `None` when the publication consumed the permit.
    pub started: Option<P>,
    pub error: BrokerRefreshError,
}

impl<P> CommitFailure<P> {
    /// The publication left the permit unspent.
    pub fn returned(started: P, error: BrokerRefreshError) -> Self {
        Self {
            started: Some(started),
            error,
        }
    }

    /// The publication spent the permit, so this attempt's failure can't be
    /// recorded through it.
    pub fn consumed(error: BrokerRefreshError) -> Self {
        Self {
            started: None,
            error,
        }
    }
}

impl<P> std::fmt::Display for CommitFailure<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl<P> std::error::Error for CommitFailure<P> {}

impl<P> From<BrokerRefreshError> for CommitFailure<P> {
    fn from(error: BrokerRefreshError) -> Self {
        Self::consumed(error)
    }
}

impl<P> std::fmt::Debug for CommitFailure<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitFailure")
            .field("returned", &self.started.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// [`valid_bundle`] for a bundle's own bytes, which it takes, leaving them
/// empty.
#[cfg(feature = "platform")]
pub(crate) fn taken_bundle<P>(
    started: P,
    bytes: &mut Vec<u8>,
) -> Result<(P, codewire_protected_store::ProtectedValue), CommitFailure<P>> {
    valid_bundle(
        started,
        codewire_protected_store::ProtectedValue::new(std::mem::take(bytes)),
    )
}

/// `value`, or the permit handed back with an invalid-bundle refusal: the
/// bundle failed before publication could spend the permit.
#[cfg(feature = "platform")]
pub(crate) fn valid_bundle<P, V, E>(
    started: P,
    value: Result<V, E>,
) -> Result<(P, V), CommitFailure<P>> {
    match value {
        Ok(value) => Ok((started, value)),
        Err(_) => Err(CommitFailure::returned(
            started,
            BrokerRefreshError::InvalidResponse,
        )),
    }
}
