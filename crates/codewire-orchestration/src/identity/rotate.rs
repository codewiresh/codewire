//! `codewire-orchestration identity rotate`: one idempotent run of the
//! rotation job, under the rotator role. Run it daily; a run that finds
//! nothing due changes nothing, and a stalled job only means signing stays on
//! the current version longer.

use chrono::{DateTime, Utc};

use super::keys::{KeySet, RotationPlan};
use super::transit::{TransitError, TransitKeyClient};

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    /// The key's custody settings differ from their pins. The job changes
    /// nothing and fails, so the drift is seen.
    #[error("the sandbox identity key's configuration has drifted from its pinned custody")]
    Drift,
    #[error(transparent)]
    Transit(#[from] TransitError),
}

/// What one run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RotationOutcome {
    /// `None` until the key's first version is 24 hours old.
    pub signing_version: Option<u32>,
    pub retired_below: Option<u32>,
    pub rotated: bool,
}

/// The OpenBao calls a run makes. [`TransitKeyClient`] in production.
#[async_trait::async_trait]
pub trait RotatableKey: Send + Sync {
    async fn read_key(&self) -> Result<KeySet, TransitError>;
    async fn rotate(&self) -> Result<(), TransitError>;
    async fn raise_minimums(&self, version: u32) -> Result<(), TransitError>;
}

#[async_trait::async_trait]
impl RotatableKey for TransitKeyClient {
    async fn read_key(&self) -> Result<KeySet, TransitError> {
        TransitKeyClient::read_key(self).await
    }
    async fn rotate(&self) -> Result<(), TransitError> {
        TransitKeyClient::rotate(self).await
    }
    async fn raise_minimums(&self, version: u32) -> Result<(), TransitError> {
        TransitKeyClient::raise_minimums(self, version).await
    }
}

pub async fn run(
    key: &dyn RotatableKey,
    now: DateTime<Utc>,
) -> Result<RotationOutcome, RotateError> {
    let key_set = key.read_key().await?;
    if !key_set.custody.is_pinned() {
        return Err(RotateError::Drift);
    }
    let RotationPlan {
        retire_below,
        rotate,
    } = key_set.rotation_plan(now);
    // Retire first: it only removes versions that stopped signing more than
    // 24 hours ago, and never touches the one that signs now.
    if let Some(version) = retire_below {
        key.raise_minimums(version).await?;
    }
    if rotate {
        key.rotate().await?;
    }
    Ok(RotationOutcome {
        signing_version: key_set
            .signing_version(now)
            .ok()
            .map(|version| version.version),
        retired_below: retire_below,
        rotated: rotate,
    })
}

#[cfg(test)]
mod openbao_tests;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::identity::keys::tests::{at, key_read, key_set};

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Read,
        Rotate,
        RaiseMinimums(u32),
    }

    struct Recorded {
        read: serde_json::Value,
        calls: Mutex<Vec<Call>>,
    }

    impl Recorded {
        fn new(read: serde_json::Value) -> Self {
            Self {
                read,
                calls: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<Call> {
            std::mem::take(&mut self.calls.lock().unwrap())
        }
    }

    #[async_trait::async_trait]
    impl RotatableKey for Recorded {
        async fn read_key(&self) -> Result<KeySet, TransitError> {
            self.calls.lock().unwrap().push(Call::Read);
            Ok(key_set(self.read.clone())?)
        }
        async fn rotate(&self) -> Result<(), TransitError> {
            self.calls.lock().unwrap().push(Call::Rotate);
            Ok(())
        }
        async fn raise_minimums(&self, version: u32) -> Result<(), TransitError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RaiseMinimums(version));
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_run_with_nothing_due_only_reads() {
        let key = Recorded::new(key_read(&[(3, "2026-11-01T00:00:00Z")], 3, 3));
        let outcome = run(&key, at("2026-11-14T00:00:00Z")).await.unwrap();
        assert_eq!(
            outcome,
            RotationOutcome {
                signing_version: Some(3),
                ..Default::default()
            }
        );
        assert_eq!(key.calls(), [Call::Read]);
    }

    #[tokio::test]
    async fn a_run_retires_and_rotates_when_both_are_due() {
        // v2 has signed for 30 days and v1 left signing long ago, but the job
        // last ran before v1 could be retired.
        let key = Recorded::new(key_read(
            &[(1, "2026-10-01T00:00:00Z"), (2, "2026-10-02T00:00:00Z")],
            1,
            1,
        ));
        let outcome = run(&key, at("2026-11-02T00:00:00Z")).await.unwrap();
        assert_eq!(
            outcome,
            RotationOutcome {
                signing_version: Some(2),
                retired_below: Some(2),
                rotated: true
            }
        );
        assert_eq!(
            key.calls(),
            [Call::Read, Call::RaiseMinimums(2), Call::Rotate]
        );
    }

    #[tokio::test]
    async fn drifted_custody_fails_the_run_without_changing_the_key() {
        let mut read = key_read(&[(1, "2026-09-01T00:00:00Z")], 1, 1);
        read["exportable"] = json!(true);
        let key = Recorded::new(read);
        assert!(matches!(
            run(&key, at("2026-11-14T00:00:00Z")).await,
            Err(RotateError::Drift)
        ));
        assert_eq!(key.calls(), [Call::Read]);
    }
}
