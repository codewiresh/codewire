//! An epoch's host-bound secrets (#4003; docs/dev/SECRETS-AND-
//! CREDENTIALS.md, "The swap" steps 1 and 2).
//!
//! The grants come from the runtime authority at the epoch's admission: the
//! secrets the Pod's first bind, or a local VM boot's sealed record,
//! recorded that its selected sources hold, evaluated under the
//! projection's authority, never from a frame. Each is kept with the
//! placeholder its record derives under the environment's application-secret
//! key, the one the environment was projected.
//!
//! Each lease rereads the secret's row through the authority and checks it
//! against the record, under an authority decision at most a minute old, as
//! a credential's lease is admitted. Its value is decrypted only for a
//! lease that passed, and reused only within the epoch for exactly the
//! version that lease read ([`SecretVersion`]), for at most two minutes.

use codewire_access::FirstBindSecret;
use codewire_platform_credentials::SecretVersion;
use zeroize::Zeroizing;

use super::{PlatformBrokerLeaseProvider, PlatformRuntimeAuthority};
use crate::BrokerLeaseError;
use crate::bound_secret::{BoundSecretLeaseError, BoundSecretRow, EpochBoundSecret};
use crate::timing::{self, Phase};

/// What an epoch admitted of its bound secrets.
pub(crate) enum EpochBoundSecrets {
    /// Its grants, each with the placeholder its record derives.
    Granted(Vec<EpochBoundSecret>),
    /// It has grants, and its environment's key couldn't be read: no
    /// placeholder can be told from another value, so every request on a
    /// bound host is refused as unavailable rather than forwarded.
    KeyUnavailable,
}

impl EpochBoundSecrets {
    pub(crate) fn none() -> Self {
        Self::Granted(Vec::new())
    }

    pub(crate) fn granted(&self) -> Result<&[EpochBoundSecret], BoundSecretLeaseError> {
        match self {
            Self::Granted(secrets) => Ok(secrets),
            Self::KeyUnavailable => Err(BoundSecretLeaseError::Unavailable),
        }
    }
}

/// The value cache's key for `secret` at `value_version`.
fn version(secret: &FirstBindSecret, value_version: u64) -> SecretVersion {
    SecretVersion {
        path: secret.path.clone(),
        key: secret.key.clone(),
        binding_id: secret.binding_id.clone(),
        binding_generation: secret.binding_generation,
        value_version,
    }
}

fn lease_error(error: BrokerLeaseError) -> BoundSecretLeaseError {
    match error {
        BrokerLeaseError::Unavailable => BoundSecretLeaseError::Unavailable,
        _ => BoundSecretLeaseError::Denied,
    }
}

impl<A: PlatformRuntimeAuthority> PlatformBrokerLeaseProvider<A> {
    /// The bound secrets an epoch serves, read once at its admission: an
    /// intercepted hosted epoch's, from its Pod's first bind, and a local
    /// VM's delegation with a front door's, from its boot's sealed record.
    /// An epoch that derives no placeholders has none: projection refuses a
    /// bound secret by name without the key. An authority that can't answer
    /// refuses the admission, so an epoch never serves part of its grants.
    pub(crate) async fn admitted_bound_secrets(
        &self,
    ) -> Result<EpochBoundSecrets, BrokerLeaseError> {
        if self.placeholders.is_none() {
            return Ok(EpochBoundSecrets::none());
        }
        let records = timing::timed(Phase::Grants, self.authority.bound_secrets())
            .await
            .map_err(super::runtime_error)?;
        if records.is_empty() {
            return Ok(EpochBoundSecrets::none());
        }
        let Some(key) = self.application_secret_key().await else {
            return Ok(EpochBoundSecrets::KeyUnavailable);
        };
        let environment = &self.session.context.environment_id;
        let mut granted = Vec::with_capacity(records.len());
        for record in records {
            match record.placeholder(&key, environment) {
                Some(placeholder) => granted.push(EpochBoundSecret {
                    record,
                    placeholder,
                }),
                // Its projection was refused by name for the same reason.
                None => tracing::warn!(
                    environment_id = environment.as_str(),
                    key = record.key.as_str(),
                    "a recorded bound secret derives no placeholder and is not served"
                ),
            }
        }
        Ok(EpochBoundSecrets::Granted(granted))
    }

    /// `secret`, when it is one of this epoch's grants.
    fn granted_secret(&self, secret: &FirstBindSecret) -> Result<(), BoundSecretLeaseError> {
        let granted = self
            .bound
            .as_ref()
            .ok_or(BoundSecretLeaseError::Denied)?
            .granted()?;
        if granted.iter().any(|granted| granted.record == *secret) {
            Ok(())
        } else {
            Err(BoundSecretLeaseError::Denied)
        }
    }

    /// The runtime's authority, from the epoch's decision while it is young
    /// (as a credential's lease), or read again without one.
    async fn current_authority(&self) -> Result<(), BoundSecretLeaseError> {
        match &self.decision {
            Some(epoch) => self.authority_holds(epoch).await,
            None => self.session().await.map(drop),
        }
        .map_err(lease_error)
    }

    /// A lease slot of the service's budget, held until the lease returns.
    async fn budget(
        &self,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, BoundSecretLeaseError> {
        match &self.leases {
            Some(leases) => leases
                .acquire(self.session.identity_expires_at_unix)
                .await
                .map(Some)
                .map_err(lease_error),
            None => Ok(None),
        }
    }

    /// A refused or failed lease reuses nothing of the secret again.
    fn forget_secret<T>(
        &self,
        secret: &FirstBindSecret,
        result: Result<T, BoundSecretLeaseError>,
    ) -> Result<T, BoundSecretLeaseError> {
        if result.is_err()
            && let Some(material) = &self.material
        {
            material.evict_secret(&secret.path, &secret.key);
        }
        result
    }

    pub(super) async fn bound_secret_row(
        &self,
        secret: &FirstBindSecret,
        host: &str,
    ) -> Result<BoundSecretRow, BoundSecretLeaseError> {
        self.granted_secret(secret)?;
        let _budget = self.budget().await?;
        self.current_authority().await?;
        let row = timing::timed(Phase::Record, self.authority.bound_secret_row(secret, host)).await;
        self.forget_secret(secret, row)
    }

    pub(super) async fn bound_secret_value(
        &self,
        secret: &FirstBindSecret,
        host: &str,
        row: &BoundSecretRow,
    ) -> Result<Zeroizing<Vec<u8>>, BoundSecretLeaseError> {
        self.granted_secret(secret)?;
        let _budget = self.budget().await?;
        self.current_authority().await?;
        // The row this request's lease just read admitted exactly this
        // version; a value read for it within the epoch's window is reused.
        if let Some(value) = self
            .material
            .as_ref()
            .and_then(|material| material.get_secret(&version(secret, row.value_version)))
        {
            return Ok(value);
        }
        let read = timing::timed(
            Phase::MaterialRead,
            self.authority.bound_secret_value(secret, host),
        )
        .await;
        let (value_version, value) = self.forget_secret(secret, read)?;
        // The KEK unwrap may outlive the authority it was admitted under.
        self.current_authority().await?;
        if let Some(material) = &self.material {
            material.fill_secret(&version(secret, value_version), &value);
        }
        Ok(value)
    }
}
