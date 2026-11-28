//! A local VM's host-bound secrets on its broker's lease channel (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap" steps 1 and 2).
//!
//! The grants are the boot's record, carried in the channel's immutable
//! projection binding, kept only for a set its selection holds and a key
//! the environment doesn't set itself, each with the placeholder its record
//! derives. A lease names a secret by its recorded path and key and is
//! checked against the channel's own record and selection, never against
//! anything the frame carries beside those names.

use codewire_access::{EpochBoundSecret, FirstBindSecret};
use zeroize::Zeroizing;

use super::projection::{record_from_proto, record_to_proto};
use super::*;
use crate::workload_secret::BoundSecretLease;
use crate::{BoundSecretLeaseRefusal, LocalLaunchSecretSelection};

/// What a broker child was granted of its boot's bound secrets.
#[derive(Debug)]
pub(super) enum Grants {
    Granted(Vec<EpochBoundSecret>),
    /// It has grants, and the authority couldn't load the key their
    /// placeholders derive under.
    KeyUnavailable,
}

impl Default for Grants {
    fn default() -> Self {
        Self::Granted(Vec::new())
    }
}

/// A lease the authority answered: the secret's binding now, its value's
/// version, and the value when it was asked for.
pub struct LeasedBoundSecret {
    pub binding: codewire_access::StoredBinding,
    pub value_version: u64,
    pub value: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for LeasedBoundSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LeasedBoundSecret")
            .field("binding", &self.binding)
            .field("value_version", &self.value_version)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl<S: ProtectedStore + 'static> BrokerLeaseRpc<S> {
    /// The record this channel's boot made, and the selection it serves.
    fn recorded(&self) -> Option<(LocalLaunchSecretSelection, Vec<FirstBindSecret>)> {
        let binding = self.projection.as_ref()?;
        let record = binding.bound_secrets.clone()?;
        Some((binding.selection.clone(), record))
    }

    pub(super) async fn bound_secret_grants(&self) -> Result<v1::BoundSecretGrants, Status> {
        let Some((selection, record)) = self.recorded().filter(|(_, record)| !record.is_empty())
        else {
            return Ok(v1::BoundSecretGrants::default());
        };
        let authority = Arc::clone(&self.authority);
        let environment = self.environment_id.clone();
        let grants = tokio::task::spawn_blocking(move || {
            authority.bound_secret_grants(&selection, &record, &environment)
        })
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        Ok(match grants {
            Some(grants) => v1::BoundSecretGrants {
                grants: grants
                    .into_iter()
                    .map(|grant| v1::BoundSecretGrant {
                        placeholder: grant.placeholder.as_str().to_owned(),
                        record: Some(record_to_proto(grant.record)),
                    })
                    .collect(),
                key_unavailable: false,
            },
            None => v1::BoundSecretGrants {
                grants: Vec::new(),
                key_unavailable: true,
            },
        })
    }

    pub(super) async fn lease_recorded_secret(
        &self,
        request: v1::BoundSecretLeaseRequest,
    ) -> Result<v1::BoundSecretLeaseResponse, Status> {
        let (selection, record) = self.recorded().ok_or_else(denied)?;
        let recorded = record
            .into_iter()
            .find(|secret| secret.is(&request.path, &request.key))
            .ok_or_else(denied)?;
        let authority = Arc::clone(&self.authority);
        let lease = tokio::task::spawn_blocking(move || {
            authority.lease_bound_secret(&selection, &recorded, &request.host, request.value)
        })
        .await
        .map_err(|_| unavailable())?
        .map_err(|error| match audit_decision_for_error(&error) {
            BrokerLeaseAuditDecision::Unavailable => unavailable(),
            _ => denied(),
        })?;
        Ok(match lease {
            Ok(BoundSecretLease {
                binding,
                value_version,
                value,
            }) => v1::BoundSecretLeaseResponse {
                refusal: v1::BoundSecretLeaseRefusal::Unspecified as i32,
                binding: serde_json::to_string(&binding).map_err(|_| unavailable())?,
                value_version,
                // Moved, not copied: the lease's buffer leaves empty, and the
                // response zeroizes the value when it drops.
                value: value
                    .map(|mut value| std::mem::take(&mut *value))
                    .unwrap_or_default(),
            },
            Err(refusal) => v1::BoundSecretLeaseResponse {
                refusal: match refusal {
                    BoundSecretLeaseRefusal::NotBoundToHost => {
                        v1::BoundSecretLeaseRefusal::NotBoundToHost
                    }
                    BoundSecretLeaseRefusal::BindingChanged => {
                        v1::BoundSecretLeaseRefusal::BindingChanged
                    }
                    BoundSecretLeaseRefusal::Deleted => v1::BoundSecretLeaseRefusal::Deleted,
                } as i32,
                binding: String::new(),
                value_version: 0,
                value: Vec::new(),
            },
        })
    }
}

fn denied() -> Status {
    Status::permission_denied("bound secret lease was denied")
}

fn unavailable() -> Status {
    Status::unavailable("bound secret lease authority is unavailable")
}

impl<S> LocalCredentialBrokerLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    /// Ask once, as the channel connects, what it was granted of its boot's
    /// bound secrets. Each grant's placeholder must read back. A channel
    /// whose authority has no such call has none.
    pub(super) async fn load_bound_secret_grants(&mut self) -> Result<(), BrokerLeaseChannelError> {
        let response = match self
            .inner
            .get_bound_secret_grants(v1::BoundSecretGrantsRequest {})
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => return Ok(()),
            Err(status) => return Err(map_client_status(status)),
        };
        let grants = if response.key_unavailable {
            if !response.grants.is_empty() {
                return Err(BrokerLeaseChannelError::InvalidResponse);
            }
            Grants::KeyUnavailable
        } else {
            Grants::Granted(
                response
                    .grants
                    .into_iter()
                    .map(|grant| {
                        let record = record_from_proto(
                            grant
                                .record
                                .ok_or(BrokerLeaseChannelError::InvalidResponse)?,
                        );
                        let placeholder =
                            codewire_access::SecretPlaceholder::parse(&grant.placeholder)
                                .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?;
                        Ok(EpochBoundSecret {
                            record,
                            placeholder,
                        })
                    })
                    .collect::<Result<_, BrokerLeaseChannelError>>()?,
            )
        };
        self.bound_secrets = Arc::new(grants);
        Ok(())
    }

    /// This channel's grants, or `None` when the authority couldn't load
    /// the key their placeholders derive under.
    pub fn bound_secret_grants(&self) -> Option<&[EpochBoundSecret]> {
        match self.bound_secrets.as_ref() {
            Grants::Granted(grants) => Some(grants),
            Grants::KeyUnavailable => None,
        }
    }

    /// One lease of `secret`, one of this channel's grants, for a request
    /// to `host`; with `value`, its value too.
    pub async fn lease_bound_secret(
        &self,
        secret: &FirstBindSecret,
        host: &str,
        value: bool,
    ) -> Result<Result<LeasedBoundSecret, BoundSecretLeaseRefusal>, BrokerLeaseChannelError> {
        let mut response = self
            .inner
            .clone()
            .lease_bound_secret(v1::BoundSecretLeaseRequest {
                path: secret.path.clone(),
                key: secret.key.clone(),
                host: host.to_owned(),
                value,
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        let refusal = match v1::BoundSecretLeaseRefusal::try_from(response.refusal) {
            Ok(v1::BoundSecretLeaseRefusal::Unspecified) => None,
            Ok(v1::BoundSecretLeaseRefusal::NotBoundToHost) => {
                Some(BoundSecretLeaseRefusal::NotBoundToHost)
            }
            Ok(v1::BoundSecretLeaseRefusal::BindingChanged) => {
                Some(BoundSecretLeaseRefusal::BindingChanged)
            }
            Ok(v1::BoundSecretLeaseRefusal::Deleted) => Some(BoundSecretLeaseRefusal::Deleted),
            Err(_) => return Err(BrokerLeaseChannelError::InvalidResponse),
        };
        if let Some(refusal) = refusal {
            return Ok(Err(refusal));
        }
        let binding = serde_json::from_str(&response.binding)
            .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?;
        let leased_value = Zeroizing::new(std::mem::take(&mut response.value));
        if value == leased_value.is_empty() {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(Ok(LeasedBoundSecret {
            binding,
            value_version: response.value_version,
            value: value.then_some(leased_value),
        }))
    }
}
#[cfg(test)]
mod tests;
