//! Source selection belongs to the authenticated channel creator, never to a
//! guest request. The binding is immutable for the channel's entire lifetime.

use codewire_workload_secrets::{MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES, ProjectionContext};

use super::*;
use crate::LocalLaunchSecretSelection;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEnvironmentProjectionBinding {
    pub selection: LocalLaunchSecretSelection,
    pub selection_sha256: [u8; 32],
}

impl LocalEnvironmentProjectionBinding {
    pub(crate) fn validate(&self) -> Result<(), LocalCredentialError> {
        self.selection.validate()?;
        if self.selection_sha256 == [0; 32] {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        Ok(())
    }

    pub(crate) fn into_proto(self) -> v1::LocalEnvironmentProjectionBinding {
        v1::LocalEnvironmentProjectionBinding {
            project_id: self.selection.project_id.map(|id| id.to_string()),
            user: self.selection.user,
            overridden_keys: self.selection.overridden_keys.into_iter().collect(),
            reserved_keys: self.selection.reserved_keys.into_iter().collect(),
            selection_sha256: self.selection_sha256.to_vec(),
        }
    }

    pub(crate) fn from_proto(value: v1::LocalEnvironmentProjectionBinding) -> Result<Self, Status> {
        let project_id = value
            .project_id
            .map(|id| {
                Uuid::parse_str(&id)
                    .ok()
                    .filter(|parsed| !parsed.is_nil() && parsed.to_string() == id)
                    .ok_or_else(projection_denied)
            })
            .transpose()?;
        // Reject duplicate keys instead of silently normalizing a wire request.
        let overridden_count = value.overridden_keys.len();
        let reserved_count = value.reserved_keys.len();
        let selection = LocalLaunchSecretSelection {
            project_id,
            user: value.user,
            overridden_keys: value.overridden_keys.into_iter().collect(),
            reserved_keys: value.reserved_keys.into_iter().collect(),
        };
        if overridden_count != selection.overridden_keys.len()
            || reserved_count != selection.reserved_keys.len()
        {
            return Err(projection_denied());
        }
        let result = Self {
            selection,
            selection_sha256: value
                .selection_sha256
                .try_into()
                .map_err(|_| projection_denied())?,
        };
        result.validate().map_err(|_| projection_denied())?;
        Ok(result)
    }
}

impl<S: ProtectedStore + 'static> BrokerLeaseRpc<S> {
    pub(super) async fn project_bound_environment(
        &self,
        request: v1::BrokerEnvironmentProjectionRequest,
    ) -> Result<v1::BrokerEnvironmentProjectionResponse, Status> {
        let binding = self.projection.clone().ok_or_else(projection_denied)?;
        if !Uuid::parse_str(&request.request_id)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == request.request_id)
            || request.selection_sha256 != binding.selection_sha256
        {
            return Err(projection_denied());
        }
        let recipient: [u8; 32] = request
            .recipient_public_key
            .try_into()
            .map_err(|_| projection_denied())?;
        codewire_workload_secrets::validate_projection_recipient(recipient)
            .map_err(|_| projection_denied())?;
        let environment_id =
            Uuid::parse_str(self.environment_id.as_str()).map_err(|_| projection_denied())?;
        let context = ProjectionContext {
            environment_id: *environment_id.as_bytes(),
            operation_generation: self.environment_generation,
            selection_sha256: binding.selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        context
            .validate_at(crate::unix_millis().map_err(|_| projection_denied())?)
            .map_err(|_| projection_denied())?;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(projection_denied)?;
        let permit = Arc::clone(&self.projection_operations)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("environment projection authority is busy"))?;
        let authority = Arc::clone(&self.authority);
        let lifetime = Arc::clone(&self.refresh_lifetime);
        let completed_context = context.clone();
        // The blocking worker owns its lifetime guard even if the async caller
        // disappears. Channel loss revokes delivery; no late worker can release
        // ciphertext after that epoch is closed or extend the original deadline.
        let sealed_projection = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            let _permit = permit;
            if lifetime.closed.load(Ordering::Acquire) {
                return Err(projection_denied());
            }
            let sealed = authority
                .seal_workload_projection(&binding.selection, &context, recipient)
                .map_err(|_| projection_denied())?;
            if lifetime.closed.load(Ordering::Acquire) {
                return Err(projection_denied());
            }
            Ok(sealed)
        })
        .await
        .map_err(|_| Status::unavailable("environment projection authority is unavailable"))??;
        if self.refresh_lifetime.closed.load(Ordering::Acquire) {
            return Err(projection_denied());
        }
        completed_context
            .validate_at(crate::unix_millis().map_err(|_| projection_denied())?)
            .map_err(|_| projection_denied())?;
        Ok(v1::BrokerEnvironmentProjectionResponse { sealed_projection })
    }
}

impl<S> LocalCredentialBrokerLeaseClient<S> {
    /// Request ciphertext for the sources already bound by the trusted owner.
    /// This client has no raw-value method and cannot change that selection.
    pub async fn project_environment(
        &self,
        request_id: Uuid,
        recipient_public_key: [u8; 32],
        selection_sha256: [u8; 32],
        deadline_unix_ms: u64,
    ) -> Result<Vec<u8>, BrokerLeaseChannelError> {
        if request_id.is_nil() {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let context = ProjectionContext {
            environment_id: *Uuid::parse_str(self.environment_id.as_str())
                .map_err(|_| BrokerLeaseChannelError::InvalidRequest)?
                .as_bytes(),
            operation_generation: self.environment_generation,
            selection_sha256,
            deadline_unix_ms,
        };
        context
            .validate_at(crate::unix_millis().map_err(|_| BrokerLeaseChannelError::Unavailable)?)
            .map_err(|_| BrokerLeaseChannelError::InvalidRequest)?;
        let response = self
            .inner
            .clone()
            .project_environment(v1::BrokerEnvironmentProjectionRequest {
                request_id: request_id.to_string(),
                recipient_public_key: recipient_public_key.to_vec(),
                selection_sha256: selection_sha256.to_vec(),
                deadline_unix_ms,
            })
            .await
            .map_err(map_client_status)?
            .into_inner()
            .sealed_projection;
        if response.is_empty() || response.len() > MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        context
            .validate_at(crate::unix_millis().map_err(|_| BrokerLeaseChannelError::Unavailable)?)
            .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?;
        Ok(response)
    }
}

fn projection_denied() -> Status {
    Status::permission_denied("environment projection was denied")
}

#[cfg(test)]
mod tests;
