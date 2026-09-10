//! Platform application sources beside a local provider profile. The parent
//! owns one admitted source stream; the child keeps its existing local broker.

use codewire_workload_secrets::{
    MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES, ProjectionContext, validate_projection_recipient,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::*;

pub(in crate::broker_channel) struct PlatformSourceConnection {
    selection_sha256: [u8; 32],
    input: mpsc::Sender<Result<bridge::CredentialBridgeGuestMessage, Status>>,
    output: PlatformCredentialOutput,
}

// An interrupted exchange must not leave a response on a reusable stream.
// Closing this same epoch also stops the inherited server and its local child;
// retained blocking operations still own their existing drain guards.
struct InvalidateOnDrop<S: ProtectedStore> {
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    armed: bool,
}

impl<S: ProtectedStore> Drop for InvalidateOnDrop<S> {
    fn drop(&mut self) {
        if self.armed {
            self.lifetime.close();
        }
    }
}

impl<S: ProtectedStore + 'static> BrokerLeaseRpc<S> {
    pub(in crate::broker_channel) async fn admit_platform_sources(
        &self,
        ready: bridge::CredentialBridgeReady,
    ) -> Result<(), Status> {
        let (binding, connector) = self.platform.lock().await.take().ok_or_else(unavailable)?;
        let mut invalidation = InvalidateOnDrop {
            lifetime: Arc::clone(&self.refresh_lifetime),
            armed: true,
        };
        if binding.selection.profile.is_some()
            || !ready_matches(&self.environment_id, self.environment_generation, &ready)
        {
            return Err(denied());
        }
        binding.validate()?;
        let _operation = self.refresh_lifetime.acquire().ok_or_else(unavailable)?;
        let composer = composition::ProjectionComposer::for_binding(self, &binding)?;
        let selection_sha256 = binding.selection_sha256;
        let (input, receiver) = mpsc::channel(1);
        let remaining: PlatformCredentialInput = Box::pin(ReceiverStream::new(receiver));
        let remaining = match &composer {
            Some(composer) => composer.input(remaining),
            None => remaining,
        };
        let deadline = Instant::now() + PLATFORM_DELEGATION_SETUP_TIMEOUT;
        let setup = connector.connect(binding, ready, remaining, deadline);
        let output = tokio::select! {
            result = tokio::time::timeout_at(deadline, setup) => {
                result.map_err(|_| expired())??
            }
            _ = self.refresh_lifetime.closed() => return Err(unavailable()),
        };
        let output = match composer {
            Some(composer) => composer.output(output),
            None => output,
        };
        let mut slot = self.platform_sources.lock().await;
        if slot.is_some()
            || Instant::now() >= deadline
            || self.refresh_lifetime.closed.load(Ordering::Acquire)
        {
            return Err(unavailable());
        }
        *slot = Some(PlatformSourceConnection {
            selection_sha256,
            input,
            output,
        });
        invalidation.armed = false;
        Ok(())
    }

    pub(in crate::broker_channel) async fn project_platform_sources(
        &self,
        request: v1::BrokerEnvironmentProjectionRequest,
    ) -> Result<v1::BrokerEnvironmentProjectionResponse, Status> {
        // Take the whole connection before awaiting. Concurrent callers cannot
        // queue against another launch, and cancellation drops both directions.
        // Do not hold projection_operations: the composer acquires that permit
        // only while its retained blocking inventory/material workers execute.
        let (mut connection, context, deadline) = {
            let mut slot = self.platform_sources.try_lock().map_err(|_| busy())?;
            let connection = slot.as_ref().ok_or_else(unavailable)?;
            let (context, deadline) = self.source_context(&request, connection.selection_sha256)?;
            (slot.take().ok_or_else(unavailable)?, context, deadline)
        };
        let mut invalidation = InvalidateOnDrop {
            lifetime: Arc::clone(&self.refresh_lifetime),
            armed: true,
        };
        let _operation = self.refresh_lifetime.acquire().ok_or_else(unavailable)?;
        let request_id = request.request_id.clone();
        let frame = bridge::CredentialBridgeGuestMessage {
            payload: Some(
                bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(
                    bridge::EnvironmentProjectionRequest {
                        request_id: request.request_id,
                        recipient_public_key: request.recipient_public_key,
                        selection_sha256: request.selection_sha256,
                        deadline_unix_ms: request.deadline_unix_ms,
                        local_inventories: Vec::new(),
                    },
                ),
            ),
        };
        let exchange = async {
            connection
                .input
                .send(Ok(frame))
                .await
                .map_err(|_| unavailable())?;
            connection.output.next().await.ok_or_else(unavailable)?
        };
        let frame = tokio::select! {
            result = tokio::time::timeout_at(deadline, exchange) => {
                result.map_err(|_| expired())??
            }
            _ = self.refresh_lifetime.closed() => return Err(unavailable()),
        };
        // Only one complete, matching projection is legal on this connection.
        // In mixed mode the composer has already consumed both fragments; no
        // HTTP, SSH, partial fragment or unrelated response can reach the child.
        if !valid_host_frame(&frame) {
            return Err(denied());
        }
        let Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(response)) =
            frame.payload
        else {
            return Err(denied());
        };
        if response.request_id != request_id {
            return Err(denied());
        }
        let result = match response.result {
            Some(bridge::environment_projection_response::Result::SealedProjection(
                sealed_projection,
            )) if !sealed_projection.is_empty()
                && sealed_projection.len() <= MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES =>
            {
                Ok(v1::BrokerEnvironmentProjectionResponse { sealed_projection })
            }
            Some(bridge::environment_projection_response::Result::Failure(_)) => Err(denied()),
            _ => return Err(denied()),
        };
        let mut slot = self.platform_sources.lock().await;
        context
            .validate_at(crate::unix_millis().map_err(|_| unavailable())?)
            .map_err(|_| expired())?;
        if slot.is_some() || self.refresh_lifetime.closed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        *slot = Some(connection);
        invalidation.armed = false;
        result
    }

    fn source_context(
        &self,
        request: &v1::BrokerEnvironmentProjectionRequest,
        selection_sha256: [u8; 32],
    ) -> Result<(ProjectionContext, Instant), Status> {
        if !Uuid::parse_str(&request.request_id)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == request.request_id)
            || request.selection_sha256 != selection_sha256
        {
            return Err(denied());
        }
        let recipient = request
            .recipient_public_key
            .as_slice()
            .try_into()
            .map_err(|_| denied())?;
        validate_projection_recipient(recipient).map_err(|_| denied())?;
        let context = ProjectionContext {
            environment_id: *Uuid::parse_str(self.environment_id.as_str())
                .map_err(|_| denied())?
                .as_bytes(),
            operation_generation: self.environment_generation,
            selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        let now = crate::unix_millis().map_err(|_| unavailable())?;
        context.validate_at(now).map_err(|_| denied())?;
        Ok((
            context,
            Instant::now() + Duration::from_millis(request.deadline_unix_ms - now),
        ))
    }
}

fn denied() -> Status {
    Status::permission_denied("environment projection was denied")
}

fn unavailable() -> Status {
    Status::unavailable("platform application source connection is unavailable")
}

fn expired() -> Status {
    Status::deadline_exceeded("platform application source deadline expired")
}

fn busy() -> Status {
    Status::resource_exhausted("environment projection authority is busy")
}

#[cfg(test)]
mod tests;
