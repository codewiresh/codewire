//! Native-owner projection composition. This owner never opens launch values;
//! it adds its selected local inventory and joins authenticated sealed outputs.

use std::collections::BTreeMap;

use codewire_daemon_proto::projection::{decode_platform_inventories, encode_local_inventories};
use codewire_project::PlatformProjectionSelection;
use codewire_workload_secrets::{
    MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES, ProjectionCompositionPlan, ProjectionContext,
    ProjectionSourceInventory, compose_environment_projection, validate_projection_recipient,
};
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::*;
use crate::broker_channel::projection_permit;
use crate::{
    LocalCredentialAuthority, LocalEnvironmentProjectionBinding, PlatformCredentialBinding,
};

pub(super) struct ProjectionComposer<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    local: LocalEnvironmentProjectionBinding,
    platform: PlatformProjectionSelection,
    environment_id: [u8; 16],
    generation: u64,
    // Derived once from immutable selected sources, never from a request or
    // response. In mixed mode an ordinary sealed single is always denied.
    mixed: bool,
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    operations: Arc<Semaphore>,
    pending: Mutex<BTreeMap<String, Pending>>,
}

#[derive(Clone)]
struct Pending {
    request_id: Uuid,
    recipient: [u8; 32],
    context: ProjectionContext,
    local_inventories: Vec<ProjectionSourceInventory>,
    cancelled: bool,
}

impl<S: ProtectedStore + 'static> ProjectionComposer<S> {
    pub(super) fn for_binding(
        rpc: &BrokerLeaseRpc<S>,
        platform: &PlatformCredentialBinding,
    ) -> Result<Option<Arc<Self>>, Status> {
        let Some(local) = &rpc.projection else {
            return Ok(None);
        };
        local.validate().map_err(|_| denied())?;
        platform.validate()?;
        platform
            .validate_local_projection(local)
            .map_err(|_| denied())?;
        let environment = Uuid::parse_str(rpc.environment_id.as_str()).map_err(|_| denied())?;
        Ok(Some(Arc::new(Self {
            authority: Arc::clone(&rpc.authority),
            local: local.clone(),
            platform: platform.selection.clone(),
            environment_id: *environment.as_bytes(),
            generation: rpc.environment_generation,
            mixed: !platform.selection.source_identities().is_empty(),
            lifetime: Arc::clone(&rpc.refresh_lifetime),
            operations: Arc::clone(&rpc.projection_operations),
            pending: Mutex::new(BTreeMap::new()),
        })))
    }

    pub(super) fn input(
        self: &Arc<Self>,
        input: PlatformCredentialInput,
    ) -> PlatformCredentialInput {
        let composer = Arc::clone(self);
        Box::pin(input.then(move |frame| {
            let composer = Arc::clone(&composer);
            async move { composer.prepare(frame?).await }
        }))
    }

    pub(super) fn output(
        self: &Arc<Self>,
        output: PlatformCredentialOutput,
    ) -> PlatformCredentialOutput {
        let composer = Arc::clone(self);
        Box::pin(output.then(move |frame| {
            let composer = Arc::clone(&composer);
            async move { composer.complete(frame?).await }
        }))
    }

    async fn prepare(
        self: Arc<Self>,
        mut frame: bridge::CredentialBridgeGuestMessage,
    ) -> Result<bridge::CredentialBridgeGuestMessage, Status> {
        use bridge::credential_bridge_guest_message::Payload;
        if self.lifetime.closed.load(Ordering::Acquire) {
            return Err(denied());
        }
        let request_id = match &frame.payload {
            Some(Payload::EnvironmentProjection(request)) => &request.request_id,
            Some(Payload::Request(request)) => &request.request_id,
            Some(Payload::Ssh(request)) => &request.request_id,
            Some(Payload::Cancel(cancel)) => {
                if let Some(pending) = self.pending.lock().await.get_mut(&cancel.request_id) {
                    pending.cancelled = true;
                }
                return Ok(frame);
            }
            _ => return Err(denied()),
        };
        if self.pending.lock().await.contains_key(request_id) {
            return Err(denied());
        }
        let Some(Payload::EnvironmentProjection(request)) = &mut frame.payload else {
            return Ok(frame);
        };
        if !request.local_inventories.is_empty()
            || request.selection_sha256 != self.local.selection_sha256
        {
            return Err(denied());
        }
        let request_id = Uuid::parse_str(&request.request_id).map_err(|_| denied())?;
        if request_id.is_nil() || request_id.to_string() != request.request_id {
            return Err(denied());
        }
        let recipient: [u8; 32] = request
            .recipient_public_key
            .as_slice()
            .try_into()
            .map_err(|_| denied())?;
        validate_projection_recipient(recipient).map_err(|_| denied())?;
        let context = ProjectionContext {
            environment_id: self.environment_id,
            operation_generation: self.generation,
            selection_sha256: self.local.selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        self.live(&context)?;
        if self.pending.lock().await.len() >= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
        {
            return Err(Status::resource_exhausted(
                "environment projection authority is busy",
            ));
        }
        let local_inventories = if self.mixed {
            let permit = projection_permit(&self.operations, context.deadline_unix_ms).await?;
            let operation = self.lifetime.acquire().ok_or_else(denied)?;
            let owner = Arc::clone(&self);
            let context = context.clone();
            tokio::task::spawn_blocking(move || {
                let _operation = operation;
                let _permit = permit;
                owner.live(&context)?;
                let inventory = owner
                    .authority
                    .inventory_workload_projection(&owner.local.selection)
                    .map_err(|_| denied())?;
                owner.live(&context)?;
                Ok::<_, Status>(inventory)
            })
            .await
            .map_err(|_| denied())??
        } else {
            Vec::new()
        };
        if self.mixed {
            request.local_inventories =
                encode_local_inventories(&local_inventories).map_err(|_| denied())?;
        }
        self.live(&context)?;
        self.pending.lock().await.insert(
            request.request_id.clone(),
            Pending {
                request_id,
                recipient,
                context,
                local_inventories,
                cancelled: false,
            },
        );
        Ok(frame)
    }

    async fn complete(
        self: Arc<Self>,
        mut frame: bridge::CredentialBridgeHostMessage,
    ) -> Result<bridge::CredentialBridgeHostMessage, Status> {
        let Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(response)) =
            &mut frame.payload
        else {
            return Ok(frame);
        };
        let pending = self
            .pending
            .lock()
            .await
            .get(&response.request_id)
            .cloned()
            .ok_or_else(denied)?;
        use bridge::environment_projection_response::Result as Output;
        if matches!(response.result, Some(Output::Failure(_))) {
            self.pending.lock().await.remove(&response.request_id);
            return Ok(frame);
        }
        self.live(&pending.context)?;
        if pending.cancelled {
            return Err(denied());
        }
        let (platform_fragment, inventories) = match response.result.take() {
            Some(Output::Composition(composition)) if self.mixed => {
                if composition.sealed_platform_fragment.is_empty()
                    || composition.sealed_platform_fragment.len()
                        > MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES
                {
                    return Err(denied());
                }
                let platform = decode_platform_inventories(&composition.platform_inventories)
                    .map_err(|_| denied())?;
                let expected = self.platform.source_identities();
                if !platform
                    .iter()
                    .map(|inventory| (inventory.source, &inventory.source_identity))
                    .eq(expected
                        .iter()
                        .map(|(source, identity)| (*source, identity)))
                {
                    return Err(denied());
                }
                let mut inventories = pending.local_inventories;
                inventories.extend(platform);
                inventories.sort_by_key(|inventory| inventory.source);
                ProjectionCompositionPlan::new(
                    &pending.context,
                    *pending.request_id.as_bytes(),
                    pending.recipient,
                    &inventories,
                    &self.platform.ordinary_keys,
                    &self.platform.reserved_keys,
                    now()?,
                )
                .map_err(|_| denied())?;
                (Some(composition.sealed_platform_fragment), inventories)
            }
            Some(Output::SealedProjection(bytes))
                if !self.mixed
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES =>
            {
                // A platform-profile/local-app-only selection has no remote
                // application sources. Its normal empty projection acknowledges
                // current remote admission; it is NEVER forwarded as local data.
                (None, Vec::new())
            }
            _ => return Err(denied()),
        };
        let permit = projection_permit(&self.operations, pending.context.deadline_unix_ms).await?;
        let operation = self.lifetime.acquire().ok_or_else(denied)?;
        let owner = Arc::clone(&self);
        let context = pending.context;
        let completed_context = context.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            let _permit = permit;
            owner.live(&context)?;
            let sealed = if let Some(platform) = platform_fragment {
                let local = owner
                    .authority
                    .seal_workload_projection_fragment(
                        &owner.local.selection,
                        &context,
                        pending.recipient,
                        *pending.request_id.as_bytes(),
                        &inventories,
                    )
                    .map_err(|_| denied())?;
                compose_environment_projection(&local, &platform).map_err(|_| denied())?
            } else {
                owner
                    .authority
                    .seal_workload_projection(&owner.local.selection, &context, pending.recipient)
                    .map_err(|_| denied())?
            };
            owner.live(&context)?;
            Ok::<_, Status>(sealed)
        })
        .await
        .map_err(|_| denied())??;
        self.live(&completed_context)?;
        if self
            .pending
            .lock()
            .await
            .remove(&response.request_id)
            .is_none_or(|pending| pending.cancelled)
        {
            return Err(denied());
        }
        response.result = Some(Output::SealedProjection(sealed));
        Ok(frame)
    }

    fn live(&self, context: &ProjectionContext) -> Result<(), Status> {
        if self.lifetime.closed.load(Ordering::Acquire) {
            return Err(denied());
        }
        context.validate_at(now()?).map_err(|_| denied())
    }
}

fn now() -> Result<u64, Status> {
    crate::unix_millis().map_err(|_| denied())
}
fn denied() -> Status {
    Status::permission_denied("environment projection composition denied")
}

#[cfg(test)]
mod tests;
