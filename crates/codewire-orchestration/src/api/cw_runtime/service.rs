//! Public operations over one immutable, authenticated Pod channel. Upload
//! cancellation cannot create an owner; after admission an owned bounded task
//! completes or records uncertainty independently of the caller's transport.
use std::time::Duration;

use buffa::Message as _;
use codewire_cw_release::identity::canonical_json;
use codewire_daemon_bridge::drain::Restart;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use futures_util::{Stream, StreamExt as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::execute::{self, PlatformBackend};
use super::intake::{self, Candidate};
use super::model::{
    CapturedBindingFacts, RuntimeAction, RuntimeMutation, invalid_request, unavailable,
};
use super::owner::{Admission, RuntimeJournal, RuntimeRequest};
use super::wire::{self, Correlation, ExpectedSelection, ObservedSelection};
use super::{CapturedPlatformCwRuntime, PlatformCwRuntimeIncarnation, capture_platform_cw_runtime};
use crate::api::ApiState;
use crate::worker::workspace_binding::live_cw_runtime_binding;

const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const DRAINING: &str =
    "Codewire is restarting the server that took this cw runtime request; send it again";

pub(super) struct Intent {
    incarnation: PlatformCwRuntimeIncarnation,
    mutation: RuntimeMutation,
}

pub(super) fn coordinates(org: &str, env: &str) -> AppResult<()> {
    if org.is_empty() || org.len() > 128 || org.chars().any(char::is_control) {
        return Err(invalid_request());
    }
    wire::uuid(env)?;
    Ok(())
}

fn selection_intent(
    org: &str,
    env: &str,
    incarnation: &proto::EnvironmentCwRuntimeIncarnation,
    selection: &proto::EnvironmentCwRuntimeExpectation,
) -> AppResult<(PlatformCwRuntimeIncarnation, ExpectedSelection)> {
    coordinates(org, env)?;
    let incarnation = wire::incarnation(incarnation)?;
    if incarnation.organization_id != org || incarnation.environment_id != env {
        return Err(invalid_request());
    }
    Ok((incarnation, wire::expectation(selection)?))
}

pub(super) fn update_intent(header: &proto::UpdateEnvironmentCwRuntimeHeader) -> AppResult<Intent> {
    if !header.__buffa_unknown_fields.is_empty() || header.encoded_len() as usize > wire::MAX_FRAME
    {
        return Err(invalid_request());
    }
    let (incarnation, selection) = selection_intent(
        &header.org_id,
        &header.environment_id,
        header
            .expected_incarnation
            .as_option()
            .ok_or_else(invalid_request)?,
        header
            .expected_selection
            .as_option()
            .ok_or_else(invalid_request)?,
    )?;
    let target = wire::identity(header.identity.as_option().ok_or_else(invalid_request)?)?;
    let bootstrap = header
        .bootstrap_identity
        .as_option()
        .map(wire::identity)
        .transpose()?;
    let mutation = wire::mutation(
        &header.request_id,
        RuntimeAction::Update,
        &selection,
        target,
        bootstrap,
    )?;
    Ok(Intent {
        incarnation,
        mutation,
    })
}

pub(super) fn rollback_intent(
    request: &proto::RollbackEnvironmentCwRuntimeRequest,
) -> AppResult<Intent> {
    if !request.__buffa_unknown_fields.is_empty()
        || request.encoded_len() as usize > wire::MAX_FRAME
    {
        return Err(invalid_request());
    }
    let (incarnation, selection) = selection_intent(
        &request.org_id,
        &request.environment_id,
        request
            .expected_incarnation
            .as_option()
            .ok_or_else(invalid_request)?,
        request
            .expected_selection
            .as_option()
            .ok_or_else(invalid_request)?,
    )?;
    let target = wire::identity(request.identity.as_option().ok_or_else(invalid_request)?)?;
    let mutation = wire::mutation(
        &request.request_id,
        RuntimeAction::Rollback,
        &selection,
        target,
        None,
    )?;
    Ok(Intent {
        incarnation,
        mutation,
    })
}

pub(super) fn chunk(request: proto::UpdateEnvironmentCwRuntimeRequest) -> AppResult<Vec<u8>> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    match request.payload {
        Some(proto::update_environment_cw_runtime_request::Payload::Chunk(bytes))
            if !bytes.is_empty() && bytes.len() <= wire::MAX_CHUNK =>
        {
            Ok(bytes)
        }
        _ => Err(invalid_request()),
    }
}

pub async fn update<S>(
    state: ApiState,
    user: AuthUser,
    mut requests: S,
) -> AppResult<proto::UpdateEnvironmentCwRuntimeResponse>
where
    S: Stream<Item = AppResult<proto::UpdateEnvironmentCwRuntimeRequest>> + Unpin,
{
    let first = tokio::time::timeout(HEADER_TIMEOUT, requests.next())
        .await
        .map_err(|_| invalid_request())?
        .ok_or_else(invalid_request)??;
    if !first.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    let header = match first.payload {
        Some(proto::update_environment_cw_runtime_request::Payload::Header(header)) => header,
        _ => return Err(invalid_request()),
    };
    let intent = update_intent(&header)?;
    // Authorize the current operator and capture the one original incarnation
    // before accepting server disk work. Capture is read-only; no command is
    // issued until the complete candidate is admitted below.
    let captured = capture_platform_cw_runtime(&state, &user, &intent.incarnation).await?;
    let chunks = requests.map(|request| request.and_then(chunk));
    // No journal admission, daemon command or bootstrap until exact EOF and
    // full static-musl/record/identity admission through the same held file.
    let candidate = intake::receive(
        intent.mutation.target_identity.clone(),
        chunks,
        state.drain.signal(Restart::Deadline),
    )
    .await?;
    let request = mutation(state, user, intent, captured, Some(candidate)).await?;
    Ok(proto::UpdateEnvironmentCwRuntimeResponse {
        operation: Some(wire::proto_operation(&request)?).into(),
        ..Default::default()
    })
}

pub async fn rollback(
    state: ApiState,
    user: AuthUser,
    request: proto::RollbackEnvironmentCwRuntimeRequest,
) -> AppResult<proto::RollbackEnvironmentCwRuntimeResponse> {
    let intent = rollback_intent(&request)?;
    let captured = capture_platform_cw_runtime(&state, &user, &intent.incarnation).await?;
    let request = mutation(state, user, intent, captured, None).await?;
    Ok(proto::RollbackEnvironmentCwRuntimeResponse {
        operation: Some(wire::proto_operation(&request)?).into(),
        ..Default::default()
    })
}

fn correlation(captured: &CapturedPlatformCwRuntime, request_id: Uuid) -> AppResult<Correlation> {
    let facts = CapturedBindingFacts::from(&captured.row);
    let bytes = canonical_json(&facts).map_err(|_| unavailable())?;
    if bytes.len() > wire::MAX_FRAME {
        return Err(unavailable());
    }
    Ok(Correlation {
        request_id,
        pod_uid: wire::uuid(&captured.incarnation().pod_uid)?,
        binding_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

pub(super) fn admit_observation(
    intent: &Intent,
    supported: bool,
    bootstrap: Option<&codewire_cw_release::identity::CwPayloadIdentity>,
    selection: &ObservedSelection,
) -> AppResult<()> {
    let expected = ExpectedSelection {
        generation: intent.mutation.expected_store_generation,
        current: intent.mutation.expected_current_sha256.clone(),
        previous: intent.mutation.expected_previous_sha256.clone(),
    };
    if !supported || selection.pending || !selection.consistent || selection.expected()? != expected
    {
        return Err(super::model::conflict());
    }
    if intent.mutation.expected_store_generation == 0
        && bootstrap != intent.mutation.bootstrap_identity.as_ref()
    {
        return Err(invalid_request());
    }
    // Rollback addresses only the exact verified retained previous identity,
    // or an exact current no-op. It never invents an arbitrary retained path.
    if intent.mutation.action == RuntimeAction::Rollback
        && selection.previous.as_ref() != Some(&intent.mutation.target_identity)
        && selection.current.as_ref() != Some(&intent.mutation.target_identity)
    {
        return Err(invalid_request());
    }
    Ok(())
}

async fn mutation(
    state: ApiState,
    user: AuthUser,
    intent: Intent,
    captured: CapturedPlatformCwRuntime,
    candidate: Option<Candidate>,
) -> AppResult<RuntimeRequest> {
    let correlation = correlation(&captured, intent.mutation.request_id)?;
    captured.recheck(&state, &user).await?;
    let (supported, bootstrap, selection) =
        execute::status(&captured.daemon(), &correlation).await?;
    admit_observation(&intent, supported, bootstrap.as_ref(), &selection)?;
    admitting(&state.drain)?;
    let journal = RuntimeJournal::new(state.pool.clone(), state.confidential_storage_flags);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // Detach BEFORE journal admission. Losing the HTTP waiter during its COMMIT
    // cannot strand a returned fresh owner or recreate a lost capability.
    tokio::spawn(async move {
        let result = async {
            match journal.admit(&captured, &user, intent.mutation).await? {
                Admission::Existing(request) => Ok(*request),
                Admission::Owned { request, owner } => {
                    execute::run(PlatformBackend {
                        state,
                        user,
                        captured,
                        journal,
                        owner,
                        request: *request,
                        correlation,
                        candidate,
                    })
                    .await
                }
            }
        }
        .await;
        let _ = sender.send(result);
    });
    receiver.await.map_err(|_| unavailable())?
}

/// Admits nothing once this replica's drain has begun (#4460). An owner
/// admitted then could still be running when the rollout kills the replica,
/// which leaves its request unresolved (#4518). Nothing is admitted, so the
/// client sends the request again, to the next replica.
fn admitting(drain: &crate::drain::Drain) -> AppResult<()> {
    if drain.begun().is_cancelled() {
        return Err(AppError::ServiceUnavailable(DRAINING.into()));
    }
    Ok(())
}

pub async fn info(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::GetEnvironmentCwRuntimeRequest,
) -> AppResult<proto::GetEnvironmentCwRuntimeResponse> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    coordinates(&request.org_id, &request.environment_id)?;
    let row = live_cw_runtime_binding(&state.pool, &request.org_id, &request.environment_id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    let incarnation = CapturedBindingFacts::from(&row).incarnation();
    // The initial query grants nothing. Capture repeats all current operator,
    // organization, environment, setup, binding and actual PodUID gates.
    let captured = capture_platform_cw_runtime(state, user, &incarnation).await?;
    let correlation = correlation(&captured, Uuid::new_v4())?;
    let (supported, bootstrap, selection) =
        execute::status(&captured.daemon(), &correlation).await?;
    captured.recheck(state, user).await?;
    Ok(proto::GetEnvironmentCwRuntimeResponse {
        incarnation: Some(wire::proto_incarnation(captured.incarnation())?).into(),
        supported_image: supported,
        bootstrap_identity: bootstrap.as_ref().map(wire::proto_identity).into(),
        selection: Some(wire::proto_selection(&selection)?).into(),
        ..Default::default()
    })
}

pub async fn observe(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::ObserveEnvironmentCwRuntimeRequest,
) -> AppResult<proto::ObserveEnvironmentCwRuntimeResponse> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    coordinates(&request.org_id, &request.environment_id)?;
    let id = wire::uuid(&request.request_id)?;
    // Saved metadata only: no capture, channel, executable, status recovery,
    // lease reacquisition or latest-binding credential lookup occurs here.
    let request = RuntimeJournal::new(state.pool.clone(), state.confidential_storage_flags)
        .observe(user, &request.org_id, &request.environment_id, id)
        .await?;
    Ok(proto::ObserveEnvironmentCwRuntimeResponse {
        operation: Some(wire::proto_operation(&request)?).into(),
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
