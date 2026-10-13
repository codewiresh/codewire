//! Closed public/private framing. Runtime capture and durable issuance live in
//! the service; these conversions grant no command or provider authority.
use buffa::Message as _;
use codewire_daemon_proto::{daemon::v1 as private, platform_managed as native};
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::{AppError, AppResult};

use crate::api::cw_runtime::{PlatformCwRuntimeIncarnation, wire as runtime_wire};

pub(super) const FRAME_BYTES: usize = 256 * 1024;

pub(super) fn invalid() -> AppError {
    AppError::BadRequest("platform agent request metadata is invalid".into())
}
pub(super) fn unavailable() -> AppError {
    AppError::Upstream("original platform agent operation is unavailable".into())
}
pub(super) fn coordinates(org: &str, env: &str) -> AppResult<()> {
    if org.is_empty()
        || org.len() > 128
        || org.chars().any(char::is_control)
        || !native::valid_uuid(env)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn digest(value: &str) -> AppResult<Vec<u8>> {
    if !native::valid_hash(value) {
        return Err(invalid());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
        })
        .collect()
}
pub(super) fn scope(
    value: &proto::EnvironmentAgentScope,
    org: &str,
    env: &str,
) -> AppResult<(PlatformCwRuntimeIncarnation, private::PlatformManagedScope)> {
    coordinates(org, env)?;
    if !value.__buffa_unknown_fields.is_empty() {
        return Err(invalid());
    }
    let incarnation =
        runtime_wire::incarnation(value.incarnation.as_option().ok_or_else(invalid)?)?;
    if incarnation.organization_id != org || incarnation.environment_id != env {
        return Err(invalid());
    }
    let scope = private::PlatformManagedScope {
        environment_id: env.to_owned(),
        org_id: org.to_owned(),
        pod_uid: incarnation.pod_uid.clone(),
        binding_generation: u64::try_from(incarnation.binding_generation).map_err(|_| invalid())?,
        projection_selection_sha256: digest(
            incarnation
                .projection_selection_sha256
                .as_deref()
                .ok_or_else(invalid)?,
        )?,
        support_image_sha256: value.support_image_sha256.clone(),
        support_image_size: value.support_image_size,
    };
    native::validate_scope(&scope).map_err(|_| invalid())?;
    Ok((incarnation, scope))
}
pub(super) fn public_scope(
    incarnation: &PlatformCwRuntimeIncarnation,
    support_sha256: Vec<u8>,
    support_size: u64,
) -> AppResult<proto::EnvironmentAgentScope> {
    let value = proto::EnvironmentAgentScope {
        incarnation: Some(runtime_wire::proto_incarnation(incarnation)?).into(),
        support_image_sha256: support_sha256,
        support_image_size: support_size,
        ..Default::default()
    };
    scope(
        &value,
        &incarnation.organization_id,
        &incarnation.environment_id,
    )?;
    Ok(value)
}

pub(super) fn agent(
    value: proto::EnvironmentAgentKind,
) -> AppResult<private::PlatformManagedAgent> {
    match value {
        proto::EnvironmentAgentKind::Codex => Ok(private::PlatformManagedAgent::Codex),
        proto::EnvironmentAgentKind::Claude => Ok(private::PlatformManagedAgent::Claude),
        _ => Err(invalid()),
    }
}
pub(super) fn public_agent(value: i32) -> AppResult<proto::EnvironmentAgentKind> {
    match private::PlatformManagedAgent::try_from(value) {
        Ok(private::PlatformManagedAgent::Codex) => Ok(proto::EnvironmentAgentKind::Codex),
        Ok(private::PlatformManagedAgent::Claude) => Ok(proto::EnvironmentAgentKind::Claude),
        _ => Err(unavailable()),
    }
}
fn action(value: proto::EnvironmentAgentAction) -> AppResult<private::PlatformManagedAction> {
    use private::PlatformManagedAction as N;
    use proto::EnvironmentAgentAction as P;
    match value {
        P::Message => Ok(N::Message),
        P::Steer => Ok(N::Steer),
        P::Interrupt => Ok(N::Interrupt),
        P::Stop => Ok(N::Stop),
        P::Restart => Ok(N::Restart),
        P::Resume => Ok(N::Resume),
        _ => Err(invalid()),
    }
}

pub(super) fn mutation(
    request: &proto::MutateEnvironmentAgentRequest,
) -> AppResult<(
    PlatformCwRuntimeIncarnation,
    private::PlatformManagedMutationRequest,
)> {
    if !request.__buffa_unknown_fields.is_empty() || request.encoded_len() as usize > FRAME_BYTES {
        return Err(invalid());
    }
    let (incarnation, scope) = scope(
        request.expected_scope.as_option().ok_or_else(invalid)?,
        &request.org_id,
        &request.environment_id,
    )?;
    use private::platform_managed_mutation_request::Operation as N;
    use proto::mutate_environment_agent_request::Operation as P;
    let operation = match request.operation.as_ref().ok_or_else(invalid)? {
        P::Launch(value) => {
            if !value.__buffa_unknown_fields.is_empty() {
                return Err(invalid());
            }
            N::Launch(private::PlatformManagedLaunch {
                agent: agent(value.agent.as_known().ok_or_else(invalid)?)? as i32,
                model: value.model.clone(),
                effort: value.effort.clone(),
                working_dir: value.working_dir.clone(),
                name: value.name.clone(),
                prompt: value.prompt.clone(),
                parent_session_id: value.parent_session_id.clone(),
                expected_parent_launch_generation: value.expected_parent_launch_generation,
                expected_provider_sha256: value.expected_provider_sha256.clone(),
                expected_provider_size: value.expected_provider_size,
                expected_provider_version: value.expected_provider_version.clone(),
            })
        }
        P::Control(value) => {
            if !value.__buffa_unknown_fields.is_empty() {
                return Err(invalid());
            }
            N::Control(private::PlatformManagedControl {
                action: action(value.action.as_known().ok_or_else(invalid)?)? as i32,
                session_id: value.session_id.clone(),
                driver_id: value.driver_id.clone(),
                expected_launch_generation: value.expected_launch_generation,
                text: value.text.clone(),
                reply_to: value.reply_to.clone(),
                expected_turn_id: value.expected_turn_id.clone(),
                expected_active_message_id: value.expected_active_message_id.clone(),
                cleanup_of_request_id: value.cleanup_of_request_id.clone(),
                // A Resume's predecessor, agent and provider are never the
                // client's: the control plane fills them before validation.
                ..Default::default()
            })
        }
    };
    let request = private::PlatformManagedMutationRequest {
        request_id: request.request_id.clone(),
        scope: Some(scope),
        operation: Some(operation),
    };
    if !is_resume(&request) {
        native::validate_mutation(&request).map_err(|_| invalid())?;
    }
    Ok((incarnation, request))
}

pub(super) fn is_resume(request: &private::PlatformManagedMutationRequest) -> bool {
    matches!(
        &request.operation,
        Some(private::platform_managed_mutation_request::Operation::Control(c))
            if c.action == private::PlatformManagedAction::Resume as i32
    )
}

pub(super) fn read(
    request: &proto::ReadEnvironmentAgentRequest,
) -> AppResult<(
    PlatformCwRuntimeIncarnation,
    private::PlatformManagedReadRequest,
)> {
    if !request.__buffa_unknown_fields.is_empty() || request.encoded_len() as usize > 32 * 1024 {
        return Err(invalid());
    }
    let kind = request.kind.as_known().ok_or_else(invalid)?;
    let valid = match kind {
        proto::EnvironmentAgentRecordKind::Current => request.message_id.is_empty(),
        proto::EnvironmentAgentRecordKind::Message => native::valid_uuid(&request.message_id),
        _ => false,
    };
    if !valid {
        return Err(invalid());
    }
    let (incarnation, scope) = scope(
        request.expected_scope.as_option().ok_or_else(invalid)?,
        &request.org_id,
        &request.environment_id,
    )?;
    let request = private::PlatformManagedReadRequest {
        scope: Some(scope),
        session_id: request.session_id.clone(),
        driver_id: request.driver_id.clone(),
        expected_launch_generation: request.expected_launch_generation,
        message_id: request.message_id.clone(),
        limit: request.limit,
    };
    native::validate_read(&request).map_err(|_| invalid())?;
    Ok((incarnation, request))
}

pub(super) fn operation(
    value: &super::journal::ManagedRequest,
) -> AppResult<proto::EnvironmentAgentOperation> {
    use super::model::{ManagedLifecycle as L, ManagedPhase as P};
    let phase = match value.phase {
        P::Admitted => proto::EnvironmentAgentPhase::Admitted,
        P::Issued => proto::EnvironmentAgentPhase::Issued,
        P::Completed => proto::EnvironmentAgentPhase::Completed,
        P::Rejected => proto::EnvironmentAgentPhase::Rejected,
        P::Unknown => proto::EnvironmentAgentPhase::Unknown,
    };
    let receipt = value.receipt.as_ref();
    let lifecycle = match receipt.map(|r| r.lifecycle).unwrap_or(L::Unspecified) {
        L::Unspecified => proto::EnvironmentSessionState::Unspecified,
        L::Starting => proto::EnvironmentSessionState::Starting,
        L::Running => proto::EnvironmentSessionState::Running,
        L::Stopping => proto::EnvironmentSessionState::Stopping,
        L::Stopped => proto::EnvironmentSessionState::Stopped,
        L::Exited => proto::EnvironmentSessionState::Exited,
        L::Failed => proto::EnvironmentSessionState::Failed,
        L::Interrupted => proto::EnvironmentSessionState::Interrupted,
    };
    Ok(proto::EnvironmentAgentOperation {
        request_id: value.mutation.request_id.to_string(),
        scope: Some(public_scope(
            &value.binding.incarnation(),
            digest(&value.mutation.support_image_sha256)?,
            value.mutation.support_image_size,
        )?)
        .into(),
        fingerprint_sha256: digest(&value.fingerprint)?,
        phase: phase.into(),
        session_id: value.mutation.session_id.clone(),
        driver_id: value.mutation.driver_id.to_string(),
        message_id: receipt
            .and_then(|r| r.message_id)
            .or(value.mutation.message_id)
            .map(|id| id.to_string())
            .unwrap_or_default(),
        launch_generation: receipt
            .map(|r| r.launch_generation)
            .unwrap_or(value.mutation.expected_launch_generation),
        lifecycle: lifecycle.into(),
        exit_code: receipt.and_then(|r| r.exit_code),
        cleanup_unknown: receipt
            .map(|r| r.cleanup_unknown)
            .unwrap_or(matches!(value.phase, P::Issued | P::Unknown)),
        pipe_acknowledged: receipt.is_some_and(|r| r.pipe_acknowledged),
        native_acknowledged: receipt.is_some_and(|r| r.native_acknowledged),
        reason_code: value.reason_code.clone(),
        cleanup_of_request_id: value
            .cleanup_of
            .map(|id| id.to_string())
            .unwrap_or_default(),
        ..Default::default()
    })
}
