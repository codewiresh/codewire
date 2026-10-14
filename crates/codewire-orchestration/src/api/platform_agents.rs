//! Authenticated managed operations on one captured platform channel. Public
//! transport cancellation never cancels an already admitted durable owner.
pub mod journal;
pub mod model;
mod wire;

use buffa::Message as _;
use codewire_daemon_bridge::client::DaemonClientError;
use codewire_daemon_proto::{daemon::v1 as private, platform_managed as native};
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::{AppError, AppResult, auth::AuthUser};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use self::journal::{Admission, ManagedJournal};
use self::model::{ManagedMutation, ManagedPhase, ManagedReceipt};
use self::wire::{invalid, unavailable};
use super::{
    ApiState,
    cw_runtime::{CapturedPlatformCwRuntime, capture_platform_cw_runtime},
};
use crate::worker::workspace_binding::live_cw_runtime_binding;

fn journal(state: &ApiState) -> ManagedJournal {
    ManagedJournal::new(state.pool.clone(), state.confidential_storage_flags)
}

async fn target_info(
    captured: &CapturedPlatformCwRuntime,
) -> AppResult<private::PlatformManagedInfoResponse> {
    let incarnation = captured.incarnation();
    let request = private::PlatformManagedInfoRequest {
        environment_id: incarnation.environment_id.clone(),
        binding_generation: u64::try_from(incarnation.binding_generation).map_err(|_| invalid())?,
        projection_selection_sha256: wire::digest(
            incarnation
                .projection_selection_sha256
                .as_deref()
                .ok_or_else(|| {
                    // The answer stays opaque; the log names the unmet precondition.
                    tracing::warn!(
                        environment_id = %incarnation.environment_id,
                        "platform agent unavailable: the live binding records no projection selection"
                    );
                    unavailable()
                })?,
        )?,
    };
    captured
        .daemon()
        .platform_managed_info(request)
        .await
        .map_err(|error| {
            // The caller's own Sandbox image lacks the pinned clients: a
            // normal state for an older Sandbox, which its owner is told.
            if let Some(stale) = stale_image_clients(&error) {
                return AppError::Precondition(wire::stale_image_text(&stale).into());
            }
            tracing::warn!(
                environment_id = %incarnation.environment_id,
                error = %error,
                "platform agent unavailable: the daemon's managed info call failed"
            );
            unavailable()
        })
}

fn stale_image_clients(error: &DaemonClientError) -> Option<Vec<native::StaleImageClient>> {
    match error {
        DaemonClientError::Status(status) if status.code() == tonic::Code::FailedPrecondition => {
            native::stale_image_clients(status.message())
        }
        _ => None,
    }
}

pub async fn info(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::GetEnvironmentAgentInfoRequest,
) -> AppResult<proto::GetEnvironmentAgentInfoResponse> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(invalid());
    }
    wire::coordinates(&request.org_id, &request.environment_id)?;
    // This first read grants no execution authority. Capture then repeats
    // current operator, lifecycle, full binding and actual original Pod gates.
    let row = live_cw_runtime_binding(&state.pool, &request.org_id, &request.environment_id)
        .await
        .map_err(|error| {
            tracing::warn!(
                environment_id = %request.environment_id,
                error = %error,
                "platform agent unavailable: the live binding could not be read"
            );
            unavailable()
        })?
        .ok_or_else(|| {
            tracing::warn!(
                environment_id = %request.environment_id,
                "platform agent unavailable: the environment has no live CW runtime binding"
            );
            unavailable()
        })?;
    let facts = super::cw_runtime::model::CapturedBindingFacts::from(&row);
    let captured = capture_platform_cw_runtime(state, user, &facts.incarnation()).await?;
    let info = target_info(&captured).await?;
    captured.recheck(state, user).await?;
    let scope = wire::public_scope(
        captured.incarnation(),
        info.support_image_sha256,
        info.support_image_size,
    )?;
    let agents = info
        .agents
        .into_iter()
        .map(|a| {
            Ok(proto::EnvironmentAgentSupport {
                agent: wire::public_agent(a.agent)?.into(),
                provider_sha256: a.provider_sha256,
                provider_size: a.provider_size,
                provider_version: a.provider_version,
                proxy_only_qualified: a.proxy_only_qualified,
                steer: a.steer,
                interrupt: a.interrupt,
                ..Default::default()
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(proto::GetEnvironmentAgentInfoResponse {
        scope: Some(scope).into(),
        support_image_version: info.support_image_version,
        agents,
        ..Default::default()
    })
}

fn require_support(
    request: &private::PlatformManagedMutationRequest,
    info: &private::PlatformManagedInfoResponse,
) -> AppResult<()> {
    let scope = request.scope.as_ref().ok_or_else(invalid)?;
    if scope.support_image_sha256 != info.support_image_sha256
        || scope.support_image_size != info.support_image_size
    {
        return Err(invalid());
    }
    if let Some(private::platform_managed_mutation_request::Operation::Launch(launch)) =
        &request.operation
        && !info.agents.iter().any(|a| {
            a.agent == launch.agent
                && a.proxy_only_qualified
                && a.provider_sha256 == launch.expected_provider_sha256
                && a.provider_size == launch.expected_provider_size
                && a.provider_version == launch.expected_provider_version
        })
    {
        return Err(invalid());
    }
    Ok(())
}

pub async fn mutate(
    state: ApiState,
    user: AuthUser,
    request: proto::MutateEnvironmentAgentRequest,
) -> AppResult<proto::MutateEnvironmentAgentResponse> {
    let (incarnation, private_request) = wire::mutation(&request)?;
    let captured = capture_platform_cw_runtime(&state, &user, &incarnation).await?;
    require_support(&private_request, &target_info(&captured).await?)?;
    captured.recheck(&state, &user).await?;
    let metadata = ManagedMutation::from_private(&private_request)?;
    let journal = journal(&state);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // Detach before the first journal COMMIT. A lost HTTP waiter cannot discard
    // the only fresh owner or acquire a replacement issue permit.
    tokio::spawn(async move {
        let result = async {
            let saved = match journal
                .admit(captured.binding_facts(), &user, metadata)
                .await?
            {
                Admission::Existing(request) => *request,
                Admission::Owned { request: _, owner } => {
                    if captured.recheck(&state, &user).await.is_err() {
                        journal
                            .reject_before_issue(owner, "platform-agent-preissue-refused")
                            .await?
                    } else {
                        let issued = journal.issue(&owner, &user).await?;
                        let result = captured
                            .daemon()
                            .mutate_platform_managed_session(private_request)
                            .await;
                        match result
                            .ok()
                            .and_then(|receipt| ManagedReceipt::from_private(&receipt).ok())
                        {
                            Some(receipt)
                                if matches!(
                                    receipt.phase,
                                    ManagedPhase::Completed
                                        | ManagedPhase::Rejected
                                        | ManagedPhase::Unknown
                                ) =>
                            {
                                journal.settle(issued, receipt).await?
                            }
                            _ => {
                                journal
                                    .mark_unknown(issued, "platform-agent-dispatch-unknown")
                                    .await?
                            }
                        }
                    }
                }
            };
            Ok(proto::MutateEnvironmentAgentResponse {
                operation: Some(wire::operation(&saved)?).into(),
                ..Default::default()
            })
        }
        .await;
        let _ = sender.send(result);
    });
    receiver.await.map_err(|_| unavailable())?
}

pub async fn observe(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::ObserveEnvironmentAgentRequest,
) -> AppResult<proto::ObserveEnvironmentAgentResponse> {
    if !request.__buffa_unknown_fields.is_empty() || !native::valid_uuid(&request.request_id) {
        return Err(invalid());
    }
    wire::coordinates(&request.org_id, &request.environment_id)?;
    let id = Uuid::parse_str(&request.request_id).map_err(|_| invalid())?;
    // Durable metadata only: no target command, latest token, new lease or
    // attempt to recover a crashed Issued capability.
    let saved = journal(state)
        .observe(user, &request.org_id, &request.environment_id, id)
        .await?;
    Ok(proto::ObserveEnvironmentAgentResponse {
        operation: Some(wire::operation(&saved)?).into(),
        ..Default::default()
    })
}

pub async fn list(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::ListEnvironmentAgentsRequest,
) -> AppResult<proto::ListEnvironmentAgentsResponse> {
    if !request.__buffa_unknown_fields.is_empty() || request.encoded_len() as usize > 32 * 1024 {
        return Err(invalid());
    }
    let (incarnation, scope) = wire::scope(
        request.expected_scope.as_option().ok_or_else(invalid)?,
        &request.org_id,
        &request.environment_id,
    )?;
    let captured = capture_platform_cw_runtime(state, user, &incarnation).await?;
    let result = captured
        .daemon()
        .list_platform_managed_sessions(private::PlatformManagedListRequest {
            scope: Some(scope),
            after_session_id: request.after_session_id.clone(),
            page_limit: 8,
        })
        .await
        .map_err(|_| unavailable())?;
    captured.recheck(state, user).await?;
    Ok(proto::ListEnvironmentAgentsResponse {
        scope: request.expected_scope.clone(),
        sessions: result
            .sessions
            .into_iter()
            .map(codewire_daemon_bridge::session::public_session)
            .collect(),
        next_after_session_id: result.next_session_id,
        ..Default::default()
    })
}

pub async fn read(
    state: &ApiState,
    user: &AuthUser,
    request: &proto::ReadEnvironmentAgentRequest,
) -> AppResult<proto::ReadEnvironmentAgentResponse> {
    let (incarnation, private_request) = wire::read(request)?;
    let captured = capture_platform_cw_runtime(state, user, &incarnation).await?;
    let record = captured
        .daemon()
        .read_platform_managed_session(private_request)
        .await
        .map_err(|_| unavailable())?
        .read_complete()
        .await
        .map_err(|_| unavailable())?;
    captured.recheck(state, user).await?;
    Ok(proto::ReadEnvironmentAgentResponse {
        scope: request.expected_scope.clone(),
        session_id: request.session_id.clone(),
        driver_id: request.driver_id.clone(),
        launch_generation: request.expected_launch_generation,
        kind: request.kind,
        message_id: request.message_id.clone(),
        record_sha256: Sha256::digest(&record).to_vec(),
        record_json: record,
        ..Default::default()
    })
}

#[cfg(test)]
mod stale_image_tests {
    use super::*;

    fn refusal(message: &str) -> DaemonClientError {
        DaemonClientError::Status(tonic::Status::failed_precondition(message))
    }

    #[test]
    fn an_older_sandbox_image_is_named_to_its_owner() {
        let stale = stale_image_clients(&refusal(
            "platform managed image clients: codex=0.157.0/0.160.0 claude=2.1.238/2.1.288",
        ))
        .unwrap();
        assert_eq!(
            wire::stale_image_text(&stale),
            "This Sandbox's image has Codex 0.157.0 and Claude Code 2.1.238; managed agents \
             need Codex 0.160.0 and Claude Code 2.1.288. Recreate the Sandbox to use managed agents."
        );
        let missing = stale_image_clients(&refusal(
            "platform managed image clients: codex=none/0.160.0",
        ))
        .unwrap();
        assert_eq!(
            wire::stale_image_text(&missing),
            "This Sandbox's image has no Codex; managed agents need Codex 0.160.0. \
             Recreate the Sandbox to use managed agents."
        );
    }

    #[test]
    fn any_other_daemon_refusal_stays_opaque() {
        for error in [
            refusal("platform managed incarnation or outcome refused"),
            refusal("platform managed image clients: codex=0.157.0/0.160.0; anything else"),
            DaemonClientError::Status(tonic::Status::unavailable(
                "platform managed image clients: codex=0.157.0/0.160.0",
            )),
            DaemonClientError::Connect,
        ] {
            assert!(stale_image_clients(&error).is_none(), "{error}");
        }
    }
}
