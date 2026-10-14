//! Authenticated managed operations on one captured platform channel. Public
//! transport cancellation never cancels an already admitted durable owner.
pub mod journal;
pub mod model;
#[cfg(test)]
#[path = "platform_agents/resume_tests.rs"]
mod resume_tests;
mod wire;

use buffa::Message as _;
use codewire_daemon_proto::{daemon::v1 as private, platform_managed as native};
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::{AppResult, auth::AuthUser};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use self::journal::{Admission, ManagedJournal, ManagedRequest};
use self::model::{
    ManagedAction, ManagedAgent, ManagedMutation, ManagedPhase, ManagedReceipt, ResumePredecessor,
};
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
                .ok_or_else(unavailable)?,
        )?,
    };
    captured
        .daemon()
        .platform_managed_info(request)
        .await
        .map_err(|_| unavailable())
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
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
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
    // A Resume runs the image's provider for its agent exactly as a Launch.
    let pinned = match &request.operation {
        Some(private::platform_managed_mutation_request::Operation::Launch(l)) => Some((
            l.agent,
            &l.expected_provider_sha256,
            l.expected_provider_size,
            &l.expected_provider_version,
        )),
        Some(private::platform_managed_mutation_request::Operation::Control(c))
            if c.action == private::PlatformManagedAction::Resume as i32 =>
        {
            Some((
                c.agent,
                &c.expected_provider_sha256,
                c.expected_provider_size,
                &c.expected_provider_version,
            ))
        }
        _ => None,
    };
    if let Some((agent, sha256, size, version)) = pinned
        && !info.agents.iter().any(|a| {
            a.agent == agent
                && a.proxy_only_qualified
                && a.provider_sha256 == *sha256
                && a.provider_size == size
                && a.provider_version == *version
        })
    {
        return Err(invalid());
    }
    Ok(())
}

/// Fill a Resume from the control plane's own journal and Kubernetes: the
/// predecessor Pod, proven absent; its agent; and this image's pinned
/// provider for that agent. Nothing here comes from the client (#2705).
async fn prepare_resume(
    state: &ApiState,
    captured: &CapturedPlatformCwRuntime,
    info: &private::PlatformManagedInfoResponse,
    request: &mut private::PlatformManagedMutationRequest,
) -> AppResult<ResumePredecessor> {
    let Some(private::platform_managed_mutation_request::Operation::Control(control)) =
        request.operation.as_mut()
    else {
        return Err(invalid());
    };
    // The request's own shape first: nothing is read for a malformed one.
    if !native::valid_uuid(&control.driver_id)
        || control.session_id != format!("session-{}", control.driver_id)
    {
        return Err(invalid());
    }
    let driver_id = Uuid::parse_str(&control.driver_id).map_err(|_| invalid())?;
    let predecessor = journal(state)
        .resume_predecessor(&captured.binding_facts(), &control.session_id, driver_id)
        .await?;
    // The client names the generation it saw; it must still be the record's.
    if control.expected_launch_generation != predecessor.generation {
        return Err(self::model::resume_refused(
            "this conversation changed since it was listed; list it again",
        ));
    }
    require_predecessor_absent(state.kube.as_ref(), &predecessor).await?;
    fill_resume(info, request, &predecessor.pod_uid, predecessor.agent)?;
    Ok(predecessor)
}

/// The predecessor Pod must be gone: absent, or another Pod under its name.
/// A present Pod, terminating included, is still stopping; a failed read, or
/// no Kubernetes client, refuses as unavailable (#2705).
async fn require_predecessor_absent(
    kube: Option<&kube::Client>,
    predecessor: &ResumePredecessor,
) -> AppResult<()> {
    let kube = kube.ok_or_else(unavailable)?;
    match crate::worker::workspace_binding::bound_pod_absent(
        kube,
        &predecessor.namespace,
        &predecessor.pod_name,
        &predecessor.pod_uid,
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(self::model::resume_refused(
            "the environment's previous Pod is still stopping; try again shortly",
        )),
        Err(_) => Err(unavailable()),
    }
}

/// The control-plane fields of a Resume: its predecessor, its agent, and this
/// image's pinned provider for that agent.
fn fill_resume(
    info: &private::PlatformManagedInfoResponse,
    request: &mut private::PlatformManagedMutationRequest,
    predecessor_pod_uid: &str,
    agent: ManagedAgent,
) -> AppResult<()> {
    let Some(private::platform_managed_mutation_request::Operation::Control(control)) =
        request.operation.as_mut()
    else {
        return Err(invalid());
    };
    let agent = match agent {
        ManagedAgent::Codex => private::PlatformManagedAgent::Codex,
        ManagedAgent::Claude => private::PlatformManagedAgent::Claude,
    } as i32;
    let support = info
        .agents
        .iter()
        .find(|a| a.agent == agent && a.proxy_only_qualified)
        .ok_or_else(|| {
            self::model::resume_refused(
                "this environment no longer selects a credential for this agent; \
                 start a new conversation",
            )
        })?;
    control.predecessor_pod_uid = predecessor_pod_uid.to_owned();
    control.agent = agent;
    control.expected_provider_sha256 = support.provider_sha256.clone();
    control.expected_provider_size = support.provider_size;
    control.expected_provider_version = support.provider_version.clone();
    native::validate_mutation(request).map_err(|_| invalid())
}

/// A Resume the target refused before issue for a plain reason is answered
/// with that reason, the first time and on every repeat (#2705).
fn resume_rejection(saved: &ManagedRequest) -> Option<&'static str> {
    if saved.phase != ManagedPhase::Rejected || saved.mutation.action != ManagedAction::Resume {
        return None;
    }
    self::model::resume_refusal_text(&saved.receipt.as_ref()?.reason_code)
}

pub async fn mutate(
    state: ApiState,
    user: AuthUser,
    request: proto::MutateEnvironmentAgentRequest,
) -> AppResult<proto::MutateEnvironmentAgentResponse> {
    let (incarnation, mut private_request) = wire::mutation(&request)?;
    let captured = capture_platform_cw_runtime(&state, &user, &incarnation).await?;
    let info = target_info(&captured).await?;
    let is_resume = wire::is_resume(&private_request);
    // A repeated Resume carries its first admission's control-plane fields
    // and is answered from it, as every other repeated request is.
    let resume = if !is_resume {
        None
    } else {
        let request_id = Uuid::parse_str(&private_request.request_id).map_err(|_| invalid())?;
        match journal(&state)
            .saved_resume(&captured.binding_facts(), &user, request_id)
            .await?
        {
            Some(saved) => {
                let agent = saved.agent.ok_or_else(invalid)?;
                let predecessor = saved.predecessor_pod_uid.ok_or_else(invalid)?;
                fill_resume(&info, &mut private_request, &predecessor, agent)?;
                None
            }
            None => Some(prepare_resume(&state, &captured, &info, &mut private_request).await?),
        }
    };
    // A plain Stop of a conversation whose last request has an unknown
    // outcome is that request's cleanup, so `cw stop` needs no request ID; a
    // repeat keeps its first admission's link (#2782).
    if wire::is_plain_stop(&private_request) {
        let request_id = Uuid::parse_str(&private_request.request_id).map_err(|_| invalid())?;
        let journal = journal(&state);
        let link = match journal
            .saved_mutation(&captured.binding_facts(), &user, request_id)
            .await?
        {
            Some(saved) => saved.cleanup_of_request_id,
            None => {
                let Some(private::platform_managed_mutation_request::Operation::Control(c)) =
                    private_request.operation.as_ref()
                else {
                    return Err(invalid());
                };
                journal
                    .unknown_active_request(&captured.binding_facts(), &user, &c.session_id)
                    .await?
            }
        };
        if let (Some(id), Some(private::platform_managed_mutation_request::Operation::Control(c))) =
            (link, private_request.operation.as_mut())
        {
            c.cleanup_of_request_id = Some(id.to_string());
        }
    }
    require_support(&private_request, &info)?;
    captured.recheck(&state, &user).await?;
    let metadata = ManagedMutation::from_private(&private_request)?;
    let journal = journal(&state);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // Detach before the first journal COMMIT. A lost HTTP waiter cannot discard
    // the only fresh owner or acquire a replacement issue permit.
    tokio::spawn(async move {
        let result = async {
            let admission = match resume {
                Some(checked) => {
                    journal
                        .admit_resume(captured.binding_facts(), &user, metadata, checked)
                        .await?
                }
                None if is_resume => Admission::Existing(Box::new(
                    journal
                        .repeat_resume(captured.binding_facts(), &user, metadata)
                        .await?,
                )),
                None => {
                    journal
                        .admit(captured.binding_facts(), &user, metadata)
                        .await?
                }
            };
            let saved = match admission {
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
            if let Some(reason) = resume_rejection(&saved) {
                return Err(self::model::resume_refused(reason));
            }
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
