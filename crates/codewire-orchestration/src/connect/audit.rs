//! Connect-RPC adapter for the Sandbox audit log's read (#6189;
//! `proto/codewire/v1/audit.proto`).

use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::{DateTime, Utc};
use codewire_proto::codewire::v1::__buffa::oneof::{audit_actor, list_audit_events_request};
use codewire_proto::codewire::v1::{
    AuditAccess, AuditActor, AuditApiKey, AuditCredentials, AuditEnvironment, AuditEvent,
    AuditEventKind, AuditLifecycle, AuditPlatform, AuditPlatformReason, AuditPolicyChange,
    AuditPolicyRevision, AuditProtocol, AuditRefusal, AuditRefusalOverflow, AuditRole,
    AuditSandbox, AuditService, AuditSize, AuditSurface, AuditUser, ListAuditEventsRequest,
    ListAuditEventsResponse, audit_credentials, audit_lifecycle, audit_policy_change,
};
use codewire_server_core::connect::{auth_context, auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use std::collections::HashMap;

use codewire_proto::codewire::v1::__buffa::oneof::audit_event::Detail;

use crate::audit::allowed_since::{Selected, allowed_since};
use crate::audit::read::{self, EnvironmentRef, Query, StoredEvent};
use crate::audit::{
    Credentials, Kind, Lifecycle, PlatformReason, Policy, Protocol, Refusal, Size, Surface, What,
};

pub fn router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(AuditConnectService { pool }))
}

struct AuditConnectService {
    pool: PgPool,
}

#[allow(refining_impl_trait)]
impl AuditService for AuditConnectService {
    async fn list_audit_events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAuditEventsRequest>,
    ) -> ServiceResult<ListAuditEventsResponse> {
        let user = auth_user(&ctx)?.clone();
        let credential = auth_context(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            read::require_reader_credential(&credential)?;
            let query = query(request)?;
            let environment = read::authorize(&self.pool, &user, &query).await?;
            let selected = selected_policy(&self.pool, &environment.id).await?;
            let page = read::read(&self.pool, &user, &query, environment).await?;
            let refusals: Vec<(String, Refusal)> = page
                .events
                .iter()
                .filter_map(|event| {
                    match What::from_stored(&event.kind, &event.action, &event.detail) {
                        Ok(What::Refused(refusal)) => Some((event.id.clone(), refusal)),
                        _ => None,
                    }
                })
                .collect();
            let allowed = match &selected {
                Some(selected) => {
                    let refusals: Vec<(&str, &Refusal)> = refusals
                        .iter()
                        .map(|(id, refusal)| (id.as_str(), refusal))
                        .collect();
                    allowed_since(&self.pool, selected, &refusals).await?
                }
                None => HashMap::new(),
            };
            Ok::<_, AppError>((page, selected, allowed))
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let (page, selected, allowed) = result;
        let policy = selected.map(|selected| AuditPolicyRevision {
            name: selected.name,
            revision: selected.current,
            ..Default::default()
        });
        connectrpc::Response::ok(ListAuditEventsResponse {
            environment: Some(AuditEnvironment {
                id: page.environment.id,
                name: page.environment.name,
                deleted: page.environment.deleted,
                ..Default::default()
            })
            .into(),
            policy: policy.into(),
            events: page
                .events
                .iter()
                .filter_map(|event| {
                    let mut proto = proto_event(event)?;
                    if let Some(Detail::Refused(refusal)) = &mut proto.detail {
                        refusal.allowed_since_revision = allowed.get(&event.id).copied();
                    }
                    Some(proto)
                })
                .collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
            left_out: page.left_out,
            ..Default::default()
        })
    }
}

fn query(request: ListAuditEventsRequest) -> AppResult<Query> {
    let environment = match request.environment {
        Some(list_audit_events_request::Environment::EnvironmentId(id)) => EnvironmentRef::Id(id),
        Some(list_audit_events_request::Environment::EnvironmentName(name)) => {
            EnvironmentRef::Name(name)
        }
        None => {
            return Err(AppError::BadRequest(
                "name the environment by id or name".into(),
            ));
        }
    };
    let kinds = request
        .kinds
        .iter()
        .map(|kind| match kind.as_known() {
            Some(AuditEventKind::AUDIT_EVENT_KIND_ACCESS) => Ok(Kind::Access),
            Some(AuditEventKind::AUDIT_EVENT_KIND_LIFECYCLE) => Ok(Kind::Lifecycle),
            Some(AuditEventKind::AUDIT_EVENT_KIND_POLICY) => Ok(Kind::Policy),
            Some(AuditEventKind::AUDIT_EVENT_KIND_REFUSED) => Ok(Kind::Refused),
            Some(AuditEventKind::AUDIT_EVENT_KIND_CREDENTIALS) => Ok(Kind::Credentials),
            _ => Err(AppError::BadRequest("unknown event kind".into())),
        })
        .collect::<AppResult<_>>()?;
    Ok(Query {
        org_id: request.org_id,
        environment,
        kinds,
        since: request
            .since
            .into_option()
            .as_ref()
            .and_then(from_timestamp),
        until: request
            .until
            .into_option()
            .as_ref()
            .and_then(from_timestamp),
        limit: request.limit,
        cursor: (!request.cursor.is_empty()).then_some(request.cursor),
        grouped: request.group_by_subject,
    })
}

/// The environment's selected stored policy at its current revision; none
/// for a built-in or no selection.
async fn selected_policy(pool: &PgPool, environment_id: &str) -> AppResult<Option<Selected>> {
    let mut connection = pool.acquire().await?;
    let view = crate::api::network_policies::environment_policy_in(&mut connection, environment_id)
        .await?;
    let id = view
        .reference
        .strip_prefix("platform:id:")
        .map(str::to_owned);
    Ok(id.filter(|_| view.revision > 0).map(|id| Selected {
        id,
        name: view.name,
        current: view.revision,
    }))
}

fn from_timestamp(value: &Timestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(value.seconds, u32::try_from(value.nanos).ok()?)
}

fn timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(
        value.timestamp(),
        i32::try_from(value.timestamp_subsec_nanos()).unwrap_or(0),
    )
}

/// The event as the read returns it, or `None` for a row this build can't
/// read, which is left out and logged.
fn proto_event(event: &StoredEvent) -> Option<AuditEvent> {
    let what = match What::from_stored(&event.kind, &event.action, &event.detail) {
        Ok(what) => what,
        Err(error) => {
            tracing::warn!(id = %event.id, %error, "audit log: an event this build can't read");
            return None;
        }
    };
    let mut proto = AuditEvent {
        id: event.id.clone(),
        kind: kind(what.kind()).into(),
        first: Some(timestamp(event.first_at)).into(),
        last: event.last_at.map(timestamp).into(),
        count: u64::try_from(event.count).unwrap_or(0),
        actor: Some(actor(event)).into(),
        ..Default::default()
    };
    proto.detail = Some(match what {
        What::Access(surface) => AuditAccess {
            surface: proto_surface(surface).into(),
            client_ip: event.client_ip.clone().unwrap_or_default(),
            ..Default::default()
        }
        .into(),
        What::Lifecycle(lifecycle) => proto_lifecycle(lifecycle).into(),
        What::Policy(policy) => proto_policy(policy).into(),
        What::Refused(refusal) => proto_refusal(refusal).into(),
        What::RefusedOverflow(overflow) => AuditRefusalOverflow {
            subjects: overflow.subjects,
            at_least: overflow.at_least,
            ..Default::default()
        }
        .into(),
        What::Credentials(credentials) => proto_credentials(credentials).into(),
    });
    Some(proto)
}

fn kind(kind: Kind) -> AuditEventKind {
    match kind {
        Kind::Access => AuditEventKind::AUDIT_EVENT_KIND_ACCESS,
        Kind::Lifecycle => AuditEventKind::AUDIT_EVENT_KIND_LIFECYCLE,
        Kind::Policy => AuditEventKind::AUDIT_EVENT_KIND_POLICY,
        Kind::Refused => AuditEventKind::AUDIT_EVENT_KIND_REFUSED,
        Kind::Credentials => AuditEventKind::AUDIT_EVENT_KIND_CREDENTIALS,
    }
}

fn actor(event: &StoredEvent) -> AuditActor {
    let id = event.actor_id.clone().unwrap_or_default();
    let label = event.actor_label.clone().unwrap_or_default();
    let actor = match event.actor_type.as_str() {
        "user" => audit_actor::Actor::from(AuditUser {
            id,
            email: label,
            role: match event.actor_role.as_deref() {
                Some("owner") => AuditRole::AUDIT_ROLE_OWNER,
                Some("admin") => AuditRole::AUDIT_ROLE_ADMIN,
                Some("member") => AuditRole::AUDIT_ROLE_MEMBER,
                Some("staff") => AuditRole::AUDIT_ROLE_STAFF,
                _ => AuditRole::AUDIT_ROLE_UNSPECIFIED,
            }
            .into(),
            ..Default::default()
        }),
        "api_key" => audit_actor::Actor::from(AuditApiKey {
            id,
            name: label,
            ..Default::default()
        }),
        "sandbox" => audit_actor::Actor::from(AuditSandbox::default()),
        _ => audit_actor::Actor::from(AuditPlatform::default()),
    };
    AuditActor {
        actor: Some(actor),
        ..Default::default()
    }
}

fn proto_surface(surface: Surface) -> AuditSurface {
    match surface {
        Surface::Terminal => AuditSurface::AUDIT_SURFACE_TERMINAL,
        Surface::Ssh => AuditSurface::AUDIT_SURFACE_SSH,
        Surface::Exec => AuditSurface::AUDIT_SURFACE_EXEC,
        Surface::Desktop => AuditSurface::AUDIT_SURFACE_DESKTOP,
        Surface::Preview => AuditSurface::AUDIT_SURFACE_PREVIEW,
    }
}

fn proto_reason(reason: Option<PlatformReason>) -> AuditPlatformReason {
    match reason {
        None => AuditPlatformReason::AUDIT_PLATFORM_REASON_UNSPECIFIED,
        Some(PlatformReason::Idle) => AuditPlatformReason::AUDIT_PLATFORM_REASON_IDLE,
        Some(PlatformReason::OutOfCredit) => {
            AuditPlatformReason::AUDIT_PLATFORM_REASON_OUT_OF_CREDIT
        }
        Some(PlatformReason::Suspended) => AuditPlatformReason::AUDIT_PLATFORM_REASON_SUSPENDED,
        Some(PlatformReason::SystemdRefused) => {
            AuditPlatformReason::AUDIT_PLATFORM_REASON_SYSTEMD_REFUSED
        }
        Some(PlatformReason::PodFailed) => AuditPlatformReason::AUDIT_PLATFORM_REASON_POD_FAILED,
        Some(PlatformReason::RuntimeReplaced) => {
            AuditPlatformReason::AUDIT_PLATFORM_REASON_RUNTIME_REPLACED
        }
        Some(PlatformReason::NodeLost) => AuditPlatformReason::AUDIT_PLATFORM_REASON_NODE_LOST,
        Some(PlatformReason::ConfigurationChanged) => {
            AuditPlatformReason::AUDIT_PLATFORM_REASON_CONFIGURATION_CHANGED
        }
        Some(PlatformReason::SourcesChanged) => {
            AuditPlatformReason::AUDIT_PLATFORM_REASON_SOURCES_CHANGED
        }
        Some(PlatformReason::Expired) => AuditPlatformReason::AUDIT_PLATFORM_REASON_EXPIRED,
    }
}

fn proto_size(size: Size) -> AuditSize {
    AuditSize {
        vcpu: size.vcpu,
        memory_mib: size.memory_mib,
        ..Default::default()
    }
}

fn proto_lifecycle(lifecycle: Lifecycle) -> AuditLifecycle {
    use audit_lifecycle::Action;
    let mut proto = AuditLifecycle::default();
    let action = match lifecycle {
        Lifecycle::Created {
            preset,
            from_snapshot,
        } => {
            proto.preset = preset.unwrap_or_default();
            proto.from_snapshot = from_snapshot.unwrap_or_default();
            Action::ACTION_CREATED
        }
        Lifecycle::Started => Action::ACTION_STARTED,
        Lifecycle::Stopped {
            reason,
            idle_stop_seconds,
        } => {
            proto.reason = proto_reason(reason).into();
            proto.idle_stop_seconds = idle_stop_seconds.unwrap_or(0);
            Action::ACTION_STOPPED
        }
        Lifecycle::Restarted { reason } => {
            proto.reason = proto_reason(reason).into();
            Action::ACTION_RESTARTED
        }
        Lifecycle::Resized { from, to } => {
            proto.from = Some(proto_size(from)).into();
            proto.to = Some(proto_size(to)).into();
            Action::ACTION_RESIZED
        }
        Lifecycle::SnapshotTaken { snapshot } => {
            proto.snapshot = snapshot;
            Action::ACTION_SNAPSHOT_TAKEN
        }
        Lifecycle::Deleted { reason } => {
            proto.reason = proto_reason(reason).into();
            Action::ACTION_DELETED
        }
    };
    proto.action = action.into();
    proto
}

fn proto_policy(policy: Policy) -> AuditPolicyChange {
    use audit_policy_change::Action;
    let mut proto = AuditPolicyChange::default();
    let action = match policy {
        Policy::Selected { from, to } => {
            proto.from = from;
            proto.to = to;
            Action::ACTION_SELECTED
        }
        Policy::Edited {
            policy,
            from_revision,
            to_revision,
            added,
            removed,
        } => {
            proto.policy = policy;
            proto.from_revision = from_revision;
            proto.to_revision = to_revision;
            proto.added = added;
            proto.removed = removed;
            Action::ACTION_EDITED
        }
        Policy::Enforcing { policy, revision } => {
            proto.policy = policy;
            proto.revision = revision;
            Action::ACTION_ENFORCING
        }
        Policy::FailedClosed { failure_code } => {
            proto.failure_code = failure_code;
            Action::ACTION_FAILED_CLOSED
        }
    };
    proto.action = action.into();
    proto
}

fn proto_refusal(refusal: Refusal) -> AuditRefusal {
    AuditRefusal {
        destination: refusal.destination.unwrap_or_default(),
        withheld: refusal.withheld,
        address: refusal.address.unwrap_or_default(),
        port: refusal.port.map(u32::from),
        protocol: match refusal.protocol {
            Protocol::Dns => AuditProtocol::AUDIT_PROTOCOL_DNS,
            Protocol::Tcp => AuditProtocol::AUDIT_PROTOCOL_TCP,
            Protocol::Udp => AuditProtocol::AUDIT_PROTOCOL_UDP,
        }
        .into(),
        reason: refusal.reason.code().to_owned(),
        source: match refusal.source {
            crate::audit::RefusalSource::Network => "network",
            crate::audit::RefusalSource::FrontDoor => "front_door",
        }
        .to_owned(),
        policy: refusal.policy.unwrap_or_default(),
        revision: refusal.revision.unwrap_or(0),
        allowed_since_revision: None,
        ..Default::default()
    }
}

fn proto_credentials(credentials: Credentials) -> AuditCredentials {
    use audit_credentials::Action;
    let (action, provider, name, host, withheld) = match credentials {
        Credentials::Attached { provider, name } => (
            Action::ACTION_ATTACHED,
            provider,
            name,
            String::new(),
            false,
        ),
        Credentials::Detached { provider, name } => (
            Action::ACTION_DETACHED,
            provider,
            name,
            String::new(),
            false,
        ),
        Credentials::Used {
            provider,
            name,
            host,
            withheld,
        } => (Action::ACTION_USED, provider, name, host, withheld),
    };
    AuditCredentials {
        action: action.into(),
        provider,
        name,
        host,
        withheld,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
