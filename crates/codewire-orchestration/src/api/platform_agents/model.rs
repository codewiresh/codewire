//! Value-blind, bounded metadata for one original platform conversation.
//!
//! Private live requests are validated and hashed in memory. Only their digest,
//! identifiers and original nonsecret scope enter this module's durable model.

use codewire_daemon_proto::daemon::v1 as private;
use codewire_daemon_proto::platform_managed as wire;
use codewire_server_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::cw_runtime::model::CapturedBindingFacts;

pub const MAX_JSON_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedAction {
    Launch,
    Message,
    Steer,
    Interrupt,
    Stop,
    Restart,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedAgent {
    Codex,
    Claude,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPhase {
    Admitted,
    Issued,
    Completed,
    Rejected,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedLifecycle {
    Unspecified,
    Starting,
    Running,
    Stopping,
    Stopped,
    Exited,
    Failed,
    Interrupted,
}

impl ManagedPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Issued => "issued",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedMutation {
    pub request_id: Uuid,
    pub organization_id: String,
    pub environment_id: String,
    pub pod_uid: String,
    pub binding_generation: u64,
    pub projection_selection_sha256: String,
    pub action: ManagedAction,
    pub cleanup_of_request_id: Option<Uuid>,
    pub agent: Option<ManagedAgent>,
    pub session_id: String,
    pub driver_id: Uuid,
    pub message_id: Option<Uuid>,
    #[serde(with = "decimal_u64")]
    pub expected_launch_generation: u64,
    pub parent_session_id: Option<String>,
    #[serde(with = "decimal_u64")]
    pub expected_parent_launch_generation: u64,
    pub support_image_sha256: String,
    pub support_image_size: u64,
    pub private_fingerprint: String,
}

impl ManagedMutation {
    pub fn from_private(request: &private::PlatformManagedMutationRequest) -> AppResult<Self> {
        use private::platform_managed_mutation_request::Operation;
        let private_fingerprint =
            wire::platform_managed_request_fingerprint(request).map_err(|_| invalid())?;
        let request_id = uuid(&request.request_id)?;
        let scope = request.scope.as_ref().ok_or_else(invalid)?;
        let (action, agent, driver_id, generation, message_id, parent, parent_generation) =
            match request.operation.as_ref().ok_or_else(invalid)? {
                Operation::Launch(l) => (
                    ManagedAction::Launch,
                    Some(
                        match private::PlatformManagedAgent::try_from(l.agent)
                            .map_err(|_| invalid())?
                        {
                            private::PlatformManagedAgent::Codex => ManagedAgent::Codex,
                            private::PlatformManagedAgent::Claude => ManagedAgent::Claude,
                            _ => return Err(invalid()),
                        },
                    ),
                    request_id,
                    1,
                    if l.prompt.is_some() {
                        Some(uuid(
                            &wire::platform_managed_initial_prompt_id(&request.request_id)
                                .map_err(|_| invalid())?,
                        )?)
                    } else {
                        None
                    },
                    (!l.parent_session_id.is_empty()).then(|| l.parent_session_id.clone()),
                    l.expected_parent_launch_generation,
                ),
                Operation::Control(c) => {
                    let action = match private::PlatformManagedAction::try_from(c.action)
                        .map_err(|_| invalid())?
                    {
                        private::PlatformManagedAction::Message => ManagedAction::Message,
                        private::PlatformManagedAction::Steer => ManagedAction::Steer,
                        private::PlatformManagedAction::Interrupt => ManagedAction::Interrupt,
                        private::PlatformManagedAction::Stop => ManagedAction::Stop,
                        private::PlatformManagedAction::Restart => ManagedAction::Restart,
                        _ => return Err(invalid()),
                    };
                    (
                        action,
                        None,
                        uuid(&c.driver_id)?,
                        c.expected_launch_generation,
                        if matches!(
                            action,
                            ManagedAction::Message
                                | ManagedAction::Steer
                                | ManagedAction::Interrupt
                        ) {
                            Some(request_id)
                        } else {
                            None
                        },
                        None,
                        0,
                    )
                }
            };
        let cleanup_of_request_id = match request.operation.as_ref().ok_or_else(invalid)? {
            Operation::Launch(_) => None,
            Operation::Control(c) => c.cleanup_of_request_id.as_deref().map(uuid).transpose()?,
        };
        let value = Self {
            request_id,
            organization_id: scope.org_id.clone(),
            environment_id: scope.environment_id.clone(),
            pod_uid: scope.pod_uid.clone(),
            binding_generation: scope.binding_generation,
            projection_selection_sha256: hex(&scope.projection_selection_sha256),
            action,
            cleanup_of_request_id,
            agent,
            session_id: format!("session-{driver_id}"),
            driver_id,
            message_id,
            expected_launch_generation: generation,
            parent_session_id: parent,
            expected_parent_launch_generation: parent_generation,
            support_image_sha256: hex(&scope.support_image_sha256),
            support_image_size: scope.support_image_size,
            private_fingerprint,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> AppResult<()> {
        if self.organization_id.is_empty()
            || self.organization_id.len() > 256
            || self.organization_id.chars().any(char::is_control)
            || !wire::valid_uuid(&self.environment_id)
            || !wire::valid_uuid(&self.pod_uid)
            || self.binding_generation == 0
            || !wire::valid_hash(&self.projection_selection_sha256)
            || self.request_id.is_nil()
            || self.cleanup_of_request_id.is_some_and(|id| {
                id.is_nil() || id == self.request_id || self.action != ManagedAction::Stop
            })
            || self.driver_id.is_nil()
            || self.session_id != format!("session-{}", self.driver_id)
            || self.expected_launch_generation == 0
            || !wire::valid_hash(&self.private_fingerprint)
            || !wire::valid_hash(&self.support_image_sha256)
            || !(4..=wire::SUPPORT_BYTES).contains(&self.support_image_size)
            || self.message_id.is_some_and(|m| m.is_nil())
            || self
                .parent_session_id
                .as_ref()
                .is_some_and(|s| !wire::valid_session(s))
            || self.parent_session_id.is_some() != (self.expected_parent_launch_generation > 0)
            || (self.action == ManagedAction::Launch) != self.agent.is_some()
            || (self.action == ManagedAction::Launch
                && (self.driver_id != self.request_id || self.expected_launch_generation != 1))
            || (self.action != ManagedAction::Launch && self.parent_session_id.is_some())
            || (matches!(
                self.action,
                ManagedAction::Message | ManagedAction::Steer | ManagedAction::Interrupt
            ) && self.message_id != Some(self.request_id))
            || (matches!(self.action, ManagedAction::Stop | ManagedAction::Restart)
                && self.message_id.is_some())
        {
            return Err(invalid());
        }
        bounded_json(self)?;
        Ok(())
    }
    pub(super) fn validate_binding(&self, b: &CapturedBindingFacts) -> AppResult<()> {
        self.validate()?;
        b.validate()?;
        if self.organization_id != b.organization_id
            || self.environment_id != b.environment_id
            || self.pod_uid != b.pod_uid
            || self.binding_generation
                != u64::try_from(b.binding_generation).map_err(|_| invalid())?
            || Some(&self.projection_selection_sha256) != b.projection_selection_sha256.as_ref()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedReceipt {
    pub request_id: Uuid,
    pub organization_id: String,
    pub environment_id: String,
    pub pod_uid: String,
    pub binding_generation: u64,
    pub projection_selection_sha256: String,
    pub support_image_sha256: String,
    pub support_image_size: u64,
    pub private_fingerprint: String,
    pub phase: ManagedPhase,
    pub session_id: String,
    pub driver_id: Uuid,
    pub message_id: Option<Uuid>,
    #[serde(with = "decimal_u64")]
    pub launch_generation: u64,
    pub lifecycle: ManagedLifecycle,
    pub exit_code: Option<i32>,
    pub cleanup_unknown: bool,
    pub pipe_acknowledged: bool,
    pub native_acknowledged: bool,
    pub cleanup_of_request_id: Option<Uuid>,
    #[serde(with = "decimal_u64")]
    pub cleanup_previous_generation: u64,
    pub cleanup_previous_cleanup_known: bool,
    pub reason_code: String,
}

impl ManagedReceipt {
    pub fn from_private(r: &private::PlatformManagedReceipt) -> AppResult<Self> {
        wire::validate_receipt(r).map_err(|_| invalid())?;
        if r.reason.len() > 64
            || !wire::valid_hash(&r.fingerprint_sha256)
            || !wire::valid_session(&r.session_id)
        {
            return Err(invalid());
        }
        let s = r.scope.as_ref().ok_or_else(invalid)?;
        wire::validate_scope(s).map_err(|_| invalid())?;
        let phase =
            match private::PlatformManagedRequestPhase::try_from(r.phase).map_err(|_| invalid())? {
                private::PlatformManagedRequestPhase::Pending => ManagedPhase::Admitted,
                private::PlatformManagedRequestPhase::Issued => ManagedPhase::Issued,
                private::PlatformManagedRequestPhase::Completed => ManagedPhase::Completed,
                private::PlatformManagedRequestPhase::Rejected => ManagedPhase::Rejected,
                private::PlatformManagedRequestPhase::Unknown => ManagedPhase::Unknown,
                _ => return Err(invalid()),
            };
        let lifecycle = match private::SessionLifecycleState::try_from(r.session_state)
            .map_err(|_| invalid())?
        {
            private::SessionLifecycleState::Unspecified => ManagedLifecycle::Unspecified,
            private::SessionLifecycleState::Starting => ManagedLifecycle::Starting,
            private::SessionLifecycleState::Running => ManagedLifecycle::Running,
            private::SessionLifecycleState::Stopping => ManagedLifecycle::Stopping,
            private::SessionLifecycleState::Stopped => ManagedLifecycle::Stopped,
            private::SessionLifecycleState::Exited => ManagedLifecycle::Exited,
            private::SessionLifecycleState::Failed => ManagedLifecycle::Failed,
            private::SessionLifecycleState::Interrupted => ManagedLifecycle::Interrupted,
        };
        Ok(Self {
            request_id: uuid(&r.request_id)?,
            organization_id: s.org_id.clone(),
            environment_id: s.environment_id.clone(),
            pod_uid: s.pod_uid.clone(),
            binding_generation: s.binding_generation,
            projection_selection_sha256: hex(&s.projection_selection_sha256),
            support_image_sha256: hex(&s.support_image_sha256),
            support_image_size: s.support_image_size,
            private_fingerprint: r.fingerprint_sha256.clone(),
            phase,
            session_id: r.session_id.clone(),
            driver_id: uuid(&r.driver_id)?,
            message_id: if r.message_id.is_empty() {
                None
            } else {
                Some(uuid(&r.message_id)?)
            },
            launch_generation: r.launch_generation,
            lifecycle,
            exit_code: r.exit_code,
            cleanup_unknown: r.cleanup_unknown,
            pipe_acknowledged: r.pipe_acknowledged,
            native_acknowledged: r.native_acknowledged,
            cleanup_of_request_id: r.cleanup_of_request_id.as_deref().map(uuid).transpose()?,
            cleanup_previous_generation: r.cleanup_previous_generation,
            cleanup_previous_cleanup_known: r.cleanup_previous_cleanup_known,
            reason_code: r.reason.clone(),
        })
    }
    pub fn known_clean(&self) -> bool {
        !self.cleanup_unknown
            && ((self.lifecycle == ManagedLifecycle::Stopped && self.exit_code.is_none())
                || (self.lifecycle == ManagedLifecycle::Exited && self.exit_code == Some(0)))
    }
    pub fn validate_for(&self, m: &ManagedMutation, b: &CapturedBindingFacts) -> AppResult<()> {
        m.validate_binding(b)?;
        let generation =
            if m.action == ManagedAction::Restart && self.phase == ManagedPhase::Completed {
                m.expected_launch_generation
                    .checked_add(1)
                    .ok_or_else(invalid)?
            } else {
                m.expected_launch_generation
            };
        if self.request_id != m.request_id
            || self.organization_id != b.organization_id
            || self.environment_id != b.environment_id
            || self.pod_uid != b.pod_uid
            || self.binding_generation
                != u64::try_from(b.binding_generation).map_err(|_| invalid())?
            || Some(&self.projection_selection_sha256) != b.projection_selection_sha256.as_ref()
            || self.support_image_sha256 != m.support_image_sha256
            || self.support_image_size != m.support_image_size
            || self.private_fingerprint != m.private_fingerprint
            || self.session_id != m.session_id
            || self.driver_id != m.driver_id
            || self.message_id != m.message_id
            || self.cleanup_of_request_id != m.cleanup_of_request_id
            || (self.cleanup_of_request_id.is_none()
                && (self.cleanup_previous_generation != 0 || self.cleanup_previous_cleanup_known))
            || (self.cleanup_of_request_id.is_some()
                && (self.cleanup_previous_generation == 0
                    || self.cleanup_previous_cleanup_known
                        != (self.phase == ManagedPhase::Completed)
                    || !(self.launch_generation == self.cleanup_previous_generation
                        || self.cleanup_previous_generation.checked_add(1)
                            == Some(self.launch_generation))))
            || self.launch_generation != generation
            || !valid_private_reason(&self.reason_code)
            || self.native_acknowledged && !self.pipe_acknowledged
            || (self.phase != ManagedPhase::Completed
                && (self.pipe_acknowledged || self.native_acknowledged))
            || (!matches!(
                self.lifecycle,
                ManagedLifecycle::Exited | ManagedLifecycle::Failed
            ) && self.exit_code.is_some())
        {
            return Err(invalid());
        }
        if self.phase == ManagedPhase::Completed {
            if self.reason_code != "settled" || self.cleanup_unknown {
                return Err(invalid());
            }
            match m.action {
                ManagedAction::Stop
                    if !self.known_clean()
                        || self.pipe_acknowledged
                        || self.native_acknowledged =>
                {
                    return Err(invalid());
                }
                ManagedAction::Launch | ManagedAction::Restart
                    if !matches!(self.lifecycle, ManagedLifecycle::Running)
                        || self.pipe_acknowledged
                        || self.native_acknowledged =>
                {
                    return Err(invalid());
                }
                ManagedAction::Message | ManagedAction::Steer
                    if !self.pipe_acknowledged
                        || !matches!(self.lifecycle, ManagedLifecycle::Running) =>
                {
                    return Err(invalid());
                }
                ManagedAction::Interrupt
                    if !self.native_acknowledged
                        || !matches!(
                            self.lifecycle,
                            ManagedLifecycle::Running | ManagedLifecycle::Interrupted
                        ) =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        if (self.phase == ManagedPhase::Rejected
            && (self.reason_code != "refused-before-issue"
                || self.cleanup_unknown
                || self.pipe_acknowledged
                || self.native_acknowledged))
            || (self.phase == ManagedPhase::Unknown
                && !matches!(
                    self.reason_code.as_str(),
                    "issued-outcome-unknown" | "target-owner-lost"
                ))
        {
            return Err(invalid());
        }
        bounded_json(self)?;
        Ok(())
    }
}

pub(super) fn fingerprint(
    actor: &str,
    api: bool,
    delegated: Option<&str>,
    m: &ManagedMutation,
    b: &CapturedBindingFacts,
) -> AppResult<String> {
    if actor.is_empty()
        || actor.len() > 256
        || actor.chars().any(char::is_control)
        || api != delegated.is_some()
        || delegated.is_some_and(|o| o != b.organization_id)
    {
        return Err(invalid());
    }
    let value = serde_json::json!({"domain":"codewire.platform-managed-admission.v1","actor":actor,
        "via_api_key":api,"delegated_organization_id":delegated,"mutation":m,"binding":b});
    Ok(format!("{:x}", Sha256::digest(bounded_json(&value)?)))
}
pub(super) fn bounded_json(v: &impl Serialize) -> AppResult<Vec<u8>> {
    let bytes = codewire_cw_release::identity::canonical_json(v).map_err(|_| invalid())?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(super) fn invalid() -> AppError {
    AppError::BadRequest("platform managed metadata is invalid".into())
}
pub(super) fn conflict() -> AppError {
    AppError::Conflict(
        "platform managed request requires observation or original-generation cleanup".into(),
    )
}
pub(super) fn unavailable() -> AppError {
    AppError::ServiceUnavailable("platform managed journal is unavailable".into())
}
pub(super) fn uuid(s: &str) -> AppResult<Uuid> {
    if !wire::valid_uuid(s) {
        return Err(invalid());
    }
    Uuid::parse_str(s).map_err(|_| invalid())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn valid_reason(s: &str) -> bool {
    matches!(
        s,
        "" | "platform-agent-preissue-refused"
            | "platform-agent-cancelled-before-dispatch"
            | "platform-agent-dispatch-unknown"
            | "platform-agent-command-refused"
    )
}
fn valid_private_reason(s: &str) -> bool {
    matches!(
        s,
        "pending"
            | "issued"
            | "settled"
            | "refused-before-issue"
            | "issued-outcome-unknown"
            | "target-owner-lost"
    )
}
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let n = s.parse::<u64>().map_err(serde::de::Error::custom)?;
        if s != n.to_string() {
            return Err(serde::de::Error::custom(
                "generation is not canonical decimal",
            ));
        }
        Ok(n)
    }
}
