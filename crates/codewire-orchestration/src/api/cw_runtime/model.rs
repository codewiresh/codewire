//! Closed, nonsecret journal facts. These are not provider credentials,
//! commands, launch values or evidence that any remote executable has run.

use chrono::{DateTime, NaiveDateTime, Utc};
use codewire_cw_release::identity::{CwPayloadIdentity, Os, canonical_json, is_sha256_hex};
use codewire_server_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{PlatformCwRuntimeIncarnation, validate_expected};
use crate::worker::workspace_binding::CwRuntimeLiveBinding;

pub(super) const MAX_JSON_BYTES: usize = 32 * 1024;
pub(super) const MAX_CHECKPOINTS: i32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAction {
    Update,
    Rollback,
}

/// Pure intent; it neither resolves a latest environment nor executes incoming
/// bytes. Complete compiled-record intake belongs to the later adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMutation {
    pub request_id: Uuid,
    pub action: RuntimeAction,
    #[serde(with = "decimal_u64")]
    pub expected_store_generation: u64,
    pub expected_current_sha256: Option<String>,
    /// Store's retained rollback default, not the pre-command current. A
    /// no-op selection preserves this value without increasing generation.
    pub expected_previous_sha256: Option<String>,
    pub bootstrap_identity: Option<CwPayloadIdentity>,
    pub target_identity: CwPayloadIdentity,
}

impl RuntimeMutation {
    pub fn validate(&self) -> AppResult<()> {
        if self.request_id.is_nil()
            || !self
                .target_identity
                .validate()
                .is_ok_and(|t| t.platform().os == Os::Linux)
            || self
                .expected_current_sha256
                .as_deref()
                .is_some_and(|v| !is_sha256_hex(v))
            || self
                .expected_previous_sha256
                .as_deref()
                .is_some_and(|v| !is_sha256_hex(v))
            || (self.expected_store_generation == 0 && self.expected_previous_sha256.is_some())
            || (self.expected_store_generation == 0) != self.expected_current_sha256.is_none()
        {
            return Err(invalid_request());
        }
        match (&self.bootstrap_identity, self.expected_store_generation) {
            (Some(bootstrap), 0)
                if self.action == RuntimeAction::Update
                    && bootstrap.validate().is_ok()
                    && bootstrap.target == self.target_identity.target => {}
            (None, 1..) => {}
            _ => return Err(invalid_request()),
        }
        if self.expected_store_generation == u64::MAX
            && self.expected_current_sha256.as_deref() != Some(&self.target_identity.sha256)
        {
            return Err(invalid_request());
        }
        bounded_json(self)?;
        Ok(())
    }
}

/// A closed future effect. The current journal component only records these;
/// it has no daemon/FileService/ExecSession dispatch implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEffect {
    Bootstrap,
    Staging,
    Update,
    Rollback,
    Cleanup,
}

impl RuntimeEffect {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Staging => "staging",
            Self::Update => "update",
            Self::Rollback => "rollback",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Admitted,
    Issued,
    Acknowledged,
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectReceipt {
    Staged {
        sha256: String,
        size: u64,
    },
    Selected {
        sha256: String,
        #[serde(with = "decimal_u64")]
        generation: u64,
        previous_sha256: Option<String>,
        changed: bool,
    },
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointAcknowledgement {
    pub checkpoint: i32,
    pub effect: RuntimeEffect,
    pub receipt: EffectReceipt,
}

/// Every field of the originally joined row, without the Pod credential or
/// channel. Equality is checked under admission locks, never reconstructed
/// from the latest target at request recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedBindingFacts {
    pub organization_id: String,
    pub organization_deletion_state: String,
    pub organization_deletion_generation: i64,
    pub environment_id: String,
    pub environment_state: String,
    pub desired_state: String,
    pub environment_type: String,
    pub isolation_tier: String,
    pub environment_generation: i64,
    pub deletion_requested_at: Option<NaiveDateTime>,
    pub backend_namespace: String,
    pub backend_pod_name: String,
    pub backend_pod_ip: String,
    pub backend_pod_uid: String,
    pub backend_claim_uid: Option<String>,
    pub backend_pvc_uid: Option<String>,
    pub backend_bound_at: DateTime<Utc>,
    pub setup_complete: bool,
    pub setup_owner_status: Option<String>,
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub claim_uid: String,
    pub sandbox_uid: String,
    pub workspace_pvc_uid: Option<String>,
    pub binding_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub credential_scope: String,
    pub binding_bound_at: DateTime<Utc>,
}

impl CapturedBindingFacts {
    pub fn incarnation(&self) -> PlatformCwRuntimeIncarnation {
        PlatformCwRuntimeIncarnation {
            organization_id: self.organization_id.clone(),
            environment_id: self.environment_id.clone(),
            environment_generation: self.environment_generation,
            namespace: self.namespace.clone(),
            pod_name: self.pod_name.clone(),
            pod_uid: self.pod_uid.clone(),
            claim_uid: self.claim_uid.clone(),
            sandbox_uid: self.sandbox_uid.clone(),
            workspace_pvc_uid: self.workspace_pvc_uid.clone(),
            binding_generation: self.binding_generation,
            projection_selection_sha256: self.projection_selection_sha256.clone(),
            managed_credential_clients: self.managed_credential_clients.clone(),
            binding_bound_at: self.binding_bound_at,
        }
    }

    pub(crate) fn validate(&self) -> AppResult<()> {
        validate_expected(&self.incarnation())?;
        if self.organization_deletion_state != "active"
            || self.organization_deletion_generation < 0
            || self.environment_state != "running"
            || self.desired_state != "started"
            || self.environment_type != "sandbox"
            || self.deletion_requested_at.is_some()
            || self.backend_namespace != self.namespace
            || self.backend_pod_name != self.pod_name
            || self.backend_pod_uid != self.pod_uid
            || self.backend_claim_uid.as_deref() != Some(&self.claim_uid)
            || self.backend_pvc_uid != self.workspace_pvc_uid
            || self.backend_bound_at != self.binding_bound_at
            || !self.setup_complete
            || self.setup_owner_status.is_some()
            || self.credential_scope != "pod"
            || self.backend_pod_ip.parse::<std::net::IpAddr>().is_err()
            || !matches!(self.isolation_tier.as_str(), "standard" | "confidential")
        {
            return Err(invalid_request());
        }
        bounded_json(self)?;
        Ok(())
    }
}

impl From<&CwRuntimeLiveBinding> for CapturedBindingFacts {
    fn from(row: &CwRuntimeLiveBinding) -> Self {
        Self {
            organization_id: row.organization_id.clone(),
            organization_deletion_state: row.organization_deletion_state.clone(),
            organization_deletion_generation: row.organization_deletion_generation,
            environment_id: row.environment_id.clone(),
            environment_state: row.environment_state.clone(),
            desired_state: row.desired_state.clone(),
            environment_type: row.environment_type.clone(),
            isolation_tier: row.isolation_tier.clone(),
            environment_generation: row.environment_generation,
            deletion_requested_at: row.deletion_requested_at,
            backend_namespace: row.backend_namespace.clone(),
            backend_pod_name: row.backend_pod_name.clone(),
            backend_pod_ip: row.backend_pod_ip.clone(),
            backend_pod_uid: row.backend_pod_uid.clone(),
            backend_claim_uid: row.backend_claim_uid.clone(),
            backend_pvc_uid: row.backend_pvc_uid.clone(),
            backend_bound_at: row.backend_bound_at,
            setup_complete: row.setup_complete,
            setup_owner_status: row.setup_owner_status.clone(),
            pod_uid: row.pod_uid.clone(),
            namespace: row.namespace.clone(),
            pod_name: row.pod_name.clone(),
            claim_uid: row.claim_uid.clone(),
            sandbox_uid: row.sandbox_uid.clone(),
            workspace_pvc_uid: row.workspace_pvc_uid.clone(),
            binding_generation: row.binding_generation,
            projection_selection_sha256: row.projection_selection_sha256.clone(),
            managed_credential_clients: row.managed_credential_clients.clone(),
            credential_scope: row.credential_scope.clone(),
            binding_bound_at: row.binding_bound_at,
        }
    }
}

pub(super) fn fingerprint(
    actor: &str,
    via_api_key: bool,
    delegated_organization: Option<&str>,
    mutation: &RuntimeMutation,
    binding: &CapturedBindingFacts,
) -> AppResult<String> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        actor: &'a str,
        via_api_key: bool,
        delegated_organization: Option<&'a str>,
        mutation: &'a RuntimeMutation,
        binding: &'a CapturedBindingFacts,
    }
    let bytes = bounded_json(&Fingerprint {
        actor,
        via_api_key,
        delegated_organization,
        mutation,
        binding,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn bounded_json(value: &impl Serialize) -> AppResult<Vec<u8>> {
    let bytes = canonical_json(value).map_err(|_| invalid_request())?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(invalid_request());
    }
    Ok(bytes)
}

pub(super) fn invalid_request() -> AppError {
    AppError::BadRequest("cw runtime request metadata is invalid".into())
}

pub(super) fn unavailable() -> AppError {
    AppError::ServiceUnavailable("cw runtime journal is unavailable".into())
}

pub(super) fn conflict() -> AppError {
    AppError::Conflict("cw runtime request requires observation or resolution".into())
}

pub(super) fn not_found() -> AppError {
    AppError::NotFound("cw runtime request not found".into())
}

pub(super) mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(serde::de::Error::custom)?;
        if parsed.to_string() != value {
            return Err(serde::de::Error::custom(
                "generation is not canonical decimal",
            ));
        }
        Ok(parsed)
    }
}
