//! Closed private role framing and lossless public contract conversion.
use chrono::{DateTime, Utc};
use codewire_cw_release::identity::{CwPayloadIdentity, canonical_json, is_sha256_hex};
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::AppResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::PlatformCwRuntimeIncarnation;
use super::model::{EffectReceipt, RuntimeAction, RuntimeEffect, RuntimeMutation, invalid_request};
use super::owner::RuntimeRequest;

pub(super) const MAX_FRAME: usize = 32 * 1024;
pub(super) const MAX_CHUNK: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Correlation {
    pub request_id: Uuid,
    pub pod_uid: Uuid,
    pub binding_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExpectedSelection {
    pub generation: u64,
    pub current: Option<String>,
    pub previous: Option<String>,
}

impl ExpectedSelection {
    pub fn validate(&self) -> AppResult<()> {
        if (self.generation == 0) != self.current.is_none()
            || self.current.as_deref().is_some_and(|v| !is_sha256_hex(v))
            || self.previous.as_deref().is_some_and(|v| !is_sha256_hex(v))
            || (self.generation == 0 && self.previous.is_some())
            || (self.previous.is_some() && self.previous == self.current)
        {
            return Err(invalid_request());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Action {
    Status,
    Bootstrap {
        identity: CwPayloadIdentity,
        expected: ExpectedSelection,
    },
    Stage {
        identity: CwPayloadIdentity,
        expected: ExpectedSelection,
    },
    Update {
        identity: CwPayloadIdentity,
        expected: ExpectedSelection,
    },
    Rollback {
        identity: CwPayloadIdentity,
        expected: ExpectedSelection,
    },
    Cleanup {
        bootstrap: Option<CwPayloadIdentity>,
        candidate: Option<CwPayloadIdentity>,
    },
}

#[derive(Serialize)]
pub(super) struct RoleRequest {
    pub schema_version: u32,
    pub request_id: Uuid,
    pub pod_uid: Uuid,
    pub binding_sha256: String,
    pub action: Action,
}

impl RoleRequest {
    pub fn frame(correlation: &Correlation, action: Action) -> AppResult<Vec<u8>> {
        let request = Self {
            schema_version: 1,
            request_id: correlation.request_id,
            pod_uid: correlation.pod_uid,
            binding_sha256: correlation.binding_sha256.clone(),
            action,
        };
        let json = canonical_json(&request).map_err(|_| invalid_request())?;
        if json.is_empty() || json.len() > MAX_FRAME {
            return Err(invalid_request());
        }
        let mut result = Vec::with_capacity(json.len() + 4);
        result.extend_from_slice(&(json.len() as u32).to_le_bytes());
        result.extend_from_slice(&json);
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservedSelection {
    pub generation: u64,
    pub current: Option<CwPayloadIdentity>,
    pub previous: Option<CwPayloadIdentity>,
    pub pending: bool,
    pub consistent: bool,
    pub retained_count: usize,
}

impl ObservedSelection {
    pub fn expected(&self) -> AppResult<ExpectedSelection> {
        let value = ExpectedSelection {
            generation: self.generation,
            current: self.current.as_ref().map(|v| v.sha256.clone()),
            previous: self.previous.as_ref().map(|v| v.sha256.clone()),
        };
        value.validate()?;
        for identity in [&self.current, &self.previous].into_iter().flatten() {
            validate_identity(identity)?;
        }
        if self.retained_count > 1024
            || self.retained_count < usize::from(self.current.is_some())
            || (self.generation == 0 && self.retained_count != 0)
        {
            return Err(invalid_request());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReplyBody {
    Status {
        supported_image: bool,
        bootstrap: Option<Box<CwPayloadIdentity>>,
        selection: Box<ObservedSelection>,
    },
    Staged {
        sha256: String,
        size: u64,
    },
    Selected {
        sha256: String,
        generation: u64,
        previous_sha256: Option<String>,
        changed: bool,
    },
    Cleaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Code {
    InvalidFrame,
    UnsupportedImage,
    UnsafeState,
    ReadOnly,
    UnmanagedEntry,
    StaleSelection,
    PendingSelection,
    CandidateRefused,
    StageExists,
    MissingStage,
    InputIncomplete,
    Deadline,
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Outcome {
    Succeeded { result: ReplyBody },
    Refused { code: Code },
    Unknown { code: Code },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u32,
    correlation: Correlation,
    outcome: Outcome,
}

pub(super) fn reply(bytes: &[u8], expected: &Correlation, exit: i32) -> AppResult<Outcome> {
    if bytes.len() < 5 || bytes.len() > MAX_FRAME + 4 {
        return Err(invalid_request());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| invalid_request())?) as usize;
    if count == 0 || count > MAX_FRAME || bytes.len() != count + 4 {
        return Err(invalid_request());
    }
    let value: Reply = serde_json::from_slice(&bytes[4..]).map_err(|_| invalid_request())?;
    if value.schema_version != 1
        || value.correlation != *expected
        || canonical_json(&value).map_err(|_| invalid_request())? != bytes[4..]
        || !matches!(
            (&value.outcome, exit),
            (Outcome::Succeeded { .. }, 0)
                | (Outcome::Refused { .. }, 3)
                | (Outcome::Unknown { .. }, 4)
        )
    {
        return Err(invalid_request());
    }
    if let Outcome::Succeeded {
        result:
            ReplyBody::Status {
                supported_image,
                bootstrap,
                selection,
            },
    } = &value.outcome
    {
        selection.expected()?;
        if let Some(identity) = bootstrap {
            validate_identity(identity)?;
        }
        if *supported_image != bootstrap.is_some() {
            return Err(invalid_request());
        }
    }
    Ok(value.outcome)
}

pub(super) fn validate_identity(value: &CwPayloadIdentity) -> AppResult<()> {
    if value.target != "x86_64-unknown-linux-musl" || value.validate().is_err() {
        return Err(invalid_request());
    }
    Ok(())
}

pub(super) fn identity(
    value: &proto::EnvironmentCwRuntimeIdentity,
) -> AppResult<CwPayloadIdentity> {
    if !value.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    // Bounds precede owned copies, validation and diagnostic construction.
    if value.package_version.len() > 64
        || value.target.len() > 64
        || value.source_revision.len() != 40
        || value.source_tree_sha256.len() != 64
        || value.rustc.len() > 128
        || value.sha256.len() != 64
    {
        return Err(invalid_request());
    }
    let result = CwPayloadIdentity {
        schema_version: value.schema_version,
        protocol_version: value.protocol_version,
        record_version: value.record_version,
        package_version: value.package_version.clone(),
        target: value.target.clone(),
        source_revision: value.source_revision.clone(),
        source_tree_sha256: value.source_tree_sha256.clone(),
        rustc: value.rustc.clone(),
        sha256: value.sha256.clone(),
        size: value.size,
    };
    validate_identity(&result)?;
    Ok(result)
}

pub(super) fn proto_identity(value: &CwPayloadIdentity) -> proto::EnvironmentCwRuntimeIdentity {
    proto::EnvironmentCwRuntimeIdentity {
        schema_version: value.schema_version,
        protocol_version: value.protocol_version,
        record_version: value.record_version,
        package_version: value.package_version.clone(),
        target: value.target.clone(),
        source_revision: value.source_revision.clone(),
        source_tree_sha256: value.source_tree_sha256.clone(),
        rustc: value.rustc.clone(),
        sha256: value.sha256.clone(),
        size: value.size,
        ..Default::default()
    }
}

pub(super) fn expectation(
    value: &proto::EnvironmentCwRuntimeExpectation,
) -> AppResult<ExpectedSelection> {
    if !value.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    let result = ExpectedSelection {
        generation: value.generation,
        current: value.current_sha256.clone(),
        previous: value.previous_sha256.clone(),
    };
    result.validate()?;
    Ok(result)
}

pub(super) fn incarnation(
    value: &proto::EnvironmentCwRuntimeIncarnation,
) -> AppResult<PlatformCwRuntimeIncarnation> {
    if !value.__buffa_unknown_fields.is_empty() {
        return Err(invalid_request());
    }
    if value.org_id.len() > 128
        || value.environment_id.len() != 36
        || value.namespace.len() > 63
        || value.pod_name.len() > 253
        || value.pod_uid.len() != 36
        || value.claim_uid.len() != 36
        || value.sandbox_uid.len() != 36
        || value
            .workspace_pvc_uid
            .as_ref()
            .is_some_and(|v| v.len() != 36)
        || value
            .projection_selection_sha256
            .as_ref()
            .is_some_and(|v| v.len() != 64)
        || value.managed_credential_clients.len() > 128
    {
        return Err(invalid_request());
    }
    let time = value
        .binding_bound_at
        .as_option()
        .ok_or_else(invalid_request)?;
    if !time.__buffa_unknown_fields.is_empty() || !(0..1_000_000_000).contains(&time.nanos) {
        return Err(invalid_request());
    }
    let result = PlatformCwRuntimeIncarnation {
        organization_id: value.org_id.clone(),
        environment_id: value.environment_id.clone(),
        environment_generation: i64::try_from(value.environment_generation)
            .map_err(|_| invalid_request())?,
        namespace: value.namespace.clone(),
        pod_name: value.pod_name.clone(),
        pod_uid: value.pod_uid.clone(),
        claim_uid: value.claim_uid.clone(),
        sandbox_uid: value.sandbox_uid.clone(),
        workspace_pvc_uid: value.workspace_pvc_uid.clone(),
        binding_generation: i64::try_from(value.binding_generation)
            .map_err(|_| invalid_request())?,
        projection_selection_sha256: value.projection_selection_sha256.clone(),
        managed_credential_clients: value.managed_credential_clients.clone(),
        binding_bound_at: DateTime::from_timestamp(time.seconds, time.nanos as u32)
            .ok_or_else(invalid_request)?,
    };
    super::validate_expected(&result)?;
    Ok(result)
}

pub(super) fn proto_incarnation(
    value: &PlatformCwRuntimeIncarnation,
) -> AppResult<proto::EnvironmentCwRuntimeIncarnation> {
    Ok(proto::EnvironmentCwRuntimeIncarnation {
        org_id: value.organization_id.clone(),
        environment_id: value.environment_id.clone(),
        environment_generation: u64::try_from(value.environment_generation)
            .map_err(|_| invalid_request())?,
        namespace: value.namespace.clone(),
        pod_name: value.pod_name.clone(),
        pod_uid: value.pod_uid.clone(),
        claim_uid: value.claim_uid.clone(),
        sandbox_uid: value.sandbox_uid.clone(),
        workspace_pvc_uid: value.workspace_pvc_uid.clone(),
        binding_generation: u64::try_from(value.binding_generation)
            .map_err(|_| invalid_request())?,
        projection_selection_sha256: value.projection_selection_sha256.clone(),
        managed_credential_clients: value.managed_credential_clients.clone(),
        binding_bound_at: Some(timestamp(value.binding_bound_at)).into(),
        ..Default::default()
    })
}

pub(super) fn proto_selection(
    value: &ObservedSelection,
) -> AppResult<proto::EnvironmentCwRuntimeSelection> {
    value.expected()?;
    Ok(proto::EnvironmentCwRuntimeSelection {
        generation: value.generation,
        current: value.current.as_ref().map(proto_identity).into(),
        previous: value.previous.as_ref().map(proto_identity).into(),
        pending: value.pending,
        consistent: value.consistent,
        retained_count: u32::try_from(value.retained_count).map_err(|_| invalid_request())?,
        ..Default::default()
    })
}

pub(super) fn uuid(value: &str) -> AppResult<Uuid> {
    if value.len() != 36 {
        return Err(invalid_request());
    }
    let parsed = Uuid::parse_str(value).map_err(|_| invalid_request())?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(invalid_request());
    }
    Ok(parsed)
}

pub(super) fn effect_name(effect: RuntimeEffect) -> &'static str {
    match effect {
        RuntimeEffect::Bootstrap => "bootstrap",
        RuntimeEffect::Staging => "staging",
        RuntimeEffect::Update => "update",
        RuntimeEffect::Rollback => "rollback",
        RuntimeEffect::Cleanup => "cleanup",
    }
}

pub(super) fn proto_operation(
    value: &RuntimeRequest,
) -> AppResult<proto::EnvironmentCwRuntimeOperation> {
    use proto::environment_cw_runtime_acknowledgement::Receipt;
    let acknowledgements = value
        .acknowledgements
        .iter()
        .map(|ack| {
            let receipt = match &ack.receipt {
                EffectReceipt::Staged { sha256, size } => {
                    Receipt::Staged(Box::new(proto::EnvironmentCwRuntimeStaged {
                        sha256: sha256.clone(),
                        size: *size,
                        ..Default::default()
                    }))
                }
                EffectReceipt::Selected {
                    sha256,
                    generation,
                    previous_sha256,
                    changed,
                } => Receipt::Selected(Box::new(proto::EnvironmentCwRuntimeSelected {
                    sha256: sha256.clone(),
                    generation: *generation,
                    previous_sha256: previous_sha256.clone(),
                    changed: *changed,
                    ..Default::default()
                })),
                EffectReceipt::Cleaned => Receipt::Cleaned(Box::default()),
            };
            Ok(proto::EnvironmentCwRuntimeAcknowledgement {
                checkpoint: u32::try_from(ack.checkpoint).map_err(|_| invalid_request())?,
                effect: effect_name(ack.effect).into(),
                receipt: Some(receipt),
                ..Default::default()
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(proto::EnvironmentCwRuntimeOperation {
        request_id: value.mutation.request_id.to_string(),
        incarnation: Some(proto_incarnation(&value.binding.incarnation())?).into(),
        action: match value.mutation.action {
            RuntimeAction::Update => "update",
            RuntimeAction::Rollback => "rollback",
        }
        .into(),
        phase: serde_json::to_value(value.phase)
            .map_err(|_| invalid_request())?
            .as_str()
            .ok_or_else(invalid_request)?
            .into(),
        checkpoint: u32::try_from(value.checkpoint).map_err(|_| invalid_request())?,
        issued_effect: value.effect.map(|v| effect_name(v).into()),
        expected_selection: Some(proto::EnvironmentCwRuntimeExpectation {
            generation: value.mutation.expected_store_generation,
            current_sha256: value.mutation.expected_current_sha256.clone(),
            previous_sha256: value.mutation.expected_previous_sha256.clone(),
            ..Default::default()
        })
        .into(),
        identity: Some(proto_identity(&value.mutation.target_identity)).into(),
        bootstrap_identity: value
            .mutation
            .bootstrap_identity
            .as_ref()
            .map(proto_identity)
            .into(),
        acknowledgements,
        error_code: value.error_code.clone(),
        admitted_at: Some(timestamp(value.admitted_at)).into(),
        issued_at: value.issued_at.map(timestamp).into(),
        terminal_at: value.terminal_at.map(timestamp).into(),
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;

fn timestamp(value: DateTime<Utc>) -> buffa_types::Timestamp {
    buffa_types::Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

pub(super) fn mutation(
    request_id: &str,
    action: RuntimeAction,
    expected: &ExpectedSelection,
    target: CwPayloadIdentity,
    bootstrap: Option<CwPayloadIdentity>,
) -> AppResult<RuntimeMutation> {
    let result = RuntimeMutation {
        request_id: uuid(request_id)?,
        action,
        expected_store_generation: expected.generation,
        expected_current_sha256: expected.current.clone(),
        expected_previous_sha256: expected.previous.clone(),
        bootstrap_identity: bootstrap,
        target_identity: target,
    };
    result.validate()?;
    Ok(result)
}
