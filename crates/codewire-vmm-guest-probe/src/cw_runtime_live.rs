//! Closed host-to-guest runtime publication and selection contract.
//!
//! The bootstrap is never replaced. Every process keeps its digest path;
//! selection changes only what a later launcher resolves.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cw_runtime::{CW_RUNTIME_MAX_CATALOG, CwRuntimeCatalog, CwRuntimeProvenance};

pub const LIVE_RUNTIME_PROTOCOL: u32 = 1;
// Separate from network7775, progress7776 and the authenticated daemon7777.
pub const LIVE_RUNTIME_VSOCK_PORT: u32 = 7_778;
pub const LIVE_RUNTIME_MAX_FRAME: usize = CW_RUNTIME_MAX_CATALOG * 2;
pub const LIVE_RUNTIME_MAX_OPERATIONS: usize = 128;
pub const LIVE_RUNTIME_TIMEOUT_SECONDS: u64 = 120;
pub const LIVE_RUNTIME_CACHE: &str = "/state/codewire/cw-runtime";
pub const LIVE_RUNTIME_VIEW: &str = "/state/codewire/cw-runtime/view";
// A login shell may replace PATH. Bind the same trusted launcher at the
// workspace's fixed system location without changing any payload path.
pub const LIVE_RUNTIME_LAUNCHER: &str = "/usr/local/bin/cw";
pub const LIVE_RUNTIME_CAPABILITY_MARKER: &[u8] = b"CODEWIRE_NATIVE_CW_LIVE_PUBLISHER_V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub environment_id: Uuid,
    pub generation: u64,
    pub bootstrap_catalog_sha256: String,
}

impl RuntimeBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.environment_id.is_nil()
            || self.generation == 0
            || !digest(&self.bootstrap_catalog_sha256)
        {
            return Err("invalid native runtime identity");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionOutcome {
    Committed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionReceipt {
    pub operation_id: Uuid,
    pub generation: u64,
    pub expected_revision: u64,
    pub target_sha256: String,
    pub outcome: SelectionOutcome,
    pub selection_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelection {
    pub schema_version: u32,
    pub environment_id: Uuid,
    pub bootstrap_catalog_sha256: String,
    pub revision: u64,
    pub previous_sha256: Option<String>,
    pub catalog: CwRuntimeCatalog,
    // Retention is bounded and never pruned behind an uncertain caller. Once
    // full, further selection operations refuse before any selector effect.
    pub operations: Vec<SelectionReceipt>,
}

impl RuntimeSelection {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != LIVE_RUNTIME_PROTOCOL
            || self.environment_id.is_nil()
            || !digest(&self.bootstrap_catalog_sha256)
            || self.revision == 0
            || self.operations.len() > LIVE_RUNTIME_MAX_OPERATIONS
            || self
                .previous_sha256
                .as_ref()
                .is_some_and(|previous| self.catalog.runtime(previous).is_none())
        {
            return Err("invalid native runtime selector");
        }
        self.catalog.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        for receipt in &self.operations {
            if receipt.operation_id.is_nil()
                || !ids.insert(receipt.operation_id)
                || receipt.generation == 0
                || receipt.expected_revision == 0
                || !digest(&receipt.target_sha256)
                || receipt.selection_revision == 0
                || receipt.selection_revision > self.revision
                || (receipt.outcome == SelectionOutcome::Committed
                    && (receipt.expected_revision.checked_add(1)
                        != Some(receipt.selection_revision)
                        || self.catalog.runtime(&receipt.target_sha256).is_none()))
            {
                return Err("invalid native runtime operation receipt");
            }
        }
        Ok(())
    }

    pub fn receipt(&self, id: Uuid) -> Option<&SelectionReceipt> {
        self.operations
            .iter()
            .find(|receipt| receipt.operation_id == id)
    }

    pub fn admit_binding(&self, binding: &RuntimeBinding) -> Result<(), &'static str> {
        binding.validate()?;
        self.validate()?;
        if self.environment_id != binding.environment_id
            || self.bootstrap_catalog_sha256 != binding.bootstrap_catalog_sha256
        {
            return Err("native runtime bootstrap identity changed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeAction {
    Info,
    Observe {
        operation_id: Uuid,
    },
    Publish {
        operation_id: Uuid,
        pack_size: u64,
        pack_sha256: String,
        provenance: Box<CwRuntimeProvenance>,
    },
    Select {
        operation_id: Uuid,
        expected_revision: u64,
        target_sha256: String,
    },
    RetainedSelect {
        operation_id: Uuid,
        expected_revision: u64,
        target_sha256: String,
    },
    Cancel {
        operation_id: Uuid,
        expected_revision: u64,
        target_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequest {
    pub protocol_version: u32,
    pub binding: RuntimeBinding,
    pub action: RuntimeAction,
}

impl RuntimeRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.binding.validate()?;
        if self.protocol_version != LIVE_RUNTIME_PROTOCOL {
            return Err("unsupported native runtime publisher protocol");
        }
        match &self.action {
            RuntimeAction::Info => {}
            RuntimeAction::Observe { operation_id } => require_operation(*operation_id)?,
            RuntimeAction::Publish {
                operation_id,
                pack_size,
                pack_sha256,
                provenance,
            } => {
                require_operation(*operation_id)?;
                provenance.validate()?;
                if !digest(pack_sha256)
                    || !(24..=crate::cw_runtime::CW_RUNTIME_MAX_PACK as u64).contains(pack_size)
                {
                    return Err("invalid native runtime publication bounds");
                }
            }
            RuntimeAction::Select {
                operation_id,
                expected_revision,
                target_sha256,
            }
            | RuntimeAction::RetainedSelect {
                operation_id,
                expected_revision,
                target_sha256,
            }
            | RuntimeAction::Cancel {
                operation_id,
                expected_revision,
                target_sha256,
            } => {
                require_operation(*operation_id)?;
                if *expected_revision == 0 || !digest(target_sha256) {
                    return Err("invalid native runtime selection request");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReply {
    pub protocol_version: u32,
    pub binding: RuntimeBinding,
    pub selection: RuntimeSelection,
    pub observed: Option<SelectionReceipt>,
}

impl RuntimeReply {
    pub fn validate(&self, binding: &RuntimeBinding) -> Result<(), &'static str> {
        if self.protocol_version != LIVE_RUNTIME_PROTOCOL || &self.binding != binding {
            return Err("native runtime publisher identity changed");
        }
        self.selection.admit_binding(binding)?;
        if let Some(observed) = &self.observed
            && self.selection.receipt(observed.operation_id) != Some(observed)
        {
            return Err("native runtime operation observation changed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRefusal {
    Identity,
    Unsupported,
    Invalid,
    StaleRevision,
    Collision,
    Capacity,
    Cancelled,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResponse {
    pub reply: Option<RuntimeReply>,
    pub refusal: Option<RuntimeRefusal>,
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "invalid runtime frame")?;
    if bytes.is_empty() || bytes.len() > LIVE_RUNTIME_MAX_FRAME {
        return Err("runtime frame exceeds its bound");
    }
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    Ok(frame)
}

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_operation(id: Uuid) -> Result<(), &'static str> {
    if id.is_nil() {
        Err("invalid native runtime operation identity")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> RuntimeRequest {
        RuntimeRequest {
            protocol_version: LIVE_RUNTIME_PROTOCOL,
            binding: RuntimeBinding {
                environment_id: Uuid::new_v4(),
                generation: 1,
                bootstrap_catalog_sha256: "a".repeat(64),
            },
            action: RuntimeAction::Info,
        }
    }
    #[test]
    fn live_runtime_protocol_refuses_old_or_unknown_versions() {
        for version in [0, LIVE_RUNTIME_PROTOCOL + 1] {
            let mut request = fixture();
            request.protocol_version = version;
            assert!(request.validate().is_err());
        }
        assert_eq!(LIVE_RUNTIME_VSOCK_PORT, 7778);
    }
    #[test]
    fn live_runtime_identity_refuses_nil_zero_and_noncanonical_digest() {
        let original = fixture();
        let mut request = original.clone();
        request.binding.environment_id = Uuid::nil();
        assert!(request.validate().is_err());
        request = original.clone();
        request.binding.generation = 0;
        assert!(request.validate().is_err());
        request = original;
        request.binding.bootstrap_catalog_sha256 = "A".repeat(64);
        assert!(request.validate().is_err());
    }
    #[test]
    fn live_runtime_wire_refuses_unknown_fields_and_general_actions() {
        let request = fixture();
        let mut value = serde_json::to_value(&request).unwrap();
        value["root_exec"] = serde_json::json!("/bin/sh");
        assert!(serde_json::from_value::<RuntimeRequest>(value).is_err());
        let mut value = serde_json::to_value(request).unwrap();
        value["action"] = serde_json::json!({"action":"delete","path":"/state"});
        assert!(serde_json::from_value::<RuntimeRequest>(value).is_err());
    }
    #[test]
    fn live_runtime_frames_are_closed_and_bounded() {
        let bytes = encode_frame(&fixture()).unwrap();
        let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(size, bytes.len() - 4);
        assert!(encode_frame(&"x".repeat(LIVE_RUNTIME_MAX_FRAME)).is_err());
    }
    #[test]
    fn live_runtime_publication_refuses_size_and_provenance_mismatch() {
        let (_, bytes) = crate::cw_runtime::fixture();
        let provenance = CwRuntimeProvenance::decode(&bytes).unwrap();
        let mut request = fixture();
        request.action = RuntimeAction::Publish {
            operation_id: Uuid::new_v4(),
            pack_size: crate::cw_runtime::CW_RUNTIME_MAX_PACK as u64 + 1,
            pack_sha256: "a".repeat(64),
            provenance: Box::new(provenance),
        };
        assert!(request.validate().is_err());
        // Boxing is Rust layout only; the published JSON remains the same
        // closed provenance object and does not add an indirection wrapper.
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["action"]["provenance"],
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        );
        assert_eq!(
            serde_json::from_value::<RuntimeRequest>(json).unwrap(),
            request
        );
    }
    #[test]
    fn live_runtime_reply_cannot_rebind_generation_or_bootstrap() {
        let request = fixture();
        let (_, bytes) = crate::cw_runtime::fixture();
        let member = CwRuntimeProvenance::decode(&bytes).unwrap();
        let selection = RuntimeSelection {
            schema_version: 1,
            environment_id: request.binding.environment_id,
            bootstrap_catalog_sha256: request.binding.bootstrap_catalog_sha256.clone(),
            revision: 1,
            previous_sha256: None,
            catalog: CwRuntimeCatalog {
                schema_version: 1,
                active_sha256: member.payload.sha256.clone(),
                runtimes: vec![member],
            },
            operations: Vec::new(),
        };
        let mut reply = RuntimeReply {
            protocol_version: 1,
            binding: request.binding.clone(),
            selection,
            observed: None,
        };
        assert!(reply.validate(&request.binding).is_ok());
        reply.binding.generation += 1;
        assert!(reply.validate(&request.binding).is_err());
        reply.binding = request.binding.clone();
        reply.selection.bootstrap_catalog_sha256 = "b".repeat(64);
        assert!(reply.validate(&request.binding).is_err());
    }
}
