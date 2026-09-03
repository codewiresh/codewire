//! Canonical guest-visible plan for explicit host directory shares.
//!
//! This plan contains only the virtio-fs tag, the admitted guest destination,
//! and the read-only decision. Host paths and host filesystem identities stay
//! in the private supervisor/runner control plane. The seed binds the digest
//! of these exact bytes so guest-writable persistent state cannot redirect a
//! later boot to a different layout.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Sha256Value;

pub const DIRECT_SHARE_PLAN_PATH: &str = "/state/codewire/direct-shares.json";
pub const DIRECT_SHARE_PLAN_RELATIVE_PATH: &str = "codewire/direct-shares.json";
pub const MAX_DIRECT_SHARES: usize = 16;
pub const MAX_DIRECT_SHARE_PLAN_BYTES: usize = 128 * 1024;

const DIRECT_SHARE_PLAN_SCHEMA_VERSION: u32 = 1;
const DIRECT_SHARE_TAG_PREFIX: &str = "cw-direct-";
const WORKSPACE_PREFIX: &str = "/workspace/";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectShareMount {
    tag: String,
    destination: String,
    read_only: bool,
}

impl DirectShareMount {
    pub fn for_index(
        index: usize,
        destination: impl Into<String>,
        read_only: bool,
    ) -> Result<Self, DirectSharePlanError> {
        if index >= MAX_DIRECT_SHARES {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        let mount = Self {
            tag: format!("{DIRECT_SHARE_TAG_PREFIX}{index:02}"),
            destination: destination.into(),
            read_only,
        };
        mount.validate_at(index)?;
        Ok(mount)
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn validate_at(&self, index: usize) -> Result<(), DirectSharePlanError> {
        if self.tag != format!("{DIRECT_SHARE_TAG_PREFIX}{index:02}")
            || !valid_destination(&self.destination)
        {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSharePlan {
    schema_version: u32,
    mounts: Vec<DirectShareMount>,
}

impl DirectSharePlan {
    pub fn new(mounts: Vec<DirectShareMount>) -> Result<Self, DirectSharePlanError> {
        let plan = Self {
            schema_version: DIRECT_SHARE_PLAN_SCHEMA_VERSION,
            mounts,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn mounts(&self) -> &[DirectShareMount] {
        &self.mounts
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, DirectSharePlanError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| DirectSharePlanError::InvalidPlan)?;
        if bytes.is_empty() || bytes.len() > MAX_DIRECT_SHARE_PLAN_BYTES {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DirectSharePlanError> {
        if bytes.is_empty() || bytes.len() > MAX_DIRECT_SHARE_PLAN_BYTES {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        let plan: Self =
            serde_json::from_slice(bytes).map_err(|_| DirectSharePlanError::InvalidPlan)?;
        plan.validate()?;
        if plan.encode_canonical()? != bytes {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        Ok(plan)
    }

    pub fn sha256(&self) -> Result<Sha256Value, DirectSharePlanError> {
        Ok(Sha256Value::calculate(&self.encode_canonical()?))
    }

    fn validate(&self) -> Result<(), DirectSharePlanError> {
        if self.schema_version != DIRECT_SHARE_PLAN_SCHEMA_VERSION
            || self.mounts.is_empty()
            || self.mounts.len() > MAX_DIRECT_SHARES
        {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        for (index, mount) in self.mounts.iter().enumerate() {
            mount.validate_at(index)?;
        }
        let mut destinations = self
            .mounts
            .iter()
            .map(|mount| mount.destination.as_str())
            .collect::<Vec<_>>();
        destinations.sort_unstable();
        if destinations.windows(2).any(|pair| {
            pair[0] == pair[1]
                || pair[1]
                    .strip_prefix(pair[0])
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        Ok(())
    }
}

fn valid_destination(destination: &str) -> bool {
    let Some(relative) = destination.strip_prefix(WORKSPACE_PREFIX) else {
        return false;
    };
    !relative.is_empty()
        && !destination.ends_with('/')
        && !destination.as_bytes().contains(&0)
        && destination.len() <= 4096
        && relative
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DirectSharePlanError {
    #[error("direct-share guest plan is invalid")]
    InvalidPlan,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_plan_contains_only_guest_safe_fields() {
        let plan = DirectSharePlan::new(vec![
            DirectShareMount::for_index(0, "/workspace/source", true).unwrap(),
            DirectShareMount::for_index(1, "/workspace/output", false).unwrap(),
        ])
        .unwrap();
        let bytes = plan.encode_canonical().unwrap();
        assert_eq!(DirectSharePlan::decode_canonical(&bytes).unwrap(), plan);
        assert_eq!(plan.mounts()[0].tag(), "cw-direct-00");
        assert_eq!(plan.mounts()[1].destination(), "/workspace/output");
        assert!(!plan.mounts()[1].read_only());
        assert!(!String::from_utf8(bytes).unwrap().contains("host"));
    }

    #[test]
    fn plan_rejects_noncanonical_tags_paths_and_overlap() {
        assert!(DirectShareMount::for_index(0, "/workspace", true).is_err());
        assert!(DirectShareMount::for_index(0, "/workspace/a/../b", true).is_err());
        assert!(
            DirectSharePlan::new(vec![
                DirectShareMount::for_index(0, "/workspace/a", true).unwrap(),
                DirectShareMount::for_index(1, "/workspace/a/b", true).unwrap(),
            ])
            .is_err()
        );

        let bytes = br#"{"schema_version":1,"mounts":[{"tag":"other","destination":"/workspace/a","read_only":true}]}"#;
        assert!(DirectSharePlan::decode_canonical(bytes).is_err());
    }
}
