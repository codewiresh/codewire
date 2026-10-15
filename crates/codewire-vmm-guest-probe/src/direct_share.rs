//! Canonical guest-visible plan for explicit host directory shares.
//!
//! This plan contains only the virtio-fs tag, the admitted guest destination,
//! the read-only decision, and the share-relative paths kept on the VM's own
//! disk (`vm_only`). Host paths and host filesystem identities stay in the
//! private supervisor/runner control plane. The seed binds the digest of these
//! exact bytes so guest-writable persistent state cannot redirect a later boot
//! to a different layout. An empty `vm_only` is not encoded, so a plan without
//! one has the same bytes as before the field existed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Sha256Value;

pub const DIRECT_SHARE_PLAN_PATH: &str = "/state/codewire/direct-shares.json";
pub const DIRECT_SHARE_PLAN_RELATIVE_PATH: &str = "codewire/direct-shares.json";
pub const MAX_DIRECT_SHARES: usize = 16;
pub const MAX_DIRECT_SHARE_PLAN_BYTES: usize = 128 * 1024;
/// Present once in a guest init that binds `vm_only` paths. Host preflight
/// reads it from the admitted boot image before it creates or starts a VM
/// whose plan keeps paths on the VM's disk; an older guest would refuse that
/// plan only at boot.
pub const VM_ONLY_CAPABILITY_MARKER: &[u8] = b"CODEWIRE_GUEST_VM_ONLY_V1\0";
/// The most share-relative paths one share keeps on the VM's own disk.
pub const MAX_VM_ONLY_PATHS: usize = 32;
const MAX_VM_ONLY_PATH_BYTES: usize = 1024;
const MAX_VM_ONLY_TOTAL_BYTES: usize = 4096;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_GUEST_PATH_BYTES: usize = 4096;

const DIRECT_SHARE_PLAN_SCHEMA_VERSION: u32 = 1;
const DIRECT_SHARE_TAG_PREFIX: &str = "cw-direct-";
const WORKSPACE_PREFIX: &str = "/workspace/";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectShareMount {
    tag: String,
    destination: String,
    read_only: bool,
    /// Share-relative directories the guest backs with its own disk and binds
    /// over the share. Empty for read-only shares.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vm_only: Vec<String>,
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
            vm_only: Vec::new(),
        };
        mount.validate_at(index)?;
        Ok(mount)
    }

    /// This share with `vm_only` paths kept on the VM's own disk. A read-only
    /// share takes none.
    pub fn with_vm_only(mut self, vm_only: Vec<String>) -> Result<Self, DirectSharePlanError> {
        self.vm_only = vm_only;
        self.validate_vm_only()?;
        Ok(self)
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

    pub fn vm_only(&self) -> &[String] {
        &self.vm_only
    }

    fn validate_at(&self, index: usize) -> Result<(), DirectSharePlanError> {
        if self.tag != format!("{DIRECT_SHARE_TAG_PREFIX}{index:02}")
            || !valid_destination(&self.destination)
        {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        self.validate_vm_only()
    }

    fn validate_vm_only(&self) -> Result<(), DirectSharePlanError> {
        if (self.read_only && !self.vm_only.is_empty())
            || !valid_vm_only_paths(&self.vm_only)
            || self
                .vm_only
                .iter()
                .any(|path| self.destination.len() + 1 + path.len() > MAX_GUEST_PATH_BYTES)
        {
            return Err(DirectSharePlanError::InvalidPlan);
        }
        Ok(())
    }
}

/// Whether `paths` is a valid `vm_only` list: at most [`MAX_VM_ONLY_PATHS`]
/// normalized relative paths (no leading or trailing `/`, no empty, `.`,
/// `..` or `.git` segment, no control character), 4 KiB in all, none equal
/// to or nested in another even ignoring ASCII case (macOS shares are
/// case-insensitive).
pub fn valid_vm_only_paths(paths: &[String]) -> bool {
    paths.len() <= MAX_VM_ONLY_PATHS
        && paths.iter().map(String::len).sum::<usize>() <= MAX_VM_ONLY_TOTAL_BYTES
        && paths.iter().all(|path| valid_vm_only_path(path))
        && paths.iter().enumerate().all(|(index, path)| {
            paths[index + 1..]
                .iter()
                .all(|other| !vm_only_paths_overlap(path, other))
        })
}

fn valid_vm_only_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_VM_ONLY_PATH_BYTES
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && !component.eq_ignore_ascii_case(".git")
                && component.len() <= MAX_PATH_COMPONENT_BYTES
        })
}

fn vm_only_paths_overlap(left: &str, right: &str) -> bool {
    let (left, right) = (left.to_ascii_lowercase(), right.to_ascii_lowercase());
    let nested = |outer: &str, inner: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|suffix| suffix.starts_with('/'))
    };
    left == right || nested(&left, &right) || nested(&right, &left)
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

    #[test]
    fn plans_without_vm_only_keep_their_exact_bytes() {
        // A plan written before vm_only existed decodes and re-encodes to the
        // same bytes, so its seed digest is unchanged.
        let before = br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":false},{"tag":"cw-direct-01","destination":"/workspace/ref","read_only":true}]}"#;
        let plan = DirectSharePlan::decode_canonical(before).unwrap();
        assert!(plan.mounts().iter().all(|mount| mount.vm_only().is_empty()));
        assert_eq!(plan.encode_canonical().unwrap(), before);
        let built = DirectSharePlan::new(vec![
            DirectShareMount::for_index(0, "/workspace/app", false)
                .unwrap()
                .with_vm_only(Vec::new())
                .unwrap(),
            DirectShareMount::for_index(1, "/workspace/ref", true).unwrap(),
        ])
        .unwrap();
        assert_eq!(built, plan);
        assert_eq!(built.sha256().unwrap(), Sha256Value::calculate(before));
    }

    #[test]
    fn vm_only_round_trips_canonically_and_changes_the_digest() {
        let paths = vec![
            "node_modules".to_owned(),
            "target".to_owned(),
            "packages/web/.venv".to_owned(),
        ];
        let plan = DirectSharePlan::new(vec![
            DirectShareMount::for_index(0, "/workspace/app", false)
                .unwrap()
                .with_vm_only(paths.clone())
                .unwrap(),
        ])
        .unwrap();
        let bytes = plan.encode_canonical().unwrap();
        assert_eq!(
            bytes,
            br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":false,"vm_only":["node_modules","target","packages/web/.venv"]}]}"#
        );
        let decoded = DirectSharePlan::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded.mounts()[0].vm_only(), paths);
        let without = DirectSharePlan::new(vec![
            DirectShareMount::for_index(0, "/workspace/app", false).unwrap(),
        ])
        .unwrap();
        assert_ne!(plan.sha256().unwrap(), without.sha256().unwrap());

        // An explicit empty list is not the canonical encoding.
        let explicit_empty = br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":false,"vm_only":[]}]}"#;
        assert!(DirectSharePlan::decode_canonical(explicit_empty).is_err());
        // Unknown fields stay refused.
        let unknown = br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":false,"vm_only":["a"],"other":1}]}"#;
        assert!(DirectSharePlan::decode_canonical(unknown).is_err());
    }

    #[test]
    fn vm_only_rejects_read_only_shares_and_unsafe_paths() {
        let share = || DirectShareMount::for_index(0, "/workspace/app", false).unwrap();
        assert!(
            DirectShareMount::for_index(0, "/workspace/app", true)
                .unwrap()
                .with_vm_only(vec!["node_modules".to_owned()])
                .is_err()
        );
        for path in [
            "", "/abs", "../up", "a/../b", "./a", ".", "..", "a//b", "a/", "a\0b", "a\nb",
        ] {
            let path = path.to_owned();
            assert!(
                share().with_vm_only(vec![path.clone()]).is_err(),
                "{path:?}"
            );
        }
        for path in [".git", "x/.git", ".GIT/y"] {
            assert!(
                share().with_vm_only(vec![path.to_owned()]).is_err(),
                "{path:?}"
            );
        }
        assert!(share().with_vm_only(vec![".github".to_owned()]).is_ok());
        for paths in [
            vec!["a", "a"],
            vec!["a", "a/b"],
            vec!["a/b", "a"],
            vec!["Node_modules", "node_modules"],
            vec!["A", "a/b"],
        ] {
            let paths = paths.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(share().with_vm_only(paths.clone()).is_err(), "{paths:?}");
        }
        assert!(
            share()
                .with_vm_only(vec!["a".to_owned(), "ab".to_owned(), "a-b".to_owned()])
                .is_ok()
        );
        assert!(share().with_vm_only(vec!["x".repeat(256)]).is_err());
        // Six paths of about 750 bytes each exceed the 4 KiB total.
        let wide = (0..6)
            .map(|index| {
                format!(
                    "{index}/{}/{}/{}",
                    "y".repeat(250),
                    "z".repeat(250),
                    "w".repeat(250)
                )
            })
            .collect::<Vec<_>>();
        assert!(share().with_vm_only(wide[..5].to_vec()).is_ok());
        assert!(share().with_vm_only(wide).is_err());
        let many = (0..=MAX_VM_ONLY_PATHS)
            .map(|index| format!("d{index}"))
            .collect::<Vec<_>>();
        assert!(
            share()
                .with_vm_only(many[..MAX_VM_ONLY_PATHS].to_vec())
                .is_ok()
        );
        assert!(share().with_vm_only(many).is_err());

        // A decoded plan gets the same checks.
        let read_only = br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":true,"vm_only":["a"]}]}"#;
        assert!(DirectSharePlan::decode_canonical(read_only).is_err());
        let escaping = br#"{"schema_version":1,"mounts":[{"tag":"cw-direct-00","destination":"/workspace/app","read_only":false,"vm_only":["../state"]}]}"#;
        assert!(DirectSharePlan::decode_canonical(escaping).is_err());
    }
}
