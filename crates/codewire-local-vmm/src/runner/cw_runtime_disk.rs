//! Whether a running VM still has the cw runtime disk it was admitted with,
//! and selecting a separate read-only `cw-runtime` store root for `standard`
//! Pods (#5602).

use std::path::PathBuf;

use super::CloudHypervisorRunner;
use crate::RunnerError;
#[cfg(target_os = "linux")]
use crate::ch_api::VmInfo;
#[cfg(target_os = "linux")]
use crate::cw_runtime::AdmittedCwRuntimeDisk;
use crate::host::path::PrivateRoot;

impl CloudHypervisorRunner {
    /// Open and revalidate the `cw-runtime` catalog from `root` instead of
    /// `state_root` (used by `standard` Pods whose catalog is pre-baked
    /// read-only into the runtime image, #5602).
    pub fn with_cw_runtime_root(mut self, root: PathBuf) -> Result<Self, RunnerError> {
        self.cw_runtime_root = Some(PrivateRoot::open(&root)?);
        Ok(self)
    }

    pub(super) fn cw_runtime_root(&self) -> &PrivateRoot {
        self.cw_runtime_root.as_ref().unwrap_or(&self.state_root)
    }

    pub(super) fn open_cw_runtime_disk(
        &self,
        generation: Option<&str>,
    ) -> Result<Option<crate::cw_runtime::AdmittedCwRuntimeDisk>, RunnerError> {
        Ok(generation
            .map(|generation| {
                crate::cw_runtime::CwRuntimeStore::create(self.cw_runtime_root())?
                    .open_catalog(generation)
            })
            .transpose()?)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn validate_live_cw_runtime_disk(
    info: &VmInfo,
    expected: &AdmittedCwRuntimeDisk,
) -> Result<(), RunnerError> {
    use codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_DISK_SERIAL;
    let disks = info
        .additional
        .get("config")
        .and_then(|config| config.get("disks"))
        .and_then(serde_json::Value::as_array)
        .ok_or(RunnerError::CwRuntimeDiskChanged)?;
    let path = expected
        .path
        .to_str()
        .ok_or(RunnerError::CwRuntimeDiskChanged)?;
    let mut matches = 0;
    for disk in disks {
        let candidate = disk.get("id").and_then(serde_json::Value::as_str) == Some("cw-runtime")
            || disk.get("serial").and_then(serde_json::Value::as_str)
                == Some(CW_RUNTIME_DISK_SERIAL)
            || disk.get("path").and_then(serde_json::Value::as_str) == Some(path);
        if !candidate {
            continue;
        }
        matches += 1;
        if disk.get("id").and_then(serde_json::Value::as_str) != Some("cw-runtime")
            || disk.get("serial").and_then(serde_json::Value::as_str)
                != Some(CW_RUNTIME_DISK_SERIAL)
            || disk.get("path").and_then(serde_json::Value::as_str) != Some(path)
            || disk.get("readonly").and_then(serde_json::Value::as_bool) != Some(true)
            || disk.get("direct").and_then(serde_json::Value::as_bool) != Some(false)
            || disk
                .get("backing_files")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
            || disk.get("vhost_user").and_then(serde_json::Value::as_bool) != Some(false)
            || disk.get("sparse").and_then(serde_json::Value::as_bool) != Some(false)
            || !disk
                .get("image_type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("raw"))
            || !disk
                .get("lock_granularity")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("full"))
        {
            return Err(RunnerError::CwRuntimeDiskChanged);
        }
    }
    if matches != 1 {
        return Err(RunnerError::CwRuntimeDiskChanged);
    }
    Ok(())
}
