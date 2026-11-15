//! Whether a running VM still has the cw runtime disk it was admitted with.

use crate::RunnerError;
use crate::ch_api::VmInfo;
use crate::cw_runtime::AdmittedCwRuntimeDisk;

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
