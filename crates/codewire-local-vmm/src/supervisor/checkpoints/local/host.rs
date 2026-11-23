//! What a VM checkpoint's admission reads differently on each host: the
//! VMM's files, the host the checkpoint was taken on, and the VMM build it
//! restores into (#4654).

use std::io::Read as _;

use sha2::Digest as _;

use super::*;
use crate::artifact::AdmittedArtifacts;

/// The VMM files' recorded digests.
pub(in crate::supervisor) struct VmmFiles {
    pub(in crate::supervisor) config_sha256: String,
    pub(in crate::supervisor) state_sha256: String,
}

/// The digest of `name` under `root`, sealed 0400 and at most `limit`
/// bytes, with its contents.
fn digest_sealed(
    root: &PrivateRoot,
    directory: &Path,
    name: &str,
    limit: u64,
) -> Result<(String, Vec<u8>), SupervisorError> {
    let opened = root
        .open_regular(Path::new(name), false, None, false, Some(0o400))
        .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
    let mut bytes = Vec::new();
    opened
        .file()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| SupervisorError::Io {
            path: directory.join(name),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    Ok((format!("{:x}", sha2::Sha256::digest(&bytes)), bytes))
}

/// The VMM's configuration: a JSON object.
fn digest_config(root: &PrivateRoot, vmm: &Path, name: &str) -> Result<String, SupervisorError> {
    let (sha256, config) = digest_sealed(root, vmm, name, MAXIMUM_VMM_CONFIG_BYTES)?;
    if !serde_json::from_slice::<serde_json::Value>(&config).is_ok_and(|value| value.is_object()) {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    Ok(sha256)
}

/// Read `vmm/` as Cloud Hypervisor must have written it: exactly its three
/// files, sealed 0400, the memory file exactly `memory_bytes`, the
/// configuration a JSON object.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) fn read_vmm_files(
    vmm: &Path,
    memory_bytes: u64,
) -> Result<VmmFiles, SupervisorError> {
    only_entries(vmm, &CHECKPOINT_VMM_FILES)?;
    let root = PrivateRoot::open(vmm)?;
    let config_sha256 = digest_config(&root, vmm, "config.json")?;
    let (state_sha256, _) = digest_sealed(&root, vmm, "state.json", MAXIMUM_VMM_STATE_BYTES)?;
    root.open_regular(
        Path::new("memory-ranges"),
        false,
        Some(memory_bytes),
        false,
        Some(0o400),
    )
    .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
    Ok(VmmFiles {
        config_sha256,
        state_sha256,
    })
}

/// Read `vmm/` as the macOS helper must have written it: exactly its
/// configuration and saved state, sealed 0400, the configuration a JSON
/// object. The saved state holds the guest's memory in a format the host
/// never parses, so it is admitted by size alone, between 1 MiB and the
/// memory plus 64 MiB, and pinned by its digest.
#[cfg(target_os = "macos")]
pub(in crate::supervisor) fn read_vmm_files(
    vmm: &Path,
    memory_bytes: u64,
) -> Result<VmmFiles, SupervisorError> {
    only_entries(vmm, &CHECKPOINT_VMM_FILES)?;
    let root = PrivateRoot::open(vmm)?;
    let config_sha256 = digest_config(&root, vmm, crate::vz::CONFIG_NAME)?;
    let state = crate::vz::CHECKPOINT_STATE_NAME;
    let opened = root
        .open_regular(Path::new(state), false, None, false, Some(0o400))
        .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
    let io_error = |source| SupervisorError::Io {
        path: vmm.join(state),
        source,
    };
    let bytes = opened.file().metadata().map_err(io_error)?.len();
    if !(MIB..=memory_bytes.saturating_add(MAXIMUM_VMM_STATE_BYTES)).contains(&bytes) {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    let mut digest = sha2::Sha256::new();
    let read = std::io::copy(&mut opened.file().take(bytes + 1), &mut digest).map_err(io_error)?;
    if read != bytes {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    Ok(VmmFiles {
        config_sha256,
        state_sha256: format!("{:x}", digest.finalize()),
    })
}

/// The first processor's vendor, family, model and stepping, and the
/// kernel release.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) fn host_identity() -> HostIdentity {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |key: &str| {
        cpuinfo
            .lines()
            .take_while(|line| !line.trim().is_empty())
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim() == key).then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    };
    // x86_64 names these; aarch64 names its implementer and part.
    let cpu = [
        field("vendor_id"),
        field("cpu family"),
        field("model"),
        field("stepping"),
        field("CPU implementer"),
        field("CPU part"),
        field("CPU variant"),
        field("CPU revision"),
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>()
    .join(":");
    HostIdentity {
        cpu: if cpu.is_empty() {
            "unknown".to_owned()
        } else {
            cpu
        },
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|release| release.trim().to_owned())
            .unwrap_or_default(),
    }
}

/// The Mac's hardware model (`hw.model`) and its macOS build
/// (`kern.osversion`, as `sw_vers -buildVersion` prints it), in the
/// manifest's `cpu` and `kernel_release`.
#[cfg(target_os = "macos")]
pub(in crate::supervisor) fn host_identity() -> HostIdentity {
    HostIdentity {
        cpu: sysctl_text(c"hw.model").unwrap_or_else(|| "unknown".to_owned()),
        kernel_release: sysctl_text(c"kern.osversion").unwrap_or_default(),
    }
}

/// A short NUL-terminated string sysctl, read without a subprocess.
#[cfg(target_os = "macos")]
fn sysctl_text(name: &std::ffi::CStr) -> Option<String> {
    let mut bytes = [0_u8; 256];
    let mut length = bytes.len();
    // SAFETY: the name is NUL-terminated, the writable buffer and length
    // remain live, and null newp/zero newlen make this a read-only query.
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return None;
    }
    let text = std::ffi::CStr::from_bytes_until_nul(bytes.get(..length)?).ok()?;
    let text = text.to_str().ok()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Why this host cannot restore a checkpoint taken on `recorded`: another
/// CPU on Linux, where another kernel is allowed; another hardware model or
/// macOS build on a Mac, since a restore across a macOS update is not
/// proven. A listing shows it, and a restore or fork is refused with it.
pub(in crate::supervisor) fn other_host(recorded: &HostIdentity) -> Option<String> {
    let host = host_identity();
    if host.cpu != recorded.cpu {
        return Some(format!(
            "it was taken on another CPU ({}; this host has {})",
            recorded.cpu, host.cpu
        ));
    }
    #[cfg(target_os = "macos")]
    if host.kernel_release != recorded.kernel_release {
        return Some(format!(
            "it was taken on macOS build {}, and this Mac runs {}; a VM checkpoint restores only on the macOS build it was taken on",
            recorded.kernel_release, host.kernel_release
        ));
    }
    None
}

pub(in crate::supervisor) fn require_same_host(
    checkpoint_name: &str,
    recorded: &HostIdentity,
) -> Result<(), Status> {
    match other_host(recorded) {
        Some(reason) => Err(Status::failed_precondition(format!(
            "VM checkpoint {checkpoint_name} cannot be restored here: {reason}"
        ))),
        None => Ok(()),
    }
}

/// A Mac restores or forks a VM checkpoint only while it is unlocked: macOS
/// releases the key that protects the saved state only then (#5976). It is
/// refused before the source stops or a fork is made, so nothing changes.
pub(in crate::supervisor) fn require_unlocked(
    checkpoint_name: &str,
    verb: &str,
) -> Result<(), Status> {
    if crate::console_lock::screen_locked() {
        return Err(Status::failed_precondition(format!(
            "VM checkpoint {checkpoint_name} cannot be {verb} while this Mac is locked: unlock it and run the command again"
        )));
    }
    Ok(())
}

/// A Linux checkpoint taken under another host kernel restores, and says so.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) fn host_warning(recorded: &HostIdentity) -> Option<String> {
    let host = host_identity();
    (host.kernel_release != recorded.kernel_release).then(|| {
        format!(
            "taken under host kernel {}; this host runs {}",
            recorded.kernel_release, host.kernel_release
        )
    })
}

/// A Mac records its macOS build there, and another build is refused
/// ([`other_host`]), so there is nothing to warn about.
#[cfg(target_os = "macos")]
pub(in crate::supervisor) fn host_warning(_recorded: &HostIdentity) -> Option<String> {
    None
}

/// The VMM file that holds the guest's memory.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) const MEMORY_FILE: &str = "memory-ranges";
#[cfg(target_os = "macos")]
pub(in crate::supervisor) const MEMORY_FILE: &str = crate::vz::CHECKPOINT_STATE_NAME;

/// The VMM executable a checkpoint pins, and its name for a refusal.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) fn pinned_vmm(artifacts: &AdmittedArtifacts) -> (&str, &'static str) {
    (
        artifacts.cloud_hypervisor.sha256(),
        "Cloud Hypervisor build",
    )
}

/// The VMM executable a checkpoint pins, and its name for a refusal.
#[cfg(target_os = "macos")]
pub(in crate::supervisor) fn pinned_vmm(artifacts: &AdmittedArtifacts) -> (&str, &'static str) {
    (artifacts.vz_runner.sha256(), "virtualization helper")
}

/// The filesystems that share blocks between files, for a refusal.
#[cfg(target_os = "linux")]
pub(in crate::supervisor) const CLONING_FILESYSTEMS: &str = "btrfs or XFS";
#[cfg(target_os = "macos")]
pub(in crate::supervisor) const CLONING_FILESYSTEMS: &str = "APFS";

/// A VM checkpoint store a file-sync service could copy off the Mac is
/// refused: iCloud Drive (`~/Library/Mobile Documents`) and the File Provider
/// mounts (`~/Library/CloudStorage/*`). One under `~/Desktop` or
/// `~/Documents`, which iCloud's Desktop & Documents may sync, is allowed
/// with a warning (cw-security's condition 10).
#[cfg(target_os = "macos")]
pub(in crate::supervisor) fn synced_store_warning(
    engine_root: &Path,
) -> Result<Option<String>, Status> {
    let (Some(home), Ok(root)) = (std::env::home_dir(), fs::canonicalize(engine_root)) else {
        return Ok(None);
    };
    let home = fs::canonicalize(&home).unwrap_or(home);
    synced_folder(&home, &root)
}

/// [`synced_store_warning`] for a canonical `home` and state `root`.
#[cfg(target_os = "macos")]
fn synced_folder(home: &Path, root: &Path) -> Result<Option<String>, Status> {
    let library = home.join("Library");
    for synced in [
        library.join("Mobile Documents"),
        library.join("CloudStorage"),
    ] {
        if root.starts_with(&synced) {
            return Err(Status::failed_precondition(format!(
                "the local VM state root {} is in a folder a sync service copies off this Mac ({}); a VM checkpoint holds the VM's memory, so move the state root out of it first",
                root.display(),
                synced.display()
            )));
        }
    }
    Ok(["Desktop", "Documents"]
        .into_iter()
        .map(|folder| home.join(folder))
        .find(|folder| root.starts_with(folder))
        .map(|folder| {
            format!(
                "the local VM state root is under {}, which iCloud may sync if Desktop & Documents is on; this VM checkpoint holds the VM's memory",
                folder.display()
            )
        }))
}

#[cfg(target_os = "linux")]
pub(in crate::supervisor) fn synced_store_warning(
    _engine_root: &Path,
) -> Result<Option<String>, Status> {
    Ok(None)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn a_state_root_a_sync_service_copies_is_refused_and_one_icloud_may_sync_warned() {
        let home = Path::new("/Users/someone");
        for synced in [
            "Library/Mobile Documents/com~apple~CloudDocs/vms",
            "Library/CloudStorage/Dropbox/native-v1",
        ] {
            let refused = synced_folder(home, &home.join(synced)).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
            assert!(refused.message().contains("sync service"), "{refused:?}");
        }
        for folder in ["Desktop", "Documents"] {
            let warning = synced_folder(home, &home.join(folder).join("vms"))
                .unwrap()
                .unwrap();
            assert!(warning.contains("iCloud may sync"), "{warning}");
        }
        for unsynced in [".codewire/native-v1", "Library/Application Support/vms"] {
            assert_eq!(synced_folder(home, &home.join(unsynced)).unwrap(), None);
        }
        // A folder whose name only starts like a synced one is not inside it.
        assert_eq!(
            synced_folder(home, &home.join("Documents2/vms")).unwrap(),
            None
        );
    }
}
