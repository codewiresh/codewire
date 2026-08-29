use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use rustix::thread::{CapabilitySet, capabilities};

use super::path::current_uid;

pub const MINIMUM_LANDLOCK_ABI: i32 = 3;
const KVM_GET_API_VERSION: libc::Ioctl = libc::_IO(0xAE, 0);
const KVM_API_VERSION: libc::c_int = 12;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub architecture: &'static str,
    pub landlock_abi: i32,
    pub kvm: PathBuf,
    pub vhost_vsock: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("the local microVM supervisor must not run as root")]
    Root,
    #[error(
        "the local microVM supervisor requires NoNewPrivs=1 and empty effective, permitted, inheritable, and ambient capability sets"
    )]
    Capabilities,
    #[error("read process security status failed")]
    ProcessStatus,
    #[error("unsupported Linux architecture {0}")]
    UnsupportedArchitecture(String),
    #[error("required character device is unavailable or unusable: {0}")]
    Device(PathBuf),
    #[error("KVM API version query failed: {0}")]
    KvmApiQuery(io::Error),
    #[error("KVM returned unsupported API version {actual}, expected {KVM_API_VERSION}")]
    KvmApiVersion { actual: libc::c_int },
    #[error("Landlock ABI query failed")]
    LandlockQuery,
    #[error("Landlock ABI {actual} is below required ABI {required}")]
    LandlockTooOld { actual: i32, required: i32 },
}

pub fn preflight() -> Result<PreflightReport, PreflightError> {
    if current_uid() == 0 {
        return Err(PreflightError::Root);
    }
    let capability_sets = capabilities(None).map_err(|_| PreflightError::Capabilities)?;
    if capability_sets.effective != CapabilitySet::empty()
        || capability_sets.permitted != CapabilitySet::empty()
        || capability_sets.inheritable != CapabilitySet::empty()
        || read_hex_status_field("CapAmb")? != 0
        || read_decimal_status_field("NoNewPrivs")? != 1
    {
        return Err(PreflightError::Capabilities);
    }
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => return Err(PreflightError::UnsupportedArchitecture(other.to_owned())),
    };

    let kvm_path = Path::new("/dev/kvm");
    let kvm = open_character_device(kvm_path)?;
    let version = kvm_api_version(&kvm)?;
    if version != KVM_API_VERSION {
        return Err(PreflightError::KvmApiVersion { actual: version });
    }

    let vhost_vsock_path = Path::new("/dev/vhost-vsock");
    let _vhost_vsock = open_character_device(vhost_vsock_path)?;
    let landlock_abi = landlock_abi()?;
    if landlock_abi < MINIMUM_LANDLOCK_ABI {
        return Err(PreflightError::LandlockTooOld {
            actual: landlock_abi,
            required: MINIMUM_LANDLOCK_ABI,
        });
    }

    Ok(PreflightReport {
        architecture,
        landlock_abi,
        kvm: kvm_path.to_owned(),
        vhost_vsock: vhost_vsock_path.to_owned(),
    })
}

fn kvm_api_version(kvm: &std::fs::File) -> Result<libc::c_int, PreflightError> {
    // SAFETY: KVM_GET_API_VERSION takes no pointer argument and only reads the
    // opened KVM descriptor. Passing an explicit zero variadic argument avoids
    // an ABI-dependent indeterminate register while remaining ignored by KVM.
    let result = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if result < 0 {
        return Err(PreflightError::KvmApiQuery(io::Error::last_os_error()));
    }
    Ok(result)
}

fn open_character_device(path: &Path) -> Result<std::fs::File, PreflightError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PreflightError::Device(path.to_owned()))?;
    if !metadata.file_type().is_char_device() || metadata.rdev() == 0 {
        return Err(PreflightError::Device(path.to_owned()));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| PreflightError::Device(path.to_owned()))
}

fn read_hex_status_field(field: &str) -> Result<u64, PreflightError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_| PreflightError::ProcessStatus)?;
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field).then(|| u64::from_str_radix(value.trim(), 16).ok())?
        })
        .ok_or(PreflightError::ProcessStatus)
}

fn read_decimal_status_field(field: &str) -> Result<u64, PreflightError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_| PreflightError::ProcessStatus)?;
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field).then(|| value.trim().parse::<u64>().ok())?
        })
        .ok_or(PreflightError::ProcessStatus)
}

fn landlock_abi() -> Result<i32, PreflightError> {
    // SAFETY: the VERSION query requires a null attribute pointer and a zero
    // size; no userspace memory is read or written by the kernel.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 || result > i32::MAX as libc::c_long {
        return Err(PreflightError::LandlockQuery);
    }
    Ok(result as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_status_parser_observes_ambient_set() {
        let value = read_hex_status_field("CapAmb").unwrap();
        assert_eq!(value, 0, "unit-test process unexpectedly has ambient caps");
    }

    #[test]
    fn missing_status_field_fails_closed() {
        assert!(matches!(
            read_hex_status_field("CodewireMissingCapabilityField"),
            Err(PreflightError::ProcessStatus)
        ));
    }

    #[test]
    fn no_new_privileges_field_is_parseable() {
        assert!(matches!(read_decimal_status_field("NoNewPrivs"), Ok(0 | 1)));
    }
}
