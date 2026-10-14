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

/// One unmet host prerequisite for local VMs, and what fixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProblem {
    /// Whether a local VM cannot run without it (otherwise only some
    /// workspaces need it, such as a cloned repository needing git).
    pub required: bool,
    pub problem: String,
    pub fix: String,
}

/// What [`host_prerequisites`] observed; separate so the advice is tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostFacts {
    pub root: bool,
    pub kvm: DeviceState,
    pub vhost_vsock: DeviceState,
    /// `None` when the kernel has no Landlock or it is disabled.
    pub landlock_abi: Option<i32>,
    pub missing_e2fsprogs: Vec<&'static str>,
    /// e2fsprogs that a user other than root could change.
    pub untrusted_e2fsprogs: Vec<std::path::PathBuf>,
    pub git: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceState {
    Usable,
    Missing,
    Denied,
    Unusable,
}

/// Every unmet prerequisite for running local VMs on this host, each with
/// its fix, checked as the user (the supervisor's own preflight enforces
/// them again). `cw setup --local` and local create and start report these
/// instead of a later opaque failure.
pub fn host_prerequisites() -> Vec<HostProblem> {
    let device = |path: &str| match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => {
            if path == "/dev/kvm" && !matches!(kvm_api_version(&file), Ok(KVM_API_VERSION)) {
                DeviceState::Unusable
            } else {
                DeviceState::Usable
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => DeviceState::Missing,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => DeviceState::Denied,
        Err(_) => DeviceState::Unusable,
    };
    let mut missing_e2fsprogs = Vec::new();
    let mut untrusted_e2fsprogs = Vec::new();
    for tool in ["mkfs.ext4", "e2fsck", "resize2fs", "debugfs"] {
        match super::locate_e2fsprogs(tool) {
            Ok(_) => {}
            Err(super::E2fsprogsProblem::Missing) => missing_e2fsprogs.push(tool),
            Err(super::E2fsprogsProblem::Untrusted(path)) => untrusted_e2fsprogs.push(path),
        }
    }
    host_problems(&HostFacts {
        root: current_uid() == 0,
        kvm: device("/dev/kvm"),
        vhost_vsock: device("/dev/vhost-vsock"),
        landlock_abi: landlock_abi().ok(),
        missing_e2fsprogs,
        untrusted_e2fsprogs,
        git: super::git().is_some_and(|git| git.program.is_file()),
    })
}

pub(crate) fn host_problems(facts: &HostFacts) -> Vec<HostProblem> {
    let mut problems = Vec::new();
    let mut required = |problem: String, fix: &str| {
        problems.push(HostProblem {
            required: true,
            problem,
            fix: fix.to_owned(),
        })
    };
    if facts.root {
        required(
            "cw is running as root".to_owned(),
            "run cw as your own user; local VMs never run as root",
        );
    }
    match facts.kvm {
        DeviceState::Usable => {}
        DeviceState::Missing => required(
            "KVM is not available (/dev/kvm does not exist)".to_owned(),
            "enable hardware virtualization (Intel VT-x or AMD-V) in the firmware and load the kvm_intel or kvm_amd module; inside a VM, enable nested virtualization",
        ),
        DeviceState::Denied => required(
            "you cannot open /dev/kvm".to_owned(),
            "add yourself to its group: sudo usermod -aG kvm \"$USER\", then log out and back in",
        ),
        DeviceState::Unusable => required(
            "/dev/kvm does not work as KVM".to_owned(),
            "check that the kvm module loaded without errors (sudo dmesg | grep -i kvm)",
        ),
    }
    match facts.vhost_vsock {
        DeviceState::Usable => {}
        DeviceState::Missing => required(
            "vhost-vsock is not loaded (/dev/vhost-vsock does not exist)".to_owned(),
            "sudo modprobe vhost_vsock; to load it at every boot: echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf",
        ),
        DeviceState::Denied => required(
            "you cannot open /dev/vhost-vsock".to_owned(),
            "make it readable and writable by your user (most distributions ship it as mode 0666; check the udev rules)",
        ),
        DeviceState::Unusable => required(
            "/dev/vhost-vsock cannot be opened".to_owned(),
            "check that the vhost_vsock module loaded without errors (sudo dmesg | grep -i vsock)",
        ),
    }
    match facts.landlock_abi {
        Some(abi) if abi >= MINIMUM_LANDLOCK_ABI => {}
        found => required(
            match found {
                Some(abi) => format!(
                    "the kernel's Landlock ABI is {abi}; local VMs need {MINIMUM_LANDLOCK_ABI} (Linux 6.2 or later)"
                ),
                None => "Landlock is not enabled in this kernel; local VMs need Landlock ABI 3 (Linux 6.2 or later)".to_owned(),
            },
            "use a Linux 6.2 or later kernel with Landlock: the Debian 12 and Ubuntu 22.04 GA kernels are too old (use Ubuntu 22.04 HWE or 24.04, Debian 13 or Fedora); on a new enough kernel, add landlock to the lsm= boot parameter",
        ),
    }
    if !facts.missing_e2fsprogs.is_empty() {
        required(
            format!(
                "e2fsprogs is missing: {} not found in /usr/sbin or /usr/bin",
                facts.missing_e2fsprogs.join(", ")
            ),
            "install your distribution's e2fsprogs package",
        );
    }
    if !facts.untrusted_e2fsprogs.is_empty() {
        required(
            format!(
                "cw runs e2fsprogs only when only root can change them, and {} or a directory above it is not owned by root or is writable by its group or others",
                facts
                    .untrusted_e2fsprogs
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "reinstall your distribution's e2fsprogs package, or make those files and directories owned by root and writable only by root",
        );
    }
    if !facts.git {
        problems.push(HostProblem {
            required: false,
            problem: "git is not installed at /usr/bin/git".to_owned(),
            fix:
                "install git to clone a repository into a local VM; other workspaces do not need it"
                    .to_owned(),
        });
    }
    problems
}

/// The report `cw` prints for `problems`; `None` when nothing is required.
pub fn host_problem_report(problems: &[HostProblem]) -> Option<String> {
    let mut report = String::from("this host cannot run local VMs yet:");
    let mut required = false;
    for problem in problems.iter().filter(|problem| problem.required) {
        required = true;
        report.push_str(&format!("\n  - {}. Fix: {}.", problem.problem, problem.fix));
    }
    required.then_some(report)
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

    fn ready() -> HostFacts {
        HostFacts {
            root: false,
            kvm: DeviceState::Usable,
            vhost_vsock: DeviceState::Usable,
            landlock_abi: Some(MINIMUM_LANDLOCK_ABI),
            missing_e2fsprogs: Vec::new(),
            untrusted_e2fsprogs: Vec::new(),
            git: true,
        }
    }

    #[test]
    fn a_ready_host_has_no_problem() {
        assert_eq!(host_problems(&ready()), Vec::new());
        assert_eq!(host_problem_report(&[]), None);
    }

    #[test]
    fn each_unmet_prerequisite_names_its_fix() {
        let facts = HostFacts {
            root: true,
            kvm: DeviceState::Denied,
            vhost_vsock: DeviceState::Missing,
            landlock_abi: Some(1),
            missing_e2fsprogs: vec!["e2fsck", "resize2fs"],
            untrusted_e2fsprogs: vec!["/usr/local/sbin/mke2fs".into()],
            git: false,
        };
        let problems = host_problems(&facts);
        assert_eq!(
            problems.iter().filter(|problem| problem.required).count(),
            6
        );
        let report = host_problem_report(&problems).unwrap();
        for expected in [
            "cw is running as root",
            "you cannot open /dev/kvm. Fix: add yourself to its group: sudo usermod -aG kvm \"$USER\"",
            "sudo modprobe vhost_vsock",
            "Landlock ABI is 1; local VMs need 3 (Linux 6.2 or later)",
            "Debian 12 and Ubuntu 22.04 GA kernels are too old",
            "e2fsck, resize2fs not found in /usr/sbin or /usr/bin",
            "/usr/local/sbin/mke2fs or a directory above it is not owned by root or is writable by its group or others. Fix: reinstall your distribution's e2fsprogs package",
        ] {
            assert!(report.contains(expected), "{expected}\n{report}");
        }
        // git is only advice: it never blocks.
        assert!(!report.contains("git"), "{report}");
        let git_only = HostFacts {
            git: false,
            ..ready()
        };
        let problems = host_problems(&git_only);
        assert_eq!(problems.len(), 1);
        assert!(!problems[0].required);
        assert_eq!(host_problem_report(&problems), None);
    }

    #[test]
    fn a_kernel_without_landlock_and_a_missing_kvm_are_named() {
        let facts = HostFacts {
            kvm: DeviceState::Missing,
            landlock_abi: None,
            ..ready()
        };
        let report = host_problem_report(&host_problems(&facts)).unwrap();
        assert!(
            report.contains("KVM is not available (/dev/kvm does not exist)"),
            "{report}"
        );
        assert!(
            report.contains("Landlock is not enabled in this kernel"),
            "{report}"
        );
    }

    #[test]
    fn this_host_reports_without_failing() {
        // Runs the real probes; the result depends on the host.
        let _ = host_prerequisites();
    }

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
