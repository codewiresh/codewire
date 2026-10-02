use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use codewire_vmm_guest_probe::{
    DOCKER_DISK_SERIAL, MAX_DIRECT_SHARES, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SETUP_DISK_SERIAL,
    STATE_DISK_SERIAL,
};

use crate::artifact::{AdmittedArtifacts, ArtifactError, validate_parameter_path};
use codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_DISK_SERIAL;

pub const DEFAULT_VCPUS: u8 = 1;
pub const DEFAULT_MEMORY_MIB: u32 = 512;
pub const GUEST_KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init panic=-1";
const LINUX_SUN_PATH_BYTES: usize = 108;

const FORBIDDEN_FLAGS: &[&str] = &[
    "--balloon",
    "--device",
    "--firmware",
    "--generic-vhost-user",
    "--landlock-rules",
    "--memory-zone",
    "--net",
    "--numa",
    "--pci-segment",
    "--pmem",
    "--restore",
    "--tpm",
    "--user-device",
    "--vdpa",
];

const ALLOWED_FLAG_COUNTS: &[(&str, usize)] = &[
    ("--api-socket", 1),
    ("--kernel", 1),
    ("--initramfs", 1),
    ("--cmdline", 1),
    ("--cpus", 1),
    ("--memory", 1),
    ("--disk", 3),
    ("--fs", 0),
    ("--vsock", 1),
    ("--serial", 1),
    ("--console", 1),
    ("--rng", 1),
    ("--seccomp", 1),
    ("--landlock", 1),
];

#[derive(Clone, PartialEq, Eq)]
pub struct CloudHypervisorConfig {
    pub executable: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub state_disk: PathBuf,
    pub docker_disk: Option<PathBuf>,
    pub root_disk: PathBuf,
    pub seed_disk: PathBuf,
    pub setup_disk: Option<PathBuf>,
    pub cw_runtime_disk: Option<PathBuf>,
    pub api_socket: PathBuf,
    pub event_monitor: PathBuf,
    pub vsock_socket: PathBuf,
    pub serial_log: PathBuf,
    pub vmm_log: PathBuf,
    pub vsock_cid: u32,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub virtiofs: Vec<VirtioFsConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioFsConfig {
    pub tag: String,
    pub socket: PathBuf,
}

impl fmt::Debug for CloudHypervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudHypervisorConfig")
            .field("executable", &self.executable)
            .field("kernel", &self.kernel)
            .field("initramfs", &self.initramfs)
            .field("state_disk", &self.state_disk)
            .field("docker_disk", &self.docker_disk)
            .field("root_disk", &self.root_disk)
            .field("seed_disk", &self.seed_disk)
            .field("setup_disk", &self.setup_disk)
            .field("cw_runtime_disk", &self.cw_runtime_disk)
            .field("api_socket", &self.api_socket)
            .field("event_monitor", &self.event_monitor)
            .field("vsock_socket", &self.vsock_socket)
            .field("serial_log", &self.serial_log)
            .field("vmm_log", &self.vmm_log)
            .field("vsock_cid", &self.vsock_cid)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("virtiofs_count", &self.virtiofs.len())
            .finish()
    }
}

impl CloudHypervisorConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifacts: &AdmittedArtifacts,
        state_disk: PathBuf,
        root_disk: PathBuf,
        seed_disk: PathBuf,
        api_socket: PathBuf,
        event_monitor: PathBuf,
        vsock_socket: PathBuf,
        serial_log: PathBuf,
        vmm_log: PathBuf,
        vsock_cid: u32,
        vcpus: u8,
        memory_mib: u32,
    ) -> Result<Self, CloudHypervisorConfigError> {
        Self::new_inner(
            artifacts,
            state_disk,
            root_disk,
            seed_disk,
            None,
            api_socket,
            event_monitor,
            vsock_socket,
            serial_log,
            vmm_log,
            vsock_cid,
            vcpus,
            memory_mib,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_setup(
        artifacts: &AdmittedArtifacts,
        state_disk: PathBuf,
        root_disk: PathBuf,
        seed_disk: PathBuf,
        setup_disk: PathBuf,
        api_socket: PathBuf,
        event_monitor: PathBuf,
        vsock_socket: PathBuf,
        serial_log: PathBuf,
        vmm_log: PathBuf,
        vsock_cid: u32,
        vcpus: u8,
        memory_mib: u32,
    ) -> Result<Self, CloudHypervisorConfigError> {
        Self::new_inner(
            artifacts,
            state_disk,
            root_disk,
            seed_disk,
            Some(setup_disk),
            api_socket,
            event_monitor,
            vsock_socket,
            serial_log,
            vmm_log,
            vsock_cid,
            vcpus,
            memory_mib,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        artifacts: &AdmittedArtifacts,
        state_disk: PathBuf,
        root_disk: PathBuf,
        seed_disk: PathBuf,
        setup_disk: Option<PathBuf>,
        api_socket: PathBuf,
        event_monitor: PathBuf,
        vsock_socket: PathBuf,
        serial_log: PathBuf,
        vmm_log: PathBuf,
        vsock_cid: u32,
        vcpus: u8,
        memory_mib: u32,
    ) -> Result<Self, CloudHypervisorConfigError> {
        let config = Self {
            executable: artifacts.cloud_hypervisor.path().to_owned(),
            kernel: artifacts.kernel.path().to_owned(),
            initramfs: artifacts.initramfs.path().to_owned(),
            state_disk,
            docker_disk: None,
            root_disk,
            seed_disk,
            setup_disk,
            cw_runtime_disk: None,
            api_socket,
            event_monitor,
            vsock_socket,
            serial_log,
            vmm_log,
            vsock_cid,
            vcpus,
            memory_mib,
            virtiofs: Vec::new(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_virtiofs(
        mut self,
        virtiofs: Vec<VirtioFsConfig>,
    ) -> Result<Self, CloudHypervisorConfigError> {
        self.virtiofs = virtiofs;
        self.validate()?;
        Ok(self)
    }

    pub fn with_docker_disk(
        mut self,
        docker_disk: Option<PathBuf>,
    ) -> Result<Self, CloudHypervisorConfigError> {
        self.docker_disk = docker_disk;
        self.validate()?;
        Ok(self)
    }

    pub fn with_cw_runtime_disk(
        mut self,
        disk: Option<PathBuf>,
    ) -> Result<Self, CloudHypervisorConfigError> {
        self.cw_runtime_disk = disk;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CloudHypervisorConfigError> {
        if self.vsock_cid < 3 || self.vsock_cid == u32::MAX {
            return Err(CloudHypervisorConfigError::InvalidVsockCid);
        }
        if self.vcpus == 0 || self.vcpus > 32 {
            return Err(CloudHypervisorConfigError::InvalidCpuCount);
        }
        if !(128..=65_536).contains(&self.memory_mib) {
            return Err(CloudHypervisorConfigError::InvalidMemorySize);
        }
        if self.virtiofs.len() > MAX_DIRECT_SHARES {
            return Err(CloudHypervisorConfigError::InvalidVirtioFsCount);
        }
        for path in self.paths() {
            if !is_normal_absolute_path(path) {
                return Err(CloudHypervisorConfigError::NonAbsolutePath(path.to_owned()));
            }
            validate_parameter_path(path).map_err(CloudHypervisorConfigError::UnsafePath)?;
        }
        let mut disks = vec![&self.state_disk, &self.root_disk, &self.seed_disk];
        if let Some(docker) = &self.docker_disk {
            disks.push(docker);
        }
        if let Some(setup) = &self.setup_disk {
            disks.push(setup);
        }
        if let Some(runtime) = &self.cw_runtime_disk {
            disks.push(runtime);
        }
        disks.sort();
        if disks.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CloudHypervisorConfigError::AliasedDiskPaths);
        }
        if self.api_socket == self.vsock_socket
            || self.api_socket.parent().is_none()
            || self.vsock_socket.parent().is_none()
            || self.api_socket.parent() == self.vsock_socket.parent()
            || self.api_socket.file_name() == self.vsock_socket.file_name()
            || self
                .api_socket
                .parent()
                .is_some_and(|parent| self.vsock_socket.starts_with(parent))
            || self
                .vsock_socket
                .parent()
                .is_some_and(|parent| self.api_socket.starts_with(parent))
        {
            return Err(CloudHypervisorConfigError::AliasedSocketPaths);
        }
        let mut sockets = vec![&self.api_socket, &self.vsock_socket];
        sockets.extend(self.virtiofs.iter().map(|share| &share.socket));
        sockets.sort();
        if sockets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CloudHypervisorConfigError::AliasedSocketPaths);
        }
        for (index, share) in self.virtiofs.iter().enumerate() {
            if share.tag != format!("cw-direct-{index:02}") {
                return Err(CloudHypervisorConfigError::InvalidVirtioFsTag);
            }
        }
        for socket in sockets {
            if socket.as_os_str().as_bytes().len() >= LINUX_SUN_PATH_BYTES {
                return Err(CloudHypervisorConfigError::SocketPathTooLong(
                    socket.to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn command(&self) -> Result<CommandSpec, CloudHypervisorConfigError> {
        self.validate()?;
        let mut arguments = Vec::<OsString>::new();
        push_option(
            &mut arguments,
            "--api-socket",
            format!("path={}", display(&self.api_socket)?),
        );
        push_option(&mut arguments, "--kernel", display(&self.kernel)?);
        push_option(&mut arguments, "--initramfs", display(&self.initramfs)?);
        push_option(&mut arguments, "--cmdline", GUEST_KERNEL_CMDLINE);
        push_option(
            &mut arguments,
            "--cpus",
            format!("boot={0},max={0}", self.vcpus),
        );
        push_option(
            &mut arguments,
            "--memory",
            format!(
                "size={}M,shared={},mergeable=off",
                self.memory_mib,
                if self.virtiofs.is_empty() {
                    "off"
                } else {
                    "on"
                }
            ),
        );
        push_option(
            &mut arguments,
            "--disk",
            format!(
                "path={},readonly=off,direct=off,id=cw-state,serial={},image_type=raw,backing_files=off,sparse=on,lock_granularity=full",
                display(&self.state_disk)?,
                STATE_DISK_SERIAL,
            ),
        );
        if let Some(docker_disk) = &self.docker_disk {
            push_option(
                &mut arguments,
                "--disk",
                format!(
                    "path={},readonly=off,direct=off,id=cw-docker,serial={},image_type=raw,backing_files=off,sparse=on,lock_granularity=full",
                    display(docker_disk)?,
                    DOCKER_DISK_SERIAL,
                ),
            );
        }
        push_option(
            &mut arguments,
            "--disk",
            format!(
                "path={},readonly=off,direct=off,id=cw-root,serial={},image_type=raw,backing_files=off,sparse=on,lock_granularity=full",
                display(&self.root_disk)?,
                ROOT_DISK_SERIAL,
            ),
        );
        push_option(
            &mut arguments,
            "--disk",
            format!(
                "path={},readonly=on,direct=off,id=cw-seed,serial={},image_type=raw,backing_files=off,sparse=off,lock_granularity=full",
                display(&self.seed_disk)?,
                SEED_DISK_SERIAL,
            ),
        );
        if let Some(setup_disk) = &self.setup_disk {
            push_option(
                &mut arguments,
                "--disk",
                format!(
                    "path={},readonly=on,direct=off,id=cw-setup,serial={},image_type=raw,backing_files=off,sparse=off,lock_granularity=full",
                    display(setup_disk)?,
                    SETUP_DISK_SERIAL,
                ),
            );
        }
        if let Some(runtime) = &self.cw_runtime_disk {
            push_option(
                &mut arguments,
                "--disk",
                format!(
                    "path={},readonly=on,direct=off,id=cw-runtime,serial={},image_type=raw,backing_files=off,sparse=off,lock_granularity=full",
                    display(runtime)?,
                    CW_RUNTIME_DISK_SERIAL,
                ),
            );
        }
        for (index, share) in self.virtiofs.iter().enumerate() {
            push_option(
                &mut arguments,
                "--fs",
                format!(
                    "tag={},socket={},num_queues=1,queue_size=1024,id=cw-fs-{index:02}",
                    share.tag,
                    display(&share.socket)?,
                ),
            );
        }
        push_option(
            &mut arguments,
            "--vsock",
            format!(
                "cid={},socket={},id=cw-vsock",
                self.vsock_cid,
                display(&self.vsock_socket)?
            ),
        );
        // Guest serial bytes are hostile and potentially unbounded. Until a
        // separately bounded collector exists, discard them inside Cloud
        // Hypervisor instead of granting the guest a host-filesystem sink.
        // Cloud Hypervisor's log and event monitor are omitted for the same
        // reason; its inherited stderr is null and the private diagnostic
        // placeholders remain empty for a future bounded collector.
        push_option(&mut arguments, "--serial", "null");
        push_option(&mut arguments, "--console", "off");
        push_option(&mut arguments, "--rng", "src=/dev/urandom");
        push_option(&mut arguments, "--seccomp", "true");
        // Native v53 Landlock derives its allowlist from the already parsed VM
        // configuration. This command admits only the durable/seed disks, an
        // optional one-boot read-only setup disk, and exact
        // private virtio-fs sockets. The kernel/initramfs, bounded diagnostics,
        // API, dedicated vsock parent, and virtio-fs sockets need no explicit
        // `--landlock-rules` broadening is permitted. This is defense in depth;
        // same-UID host processes and the host kernel remain trusted.
        arguments.push(OsString::from("--landlock"));

        let command = CommandSpec {
            program: self.executable.clone(),
            arguments,
            expected_disk_count: 3
                + usize::from(self.docker_disk.is_some())
                + usize::from(self.setup_disk.is_some())
                + usize::from(self.cw_runtime_disk.is_some()),
            expected_fs_count: self.virtiofs.len(),
        };
        command.validate_allowlist()?;
        Ok(command)
    }

    fn paths(&self) -> Vec<&Path> {
        let mut paths: Vec<&Path> = vec![
            self.executable.as_path(),
            self.kernel.as_path(),
            self.initramfs.as_path(),
            self.state_disk.as_path(),
            self.root_disk.as_path(),
            self.seed_disk.as_path(),
            self.api_socket.as_path(),
            self.event_monitor.as_path(),
            self.vsock_socket.as_path(),
            self.serial_log.as_path(),
            self.vmm_log.as_path(),
        ];
        if let Some(docker) = &self.docker_disk {
            paths.push(docker.as_path());
        }
        if let Some(setup) = &self.setup_disk {
            paths.push(setup.as_path());
        }
        if let Some(runtime) = &self.cw_runtime_disk {
            paths.push(runtime.as_path());
        }
        paths.extend(self.virtiofs.iter().map(|share| share.socket.as_path()));
        paths
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    expected_disk_count: usize,
    expected_fs_count: usize,
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .finish()
    }
}

impl CommandSpec {
    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    #[cfg(test)]
    pub(crate) fn for_test(program: PathBuf) -> Self {
        Self {
            program,
            arguments: Vec::new(),
            expected_disk_count: 3,
            expected_fs_count: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_arguments(program: PathBuf, arguments: Vec<OsString>) -> Self {
        Self {
            program,
            arguments,
            expected_disk_count: 3,
            expected_fs_count: 0,
        }
    }

    pub fn validate_allowlist(&self) -> Result<(), CloudHypervisorConfigError> {
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        let mut index = 0;
        while index < self.arguments.len() {
            let flag = self.arguments[index]
                .to_str()
                .ok_or(CloudHypervisorConfigError::InvalidArgumentStructure)?;
            let Some((allowed, _)) = ALLOWED_FLAG_COUNTS
                .iter()
                .find(|(allowed, _)| *allowed == flag)
            else {
                if FORBIDDEN_FLAGS.contains(&flag) {
                    return Err(CloudHypervisorConfigError::ForbiddenDevice(flag.to_owned()));
                }
                return Err(CloudHypervisorConfigError::UnexpectedFlag(flag.to_owned()));
            };
            *counts.entry(*allowed).or_default() += 1;
            index += 1;
            if flag != "--landlock" {
                let value = self
                    .arguments
                    .get(index)
                    .and_then(|argument| argument.to_str())
                    .filter(|value| !value.starts_with("--"))
                    .ok_or(CloudHypervisorConfigError::InvalidArgumentStructure)?;
                if value.is_empty() {
                    return Err(CloudHypervisorConfigError::InvalidArgumentStructure);
                }
                if flag == "--seccomp" && value != "true" {
                    return Err(CloudHypervisorConfigError::InvalidSeccompValue);
                }
                index += 1;
            }
        }
        for (required, expected_count) in ALLOWED_FLAG_COUNTS {
            let expected_count = match *required {
                "--disk" => self.expected_disk_count,
                "--fs" => self.expected_fs_count,
                _ => *expected_count,
            };
            let actual_count = counts.get(required).copied().unwrap_or_default();
            if actual_count != expected_count {
                return Err(CloudHypervisorConfigError::FlagCount {
                    flag: required,
                    expected: expected_count,
                    actual: actual_count,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CloudHypervisorConfigError {
    #[error("invalid guest vsock CID")]
    InvalidVsockCid,
    #[error("invalid guest CPU count")]
    InvalidCpuCount,
    #[error("invalid guest memory size")]
    InvalidMemorySize,
    #[error("invalid virtio-fs tag")]
    InvalidVirtioFsTag,
    #[error("invalid virtio-fs device count")]
    InvalidVirtioFsCount,
    #[error("Cloud Hypervisor path must be absolute: {0}")]
    NonAbsolutePath(PathBuf),
    #[error(transparent)]
    UnsafePath(ArtifactError),
    #[error("Cloud Hypervisor API and hybrid-vsock sockets must be distinct")]
    AliasedSocketPaths,
    #[error("Cloud Hypervisor disk paths must be distinct")]
    AliasedDiskPaths,
    #[error("Cloud Hypervisor Unix socket path is too long: {0}")]
    SocketPathTooLong(PathBuf),
    #[error("Cloud Hypervisor configuration contains forbidden device flag {0}")]
    ForbiddenDevice(String),
    #[error("Cloud Hypervisor configuration contains an unallowlisted flag {0}")]
    UnexpectedFlag(String),
    #[error("Cloud Hypervisor argument vector has an invalid flag/value structure")]
    InvalidArgumentStructure,
    #[error("Cloud Hypervisor seccomp mode must be exactly true")]
    InvalidSeccompValue,
    #[error(
        "Cloud Hypervisor flag {flag} occurred {actual} times; the v53 profile requires {expected}"
    )]
    FlagCount {
        flag: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("Cloud Hypervisor path is not valid UTF-8: {0}")]
    NonUtf8Path(PathBuf),
}

fn display(path: &Path) -> Result<&str, CloudHypervisorConfigError> {
    path.to_str()
        .ok_or_else(|| CloudHypervisorConfigError::NonUtf8Path(path.to_owned()))
}

fn is_normal_absolute_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.clone().next().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
}

fn push_option(arguments: &mut Vec<OsString>, flag: &'static str, value: impl Into<OsString>) {
    arguments.push(OsString::from(flag));
    arguments.push(value.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{AdmittedArtifact, AdmittedArtifacts};

    fn artifact(path: &str) -> AdmittedArtifact {
        AdmittedArtifact::for_test(path)
    }

    fn config() -> CloudHypervisorConfig {
        let artifacts = AdmittedArtifacts {
            cloud_hypervisor: artifact("/artifacts/cloud-hypervisor"),
            virtiofsd: None,
            kernel: artifact("/artifacts/kernel"),
            initramfs: artifact("/artifacts/initramfs"),
        };
        CloudHypervisorConfig::new(
            &artifacts,
            "/state/disks/state.raw".into(),
            "/state/generations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/root.raw".into(),
            "/state/seed/seed.raw".into(),
            "/state/api/api.sock".into(),
            "/state/diagnostics/events.json".into(),
            "/state/vsock/hybrid.sock".into(),
            "/state/diagnostics/serial.log".into(),
            "/state/diagnostics/vmm.log".into(),
            7,
            DEFAULT_VCPUS,
            DEFAULT_MEMORY_MIB,
        )
        .unwrap()
    }

    #[test]
    fn v53_command_is_explicit_and_has_no_network_or_passthrough_devices() {
        let mut config = config();
        config.vcpus = 2;
        config.memory_mib = 16_384;
        let command = config.command().unwrap();
        command.validate_allowlist().unwrap();
        let args = command
            .arguments()
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        for flag in FORBIDDEN_FLAGS {
            assert!(!args.contains(flag), "forbidden flag {flag}");
        }
        assert_eq!(args.iter().filter(|value| **value == "--disk").count(), 3);
        assert!(args.windows(2).any(|pair| pair == ["--seccomp", "true"]));
        assert!(args.windows(2).any(|pair| pair == ["--serial", "null"]));
        assert!(!args.contains(&"--log-file"));
        assert!(!args.contains(&"--event-monitor"));
        assert!(args.contains(&"--landlock"));
        assert!(args.contains(&"boot=2,max=2"));
        assert!(args.contains(&"size=16384M,shared=off,mergeable=off"));
        assert!(args.iter().any(|argument| {
            argument.contains("serial=CWSTATE1") && argument.contains("lock_granularity=full")
        }));
        assert!(args.iter().any(|argument| {
            argument.contains("serial=CWROOT1")
                && argument.contains("readonly=off")
                && argument.contains("lock_granularity=full")
        }));
        assert!(args.iter().any(|argument| {
            argument.contains("serial=CWSEED1")
                && argument.contains("readonly=on")
                && argument.contains("lock_granularity=full")
        }));
    }

    #[test]
    fn resource_bounds_fail_closed() {
        let mut invalid_cpus = config();
        invalid_cpus.vcpus = 0;
        assert!(matches!(
            invalid_cpus.command(),
            Err(CloudHypervisorConfigError::InvalidCpuCount)
        ));

        let mut invalid_memory = config();
        invalid_memory.memory_mib = 65_537;
        assert!(matches!(
            invalid_memory.command(),
            Err(CloudHypervisorConfigError::InvalidMemorySize)
        ));
    }

    #[test]
    fn setup_pack_is_an_exact_optional_fourth_read_only_disk() {
        let mut with_setup = config();
        with_setup.setup_disk = Some(
            "/state/generations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/setup.raw"
                .into(),
        );
        let command = with_setup.command().unwrap();
        let args = command
            .arguments()
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(args.iter().filter(|value| **value == "--disk").count(), 4);
        assert!(args.iter().any(|argument| {
            argument.contains("id=cw-setup")
                && argument.contains("serial=CWSETUP1")
                && argument.contains("readonly=on")
                && argument.contains("sparse=off")
                && argument.contains("lock_granularity=full")
        }));
        command.validate_allowlist().unwrap();

        let mut unexpected = config().command().unwrap();
        unexpected.arguments.push(OsString::from("--disk"));
        unexpected.arguments.push(OsString::from(
            "path=/state/extra.raw,readonly=on,id=unexpected",
        ));
        assert!(matches!(
            unexpected.validate_allowlist(),
            Err(CloudHypervisorConfigError::FlagCount {
                flag: "--disk",
                expected: 3,
                actual: 4
            })
        ));
    }

    #[test]
    fn runtime_catalog_is_an_exact_readonly_disk_and_cannot_alias_storage() {
        let selected = config()
            .with_cw_runtime_disk(Some("/runtime/catalog/runtime.raw".into()))
            .unwrap();
        let command = selected.command().unwrap();
        command.validate_allowlist().unwrap();
        let disks = command
            .arguments()
            .windows(2)
            .filter(|pair| pair[0] == "--disk")
            .map(|pair| pair[1].to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(disks.len(), 4);
        assert_eq!(
            disks
                .iter()
                .filter(|disk| disk.contains("id=cw-runtime,"))
                .count(),
            1
        );
        assert!(disks.iter().any(|disk| *disk == "path=/runtime/catalog/runtime.raw,readonly=on,direct=off,id=cw-runtime,serial=CWRUNTIME1,image_type=raw,backing_files=off,sparse=off,lock_granularity=full"));
        let original = config();
        assert!(matches!(
            original
                .clone()
                .with_cw_runtime_disk(Some(original.seed_disk.clone())),
            Err(CloudHypervisorConfigError::AliasedDiskPaths)
        ));
    }

    #[test]
    fn docker_data_is_an_exact_optional_writable_disk_without_network_devices() {
        let config = config()
            .with_docker_disk(Some("/state/disks/docker.raw".into()))
            .unwrap();
        let command = config.command().unwrap();
        command.validate_allowlist().unwrap();
        let args = command
            .arguments()
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(args.iter().filter(|value| **value == "--disk").count(), 4);
        assert!(args.iter().any(|argument| {
            argument.contains("path=/state/disks/docker.raw")
                && argument.contains("id=cw-docker")
                && argument.contains("serial=CWDOCKER1")
                && argument.contains("readonly=off")
                && argument.contains("direct=off")
                && argument.contains("backing_files=off")
                && argument.contains("sparse=on")
                && argument.contains("lock_granularity=full")
        }));
        for flag in FORBIDDEN_FLAGS {
            assert!(!args.contains(flag), "forbidden flag {flag}");
        }
    }

    #[test]
    fn setup_pack_must_not_alias_another_disk() {
        let mut setup_alias = config();
        setup_alias.setup_disk = Some(setup_alias.root_disk.clone());
        assert!(matches!(
            setup_alias.validate(),
            Err(CloudHypervisorConfigError::AliasedDiskPaths)
        ));

        let mut docker_alias = config();
        docker_alias.docker_disk = Some(docker_alias.state_disk.clone());
        assert!(matches!(
            docker_alias.validate(),
            Err(CloudHypervisorConfigError::AliasedDiskPaths)
        ));
    }

    #[test]
    fn direct_shares_enable_shared_memory_and_exact_virtiofs_devices() {
        let config = config()
            .with_virtiofs(vec![
                VirtioFsConfig {
                    tag: "cw-direct-00".to_owned(),
                    socket: "/state/virtiofs/share-00.sock".into(),
                },
                VirtioFsConfig {
                    tag: "cw-direct-01".to_owned(),
                    socket: "/state/virtiofs/share-01.sock".into(),
                },
            ])
            .unwrap();
        let command = config.command().unwrap();
        let args = command
            .arguments()
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(args.contains(&"size=512M,shared=on,mergeable=off"));
        assert_eq!(
            args.iter().filter(|argument| **argument == "--fs").count(),
            2
        );
        assert!(args.iter().any(|argument| {
            *argument
                == "tag=cw-direct-00,socket=/state/virtiofs/share-00.sock,num_queues=1,queue_size=1024,id=cw-fs-00"
        }));
        command.validate_allowlist().unwrap();

        let mut aliased = config.clone();
        aliased.virtiofs[1].socket = aliased.virtiofs[0].socket.clone();
        assert!(matches!(
            aliased.validate(),
            Err(CloudHypervisorConfigError::AliasedSocketPaths)
        ));
    }

    #[test]
    fn path_parameter_injection_fails_closed() {
        let mut config = config();
        config.state_disk = "/state/disks/state.raw,--net=tap0".into();
        assert!(matches!(
            config.command(),
            Err(CloudHypervisorConfigError::UnsafePath(_))
        ));
    }

    #[test]
    fn unix_socket_paths_reserve_the_required_nul_byte() {
        let mut accepted = config();
        accepted.api_socket = PathBuf::from(format!("/api/{}/a", "a".repeat(100)));
        assert_eq!(accepted.api_socket.as_os_str().as_bytes().len(), 107);
        assert!(accepted.validate().is_ok());

        accepted.api_socket = PathBuf::from(format!("/api/{}/a", "a".repeat(101)));
        assert_eq!(accepted.api_socket.as_os_str().as_bytes().len(), 108);
        assert!(matches!(
            accepted.validate(),
            Err(CloudHypervisorConfigError::SocketPathTooLong(path))
                if path == accepted.api_socket
        ));
    }

    #[test]
    fn command_rejects_every_unallowlisted_or_duplicate_flag() {
        let mut command = config().command().unwrap();
        command.arguments.push(OsString::from("--watchdog"));
        command.arguments.push(OsString::from("true"));
        assert!(matches!(
            command.validate_allowlist(),
            Err(CloudHypervisorConfigError::UnexpectedFlag(flag)) if flag == "--watchdog"
        ));

        let mut command = config().command().unwrap();
        command.arguments.push(OsString::from("--net"));
        command.arguments.push(OsString::from("tap=evil"));
        assert!(matches!(
            command.validate_allowlist(),
            Err(CloudHypervisorConfigError::ForbiddenDevice(flag)) if flag == "--net"
        ));
    }

    #[test]
    fn command_rejects_every_non_enforcing_seccomp_value() {
        for value in ["false", "log", "errno"] {
            let mut command = config().command().unwrap();
            let seccomp = command
                .arguments
                .iter()
                .position(|argument| argument == "--seccomp")
                .unwrap();
            command.arguments[seccomp + 1] = OsString::from(value);

            assert!(matches!(
                command.validate_allowlist(),
                Err(CloudHypervisorConfigError::InvalidSeccompValue)
            ));
        }
    }

    #[test]
    fn debug_contains_no_authentication_field() {
        let rendered = format!("{:?}", config().command().unwrap());
        assert!(!rendered.to_ascii_lowercase().contains("token"));
        assert!(!rendered.to_ascii_lowercase().contains("credential"));
    }
}
