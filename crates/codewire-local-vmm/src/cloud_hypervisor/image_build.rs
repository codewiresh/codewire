//! The Cloud Hypervisor command of an image disk's builder guest (#4646).
//!
//! It has exactly three disks: its seed and the setup pack, both read-only,
//! and the staging image disk, read-write. It has no network device, no
//! share, no state or root disk and no checkpoint directory, so the one
//! thing it can write is the disk it builds (condition 2 on #4646). The
//! hybrid vsock carries only its boot progress, which is how the host learns
//! the build finished.

use std::path::{Path, PathBuf};

use codewire_vmm_guest_probe::image_disk::IMAGE_DISK_SERIAL;
use codewire_vmm_guest_probe::{SEED_DISK_SERIAL, SETUP_DISK_SERIAL};

use super::{
    CloudHypervisorConfigError, CommandSpec, GUEST_KERNEL_CMDLINE, display,
    is_normal_absolute_path, push_option, validate_parameter_path, validate_sockets,
};
use crate::artifact::AdmittedArtifacts;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageBuildVmConfig {
    pub executable: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub seed_disk: PathBuf,
    pub setup_disk: PathBuf,
    /// The staging image disk, the only disk the builder may write.
    pub image_disk: PathBuf,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    pub vsock_cid: u32,
    pub vcpus: u8,
    pub memory_mib: u32,
}

impl ImageBuildVmConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifacts: &AdmittedArtifacts,
        seed_disk: PathBuf,
        setup_disk: PathBuf,
        image_disk: PathBuf,
        api_socket: PathBuf,
        vsock_socket: PathBuf,
        vsock_cid: u32,
        vcpus: u8,
        memory_mib: u32,
    ) -> Self {
        Self {
            executable: artifacts.cloud_hypervisor.path().to_owned(),
            kernel: artifacts.kernel.path().to_owned(),
            initramfs: artifacts.initramfs.path().to_owned(),
            seed_disk,
            setup_disk,
            image_disk,
            api_socket,
            vsock_socket,
            vsock_cid,
            vcpus,
            memory_mib,
        }
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
        for path in self.paths() {
            if !is_normal_absolute_path(path) {
                return Err(CloudHypervisorConfigError::NonAbsolutePath(path.to_owned()));
            }
            validate_parameter_path(path).map_err(CloudHypervisorConfigError::UnsafePath)?;
        }
        if self.seed_disk == self.setup_disk
            || self.seed_disk == self.image_disk
            || self.setup_disk == self.image_disk
        {
            return Err(CloudHypervisorConfigError::AliasedDiskPaths);
        }
        validate_sockets(&self.api_socket, &self.vsock_socket, &[])
    }

    pub fn command(&self) -> Result<CommandSpec, CloudHypervisorConfigError> {
        self.validate()?;
        let mut arguments = Vec::new();
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
            format!("size={}M,shared=off,mergeable=off", self.memory_mib),
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
        push_option(
            &mut arguments,
            "--disk",
            format!(
                "path={},readonly=on,direct=off,id=cw-setup,serial={},image_type=raw,backing_files=off,sparse=off,lock_granularity=full",
                display(&self.setup_disk)?,
                SETUP_DISK_SERIAL,
            ),
        );
        push_option(
            &mut arguments,
            "--disk",
            format!(
                "path={},readonly=off,direct=off,id=cw-image,serial={},image_type=raw,backing_files=off,sparse=on,lock_granularity=full",
                display(&self.image_disk)?,
                IMAGE_DISK_SERIAL,
            ),
        );
        push_option(
            &mut arguments,
            "--vsock",
            format!(
                "cid={},socket={},id=cw-vsock",
                self.vsock_cid,
                display(&self.vsock_socket)?
            ),
        );
        // As a VM's: guest serial bytes are hostile and unbounded.
        push_option(&mut arguments, "--serial", "null");
        push_option(&mut arguments, "--console", "off");
        push_option(&mut arguments, "--rng", "src=/dev/urandom");
        push_option(&mut arguments, "--seccomp", "true");
        // Native Landlock from the parsed configuration, with no broadening:
        // the builder writes only its staging disk.
        arguments.push(std::ffi::OsString::from("--landlock"));
        let command = CommandSpec {
            program: self.executable.clone(),
            arguments,
            expected_disk_count: 3,
            expected_fs_count: 0,
            landlock_rule: None,
        };
        command.validate_allowlist()?;
        Ok(command)
    }

    fn paths(&self) -> [&Path; 8] {
        [
            &self.executable,
            &self.kernel,
            &self.initramfs,
            &self.seed_disk,
            &self.setup_disk,
            &self.image_disk,
            &self.api_socket,
            &self.vsock_socket,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ImageBuildVmConfig {
        ImageBuildVmConfig {
            executable: PathBuf::from("/opt/codewire/cloud-hypervisor"),
            kernel: PathBuf::from("/opt/codewire/vmlinux"),
            initramfs: PathBuf::from("/opt/codewire/initramfs.cpio"),
            seed_disk: PathBuf::from("/var/codewire/build/seed.raw"),
            setup_disk: PathBuf::from("/var/codewire/build/setup.raw"),
            image_disk: PathBuf::from("/var/codewire/build/image.raw"),
            api_socket: PathBuf::from("/run/codewire/build-api/api.sock"),
            vsock_socket: PathBuf::from("/run/codewire/build-vsock/vsock.sock"),
            vsock_cid: 41,
            vcpus: 4,
            memory_mib: 2048,
        }
    }

    fn values<'a>(arguments: &'a [std::ffi::OsString], flag: &str) -> Vec<&'a str> {
        arguments
            .windows(2)
            .filter(|pair| pair[0] == flag)
            .map(|pair| pair[1].to_str().unwrap())
            .collect()
    }

    /// Condition 2 on #4646: exactly the seed and the setup pack read-only and
    /// the staging disk read-write; no network, share, state or root disk.
    #[test]
    fn the_builder_has_exactly_three_disks_and_no_network_or_share() {
        let command = config().command().unwrap();
        let arguments = command.arguments();
        let disks = values(arguments, "--disk");
        assert_eq!(disks.len(), 3);
        assert!(disks[0].contains("id=cw-seed") && disks[0].contains("readonly=on"));
        assert!(disks[1].contains("id=cw-setup") && disks[1].contains("readonly=on"));
        assert!(disks[2].contains("id=cw-image") && disks[2].contains("readonly=off"));
        assert!(disks[2].contains(&format!("serial={IMAGE_DISK_SERIAL}")));
        for flag in [
            "--net",
            "--fs",
            "--landlock-rules",
            "--pmem",
            "--device",
            "--user-device",
        ] {
            assert!(values(arguments, flag).is_empty(), "{flag}");
        }
        assert!(values(arguments, "--memory")[0].contains("shared=off"));
    }

    #[test]
    fn aliased_disks_or_sockets_are_refused() {
        let mut aliased = config();
        aliased.image_disk = aliased.setup_disk.clone();
        assert!(matches!(
            aliased.command(),
            Err(CloudHypervisorConfigError::AliasedDiskPaths)
        ));
        let mut sockets = config();
        sockets.vsock_socket = sockets.api_socket.clone();
        assert!(matches!(
            sockets.command(),
            Err(CloudHypervisorConfigError::AliasedSocketPaths)
        ));
    }
}
