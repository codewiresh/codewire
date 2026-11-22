//! The smoke's own arguments: every path absolute, every count bounded.

use super::image_disk::ImageDiskOptions;
use super::*;
use codewire_local_vmm::oci::RegistryReference;

impl Args {
    pub(super) fn parse(arguments: impl IntoIterator<Item = String>) -> SmokeResult<Option<Self>> {
        let mut arguments = arguments.into_iter();
        let Some(mode) = arguments.next() else {
            return Err(failure("missing run or cleanup subcommand"));
        };
        if matches!(mode.as_str(), "-h" | "--help") {
            if arguments.next().is_some() {
                return Err(failure("--help accepts no arguments"));
            }
            return Ok(None);
        }
        let mode = match mode.as_str() {
            "run" => Mode::Run,
            "image-disk" => Mode::ImageDisk,
            "cleanup" => Mode::Cleanup,
            _ => return Err(failure("unknown smoke subcommand")),
        };
        let mut artifact_root = None;
        let mut artifact_lock = None;
        let mut state_root = None;
        let mut vm_id = None;
        let mut second_vm_id = None;
        let mut publish = None;
        let mut image = None;
        let mut outside_disk = None;
        let mut vcpus = None;
        let mut memory_mib = None;
        while let Some(flag) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| failure("smoke flag requires a value"))?;
            let destination = match flag.as_str() {
                "--artifact-root" => &mut artifact_root,
                "--artifact-lock" => &mut artifact_lock,
                "--state-root" => &mut state_root,
                "--outside-disk" if mode == Mode::Run => &mut outside_disk,
                "--vm-id" => {
                    if vm_id.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    vm_id = Some(
                        Uuid::parse_str(&value).map_err(|_| failure("--vm-id is not a UUID"))?,
                    );
                    continue;
                }
                "--second-vm-id" if mode == Mode::ImageDisk => {
                    if second_vm_id.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    second_vm_id = Some(
                        Uuid::parse_str(&value)
                            .map_err(|_| failure("--second-vm-id is not a UUID"))?,
                    );
                    continue;
                }
                "--image" if mode == Mode::ImageDisk => {
                    if image.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    image = Some(
                        RegistryReference::parse(&value)
                            .map_err(|_| failure("--image is not an image reference"))?,
                    );
                    continue;
                }
                "--publish" if mode == Mode::ImageDisk => {
                    if publish.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    publish = Some(PathBuf::from(value));
                    continue;
                }
                "--cpus" if mode != Mode::Cleanup => {
                    if vcpus.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    vcpus = Some(parse_vcpus(&value)?);
                    continue;
                }
                "--memory-mib" if mode != Mode::Cleanup => {
                    if memory_mib.is_some() {
                        return Err(failure("duplicate smoke flag"));
                    }
                    memory_mib = Some(parse_memory_mib(&value)?);
                    continue;
                }
                _ => return Err(failure("unknown or invalid smoke flag")),
            };
            if destination.is_some() {
                return Err(failure("duplicate smoke flag"));
            }
            *destination = Some(PathBuf::from(value));
        }
        let resources = match mode {
            Mode::Run | Mode::ImageDisk => Some(RunResources {
                vcpus: vcpus.ok_or_else(|| failure("--cpus is required for run"))?,
                memory_mib: memory_mib
                    .ok_or_else(|| failure("--memory-mib is required for run"))?,
            }),
            Mode::Cleanup => None,
        };
        let result = Self {
            mode,
            artifact_root: artifact_root.ok_or_else(|| failure("--artifact-root is required"))?,
            artifact_lock: artifact_lock.ok_or_else(|| failure("--artifact-lock is required"))?,
            state_root: state_root.ok_or_else(|| failure("--state-root is required"))?,
            vm_id: vm_id.ok_or_else(|| failure("--vm-id is required"))?,
            image_disk: ImageDiskOptions {
                second_vm_id,
                publish,
                image,
            },
            outside_disk,
            resources,
        };
        if result.mode == Mode::Run && result.outside_disk.is_none() {
            return Err(failure("--outside-disk is required for run"));
        }
        let options = &result.image_disk;
        if options.image.is_some() && options.publish.is_none() {
            return Err(failure("--image needs --publish"));
        }
        if result.mode == Mode::ImageDisk
            && options.image.is_none()
            && options
                .second_vm_id
                .is_none_or(|second| second == result.vm_id)
        {
            return Err(failure(
                "--second-vm-id is required and differs from --vm-id",
            ));
        }
        for path in [
            &result.artifact_root,
            &result.artifact_lock,
            &result.state_root,
        ] {
            if !path.is_absolute() {
                return Err(failure("all smoke paths must be absolute"));
            }
        }
        if result
            .outside_disk
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(failure("all smoke paths must be absolute"));
        }
        Ok(Some(result))
    }

    pub(super) fn runner_config(&self) -> RunnerConfig {
        RunnerConfig {
            state_root: self.state_root.clone(),
            artifact_root: self.artifact_root.clone(),
            artifact_lock: self.artifact_lock.clone(),
        }
    }
}

pub(super) fn print_usage() {
    eprintln!(
        "usage:\n  codewire-local-vmm-smoke run --artifact-root PATH --artifact-lock PATH --state-root PATH --vm-id UUID --outside-disk PATH --cpus COUNT --memory-mib MIB\n  codewire-local-vmm-smoke image-disk --artifact-root PATH --artifact-lock PATH --state-root PATH --vm-id UUID (--second-vm-id UUID [--publish DIR] | --image REF --publish DIR) --cpus COUNT --memory-mib MIB\n  codewire-local-vmm-smoke cleanup --artifact-root PATH --artifact-lock PATH --state-root PATH --vm-id UUID"
    );
}

fn parse_vcpus(value: &str) -> SmokeResult<u8> {
    if !is_canonical_decimal(value) {
        return Err(failure(
            "--cpus must be a decimal integer from 1 through 32",
        ));
    }
    let value = value
        .parse::<u8>()
        .map_err(|_| failure("--cpus must be a decimal integer from 1 through 32"))?;
    if !(1..=32).contains(&value) {
        return Err(failure(
            "--cpus must be a decimal integer from 1 through 32",
        ));
    }
    Ok(value)
}

fn parse_memory_mib(value: &str) -> SmokeResult<u32> {
    if !is_canonical_decimal(value) {
        return Err(failure(
            "--memory-mib must be a decimal integer from 128 through 65536",
        ));
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| failure("--memory-mib must be a decimal integer from 128 through 65536"))?;
    if !(128..=65_536).contains(&value) {
        return Err(failure(
            "--memory-mib must be a decimal integer from 128 through 65536",
        ));
    }
    Ok(value)
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}
