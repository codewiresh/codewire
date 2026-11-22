//! A VM whose overlay takes its lower from the shared image disk (#4646).
//!
//! The image disk is mounted read-only, `noload`, at `/image`. On the first
//! boot its marker must name the image disk and the build the setup pack is
//! bound to; the guest then records that build beside its root generation
//! and checks the marker against the record on every later boot. This is a
//! consistency check against host mistakes: the record lives on the
//! guest-writable root disk, and the host's own record of the build is the
//! boundary (design section 4).

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context as _, Result, ensure};

use super::{
    DEV_PATH, DISK_DISCOVERY_TIMEOUT, READ_LIMIT, ROOT_MOUNT_PATH, SYS_BLOCK_PATH, create_dir,
    mount_fs, read_bounded, validate_block_device, wait_for_disk_by_serial, write_durable,
};
use crate::image_disk::{
    BuildId, IMAGE_DISK_MOUNT, IMAGE_DISK_SERIAL, IMAGE_LOWER_PATH, image_disk_id,
};
use crate::setup_apply::{COMPLETION_FILE, completion_bytes};
use crate::{SetupHeader, SetupImage, Sha256Value};

/// The record of the build this VM's root generation sits on.
const RECORD_NAME: &str = "image-build";

static ATTACHED: OnceLock<()> = OnceLock::new();

/// The overlay's lower: the image disk's when attached, else the root disk's.
pub(super) fn lower_path(root_lower: &'static str) -> &'static str {
    if ATTACHED.get().is_some() {
        IMAGE_LOWER_PATH
    } else {
        root_lower
    }
}

pub(super) fn attached() -> bool {
    ATTACHED.get().is_some()
}

/// Finds and mounts the image disk. `others` are every disk already
/// admitted, none of which it may alias.
pub(super) fn mount(others: &[&Path]) -> Result<()> {
    let device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        IMAGE_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    ensure!(
        others.iter().all(|other| *other != device.as_path()),
        "the image disk must be distinct from every other guest disk"
    );
    validate_block_device(&device)?;
    create_dir(Path::new(IMAGE_DISK_MOUNT), 0o755)?;
    let source = device
        .to_str()
        .context("the image disk path is not UTF-8")?;
    mount_fs(
        source,
        IMAGE_DISK_MOUNT,
        "ext4",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        "noload",
    )
    .context("mount the image disk read-only")?;
    let _ = ATTACHED.set(());
    Ok(())
}

/// The first boot's check: the setup pack and the image disk agree on the
/// build, which is then recorded for later boots. A combined root's pack on
/// an attached VM, or the other way round, is refused.
pub(super) fn bind_first_boot(header: &SetupHeader) -> Result<()> {
    match (header.image, attached()) {
        (SetupImage::CombinedRoot, false) => Ok(()),
        (SetupImage::Attach { build_id }, true) => {
            let disk = image_disk_id(header.manifest_sha256, header.architecture);
            check_marker(disk, build_id)?;
            write_durable(
                &Path::new(ROOT_MOUNT_PATH).join(RECORD_NAME),
                record(disk, build_id).as_bytes(),
                0o400,
            )
            .context("record the image disk build")
        }
        _ => anyhow::bail!("the setup pack and the image disk attachment disagree"),
    }
}

/// A later boot's check: the attached disk is still the recorded build.
pub(super) fn verify_recorded() -> Result<()> {
    let bytes = read_bounded(&Path::new(ROOT_MOUNT_PATH).join(RECORD_NAME), READ_LIMIT)
        .context("read the recorded image disk build")?;
    let text = std::str::from_utf8(&bytes).context("the image disk record is not text")?;
    let (disk, build) = text
        .strip_suffix('\n')
        .and_then(|line| line.split_once(' '))
        .context("the image disk record is malformed")?;
    let disk = Sha256Value::parse_hex(disk).context("the recorded image disk id")?;
    let build_id = parse_build_id(build).context("the recorded build id")?;
    check_marker(disk, build_id)
}

fn check_marker(disk: Sha256Value, build_id: BuildId) -> Result<()> {
    let marker = read_bounded(&Path::new(IMAGE_DISK_MOUNT).join(COMPLETION_FILE), 4096)
        .context("read the image disk's marker")?;
    ensure!(
        marker == completion_bytes(disk, Some(build_id)),
        "this image disk is a different build than the VM was made on; remove the VM's image disk record by recreating the VM, or restore the image disk"
    );
    Ok(())
}

fn record(disk: Sha256Value, build_id: BuildId) -> String {
    let build: String = build_id.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{disk} {build}\n")
}

fn parse_build_id(hex: &str) -> Option<BuildId> {
    let bytes = hex.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut build_id = [0_u8; 16];
    for (index, pair) in bytes.chunks(2).enumerate() {
        build_id[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(build_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_build_reads_back_exactly() {
        let disk = Sha256Value::calculate(b"image");
        let mut build_id = [0_u8; 16];
        build_id[3] = 0xfe;
        let line = record(disk, build_id);
        let (recorded, build) = line.strip_suffix('\n').unwrap().split_once(' ').unwrap();
        assert_eq!(Sha256Value::parse_hex(recorded).unwrap(), disk);
        assert_eq!(parse_build_id(build), Some(build_id));
        assert_eq!(parse_build_id("zz"), None);
        assert_eq!(parse_build_id(&"g".repeat(32)), None);
    }
}
