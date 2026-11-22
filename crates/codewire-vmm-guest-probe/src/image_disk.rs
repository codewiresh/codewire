//! The shared read-only image disk (#4646): one per image, unpacked once by a
//! builder guest and attached to every local VM of that image.

use sha2::{Digest as _, Sha256};

use crate::setup::{GUEST_ABI_VERSION, ROOT_FORMAT_VERSION, SetupArchitecture, Sha256Value};

/// The virtio serial of the image disk, attached right after the cw runtime
/// disk. A VM checkpoint records the ordered disk list, so this serial and
/// position never change.
pub const IMAGE_DISK_SERIAL: &str = "CWIMAGE1";
/// Where the guest mounts the image disk, `ro,noload,nosuid,nodev`.
pub const IMAGE_DISK_MOUNT: &str = "/image";
/// The unpacked image on the disk, the overlay's lower.
pub const IMAGE_LOWER_PATH: &str = "/image/lower";

/// Changes whenever the unpacking rules change, so a disk built by older
/// rules is never reused.
pub const IMAGE_DISK_FORMAT_VERSION: u32 = 1;
const IMAGE_DISK_DOMAIN: &[u8] = b"codewire-local-image-disk-v1\0";
const IMAGE_ROOT_GENERATION_DOMAIN: &[u8] = b"codewire-image-root-generation-v1\0";

/// A random 128-bit build id, chosen by the host for one build.
pub type BuildId = [u8; 16];

/// The image disk id: the format version, the architecture and the image
/// manifest digest. It leaves out the project and the runtime, because
/// neither changes what the layers unpack to.
pub fn image_disk_id(manifest_sha256: Sha256Value, architecture: SetupArchitecture) -> Sha256Value {
    let mut digest = Sha256::new();
    digest.update(IMAGE_DISK_DOMAIN);
    digest.update(IMAGE_DISK_FORMAT_VERSION.to_le_bytes());
    digest.update([architecture as u8]);
    digest.update(manifest_sha256.as_bytes());
    Sha256Value::from_bytes(digest.finalize().into())
}

/// The root generation of a VM whose lower is on an image disk: the project
/// and the exact build it sits on. A rebuilt disk is a new root generation,
/// so an upper is never reused over a different build.
pub fn image_root_generation(
    project_sha256: Sha256Value,
    image_disk_id: Sha256Value,
    build_id: BuildId,
) -> Sha256Value {
    let mut digest = Sha256::new();
    digest.update(IMAGE_ROOT_GENERATION_DOMAIN);
    digest.update(GUEST_ABI_VERSION.to_le_bytes());
    digest.update(ROOT_FORMAT_VERSION.to_le_bytes());
    digest.update(project_sha256.as_bytes());
    digest.update(image_disk_id.as_bytes());
    digest.update(build_id);
    Sha256Value::from_bytes(digest.finalize().into())
}
