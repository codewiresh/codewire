//! An image disk's builder guest (#4646). It has exactly three disks: its
//! seed and the setup pack, both read-only, and the staging image disk,
//! read-write. It unpacks the pack's layers onto the staging disk, writes the
//! completion marker with the host's build id, reports that over the boot
//! progress channel and powers off. It never mounts a state or root disk,
//! never starts a workload and holds no project, credential or network input;
//! the seed refuses build mode with any of those (condition 2 on #4646).
//!
//! The host promotes the disk only after this guest reports the layers ready
//! and its VMM exits. It never reads the disk, so this guest's one message is
//! the stage, and nothing it writes names a path, size or id the host acts on.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};

use super::{
    BOOT_PROGRESS, CONTROL_PATH, DEV_PATH, DISK_DISCOVERY_TIMEOUT, PROGRESS_SERVED,
    STATE_MOUNT_PATH, SYS_BLOCK_PATH, apply_setup_layers, create_dir, mount_fs, open_setup_device,
    power_off, record_boot_stage, setup_apply_failure_stage, setup_content_failure_stage,
    start_boot_progress, validate_block_device, verify_setup_contents, verify_setup_header,
    wait_for_disk_by_serial,
};
use crate::image_disk::{IMAGE_DISK_MOUNT, IMAGE_DISK_SERIAL};
use crate::{GuestBootStage, SETUP_DISK_SERIAL, Seed, SetupImage};

/// How long the builder waits for its "ready" stage to reach the host before
/// it powers off. A host that missed it promotes nothing and builds again.
const READY_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the image disk, then power off. Returns only on an error, which the
/// caller turns into a poweroff without the "ready" stage, so the host
/// promotes nothing.
pub(super) fn run(seed: &Seed, seed_device: &Path) -> Result<()> {
    let binding = seed
        .setup()
        .context("an image disk build carries its setup pack")?;
    let setup_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        SETUP_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    let staging_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        IMAGE_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    ensure!(
        setup_device != seed_device
            && staging_device != seed_device
            && staging_device != setup_device,
        "an image build's seed, setup and staging disks must be distinct"
    );
    validate_block_device(&setup_device)?;
    validate_block_device(&staging_device)?;
    let mut setup = open_setup_device(&setup_device)?;
    let header = verify_setup_header(&mut setup, binding)?;
    ensure!(
        matches!(header.image, SetupImage::Build { .. }),
        "an image build's setup pack must build an image disk"
    );

    // No state disk: the boot stage lives in memory for this one boot.
    create_dir(Path::new(STATE_MOUNT_PATH), 0o700)?;
    mount_fs(
        "tmpfs",
        STATE_MOUNT_PATH,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0700,size=1m",
    )
    .context("mount the builder's in-memory state")?;
    create_dir(Path::new(CONTROL_PATH), 0o700)?;
    create_dir(Path::new(IMAGE_DISK_MOUNT), 0o700)?;
    let staging = staging_device
        .to_str()
        .context("the staging image disk path is not UTF-8")?;
    mount_fs(
        staging,
        IMAGE_DISK_MOUNT,
        "ext4",
        libc::MS_NOSUID | libc::MS_NODEV,
        "errors=remount-ro",
    )
    .context("mount the staging image disk")?;
    start_boot_progress(seed, GuestBootStage::RootMounted)?;
    record_boot_stage("setup-header-ready")?;

    let contents = match verify_setup_contents(&mut setup, &header) {
        Ok(contents) => contents,
        Err(error) => {
            record_boot_stage(setup_content_failure_stage(&error))?;
            return Err(error).context("verify every image layer digest");
        }
    };
    record_boot_stage("setup-content-ready")?;
    if let Err(error) =
        apply_setup_layers(&mut setup, &header, &contents, Path::new(IMAGE_DISK_MOUNT))
    {
        record_boot_stage(setup_apply_failure_stage(&error))?;
        return Err(error).context("unpack every image layer onto the staging disk");
    }
    // The layers are synced and the marker with the build id is published:
    // this is the build's "complete".
    record_boot_stage("root-layers-ready")?;
    wait_until_ready_served();
    power_off()
}

/// Waits, bounded, until the progress server has written and flushed the
/// latest stage to the host.
fn wait_until_ready_served() {
    let Some(progress) = BOOT_PROGRESS.get() else {
        return;
    };
    let ready = progress.borrow().sequence;
    let deadline = Instant::now() + READY_DELIVERY_TIMEOUT;
    while PROGRESS_SERVED.load(Ordering::Acquire) < ready && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
}
