//! Punching a range out of an image file, so it reads as zeros and the file
//! keeps its length: the one call each host makes for it, and its checks.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;

/// Deallocate `bytes` of `image` from `offset`.
pub(crate) fn punch_hole(image: &File, offset: u64, bytes: u64) -> io::Result<()> {
    let (Ok(offset), Ok(bytes)) = (libc::off_t::try_from(offset), libc::off_t::try_from(bytes))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range too large",
        ));
    };
    punch(image, offset, bytes)
}

#[cfg(target_os = "linux")]
fn punch(image: &File, offset: libc::off_t, bytes: libc::off_t) -> io::Result<()> {
    // SAFETY: fallocate takes only integers and a descriptor, which `image`
    // keeps open for the call; it touches no memory of ours.
    let result = unsafe {
        libc::fallocate(
            image.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            bytes,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// APFS punches only whole blocks of its own size, and keeps the file's
/// length. A range it would round, leaving part of it in place, is refused.
#[cfg(target_os = "macos")]
fn punch(image: &File, offset: libc::off_t, bytes: libc::off_t) -> io::Result<()> {
    let alignment = libc::off_t::try_from(filesystem_block_size(image)?)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if alignment <= 0 || offset % alignment != 0 || bytes % alignment != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the range is not whole blocks of the image's filesystem",
        ));
    }
    let hole = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset,
        fp_length: bytes,
    };
    // SAFETY: F_PUNCHHOLE reads one `fpunchhole_t` through its third argument
    // and keeps no reference to it. `hole` is a fully initialised, aligned
    // value of libc's definition of that struct (<sys/fcntl.h>), and it lives
    // until the call returns. `image` keeps the descriptor open for the call.
    let result = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_PUNCHHOLE, &raw const hole) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The block size of the filesystem holding `image`.
#[cfg(target_os = "macos")]
fn filesystem_block_size(image: &File) -> io::Result<u64> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes one `statfs` through its second argument and
    // keeps no reference to it. The pointer is to writable, aligned space for
    // exactly libc's `statfs`, the layout libc's `fstatfs` binding fills on
    // Apple targets. `image` keeps the descriptor open for the call.
    if unsafe { libc::fstatfs(image.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs returned 0, so it wrote the whole struct.
    let status = unsafe { status.assume_init() };
    Ok(u64::from(status.f_bsize))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};

    use super::*;

    const BLOCK: usize = 4096;

    fn image(directory: &Path) -> (PathBuf, File) {
        let path = directory.join("image");
        std::fs::write(&path, vec![0xa5_u8; 4 * BLOCK]).unwrap();
        let image = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (path, image)
    }

    #[test]
    fn a_punched_range_reads_as_zeros_and_the_image_keeps_its_length() {
        let directory = tempfile::tempdir().unwrap();
        let (path, image) = image(directory.path());
        punch_hole(&image, BLOCK as u64, 2 * BLOCK as u64).unwrap();
        image.sync_all().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 4 * BLOCK);
        assert!(bytes[..BLOCK].iter().all(|byte| *byte == 0xa5));
        assert!(bytes[BLOCK..3 * BLOCK].iter().all(|byte| *byte == 0));
        assert!(bytes[3 * BLOCK..].iter().all(|byte| *byte == 0xa5));
    }

    /// Refused by this check, not by APFS, which would return EINVAL itself.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_range_apfs_would_round_is_refused_and_nothing_is_punched() {
        let directory = tempfile::tempdir().unwrap();
        let (path, image) = image(directory.path());
        for (offset, bytes) in [(512, BLOCK as u64), (BLOCK as u64, 512)] {
            let error = punch_hole(&image, offset, bytes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("not whole blocks"), "{error}");
        }
        assert!(
            std::fs::read(&path)
                .unwrap()
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }
}
