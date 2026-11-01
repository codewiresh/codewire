//! The block-device backend: clearing ranges of a disk that is a device
//! rather than an image file, such as a Kubernetes Block volume.
//!
//! A discard is the fast way to clear a range, but what a discarded range
//! reads as depends on the storage. Under LUKS on thin LVM, as on
//! `linstor-local`, an unmapped chunk reads as the decryption of zeros:
//! pseudo-random, never zero. So the check is that the old data is gone, not
//! that the range reads zero, and it is made with canaries:
//!
//! - a range holding no whole aligned granule, and the unaligned head and tail
//!   of every other range, are overwritten with zeros;
//! - a random canary, new on every run, is written over the first and the last
//!   aligned granule of each range, and synced;
//! - the aligned interior is discarded;
//! - a range is overwritten with zeros if any 4 KiB block of either canary
//!   granule still holds the canary's bytes after the discard, as is every
//!   range on a device that takes no discard;
//! - once synced, every byte written as zeros is read back from the device as
//!   zeros, and no canary block may remain.
//!
//! This rests on the storage unmapping exactly the chunks a discard fully
//! covers, as dm-thin does, so only the chunks across the interior's two ends
//! can be partly covered. A range counts as discarded only when no block of
//! its canary granules survived, that is when the chunks across both ends were
//! unmapped too, or lay wholly outside the interior. Any other chunk size, one
//! larger than [`GRANULE`] or one that doesn't divide it, leaves a canary
//! block and the range is written instead. A chunk size other than the
//! granule's costs writes, never correctness.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;

use super::{Error, Tools, unreadable_ranges};

/// The aligned unit a range is discarded in, and the size of a canary: a
/// multiple of every thin-pool chunk size Codewire's storage uses.
const GRANULE: u64 = 1024 * 1024;

/// What a wipe did, for its caller's record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WipeReport {
    /// The merged ranges cleared.
    pub ranges: usize,
    /// Their total size.
    pub bytes: u64,
    /// Whether the device took discards. One that refuses them is cleared by
    /// writing alone.
    pub discard_supported: bool,
    /// Ranges whose interior a discard was proven to clear.
    pub discarded_ranges: usize,
    /// Ranges with an aligned interior whose canary survived the discard, so
    /// were overwritten.
    pub fallback_ranges: usize,
    /// How much was overwritten with zeros, canaries aside.
    pub written_bytes: u64,
}

/// Clear, on the block device `device`, every block the guest cannot read
/// ([`super::punch_unreadable_blocks`] has the list), and prove the old data
/// gone (see the module). The filesystem must not be mounted: the device is
/// opened exclusively, so a mounted one is refused.
///
/// The block size is the filesystem's own, as `dumpe2fs` reports it. A
/// regular file is accepted too and cleared by writing alone, since it takes
/// no discard; tests use that.
pub async fn wipe_unreadable_blocks(
    tools: &impl Tools,
    device: &Path,
) -> Result<WipeReport, Error> {
    let (block_size, ranges) = unreadable_ranges(tools, device).await?;
    let mut disk = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_EXCL)
        .open(device)?;
    // A block device's metadata says 0 bytes; its end is its size.
    let length = disk.seek(SeekFrom::End(0))?;
    let mut spans = Vec::with_capacity(ranges.len());
    for &(first, last) in &ranges {
        let offset = first
            .checked_mul(block_size)
            .ok_or(Error::Unreadable("dumpe2fs"))?;
        let bytes = (last - first + 1)
            .checked_mul(block_size)
            .filter(|bytes| offset.saturating_add(*bytes) <= length)
            .ok_or(Error::Unreadable("dumpe2fs"))?;
        spans.push((offset, bytes));
    }
    wipe_spans(&disk, &spans, discard)
}

/// What a discard of one range did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discard {
    Issued,
    /// The disk takes no discard.
    Unsupported,
}

/// Clear byte ranges `spans` of `disk`, discarding through `discard`.
fn wipe_spans(
    disk: &File,
    spans: &[(u64, u64)],
    mut discard: impl FnMut(&File, u64, u64) -> io::Result<Discard>,
) -> Result<WipeReport, Error> {
    let mut report = WipeReport {
        ranges: spans.len(),
        bytes: spans.iter().map(|(_, bytes)| bytes).sum(),
        discard_supported: true,
        ..WipeReport::default()
    };
    let canary = canary()?;
    let mut zeroed = Vec::new();
    // Each range's aligned interior, from its first canary granule to the end
    // of its last.
    let mut interiors = Vec::new();
    for &(offset, bytes) in spans {
        let end = offset + bytes;
        let first = offset.next_multiple_of(GRANULE);
        let after = end - end % GRANULE;
        if after <= first {
            zeroed.push((offset, bytes));
            continue;
        }
        if offset < first {
            zeroed.push((offset, first - offset));
        }
        if after < end {
            zeroed.push((after, end - after));
        }
        disk.write_all_at(&canary, first)?;
        disk.write_all_at(&canary, after - GRANULE)?;
        interiors.push((first, after));
    }
    disk.sync_data()?;
    for &(first, after) in &interiors {
        if discard(disk, first, after - first)? == Discard::Unsupported {
            report.discard_supported = false;
            break;
        }
    }
    drop_cached(disk)?;
    let mut granule = vec![0_u8; GRANULE as usize];
    for &(first, after) in &interiors {
        let mut survived = !report.discard_supported;
        for at in [first, after - GRANULE] {
            disk.read_exact_at(&mut granule, at)?;
            survived |= holds_canary(&granule, &canary);
        }
        if !survived {
            report.discarded_ranges += 1;
            continue;
        }
        if report.discard_supported {
            report.fallback_ranges += 1;
        }
        zeroed.push((first, after - first));
    }
    for &(offset, bytes) in &zeroed {
        write_zeros(disk, offset, bytes)?;
        report.written_bytes += bytes;
    }
    disk.sync_data()?;
    drop_cached(disk)?;
    for &(offset, bytes) in &zeroed {
        if !reads_as_zeros(disk, offset, bytes)? {
            return Err(Error::NotCleared);
        }
    }
    for &(first, after) in &interiors {
        for at in [first, after - GRANULE] {
            disk.read_exact_at(&mut granule, at)?;
            if holds_canary(&granule, &canary) {
                return Err(Error::NotCleared);
            }
        }
    }
    Ok(report)
}

/// How finely a canary granule is compared: the smallest block ext4 or any
/// thin-pool chunk Codewire's storage uses.
const CANARY_BLOCK: usize = 4096;

/// Whether any 4 KiB block of `granule` still holds the canary's bytes at that
/// offset, so a discard that cleared only part of it isn't taken as done.
fn holds_canary(granule: &[u8], canary: &[u8]) -> bool {
    granule
        .chunks(CANARY_BLOCK)
        .zip(canary.chunks(CANARY_BLOCK))
        .any(|(read, written)| read == written)
}

/// A granule of random bytes, which no disk holds by chance.
fn canary() -> io::Result<Vec<u8>> {
    let mut canary = vec![0_u8; GRANULE as usize];
    File::open("/dev/urandom")?.read_exact(&mut canary)?;
    Ok(canary)
}

/// `BLKDISCARD` of one range.
fn discard(disk: &File, offset: u64, bytes: u64) -> io::Result<Discard> {
    let range = [offset, bytes];
    // SAFETY: BLKDISCARD reads two u64s, start and length, from the pointer.
    let result = unsafe { libc::ioctl(disk.as_raw_fd(), BLKDISCARD, range.as_ptr()) };
    if result == 0 {
        return Ok(Discard::Issued);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Not a block device, or one without discard.
        Some(libc::ENOTTY | libc::EOPNOTSUPP) => Ok(Discard::Unsupported),
        _ => Err(error),
    }
}

/// `_IO(0x12, 119)` from `<linux/fs.h>`.
const BLKDISCARD: libc::Ioctl = 0x1277;

fn write_zeros(disk: &File, offset: u64, bytes: u64) -> io::Result<()> {
    let zeros = vec![0_u8; GRANULE as usize];
    let end = offset + bytes;
    let mut at = offset;
    while at < end {
        let length = (end - at).min(GRANULE) as usize;
        disk.write_all_at(&zeros[..length], at)?;
        at += length as u64;
    }
    Ok(())
}

/// Whether every byte of the range reads as zero.
fn reads_as_zeros(disk: &File, offset: u64, bytes: u64) -> io::Result<bool> {
    let mut buffer = vec![0_u8; GRANULE as usize];
    let end = offset + bytes;
    let mut at = offset;
    while at < end {
        let length = (end - at).min(GRANULE) as usize;
        disk.read_exact_at(&mut buffer[..length], at)?;
        if buffer[..length].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        at += length as u64;
    }
    Ok(true)
}

/// Drop the disk's cached pages, which are clean once synced, so the reads
/// that follow come from the device rather than from what was just written.
fn drop_cached(disk: &File) -> io::Result<()> {
    // SAFETY: a plain fadvise on a live descriptor; 0, 0 is the whole file.
    let result = unsafe { libc::posix_fadvise(disk.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

#[cfg(test)]
mod tests;
