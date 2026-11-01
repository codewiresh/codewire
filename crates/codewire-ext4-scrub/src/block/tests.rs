//! The block backend on real e2fsprogs images, and on a loop device when the
//! operator provides one.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::SystemTools;

const MIB: u64 = 1024 * 1024;

fn tool(name: &str) -> PathBuf {
    ["/usr/sbin", "/usr/bin", "/sbin"]
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} for ext4 scrub tests"))
}

/// A synthetic marker no disk holds by chance.
fn marker(label: &str) -> String {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut random)
        .unwrap();
    let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("cw-ext4-scrub-test-{label}-{hex}")
}

fn format(disk: &Path) {
    let status = Command::new(tool("mkfs.ext4"))
        .args(["-q", "-F", "-b", "4096", "-E", "nodiscard"])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
}

/// Run debugfs on `disk` unconfined, as a test's own setup.
fn debugfs_setup(disk: &Path, request: &str) -> Vec<u8> {
    let output = Command::new(tool("debugfs"))
        .args(["-w", "-R", request])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

fn plant(disk: &Path, scratch: &Path, destination: &str, contents: &[u8]) {
    let host = scratch.join("planted");
    fs::write(&host, contents).unwrap();
    debugfs_setup(
        disk,
        &format!("write {} {destination}", host.to_str().unwrap()),
    );
    fs::remove_file(host).unwrap();
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Leave copies of `token` in freed blocks of `disk` and a kept `control`
/// file: three generations of a token file, each rewritten under a new name
/// and renamed over the last, and then the last removed.
fn plant_freed_token(disk: &Path, scratch: &Path, token: &str, control: &str) {
    let body = |generation: u32| {
        format!("{{\"generation\":{generation},\"token\":\"{token}\"}}\n")
            .repeat(2000)
            .into_bytes()
    };
    plant(disk, scratch, "/control", control.repeat(100).as_bytes());
    plant(disk, scratch, "/token", &body(0));
    for generation in 1..=3 {
        plant(disk, scratch, "/token.new", &body(generation));
        // A rename over: the old inode and its blocks are freed, the new
        // one keeps its single link under the old name.
        debugfs_setup(disk, "rm /token");
        debugfs_setup(disk, "link /token.new /token");
        debugfs_setup(disk, "unlink /token.new");
    }
    debugfs_setup(disk, "rm /token");
    let status = Command::new(tool("e2fsck"))
        .args(["-f", "-p"])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(matches!(status.code(), Some(0 | 1)), "{status:?}");
}

fn assert_cleared(disk: &Path, token: &str, control: &str) {
    let mut bytes = Vec::new();
    File::open(disk).unwrap().read_to_end(&mut bytes).unwrap();
    assert_eq!(count(&bytes, token.as_bytes()), 0, "a token copy survived");
    assert!(
        count(&bytes, control.as_bytes()) >= 100,
        "the scan cannot see the kept control"
    );
    let kept = debugfs_setup(disk, "cat /control");
    assert_eq!(kept, control.repeat(100).as_bytes());
    let check = Command::new(tool("e2fsck"))
        .args(["-f", "-n"])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert_eq!(check.code(), Some(0), "the filesystem is not clean");
}

#[tokio::test]
async fn freed_copies_of_a_token_are_wiped_from_an_image_by_writing_alone() {
    let scratch = tempfile::tempdir().unwrap();
    let image = scratch.path().join("disk.raw");
    File::create(&image).unwrap().set_len(64 * MIB).unwrap();
    format(&image);
    let (token, control) = (marker("token"), marker("control"));
    plant_freed_token(&image, scratch.path(), &token, &control);
    let before = fs::read(&image).unwrap();
    assert!(count(&before, token.as_bytes()) >= 4, "nothing was planted");

    let report = wipe_unreadable_blocks(&SystemTools, &image).await.unwrap();

    assert_cleared(&image, &token, &control);
    assert!(!report.discard_supported, "a regular file takes no discard");
    assert_eq!(report.written_bytes, report.bytes);
    assert!(report.ranges > 0);
}

/// What an unmapped chunk of LUKS on thin LVM reads as: the decryption of
/// zeros, pseudo-random and fixed per chunk, never zero.
fn decrypted_zeros(chunk: u64, bytes: u64) -> Vec<u8> {
    let mut state = chunk.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..bytes)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// A simulated LUKS-on-thin disk of `bytes`, never written, so every chunk
/// reads as decrypted zeros, with `secret` written over each of `spans`.
fn thin_disk(scratch: &Path, bytes: u64, chunk: u64, spans: &[(u64, u64)], secret: &str) -> File {
    let path = scratch.join("disk.raw");
    let mut contents = Vec::with_capacity(bytes as usize);
    for index in 0..bytes / chunk {
        contents.extend(decrypted_zeros(index, chunk));
    }
    for &(offset, length) in spans {
        let text = secret.repeat(length as usize / secret.len() + 1);
        contents[offset as usize..(offset + length) as usize]
            .copy_from_slice(&text.as_bytes()[..length as usize]);
    }
    fs::write(&path, &contents).unwrap();
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

/// A discard as dm-thin under dm-crypt serves it: every chunk of `chunk`
/// bytes the range fully covers is unmapped and reads as decrypted zeros; a
/// partly covered one is left as it was.
fn thin_discard(chunk: u64) -> impl FnMut(&File, u64, u64) -> io::Result<Discard> {
    move |disk, offset, bytes| {
        let mut at = offset.next_multiple_of(chunk);
        while at + chunk <= offset + bytes {
            disk.write_all_at(&decrypted_zeros(at / chunk, chunk), at)?;
            at += chunk;
        }
        Ok(Discard::Issued)
    }
}

/// Every byte of `disk`, from its start whatever was read before.
fn whole(disk: &File) -> Vec<u8> {
    let mut bytes = vec![0_u8; disk.metadata().unwrap().len() as usize];
    disk.read_exact_at(&mut bytes, 0).unwrap();
    assert!(!bytes.is_empty());
    bytes
}

/// Ranges with unaligned ends, one too small for a granule and one aligned.
const SPANS: [(u64, u64); 3] = [(MIB / 2, 5 * MIB), (8 * MIB, MIB / 4), (10 * MIB, 4 * MIB)];

#[test]
fn on_luks_over_thin_a_discarded_interior_reads_as_noise_and_only_the_edges_are_written() {
    let scratch = tempfile::tempdir().unwrap();
    let secret = marker("secret");
    let disk = thin_disk(scratch.path(), 16 * MIB, MIB, &SPANS, &secret);
    let before = whole(&disk);

    let report = wipe_spans(&disk, &SPANS, thin_discard(MIB)).unwrap();

    let after = whole(&disk);
    assert_eq!(count(&after, secret.as_bytes()), 0, "old data survived");
    assert_eq!(
        report,
        WipeReport {
            ranges: 3,
            bytes: 5 * MIB + MIB / 4 + 4 * MIB,
            discard_supported: true,
            discarded_ranges: 2,
            fallback_ranges: 0,
            // Two half-granule edges and the small range.
            written_bytes: MIB + MIB / 4,
        }
    );
    // The discarded interior is noise, not zeros, and still passed.
    assert_eq!(
        &after[MIB as usize..5 * MIB as usize],
        &{
            let mut noise = Vec::new();
            for chunk in 1..5 {
                noise.extend(decrypted_zeros(chunk, MIB));
            }
            noise
        }[..]
    );
    // Outside the ranges nothing changed.
    assert_eq!(
        &after[7 * MIB as usize..8 * MIB as usize],
        &before[7 * MIB as usize..8 * MIB as usize]
    );
}

#[test]
fn a_chunk_larger_than_the_granule_leaves_a_canary_and_its_range_is_written() {
    let scratch = tempfile::tempdir().unwrap();
    let secret = marker("secret");
    // The first range starts mid-chunk, so its first granule's chunk is only
    // partly covered; the second starts and ends on chunk boundaries.
    let spans = [(MIB, 6 * MIB), (8 * MIB, 4 * MIB)];
    let disk = thin_disk(scratch.path(), 16 * MIB, 2 * MIB, &spans, &secret);

    let report = wipe_spans(&disk, &spans, thin_discard(2 * MIB)).unwrap();

    assert_eq!(
        count(&whole(&disk), secret.as_bytes()),
        0,
        "old data survived"
    );
    assert_eq!(report.discarded_ranges, 1);
    assert_eq!(report.fallback_ranges, 1);
    assert_eq!(report.written_bytes, 6 * MIB);
}

#[test]
fn a_chunk_that_does_not_divide_the_granule_clears_part_of_a_canary_and_its_range_is_written() {
    let scratch = tempfile::tempdir().unwrap();
    let secret = marker("secret");
    // dm-thin allows any multiple of 64 KiB: a 192 KiB chunk crosses the
    // first granule's start, so the discard clears all of that granule but
    // the part of it in the partly covered chunk.
    let chunk = 192 * 1024;
    let disk = thin_disk(
        scratch.path(),
        16 * MIB - (16 * MIB) % chunk,
        chunk,
        &SPANS,
        &secret,
    );

    let report = wipe_spans(&disk, &SPANS, thin_discard(chunk)).unwrap();

    let after = whole(&disk);
    assert_eq!(count(&after, secret.as_bytes()), 0, "old data survived");
    assert_eq!(report.discarded_ranges, 0, "{report:?}");
    assert_eq!(report.fallback_ranges, 2, "{report:?}");
    assert_eq!(report.written_bytes, report.bytes);
}

#[test]
fn a_canary_counts_as_left_when_any_one_of_its_blocks_is() {
    let canary = (0..GRANULE)
        .map(|byte| (byte % 251) as u8)
        .collect::<Vec<_>>();
    let mut read = vec![0_u8; GRANULE as usize];
    assert!(!holds_canary(&read, &canary));
    read[GRANULE as usize - CANARY_BLOCK..]
        .copy_from_slice(&canary[GRANULE as usize - CANARY_BLOCK..]);
    assert!(
        holds_canary(&read, &canary),
        "the last block alone is a survivor"
    );
    read[GRANULE as usize - 1] ^= 1;
    assert!(
        !holds_canary(&read, &canary),
        "a block with any byte changed is not"
    );
}

#[test]
fn a_discard_that_changes_nothing_leaves_every_canary_and_everything_is_written() {
    let scratch = tempfile::tempdir().unwrap();
    let secret = marker("secret");
    let disk = thin_disk(scratch.path(), 16 * MIB, MIB, &SPANS, &secret);

    let report = wipe_spans(&disk, &SPANS, |_: &File, _, _| Ok(Discard::Issued)).unwrap();

    assert_eq!(
        count(&whole(&disk), secret.as_bytes()),
        0,
        "old data survived"
    );
    assert!(report.discard_supported);
    assert_eq!((report.discarded_ranges, report.fallback_ranges), (0, 2));
    assert_eq!(report.written_bytes, report.bytes);
}

#[test]
fn a_disk_without_discard_is_cleared_by_writing_alone() {
    let scratch = tempfile::tempdir().unwrap();
    let secret = marker("secret");
    let disk = thin_disk(scratch.path(), 16 * MIB, MIB, &SPANS, &secret);
    let mut calls = 0;

    let report = wipe_spans(&disk, &SPANS, |_: &File, _, _| {
        calls += 1;
        Ok(Discard::Unsupported)
    })
    .unwrap();

    assert_eq!(calls, 1, "a refused discard is not tried again");
    assert_eq!(
        count(&whole(&disk), secret.as_bytes()),
        0,
        "old data survived"
    );
    assert!(!report.discard_supported);
    assert_eq!((report.discarded_ranges, report.fallback_ranges), (0, 0));
    assert_eq!(report.written_bytes, report.bytes);
}

#[test]
fn a_failing_discard_fails_the_wipe() {
    let scratch = tempfile::tempdir().unwrap();
    let disk = thin_disk(scratch.path(), 16 * MIB, MIB, &SPANS, &marker("secret"));

    let error = wipe_spans(&disk, &SPANS, |_: &File, _, _| {
        Err(io::Error::from_raw_os_error(libc::EIO))
    })
    .unwrap_err();

    assert!(matches!(error, Error::Io(_)), "{error}");
}

/// Needs a loop device the operator made and handed over, for example
/// `sudo losetup --find --show BACKING` then `sudo chown "$USER"` of the
/// device, named by `CODEWIRE_EXT4_SCRUB_LOOP_DEVICE`. The device is
/// reformatted.
#[tokio::test]
#[ignore = "needs a loop device named by CODEWIRE_EXT4_SCRUB_LOOP_DEVICE"]
async fn freed_copies_of_a_token_are_discarded_from_a_loop_device() {
    let device = PathBuf::from(
        std::env::var_os("CODEWIRE_EXT4_SCRUB_LOOP_DEVICE")
            .expect("CODEWIRE_EXT4_SCRUB_LOOP_DEVICE names the loop device"),
    );
    let scratch = tempfile::tempdir().unwrap();
    format(&device);
    let (token, control) = (marker("token"), marker("control"));
    plant_freed_token(&device, scratch.path(), &token, &control);

    let report = wipe_unreadable_blocks(&SystemTools, &device).await.unwrap();

    assert_cleared(&device, &token, &control);
    assert!(report.discard_supported, "a loop device takes discards");
    assert!(report.discarded_ranges > 0, "{report:?}");
    assert_eq!(report.fallback_ranges, 0, "{report:?}");
    eprintln!("{report:?}");
}
