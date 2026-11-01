//! Clearing every block of an ext4 disk its guest cannot read through the
//! filesystem: each free range of the block bitmaps, and in each regular file
//! every unwritten extent and every block past its end. A token an earlier
//! rewrite left in a freed block, even one since reallocated without being
//! written, is gone, and nothing the guest reads changes.
//!
//! The ranges come from e2fsprogs (`dumpe2fs`, `debugfs stat`), run through
//! the caller's [`Tools`]: a local snapshot runs the host's tools confined to
//! the disk alone (`codewire-local-vmm`), because they parse a filesystem a
//! guest wrote.

#![cfg(target_os = "linux")]

mod ranges;

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

pub use ranges::{FileExtent, parse_extent};

/// How long one e2fsprogs run may take.
const TOOL_TIMEOUT: Duration = Duration::from_secs(300);
/// The most a tool may write to stdout or stderr.
const MAXIMUM_TOOL_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// How many blocks of each cleared range are read back.
const SAMPLES: u64 = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("e2fsprogs' {0} is unavailable")]
    ToolUnavailable(&'static str),
    #[error("{0} could not run confined: {1}")]
    Confinement(&'static str, io::Error),
    #[error("{0} did not finish in time")]
    Timeout(&'static str),
    #[error("{0} failed (exit status {1:?})")]
    Failed(&'static str, Option<i32>),
    #[error("{0} reported an error")]
    Reported(&'static str),
    #[error("{0} reported something this cw cannot read")]
    Unreadable(&'static str),
    #[error("a block the guest cannot read still held data after it was cleared")]
    NotCleared,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// How e2fsprogs run on a disk.
pub trait Tools: Sync {
    /// The trusted path of the e2fsprogs program `name`, such as `debugfs`.
    fn program(&self, name: &'static str) -> Option<PathBuf>;

    /// `program leading_args... disk`, with any confinement applied. The
    /// caller sets the environment and standard streams.
    fn command(
        &self,
        program: &Path,
        leading_args: &[&str],
        disk: &Path,
    ) -> io::Result<tokio::process::Command>;
}

/// A settling `e2fsck -f -p`: 0 clean, 1 corrected.
pub async fn e2fsck(tools: &impl Tools, disk: &Path) -> Result<(), Error> {
    let (code, _, _) = run_tool(tools, "e2fsck", &["-f", "-p"], disk).await?;
    if !matches!(code, Some(0 | 1)) {
        return Err(Error::Failed("e2fsck", code));
    }
    Ok(())
}

/// `debugfs [-w] -R request disk`: its stdout, once it exited 0 and reported
/// nothing on stderr.
pub async fn debugfs(
    tools: &impl Tools,
    disk: &Path,
    write: bool,
    request: &str,
) -> Result<Vec<u8>, Error> {
    let mut arguments = Vec::new();
    if write {
        arguments.push("-w");
    }
    arguments.extend(["-R", request]);
    let (code, output, errors) = run_tool(tools, "debugfs", &arguments, disk).await?;
    if code != Some(0) {
        return Err(Error::Failed("debugfs", code));
    }
    // debugfs exits 0 after a failed request and says so only on stderr.
    require_quiet("debugfs", &errors)?;
    Ok(output)
}

/// Punch out of the image file `disk` every block the guest cannot read,
/// then read samples of each range back as zeros.
pub async fn punch_unreadable_blocks(
    tools: &impl Tools,
    disk: &Path,
    block_size: u64,
) -> Result<(), Error> {
    let ranges = unreadable_ranges(tools, disk, block_size).await?;
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(disk)?;
    let length = image.metadata()?.len();
    for &(first, last) in &ranges {
        let offset = first
            .checked_mul(block_size)
            .ok_or(Error::Unreadable("dumpe2fs"))?;
        let bytes = (last - first + 1)
            .checked_mul(block_size)
            .filter(|bytes| offset.saturating_add(*bytes) <= length)
            .ok_or(Error::Unreadable("dumpe2fs"))?;
        punch_hole(&image, offset, bytes)?;
    }
    image.sync_all()?;
    verify_samples(&image, &ranges, block_size)
}

/// Every block of `disk` the guest cannot read, as merged inclusive block
/// ranges: the free ranges `dumpe2fs` reports, and each used regular file's
/// unwritten extents and blocks past its end.
async fn unreadable_ranges(
    tools: &impl Tools,
    disk: &Path,
    block_size: u64,
) -> Result<Vec<(u64, u64)>, Error> {
    let (code, output, errors) = run_tool(tools, "dumpe2fs", &[], disk).await?;
    if code != Some(0) {
        return Err(Error::Failed("dumpe2fs", code));
    }
    require_quiet("dumpe2fs", &errors)?;
    let mut ranges = ranges::free_ranges(&output)?;
    let inodes = ranges::used_inodes(&output)?;
    let block_count = ranges::block_count(&output)?;
    let unreadable = ranges::unreadable_file_blocks(tools, disk, &inodes, block_size).await?;
    if unreadable.iter().any(|(_, last)| *last >= block_count) {
        return Err(Error::Unreadable("debugfs"));
    }
    ranges.extend(unreadable);
    Ok(ranges::merge_ranges(ranges))
}

/// Every block of a short range, and the first, middle and last of a longer
/// one, read back as zeros.
fn verify_samples(image: &File, ranges: &[(u64, u64)], block_size: u64) -> Result<(), Error> {
    let mut sample = vec![0_u8; usize::try_from(block_size).map_err(|_| Error::NotCleared)?];
    for &(first, last) in ranges {
        let samples = if last - first < SAMPLES {
            (first..=last).collect::<Vec<_>>()
        } else {
            vec![first, first + (last - first) / 2, last]
        };
        for block in samples {
            image.read_exact_at(&mut sample, block * block_size)?;
            if sample.iter().any(|byte| *byte != 0) {
                return Err(Error::NotCleared);
            }
        }
    }
    Ok(())
}

fn punch_hole(image: &File, offset: u64, bytes: u64) -> io::Result<()> {
    let (Ok(offset), Ok(bytes)) = (libc::off_t::try_from(offset), libc::off_t::try_from(bytes))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range too large",
        ));
    };
    // SAFETY: a plain fallocate on a live descriptor.
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

fn program(tools: &impl Tools, name: &'static str) -> Result<PathBuf, Error> {
    tools.program(name).ok_or(Error::ToolUnavailable(name))
}

/// Nothing on a tool's stderr but its version banner.
fn require_quiet(label: &'static str, errors: &[u8]) -> Result<(), Error> {
    let text = String::from_utf8_lossy(errors);
    let banner = |line: &str| line.starts_with(&format!("{label} ")) && line.ends_with(')');
    if text
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !banner(line))
    {
        return Err(Error::Reported(label));
    }
    Ok(())
}

/// Run the e2fsprogs tool `name` on `disk` through `tools`: its exit status,
/// stdout and stderr.
async fn run_tool(
    tools: &impl Tools,
    name: &'static str,
    arguments: &[&str],
    disk: &Path,
) -> Result<(Option<i32>, Vec<u8>, Vec<u8>), Error> {
    use tokio::io::AsyncReadExt as _;

    let program = program(tools, name)?;
    let mut command = tools
        .command(&program, arguments, disk)
        .map_err(|error| Error::Confinement(name, error))?;
    let mut child = command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .env("DEBUGFS_PAGER", "__none__")
        .env("E2FSCK_CONFIG", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::Confinement(name, error))?;
    let mut stdout = child.stdout.take().ok_or(Error::Unreadable(name))?;
    let mut stderr = child.stderr.take().ok_or(Error::Unreadable(name))?;
    let run = async {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let limit = MAXIMUM_TOOL_OUTPUT_BYTES as u64 + 1;
        let mut stdout = (&mut stdout).take(limit);
        let mut stderr = (&mut stderr).take(limit);
        let (out, err) = tokio::join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors),
        );
        out?;
        err?;
        let status = child.wait().await?;
        Ok::<_, io::Error>((status.code(), output, errors))
    };
    let (code, output, errors) = tokio::time::timeout(TOOL_TIMEOUT, run)
        .await
        .map_err(|_| Error::Timeout(name))??;
    if output.len() > MAXIMUM_TOOL_OUTPUT_BYTES || errors.len() > MAXIMUM_TOOL_OUTPUT_BYTES {
        return Err(Error::Unreadable(name));
    }
    Ok((code, output, errors))
}
