//! Clearing every block of an ext4 disk its guest cannot read through the
//! filesystem: each free range of the block bitmaps, and in each regular file
//! every unwritten extent and every block past its end. A token an earlier
//! rewrite left in a freed block, even one since reallocated without being
//! written, is gone, and nothing the guest reads changes.
//!
//! The ranges come from e2fsprogs (`dumpe2fs`, `debugfs stat`), run through
//! the caller's [`Tools`]: a local snapshot runs the host's tools confined to
//! the disk alone (`codewire-local-vmm`), because they parse a filesystem a
//! guest wrote; a hosted clearing Sandbox runs them as they are, inside a VM
//! that is itself the boundary ([`SystemTools`]).
//!
//! There are two backends. An image file has its ranges punched out
//! ([`punch_unreadable_blocks`]), on Linux and macOS; a block device, on
//! Linux, has them discarded, then overwritten wherever they still read as
//! data, then read back from the device ([`wipe_unreadable_blocks`]).
//!
//! Before either, a caller removes files through [`files`], with debugfs on
//! the unmounted disk.

#![cfg(any(target_os = "linux", target_os = "macos"))]

#[cfg(target_os = "linux")]
mod block;
pub mod files;
mod punch;
mod ranges;

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub use block::{WipeReport, wipe_unreadable_blocks};
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
    #[error("a removed file or tree was still present after its removal")]
    NotRemoved,
    #[error("a cleared path is a symbolic link")]
    SymbolicLink,
    #[error("a file's data is not in blocks clearing can overwrite")]
    DataNotInBlocks,
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

/// e2fsprogs as they are, for a disk inside a VM that is itself the boundary,
/// such as a hosted clearing Sandbox's. A tool is taken only from `/usr/sbin`,
/// `/sbin` or `/usr/bin`, never `PATH`, and only when only root can change it.
#[cfg(target_os = "linux")]
pub struct SystemTools;

#[cfg(target_os = "linux")]
impl Tools for SystemTools {
    fn program(&self, name: &'static str) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt as _;

        if !matches!(name, "e2fsck" | "debugfs" | "dumpe2fs") {
            return None;
        }
        let found = ["/usr/sbin", "/sbin", "/usr/bin"]
            .iter()
            .map(|directory| Path::new(directory).join(name))
            .find(|path| path.is_file())?;
        let real = std::fs::canonicalize(found).ok()?;
        real.ancestors()
            .all(|entry| {
                std::fs::symlink_metadata(entry)
                    .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
            })
            .then_some(real)
    }

    fn command(
        &self,
        program: &Path,
        leading_args: &[&str],
        disk: &Path,
    ) -> io::Result<tokio::process::Command> {
        let mut command = tokio::process::Command::new(program);
        command.kill_on_drop(true).args(leading_args).arg(disk);
        Ok(command)
    }
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
    let (reported, ranges) = unreadable_ranges(tools, disk).await?;
    if reported != block_size {
        return Err(Error::Unreadable("dumpe2fs"));
    }
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
        punch::punch_hole(&image, offset, bytes)?;
    }
    image.sync_all()?;
    verify_samples(&image, &ranges, block_size)
}

/// The block size `dumpe2fs` reports for `disk`, and every block the guest
/// cannot read, as merged inclusive block ranges: the free ranges, and each
/// used regular file's unwritten extents and blocks past its end.
async fn unreadable_ranges(
    tools: &impl Tools,
    disk: &Path,
) -> Result<(u64, Vec<(u64, u64)>), Error> {
    let (code, output, errors) = run_tool(tools, "dumpe2fs", &[], disk).await?;
    if code != Some(0) {
        return Err(Error::Failed("dumpe2fs", code));
    }
    require_quiet("dumpe2fs", &errors)?;
    let block_size = ranges::block_size(&output)?;
    let mut ranges = ranges::free_ranges(&output)?;
    let inodes = ranges::used_inodes(&output)?;
    let block_count = ranges::block_count(&output)?;
    let unreadable = ranges::unreadable_file_blocks(tools, disk, &inodes, block_size).await?;
    if unreadable.iter().any(|(_, last)| *last >= block_count) {
        return Err(Error::Unreadable("debugfs"));
    }
    ranges.extend(unreadable);
    Ok((block_size, ranges::merge_ranges(ranges)))
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

fn program(tools: &impl Tools, name: &'static str) -> Result<PathBuf, Error> {
    tools.program(name).ok_or(Error::ToolUnavailable(name))
}

/// `name arguments... disk` through `tools`, with the one environment every
/// e2fsprogs run here gets: none of the supervisor's, the C locale, no pager,
/// no e2fsck configuration and no readline. `TZ` is set and empty, which libc
/// takes as UTC without reading a zone file; a Mac's Seatbelt profile denies
/// and logs each such read, and `TZ=UTC0` still makes one on macOS 27. The
/// scrub reads no times. The caller sets the standard streams.
fn tool_command(
    tools: &impl Tools,
    name: &'static str,
    arguments: &[&str],
    disk: &Path,
) -> Result<tokio::process::Command, Error> {
    let program = program(tools, name)?;
    let mut command = tools
        .command(&program, arguments, disk)
        .map_err(|error| Error::Confinement(name, error))?;
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .env("DEBUGFS_PAGER", "__none__")
        .env("E2FSCK_CONFIG", "/dev/null")
        .env("SS_READLINE_PATH", "")
        .env("TZ", "");
    Ok(command)
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
    run_tool_with_input(tools, name, arguments, disk, None).await
}

/// [`run_tool`], writing `input` to the tool's stdin when there is one.
async fn run_tool_with_input(
    tools: &impl Tools,
    name: &'static str,
    arguments: &[&str],
    disk: &Path,
    input: Option<&[u8]>,
) -> Result<(Option<i32>, Vec<u8>, Vec<u8>), Error> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut child = tool_command(tools, name, arguments, disk)?
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::Confinement(name, error))?;
    let mut stdout = child.stdout.take().ok_or(Error::Unreadable(name))?;
    let mut stderr = child.stderr.take().ok_or(Error::Unreadable(name))?;
    let stdin = child.stdin.take();
    let run = async {
        let write = async {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                stdin.write_all(input).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, io::Error>(())
        };
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let limit = MAXIMUM_TOOL_OUTPUT_BYTES as u64 + 1;
        let mut stdout = (&mut stdout).take(limit);
        let mut stderr = (&mut stderr).take(limit);
        let (written, out, err) = tokio::join!(
            write,
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors),
        );
        written?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each tool is a shell that records the time zone and home directory it
    /// was given.
    struct Recorder(PathBuf);

    impl Tools for Recorder {
        fn program(&self, _name: &'static str) -> Option<PathBuf> {
            Some(PathBuf::from("/bin/sh"))
        }

        fn command(
            &self,
            program: &Path,
            _leading_args: &[&str],
            _disk: &Path,
        ) -> io::Result<tokio::process::Command> {
            let mut command = tokio::process::Command::new(program);
            command
                .arg("-c")
                .arg(r#"printf 'TZ=%s HOME=%s\n' "${TZ-unset}" "${HOME-unset}" > "$0""#)
                .arg(&self.0);
            Ok(command)
        }
    }

    /// The single-tool runs and the punch's inode read alike.
    #[tokio::test]
    async fn every_tool_run_gets_an_empty_time_zone_and_none_of_the_callers_environment() {
        let scratch = tempfile::tempdir().unwrap();
        let record = scratch.path().join("environment");
        let tools = Recorder(record.clone());
        let disk = scratch.path().join("disk.img");
        let given = || std::fs::read_to_string(&record).unwrap();
        assert!(std::env::var_os("HOME").is_some());
        e2fsck(&tools, &disk).await.unwrap();
        assert_eq!(given(), "TZ= HOME=unset\n");
        std::fs::remove_file(&record).unwrap();
        // The shell answers no stat, so the read fails after the run.
        assert!(
            ranges::unreadable_file_blocks(&tools, &disk, &[12], 4096)
                .await
                .is_err()
        );
        assert_eq!(given(), "TZ= HOME=unset\n");
    }
}
