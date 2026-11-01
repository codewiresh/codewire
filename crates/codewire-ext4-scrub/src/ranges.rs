//! The ranges e2fsprogs report: free blocks and used inodes from `dumpe2fs`,
//! and each file's unreadable blocks from `debugfs stat`.

use std::io;
use std::path::Path;
use std::process::Stdio;

use super::{Error, MAXIMUM_TOOL_OUTPUT_BYTES, TOOL_TIMEOUT, Tools, program, require_quiet};

/// ext4's inode flag for an fs-verity file (`EXT4_VERITY_FL`).
const EXT4_VERITY_FL: u64 = 0x0010_0000;
/// ext4 places a verity file's metadata at its size rounded up to this.
const VERITY_METADATA_ALIGNMENT: u64 = 64 * 1024;

/// The free block ranges `dumpe2fs` reports, merged where adjacent:
/// every group must report its free blocks, and every range must lie in
/// the filesystem.
pub(crate) fn free_ranges(output: &[u8]) -> Result<Vec<(u64, u64)>, Error> {
    let unreadable = || Error::Unreadable("dumpe2fs");
    let text = std::str::from_utf8(output).map_err(|_| unreadable())?;
    let mut block_count = None;
    let mut groups = 0_u64;
    let mut reports = 0_u64;
    let mut ranges = Vec::new();
    for line in text.lines() {
        if let Some(count) = line.strip_prefix("Block count:") {
            block_count = Some(count.trim().parse::<u64>().map_err(|_| unreadable())?);
        } else if line.starts_with("Group ") && line.contains(": (Blocks ") {
            groups += 1;
        } else if let Some(list) = line.strip_prefix("  Free blocks:") {
            reports += 1;
            for item in list
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let (first, last) = match item.split_once('-') {
                    Some((first, last)) => (first, last),
                    None => (item, item),
                };
                let first = first.parse::<u64>().map_err(|_| unreadable())?;
                let last = last.parse::<u64>().map_err(|_| unreadable())?;
                if last < first {
                    return Err(unreadable());
                }
                ranges.push((first, last));
            }
        }
    }
    let block_count = block_count.ok_or_else(unreadable)?;
    if groups == 0 || groups != reports || ranges.iter().any(|(_, last)| *last >= block_count) {
        return Err(unreadable());
    }
    Ok(merge_ranges(ranges))
}

pub(crate) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (first, last) in ranges {
        match merged.last_mut() {
            Some(previous) if first <= previous.1.saturating_add(1) => {
                previous.1 = previous.1.max(last);
            }
            _ => merged.push((first, last)),
        }
    }
    merged
}

pub(crate) fn block_count(output: &[u8]) -> Result<u64, Error> {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.strip_prefix("Block count:"))
        .and_then(|count| count.trim().parse().ok())
        .ok_or(Error::Unreadable("dumpe2fs"))
}

/// The filesystem's block size, one of ext4's: 1, 2, 4 or 64 KiB.
pub(crate) fn block_size(output: &[u8]) -> Result<u64, Error> {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.strip_prefix("Block size:"))
        .and_then(|size| size.trim().parse().ok())
        .filter(|size| matches!(size, 1024 | 2048 | 4096 | 65536))
        .ok_or(Error::Unreadable("dumpe2fs"))
}

/// Every inode `dumpe2fs` reports in use from the first ordinary one:
/// each group's inodes but its free ones.
pub(crate) fn used_inodes(output: &[u8]) -> Result<Vec<u64>, Error> {
    let unreadable = || Error::Unreadable("dumpe2fs");
    let text = std::str::from_utf8(output).map_err(|_| unreadable())?;
    let header = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    let per_group = header("Inodes per group:")
        .filter(|count| *count > 0)
        .ok_or_else(unreadable)?;
    let first = header("First inode:").ok_or_else(unreadable)?;
    let count = header("Inode count:").ok_or_else(unreadable)?;
    let mut group = None;
    let mut used = Vec::new();
    let mut reports = 0_u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Group ")
            && line.contains(": (Blocks ")
        {
            group = Some(
                rest.split(':')
                    .next()
                    .and_then(|number| number.trim().parse::<u64>().ok())
                    .ok_or_else(unreadable)?,
            );
        } else if let Some(list) = line.strip_prefix("  Free inodes:") {
            let group = group.take().ok_or_else(unreadable)?;
            reports += 1;
            let start = group * per_group + 1;
            let end = start + per_group - 1;
            let mut free = Vec::new();
            for item in list
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let (low, high) = item.split_once('-').unwrap_or((item, item));
                let low = low.parse::<u64>().map_err(|_| unreadable())?;
                let high = high.parse::<u64>().map_err(|_| unreadable())?;
                if high < low || low < start || high > end {
                    return Err(unreadable());
                }
                free.push((low, high));
            }
            free.sort_unstable();
            let mut next = start;
            for (low, high) in free.into_iter().chain([(end + 1, end + 1)]) {
                used.extend((next..low).filter(|inode| *inode >= first));
                next = next.max(high + 1);
            }
        }
    }
    if reports == 0 || reports * per_group != count {
        return Err(unreadable());
    }
    Ok(used)
}

/// The physical blocks of every regular file in `inodes` that the guest
/// cannot read: unwritten extents and blocks past the file's end, from
/// one debugfs session that stats each inode.
pub(crate) async fn unreadable_file_blocks(
    tools: &impl Tools,
    disk: &Path,
    inodes: &[u64],
    block_size: u64,
) -> Result<Vec<(u64, u64)>, Error> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

    if inodes.is_empty() {
        return Ok(Vec::new());
    }
    let program = program(tools, "debugfs")?;
    let mut command = tools
        .command(&program, &[], disk)
        .map_err(|error| Error::Confinement("debugfs", error))?;
    let mut child = command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .env("DEBUGFS_PAGER", "__none__")
        .env("SS_READLINE_PATH", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::Confinement("debugfs", error))?;
    let mut stdin = child.stdin.take().ok_or(Error::Unreadable("debugfs"))?;
    let stdout = child.stdout.take().ok_or(Error::Unreadable("debugfs"))?;
    let mut stderr = child.stderr.take().ok_or(Error::Unreadable("debugfs"))?;
    let mut commands = String::with_capacity(inodes.len() * 16);
    for inode in inodes {
        commands.push_str(&format!("stat <{inode}>\n"));
    }
    let run = async {
        let write = async {
            stdin.write_all(commands.as_bytes()).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, io::Error>(())
        };
        let read = async {
            let mut parser = InodeBlocks::new(block_size);
            let requested = inodes;
            let mut lines = tokio::io::BufReader::new(stdout);
            let mut line = Vec::new();
            loop {
                line.clear();
                if lines.read_until(b'\n', &mut line).await? == 0 {
                    break;
                }
                parser.line(&String::from_utf8_lossy(&line));
            }
            Ok::<_, io::Error>(parser.finish(requested))
        };
        let errors = async {
            let mut errors = Vec::new();
            (&mut stderr)
                .take(MAXIMUM_TOOL_OUTPUT_BYTES as u64 + 1)
                .read_to_end(&mut errors)
                .await?;
            Ok::<_, io::Error>(errors)
        };
        let (written, ranges, errors) = tokio::join!(write, read, errors);
        written?;
        let status = child.wait().await?;
        Ok::<_, io::Error>((status.code(), ranges?, errors?))
    };
    let (code, ranges, errors) = tokio::time::timeout(TOOL_TIMEOUT, run)
        .await
        .map_err(|_| Error::Timeout("debugfs"))??;
    if code != Some(0) {
        return Err(Error::Failed("debugfs", code));
    }
    require_quiet("debugfs", &errors)?;
    ranges
}

/// One extent of a file, as `debugfs stat` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileExtent {
    pub logical: u64,
    pub physical: u64,
    pub length: u64,
    pub unwritten: bool,
}

/// Reads `debugfs stat` records and keeps, of each regular file, the
/// physical blocks the guest cannot read. A file's map is either
/// `EXTENTS:` or, for a file mapped by indirect blocks, `BLOCKS:`.
struct InodeBlocks {
    block_size: u64,
    regular: bool,
    /// `EXT4_VERITY_FL`: the file's Merkle tree lives past its end.
    verity: bool,
    size: Option<u64>,
    extents: Vec<FileExtent>,
    in_map: bool,
    ranges: Vec<(u64, u64)>,
    /// Every record's inode, in order.
    seen: Vec<u64>,
    malformed: bool,
}

impl InodeBlocks {
    fn new(block_size: u64) -> Self {
        Self {
            block_size,
            regular: false,
            verity: false,
            size: None,
            extents: Vec::new(),
            in_map: false,
            ranges: Vec::new(),
            seen: Vec::new(),
            malformed: false,
        }
    }

    fn line(&mut self, line: &str) {
        let mut line = line.trim_end();
        while let Some(rest) = line.strip_prefix("debugfs:") {
            line = rest.trim_start();
        }
        if let Some(rest) = line.strip_prefix("Inode: ") {
            self.end_record();
            match rest
                .split_whitespace()
                .next()
                .and_then(|inode| inode.parse::<u64>().ok())
            {
                Some(inode) => self.seen.push(inode),
                None => self.malformed = true,
            }
            self.regular = rest
                .split_whitespace()
                .skip_while(|word| *word != "Type:")
                .nth(1)
                == Some("regular");
            match rest
                .split_whitespace()
                .skip_while(|word| *word != "Flags:")
                .nth(1)
                .and_then(|flags| flags.strip_prefix("0x"))
                .and_then(|flags| u64::from_str_radix(flags, 16).ok())
            {
                Some(flags) => self.verity = flags & EXT4_VERITY_FL != 0,
                None => self.malformed = true,
            }
            return;
        }
        if line.starts_with("User:") {
            self.size = line
                .rsplit_once("Size:")
                .and_then(|(_, size)| size.trim().parse().ok());
            if self.size.is_none() {
                self.malformed = true;
            }
            return;
        }
        if line == "EXTENTS:" || line == "BLOCKS:" {
            self.in_map = true;
            return;
        }
        if self.in_map {
            if !line.starts_with('(') {
                self.in_map = false;
                return;
            }
            for entry in line
                .split(", ")
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
            {
                match parse_extent(entry) {
                    Some(Some(extent)) => self.extents.push(extent),
                    Some(None) => {}
                    None => self.malformed = true,
                }
            }
        }
    }

    fn end_record(&mut self) {
        if self.regular && self.size.is_none() {
            // A regular file's record always says its size.
            self.malformed = true;
        }
        if self.regular
            && let Some(size) = self.size
        {
            let end = size.div_ceil(self.block_size);
            // A verity file's Merkle tree and descriptor start at its
            // size rounded up to 64 KiB (`ext4_verity_metadata_pos`), and
            // the kernel reads them to verify every page, so they stay.
            let kept = if self.verity {
                size.next_multiple_of(VERITY_METADATA_ALIGNMENT) / self.block_size
            } else {
                u64::MAX
            };
            for extent in &self.extents {
                let next = extent.logical + extent.length;
                // An unwritten extent reads as zeros wherever it lies.
                if extent.unwritten {
                    self.ranges
                        .push((extent.physical, extent.physical + extent.length - 1));
                    continue;
                }
                let first = extent.logical.max(end);
                let after = next.min(kept);
                if first < after {
                    self.ranges.push((
                        extent.physical + (first - extent.logical),
                        extent.physical + (after - extent.logical) - 1,
                    ));
                }
            }
        }
        self.regular = false;
        self.verity = false;
        self.size = None;
        self.extents.clear();
        self.in_map = false;
    }

    /// The ranges, once exactly one record was read for each of
    /// `requested`, in order.
    fn finish(mut self, requested: &[u64]) -> Result<Vec<(u64, u64)>, Error> {
        self.end_record();
        if self.malformed || self.seen != requested {
            return Err(Error::Unreadable("debugfs"));
        }
        Ok(self.ranges)
    }
}

/// One `stat` map entry: `(L[-L2][[u]]):P[-P2]`. `Some(None)` for a
/// mapping block, an extent index (`(ETBn):P`) or an indirect block
/// (`(IND):P`, `(DIND):P`, `(TIND):P`), `None` for anything unreadable.
pub fn parse_extent(entry: &str) -> Option<Option<FileExtent>> {
    let (logical, physical) = entry.strip_prefix('(')?.split_once("):")?;
    if logical.starts_with("ETB") || matches!(logical, "IND" | "DIND" | "TIND") {
        physical.parse::<u64>().ok()?;
        return Some(None);
    }
    let (logical, unwritten) = match logical.strip_suffix("[u]") {
        Some(logical) => (logical, true),
        None => (logical, false),
    };
    let range = |text: &str| -> Option<(u64, u64)> {
        let (first, last) = text.split_once('-').unwrap_or((text, text));
        let (first, last) = (first.parse::<u64>().ok()?, last.parse::<u64>().ok()?);
        (last >= first).then_some((first, last))
    };
    let (logical_first, logical_last) = range(logical)?;
    let (physical_first, physical_last) = range(physical)?;
    if logical_last - logical_first != physical_last - physical_first {
        return None;
    }
    Some(Some(FileExtent {
        logical: logical_first,
        physical: physical_first,
        length: logical_last - logical_first + 1,
        unwritten,
    }))
}

#[cfg(test)]
mod tests;
