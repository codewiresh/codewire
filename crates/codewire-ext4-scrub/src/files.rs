//! Reading and removing files of an ext4 disk that nothing has mounted,
//! through debugfs, so clearing a disk never needs to mount it (#4013).
//!
//! Every path is looked up one component at a time in its parent's own
//! listing, so a symbolic link is never followed and an absent path is never
//! inferred from an error. Every removal is proven by a listing taken after
//! it.
//!
//! Every path is passed to debugfs quoted, so a name may hold spaces and any
//! printable UTF-8. A name holding `"`, `\`, a control character or bytes that
//! are not UTF-8 can't be passed back, so a tree holding one fails its removal,
//! as does a tree of more than [`MAXIMUM_TREE_ENTRIES`] entries or a directory
//! whose listing exceeds the tool output bound. A clearing that fails keeps
//! nothing.

use std::fs::OpenOptions;
use std::io::{Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;

use super::{Error, Tools, debugfs, ranges, require_quiet, run_tool, run_tool_with_input};

/// The most entries one removed tree may hold.
const MAXIMUM_TREE_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    SymbolicLink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `None` for a name debugfs can't be handed back quoted, which no
    /// Codewire file has.
    pub name: Option<String>,
    pub kind: EntryKind,
    /// A regular file's size in bytes; 0 for anything else.
    pub size: u64,
}

/// What a directory path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Absent,
    /// A component is not a directory: what the first such one is.
    NotDirectory(EntryKind),
    Directory(Vec<Entry>),
}

/// `/a/b` for `["a", "b"]`.
pub fn absolute(components: &[&str]) -> String {
    format!("/{}", components.join("/"))
}

/// `path` as one quoted debugfs argument. Every name in it passed
/// [`nameable`] or is one of the caller's own.
fn quoted(path: &str) -> String {
    format!("\"{path}\"")
}

/// The block size `dumpe2fs -h` reports for `disk`.
pub async fn block_size(tools: &impl Tools, disk: &Path) -> Result<u64, Error> {
    let (code, output, errors) = run_tool(tools, "dumpe2fs", &["-h"], disk).await?;
    if code != Some(0) {
        return Err(Error::Failed("dumpe2fs", code));
    }
    require_quiet("dumpe2fs", &errors)?;
    ranges::block_size(&output)
}

/// The entries of the directory at `components` from the root.
pub async fn lookup_directory(
    tools: &impl Tools,
    disk: &Path,
    components: &[&str],
) -> Result<Lookup, Error> {
    let mut entries = list_directory(tools, disk, "/").await?;
    for (index, component) in components.iter().enumerate() {
        match entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some(*component))
        {
            None => return Ok(Lookup::Absent),
            Some(entry) if entry.kind != EntryKind::Directory => {
                return Ok(Lookup::NotDirectory(entry.kind));
            }
            Some(_) => {}
        }
        entries = list_directory(tools, disk, &absolute(&components[..=index])).await?;
    }
    Ok(Lookup::Directory(entries))
}

/// The contents of the regular file `name` in the directory at `directory`.
/// The caller has seen it in that directory's listing.
pub async fn read_file(
    tools: &impl Tools,
    disk: &Path,
    directory: &[&str],
    name: &str,
) -> Result<Vec<u8>, Error> {
    debugfs(
        tools,
        disk,
        false,
        &format!("cat {}", quoted(&format!("{}/{name}", absolute(directory)))),
    )
    .await
}

/// Remove the regular file `name` in the directory at `directory`, overwrite
/// every block it held with zeros, and prove it gone from its directory. The
/// blocks are recorded before the removal and zeroed after it: they include
/// the file's extent tree or indirect blocks, which the removal reads to free
/// its data. Nothing allocates in between. A non-empty file with no blocks
/// keeps its data in the inode, where zeros can't reach it, so it is refused.
pub async fn zero_and_remove(
    tools: &impl Tools,
    disk: &Path,
    directory: &[&str],
    name: &str,
    size: u64,
    block_size: u64,
) -> Result<(), Error> {
    let path = quoted(&format!("{}/{name}", absolute(directory)));
    let output = debugfs(tools, disk, false, &format!("blocks {path}")).await?;
    let text = String::from_utf8(output).map_err(|_| Error::Unreadable("debugfs"))?;
    let blocks = text
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Unreadable("debugfs"))?;
    if size > 0 && blocks.is_empty() {
        return Err(Error::DataNotInBlocks);
    }
    let mut image = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(disk)?;
    // A block device's length is where its end seeks to; its metadata says 0.
    let length = image.seek(SeekFrom::End(0))?;
    let offsets = blocks
        .iter()
        .map(|block| {
            block
                .checked_mul(block_size)
                .filter(|offset| offset.saturating_add(block_size) <= length)
                .ok_or(Error::Unreadable("debugfs"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    debugfs(tools, disk, true, &format!("rm {path}")).await?;
    let zeros = vec![0_u8; usize::try_from(block_size).map_err(|_| Error::Unreadable("debugfs"))?];
    for offset in offsets {
        image.write_all_at(&zeros, offset)?;
    }
    image.sync_all()?;
    drop(image);
    if let Lookup::Directory(remaining) = lookup_directory(tools, disk, directory).await?
        && remaining
            .iter()
            .any(|entry| entry.name.as_deref() == Some(name))
    {
        return Err(Error::NotRemoved);
    }
    Ok(())
}

/// Remove the tree at `components`, if present: every file first, then each
/// directory, deepest first, in one debugfs session. A symbolic link on the
/// way to it, or at it, is refused; a file at it is removed. Returns whether
/// anything was there.
pub async fn remove_tree(
    tools: &impl Tools,
    disk: &Path,
    components: &[&str],
) -> Result<bool, Error> {
    let (last, parent) = components.split_last().expect("a tree has a path");
    let at_tree = |lookup: &Lookup| match lookup {
        Lookup::Directory(entries) => entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some(*last))
            .map(|entry| entry.kind),
        Lookup::Absent | Lookup::NotDirectory(_) => None,
    };
    let lookup = lookup_directory(tools, disk, parent).await?;
    if lookup == Lookup::NotDirectory(EntryKind::SymbolicLink) {
        return Err(Error::SymbolicLink);
    }
    let path = absolute(components);
    let mut requests = Vec::new();
    match at_tree(&lookup) {
        None => return Ok(false),
        Some(EntryKind::SymbolicLink) => return Err(Error::SymbolicLink),
        Some(EntryKind::Directory) => {
            let mut directories = vec![path];
            let mut files = Vec::new();
            let mut index = 0;
            while index < directories.len() {
                let directory = directories[index].clone();
                index += 1;
                for entry in list_directory(tools, disk, &directory).await? {
                    let name = entry.name.ok_or(Error::Unreadable("debugfs"))?;
                    let path = format!("{directory}/{name}");
                    if entry.kind == EntryKind::Directory {
                        directories.push(path);
                    } else {
                        files.push(path);
                    }
                    if directories.len() + files.len() > MAXIMUM_TREE_ENTRIES {
                        return Err(Error::Unreadable("debugfs"));
                    }
                }
            }
            requests.extend(
                files
                    .into_iter()
                    .map(|file| format!("rm {}", quoted(&file))),
            );
            requests.extend(
                directories
                    .iter()
                    .rev()
                    .map(|directory| format!("rmdir {}", quoted(directory))),
            );
        }
        Some(_) => requests.push(format!("rm {}", quoted(&path))),
    }
    debugfs_session(tools, disk, &requests).await?;
    if at_tree(&lookup_directory(tools, disk, parent).await?).is_some() {
        return Err(Error::NotRemoved);
    }
    Ok(true)
}

/// Run `requests` in one writing debugfs session, read from its stdin; any
/// request that fails says so on stderr.
async fn debugfs_session(
    tools: &impl Tools,
    disk: &Path,
    requests: &[String],
) -> Result<(), Error> {
    let mut input = String::new();
    for request in requests {
        input.push_str(request);
        input.push('\n');
    }
    let (code, _, errors) = run_tool_with_input(
        tools,
        "debugfs",
        &["-w", "-f", "-"],
        disk,
        Some(input.as_bytes()),
    )
    .await?;
    if code != Some(0) {
        return Err(Error::Failed("debugfs", code));
    }
    require_quiet("debugfs", &errors)
}

/// A name debugfs takes back inside one quoted argument: any UTF-8 but `"`,
/// `\` and control characters, as every name Codewire writes is.
fn nameable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name
            .chars()
            .any(|character| matches!(character, '"' | '\\') || character.is_control())
}

/// `debugfs ls -p <directory>`, which must exist.
async fn list_directory(
    tools: &impl Tools,
    disk: &Path,
    directory: &str,
) -> Result<Vec<Entry>, Error> {
    let output = debugfs(tools, disk, false, &format!("ls -p {}", quoted(directory))).await?;
    Ok(parse_listing(&output))
}

/// `ls -p` lines: `/inode/mode/uid/gid/name/size/`. A name with a newline, a
/// slash or non-UTF-8 bytes breaks or bends its line; such a name is never
/// one of Codewire's, so its pieces are skipped, and an entry whose name
/// debugfs could not take back is kept nameless.
pub fn parse_listing(output: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    for line in output.split(|byte| *byte == b'\n') {
        let fields = line.split(|byte| *byte == b'/').collect::<Vec<_>>();
        let [empty, inode, mode, _uid, _gid, name, size, trailing] = fields.as_slice() else {
            continue;
        };
        let text = |bytes: &[u8]| std::str::from_utf8(bytes).ok().map(str::to_owned);
        let (Some(inode), Some(mode)) = (text(inode), text(mode)) else {
            continue;
        };
        let Ok(mode) = u32::from_str_radix(&mode, 8) else {
            continue;
        };
        if !empty.is_empty() || !trailing.is_empty() || inode.parse::<u64>().is_err() {
            continue;
        }
        let name = text(name);
        if matches!(name.as_deref(), Some("." | "..")) {
            continue;
        }
        let kind = match mode & 0o170_000 {
            0o100_000 => EntryKind::File,
            0o040_000 => EntryKind::Directory,
            0o120_000 => EntryKind::SymbolicLink,
            _ => EntryKind::Other,
        };
        entries.push(Entry {
            name: name.filter(|name| nameable(name)),
            kind,
            size: if kind == EntryKind::File {
                match text(size).and_then(|size| size.parse().ok()) {
                    Some(size) => size,
                    None => continue,
                }
            } else {
                0
            },
        });
    }
    entries
}

#[cfg(test)]
mod tests;
