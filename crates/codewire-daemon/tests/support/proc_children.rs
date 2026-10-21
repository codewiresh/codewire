//! Direct children of a process for tests, on any Linux kernel. Test modules
//! in several crates include this file with `#[path]`, so it uses only `std`.
//!
//! Each process's `/proc/<pid>/stat` names its parent, so the scan reads
//! those. The task `children` lists need `CONFIG_PROC_CHILDREN`, which the
//! CI's Kata guest kernel does not have.

use std::collections::BTreeSet;
use std::io;

/// ESRCH on Linux: the process exited between opening and reading its stat.
const ESRCH: i32 = 3;

/// Live and zombie direct children of `parent`. A process that exits during
/// the scan is skipped. `comm` may hold spaces and parentheses, so the parent
/// pid is the second field after the last `)`.
pub(crate) fn child_pids(parent: u32) -> io::Result<BTreeSet<u32>> {
    let mut children = BTreeSet::new();
    for entry in std::fs::read_dir("/proc")? {
        let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(ESRCH) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        // An empty read is also a process that exited during the scan.
        let Some(close) = stat.iter().rposition(|byte| *byte == b')') else {
            continue;
        };
        let ppid = std::str::from_utf8(&stat[close + 1..])
            .ok()
            .and_then(|fields| fields.split_ascii_whitespace().nth(1))
            .and_then(|field| field.parse::<u32>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc stat"))?;
        if ppid == parent {
            children.insert(pid);
        }
    }
    Ok(children)
}
