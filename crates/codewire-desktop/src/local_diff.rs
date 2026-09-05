//! Local git diff discovery via std::process::Command
//!
//! Provides DiffSource and local git diff discovery using std::process::Command.

use codewire_types::{FileDiff, parse_name_status, parse_numstat, parse_unified_diff};
use std::process::Command;

/// Source of diff data.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DiffSource {
    /// Local git repository on disk
    Local { path: String },
}

impl DiffSource {
    /// Unique key for tab deduplication and entity caching
    pub fn source_id(&self) -> String {
        match self {
            DiffSource::Local { path } => format!("local:{}", path),
        }
    }

    /// Display name for tab title
    pub fn display_name(&self) -> String {
        match self {
            DiffSource::Local { path } => {
                // Use last path component as display name
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path)
                    .to_string()
            }
        }
    }
}

/// Result of local diff discovery
pub struct LocalDiffResult {
    pub files: Vec<FileDiff>,
}

/// Run a git command in the given directory, returning stdout as a String.
fn git_command(repo_path: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", args.join(" "), stderr.trim()));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8: {}", e))
}

/// Discover diffs for a local git repository against the primary branch merge-base.
///
/// Runs the local discovery sequence using `std::process::Command`.
pub fn discover_local_diff(path: &str) -> Result<LocalDiffResult, String> {
    // 1. Verify git repo and find root
    let repo_root = git_command(path, &["rev-parse", "--show-toplevel"])?;
    let repo_root = repo_root.trim();

    // 2. Detect primary branch
    let primary_ref =
        git_command(repo_root, &["symbolic-ref", "refs/remotes/origin/HEAD"]).unwrap_or_default();
    let primary = primary_ref
        .trim()
        .strip_prefix("refs/remotes/origin/")
        .unwrap_or("main")
        .to_string();

    // 3. Find merge-base
    let merge_base_output = git_command(
        repo_root,
        &["merge-base", "HEAD", &format!("origin/{}", primary)],
    )?;
    let base = merge_base_output.trim();
    if base.is_empty() {
        return Err("No merge-base found".into());
    }

    // 4. Run unified diff
    let diff_output = git_command(repo_root, &["diff", "-M", base]).unwrap_or_default();

    // 5. Run numstat
    let numstat_output =
        git_command(repo_root, &["diff", "-M", "--numstat", base]).unwrap_or_default();

    // 6. Run name-status
    let namestatus_output =
        git_command(repo_root, &["diff", "-M", "--name-status", base]).unwrap_or_default();

    // Parse and merge the local discovery results.
    let mut files = parse_unified_diff(diff_output.trim());
    let numstats = parse_numstat(numstat_output.trim());
    let name_statuses = parse_name_status(namestatus_output.trim());

    // Merge numstat data
    for (path, adds, dels) in &numstats {
        if let Some(file) = files.iter_mut().find(|f| &f.file_path == path) {
            file.additions = *adds;
            file.deletions = *dels;
        }
    }

    // Merge name-status data for files not in unified diff (binary files, etc.)
    for (ns_path, change_type) in &name_statuses {
        if !files.iter().any(|f| &f.file_path == ns_path) {
            let (adds, dels) = numstats
                .iter()
                .find(|(p, _, _)| p == ns_path)
                .map(|(_, a, d)| (*a, *d))
                .unwrap_or((0, 0));
            files.push(FileDiff {
                file_path: ns_path.to_string(),
                old_path: None,
                change_type: *change_type,
                is_binary: adds == 0 && dels == 0,
                additions: adds,
                deletions: dels,
                hunks: Vec::new(),
            });
        }
    }

    Ok(LocalDiffResult { files })
}

/// Discover uncommitted changes (working directory diff, no base commit).
pub fn discover_local_diff_uncommitted(path: &str) -> Result<LocalDiffResult, String> {
    // 1. Verify git repo
    let repo_root = git_command(path, &["rev-parse", "--show-toplevel"])?;
    let repo_root = repo_root.trim();

    // 2. Run diff against HEAD (uncommitted changes)
    let diff_output = git_command(repo_root, &["diff", "-M", "HEAD"]).unwrap_or_default();
    let numstat_output =
        git_command(repo_root, &["diff", "-M", "--numstat", "HEAD"]).unwrap_or_default();
    let namestatus_output =
        git_command(repo_root, &["diff", "-M", "--name-status", "HEAD"]).unwrap_or_default();

    let mut files = parse_unified_diff(diff_output.trim());
    let numstats = parse_numstat(numstat_output.trim());
    let name_statuses = parse_name_status(namestatus_output.trim());

    for (path, adds, dels) in &numstats {
        if let Some(file) = files.iter_mut().find(|f| &f.file_path == path) {
            file.additions = *adds;
            file.deletions = *dels;
        }
    }

    for (ns_path, change_type) in &name_statuses {
        if !files.iter().any(|f| &f.file_path == ns_path) {
            let (adds, dels) = numstats
                .iter()
                .find(|(p, _, _)| p == ns_path)
                .map(|(_, a, d)| (*a, *d))
                .unwrap_or((0, 0));
            files.push(FileDiff {
                file_path: ns_path.to_string(),
                old_path: None,
                change_type: *change_type,
                is_binary: adds == 0 && dels == 0,
                additions: adds,
                deletions: dels,
                hunks: Vec::new(),
            });
        }
    }

    Ok(LocalDiffResult { files })
}

#[cfg(test)]
mod tests {
    use super::DiffSource;

    #[test]
    fn retired_ssh_diff_source_is_rejected() {
        let retired = r#"{"Ssh":{"workspace_name":"old","ssh_host":"example.invalid"}}"#;
        assert!(serde_json::from_str::<DiffSource>(retired).is_err());
    }
}
