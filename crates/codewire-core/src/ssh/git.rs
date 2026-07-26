//! Git repository discovery and status via SSH

use crate::CoreError;
use crate::platform::SshSession;
use crate::types::GitStatus;
use codewire_types::{FileDiff, PullRequest};

// Re-export pure parsers from codewire-types
pub use codewire_types::parse_git_status;
pub use codewire_types::{parse_name_status, parse_numstat, parse_pr_json, parse_unified_diff};

/// Git status discovery script
const GIT_STATUS_SCRIPT: &str = r#"
REPO_ROOT=""
if [ -d "$HOME/.git" ]; then
  REPO_ROOT="$HOME"
else
  REPO_ROOT=$(find "$HOME" -maxdepth 2 -name ".git" -type d 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
fi

[ -z "$REPO_ROOT" ] && exit 1
cd "$REPO_ROOT" || exit 1

PRIMARY=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@')
[ -z "$PRIMARY" ] && PRIMARY="main"

AB=$(git rev-list --left-right --count HEAD...origin/$PRIMARY 2>/dev/null || echo "0 0")

DIRTY=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')

BASE=$(git merge-base HEAD origin/$PRIMARY 2>/dev/null || echo "")
if [ -n "$BASE" ]; then
  STATS=$(git diff --numstat $BASE 2>/dev/null | awk '{a+=$1;d+=$2}END{print a+0,d+0}')
else
  STATS="0 0"
fi

echo "REPO:$REPO_ROOT"
echo "AB:$AB"
echo "DIRTY:$DIRTY"
echo "LINES:$STATS"
"#;

/// Git discovery service for remote workspaces
pub struct GitDiscovery;

impl GitDiscovery {
    pub fn new() -> Self {
        Self
    }

    /// Discover git status from workspace home directory.
    /// Returns `None` if no git repository is found.
    pub async fn discover<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Option<GitStatus>, CoreError> {
        let output = connection.exec(GIT_STATUS_SCRIPT).await?;

        if output.trim().is_empty() {
            return Ok(None);
        }

        Ok(parse_git_status(&output))
    }
}

impl Default for GitDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PR Discovery
// ============================================================================

/// PR discovery script: check for gh CLI, then fetch PR info for current branch
const PR_DISCOVERY_SCRIPT: &str = r#"
command -v gh >/dev/null 2>&1 || { echo '{"no_pr":true}'; exit 0; }

REPO_ROOT=""
if [ -d "$HOME/.git" ]; then
  REPO_ROOT="$HOME"
else
  REPO_ROOT=$(find "$HOME" -maxdepth 2 -name ".git" -type d 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
fi

[ -z "$REPO_ROOT" ] && { echo '{"no_pr":true}'; exit 0; }
cd "$REPO_ROOT" || { echo '{"no_pr":true}'; exit 0; }

gh pr view --json number,url,state,mergeable,mergeStateStatus,title,isDraft,headRefName,baseRefName,statusCheckRollup 2>/dev/null || echo '{"no_pr":true}'
"#;

/// Pull request discovery for remote workspaces
pub struct PrDiscovery;

impl PrDiscovery {
    pub fn new() -> Self {
        Self
    }

    /// Discover PR for the current branch.
    /// Returns `None` if no PR exists or gh CLI is not available.
    pub async fn discover<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Option<PullRequest>, CoreError> {
        let output = connection.exec(PR_DISCOVERY_SCRIPT).await?;

        if output.trim().is_empty() {
            return Ok(None);
        }

        Ok(parse_pr_json(output.trim()))
    }
}

impl Default for PrDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Diff Discovery
// ============================================================================

/// Diff discovery script: find repo, detect primary branch, run diff commands with markers
const DIFF_DISCOVERY_SCRIPT: &str = r#"
REPO_ROOT=""
if [ -d "$HOME/.git" ]; then
  REPO_ROOT="$HOME"
else
  REPO_ROOT=$(find "$HOME" -maxdepth 2 -name ".git" -type d 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
fi

[ -z "$REPO_ROOT" ] && exit 1
cd "$REPO_ROOT" || exit 1

PRIMARY=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@')
[ -z "$PRIMARY" ] && PRIMARY="main"

BASE=$(git merge-base HEAD origin/$PRIMARY 2>/dev/null || echo "")
[ -z "$BASE" ] && exit 1

echo "___DIFF_START___"
git diff -M $BASE 2>/dev/null

echo "___NUMSTAT_START___"
git diff -M --numstat $BASE 2>/dev/null

echo "___NAMESTATUS_START___"
git diff -M --name-status $BASE 2>/dev/null
"#;

/// Unified diff discovery for remote workspaces
pub struct DiffDiscovery;

impl DiffDiscovery {
    pub fn new() -> Self {
        Self
    }

    /// Discover diff between current branch and primary branch.
    /// Returns an empty Vec if no repository or no changes found.
    pub async fn discover<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Vec<FileDiff>, CoreError> {
        let output = connection.exec(DIFF_DISCOVERY_SCRIPT).await?;

        if output.trim().is_empty() {
            return Ok(Vec::new());
        }

        // Split output by markers
        let diff_section = extract_section(&output, "___DIFF_START___", "___NUMSTAT_START___");
        let numstat_section =
            extract_section(&output, "___NUMSTAT_START___", "___NAMESTATUS_START___");
        let namestatus_section = extract_after(&output, "___NAMESTATUS_START___");

        // Parse unified diff for hunks
        let mut files = parse_unified_diff(diff_section.trim());

        // Parse numstat for accurate addition/deletion counts
        let numstats = parse_numstat(numstat_section.trim());

        // Parse name-status for accurate change types
        let name_statuses = parse_name_status(namestatus_section.trim());

        // Merge numstat data into file diffs
        for (path, adds, dels) in &numstats {
            if let Some(file) = files.iter_mut().find(|f| &f.file_path == path) {
                file.additions = *adds;
                file.deletions = *dels;
            }
        }

        // Merge name-status data for files that might not have hunks (binary files)
        for (path, change_type) in &name_statuses {
            if !files.iter().any(|f| &f.file_path == path) {
                // Binary or empty-diff file not in unified diff output
                let (adds, dels) = numstats
                    .iter()
                    .find(|(p, _, _)| p == path)
                    .map(|(_, a, d)| (*a, *d))
                    .unwrap_or((0, 0));
                files.push(FileDiff {
                    file_path: path.clone(),
                    old_path: None,
                    change_type: *change_type,
                    is_binary: adds == 0 && dels == 0,
                    additions: adds,
                    deletions: dels,
                    hunks: Vec::new(),
                });
            }
        }

        Ok(files)
    }
}

impl Default for DiffDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_section<'a>(output: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = output
        .find(start_marker)
        .map(|i| i + start_marker.len())
        .unwrap_or(0);
    let end = output[start..]
        .find(end_marker)
        .unwrap_or(output.len() - start);
    &output[start..start + end]
}

fn extract_after<'a>(output: &'a str, marker: &str) -> &'a str {
    output
        .find(marker)
        .map(|i| &output[i + marker.len()..])
        .unwrap_or("")
}

// Tests for parsers are in codewire-types::parsers
