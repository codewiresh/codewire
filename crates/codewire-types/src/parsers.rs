//! I/O-free parsers for local git status and diff output.
//!
//! These parse local git status and diff output.

use crate::types::{DiffHunk, DiffLine, DiffLineType, FileChangeType, FileDiff, GitStatus};

// ============================================================================
// Git status parsing
// ============================================================================

/// Parse git status script output into GitStatus struct
pub fn parse_git_status(output: &str) -> Option<GitStatus> {
    let mut ahead = 0u32;
    let mut behind = 0u32;
    let mut dirty = false;
    let mut additions = 0u32;
    let mut deletions = 0u32;
    let mut found_any = false;

    for line in output.lines() {
        let line = line.trim();

        if let Some(ab) = line.strip_prefix("AB:") {
            found_any = true;
            let parts: Vec<&str> = ab.split_whitespace().collect();
            if parts.len() >= 2 {
                ahead = parts[0].parse().unwrap_or(0);
                behind = parts[1].parse().unwrap_or(0);
            }
        } else if let Some(d) = line.strip_prefix("DIRTY:") {
            found_any = true;
            let count: u32 = d.trim().parse().unwrap_or(0);
            dirty = count > 0;
        } else if let Some(stats) = line.strip_prefix("LINES:") {
            found_any = true;
            let parts: Vec<&str> = stats.split_whitespace().collect();
            if parts.len() >= 2 {
                additions = parts[0].parse().unwrap_or(0);
                deletions = parts[1].parse().unwrap_or(0);
            }
        }
    }

    if found_any {
        Some(GitStatus {
            ahead,
            behind,
            dirty,
            additions,
            deletions,
        })
    } else {
        None
    }
}

// ============================================================================
// Unified diff parsing
// ============================================================================

/// Parse unified diff output (from `git diff -M`) into structured file diffs
pub fn parse_unified_diff(diff_output: &str) -> Vec<FileDiff> {
    let lines: Vec<&str> = diff_output.lines().collect();
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current_file: Option<FileDiff> = None;
    let mut current_hunk: Option<DiffHunk> = None;
    let mut old_line: u32 = 0;
    let mut new_line: u32 = 0;

    let finish_hunk = |file: &mut FileDiff, hunk: Option<DiffHunk>| {
        if let Some(h) = hunk
            && !h.lines.is_empty()
        {
            file.hunks.push(h);
        }
    };

    for line in &lines {
        // File header: diff --git a/... b/...
        if line.starts_with("diff --git ") {
            // Finish previous file
            if let Some(mut file) = current_file.take() {
                finish_hunk(&mut file, current_hunk.take());
                // Count additions/deletions from hunks
                let (adds, dels) = count_hunk_stats(&file.hunks);
                file.additions = adds;
                file.deletions = dels;
                files.push(file);
            }
            current_hunk = None;

            // Extract paths from "diff --git a/path b/path"
            if let Some(rest) = line.strip_prefix("diff --git a/")
                && let Some(b_pos) = rest.find(" b/")
            {
                let old_path = &rest[..b_pos];
                let new_path = &rest[b_pos + 3..];
                current_file = Some(FileDiff {
                    file_path: new_path.to_string(),
                    old_path: if old_path != new_path {
                        Some(old_path.to_string())
                    } else {
                        None
                    },
                    change_type: FileChangeType::Modified,
                    is_binary: false,
                    additions: 0,
                    deletions: 0,
                    hunks: Vec::new(),
                });
            }
            continue;
        }

        let file = match current_file.as_mut() {
            Some(f) => f,
            None => continue,
        };

        // Binary file marker
        if line.starts_with("Binary files ") {
            file.is_binary = true;
            continue;
        }

        // New file mode
        if line.starts_with("new file mode ") {
            file.change_type = FileChangeType::Added;
            continue;
        }

        // Deleted file mode
        if line.starts_with("deleted file mode ") {
            file.change_type = FileChangeType::Deleted;
            continue;
        }

        // Rename markers
        if line.starts_with("rename from ") || line.starts_with("rename to ") {
            file.change_type = FileChangeType::Renamed;
            continue;
        }

        // Hunk header: @@ -old_start,old_lines +new_start,new_lines @@
        if line.starts_with("@@") {
            finish_hunk(file, current_hunk.take());

            if let Some(parsed) = parse_hunk_header(line) {
                old_line = parsed.0;
                new_line = parsed.2;
                current_hunk = Some(DiffHunk {
                    header: line.to_string(),
                    old_start: parsed.0,
                    old_lines: parsed.1,
                    new_start: parsed.2,
                    new_lines: parsed.3,
                    lines: vec![DiffLine {
                        line_type: DiffLineType::Header,
                        content: line.to_string(),
                        old_line_number: None,
                        new_line_number: None,
                    }],
                });
            }
            continue;
        }

        // Hunk content
        if let Some(hunk) = current_hunk.as_mut() {
            if let Some(content) = line.strip_prefix('+') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Add,
                    content: content.to_string(),
                    old_line_number: None,
                    new_line_number: Some(new_line),
                });
                new_line += 1;
            } else if let Some(content) = line.strip_prefix('-') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Remove,
                    content: content.to_string(),
                    old_line_number: Some(old_line),
                    new_line_number: None,
                });
                old_line += 1;
            } else if let Some(content) = line.strip_prefix(' ') {
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Context,
                    content: content.to_string(),
                    old_line_number: Some(old_line),
                    new_line_number: Some(new_line),
                });
                old_line += 1;
                new_line += 1;
            } else if line.is_empty() {
                // Empty line within hunk = context
                hunk.lines.push(DiffLine {
                    line_type: DiffLineType::Context,
                    content: String::new(),
                    old_line_number: Some(old_line),
                    new_line_number: Some(new_line),
                });
                old_line += 1;
                new_line += 1;
            }
        }
    }

    // Finish last file
    if let Some(mut file) = current_file.take() {
        finish_hunk(&mut file, current_hunk.take());
        let (adds, dels) = count_hunk_stats(&file.hunks);
        file.additions = adds;
        file.deletions = dels;
        files.push(file);
    }

    files
}

/// Parse a hunk header line: @@ -old_start,old_lines +new_start,new_lines @@
fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    let line = line.strip_prefix("@@ ")?;
    let end = line.find(" @@")?;
    let range_part = &line[..end]; // e.g. "-1,5 +1,6"

    let parts: Vec<&str> = range_part.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let old = parts[0].strip_prefix('-')?;
    let new = parts[1].strip_prefix('+')?;

    let (old_start, old_lines) = parse_range(old);
    let (new_start, new_lines) = parse_range(new);

    Some((old_start, old_lines, new_start, new_lines))
}

fn parse_range(s: &str) -> (u32, u32) {
    if let Some((start, lines)) = s.split_once(',') {
        (start.parse().unwrap_or(1), lines.parse().unwrap_or(1))
    } else {
        (s.parse().unwrap_or(1), 1)
    }
}

fn count_hunk_stats(hunks: &[DiffHunk]) -> (u32, u32) {
    let mut adds = 0u32;
    let mut dels = 0u32;
    for hunk in hunks {
        for line in &hunk.lines {
            match line.line_type {
                DiffLineType::Add => adds += 1,
                DiffLineType::Remove => dels += 1,
                _ => {}
            }
        }
    }
    (adds, dels)
}

/// Parse `git diff --numstat` output into (path, additions, deletions) tuples
pub fn parse_numstat(output: &str) -> Vec<(String, u32, u32)> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 3 {
                return None;
            }
            // Binary files show "-" for adds/dels
            let adds = parts[0].parse().unwrap_or(0);
            let dels = parts[1].parse().unwrap_or(0);
            let path = parts[2].to_string();
            Some((path, adds, dels))
        })
        .collect()
}

/// Parse `git diff --name-status` output into (path, FileChangeType) tuples
pub fn parse_name_status(output: &str) -> Vec<(String, FileChangeType)> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.is_empty() {
                return None;
            }
            let status = parts[0];
            let change_type = if status.starts_with('R') {
                FileChangeType::Renamed
            } else {
                match status {
                    "A" => FileChangeType::Added,
                    "D" => FileChangeType::Deleted,
                    "M" => FileChangeType::Modified,
                    _ => FileChangeType::Modified,
                }
            };
            // For renames, path is the new path (parts[2]), otherwise parts[1]
            let path = if status.starts_with('R') && parts.len() >= 3 {
                parts[2].to_string()
            } else if parts.len() >= 2 {
                parts[1].to_string()
            } else {
                return None;
            };
            Some((path, change_type))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Git status tests
    #[test]
    fn test_parse_git_status_full() {
        let output = "REPO:/home/user/project\nAB:5 3\nDIRTY:2\nLINES:150 75\n";
        let status = parse_git_status(output).unwrap();
        assert_eq!(status.ahead, 5);
        assert_eq!(status.behind, 3);
        assert!(status.dirty);
        assert_eq!(status.additions, 150);
        assert_eq!(status.deletions, 75);
    }

    #[test]
    fn test_parse_git_status_clean() {
        let output = "REPO:/home/user/project\nAB:0 0\nDIRTY:0\nLINES:0 0\n";
        let status = parse_git_status(output).unwrap();
        assert!(!status.dirty);
    }

    #[test]
    fn test_parse_git_status_empty() {
        assert!(parse_git_status("").is_none());
    }

    // ================================================================
    // Unified diff parser tests
    // ================================================================

    #[test]
    fn test_parse_unified_diff_single_file() {
        let diff = "\
diff --git a/src/main.rs b/src/main.rs
index abc1234..def5678 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,5 +1,6 @@
 fn main() {
-    println!(\"hello\");
+    println!(\"hello world\");
+    println!(\"goodbye\");
     let x = 1;
 }
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 1);
        let file = &files[0];
        assert_eq!(file.file_path, "src/main.rs");
        assert_eq!(file.change_type, FileChangeType::Modified);
        assert!(!file.is_binary);
        assert_eq!(file.additions, 2);
        assert_eq!(file.deletions, 1);
        assert_eq!(file.hunks.len(), 1);

        let hunk = &file.hunks[0];
        assert_eq!(hunk.old_start, 1);
        assert_eq!(hunk.old_lines, 5);
        assert_eq!(hunk.new_start, 1);
        assert_eq!(hunk.new_lines, 6);
        // Header + 1 context + 1 remove + 2 add + 1 context + 1 context = 6 lines
        assert!(hunk.lines.len() >= 5);
    }

    #[test]
    fn test_parse_unified_diff_multifile() {
        let diff = "\
diff --git a/new_file.rs b/new_file.rs
new file mode 100644
--- /dev/null
+++ b/new_file.rs
@@ -0,0 +1,3 @@
+fn new() {}
+fn also_new() {}
+fn third() {}
diff --git a/deleted.rs b/deleted.rs
deleted file mode 100644
--- a/deleted.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-fn old() {}
-fn also_old() {}
diff --git a/old_name.rs b/new_name.rs
rename from old_name.rs
rename to new_name.rs
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 3);

        assert_eq!(files[0].file_path, "new_file.rs");
        assert_eq!(files[0].change_type, FileChangeType::Added);
        assert_eq!(files[0].additions, 3);
        assert_eq!(files[0].deletions, 0);

        assert_eq!(files[1].file_path, "deleted.rs");
        assert_eq!(files[1].change_type, FileChangeType::Deleted);
        assert_eq!(files[1].additions, 0);
        assert_eq!(files[1].deletions, 2);

        assert_eq!(files[2].file_path, "new_name.rs");
        assert_eq!(files[2].change_type, FileChangeType::Renamed);
    }

    #[test]
    fn test_parse_unified_diff_binary() {
        let diff = "\
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_binary);
    }

    #[test]
    fn test_parse_unified_diff_empty() {
        assert!(parse_unified_diff("").is_empty());
    }

    #[test]
    fn test_parse_unified_diff_line_numbers() {
        let diff = "\
diff --git a/foo.rs b/foo.rs
--- a/foo.rs
+++ b/foo.rs
@@ -10,3 +10,4 @@
 context
-removed
+added1
+added2
 context2
";
        let files = parse_unified_diff(diff);
        let hunk = &files[0].hunks[0];
        // After header: context(10,10), remove(11,_), add(_,11), add(_,12), context(12,13)
        let lines: Vec<_> = hunk
            .lines
            .iter()
            .filter(|l| l.line_type != DiffLineType::Header)
            .collect();
        assert_eq!(lines[0].line_type, DiffLineType::Context);
        assert_eq!(lines[0].old_line_number, Some(10));
        assert_eq!(lines[0].new_line_number, Some(10));

        assert_eq!(lines[1].line_type, DiffLineType::Remove);
        assert_eq!(lines[1].old_line_number, Some(11));
        assert_eq!(lines[1].new_line_number, None);

        assert_eq!(lines[2].line_type, DiffLineType::Add);
        assert_eq!(lines[2].new_line_number, Some(11));

        assert_eq!(lines[3].line_type, DiffLineType::Add);
        assert_eq!(lines[3].new_line_number, Some(12));

        assert_eq!(lines[4].line_type, DiffLineType::Context);
        assert_eq!(lines[4].old_line_number, Some(12));
        assert_eq!(lines[4].new_line_number, Some(13));
    }

    // ================================================================
    // Numstat / name-status parser tests
    // ================================================================

    #[test]
    fn test_parse_numstat() {
        let output = "10\t5\tsrc/main.rs\n-\t-\timage.png\n3\t0\tnew_file.rs\n";
        let result = parse_numstat(output);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], ("src/main.rs".to_string(), 10, 5));
        assert_eq!(result[1], ("image.png".to_string(), 0, 0)); // binary
        assert_eq!(result[2], ("new_file.rs".to_string(), 3, 0));
    }

    #[test]
    fn test_parse_name_status() {
        let output = "M\tsrc/main.rs\nA\tnew_file.rs\nD\told_file.rs\nR100\told.rs\tnew.rs\n";
        let result = parse_name_status(output);
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            ("src/main.rs".to_string(), FileChangeType::Modified)
        );
        assert_eq!(
            result[1],
            ("new_file.rs".to_string(), FileChangeType::Added)
        );
        assert_eq!(
            result[2],
            ("old_file.rs".to_string(), FileChangeType::Deleted)
        );
        assert_eq!(result[3], ("new.rs".to_string(), FileChangeType::Renamed));
    }
}
