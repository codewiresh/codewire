//! Git clone progress reduced to numbers (Program #2238, A5a contract v1).
//!
//! `git clone --progress` writes its stage meters to stderr. This parser
//! reads only those meters: a fixed stage label (optionally behind Git's
//! `remote: ` prefix) followed by a whole-number percentage. Everything else
//! is discarded, and nothing read from the stream leaves this module except a
//! [`CloneStage`] token chosen from the fixed table below and a percentage
//! from 0 to 100. Raw output, paths, URLs and remote messages never reach a
//! log row. The reader contract lives in
//! `crates/codewire-cli/src/commands/environment/progress.rs`.

use std::time::{Duration, Instant};

/// A segment longer than this is not a Git progress meter. It is discarded up
/// to its next line or carriage-return terminator.
const MAX_SEGMENT_BYTES: usize = 256;

/// Progress rows for one repository are written at most this often, except
/// that a stage's first report and its completion are always written.
pub(super) const PROGRESS_ROW_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CloneStage {
    CountingObjects,
    CompressingObjects,
    ReceivingObjects,
    ResolvingDeltas,
    UpdatingFiles,
}

const STAGES: [(&[u8], CloneStage); 5] = [
    (b"Counting objects:", CloneStage::CountingObjects),
    (b"Compressing objects:", CloneStage::CompressingObjects),
    (b"Receiving objects:", CloneStage::ReceivingObjects),
    (b"Resolving deltas:", CloneStage::ResolvingDeltas),
    (b"Updating files:", CloneStage::UpdatingFiles),
];

impl CloneStage {
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::CountingObjects => "counting_objects",
            Self::CompressingObjects => "compressing_objects",
            Self::ReceivingObjects => "receiving_objects",
            Self::ResolvingDeltas => "resolving_deltas",
            Self::UpdatingFiles => "updating_files",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CloneProgress {
    pub(super) stage: CloneStage,
    pub(super) percent: u8,
}

/// Incremental parser over arbitrary stderr chunks. A meter split across
/// chunks is completed by the next chunk; an unterminated tail is held, never
/// guessed at.
#[derive(Debug, Default)]
pub(super) struct CloneProgressParser {
    segment: Vec<u8>,
    discarding: bool,
}

impl CloneProgressParser {
    pub(super) fn feed(&mut self, bytes: &[u8]) -> Vec<CloneProgress> {
        let mut found = Vec::new();
        for &byte in bytes {
            if byte == b'\r' || byte == b'\n' {
                if !self.discarding
                    && let Some(progress) = parse_segment(&self.segment)
                {
                    found.push(progress);
                }
                self.segment.clear();
                self.discarding = false;
            } else if !self.discarding {
                if self.segment.len() == MAX_SEGMENT_BYTES {
                    self.segment.clear();
                    self.discarding = true;
                } else {
                    self.segment.push(byte);
                }
            }
        }
        found
    }
}

impl Drop for CloneProgressParser {
    fn drop(&mut self) {
        // The held tail is child output; do not leave it in freed memory.
        self.segment.fill(0);
    }
}

fn parse_segment(segment: &[u8]) -> Option<CloneProgress> {
    let segment = segment.trim_ascii_start();
    let segment = segment.strip_prefix(b"remote:").unwrap_or(segment);
    let segment = segment.trim_ascii_start();
    let (label, stage) = STAGES
        .iter()
        .find(|(label, _)| segment.starts_with(label))?;
    let rest = segment[label.len()..].trim_ascii_start();
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 || digits > 3 || rest.get(digits) != Some(&b'%') {
        return None;
    }
    let percent = rest[..digits]
        .iter()
        .fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
    let percent = u8::try_from(percent)
        .ok()
        .filter(|percent| *percent <= 100)?;
    Some(CloneProgress {
        stage: *stage,
        percent,
    })
}

/// Decides which parsed meters become rows for one repository. Within a stage
/// the percentage only moves forward, so a repository writes at most
/// 5 stages × 101 values no matter what the remote sends.
#[derive(Debug)]
pub(super) struct ProgressThrottle {
    reported: [Option<u8>; 5],
    last_row: Option<Instant>,
    interval: Duration,
}

impl ProgressThrottle {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            reported: [None; 5],
            last_row: None,
            interval,
        }
    }

    pub(super) fn admit(&mut self, progress: CloneProgress, now: Instant) -> bool {
        let reported = &mut self.reported[progress.stage.index()];
        let admitted = match *reported {
            None => true,
            Some(previous) if progress.percent <= previous => false,
            Some(_) if progress.percent == 100 => true,
            Some(_) => self
                .last_row
                .is_none_or(|last| now.saturating_duration_since(last) >= self.interval),
        };
        if admitted {
            *reported = Some(progress.percent);
            self.last_row = Some(now);
        }
        admitted
    }
}

/// The row metadata for one admitted meter: numbers and a fixed token only.
pub(super) fn progress_metadata(
    repo_index: usize,
    repo_count: usize,
    progress: CloneProgress,
) -> serde_json::Value {
    serde_json::json!({
        "repo_index": repo_index,
        "repo_count": repo_count,
        "stage": progress.stage.token(),
        "percent": progress.percent,
    })
}

/// The row metadata that scopes a per-repository `started` or `completed`
/// row under the phase-level `git_clone` rows.
pub(super) fn repository_metadata(repo_index: usize, repo_count: usize) -> serde_json::Value {
    serde_json::json!({
        "repo_index": repo_index,
        "repo_count": repo_count,
    })
}

#[cfg(test)]
mod tests;
