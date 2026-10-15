//! `workspace.vm_only`: .dockerignore-style patterns naming project folders
//! kept on the VM's own disk.
//!
//! A pattern is `/`-separated and anchored at the project folder, so
//! `node_modules` names the top-level folder only. A `**` segment matches zero
//! or more folders (so `build/**` also names `build`); within a segment `*`
//! matches any run of characters, `?` one character, `[abc]`, `[a-z]` and
//! `[!a-z]` (or `[^a-z]`) one character of a class, and `\` escapes the next
//! character. Wildcards match a leading dot. Matching is case-sensitive and
//! never selects, or looks inside, a `.git` folder.
//!
//! This module performs no I/O: [`expand_vm_only`] walks a tree the caller
//! lists, so the host review, the host copy and the guest bind share one
//! matcher. A walk carries a [`VmOnlyCursor`] down the tree, so each name is
//! matched once per live pattern position, and every cost is capped: the
//! pattern sizes here, and the folders, entries, depth and character
//! comparisons of a walk.

use std::fmt;

/// The most patterns one project may list.
pub const MAX_VM_ONLY_PATTERNS: usize = 32;
/// The most folders kept in one VM.
pub const MAX_VM_ONLY_MATCHES: usize = 256;
/// The most folders one expansion looks inside.
pub const MAX_VM_ONLY_WALK_DIRECTORIES: usize = 20_000;
/// The most names one expansion reads.
pub const MAX_VM_ONLY_WALK_ENTRIES: usize = 100_000;
/// The deepest folder one expansion looks at, in path components.
pub const MAX_VM_ONLY_DEPTH: usize = 64;
/// The most character comparisons one walk spends matching names.
pub const MAX_VM_ONLY_MATCH_STEPS: u64 = 50_000_000;
/// The longest kept folder path, relative to the project folder.
pub const MAX_VM_ONLY_PATH_BYTES: usize = 1024;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_TOTAL_PATTERN_BYTES: usize = 2048;
const MAX_SEGMENTS: usize = 16;
const MAX_SEGMENT_BYTES: usize = 255;
const MAX_SEGMENT_TOKENS: usize = 64;
const MAX_SEGMENT_STARS: usize = 4;
/// Matches a walk collects before choosing which to keep.
const MAX_CANDIDATES: usize = 4096;

/// Why a `vm_only` pattern list is refused, in words for codewire.yaml.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmOnlyPatternError {
    TooMany,
    TooLarge,
    Duplicate(String),
    Invalid {
        pattern: String,
        reason: &'static str,
    },
}

impl fmt::Display for VmOnlyPatternError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany => write!(formatter, "lists more than {MAX_VM_ONLY_PATTERNS} patterns"),
            Self::TooLarge => write!(formatter, "patterns exceed 2 KiB in all"),
            Self::Duplicate(pattern) => write!(
                formatter,
                "{pattern:?} is listed twice (letter case aside: macOS folders ignore it)"
            ),
            Self::Invalid { pattern, reason } => write!(formatter, "{pattern:?} {reason}"),
        }
    }
}

impl std::error::Error for VmOnlyPatternError {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Literal(char),
    /// `*`: any run of characters within one folder name.
    Star,
    /// `?`: one character.
    One,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    /// `**`: zero or more folders.
    AnyDepth,
    Name(Vec<Token>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    text: String,
    segments: Vec<Segment>,
    /// The folder a pattern without wildcards names, unescaped.
    literal: Option<String>,
}

/// A validated, canonical `vm_only` pattern list and its matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmOnlyPatterns {
    patterns: Vec<Pattern>,
}

/// Where each pattern stands after matching a folder's path from the
/// project folder: carry it down a walk with [`VmOnlyPatterns::step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmOnlyCursor {
    states: Vec<Vec<bool>>,
}

/// The canonical form of one pattern as written: trimmed, one trailing `/`
/// removed. Validation follows in [`VmOnlyPatterns::parse`].
pub fn normalize_vm_only_pattern(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_suffix('/')
        .filter(|rest| !rest.ends_with('\\'))
        .unwrap_or(trimmed)
        .to_owned()
}

/// Whether `patterns` is a valid canonical `vm_only` list.
pub fn valid_vm_only_patterns(patterns: &[String]) -> bool {
    VmOnlyPatterns::parse(patterns).is_ok()
}

impl VmOnlyPatterns {
    /// Parse a canonical list: each pattern exactly as
    /// [`normalize_vm_only_pattern`] leaves it.
    pub fn parse(patterns: &[String]) -> Result<Self, VmOnlyPatternError> {
        if patterns.len() > MAX_VM_ONLY_PATTERNS {
            return Err(VmOnlyPatternError::TooMany);
        }
        if patterns.iter().map(String::len).sum::<usize>() > MAX_TOTAL_PATTERN_BYTES {
            return Err(VmOnlyPatternError::TooLarge);
        }
        let mut parsed: Vec<Pattern> = Vec::with_capacity(patterns.len());
        for text in patterns {
            let pattern = parse_pattern(text)?;
            let duplicate = parsed.iter().any(|other| {
                other.text == pattern.text
                    || matches!(
                        (&other.literal, &pattern.literal),
                        (Some(left), Some(right)) if left.eq_ignore_ascii_case(right)
                    )
            });
            if duplicate {
                return Err(VmOnlyPatternError::Duplicate(text.clone()));
            }
            parsed.push(pattern);
        }
        Ok(Self { patterns: parsed })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether some pattern has a wildcard, so an expansion walks the tree.
    pub fn needs_walk(&self) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.literal.is_none())
    }

    /// The patterns, in order.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.patterns.iter().map(|pattern| pattern.text.as_str())
    }

    /// The cursor of the project folder itself.
    pub fn cursor(&self) -> VmOnlyCursor {
        VmOnlyCursor {
            states: self
                .patterns
                .iter()
                .map(|pattern| {
                    let mut states = vec![false; pattern.segments.len() + 1];
                    states[0] = true;
                    close(&pattern.segments, &mut states);
                    states
                })
                .collect(),
        }
    }

    /// The cursor of folder `name` inside the folder at `cursor`. A `.git`
    /// folder, in any letter case, matches nothing and holds nothing that
    /// matches. `steps` counts the character comparisons spent.
    pub fn step(&self, cursor: &VmOnlyCursor, name: &str, steps: &mut u64) -> VmOnlyCursor {
        let git = is_git(name);
        VmOnlyCursor {
            states: self
                .patterns
                .iter()
                .zip(&cursor.states)
                .map(|(pattern, states)| {
                    let mut next = vec![false; states.len()];
                    if git {
                        return next;
                    }
                    for (position, active) in states.iter().enumerate() {
                        if !active || position == pattern.segments.len() {
                            continue;
                        }
                        match &pattern.segments[position] {
                            Segment::AnyDepth => next[position] = true,
                            Segment::Name(tokens) => {
                                if match_name(tokens, name, steps) {
                                    next[position + 1] = true;
                                }
                            }
                        }
                    }
                    close(&pattern.segments, &mut next);
                    next
                })
                .collect(),
        }
    }

    /// The first pattern that names the folder at `cursor`.
    pub fn accepts(&self, cursor: &VmOnlyCursor) -> Option<usize> {
        cursor
            .states
            .iter()
            .position(|states| states.last().copied().unwrap_or(false))
    }

    /// Whether some pattern may name a folder beneath the one at `cursor`,
    /// so a walk must look inside it.
    pub fn alive(&self, cursor: &VmOnlyCursor) -> bool {
        cursor
            .states
            .iter()
            .any(|states| states[..states.len() - 1].contains(&true))
    }

    /// The first pattern that names the folder at `path` (components from
    /// the project folder). Never the project folder itself.
    pub fn matching(&self, path: &[&str]) -> Option<usize> {
        if path.is_empty() {
            return None;
        }
        self.accepts(&self.walk_to(path))
    }

    /// Whether some pattern may name a folder strictly beneath `path`.
    pub fn may_match_below(&self, path: &[&str]) -> bool {
        self.alive(&self.walk_to(path))
    }

    fn walk_to(&self, path: &[&str]) -> VmOnlyCursor {
        let mut steps = 0;
        path.iter().fold(self.cursor(), |cursor, name| {
            self.step(&cursor, name, &mut steps)
        })
    }
}

fn is_git(component: &str) -> bool {
    component.eq_ignore_ascii_case(".git")
}

/// `**` may match zero folders, so reaching it also reaches what follows.
fn close(segments: &[Segment], states: &mut [bool]) {
    for position in 0..segments.len() {
        if states[position] && segments[position] == Segment::AnyDepth {
            states[position + 1] = true;
        }
    }
}

/// One folder name against one segment: `*` backtracks to its last use, so
/// the work stays within the two lengths' product, counted in `steps`.
fn match_name(tokens: &[Token], name: &str, steps: &mut u64) -> bool {
    let name = name.chars().collect::<Vec<_>>();
    let (mut token, mut index) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while index < name.len() {
        *steps = steps.saturating_add(1);
        if let Some(Token::Star) = tokens.get(token) {
            star = Some((token, index));
            token += 1;
            continue;
        }
        let matched = match tokens.get(token) {
            Some(Token::Literal(character)) => *character == name[index],
            Some(Token::One) => true,
            Some(Token::Class { negated, ranges }) => {
                ranges
                    .iter()
                    .any(|(low, high)| (*low..=*high).contains(&name[index]))
                    != *negated
            }
            Some(Token::Star) | None => false,
        };
        if matched {
            token += 1;
            index += 1;
        } else if let Some((star_token, star_index)) = star {
            token = star_token + 1;
            index = star_index + 1;
            star = Some((star_token, star_index + 1));
        } else {
            return false;
        }
    }
    tokens[token..].iter().all(|token| *token == Token::Star)
}

fn parse_pattern(text: &str) -> Result<Pattern, VmOnlyPatternError> {
    let invalid = |reason| VmOnlyPatternError::Invalid {
        pattern: text.to_owned(),
        reason,
    };
    if text.is_empty() {
        return Err(invalid("is empty"));
    }
    if normalize_vm_only_pattern(text) != text {
        return Err(invalid("is not in canonical form"));
    }
    if text.starts_with('/') {
        return Err(invalid("must be relative to the project folder"));
    }
    if text.starts_with('!') {
        return Err(invalid(
            "is an exception, which vm_only does not support; write \\! for a name that starts with !",
        ));
    }
    if text.len() > MAX_PATTERN_BYTES {
        return Err(invalid("is longer than 256 bytes"));
    }
    if text.chars().any(char::is_control) {
        return Err(invalid("contains a control character"));
    }
    let raw_segments = split_segments(text);
    if raw_segments.len() > MAX_SEGMENTS {
        return Err(invalid("has more than 16 segments"));
    }
    let mut segments = Vec::new();
    let mut literal = Some(String::new());
    for raw in raw_segments {
        if raw.is_empty() {
            return Err(invalid("has an empty segment"));
        }
        if raw.len() > MAX_SEGMENT_BYTES {
            return Err(invalid("has a segment longer than 255 bytes"));
        }
        if raw == "**" {
            if segments.last() == Some(&Segment::AnyDepth) {
                return Err(invalid("repeats **"));
            }
            segments.push(Segment::AnyDepth);
            literal = None;
            continue;
        }
        let tokens = parse_segment(raw).map_err(invalid)?;
        if tokens.len() > MAX_SEGMENT_TOKENS {
            return Err(invalid(
                "has a segment of more than 64 characters and wildcards",
            ));
        }
        if tokens.iter().filter(|token| **token == Token::Star).count() > MAX_SEGMENT_STARS {
            return Err(invalid("has more than 4 * in one segment"));
        }
        let name = tokens
            .iter()
            .map(|token| match token {
                Token::Literal(character) => Some(*character),
                _ => None,
            })
            .collect::<Option<String>>();
        match name.as_deref() {
            Some(".") | Some("..") => return Err(invalid("must not contain . or .. segments")),
            Some(name) if is_git(name) => {
                return Err(invalid("would hide the Git repository from the VM"));
            }
            _ => {}
        }
        literal = match (literal, name) {
            (Some(mut path), Some(name)) => {
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(&name);
                Some(path)
            }
            _ => None,
        };
        segments.push(Segment::Name(tokens));
    }
    if segments.iter().all(|segment| *segment == Segment::AnyDepth) {
        return Err(invalid("would keep the whole project in the VM"));
    }
    Ok(Pattern {
        text: text.to_owned(),
        segments,
        literal,
    })
}

/// Split on `/` that is not escaped.
fn split_segments(text: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '/' {
            segments.push(&text[start..index]);
            start = index + 1;
        }
    }
    segments.push(&text[start..]);
    segments
}

fn parse_segment(raw: &str) -> Result<Vec<Token>, &'static str> {
    let mut tokens = Vec::new();
    let mut characters = raw.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('/') => return Err("escapes a /, which no folder name contains"),
                Some(escaped) => tokens.push(Token::Literal(escaped)),
                None => return Err("ends with a lone \\"),
            },
            '*' => {
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
            }
            '?' => tokens.push(Token::One),
            '[' => {
                let negated = matches!(characters.peek(), Some('!' | '^'));
                if negated {
                    characters.next();
                }
                let mut ranges = Vec::new();
                let mut first = true;
                loop {
                    let low = match characters.next() {
                        None => return Err("has an unclosed ["),
                        Some(']') if !first => break,
                        Some('\\') => characters.next().ok_or("ends with a lone \\")?,
                        Some(low) => low,
                    };
                    first = false;
                    let high = if characters.peek() == Some(&'-') {
                        let mut lookahead = characters.clone();
                        lookahead.next();
                        match lookahead.peek() {
                            Some(']') | None => low,
                            Some(_) => {
                                characters.next();
                                match characters.next() {
                                    Some('\\') => characters.next().ok_or("ends with a lone \\")?,
                                    Some(high) => high,
                                    None => return Err("has an unclosed ["),
                                }
                            }
                        }
                    } else {
                        low
                    };
                    if high < low {
                        return Err("has a character range that runs backwards");
                    }
                    ranges.push((low, high));
                }
                tokens.push(Token::Class { negated, ranges });
            }
            literal => tokens.push(Token::Literal(literal)),
        }
    }
    Ok(tokens)
}

/// A folder tree an expansion walks. Implementations open each folder by
/// itself, without following symlinks or crossing mounts.
pub trait VmOnlyTree {
    type Folder;

    /// The names in `folder` that may be folders. Errors list nothing.
    fn names(&mut self, folder: &Self::Folder) -> Vec<String>;

    /// `name` beneath `folder`, when it is a plain folder on the same
    /// filesystem: never a symlink, file or mount point.
    fn open(&mut self, folder: &Self::Folder, name: &str) -> Option<Self::Folder>;

    /// Whether `folder` holds a `.git` entry of any kind: a repository of
    /// its own, which stays shared.
    fn holds_repository(&mut self, folder: &Self::Folder) -> bool;

    /// Whether the caller's own budget, such as a deadline, has run out.
    fn exhausted(&mut self) -> bool {
        false
    }
}

/// One folder a pattern keeps in the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmOnlyMatch {
    /// Relative to the project folder.
    pub path: String,
    /// The first pattern that names it.
    pub pattern: usize,
    /// Whether the walk found it as a plain folder. A pattern without
    /// wildcards names its folder whether found or not (with only such
    /// patterns there is no walk), and the guest creates it empty when its
    /// parent exists.
    pub exists: bool,
}

/// The folders a pattern list keeps, sorted by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmOnlyExpansion {
    pub matches: Vec<VmOnlyMatch>,
    /// Matching folders left shared because they hold a Git repository.
    pub repositories: Vec<String>,
    /// A cap stopped the walk or dropped matches: some folders may be missing.
    pub truncated: bool,
}

/// Find the folders `patterns` keep beneath `root`. A matching folder is kept
/// whole, so nothing beneath it is looked at; `.git` is never entered, and a
/// match holding a `.git` stays shared. Patterns without wildcards also name
/// their folder when it is absent; a list of only those needs no walk. Of
/// more than [`MAX_VM_ONLY_MATCHES`] folders, those named by patterns without
/// wildcards come first, then the shallowest.
pub fn expand_vm_only<T: VmOnlyTree>(
    patterns: &VmOnlyPatterns,
    tree: &mut T,
    root: &T::Folder,
) -> VmOnlyExpansion {
    let mut walk = Walk {
        patterns,
        candidates: Vec::new(),
        repositories: Vec::new(),
        directories: 0,
        entries: 0,
        steps: 0,
        truncated: false,
    };
    if patterns.needs_walk() {
        walk.folder(tree, root, &patterns.cursor(), &mut Vec::new());
    }
    let Walk {
        mut candidates,
        repositories,
        mut truncated,
        ..
    } = walk;
    for (index, pattern) in patterns.patterns.iter().enumerate() {
        let Some(path) = &pattern.literal else {
            continue;
        };
        if !candidates.iter().any(|found| found.path == *path) && !repositories.contains(path) {
            candidates.push(VmOnlyMatch {
                path: path.clone(),
                pattern: index,
                exists: false,
            });
        }
    }
    candidates.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    // Keep the outermost: sorted, an ancestor comes before what it holds.
    let mut outermost: Vec<VmOnlyMatch> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.path.len() > MAX_VM_ONLY_PATH_BYTES {
            truncated = true;
            continue;
        }
        let nested = outermost.iter().any(|outer| {
            candidate
                .path
                .strip_prefix(outer.path.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        });
        if !nested {
            outermost.push(candidate);
        }
    }
    if outermost.len() > MAX_VM_ONLY_MATCHES {
        // Patterns without wildcards first, then the shallowest.
        outermost.sort_by_key(|found| {
            (
                patterns.patterns[found.pattern].literal.is_none(),
                found.path.matches('/').count(),
                found.path.clone(),
            )
        });
        outermost.truncate(MAX_VM_ONLY_MATCHES);
        outermost.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        truncated = true;
    }
    VmOnlyExpansion {
        matches: outermost,
        repositories,
        truncated,
    }
}

struct Walk<'a> {
    patterns: &'a VmOnlyPatterns,
    candidates: Vec<VmOnlyMatch>,
    repositories: Vec<String>,
    directories: usize,
    entries: usize,
    steps: u64,
    truncated: bool,
}

impl Walk<'_> {
    fn spent(&self) -> bool {
        self.directories >= MAX_VM_ONLY_WALK_DIRECTORIES
            || self.entries >= MAX_VM_ONLY_WALK_ENTRIES
            || self.steps >= MAX_VM_ONLY_MATCH_STEPS
            || self.candidates.len() >= MAX_CANDIDATES
    }

    fn folder<T: VmOnlyTree>(
        &mut self,
        tree: &mut T,
        folder: &T::Folder,
        cursor: &VmOnlyCursor,
        path: &mut Vec<String>,
    ) {
        if self.spent() || tree.exhausted() {
            self.truncated = true;
            return;
        }
        self.directories += 1;
        let mut names = tree.names(folder);
        self.entries = self.entries.saturating_add(names.len());
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        names.dedup();
        for name in names {
            if self.spent() {
                self.truncated = true;
                return;
            }
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.chars().any(char::is_control)
                || is_git(&name)
            {
                continue;
            }
            let child = self.patterns.step(cursor, &name, &mut self.steps);
            let accepted = self.patterns.accepts(&child);
            let alive = self.patterns.alive(&child);
            if accepted.is_none() && !alive {
                continue;
            }
            if path.len() >= MAX_VM_ONLY_DEPTH {
                self.truncated = true;
                continue;
            }
            let Some(opened) = tree.open(folder, &name) else {
                continue;
            };
            path.push(name);
            match accepted {
                Some(pattern) if !tree.holds_repository(&opened) => {
                    self.candidates.push(VmOnlyMatch {
                        path: path.join("/"),
                        pattern,
                        exists: true,
                    });
                }
                Some(_) => {
                    self.repositories.push(path.join("/"));
                    if alive {
                        self.folder(tree, &opened, &child, path);
                    }
                }
                None => self.folder(tree, &opened, &child, path),
            }
            path.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn patterns(list: &[&str]) -> VmOnlyPatterns {
        VmOnlyPatterns::parse(&list.iter().map(|text| text.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    fn matches(list: &[&str], path: &str) -> bool {
        let components = path.split('/').collect::<Vec<_>>();
        patterns(list).matching(&components).is_some()
    }

    #[test]
    fn plain_names_are_anchored_at_the_project_folder() {
        assert!(matches(&["node_modules"], "node_modules"));
        assert!(!matches(&["node_modules"], "web/node_modules"));
        assert!(matches(&["web/node_modules"], "web/node_modules"));
        assert!(!matches(&["web/node_modules"], "web"));
        assert!(!matches(&["node_modules"], "node_modules/x"));
    }

    #[test]
    fn double_star_matches_any_depth_including_none() {
        let list = ["**/node_modules"];
        for path in [
            "node_modules",
            "a/node_modules",
            "a/b/c/node_modules",
            ".hidden/node_modules",
        ] {
            assert!(matches(&list, path), "{path}");
        }
        assert!(!matches(&list, "a/node_modules_x"));
        assert!(matches(&["packages/**/dist"], "packages/dist"));
        assert!(matches(&["packages/**/dist"], "packages/a/b/dist"));
        assert!(!matches(&["packages/**/dist"], "dist"));
        assert!(matches(&["build/**"], "build"));
        assert!(matches(&["build/**"], "build/x/y"));
        assert!(matches(&["a/**/b/**/c"], "a/x/b/y/z/c"));
        assert!(!matches(&["a/**/b/**/c"], "a/x/c"));
    }

    #[test]
    fn wildcards_classes_and_escapes_match_within_one_name() {
        assert!(matches(&["*"], "anything"));
        assert!(matches(&["*"], ".hidden"));
        assert!(!matches(&["*"], "a/b"));
        assert!(matches(
            &["packages/*/node_modules"],
            "packages/web/node_modules"
        ));
        assert!(!matches(
            &["packages/*/node_modules"],
            "packages/a/b/node_modules"
        ));
        assert!(matches(&["build-?"], "build-1"));
        assert!(!matches(&["build-?"], "build-10"));
        assert!(matches(&["[bt]arget"], "target"));
        assert!(matches(&["[a-c]x"], "bx"));
        assert!(!matches(&["[!a-c]x"], "bx"));
        assert!(matches(&["[^a-c]x"], "dx"));
        assert!(matches(&["[]a]"], "]"));
        assert!(matches(&["[a-]"], "-"));
        assert!(matches(&["\\*"], "*"));
        assert!(!matches(&["\\*"], "x"));
        assert!(matches(&["\\!keep"], "!keep"));
        assert!(matches(&["*.cache"], ".cache"));
        assert!(matches(&["a*b*c"], "aXbYc"));
        assert!(!matches(&["a*b*c"], "aXbY"));
        assert!(matches(&["*x*y*"], &"xy".repeat(100)));
    }

    #[test]
    fn git_is_never_matched_or_entered_and_the_root_never_matches() {
        assert!(!matches(&["*"], ".git"));
        assert!(!matches(&[".gi?"], ".GIT"));
        assert!(!matches(&["**/x"], ".git/x"));
        assert!(!matches(&["*/x"], ".Git/x"));
        let list = patterns(&["**/node_modules"]);
        assert!(!list.may_match_below(&[".git"]));
        assert_eq!(list.matching(&[]), None);
        assert_eq!(list.accepts(&list.cursor()), None);
    }

    #[test]
    fn pruning_descends_only_where_a_match_may_lie() {
        let list = patterns(&["node_modules", "target", "packages/*/node_modules"]);
        assert!(list.may_match_below(&[]));
        assert!(list.may_match_below(&["packages"]));
        assert!(list.may_match_below(&["packages", "web"]));
        assert!(!list.may_match_below(&["src"]));
        assert!(!list.may_match_below(&["packages", "web", "src"]));
        let deep = patterns(&["**/node_modules"]);
        assert!(deep.may_match_below(&["src", "a", "b"]));
    }

    #[test]
    fn matching_cost_is_counted_and_bounded_by_the_pattern_limits() {
        let list = patterns(&["**/*a*a*a*b"]);
        let mut steps = 0;
        let cursor = list.step(&list.cursor(), &"a".repeat(255), &mut steps);
        assert_eq!(list.accepts(&cursor), None);
        assert!(steps > 0 && steps <= 255 * 64, "{steps}");
    }

    #[test]
    fn validation_refuses_unsafe_malformed_and_costly_patterns() {
        for (pattern, reason) in [
            ("", "is empty"),
            ("/abs", "relative"),
            ("../up", ". or .."),
            ("a/../b", ". or .."),
            ("./a", ". or .."),
            ("\\.\\.", ". or .."),
            ("a//b", "empty segment"),
            (".git", "Git repository"),
            ("x/.GIT", "Git repository"),
            (".gi\\t", "Git repository"),
            ("!keep", "exception"),
            ("**", "whole project"),
            ("**/**", "repeats **"),
            ("a/**/**/b", "repeats **"),
            ("[ab", "unclosed"),
            ("a\\", "lone"),
            ("[z-a]", "backwards"),
            ("a\tb", "control"),
            (" a", "canonical"),
            ("a/", "canonical"),
            ("*a*b*c*d*e", "more than 4 *"),
        ] {
            let error = VmOnlyPatterns::parse(&[pattern.to_owned()]).unwrap_err();
            assert!(error.to_string().contains(reason), "{pattern:?}: {error}");
        }
        let long = "x".repeat(257);
        assert!(VmOnlyPatterns::parse(&[long]).is_err());
        let deep = (0..17).map(|_| "d").collect::<Vec<_>>().join("/");
        assert!(VmOnlyPatterns::parse(&[deep]).is_err());
        let tokens = "?".repeat(65);
        assert!(VmOnlyPatterns::parse(&[tokens]).is_err());
        for duplicate in [["a", "a"], ["Node_modules", "node_modules"]] {
            assert!(matches!(
                VmOnlyPatterns::parse(&duplicate.map(str::to_owned)),
                Err(VmOnlyPatternError::Duplicate(_))
            ));
        }
        assert!(matches!(
            VmOnlyPatterns::parse(&(0..33).map(|index| format!("d{index}")).collect::<Vec<_>>()),
            Err(VmOnlyPatternError::TooMany)
        ));
        let wide = (0..9)
            .map(|index| format!("{index}{}", "y".repeat(250)))
            .collect::<Vec<_>>();
        assert_eq!(
            VmOnlyPatterns::parse(&wide),
            Err(VmOnlyPatternError::TooLarge)
        );
        // Overlapping patterns are fine: the outermost match wins.
        patterns(&["node_modules", "**/node_modules", "packages", ".github"]);
        assert_eq!(normalize_vm_only_pattern("  target/ "), "target");
        assert_eq!(normalize_vm_only_pattern("a\\/"), "a\\/");
    }

    /// An in-memory tree: folder path -> child names; a name absent from the
    /// map is a file or symlink and does not open. Counts listings.
    struct Fixture {
        folders: BTreeMap<String, Vec<String>>,
        listed: usize,
    }

    impl Fixture {
        fn new(folders: &[&str]) -> Self {
            let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
            map.entry(String::new()).or_default();
            for folder in folders {
                let mut parent = String::new();
                for component in folder.split('/') {
                    let child = if parent.is_empty() {
                        component.to_owned()
                    } else {
                        format!("{parent}/{component}")
                    };
                    let names = map.entry(parent.clone()).or_default();
                    if !names.iter().any(|name| name == component) {
                        names.push(component.to_owned());
                    }
                    map.entry(child.clone()).or_default();
                    parent = child;
                }
            }
            Self {
                folders: map,
                listed: 0,
            }
        }
    }

    impl VmOnlyTree for Fixture {
        type Folder = String;

        fn names(&mut self, folder: &String) -> Vec<String> {
            self.listed += 1;
            self.folders.get(folder).cloned().unwrap_or_default()
        }

        fn open(&mut self, folder: &String, name: &str) -> Option<String> {
            let child = if folder.is_empty() {
                name.to_owned()
            } else {
                format!("{folder}/{name}")
            };
            self.folders.contains_key(&child).then_some(child)
        }

        fn holds_repository(&mut self, folder: &String) -> bool {
            self.folders.contains_key(&format!("{folder}/.git"))
        }
    }

    fn expand(list: &[&str], folders: &[&str]) -> (VmOnlyExpansion, usize) {
        let mut tree = Fixture::new(folders);
        let expansion = expand_vm_only(&patterns(list), &mut tree, &String::new());
        (expansion, tree.listed)
    }

    fn paths(expansion: &VmOnlyExpansion) -> Vec<(&str, bool)> {
        expansion
            .matches
            .iter()
            .map(|found| (found.path.as_str(), found.exists))
            .collect()
    }

    #[test]
    fn expansion_keeps_the_outermost_existing_folders_and_absent_literals() {
        let folders = [
            "node_modules/a/node_modules",
            "packages/web/node_modules/x",
            "packages/api/node_modules",
            "packages/api/src",
            "packages/vendored/.git",
            "packages/vendored/node_modules",
            ".git/node_modules",
            "src/deep/node_modules",
        ];
        let (expansion, _) = expand(&["node_modules", "target", "**/node_modules"], &folders);
        assert!(!expansion.truncated);
        assert_eq!(
            paths(&expansion),
            [
                ("node_modules", true),
                ("packages/api/node_modules", true),
                ("packages/vendored/node_modules", true),
                ("packages/web/node_modules", true),
                ("src/deep/node_modules", true),
                // Absent, without wildcards: created empty when bound.
                ("target", false),
            ]
        );
        // A literal under a kept folder adds nothing; plain names are not
        // looked for.
        let (expansion, listed) = expand(&["packages", "packages/web/node_modules"], &folders);
        assert_eq!(paths(&expansion), [("packages", false)]);
        assert_eq!(listed, 0);
        // A match that holds its own repository stays shared; what is
        // beneath it is still looked at.
        let (expansion, _) = expand(&["packages/*", "**/node_modules"], &folders);
        assert_eq!(expansion.repositories, ["packages/vendored".to_owned()]);
        assert!(paths(&expansion).contains(&("packages/vendored/node_modules", true)));
        assert!(paths(&expansion).contains(&("packages/api", true)));
    }

    #[test]
    fn expansion_of_plain_names_does_not_walk() {
        let mut folders = vec!["node_modules".to_owned()];
        for index in 0..500 {
            folders.push(format!("src/m{index}/x"));
        }
        let folders = folders.iter().map(String::as_str).collect::<Vec<_>>();
        let (expansion, listed) = expand(&["node_modules", "target", ".venv"], &folders);
        assert_eq!(expansion.matches.len(), 3);
        assert!(expansion.matches.iter().all(|found| !found.exists));
        assert_eq!(listed, 0, "plain names need no walk");
        let (_, listed) = expand(&["packages/*/node_modules"], &folders);
        assert_eq!(
            listed, 1,
            "only the folders on a pattern's prefix are listed"
        );
        let (_, listed) = expand(&["**/node_modules"], &folders);
        assert!(listed > 500);
    }

    #[test]
    fn expansion_keeps_plain_names_and_the_shallowest_at_the_cap() {
        let mut folders = (0..300)
            .map(|index| format!("p{index:03}/q/node_modules"))
            .collect::<Vec<_>>();
        folders.push("z/node_modules".to_owned());
        let folders = folders.iter().map(String::as_str).collect::<Vec<_>>();
        let (expansion, _) = expand(&["**/node_modules", "target"], &folders);
        assert_eq!(expansion.matches.len(), MAX_VM_ONLY_MATCHES);
        assert!(expansion.truncated);
        let kept = paths(&expansion);
        assert!(kept.contains(&("target", false)));
        assert!(kept.contains(&("z/node_modules", true)));
    }

    #[test]
    fn expansion_stops_at_its_depth_cap() {
        let deep = (0..80)
            .map(|index| format!("d{index}"))
            .collect::<Vec<_>>()
            .join("/");
        let (expansion, _) = expand(&["**/d79"], &[deep.as_str()]);
        assert!(expansion.matches.is_empty());
        assert!(expansion.truncated, "the depth cap is reported");
    }

    #[test]
    fn expansion_stops_when_the_caller_is_out_of_time() {
        struct Expired(Fixture);
        impl VmOnlyTree for Expired {
            type Folder = String;
            fn names(&mut self, folder: &String) -> Vec<String> {
                self.0.names(folder)
            }
            fn open(&mut self, folder: &String, name: &str) -> Option<String> {
                self.0.open(folder, name)
            }
            fn holds_repository(&mut self, folder: &String) -> bool {
                self.0.holds_repository(folder)
            }
            fn exhausted(&mut self) -> bool {
                true
            }
        }
        let mut tree = Expired(Fixture::new(&["a/node_modules"]));
        let expansion = expand_vm_only(&patterns(&["**/node_modules"]), &mut tree, &String::new());
        assert!(expansion.matches.is_empty());
        assert!(expansion.truncated);
    }
}
