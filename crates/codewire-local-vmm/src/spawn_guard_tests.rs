//! cw-security, #4654: every process this crate can start on macOS runs the
//! close-on-exec sweep (`darwin::process::mark_inherited_descriptors_close_on_exec`)
//! between fork and exec. Darwin creates a socket or pipe and only then marks
//! it close-on-exec, so a child started in between inherits it: for one, the
//! runner's end of a VZ helper's control channel.
//!
//! The guard reads every source file under `src/`. A process starts through
//! `Command::new(`, under any other name the crate gives a command type
//! (`use ... as`, `type`), through `fork` or `vfork` called by path, imported
//! or brought in by a glob of a module that exports it, or through
//! `posix_spawn`. Each function that does one of these,
//! or names `process::Command`, must be listed in [`SPAWNS`] and run the sweep
//! once for each process it starts: itself, or by calling one of
//! [`PREPARATIONS`]. Any of them outside a function fails. Code that macOS
//! never compiles is skipped: test code, `linux/`, and anything under
//! `#[cfg(target_os = "linux")]`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SWEEP: &str = "mark_inherited_descriptors_close_on_exec()";
/// Glob imports of a module that exports `fork`, after which a bare `fork()`
/// starts a process unseen (cw-security on #4685).
const FORK_GLOBS: [&str; 3] = ["libc::*", "unistd::*", "runtime::*"];
const LINUX: &str = "#[cfg(target_os = \"linux\")]";
const TEST: [&str; 2] = ["#[cfg(test)]", "#[cfg(all(test,"];

/// Every function macOS compiles that starts a process or names its command,
/// by its file under `src/`.
const SPAWNS: [(&str, &str); 22] = [
    ("cw_runtime.rs", "run_tool"),
    ("darwin/disk_tool.rs", "command"),
    ("darwin/mod.rs", "vz_helper_problem"),
    ("generation.rs", "format_ext4"),
    ("lib.rs", "sweep_before_exec"),
    ("runner.rs", "disk_tool_command"),
    ("runner.rs", "spawn_egress_broker_process"),
    ("runner.rs", "spawn_network_worker_process"),
    ("runner/front_door.rs", "spawn"),
    ("runner/mesh_processes.rs", "spawn_mesh_enrollment_process"),
    ("runner/mesh_processes.rs", "spawn_mesh_transport_process"),
    ("supervisor.rs", "spawn_runner"),
    ("supervisor.rs", "spawn_supervisor"),
    ("supervisor/snapshots.rs", "command"),
    ("vz.rs", "probe_protocol_within"),
    ("vz.rs", "spawn"),
    ("workspace.rs", "format_empty_ext4"),
    ("workspace.rs", "format_state_disk"),
    ("workspace.rs", "git_clone_output"),
    ("workspace.rs", "git_output"),
    ("workspace.rs", "import_git_bundle"),
    ("workspace_plan.rs", "git_command"),
];

/// The functions that make the child of a command they are given, or build,
/// run the sweep: by file, name, and the call that uses one.
const PREPARATIONS: [(&str, &str, &str); 5] = [
    (
        "cw_runtime.rs",
        "inherit_publication_custody",
        "inherit_publication_custody(",
    ),
    ("darwin/disk_tool.rs", "command", "disk_tool::command("),
    ("lib.rs", "sweep_before_exec", "sweep_before_exec("),
    (
        "runner.rs",
        "prepare_isolated_child",
        "prepare_isolated_child(",
    ),
    (
        "runner.rs",
        "prepare_isolated_child_pair",
        "prepare_isolated_child_pair(",
    ),
];

#[test]
fn every_macos_spawn_runs_the_close_on_exec_sweep() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    read_sources(&root, &root, &mut sources);
    let source = |path: &str| {
        sources
            .iter()
            .find(|source| source.path == path)
            .unwrap_or_else(|| panic!("no src/{path}"))
    };

    // What the skips rely on: `linux/` compiles only on Linux, a test-named
    // module only in tests, and each module is the file its name says.
    assert!(
        source("lib.rs")
            .lines
            .join("\n")
            .contains("#[cfg(target_os = \"linux\")]\npub mod linux;")
    );
    for product in sources.iter().filter(|source| !is_test_path(&source.path)) {
        for (at, line) in product.lines.iter().enumerate() {
            if is_comment(line) {
                continue;
            }
            assert!(
                !line.contains("#[path"),
                "src/{}:{}: a module path this guard cannot follow",
                product.path,
                at + 1
            );
            if let Some(rest) = without_visibility(line.trim_start()).strip_prefix("mod ")
                && is_test_path(&identifier(rest))
            {
                let attributes = enclosing_attributes(&product.lines, at);
                assert!(
                    TEST.iter().any(|test| attributes.contains(test)),
                    "src/{}:{}: a test-named module outside #[cfg(test)]",
                    product.path,
                    at + 1
                );
            }
        }
    }

    let mut problems = Vec::new();
    // Each function's count of process starts, and its body.
    let mut functions_found: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    for spawn in spawns(&sources) {
        match spawn.function {
            None => problems.push(format!(
                "src/{}:{}: a process start or command type outside a function",
                spawn.file, spawn.line
            )),
            Some(function) => {
                let entry = functions_found
                    .entry((spawn.file, function.name))
                    .or_insert((0, function.body));
                entry.0 += usize::from(spawn.starts);
            }
        }
    }
    for ((file, name), (starts, body)) in &functions_found {
        if !SPAWNS.contains(&(file.as_str(), name.as_str())) {
            problems.push(format!(
                "src/{file}: `{name}` starts a process or names its command and is not listed; on macOS it must run the close-on-exec sweep (#4654)"
            ));
            continue;
        }
        let sweeps = body.matches(SWEEP).count()
            + PREPARATIONS
                .iter()
                .map(|(_, _, call)| body.matches(call).count())
                .sum::<usize>();
        if sweeps < (*starts).max(1) {
            problems.push(format!(
                "src/{file}: `{name}` starts {starts} process(es) and runs the close-on-exec sweep {sweeps} time(s)"
            ));
        }
    }
    for (file, name) in SPAWNS {
        if !functions_found.contains_key(&(file.to_owned(), name.to_owned())) {
            problems.push(format!(
                "src/{file}: `{name}` is listed but starts no process"
            ));
        }
    }
    for (file, name, _) in PREPARATIONS {
        let source = source(file);
        let definitions: Vec<_> = functions(&source.lines)
            .into_iter()
            .filter(|function| function.name == name && !source.skipped(function.start))
            .collect();
        if definitions.is_empty() {
            problems.push(format!("src/{file}: no macOS `{name}`"));
        }
        for function in definitions {
            if !source.lines[function.start..=function.end]
                .join("\n")
                .contains(SWEEP)
            {
                problems.push(format!(
                    "src/{file}: the macOS `{name}` lost the close-on-exec sweep"
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_guard_follows_aliases_imports_and_paths_and_skips_only_what_macos_never_compiles() {
    let starts = r##"use std::process::Command as Cmd;
use libc::fork;

type Launcher = tokio::process::Command;

fn direct() {
    let _ = std::process::Command::new("/bin/true");
}

fn aliased() {
    let _ = Cmd::new("/bin/true");
}

fn typed() {
    let _ = Launcher::new("/bin/true");
}

fn forked() {
    // SAFETY: none; a fixture.
    let _ = unsafe { libc::fork() };
}

fn spawned() {
    let _ = libc::posix_spawn;
}

fn named(
    command: &mut std::process::Command,
) {
}

fn harmless(command: &mut Command) -> String {
    use std::os::unix::process::CommandExt as _;
    // Command::new("/bin/true") in a comment.
    let _ = MyCommand::new();
    fork()
}

#[cfg(target_os = "linux")]
fn linux_only() {
    let _ = Cmd::new("/bin/true");
}

impl Thing {
    #[cfg(target_os = "linux")]
    fn linux_method(&self) {
        let _ = Cmd::new("/bin/true");
    }

    fn method(&self) {
        let _ = Cmd::new("/bin/true");
    }
}

#[cfg(test)]
mod tests {
    fn helper() {
        let _ = Cmd::new("/bin/true");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    const SCRIPT: &str = r#"
if(mode){
Command::new("/bin/true")
}"#;

    fn after_a_script() {
        let _ = Cmd::new("/bin/true");
    }
}

const NOTE: &str = "a string across lines
Command::new(\"/bin/true\")";

fn quoted() {
    let _ = ('"', 'a', '\'', b'"');
    let _ = Cmd::new("/bin/true");
}

use libc::*;
"##;
    let elsewhere = "fn elsewhere() {\n    let _ = Cmd::new(\"/bin/true\");\n}\n";
    let sources = [
        Source::new("a.rs", starts),
        Source::new("b.rs", elsewhere),
        Source::new("a_tests.rs", elsewhere),
        Source::new("linux/c.rs", elsewhere),
    ];
    let found: Vec<(String, usize, Option<String>, bool)> = spawns(&sources)
        .into_iter()
        .map(|spawn| {
            (
                spawn.file,
                spawn.line,
                spawn.function.map(|function| function.name),
                spawn.starts,
            )
        })
        .collect();
    let expected = [
        ("a.rs", 2, None, true),
        ("a.rs", 4, None, false),
        ("a.rs", 7, Some("direct"), true),
        ("a.rs", 11, Some("aliased"), true),
        ("a.rs", 15, Some("typed"), true),
        ("a.rs", 20, Some("forked"), true),
        ("a.rs", 24, Some("spawned"), true),
        ("a.rs", 28, Some("named"), false),
        ("a.rs", 51, Some("method"), true),
        ("a.rs", 79, Some("quoted"), true),
        ("a.rs", 82, None, true),
        ("b.rs", 2, Some("elsewhere"), true),
    ]
    .map(|(file, line, function, starts)| {
        (file.to_owned(), line, function.map(str::to_owned), starts)
    });
    assert_eq!(found, expected);
}

/// One source file, by its path under `src/`.
struct Source {
    path: String,
    lines: Vec<String>,
}

impl Source {
    fn new(path: &str, text: &str) -> Self {
        Self {
            path: path.to_owned(),
            lines: code_lines(text),
        }
    }

    /// Whether macOS never compiles line `at`.
    fn skipped(&self, at: usize) -> bool {
        let attributes = enclosing_attributes(&self.lines, at);
        self.path.starts_with("linux/")
            || attributes.contains(LINUX)
            || TEST.iter().any(|test| attributes.contains(test))
    }
}

/// A function with a body: its name and the lines from its declaration to
/// its closing brace.
struct FunctionLines {
    name: String,
    start: usize,
    end: usize,
}

/// A line macOS compiles that starts a process or names `process::Command`.
struct Spawn {
    file: String,
    line: usize,
    /// The innermost function around it.
    function: Option<Function>,
    /// Whether it starts a process, rather than only naming its command.
    starts: bool,
}

struct Function {
    name: String,
    body: String,
}

fn read_sources(directory: &Path, root: &Path, sources: &mut Vec<Source>) {
    let mut entries: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            read_sources(&path, root, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
            sources.push(Source::new(
                relative,
                &std::fs::read_to_string(&path).unwrap(),
            ));
        }
    }
}

fn spawns(sources: &[Source]) -> Vec<Spawn> {
    let product: Vec<&Source> = sources
        .iter()
        .filter(|source| !is_test_path(&source.path))
        .collect();
    // Every other name the crate gives a command type, from any file.
    let mut aliases = BTreeSet::new();
    for source in &product {
        let uses = use_declarations(&source.lines);
        for (at, line) in source.lines.iter().enumerate() {
            if is_comment(line) {
                continue;
            }
            let alias = if uses[at] {
                line.match_indices("Command as ")
                    .find(|(position, _)| !line[..*position].ends_with(is_identifier))
                    .map(|(position, pattern)| &line[position + pattern.len()..])
            } else {
                without_visibility(line.trim_start())
                    .strip_prefix("type ")
                    .filter(|rest| {
                        rest.split_once('=')
                            .is_some_and(|(_, value)| has_word(value, "Command"))
                    })
            };
            if let Some(name) = alias.map(identifier)
                && !name.is_empty()
                && !source.skipped(at)
            {
                aliases.insert(name);
            }
        }
    }
    let mut found = Vec::new();
    for source in &product {
        let uses = use_declarations(&source.lines);
        let functions = functions(&source.lines);
        for (at, line) in source.lines.iter().enumerate() {
            if is_comment(line) {
                continue;
            }
            let starts = calls(line, "Command::new")
                || aliases
                    .iter()
                    .any(|alias| calls(line, &format!("{alias}::new")))
                || line.contains("::fork(")
                || line.contains("::vfork(")
                || line.contains("posix_spawn")
                || (uses[at]
                    && (has_word(line, "fork")
                        || has_word(line, "vfork")
                        || FORK_GLOBS.iter().any(|glob| line.contains(glob))));
            let names = !uses[at] && has_word(line, "process::Command");
            if !(starts || names) || source.skipped(at) {
                continue;
            }
            let function = functions
                .iter()
                .filter(|function| function.start <= at && at <= function.end)
                .max_by_key(|function| function.start)
                .map(|function| Function {
                    name: function.name.clone(),
                    body: source.lines[function.start + 1..=function.end].join("\n"),
                });
            found.push(Spawn {
                file: source.path.clone(),
                line: at + 1,
                function,
                starts,
            });
        }
    }
    found
}

/// `text`'s lines without the inside of any string that spans lines, so a
/// script or a profile in a raw string never reads as code. A string on one
/// line stays, as `#[cfg(target_os = "linux")]` needs; so do whole-line
/// comments. Trailing and block comments go.
fn code_lines(text: &str) -> Vec<String> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        Text,
        Raw(usize),
        Comment,
    }
    let mut state = State::Code;
    let mut lines = Vec::new();
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        let mut kept = String::new();
        // Where the inside of a string opened on this line begins in `kept`.
        let mut opened = None;
        let mut at = 0;
        while at < chars.len() {
            let c = chars[at];
            let next = chars.get(at + 1).copied();
            match state {
                State::Code if c == '/' && next == Some('/') => {
                    if kept.trim().is_empty() {
                        kept.extend(&chars[at..]);
                    }
                    break;
                }
                State::Code if c == '/' && next == Some('*') => {
                    state = State::Comment;
                    at += 2;
                }
                State::Code if c == '\'' => {
                    // A character literal, or a lifetime or label.
                    let end = if next == Some('\\') {
                        (at + 3..chars.len()).find(|end| chars[*end] == '\'')
                    } else {
                        (chars.get(at + 2) == Some(&'\'')).then_some(at + 2)
                    }
                    .unwrap_or(at);
                    kept.extend(&chars[at..=end]);
                    at = end + 1;
                }
                State::Code if c == '"' => {
                    kept.push(c);
                    state = State::Text;
                    opened = Some(kept.len());
                    at += 1;
                }
                State::Code if c == 'r' && starts_raw_string(&chars, at).is_some() => {
                    let hashes = starts_raw_string(&chars, at).unwrap_or(0);
                    kept.extend(&chars[at..at + hashes + 2]);
                    state = State::Raw(hashes);
                    opened = Some(kept.len());
                    at += hashes + 2;
                }
                State::Code => {
                    kept.push(c);
                    at += 1;
                }
                State::Text if c == '\\' => {
                    if opened.is_some() {
                        kept.extend(chars.get(at..at + 2).unwrap_or(&chars[at..]));
                    }
                    at += 2;
                }
                State::Raw(hashes)
                    if c == '"'
                        && chars.len() > at + hashes
                        && chars[at + 1..=at + hashes].iter().all(|c| *c == '#') =>
                {
                    kept.extend(&chars[at..=at + hashes]);
                    state = State::Code;
                    opened = None;
                    at += hashes + 1;
                }
                State::Text if c == '"' => {
                    kept.push(c);
                    state = State::Code;
                    opened = None;
                    at += 1;
                }
                State::Text | State::Raw(_) => {
                    if opened.is_some() {
                        kept.push(c);
                    }
                    at += 1;
                }
                State::Comment if c == '*' && next == Some('/') => {
                    state = State::Code;
                    at += 2;
                }
                State::Comment => at += 1,
            }
        }
        if let (Some(opened), State::Text | State::Raw(_)) = (opened, state) {
            kept.truncate(opened);
        }
        lines.push(kept);
    }
    lines
}

/// The number of `#`s of a raw string that starts at `at`, if one does.
fn starts_raw_string(chars: &[char], at: usize) -> Option<usize> {
    let before = |offset: usize| at.checked_sub(offset).map(|at| chars[at]);
    let prefix_ends = !before(1).is_some_and(is_identifier)
        || (before(1) == Some('b') && !before(2).is_some_and(is_identifier));
    let hashes = chars[at + 1..].iter().take_while(|c| **c == '#').count();
    (prefix_ends && chars.get(at + 1 + hashes) == Some(&'"')).then_some(hashes)
}

/// Every function with a body, as rustfmt lays it out: the body closes on a
/// line of its own at the declaration's indentation.
fn functions(lines: &[String]) -> Vec<FunctionLines> {
    let mut found = Vec::new();
    for (start, line) in lines.iter().enumerate() {
        let Some(name) = declared_function(line) else {
            continue;
        };
        let Some(open) = (start..lines.len()).find(|at| {
            let line = lines[*at].trim_end();
            line.ends_with('{') || line.ends_with(';') || line.ends_with('}')
        }) else {
            continue;
        };
        let open_line = lines[open].trim_end();
        if open_line.ends_with(';') {
            // A declaration without a body.
            continue;
        }
        let end = if open_line.ends_with('}') {
            open
        } else {
            let close = format!("{}}}", " ".repeat(indentation(line)));
            (open + 1..lines.len())
                .find(|at| lines[*at] == close)
                .unwrap_or(lines.len() - 1)
        };
        found.push(FunctionLines { name, start, end });
    }
    found
}

/// The name of the function a line declares, if it does.
fn declared_function(line: &str) -> Option<String> {
    let mut rest = without_visibility(line.trim_start());
    for qualifier in ["const ", "async ", "unsafe ", "extern \"C\" "] {
        rest = rest.strip_prefix(qualifier).unwrap_or(rest);
    }
    let name = identifier(rest.strip_prefix("fn ")?);
    (!name.is_empty()).then_some(name)
}

/// The attributes of the item or statement at `at` and of every block around
/// it, without comments.
fn enclosing_attributes(lines: &[String], at: usize) -> String {
    let mut text = String::new();
    let mut at = at;
    loop {
        let start = item_start(lines, at);
        text.push_str(&attributes(lines, start));
        text.push('\n');
        let depth = indentation(&lines[start]);
        let header = (0..start).rev().find(|header| {
            let line = &lines[*header];
            !line.trim().is_empty() && indentation(line) < depth && line.trim_end().ends_with('{')
        });
        match header {
            Some(header) => at = header,
            None => return text,
        }
    }
}

/// The first line of the item or statement that `at` ends or continues: a
/// multi-line signature's `fn` line, not its `) -> T {`.
fn item_start(lines: &[String], at: usize) -> usize {
    let depth = indentation(&lines[at]);
    let mut start = at;
    while start > 0 && (continues(&lines[start]) || indentation(&lines[start]) > depth) {
        start -= 1;
    }
    start
}

fn continues(line: &str) -> bool {
    let line = line.trim_start();
    [")", "{", "where", "->"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

/// The attribute lines above the item that starts at `start`.
fn attributes(lines: &[String], start: usize) -> String {
    let depth = indentation(&lines[start]);
    let mut first = start;
    while first > 0 {
        let above = &lines[first - 1];
        let trimmed = above.trim_start();
        let attribute = trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with(')')
            || (!trimmed.is_empty() && indentation(above) > depth);
        if !attribute {
            break;
        }
        first -= 1;
    }
    lines[first..start]
        .iter()
        .filter(|line| !is_comment(line))
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Which lines belong to a `use` declaration.
fn use_declarations(lines: &[String]) -> Vec<bool> {
    let mut inside = false;
    lines
        .iter()
        .map(|line| {
            inside = inside || without_visibility(line.trim_start()).starts_with("use ");
            let this = inside;
            inside = inside && !line.contains(';');
            this
        })
        .collect()
}

/// A test module's file, or one inside a test module's directory.
fn is_test_path(path: &str) -> bool {
    path.split('/').any(|part| {
        let stem = part.strip_suffix(".rs").unwrap_or(part);
        stem == "tests" || stem.ends_with("_tests")
    })
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn without_visibility(line: &str) -> &str {
    ["pub(crate) ", "pub(super) ", "pub "]
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
        .unwrap_or(line)
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn identifier(text: &str) -> String {
    text.chars().take_while(|c| is_identifier(*c)).collect()
}

fn is_identifier(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `line` calls `path`, with nothing of an identifier before it.
fn calls(line: &str, path: &str) -> bool {
    line.match_indices(&format!("{path}("))
        .any(|(position, _)| !line[..position].ends_with(is_identifier))
}

fn has_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(position, _)| {
        !line[..position].ends_with(is_identifier)
            && !line[position + word.len()..].starts_with(is_identifier)
    })
}
