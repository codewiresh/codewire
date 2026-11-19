"""The credentials CLI uses only the words in docs/GLOSSARY.md (#4938).

One thing had several names on screen ("access profile", "credential
profile", "profile"; "platform", "cloud", "your Codewire account") and
internal words reached it ("protected value", "hard expiry", "OAuth"). The
glossary's "Words users see: credentials" fixes the words; this fails on a
banned word in the text the credentials commands show.

The files, the banned words with the word to use, and the exceptions are in
scripts/checks/contracts/credential-words.json, so the dashboard's files and
words can join the same list.

What is checked, in each listed Rust file outside its tests:
- a string literal with a space in it, or one that ends a sentence (`.`, `?`
  or `!`), so prose and not an identifier, a key or a protocol name, and not
  a URL;
- whose statement shows it to a person: a print or `write!` macro, `bail!`,
  `anyhow!`, `ensure!`, an error's `.context(` (a context is shown in the
  error chain), `format!` (messages are built with it), a `const` (these files
  keep their messages in constants), `with_next_step`, a clap `help`,
  `about` or `long_about`, or a picker or prompt (`Choice::new`, `choose`,
  `confirm`, `text`, a `prompt_*` helper);
- and not a `tracing` macro's message, which only a log reads.
A statement runs back from the literal to the nearest `;`, `{` or `}` in the
code with every literal's contents blanked, so a brace inside an earlier
literal never ends it. A banned word's plural counts as the word.

An exception names a file and, optionally, the functions or items (a glob on
the name) whose literals it skips, or a text the literal contains, with the
reason. Each one says when it is removed, and a text exception that matches
nothing in its file fails the check, so it goes once its code changes.
"""

from __future__ import annotations

import fnmatch

from .shared import *

CONTRACT_REL = "scripts/checks/contracts/credential-words.json"

SINKS = re.compile(
    r"\b(?:e?print(?:ln)?!|write(?:ln)?!|bail!|anyhow!|ensure!|format!|const\b|with_next_step|"
    r"with_context|help\s*=|about\s*=|long_about\s*=)|\.context\("
    # A picker's labels and its questions: guided::Choice, choose, confirm,
    # text, and the prompt_* helpers that ask at the terminal.
    r"|\bChoice::new\(|\b(?:choose|confirm|text)\(|\bprompt_[a-z_]+\("
)
LOG_ONLY = re.compile(r"\b(?:tracing::|debug!|trace!|info!|warn!|error!)")
LITERAL = re.compile(r'(?<![A-Za-z0-9_])(r#*)?"((?:[^"\\]|\\.)*)"', re.S)
ITEM = re.compile(r"\b(?:fn|struct|enum|impl|mod)\s+([A-Za-z_][A-Za-z0-9_]*)")


def strip_comments(source: str) -> str:
    """`source` with comments blanked to spaces, keeping offsets and lines."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c == '"' or (c == "r" and source[i + 1 : i + 2] in ('"', "#") and not source[i - 1 : i].isalnum()):
            match = LITERAL.match(source, i)
            if match:
                i = match.end()
                continue
        if c == "'" and source[i + 1 : i + 2] == '"' and source[i + 2 : i + 3] == "'":
            i += 3
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            out[i:end] = " " * (end - i)
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out[i:end] = [ch if ch == "\n" else " " for ch in source[i:end]]
            i = end
            continue
        i += 1
    return "".join(out)


def test_start(source: str) -> int:
    """Where the file's own test module starts, or its end."""
    match = re.search(r"#\[cfg\(test\)\]\s*mod\s+tests\b", source)
    return match.start() if match else len(source)


def item_spans(source: str) -> list[tuple[str, int, int]]:
    """Each named item's name and the span of its body, braces matched."""
    spans = []
    for match in ITEM.finditer(source):
        start = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if start < 0 or (0 <= semicolon < start):
            continue
        depth, i = 0, start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif source[i] == '"':
                literal = LITERAL.match(source, i)
                if literal:
                    i = literal.end()
                    continue
            i += 1
        spans.append((match.group(1), match.start(), i))
    return spans


def blank_literals(source: str) -> str:
    """`source` with every string literal's contents blanked to spaces, so a
    brace or a sink word inside a literal never reads as code."""
    out = list(source)
    for match in LITERAL.finditer(source):
        start, stop = match.start(2), match.end(2)
        out[start:stop] = [ch if ch == "\n" else " " for ch in source[start:stop]]
    return "".join(out)


def statement_before(source: str, offset: int) -> str:
    """The text from the statement's start up to `offset`, in a `source`
    whose literals are blanked."""
    start = max(source.rfind(";", 0, offset), source.rfind("{", 0, offset), source.rfind("}", 0, offset))
    return source[start + 1 : offset]


def shown_literals(source: str) -> list[tuple[int, int, str]]:
    """(offset, line, text) of every literal the file shows a person."""
    code = strip_comments(source)
    structure = blank_literals(code)
    end = test_start(code)
    found = []
    for match in LITERAL.finditer(code, 0, end):
        text = match.group(2)
        sentence = " " in text or text.rstrip().endswith((".", "?", "!"))
        if not sentence or text.lstrip().startswith(("http://", "https://")):
            continue
        before = statement_before(structure, match.start())
        if LOG_ONLY.search(before) or not SINKS.search(before):
            continue
        found.append((match.start(), code.count("\n", 0, match.start()) + 1, text))
    return found


def excepted(exceptions: list[dict], rel: str, offset: int, text: str, spans) -> bool:
    for exception in exceptions:
        if exception["file"] != rel:
            continue
        if "text" in exception and exception["text"] in text:
            return True
        names = exception.get("items")
        if names is None and "text" not in exception:
            return True
        if names and any(
            any(fnmatch.fnmatchcase(name, pattern) for pattern in names) and start <= offset <= stop
            for name, start, stop in spans
        ):
            return True
    return False


def scan(contract: dict, read) -> tuple[list[str], int]:
    """Failures, and how many shown literals were read."""
    # A plural counts too: "access profiles" is the same word.
    words = [
        (re.compile(rf"(?<![A-Za-z]){re.escape(word)}(?:e?s)?(?![A-Za-z])", re.I), word, use)
        for word, use in contract["banned"].items()
    ]
    failures, read_count = [], 0
    shown_by_file: dict[str, list[str]] = {}
    for entry in contract["files"]:
        rel = entry["path"]
        source = read(rel)
        spans = item_spans(strip_comments(source))
        only = entry.get("items")
        for offset, line, text in shown_literals(source):
            if only and not any(
                any(fnmatch.fnmatchcase(name, pattern) for pattern in only) and start <= offset <= stop
                for name, start, stop in spans
            ):
                continue
            read_count += 1
            shown_by_file.setdefault(rel, []).append(text)
            for pattern, word, use in words:
                if pattern.search(text) and not excepted(contract["exceptions"], rel, offset, text, spans):
                    failures.append(f"{rel}:{line}: \"{word}\" on screen; use {use}")
    # A text exception outlives the code it covered once that code changes,
    # as when another change lands first; it then matches nothing and goes.
    for exception in contract["exceptions"]:
        if "text" in exception and not any(
            exception["text"] in text for text in shown_by_file.get(exception["file"], [])
        ):
            failures.append(
                f"{CONTRACT_REL}: the exception for {exception['file']} text "
                f"{exception['text']!r} matches nothing; remove it"
            )
    return failures, read_count


def self_test() -> list[str]:
    contract = {
        "banned": {"access profile": "\"profile\"", "OAuth": "\"sign-in\"", "canceled": "\"cancelled\""},
        "files": [{"path": "a.rs"}, {"path": "b.rs", "items": ["Credential*"]}],
        "exceptions": [
            {"file": "a.rs", "items": ["connect_*"], "reason": "track B"},
            {"file": "a.rs", "text": "kept OAuth", "reason": "a test of the exception"},
            {"file": "a.rs", "text": "a line since rewritten", "reason": "stale"},
        ],
    }
    files = {
        "a.rs": (
            'fn shown() { anyhow::bail!("no access profile named {name}"); }\n'
            'fn fine() { println!("no profile named {name}"); }\n'
            '// eprintln!("an access profile in a comment")\n'
            'fn logged() { tracing::debug!("access profile refreshed"); }\n'
            'fn key() { let x = map.get("access profile"); }\n'
            'fn connect_codex() { eprintln!("OAuth sign-in"); }\n'
            'fn kept() { eprintln!("a kept OAuth line"); }\n'
            'fn chained() { let x = y\n        .context("read the access profile")?; }\n'
            'fn stopped() { eprintln!("Canceled."); }\n'
            'fn keyed() { eprintln!("{}", "canceled"); }\n'
            'fn spaced() { eprintln!("{} {}", style, "no access profile here"); }\n'
            'fn picked() { let c = vec![Choice::new("OAuth app", "pick it")]; }\n'
            'fn plural() { let x = y.context("list local access profiles")?; }\n'
            'const LINK: &str = "https://example.test/oauth thing";\n'
            '#[cfg(test)]\nmod tests { fn t() { assert_eq!(x, "no access profile"); } }\n'
        ),
        "b.rs": (
            'pub(crate) enum CredentialsCommand {\n'
            '    #[command(about = "Set one OAuth identity")]\n    Set,\n}\n'
            'pub(crate) struct Other {\n    #[arg(help = "an OAuth flag elsewhere")]\n    x: bool,\n}\n'
        ),
    }
    failures, _ = scan(contract, files.__getitem__)
    wanted = [
        'a.rs:1: "access profile" on screen; use "profile"',
        'a.rs:9: "access profile" on screen; use "profile"',
        'a.rs:10: "canceled" on screen; use "cancelled"',
        'a.rs:12: "access profile" on screen; use "profile"',
        'a.rs:13: "OAuth" on screen; use "sign-in"',
        'a.rs:14: "access profile" on screen; use "profile"',
        'b.rs:2: "OAuth" on screen; use "sign-in"',
        f"{CONTRACT_REL}: the exception for a.rs text 'a line since rewritten' matches nothing; remove it",
    ]
    if failures != wanted:
        return [f"credential words self-test: expected {wanted}, got {failures}"]
    return []


def check_credential_words(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("credential words", self_test()):
            return 1
        print("credential words: OK (self-test)")
        return 0
    contract = json.loads((ROOT / CONTRACT_REL).read_text(encoding="utf-8"))
    failures, read_count = scan(contract, lambda rel: (ROOT / rel).read_text(encoding="utf-8"))
    for entry in contract["exceptions"]:
        if not entry.get("reason"):
            failures.append(f"{CONTRACT_REL}: the exception for {entry['file']} gives no reason")
    if report("credential words", failures):
        print(
            "credential words: the words are in docs/GLOSSARY.md, \"Words users see: credentials\"",
            file=sys.stderr,
        )
        return 1
    print(f"credential words: OK ({len(contract['files'])} files, {read_count} shown texts)")
    return 0
