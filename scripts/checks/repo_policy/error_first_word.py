"""A CLI error never begins with a value.

The CLI prints a failed command's error as one sentence and raises its first
letter (crates/codewire-cli/src/error_report.rs). Errors are lowercase
fragments that compose, so the printer only has to capitalise the outermost
one. When that fragment begins with a value, the printer changes the value:
an environment named `cwcli-msg-walk` printed as `Cwcli-msg-walk has 2 running
sessions`. A message that begins with a literal word has only a word to raise.

It reads the tracked Rust files under crates/codewire-cli/src/, except test
code: files named tests.rs or *_tests.rs, files under a tests/ directory, and
`#[cfg(test)] mod NAME { ... }` blocks. It fails a format string that begins
with an interpolation (`{`, not the escaped `{{`) in `anyhow!(...)`,
`bail!(...)`, `ensure!(COND, ...)` (the message after the condition),
`.context(format!(...))`, `.with_context(|| format!(...))` and
`#[error("...")]`. A string that is exactly one placeholder (`"{}"`,
`"{error:#}"`, `"{SOME_CONST}"`) passes: it forwards another message
unchanged, and that message is checked where it is written.
"""

from .shared import *

SCANNED = "crates/codewire-cli/src/"
SINGLE_PLACEHOLDER = re.compile(r"\{[^{}]*\}")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RAW_STRING = re.compile(r'(?:br|r)(#*)"')
STRING_ESCAPE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]*\}|\n\s*|.)", re.S)
CHAR_LITERAL = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]*\}|.)|[^\\'\n])'")
MACROS = {"anyhow", "bail"}


def scanned(path: str) -> bool:
    if not path.startswith(SCANNED) or not path.endswith(".rs"):
        return False
    parts = path.split("/")
    name = parts[-1]
    return "tests" not in parts[:-1] and name != "tests.rs" and not name.endswith("_tests.rs")


def tokens(text: str) -> list[tuple[str, str, int]]:
    """Rust tokens as (kind, value, offset); kind is ident, string or punct.

    A string's value is its contents with escapes left as written, which keeps
    `{{` and `{` apart. Comments and whitespace are dropped.
    """
    out: list[tuple[str, str, int]] = []
    index, end = 0, len(text)
    while index < end:
        char = text[index]
        if char.isspace():
            index += 1
        elif text.startswith("//", index):
            newline = text.find("\n", index)
            index = end if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            depth, index = 1, index + 2
            while index < end and depth:
                if text.startswith("/*", index):
                    depth, index = depth + 1, index + 2
                elif text.startswith("*/", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
        elif raw := RAW_STRING.match(text, index):
            close = '"' + raw.group(1)
            stop = text.find(close, raw.end())
            stop = end if stop < 0 else stop
            out.append(("string", text[raw.end():stop], index))
            index = stop + len(close)
        elif char == '"' or text.startswith('b"', index):
            start = index
            index += 1 if char == '"' else 2
            body = index
            while index < end and text[index] != '"':
                if text[index] == "\\":
                    escape = STRING_ESCAPE.match(text, index)
                    index = escape.end() if escape else index + 1
                else:
                    index += 1
            out.append(("string", text[body:index], start))
            index += 1
        elif char == "'":
            literal = CHAR_LITERAL.match(text, index)
            if literal:
                out.append(("punct", "'", index))
                index = literal.end()
            else:  # a lifetime or label
                index += 1
        elif ident := IDENT.match(text, index):
            out.append(("ident", ident.group(), index))
            index = ident.end()
        else:
            out.append(("punct", char, index))
            index += 1
    return out


def without_test_modules(toks: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    """Drop `#[cfg(test)]` modules, with any attributes between, to their closing brace."""
    values = [value for _, value, _ in toks]
    kept, index = [], 0
    while index < len(toks):
        if values[index:index + 7] == ["#", "[", "cfg", "(", "test", ")", "]"]:
            probe = index + 7
            while values[probe:probe + 2] == ["#", "["]:
                probe = closing(values, probe + 1, "[", "]") + 1
            if values[probe:probe + 1] == ["pub"]:
                probe += 1
            if values[probe:probe + 1] == ["mod"] and values[probe + 2:probe + 3] == ["{"]:
                index = closing(values, probe + 2, "{", "}") + 1
                continue
        kept.append(toks[index])
        index += 1
    return kept


def closing(values: list[str], start: int, opening: str, close: str) -> int:
    """The index of the bracket closing the one at START, or the last index."""
    depth = 0
    for index in range(start, len(values)):
        if values[index] == opening:
            depth += 1
        elif values[index] == close:
            depth -= 1
            if depth == 0:
                return index
    return len(values) - 1


def messages(toks: list[tuple[str, str, int]]) -> list[tuple[str, int]]:
    """The (format string, offset) of each error message the policy reads."""
    kinds = [kind for kind, _, _ in toks]
    values = [value for _, value, _ in toks]

    def string_at(index: int) -> tuple[str, int] | None:
        if index < len(toks) and kinds[index] == "string":
            return values[index], toks[index][2]
        return None

    def format_at(index: int) -> tuple[str, int] | None:
        if values[index:index + 3] == ["format", "!", "("]:
            return string_at(index + 3)
        return None

    found = []
    for index, (kind, value, _) in enumerate(toks):
        message = None
        if kind != "ident":
            continue
        if value in MACROS and values[index + 1:index + 3] == ["!", "("]:
            message = string_at(index + 3)
        elif value == "ensure" and values[index + 1:index + 3] == ["!", "("]:
            depth = 0
            for probe in range(index + 2, len(toks)):
                if values[probe] in "([{" and kinds[probe] == "punct":
                    depth += 1
                elif values[probe] in ")]}" and kinds[probe] == "punct":
                    depth -= 1
                    if depth == 0:
                        break
                elif values[probe] == "," and kinds[probe] == "punct" and depth == 1:
                    message = string_at(probe + 1)
                    break
        elif index and values[index - 1] == "." and values[index + 1:index + 2] == ["("]:
            if value == "context":
                message = format_at(index + 2)
            elif value == "with_context":
                probe = index + 2
                if values[probe:probe + 1] == ["move"]:
                    probe += 1
                if values[probe:probe + 2] == ["|", "|"]:
                    probe += 2
                    if values[probe:probe + 1] == ["{"]:
                        probe += 1
                    message = format_at(probe)
        elif (value == "error" and index >= 2 and values[index - 2:index] == ["#", "["]
              and values[index + 1:index + 2] == ["("]):
            message = string_at(index + 2)
        if message is not None:
            found.append(message)
    return found


def begins_with_value(message: str) -> bool:
    if not message.startswith("{") or message.startswith("{{"):
        return False
    return not SINGLE_PLACEHOLDER.fullmatch(message)


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths to their text; unscanned paths are ignored."""
    failures: list[str] = []
    for path, text in sorted(sources.items()):
        if not scanned(path):
            continue
        for message, offset in messages(without_test_modules(tokens(text))):
            if begins_with_value(message):
                line = text.count("\n", 0, offset) + 1
                failures.append(f'{path}:{line}: "{" ".join(message.split())[:120]}"')
    return failures


def self_test() -> None:
    src = "crates/codewire-cli/src/commands/x.rs"
    for label, path, source, expected in [
        ("anyhow", src, 'let e = anyhow!("{name} is not running");', 1),
        ("anyhow by path", src, 'return Err(anyhow::anyhow!("{name} is not running"));', 1),
        ("bail", src, 'bail!("{} already exists", path.display());', 1),
        ("ensure", src, 'ensure!(!label.is_empty(), "{label} must be non-empty");', 1),
        ("ensure with a call", src, 'ensure!(f(a, "x"), "{label} must be non-empty");', 1),
        ("context", src, 'x.context(format!("{host} didn\'t answer"))?;', 1),
        ("with_context", src, 'x.with_context(|| format!("{} names no file", p.display()))?;', 1),
        ("with_context move block", src, 'x.with_context(move || { format!("{p} names no file") })?;', 1),
        ("error attribute", src, '#[derive(Error)]\nenum E {\n    #[error("{0} is not a port")]\n    Port(u16),\n}', 1),
        ("multi-line bail", src, 'bail!(\n    "{x} is running; \\\n     stop it first",\n    x = name,\n);', 1),
        ("escaped quote", src, 'bail!("the name \\"{name}\\" is taken");\nbail!("{name} \\"x\\"");', 1),
        ("raw string", src, 'bail!(r#"{name} has a "quote""#);', 1),
        ("forward", src, 'bail!("{}", message);\nbail!("{error:#}");\nbail!("{NOEL_HOST_ONLY}");', 0),
        ("forward in context", src, 'x.with_context(|| format!("{}", status.message()))?;', 0),
        ("word first", src, 'bail!("environment {name} is not running");', 0),
        ("escaped brace", src, 'bail!("{{ needs its }}");', 0),
        ("plain context", src, 'x.context("{name} literal")?;', 0),
        ("other macro", src, 'let s = format!("{name} is running");\nprintln!("{name}");', 0),
        ("comment", src, '// bail!("{name} is running");\n/* anyhow!("{x} y") */', 0),
        ("char literal", src, "let q = '\"';\nbail!(\"{name} is running\");", 1),
        ("lifetime", src, "fn f<'a>(x: &'a str) { bail!(\"{x} is running\"); }", 1),
        ("tests file", "crates/codewire-cli/src/commands/tests.rs", 'bail!("{name} x");', 0),
        ("tests suffix", "crates/codewire-cli/src/commands/x_tests.rs", 'bail!("{name} x");', 0),
        ("tests directory", "crates/codewire-cli/src/commands/tests/x.rs", 'bail!("{name} x");', 0),
        ("inline test module", src,
         'fn f() {}\n\n#[cfg(test)]\nmod tests {\n    fn g() { bail!("{name} x"); }\n}\n', 0),
        ("code after a test module", src,
         '#[cfg(test)]\n#[allow(x)]\nmod tests {\n    fn g() { bail!("{name} x"); }\n}\nfn h() { bail!("{y} z"); }\n', 1),
        ("another crate", "crates/codewire-daemon/src/x.rs", 'bail!("{name} x");', 0),
        ("not rust", "crates/codewire-cli/src/x.md", 'bail!("{name} x");', 0),
    ]:
        failures = violations_from({path: source})
        assert len(failures) == expected, f"{label}: {failures}"


def check_error_first_word(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("Error first word self-test: OK")
        return 0
    sources = {}
    for path in git_source_files():
        if scanned(path) and not (ROOT / path).is_symlink():
            try:
                sources[path] = read_text(path)
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                continue
    failures = violations_from(sources)
    for failure in failures:
        print(f"::error::Error first word: {failure}: begin the message with a word; the CLI "
              "capitalises an error's first letter, which changes a value written first",
              file=sys.stderr)
    if failures:
        return 1
    print(f"Error first word: OK ({len(sources)} Rust files read)")
    return 0
