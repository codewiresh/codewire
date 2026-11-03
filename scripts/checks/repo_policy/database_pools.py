"""Every production Postgres pool closes a connection left inside a transaction.

A request cancelled while sqlx 0.8.6 waits for the reply to BEGIN returns its
connection to the pool with a transaction open that sqlx cannot see. Later
statements on it report success without committing, and an unrelated ROLLBACK
discards them (#3927). codewire_server_core::db::checked_pool_options closes
such a connection on release, so production code builds its pools from that.
A pool built any other way, or a second after_release that would replace the
check, fails here. Tests and the short-lived binaries in REVIEWED_POOLS serve
no requests and may build their own.
"""

from .shared import *

CHECKED_OPTIONS_OWNER = "crates/codewire-server-core/src/db.rs"
# Each reviewed file is a short-lived binary or test support, not a service.
REVIEWED_POOLS = frozenset({
    "crates/codewire-billing/src/bin/runtime-smoke.rs",
    "crates/codewire-billing/src/bin/runtime_smoke/dev_receipt.rs",
    "crates/codewire-orchestration/src/api/runtime_lease_test_support.rs",
    "crates/codewire-orchestration/src/bin/deploy-shape-smoke.rs",
    "crates/codewire-orchestration/src/bin/log-stream-smoke.rs",
    "crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs",
    "crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs",
    "crates/codewire-orchestration/src/bin/temporal-smoke.rs",
})
UNCHECKED_POOL = re.compile(
    r"\b(?:Pg)?PoolOptions\s*(?:::\s*<[^>]*>\s*)?::\s*(?:new|default)\b"
    r"|\b(?:PgPool|Pool\s*::\s*<[^>]*>)\s*::\s*connect(?:_with|_lazy|_lazy_with)?\b"
    r"|\.\s*after_release\b"
)
TEST_ATTRIBUTE = re.compile(r"#\s*\[\s*(?:cfg\s*\(\s*(?:all\s*\(\s*)?test\b|(?:\w+\s*::\s*)?test\b)[^\]]*\]")
TEST_FILE = re.compile(r"(?:^|/)(?:tests?\.rs|[^/]*_tests?\.rs|tests/[^/]*(?:/.*)?)$")


def without_comments_and_strings(source: str) -> str:
    """Blanks comments, strings and char literals, keeping every line break."""
    out = list(source)
    length = len(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, length)):
            if out[index] != "\n":
                out[index] = " "

    index = 0
    while index < length:
        pair = source[index:index + 2]
        if pair == "//":
            end = source.find("\n", index)
            end = length if end < 0 else end
        elif pair == "/*":
            depth, end = 1, index + 2
            while end < length and depth:
                if source[end:end + 2] == "/*":
                    depth, end = depth + 1, end + 2
                elif source[end:end + 2] == "*/":
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        elif raw := re.match(r'b?r(#*)"', source[index:index + 80]):
            closing = source.find('"' + raw.group(1), index + raw.end())
            end = length if closing < 0 else closing + 1 + len(raw.group(1))
        elif source[index] == '"':
            end = index + 1
            while end < length and source[end] != '"':
                end += 2 if source[end] == "\\" else 1
            end += 1
        elif char := re.match(r"'(?:\\.[^']*|[^\\'])'", source[index:index + 16]):
            end = index + char.end()
        else:
            index += 1
            continue
        blank(index, end)
        index = end
    return "".join(out)


def production_source(source: str) -> str:
    """Rust source without comments, strings or items marked as tests."""
    code = list(without_comments_and_strings(source))
    text = "".join(code)
    position = 0
    while attribute := TEST_ATTRIBUTE.search(text, position):
        depth, end = 0, attribute.end()
        while end < len(text):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif text[end] == ";" and depth == 0:
                break
            end += 1
        for index in range(attribute.start(), min(end + 1, len(text))):
            if code[index] != "\n":
                code[index] = " "
        text = "".join(code)
        position = attribute.start() + 1
    return text


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths under crates/*/src to their Rust text."""
    failures: list[str] = []
    seen: set[str] = set()
    for path, source in sorted(sources.items()):
        if path == CHECKED_OPTIONS_OWNER or TEST_FILE.search(path):
            continue
        production = production_source(source)
        for match in UNCHECKED_POOL.finditer(production):
            if path in REVIEWED_POOLS:
                seen.add(path)
                continue
            failures.append(
                f"{path}:{line_number(production, match.start())}: build production pools "
                "from codewire_server_core::db::checked_pool_options (#3927)")
    failures.extend(
        f"{path}: listed in REVIEWED_POOLS but builds no pool of its own"
        for path in sorted(REVIEWED_POOLS - seen))
    return failures


def self_test() -> None:
    reviewed = {path: "PgPool::connect(&url)" for path in REVIEWED_POOLS}
    production = "crates/codewire-example/src/store.rs"
    for label, source, expected in [
        ("built directly", "let p = PgPoolOptions::new().connect(u);", 1),
        ("full path", "sqlx::postgres::PgPoolOptions::new()", 1),
        ("generic options", "PoolOptions::<Postgres>::new()", 1),
        ("connect", "PgPool::connect(&url)", 1),
        ("connect_lazy", "PgPool::connect_lazy(&url)", 1),
        ("connect_with", "sqlx::PgPool::connect_with(o)", 1),
        ("replaced check", "checked_pool_options().after_release(|c, _| f(c))", 1),
        ("checked options", "codewire_server_core::db::checked_pool_options().connect(u)", 0),
        ("shared connect", "codewire_server_core::db::connect(&url)", 0),
        ("pool type only", "fn f(pool: &PgPool, o: PgPoolOptions) {}", 0),
        ("comment", "// PgPoolOptions::new()\n/* PgPool::connect(u) /* nested */ */", 0),
        ("string", 'let s = "PgPoolOptions::new()"; let r = r#"PgPool::connect("x")"#;', 0),
        ("test module", "#[cfg(test)]\nmod tests { fn f() { PgPoolOptions::new(); } }", 0),
        ("test function", "#[tokio::test]\nasync fn f() { PgPool::connect(u); }", 0),
        ("code after a test module", "#[cfg(test)] mod t { fn f() {} }\nfn g() { PgPoolOptions::new(); }", 1),
        ("code after a test declaration", "#[cfg(test)] mod tests;\nfn g() { PgPoolOptions::new(); }", 1),
        ("brace in a string", '#[cfg(test)] mod t { const S: &str = "}"; }\nfn g() { PgPool::connect(u); }', 1),
        ("lifetime beside code", "fn f<'a>(x: &'a str) { PgPool::connect(x); }", 1),
    ]:
        failures = violations_from({production: source, **reviewed})
        assert len(failures) == expected, f"{label}: {failures}"
    assert violations_from({"crates/codewire-example/src/api/tests.rs": "PgPool::connect(u)", **reviewed}) == []
    assert violations_from({"crates/codewire-example/src/api/store_tests.rs": "PgPool::connect(u)", **reviewed}) == []
    assert violations_from({CHECKED_OPTIONS_OWNER: "PgPoolOptions::new().after_release(f)", **reviewed}) == []
    stale = next(iter(sorted(REVIEWED_POOLS)))
    failures = violations_from({**reviewed, stale: "codewire_server_core::db::connect(&url)"})
    assert len(failures) == 1 and "REVIEWED_POOLS" in failures[0], failures


def check_database_pools(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("database pools self-test: OK")
        return 0
    sources = {
        path: read_text(path)
        for path in git_source_files()
        if path.startswith("crates/") and "/src/" in path and path.endswith(".rs")
    }
    failures = violations_from(sources)
    for failure in failures:
        print(f"::error::database pools: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"database pools: OK ({len(sources)} Rust files, {len(REVIEWED_POOLS)} reviewed non-service files)")
    return 0
