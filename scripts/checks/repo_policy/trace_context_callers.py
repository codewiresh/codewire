"""Our trace context is written into outgoing requests only by the dashboard's transport.

`codewire_server_core::obs::inject_http_headers` writes the current span's W3C
`traceparent` and `tracestate` into a request. The dashboard's transport calls
it for the services inside the deployment, and nothing else may: a second
caller could send our trace ids to an outside address or into a user's app
through the preview proxy (docs/CONFIGURATION.md, "Tracing"; #5628). A new
caller is reviewed first, then added to CALLERS.
"""

from .database_pools import TEST_FILE, production_source
from .shared import *

DEFINITION_OWNER = "crates/codewire-server-core/src/obs.rs"
CALLERS = ("crates/codewire-dashboard-web/src/transport.rs",)
NAME = re.compile(r"\binject_http_headers\b")
DEFINITION = re.compile(r"\bfn\s+(inject_http_headers)\b")


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths under crates/ to their Rust text."""
    failures: list[str] = []
    seen: set[str] = set()
    for path, source in sorted(sources.items()):
        if TEST_FILE.search(path):
            continue
        production = production_source(source)
        definitions = {match.start(1) for match in DEFINITION.finditer(production)}
        for match in NAME.finditer(production):
            if path == DEFINITION_OWNER and match.start() in definitions:
                continue
            if path in CALLERS:
                seen.add(path)
                continue
            failures.append(
                f"{path}:{line_number(production, match.start())}: only the dashboard's "
                "transport writes our trace context into a request; a new caller is "
                "reviewed and added to CALLERS first (#5628)")
    failures.extend(
        f"{path}: listed in CALLERS but no longer calls inject_http_headers"
        for path in sorted(set(CALLERS) - seen))
    return failures


def self_test() -> None:
    caller = {CALLERS[0]: "obs::inject_http_headers(&mut parts.headers);"}
    other = "crates/codewire-orchestration/src/api/preview.rs"
    for label, sources, expected in [
        ("the transport", {**caller}, 0),
        ("the definition", {**caller, DEFINITION_OWNER: "pub fn inject_http_headers(h: &mut H) {}"}, 0),
        ("another call in the owner", {**caller, DEFINITION_OWNER: "fn f() { inject_http_headers(&mut h); }"}, 1),
        ("another crate", {**caller, other: "obs::inject_http_headers(&mut headers);"}, 1),
        ("an import", {**caller, other: "use codewire_server_core::obs::inject_http_headers;"}, 1),
        ("a function value", {**caller, other: "headers.map(inject_http_headers)"}, 1),
        ("comment", {**caller, other: "// inject_http_headers(&mut h)"}, 0),
        ("string", {**caller, other: 'let s = "inject_http_headers";'}, 0),
        ("test module", {**caller, other: "#[cfg(test)]\nmod tests { fn f() { inject_http_headers(&mut h); } }"}, 0),
        ("test file", {**caller, "crates/codewire-orchestration/src/api/preview_trace_tests.rs": "inject_http_headers(&mut h);"}, 0),
        ("stale caller", {CALLERS[0]: "fn send() {}"}, 1),
    ]:
        failures = violations_from(sources)
        assert len(failures) == expected, f"{label}: {failures}"


def check_trace_context_callers(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("trace context callers self-test: OK")
        return 0
    sources = {
        path: read_text(path)
        for path in git_source_files()
        if path.startswith("crates/") and path.endswith(".rs")
    }
    failures = violations_from(sources)
    for failure in failures:
        print(f"::error::trace context callers: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"trace context callers: OK ({len(sources)} Rust files, {len(CALLERS)} caller)")
    return 0
