"""No polling for state the server knows: pages learn of changes from the
shared live stream (private-docs designs/live-updates.md, codewire#4762).

The check refuses an htmx `every` trigger and a `setInterval(` call in the
dashboard's templates, its Rust sources (tests excepted) and
packages/codewire-design, unless the site is on the allow-list. A poll on the
list names the issue and step that removes it; a client-only timer (one that
fetches nothing, such as an elapsed-time display) names why it is not a poll.
It also refuses a `setTimeout` loop: a `setTimeout(` that schedules the
function it is written in (`setTimeout(refresh, ...)` inside `refresh`). A
bounded retry that reschedules itself is listed with `retry` and why. Each
entry allows an exact number of sites in its file, so a new site in a listed
file fails, and a site that has been removed must leave the list too.
"""

from __future__ import annotations

from .shared import *


ALLOWLIST = "scripts/checks/contracts/live-state-allowlist.json"
SCANNED_PREFIXES = (
    "crates/codewire-dashboard-web/templates/",
    "crates/codewire-dashboard-web/src/",
    "packages/codewire-design/",
)
SCANNED_SUFFIXES = (".html", ".js", ".rs")
PATTERNS = {
    "hx-every": re.compile(r"""hx-trigger\s*=\s*\\?["'][^"'\n]*\bevery\s+\d"""),
    "setInterval": re.compile(r"\bsetInterval\s*\("),
}
SET_TIMEOUT_LOOP = "setTimeout-loop"
KNOWN_PATTERNS = (*PATTERNS, SET_TIMEOUT_LOOP)
# A named function: `function name(`, `const name = (...) => {`,
# `const name = async function (...) {`, or a method `name(...) {`.
FUNCTION = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("
    r"|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b[^(]*)?\([^)]*\)\s*(?:=>)?\s*\{"
    r"|^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)
NOT_FUNCTIONS = {"if", "for", "while", "switch", "catch", "function", "with"}


def scanned(rel: str) -> bool:
    if not rel.startswith(SCANNED_PREFIXES) or not rel.endswith(SCANNED_SUFFIXES):
        return False
    name = rel.rsplit("/", 1)[-1]
    # Rust tests assert on rendered markup; they don't poll.
    return not (rel.endswith(".rs") and (name == "tests.rs" or name.endswith("_tests.rs") or "/tests/" in rel))


def function_body(text: str, start: int) -> tuple[int, int] | None:
    """The braces of the function whose header starts at `start`."""
    opening = text.find("{", start)
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return opening, index
    return opening, len(text)


def set_timeout_loops(text: str) -> list[int]:
    """Offsets of `setTimeout(` calls that schedule their own function."""
    offsets: set[int] = set()
    for match in FUNCTION.finditer(text):
        name = next(group for group in match.groups() if group)
        body = function_body(text, match.start())
        if name in NOT_FUNCTIONS or body is None:
            continue
        again = re.compile(
            r"\bsetTimeout\s*\(\s*(?:" + re.escape(name) + r"\b|\(\)\s*=>\s*(?:void\s+)?" + re.escape(name) + r"\s*\()"
        )
        for call in again.finditer(text, body[0], body[1]):
            offsets.add(call.start())
    return sorted(offsets)


def live_state_sites(rel: str, text: str) -> list[tuple[str, int]]:
    sites = [
        (kind, line_number(text, match.start()))
        for kind, pattern in PATTERNS.items()
        for match in pattern.finditer(text)
    ]
    if rel.endswith((".js", ".html")):
        sites.extend((SET_TIMEOUT_LOOP, line_number(text, offset)) for offset in set_timeout_loops(text))
    return sites


def live_state_findings(files: dict[str, str], allowlist: list[dict[str, Any]]) -> list[str]:
    findings: list[str] = []
    allowed: dict[tuple[str, str], int] = {}
    for entry in allowlist:
        key = (entry.get("path", ""), entry.get("pattern", ""))
        if key[1] not in KNOWN_PATTERNS:
            findings.append(f"{ALLOWLIST}: {key[0]}: unknown pattern {key[1]!r}")
        if key in allowed:
            findings.append(f"{ALLOWLIST}: {key[0]}: {key[1]} is listed twice")
        poll = entry.get("issue") and entry.get("step")
        if not poll and not entry.get("client_only") and not entry.get("retry"):
            findings.append(
                f"{ALLOWLIST}: {key[0]}: an entry names its issue and step, or says client_only or retry and why"
            )
        allowed[key] = int(entry.get("count", 0))
    found: Counter[tuple[str, str]] = Counter()
    lines: dict[tuple[str, str], list[int]] = {}
    for rel, text in sorted(files.items()):
        if not scanned(rel):
            continue
        for kind, line in live_state_sites(rel, text):
            found[(rel, kind)] += 1
            lines.setdefault((rel, kind), []).append(line)
    for key, count in sorted(found.items()):
        limit = allowed.get(key, 0)
        if count > limit:
            where = ", ".join(str(line) for line in lines[key])
            findings.append(f"{key[0]}:{where}: {key[1]} polls ({count} sites, {limit} allowed)")
    for key, limit in sorted(allowed.items()):
        if found.get(key, 0) < limit:
            findings.append(
                f"{ALLOWLIST}: {key[0]}: {key[1]} allows {limit} but {found.get(key, 0)} remain; shrink the entry"
            )
    return findings


def live_state_self_test() -> None:
    template = "crates/codewire-dashboard-web/templates/x.html"
    script = "packages/codewire-design/x.js"
    rejected = {
        "every trigger": (template, '<div hx-get="/f" hx-trigger="load, every 5s"></div>'),
        "every trigger in Rust": ("crates/codewire-dashboard-web/src/x.rs", r'format!("hx-trigger=\"every 2s\"")'),
        "interval": (script, "window.setInterval(refresh, 10000);"),
        "timeout loop": (script, "async function refresh() {\n  await fetch(u);\n  timer = setTimeout(refresh, 5000);\n}"),
        "arrow timeout loop": (script, "const poll = async () => {\n  await fetch(u);\n  setTimeout(() => void poll(), 2000);\n};"),
        "timeout loop in a template": (template, "<script>function tick() { setTimeout(tick, 1000); }</script>"),
    }
    accepted = {
        "event trigger": (template, '<div hx-trigger="codewire:live:sandbox from:body"></div>'),
        "load trigger": (template, '<div hx-trigger="load"></div>'),
        "retry timeout": (script, "setTimeout(retry, delay);"),
        "timeout of another function": (script, "function open() {\n  setTimeout(focusFirst, 0);\n}"),
        "one-shot timeout": (script, "function show() {\n  setTimeout(() => hide(), 3000);\n}"),
        "Rust test": ("crates/codewire-dashboard-web/src/routes/x_tests.rs", 'hx-trigger="every 5s"'),
        "vendored asset": ("crates/codewire-dashboard-web/assets/htmx.min.js", "setInterval(a,b)"),
        "prose": (template, "<p>Refreshes every 5 seconds.</p>"),
    }
    for label, (rel, text) in rejected.items():
        if not live_state_findings({rel: text}, []):
            raise RuntimeError(f"self-test accepted {label}")
    for label, (rel, text) in accepted.items():
        findings = live_state_findings({rel: text}, [])
        if findings:
            raise RuntimeError(f"self-test rejected {label}: {findings}")
    poll = [{"path": script, "pattern": "setInterval", "count": 1, "issue": "#1", "step": "s"}]
    if live_state_findings({script: "setInterval(a, 1);"}, poll):
        raise RuntimeError("self-test refused an allowed site")
    if not live_state_findings({script: "setInterval(a, 1); setInterval(b, 1);"}, poll):
        raise RuntimeError("self-test allowed a second site in a listed file")
    if not live_state_findings({script: "setTimeout(a, 1);"}, poll):
        raise RuntimeError("self-test kept a stale entry")
    if not live_state_findings({script: "setInterval(a, 1);"}, [{"path": script, "pattern": "setInterval", "count": 1}]):
        raise RuntimeError("self-test accepted an entry with no issue or reason")


def check_live_state(args: argparse.Namespace) -> int:
    try:
        if args.self_test:
            live_state_self_test()
        allowlist = read_json(ALLOWLIST)["entries"]
        files = {
            rel: (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            for rel in git_source_files()
            if scanned(rel)
        }
        findings = live_state_findings(files, allowlist)
    except Exception as error:  # noqa: BLE001 - repo check script
        print(f"live state: {error}", file=sys.stderr)
        return 1
    if findings:
        print("live state: polling for server state", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Subscribe the region to a codewire:live:<kind> event from the shared stream "
            "instead (codewire-design skill, Live state; codewire#4762).",
            file=sys.stderr,
        )
        return 1
    print("live state: OK")
    return 0
