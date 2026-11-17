"""Every Forgejo list call names its page.

Forgejo 17's FindAndCount adds a LIMIT only when the page is 1 or more, and
its API leaves the page at 0 when a call sends none. Such a call reads and
converts every matching record, and only then cuts the reply to `limit`: on
codewire/codewire on 2026-11-17, `actions/runs?limit=1` read 40,128 runs and
failed after 120 s, while `page=1&limit=1` answered in 0.2 s (infra#2709,
infra#2710).

A list path is actions/runs, actions/tasks, pulls or issues, ending its
string or followed by its query. A run's jobs are not one: Forgejo 17 returns
all of one run's jobs whatever the page, so that read is bounded by the run.
The statement that holds a list path must name `page`:
- in Python, the smallest statement around the string, or the expression
  that a compound statement tests, iterates or opens;
- in a shell script or workflow, the line with its backslash continuations.

It reads the tracked Python and shell scripts under scripts/ and the workflows
under .gitea/workflows/, except tests and fixtures, whose fake servers answer
what the callers send. A write passes: a statement naming POST, PUT, PATCH or
DELETE, or a curl body without --get. A list path that is not a call says why
in its statement, or on the line above it, with `forgejo-list-unpaged: <why>`.
"""

import ast

from .shared import *

SCANNED = ("scripts/", ".gitea/workflows/")
# In a Python string the path may stand alone ("actions/runs" with a params
# dict). Pulls and issues need their slash, so a bare "issues" is not a call.
PYTHON_LIST_PATH = re.compile(
    r"(?:(?:^|/)actions/(?:runs|tasks)|/(?:pulls|issues))(?=$|\?)")
LINE_LIST_PATH = re.compile(
    r"/(?:actions/(?:runs|tasks)|pulls|issues)(?=$|[?\"'\s`)])")
PAGE = re.compile(r"\bpage\b")
WRITE_METHOD = re.compile(r"\b(?:POST|PUT|PATCH|DELETE)\b")
CURL_BODY = re.compile(r"--(?:data|json)\b")
CURL_GET = re.compile(r"--get\b|\s-G\b")
MARKER = "forgejo-list-unpaged:"


def writes(text: str) -> bool:
    return bool(WRITE_METHOD.search(text) or (CURL_BODY.search(text) and not CURL_GET.search(text)))


def scanned(path: str) -> bool:
    parts = path.split("/")
    return (path.startswith(SCANNED)
            and not any(part in {"tests", "fixtures"} for part in parts[:-1])
            and not parts[-1].startswith(("test-", "test_")))


def kind(path: str, text: str) -> str | None:
    shebang = text.split("\n", 1)[0] if text.startswith("#!") else ""
    if path.endswith(".py") or "python" in shebang:
        return "python"
    if (path.endswith((".sh", ".bash")) or re.search(r"\b(?:ba)?sh\b", shebang)
            or (path.startswith(".gitea/workflows/") and path.endswith((".yml", ".yaml")))):
        return "line"
    return None


def marked(lines: list[str], first: int, text: str) -> bool:
    """`first` is the statement's 1-based first line."""
    return MARKER in text or (first > 1 and MARKER in lines[first - 2])


def string_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value if isinstance(part, ast.Constant) else "{}" for part in node.values)
    return None


def python_failures(path: str, text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return line_failures(path, text)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    lines = text.splitlines()
    failures = []
    for node in ast.walk(tree):
        if isinstance(parents.get(node), ast.JoinedStr):
            continue
        value = string_text(node)
        if value is None or not PYTHON_LIST_PATH.search(value):
            continue
        scope, parent = node, parents.get(node)
        while parent is not None and not isinstance(parent, ast.stmt):
            scope, parent = parent, parents.get(parent)
        if isinstance(parent, ast.Expr) and parent.value is node:
            continue  # a docstring or a bare string says, it does not call
        if parent is not None and not hasattr(parent, "body"):
            scope = parent
        segment = ast.get_source_segment(text, scope) or ""
        if PAGE.search(segment) or writes(segment) or marked(lines, scope.lineno, segment):
            continue
        failures.append(f"{path}:{scope.lineno}: {' '.join(segment.split())[:160]}")
    return failures


def line_failures(path: str, text: str) -> list[str]:
    lines = text.splitlines()
    failures = []
    index = 0
    while index < len(lines):
        first, logical = index + 1, lines[index]
        while logical.endswith("\\") and index + 1 < len(lines):
            index += 1
            logical = logical[:-1] + " " + lines[index]
        index += 1
        if logical.lstrip().startswith("#") or not LINE_LIST_PATH.search(logical):
            continue
        if PAGE.search(logical) or writes(logical) or marked(lines, first, logical):
            continue
        failures.append(f"{path}:{first}: {' '.join(logical.split())[:160]}")
    return failures


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths to their text; unscanned paths are ignored."""
    failures: list[str] = []
    for path, text in sorted(sources.items()):
        if not scanned(path):
            continue
        language = kind(path, text)
        if language == "python":
            failures += python_failures(path, text)
        elif language == "line":
            failures += line_failures(path, text)
    return failures


def self_test() -> None:
    py, sh = "#!/usr/bin/env python3\n", "#!/usr/bin/env bash\n"
    for label, path, source, expected in [
        ("python runs", "scripts/ci/x.py", 'r = api("GET", f"/repos/{repo}/actions/runs?limit=1")', 1),
        ("a run's jobs", "scripts/ci/x.py", 'j = api("GET", f"/repos/{r}/actions/runs/{run}/jobs")', 0),
        ("python params", "scripts/ci/x.py", 'd = get(\n    "actions/runs",\n    {"status": "running", "limit": "50"},\n)', 1),
        ("python pulls loop", "scripts/ci/x.py", 'for pr in api("GET", "/repos/o/r/pulls?state=open&limit=50"):\n    pass', 1),
        ("python shebang", "scripts/dev/lister", py + 'r = api("GET", "/repos/o/r/actions/tasks")', 1),
        ("shell runs", "scripts/ci/x.sh", 'curl -fsS "$API/repos/$REPO/actions/runs?limit=1"', 1),
        ("shell continued", "scripts/ci/x.sh", 'curl -fsS "$API/repos/$REPO/issues?state=open" \\\n  -o issues.json', 1),
        ("workflow", ".gitea/workflows/w.yaml", '        run: curl "$API/repos/$R/actions/runs?status=running"', 1),
        ("python paged", "scripts/ci/x.py", 'r = api("GET", f"/repos/{repo}/actions/runs?page=1&limit=1")', 0),
        ("python paged params", "scripts/ci/x.py", 'd = get("actions/runs", {"limit": "50", "page": "1"})', 0),
        ("python split string", "scripts/ci/x.py",
         'p = (f"/repos/{r}/actions/runs?event=push"\n     f"&page={page}&limit=50")', 0),
        ("shell paged", "scripts/ci/x.sh", 'curl "$API/repos/$R/actions/runs?status=running" \\\n  --get --data page=1', 0),
        ("one run", "scripts/ci/x.py", 'r = api("GET", f"/repos/{repo}/actions/runs/{run_id}")', 0),
        ("python write", "scripts/ci/x.py", 'api("POST", "/repos/o/r/pulls", {"title": t})', 0),
        ("shell write", "scripts/ci/x.sh", 'api DELETE "/repos/$REPO/actions/runs/0"', 0),
        ("curl body", "scripts/ci/x.sh", 'curl --data @pr.json "${api}/pulls"', 0),
        ("curl get body", "scripts/ci/x.sh", 'curl --get --data state=open "${api}/pulls"', 1),
        ("docstring", "scripts/ci/x.py", '"""Reads GET /repos/o/r/actions/runs without a page."""', 0),
        ("a word", "scripts/ci/x.py", 'if kind == "issues":\n    pass', 0),
        ("shell comment", "scripts/ci/x.sh", '# curl "$API/actions/runs?limit=1" was replaced', 0),
        ("a grep guard", "scripts/ci/x.sh", "grep -Fq 'actions/runs?limit=100' \"$HELPER\"", 0),
        ("marked", "scripts/ci/x.sh", '# forgejo-list-unpaged: an example\ncurl "$API/repos/$R/actions/runs?limit=1"', 0),
        ("marked too far", "scripts/ci/x.sh", '# forgejo-list-unpaged: far\n\ncurl "$API/repos/$R/actions/runs?limit=1"', 1),
        ("a test", "scripts/ci/tests/test-x.py", 'ROUTE = "/repos/o/r/actions/runs?limit=1"', 0),
        ("a fixture", "scripts/ci/fixtures/server.py", 'ROUTE = "/repos/o/r/actions/runs?limit=1"', 0),
        ("not a script", "scripts/ci/notes.md", 'curl "$API/repos/o/r/actions/runs?limit=1"', 0),
        ("outside scripts", "crates/x/src/forge.rs", 'format!("/actions/runs?head_sha={c}")', 0),
    ]:
        failures = violations_from({path: source})
        assert len(failures) == expected, f"{label}: {failures}"


def check_forgejo_list_paging(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("Forgejo list paging self-test: OK")
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
        print(f"::error::Forgejo list paging: {failure}: send page=1; without a page Forgejo 17 reads "
              "every matching record (infra#2709)", file=sys.stderr)
    if failures:
        return 1
    print(f"Forgejo list paging: OK ({len(sources)} scripts and workflows read)")
    return 0
