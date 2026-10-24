from .shared import *


def package_name(rel: str) -> str:
    text = read_text(rel)
    match = re.search(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.MULTILINE)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Source-retirement and validation guards

def check_rust_validation_source(_args: argparse.Namespace) -> int:
    failures: list[str] = []
    allowed_raw_body_extractors: dict[str, dict[str, Any]] = {}
    raw_json_body_extractor = re.compile(
        r"Json\s*\(\s*[^)]*\)\s*:\s*Json\s*<\s*(?:serde_json::)?Value\s*>"
    )
    matches_by_file: dict[str, list[tuple[int, str]]] = {}

    for file in walk_files(ROOT / "crates"):
        if file.suffix != ".rs":
            continue
        rel = file.relative_to(ROOT).as_posix()
        text = file.read_text(encoding="utf-8")
        for match in raw_json_body_extractor.finditer(text):
            line = line_number(text, match.start())
            source = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else ""
            matches_by_file.setdefault(rel, []).append((line, source))

    for file, matches in matches_by_file.items():
        allowed = allowed_raw_body_extractors.get(file)
        if not allowed:
            for line, _source in matches:
                failures.append(
                    f"rust validation source: {file}:{line} uses raw Json<serde_json::Value> "
                    "request extraction; use ValidatedJson<T>"
                )
            continue
        if len(matches) != allowed["expected"]:
            failures.append(
                f"rust validation source: {file} has {len(matches)} raw JSON request extractors, "
                f"expected {allowed['expected']} ({allowed['reason']})"
            )

    for file, allowed in allowed_raw_body_extractors.items():
        if file not in matches_by_file and allowed["expected"] > 0:
            failures.append(
                f"rust validation source: {file} has no raw JSON request extractors, "
                f"expected {allowed['expected']} ({allowed['reason']}); update the #60 allowlist"
            )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("rust validation source: OK")
    return 0


def check_retired_reference_source(_args: argparse.Namespace) -> int:
    retired_coder_pattern = re.compile(r"(?<![A-Za-z])coder(?![A-Za-z])", re.IGNORECASE)
    allowed: list[dict[str, Any]] = []
    for path in [
        "tests/contract/go.mod",
        "tests/contract/go.sum",
    ]:
        allowed.append(
            {
                "path": path,
                "line": re.compile(r"github\.com/coder/websocket"),
                "reason": "known third-party module debt; not a Coder product integration",
            }
        )

    def is_allowed(path: str, line: str, kind: str) -> bool:
        for entry in allowed:
            if entry["path"] != path:
                continue
            if kind == "path":
                return entry.get("path_only") is True
            pattern = entry.get("line")
            if pattern is not None and pattern.search(line):
                return True
        return False

    findings: list[str] = []
    self_path = Path(__file__).relative_to(ROOT).as_posix()
    for rel in git_source_files():
        if rel == self_path or rel == ".git" or rel.startswith(".git/"):
            continue
        path = ROOT / rel
        if not path.exists():
            continue
        if retired_coder_pattern.search(rel) and not is_allowed(rel, "", "path"):
            findings.append(f"{rel}: path contains unclassified retired Coder wording")
        data = path.read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for index, line in enumerate(text.split("\n"), start=1):
            if retired_coder_pattern.search(line) and not is_allowed(rel, line, "line"):
                findings.append(f"{rel}:{index}: {line.strip()}")

    if findings:
        print("retired reference guard: unclassified Coder references found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Either remove the reference or classify it in "
            "scripts/checks/repo_checks.py for #48.",
            file=sys.stderr,
        )
        return 1
    print("retired reference guard: OK")
    return 0


def check_go_source_classification(_args: argparse.Namespace) -> int:
    retired_runtime_paths = [
        "apps/api",
        "autoagent",
        "apps/cli/go.mod",
        "apps/cli/cmd/cw",
        "apps/cli/cmd/codewire-relay",
        "apps/cli/cwshell",
        "apps/cli/demo/broker",
        "apps/cli/internal",
        "apps/cli/internal/relay",
        "libs/daemon-proto/buf.gen.yaml",
        "libs/daemon-proto/gen",
        "libs/daemon-proto/go.mod",
        "libs/daemon-proto/go.sum",
        "libs/gatewayauth",
        "libs/tailnet",
        "tests/contract/billing",
        "tests/contract/connectcore",
        "tests/contract/coordinator",
        "tests/contract/file",
        "tests/contract/orchestration",
    ]
    categories: list[tuple[str, re.Pattern[str]]] = [
        (
            "Tailscale Go-client DERP interoperability",
            re.compile(r"^tests/contract/derp/.*\.go$"),
        ),
        (
            "Tailscale wire-format golden",
            re.compile(r"^tests/contract/tailscalegolden/.*\.go$"),
        ),
        (
            "generated Go API consumers",
            re.compile(r"^libs/gen-go/.*\.go$"),
        ),
        (
            "public Go SDK",
            re.compile(r"^libs/sdk-go/.*\.go$"),
        ),
    ]
    findings: list[str] = []
    counts = {name: 0 for name, _pattern in categories}

    for rel in retired_runtime_paths:
        if (ROOT / rel).exists():
            findings.append(f"{rel}: retired Go runtime/source path must not exist")

    for rel in [
        path
        for path in git_source_files()
        if path.endswith(".go") and (ROOT / path).is_file()
    ]:
        category = next((item for item in categories if item[1].search(rel)), None)
        if category is None:
            findings.append(f"{rel}: unclassified Go source; update #45 and this guard or delete it")
            continue
        counts[category[0]] += 1
        package = package_name(rel)
        if package == "main":
            findings.append(f"{rel}: package main is not an accepted Go consumer surface")

    if findings:
        print("Go source classification guard: unaccepted Go source found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "Remaining Go must be accepted support/test/generated/oracle/SDK surface "
            "in this guard's categories.",
            file=sys.stderr,
        )
        return 1
    print("Go source classification guard: OK")
    for name, count in counts.items():
        print(f"  {name}: {count}")
    return 0
