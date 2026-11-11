"""Every image built from the root workspace has the root manifest's [patch] paths.

Cargo resolves every `[patch]` entry before it builds anything, so an image
that copies the root `Cargo.toml` into its build stage but not a patched path
fails with "patch location ... does not contain packages" (#3980: #4136 added
`third_party/sqlx-sqlite-unused` and every Dev runtime image build failed).

For each local path a root `[patch]` table names, this check requires:
- every Dockerfile stage that copies the root `Cargo.toml` also copies the
  path, or a directory above it;
- that Dockerfile's build context keeps the path's manifest and Rust sources:
  its `<Dockerfile>.dockerignore`, or the root `.dockerignore`, does not
  exclude them;
- every image artifact in `scripts/ci/plan/artifact-graph.json` that builds
  from the root workspace (inputs `Cargo.lock` and `crates/**`) lists the
  path's files as inputs, so a change to them rebuilds the image.
"""

from __future__ import annotations

from .shared import *

DOCKERFILE = re.compile(r"(?:^|/)(?:[^/]*\.)?Dockerfile$")
ARTIFACT_GRAPH = "scripts/ci/plan/artifact-graph.json"
ROOT_MANIFEST_COPY = re.compile(r"^COPY\s+(?:--\S+\s+)*Cargo\.toml\s+Cargo\.lock\s+\S+\s*$")


def patch_paths(manifest_text: str) -> list[str]:
    """The local paths the root manifest's [patch] tables name."""
    paths = []
    for table in tomllib.loads(manifest_text).get("patch", {}).values():
        for spec in table.values():
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                paths.append(spec["path"].removeprefix("./").rstrip("/"))
    return sorted(set(paths))


def copy_sources(line: str) -> list[str] | None:
    """The sources of a plain COPY line from the build context, else None."""
    words = line.split()
    if not words or words[0] != "COPY" or any(word.startswith("--from") for word in words):
        return None
    operands = [word for word in words[1:] if not word.startswith("--")]
    return [source.removeprefix("./").rstrip("/") or "." for source in operands[:-1]]


def covers(source: str, path: str) -> bool:
    return source == "." or source == path or path.startswith(source + "/")


def dockerfile_failures(name: str, text: str, paths: list[str]) -> list[str]:
    failures = []
    stages: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.startswith("FROM "):
            stages.append([])
        stages[-1].append(line)
    for stage in stages:
        if not any(ROOT_MANIFEST_COPY.match(line) for line in stage):
            continue
        sources = [source for line in stage for source in copy_sources(line) or []]
        header = next((line for line in stage if line.startswith("FROM ")), "the first stage")
        for path in paths:
            if not any(covers(source, path) for source in sources):
                failures.append(f"{name}: {header!r} copies the root Cargo.toml but not {path}")
    return failures


def ignore_pattern(pattern: str) -> re.Pattern[str]:
    pattern = pattern.removeprefix("/").rstrip("/")
    out = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            out += ".*"
            index += 2
        elif pattern[index] == "*":
            out += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            out += "[^/]"
            index += 1
        else:
            out += re.escape(pattern[index])
            index += 1
    return re.compile(out + r"\Z")


def ignored(ignore_text: str, path: str) -> bool:
    """Whether a .dockerignore excludes `path`: the last pattern that matches
    it or a directory above it decides."""
    parts = path.split("/")
    candidates = ["/".join(parts[: count + 1]) for count in range(len(parts))]
    excluded = False
    for raw in ignore_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        regex = ignore_pattern(line[1:] if negated else line)
        if any(regex.match(candidate) for candidate in candidates):
            excluded = not negated
    return excluded


def context_failures(name: str, ignore_name: str, ignore_text: str, files: list[str]) -> list[str]:
    return [
        f"{name}: {ignore_name} excludes {path} from the build context"
        for path in files
        if ignored(ignore_text, path)
    ]


def graph_failures(graph: dict, paths: list[str]) -> list[str]:
    failures = []
    for artifact, entry in sorted(graph.get("artifacts", {}).items()):
        inputs = entry.get("inputs") if isinstance(entry, dict) else None
        if not isinstance(inputs, list) or "Cargo.lock" not in inputs or "crates/**" not in inputs:
            continue
        for path in paths:
            if f"{path}/**" not in inputs:
                failures.append(f"{ARTIFACT_GRAPH}: {artifact} builds the root workspace but does not list {path}/**")
    return failures


def check_image_patch_paths(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("image patch paths", self_test()):
            return 1
        print("image patch paths: OK (self-test)")
        return 0
    paths = patch_paths(read_text("Cargo.toml"))
    sources = git_source_files()
    needed = [
        source
        for source in sources
        if any(source.startswith(path + "/") for path in paths) and source.endswith((".toml", ".rs"))
    ]
    failures = []
    checked = 0
    for name in sorted(source for source in sources if DOCKERFILE.search(source)):
        text = read_text(name)
        if not any(ROOT_MANIFEST_COPY.match(line) for line in text.splitlines()):
            continue
        checked += 1
        failures.extend(dockerfile_failures(name, text, paths))
        ignore_name = f"{name}.dockerignore" if f"{name}.dockerignore" in sources else ".dockerignore"
        failures.extend(context_failures(name, ignore_name, read_text(ignore_name), needed))
    failures.extend(graph_failures(read_json(ARTIFACT_GRAPH), paths))
    if report("image patch paths", failures):
        return 1
    print(f"image patch paths: OK ({len(paths)} patch paths, {checked} Dockerfiles)")
    return 0


def self_test() -> list[str]:
    failures = []

    def expect(label: str, condition: bool) -> None:
        if not condition:
            failures.append(f"self-test: {label}")

    manifest = (
        '[patch.crates-io]\nsqlx-sqlite = { path = "third_party/stub" }\n'
        'other = { version = "1" }\n[patch."https://example.test/x"]\nx = { path = "./vendor/x/" }\n'
    )
    paths = patch_paths(manifest)
    expect("patch paths are read from every [patch] table", paths == ["third_party/stub", "vendor/x"])
    expect("a manifest without [patch] names none", patch_paths("[workspace]\n") == [])

    good = (
        "FROM base AS builder\nCOPY Cargo.toml Cargo.lock ./\nCOPY third_party/stub ./third_party/stub\n"
        "COPY vendor ./vendor\nCOPY crates ./crates\nFROM debian\nCOPY --from=builder /out /out\n"
    )
    expect("a stage that copies every path passes", dockerfile_failures("D", good, paths) == [])
    missing = "FROM base\nCOPY Cargo.toml Cargo.lock ./\nCOPY crates ./crates\n"
    expect(
        "a stage that copies neither path fails for each",
        len(dockerfile_failures("D", missing, paths)) == 2,
    )
    split = (
        "FROM base AS one\nCOPY Cargo.toml Cargo.lock ./\nCOPY third_party ./third_party\nCOPY vendor ./vendor\n"
        "FROM base AS two\nCOPY Cargo.toml Cargo.lock ./\nCOPY crates ./crates\n"
    )
    expect("each stage is checked on its own", len(dockerfile_failures("D", split, paths)) == 2)
    expect(
        "copying the whole context covers every path",
        dockerfile_failures("D", "FROM b\nCOPY Cargo.toml Cargo.lock ./\nCOPY . .\n", paths) == [],
    )
    expect(
        "a stage with only a curated manifest is not checked",
        dockerfile_failures("D", "FROM b\nCOPY derp.Cargo.toml ./Cargo.toml\n", paths) == [],
    )
    expect(
        "a copy from another stage covers nothing",
        len(
            dockerfile_failures(
                "D",
                "FROM b\nCOPY Cargo.toml Cargo.lock ./\nCOPY --from=x third_party/stub ./third_party/stub\n"
                "COPY vendor ./vendor\n",
                paths,
            )
        )
        == 1,
    )

    files = ["third_party/stub/Cargo.toml", "third_party/stub/src/lib.rs"]
    allow_list = "*\n!Cargo.toml\n!crates\n!crates/**\n"
    expect("a deny-all ignore without the path excludes it", len(context_failures("D", "i", allow_list, files)) == 2)
    allowed = allow_list + "!third_party\n!third_party/stub\n!third_party/stub/**\n"
    expect("allowing the path keeps it", context_failures("D", "i", allowed, files) == [])
    expect(
        "a later exclusion wins over an allow",
        len(context_failures("D", "i", allowed + "third_party/stub/src\n", files)) == 1,
    )
    root = ".git\ntarget\n*.md\ndeployments\n!deployments/docker/**\n"
    expect("an ignore that names other paths keeps it", context_failures("D", "i", root, files) == [])
    expect("a root *.md pattern does not reach into directories", not ignored(root, "third_party/stub/README.md"))

    graph = {
        "artifacts": {
            "image": {"inputs": ["Cargo.lock", "crates/**"]},
            "listed": {"inputs": ["Cargo.lock", "crates/**", "third_party/stub/**", "vendor/x/**"]},
            "curated": {"inputs": ["derp.Cargo.lock", "crates/codewire-derp/**"]},
            "package": {"kind": "rust-package", "lockfile": "Cargo.lock"},
        }
    }
    expect("an image of the root workspace must list each path", len(graph_failures(graph, paths)) == 2)
    return failures
