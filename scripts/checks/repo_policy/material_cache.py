"""Decrypted-material reuse ownership guard (AGENTS.md "Repository invariants").

Decrypted provider material may be reused only within one platform broker
bridge epoch. The only production code that creates an `EpochMaterialCache`
is therefore the bridge service's epoch admission (`admit` in
`crates/codewire-credential-broker/src/platform/bridge.rs`), exactly once.
Tests may create caches freely. No source may alias the type, hold it in a
static, a lazy or once cell, or a thread local, or call a `default`
constructor: those are the ways a process-wide cache would appear.

This is a source guard, not a proof: the type itself has no `Clone`,
`Debug` or `Default`, and its fields are private, so outside its own module
the guarded constructor is the only way to obtain one.
"""

from __future__ import annotations

import re

from .shared import ROOT, argparse, git_source_files

DEFINING = "crates/codewire-platform-credentials/src/material_cache.rs"
OWNER = "crates/codewire-credential-broker/src/platform/bridge.rs"
OWNER_FUNCTION = "admit"
TYPE = "EpochMaterialCache"
CONSTRUCTION = re.compile(rf"\b{TYPE}\s*::\s*(?:new|default)\b")
ALIAS = re.compile(rf"\b{TYPE}\s+as\b")
GLOBAL_HOLDERS = re.compile(
    r"\bstatic\b|\bOnceLock\b|\bLazyLock\b|\bOnceCell\b|\bLazy\b|\bthread_local!|\blazy_static!"
)


def is_test_source(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return "tests" in parts[:-1] or name == "tests.rs" or name.endswith("_tests.rs")


def code_only(text: str) -> str:
    """Blank comments and string and char literals, keeping offsets and lines."""
    out = list(text)
    index = 0
    length = len(text)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        char = text[index]
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            blank(index, end)
            index = end
        elif char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            blank(index + 1, min(end, length))
            index = end + 1
        elif char == "'" and (literal := re.match(r"'(?:\\.|[^\\'])'", text[index:index + 4])):
            end = index + len(literal.group(0)) - 1
            blank(index + 1, end)
            index = end + 1
        else:
            index += 1
    return "".join(out)


def function_body(code: str, name: str) -> tuple[int, int] | None:
    match = re.search(rf"\bfn\s+{re.escape(name)}\b", code)
    if not match:
        return None
    start = code.find("{", match.end())
    if start < 0:
        return None
    depth = 0
    for position in range(start, len(code)):
        if code[position] == "{":
            depth += 1
        elif code[position] == "}":
            depth -= 1
            if depth == 0:
                return start, position
    return None


def violations(sources: dict[str, str]) -> list[str]:
    failures: list[str] = []
    owned = 0
    for path in sorted(sources):
        if TYPE not in sources[path]:
            continue
        code = code_only(sources[path])
        lines = code.splitlines()
        for number, line in enumerate(lines, start=1):
            if TYPE in line and GLOBAL_HOLDERS.search(line):
                failures.append(f"{path}:{number}: {TYPE} must not be held process-wide")
        if path == DEFINING:
            continue
        for match in ALIAS.finditer(code):
            number = code.count("\n", 0, match.start()) + 1
            failures.append(f"{path}:{number}: {TYPE} must not be aliased")
        if is_test_source(path):
            continue
        body = function_body(code, OWNER_FUNCTION) if path == OWNER else None
        for match in CONSTRUCTION.finditer(code):
            number = code.count("\n", 0, match.start()) + 1
            if body and body[0] < match.start() < body[1] and match.group(0).endswith("new"):
                owned += 1
            else:
                failures.append(
                    f"{path}:{number}: only bridge epoch admission ({OWNER} `{OWNER_FUNCTION}`) "
                    f"may create an {TYPE}"
                )
    if owned != 1:
        failures.append(
            f"{OWNER} `{OWNER_FUNCTION}` must create exactly one {TYPE} per epoch (found {owned})"
        )
    return failures


def self_test(sources: dict[str, str]) -> None:
    owner_construction = f"material: Some({TYPE}::new()),"
    if owner_construction not in sources.get(OWNER, ""):
        raise RuntimeError(f"self-test cannot find the epoch construction in {OWNER}")

    def changed(path: str, transform) -> dict[str, str]:
        mutated = dict(sources)
        mutated[path] = transform(mutated.get(path, ""))
        return mutated

    service = "crates/codewire-credential-service/src/runtime.rs"
    platform = "crates/codewire-credential-broker/src/platform.rs"
    rejected = {
        "construction elsewhere": changed(
            service, lambda text: text + f"\nfn cache() -> {TYPE} {{ {TYPE}::new() }}\n"),
        "second construction outside admit": changed(
            OWNER, lambda text: text + f"\nfn spare() -> {TYPE} {{ {TYPE}::new() }}\n"),
        "no epoch construction": changed(
            OWNER, lambda text: text.replace(owner_construction, "material: None,")),
        "default constructor": changed(
            platform, lambda text: text + f"\nfn cache() -> {TYPE} {{ {TYPE}::default() }}\n"),
        "process-wide static": changed(
            platform, lambda text: text + f"\nstatic CACHE: std::sync::OnceLock<{TYPE}> = "
            "std::sync::OnceLock::new();\n"),
        "aliased constructor": changed(
            service, lambda text: text + f"\nuse codewire_platform_credentials::{TYPE} as Cache;\n"
            "fn cache() -> Cache { Cache::new() }\n"),
        "static in a test": changed(
            "crates/codewire-credential-broker/src/platform/tests.rs",
            lambda text: text + f"\nstatic CACHE: std::sync::LazyLock<{TYPE}> = "
            f"std::sync::LazyLock::new({TYPE}::new);\n"),
    }
    for name, mutated in rejected.items():
        if not violations(mutated):
            raise RuntimeError(f"self-test: {name} was accepted")
    accepted = {
        "test construction": changed(
            "crates/codewire-credential-broker/src/platform/tests/material_cache.rs",
            lambda text: text + f"\nfn spare() -> {TYPE} {{ {TYPE}::new() }}\n"),
        "commented construction": changed(
            service, lambda text: text + f"\n// {TYPE}::new() is admission's alone.\n"),
    }
    for name, mutated in accepted.items():
        if violations(mutated):
            raise RuntimeError(f"self-test: {name} was rejected")


def check_epoch_material_cache_owner(args: argparse.Namespace) -> int:
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in git_source_files()
        if path.startswith("crates/") and path.endswith(".rs")
    }
    failures = violations(sources)
    if args.self_test and not failures:
        try:
            self_test(sources)
        except RuntimeError as error:
            failures.append(str(error))
    for failure in failures:
        print(f"::error::epoch material cache owner: {failure}")
    if failures:
        return 1
    suffix = ", self-test" if args.self_test else ""
    print(f"epoch material cache owner: OK (1 epoch construction{suffix})")
    return 0
