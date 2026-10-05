"""Epoch-owned reuse guard (AGENTS.md "Repository invariants").

Decrypted provider material may be reused only within one platform broker
bridge epoch, and a hosted epoch's authority decision only within that epoch.
The only production code that creates an `EpochMaterialCache` or an
`EpochDecision` is therefore the bridge service's epoch admission (`admit` in
`crates/codewire-credential-broker/src/platform/bridge.rs`), each exactly
once. A `Decision` value is built only by that epoch's evaluation (`decide`
in `platform/decision.rs`), is private to its module, derives nothing, and
names no material type. Tests may create all of them freely. No source may
alias these types, hold them in a static, a lazy or once cell, or a thread
local, or call a `default` constructor: those are the ways a process-wide or
persistent cache would appear.

This is a source guard, not a proof: the types have no `Clone`, `Debug` or
`Default`, and their fields are private, so outside their own modules the
guarded constructors are the only way to obtain one.
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

DECISION_DEFINING = "crates/codewire-credential-broker/src/platform/decision.rs"
DECISION_BUILDER = "decide"
HOLDER = "EpochDecision"
DECISION = "Decision"
# Every type an epoch's decision is made of.
DECISION_TYPES = (HOLDER, DECISION)
HOLDER_CONSTRUCTION = re.compile(rf"\b{HOLDER}\s*::\s*(?:new|default)\b")
# `Decision` is private to its module (checked below), so only that module and
# its tests can name it; other modules may have unrelated types of that name.
HOLDER_NAME = re.compile(rf"\b{HOLDER}\b")
DECISION_NAMES = re.compile(rf"\b(?:{HOLDER}|{DECISION})\b")
HOLDER_ALIAS = re.compile(rf"\b{HOLDER}\s+as\b")
DECISION_ALIAS = re.compile(rf"\b(?:{HOLDER}|{DECISION})\s+as\b")
DECISION_LITERAL = re.compile(rf"\b{DECISION}\s*\{{")
MATERIAL_TYPES = re.compile(
    r"\b(?:ProtectedValue|EpochMaterialCache|PlatformCredentialLease|Zeroizing|material)\b"
)
FORBIDDEN_DERIVES = re.compile(r"\b(?:Clone|Copy|Debug|Default|Serialize|Deserialize)\b")


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


def struct_body(code: str, name: str) -> tuple[int, int, str] | None:
    """The braces of `struct name`, and the attributes written above it."""
    match = re.search(rf"\bstruct\s+{re.escape(name)}\b", code)
    if not match:
        return None
    start = code.find("{", match.end())
    end = code.find("}", start)
    if start < 0 or end < 0:
        return None
    line_start = code.rfind("\n", 0, match.start()) + 1
    attributes = []
    for line in reversed(code[:line_start].splitlines()):
        if not line.strip().startswith("#["):
            break
        attributes.append(line)
    return start, end, code[line_start:match.start()] + "\n".join(attributes)


def impl_bodies(code: str, name: str) -> list[tuple[int, int]]:
    bodies = []
    for match in re.finditer(rf"\bimpl\b[^{{;]*?\b{re.escape(name)}\s*\{{", code):
        depth = 0
        for position in range(match.end() - 1, len(code)):
            if code[position] == "{":
                depth += 1
            elif code[position] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append((match.end() - 1, position))
                    break
    return bodies


def decision_violations(sources: dict[str, str]) -> list[str]:
    """The epoch decision's ownership, shape and construction."""
    failures: list[str] = []
    holders = 0
    built = 0
    for path in sorted(sources):
        own = path == DECISION_DEFINING or path.startswith(DECISION_DEFINING[:-3] + "/")
        names, alias = (DECISION_NAMES, DECISION_ALIAS) if own else (HOLDER_NAME, HOLDER_ALIAS)
        if not names.search(sources[path]):
            continue
        code = code_only(sources[path])
        for number, line in enumerate(code.splitlines(), start=1):
            if names.search(line) and GLOBAL_HOLDERS.search(line):
                failures.append(f"{path}:{number}: an epoch decision must not be held process-wide")
        for match in alias.finditer(code):
            number = code.count("\n", 0, match.start()) + 1
            failures.append(f"{path}:{number}: an epoch decision type must not be aliased")
        if is_test_source(path):
            continue
        admit = function_body(code, OWNER_FUNCTION) if path == OWNER else None
        for match in HOLDER_CONSTRUCTION.finditer(code):
            number = code.count("\n", 0, match.start()) + 1
            if admit and admit[0] < match.start() < admit[1] and match.group(0).endswith("new"):
                holders += 1
            else:
                failures.append(
                    f"{path}:{number}: only bridge epoch admission ({OWNER} `{OWNER_FUNCTION}`) "
                    f"may create an {HOLDER}"
                )
        if path != DECISION_DEFINING:
            continue
        builder = function_body(code, DECISION_BUILDER)
        for match in DECISION_LITERAL.finditer(code):
            before = re.search(r"(\w+|->)\s*$", code[:match.start()])
            if before and before.group(1) in {"struct", "impl", "for", "enum", "->"}:
                continue
            number = code.count("\n", 0, match.start()) + 1
            if builder and builder[0] < match.start() < builder[1]:
                built += 1
            else:
                failures.append(
                    f"{path}:{number}: only an epoch's evaluation ({DECISION_DEFINING} "
                    f"`{DECISION_BUILDER}`) may build a {DECISION}"
                )
    code = code_only(sources.get(DECISION_DEFINING, ""))
    for name in DECISION_TYPES:
        found = struct_body(code, name)
        if found is None:
            failures.append(f"{DECISION_DEFINING}: struct {name} not found")
            continue
        start, end, preamble = found
        number = code.count("\n", 0, start) + 1
        if MATERIAL_TYPES.search(code[start:end]):
            failures.append(f"{DECISION_DEFINING}:{number}: {name} must name no material type")
        for derive in re.findall(r"#\[derive\(([^)]*)\)\]", preamble):
            if FORBIDDEN_DERIVES.search(derive):
                failures.append(f"{DECISION_DEFINING}:{number}: {name} must not derive {derive}")
        if name == DECISION and re.search(r"\bpub\b", preamble):
            failures.append(f"{DECISION_DEFINING}:{number}: {DECISION} must stay private to its module")
    for start, end in impl_bodies(code, DECISION):
        if re.search(r"\bSelf\s*\{", code[start:end]):
            number = code.count("\n", 0, start) + 1
            failures.append(f"{DECISION_DEFINING}:{number}: {DECISION} must be built only by `{DECISION_BUILDER}`")
    if holders != 1:
        failures.append(
            f"{OWNER} `{OWNER_FUNCTION}` must create exactly one {HOLDER} per hosted epoch "
            f"(found {holders})"
        )
    if built != 1:
        failures.append(
            f"{DECISION_DEFINING} `{DECISION_BUILDER}` must build exactly one {DECISION} "
            f"(found {built})"
        )
    return failures


def violations(sources: dict[str, str]) -> list[str]:
    failures: list[str] = decision_violations(sources)
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
    holder_construction = f"decision: hosted.then({HOLDER}::new),"
    if holder_construction not in sources.get(OWNER, ""):
        raise RuntimeError(f"self-test cannot find the epoch decision construction in {OWNER}")
    decision_struct = f"\nstruct {DECISION} {{\n"
    if decision_struct not in sources.get(DECISION_DEFINING, ""):
        raise RuntimeError(f"self-test cannot find struct {DECISION} in {DECISION_DEFINING}")

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
        "decision holder elsewhere": changed(
            service, lambda text: text + f"\nfn decision() -> {HOLDER} {{ {HOLDER}::new() }}\n"),
        "second decision holder outside admit": changed(
            OWNER, lambda text: text + f"\nfn spare() -> {HOLDER} {{ {HOLDER}::new() }}\n"),
        "no hosted decision holder": changed(
            OWNER, lambda text: text.replace(holder_construction, "decision: None,")),
        "default decision holder": changed(
            platform, lambda text: text + f"\nfn decision() -> {HOLDER} {{ {HOLDER}::default() }}\n"),
        "process-wide decision": changed(
            platform, lambda text: text + f"\nstatic DECISION: std::sync::OnceLock<{HOLDER}> = "
            "std::sync::OnceLock::new();\n"),
        "aliased decision holder": changed(
            service, lambda text: text + f"\nuse super::{HOLDER} as Holder;\n"),
        "decision built outside its evaluation": changed(
            DECISION_DEFINING, lambda text: text + f"\nfn spare() -> {DECISION} {{ {DECISION} {{ "
            "evaluation: 0 } }\n"),
        "decision built by Self": changed(
            DECISION_DEFINING, lambda text: text.replace(
                f"impl {DECISION} {{\n", f"impl {DECISION} {{\n    fn spare() -> Self {{ Self {{ "
                "evaluation: 0 } }\n", 1)),
        "decision holding material": changed(
            DECISION_DEFINING, lambda text: text.replace(
                decision_struct, f"{decision_struct}    value: ProtectedValue,\n", 1)),
        "decision holding a material cache": changed(
            DECISION_DEFINING, lambda text: text.replace(
                decision_struct, f"{decision_struct}    material: Option<{TYPE}>,\n", 1)),
        "cloneable decision": changed(
            DECISION_DEFINING, lambda text: text.replace(
                decision_struct, f"\n#[derive(Clone)]{decision_struct}", 1)),
        "debuggable decision holder": changed(
            DECISION_DEFINING, lambda text: text.replace(
                f"pub(super) struct {HOLDER} {{", f"#[derive(Debug)]\npub(super) struct {HOLDER} {{", 1)),
        "public decision": changed(
            DECISION_DEFINING, lambda text: text.replace(
                decision_struct, f"\npub(crate) struct {DECISION} {{\n", 1)),
        "decision in a test static": changed(
            "crates/codewire-credential-broker/src/platform/decision/tests.rs",
            lambda text: text + f"\nthread_local! {{ static D: {HOLDER} = {HOLDER}::new(); }}\n"),
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
        "unrelated type of the same name": changed(
            platform, lambda text: text + f"\nenum {DECISION} {{ Due }}\nfn due() -> {DECISION} {{ "
            f"{DECISION}::Due }}\n"),
        "test decision": changed(
            "crates/codewire-credential-broker/src/platform/tests/decision.rs",
            lambda text: text + f"\nfn spare() -> {HOLDER} {{ {HOLDER}::new() }}\n"),
        "commented decision": changed(
            service, lambda text: text + f"\n// {HOLDER}::new() and {DECISION} {{ }} are the epoch's.\n"),
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
    print(
        "epoch material cache owner: OK "
        f"(1 epoch construction, 1 hosted decision holder, 1 decision evaluation{suffix})"
    )
    return 0
