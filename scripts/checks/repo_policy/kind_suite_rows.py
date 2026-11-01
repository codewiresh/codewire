"""Every workspace crate has its own row in the Kind suite selection.

scripts/dev/kind/test-selected.sh maps each crate's selection token
(`rust_pkg_<crate>` or `transport_pkg_<crate>`) to the Kind suites that observe
it, or to `unobserved` or `full` with a reason. A crate without a row is
neither, so its change selects nothing in Kind without saying why. This lives
in Policy rather than in the Kind tool tests because a pull request runs those
only with its Kind opt-in, so a crate added without a row reached main
(codewire-ext4-scrub, #3800; main run 32192, fixed by #3814).
"""

from __future__ import annotations

from .shared import *

SELECTED = "scripts/dev/kind/test-selected.sh"
# The selector reports these crates through another crate's token.
ALIASES = {"codewire-ui": "codewire-desktop"}


def map_token_table(text: str) -> str | None:
    """The `map_token` case table, up to its catch-all for unknown crates."""
    start = text.find("map_token() {")
    end = text.find("rust_pkg_* | transport_pkg_*)", start)
    if start < 0 or end < 0:
        return None
    return text[start:end]


def missing_rows(crates: list[str], table: str) -> list[str]:
    """The crates of `crates` with no token row in `table`."""
    missing = []
    for crate in crates:
        token = ALIASES.get(crate, crate).replace("-", "_")
        if not re.search(rf"(rust|transport)_pkg_{token}\b", table):
            missing.append(crate)
    return missing


def workspace_crates() -> list[str]:
    return sorted(path.parent.name for path in (ROOT / "crates").glob("*/Cargo.toml"))


def self_test() -> list[str]:
    failures: list[str] = []
    table = map_token_table(
        'map_token() {\n  case "$token" in\n'
        "    rust_pkg_codewire_a | transport_pkg_codewire_b) want x ;;\n"
        "    rust_pkg_codewire_desktop) unobserved \"$token\" 'desktop only' ;;\n"
        "    rust_pkg_codewire_ab_c) full \"$token\" 'every service' ;;\n"
        "    rust_pkg_* | transport_pkg_*)\n"
        "      rust_pkg_codewire_after_the_table ;;\n"
    )
    if table is None:
        return ["kind suite rows self-test: the fixture's table was not found"]
    if missing_rows(["codewire-a", "codewire-b", "codewire-ui", "codewire-ab-c"], table):
        failures.append("kind suite rows self-test: a crate with a row was reported missing")
    if missing_rows(["codewire-c"], table) != ["codewire-c"]:
        failures.append("kind suite rows self-test: a crate without a row was admitted")
    # A row for a longer name is not a row for its prefix.
    if missing_rows(["codewire-ab"], table) != ["codewire-ab"]:
        failures.append("kind suite rows self-test: a prefix of another crate's row was admitted")
    # Only the table counts, not the catch-all below it.
    if missing_rows(["codewire-after-the-table"], table) != ["codewire-after-the-table"]:
        failures.append("kind suite rows self-test: a token after the table was admitted")
    if map_token_table("no table here") is not None:
        failures.append("kind suite rows self-test: a file without the table gave one")
    return failures


def check_kind_suite_rows(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("kind suite rows", self_test()):
            return 1
        print("kind suite rows: OK (self-test)")
        return 0
    table = map_token_table(read_text(SELECTED))
    if table is None:
        return report("kind suite rows", [f"{SELECTED} has no map_token table"])
    crates = workspace_crates()
    failures = [
        f"crates/{crate} has no rust_pkg_ or transport_pkg_ row in {SELECTED} map_token: "
        "add one naming the Kind suites that observe it, or `unobserved` with the reason"
        for crate in missing_rows(crates, table)
    ]
    if report("kind suite rows", failures):
        return 1
    print(f"kind suite rows: OK ({len(crates)} crates)")
    return 0
