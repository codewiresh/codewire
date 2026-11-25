"""The sandbox identity token files stay out of projections and previews.

The daemon keeps each `--file` audience's token in `/codewire/run/identity`
(docs/dev/SANDBOX-IDENTITY.md, "In the Sandbox", Files), and the spec excludes
them from environment projections and previews with a test each (#4664).
Three rules hold that here, so an exclusion stands even for code that never
names the directory:

- Only the token-file code names the directory, by its constant or by the
  hosted state path that carries it.
- The projection modules, which deliver one launch's values, read no file at
  all: their values come only from the credential bridge's answer. They may
  still manage their own socket and check their helper's metadata.
- The preview proxy uses no file system and no daemon file call. It reaches a
  Sandbox only as TCP to one port, through the daemon's `ForwardTcp`.

A new file in either module joins its list after review.
"""

from .database_pools import TEST_FILE, production_source
from .shared import *

DIRECTORY = re.compile(r"\bHOSTED_DAEMON_IDENTITY_FILES_DIRECTORY\b")
DIRECTORY_NAMERS = (
    "crates/codewire-daemon-proto/src/lib.rs",
    "crates/codewire-daemon/src/hosted_state.rs",
)
# The hosted state path, and the grant's list of files, in the daemon crates
# where a copy path could otherwise read it.
FIELD = re.compile(r"\.identity_files\b")
FIELD_CRATES = ("crates/codewire-daemon/", "crates/codewire-cli/", "crates/codewire-workspace-access/")
FIELD_READERS = (
    "crates/codewire-cli/src/hosted_access.rs",
    "crates/codewire-cli/src/hosted_binding.rs",
    "crates/codewire-daemon/src/access.rs",
    "crates/codewire-daemon/src/hosted_state.rs",
)
FIELD_READER_MODULE = "crates/codewire-daemon/src/identity_files"

PROJECTION = (
    "crates/codewire-daemon/src/execution/bootstrap.rs",
    "crates/codewire-daemon/src/execution/projection.rs",
    "crates/codewire-workload-secrets/src/launch.rs",
    "crates/codewire-workload-secrets/src/launch/composition.rs",
    "crates/codewire-workload-secrets/src/launcher.rs",
)
PROJECTION_DIRECTORIES = (
    "crates/codewire-daemon/src/execution/bootstrap/",
    "crates/codewire-daemon/src/execution/projection/",
    "crates/codewire-workload-secrets/src/launch/",
    "crates/codewire-workload-secrets/src/launcher/",
)
# Opening, reading or copying any file, by path or through a directory
# handle, from the standard library or a lower-level crate.
FILE_READ = re.compile(
    r"\bFile::(?:open|create|options)\b|\bOpenOptions\b|\bread_to_string\b|\bfs::read(?:_dir|_link)?\b"
    r"|\bfs::copy\b|\btokio::fs\b|\bopenat2?\b|\breadlinkat\b|\bread_link\b|\bDir::read_from\b"
    r"|\b(?:fs|libc|fcntl)::open(?:at)?\b|\b(?:libc|rustix::fs|nix::fcntl)::\{[^}]*\bopen\b")

PREVIEW = "crates/codewire-orchestration/src/api/preview.rs"
PREVIEW_DIRECTORY = "crates/codewire-orchestration/src/api/preview/"
PREVIEW_UPSTREAM = "crates/codewire-orchestration/src/api/preview/upstream.rs"
# Any file system API, or a daemon file call or its request.
PREVIEW_FILE_ACCESS = re.compile(
    r"\bstd::fs\b|\bfs::\w+|\btokio::fs\b|\bFile::\w+|\bOpenOptions\b|\bopenat2?\b"
    r"|\bFileService\w*|\bconnect::file\b|\b(?:OpenFile|Read|Write|List|Stat|Readlink|Mkdir|Remove|Rename|SetStat)Request\b"
    r"|\.(?:open_file|read_dir|set_stat|readlink)\(")
FORWARD_TCP = re.compile(r"\.forward_tcp\(")


def rust_production(path: str, source: str) -> str | None:
    if not path.endswith(".rs") or TEST_FILE.search(path):
        return None
    return production_source(source)


def violations_from(sources: dict[str, str]) -> list[str]:
    """SOURCES maps repository paths under crates/ to their Rust text."""
    failures: list[str] = []
    for path, source in sorted(sources.items()):
        production = rust_production(path, source)
        if production is None:
            continue
        for match in DIRECTORY.finditer(production):
            if path not in DIRECTORY_NAMERS:
                failures.append(
                    f"{path}:{line_number(production, match.start())}: only the token-file code names the "
                    "identity token directory; a new reader is reviewed and added to DIRECTORY_NAMERS first (#4664)")
        if path.startswith(FIELD_CRATES) and not (path in FIELD_READERS or path.startswith(FIELD_READER_MODULE)):
            for match in FIELD.finditer(production):
                failures.append(
                    f"{path}:{line_number(production, match.start())}: only the token-file code reads "
                    "identity_files; a new reader is reviewed and added to FIELD_READERS first (#4664)")
        in_projection = path in PROJECTION or path.startswith(PROJECTION_DIRECTORIES)
        if in_projection and path not in PROJECTION:
            failures.append(f"{path}: a new projection module joins PROJECTION after review (#4664)")
        if in_projection:
            for match in FILE_READ.finditer(production):
                failures.append(
                    f"{path}:{line_number(production, match.start())}: a projection reads no file, so no "
                    f"identity token file reaches a launch's values: {match.group(0)} (#4664)")
        if path == PREVIEW or path.startswith(PREVIEW_DIRECTORY):
            for match in PREVIEW_FILE_ACCESS.finditer(production):
                failures.append(
                    f"{path}:{line_number(production, match.start())}: the preview proxy uses no file system "
                    f"and no daemon file call, only ForwardTcp: {match.group(0)} (#4664)")
    for path in PROJECTION:
        if path not in sources:
            failures.append(f"{path}: listed in PROJECTION but missing")
    if PREVIEW_UPSTREAM in sources and not FORWARD_TCP.search(production_source(sources[PREVIEW_UPSTREAM])):
        failures.append(f"{PREVIEW_UPSTREAM}: the preview proxy no longer reaches a port by ForwardTcp")
    elif PREVIEW_UPSTREAM not in sources:
        failures.append(f"{PREVIEW_UPSTREAM}: missing")
    return failures


def self_test() -> None:
    base = {path: "fn launch() {}" for path in PROJECTION}
    base[PREVIEW_UPSTREAM] = "fn dial() { client.forward_tcp(address); }"
    other = "crates/codewire-daemon/src/files.rs"
    for label, changes, expected in [
        ("the base", {}, 0),
        ("the definition", {DIRECTORY_NAMERS[0]: "pub const HOSTED_DAEMON_IDENTITY_FILES_DIRECTORY: &str = \"\";"}, 0),
        ("another namer", {other: "let d = HOSTED_DAEMON_IDENTITY_FILES_DIRECTORY;"}, 1),
        ("a comment naming it", {other: "// HOSTED_DAEMON_IDENTITY_FILES_DIRECTORY"}, 0),
        ("a test naming it", {"crates/codewire-daemon/src/files/tests.rs": "HOSTED_DAEMON_IDENTITY_FILES_DIRECTORY"}, 0),
        ("the loop reading the path", {"crates/codewire-daemon/src/identity_files/renewal.rs": "paths.identity_files"}, 0),
        ("a copy path reading it", {"crates/codewire-workspace-access/src/scp.rs": "paths.identity_files"}, 1),
        ("orchestration's own list", {"crates/codewire-orchestration/src/x.rs": "access.identity_files"}, 0),
        ("a projection opening a file", {PROJECTION[1]: "fn f() { File::open(path) }"}, 1),
        ("a projection reading a file", {PROJECTION[2]: "fn f() { std::fs::read_to_string(p) }"}, 1),
        ("a projection through a handle", {PROJECTION[0]: "fn f() { openat2(dir, p) }"}, 1),
        ("a projection's own socket", {PROJECTION[1]: "fn f() { fs::set_permissions(s, m); fs::remove_file(s); }"}, 0),
        ("a projection calling libc", {PROJECTION[1]: "fn f() { unsafe { libc::open(p, flags) } }"}, 1),
        ("a projection importing rustix's open", {PROJECTION[4]: "use rustix::fs::{Mode, OFlags, open};"}, 1),
        ("a projection calling nix", {PROJECTION[3]: "fn f() { nix::fcntl::open(p, f, m) }"}, 1),
        ("a projection copying a file", {PROJECTION[2]: "fn f() { std::fs::copy(a, b) }"}, 1),
        ("a projection opening through its rustix import", {PROJECTION[0]: "use rustix::fs;\nfn f() { fs::open(p, o, m) }"}, 1),
        ("a projection opening through its nix import", {PROJECTION[0]: "use nix::fcntl;\nfn f() { fcntl::open(p, f, m) }"}, 1),
        ("a projection's rustix socket mode", {PROJECTION[1]: "use rustix::fs::{Mode, fchmod};"}, 0),
        ("a cipher opening a box", {PROJECTION[4]: "fn f() { recipient.open(&ciphertext) }"}, 0),
        ("a new projection module", {"crates/codewire-daemon/src/execution/projection/values.rs": "fn f() {}"}, 1),
        ("a projection test file", {"crates/codewire-daemon/src/execution/projection/tests.rs": "File::open(p)"}, 0),
        ("a preview reading a file", {PREVIEW: "fn f() { tokio::fs::read(p) }"}, 1),
        ("a preview asking for metadata", {PREVIEW: "fn f() { std::fs::metadata(p) }"}, 1),
        ("a preview calling the files API", {PREVIEW_DIRECTORY + "browser.rs": "client.open_file(OpenFileRequest {})"}, 2),
        ("a preview's include_str", {PREVIEW: "const PAGE: &str = include_str!(\"denied.html\");"}, 0),
        ("a preview test", {PREVIEW: "#[cfg(test)]\nmod tests { fn f() { std::fs::read(p) } }"}, 0),
        ("no ForwardTcp", {PREVIEW_UPSTREAM: "fn dial() {}"}, 1),
    ]:
        failures = violations_from({**base, **changes})
        assert len(failures) == expected, f"{label}: {failures}"


def check_identity_file_exclusions(args: argparse.Namespace) -> int:
    if args.self_test:
        self_test()
        print("identity file exclusions self-test: OK")
        return 0
    sources = {
        path: read_text(path)
        for path in git_source_files()
        if path.startswith("crates/") and path.endswith(".rs")
    }
    failures = violations_from(sources)
    for failure in failures:
        print(f"::error::identity file exclusions: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"identity file exclusions: OK ({len(sources)} Rust files, {len(PROJECTION)} projection modules)")
    return 0
