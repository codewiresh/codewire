#!/usr/bin/env python3
"""Build the pinned git that the macOS local runtime ships.

Developer tooling for an Apple Silicon Mac with the system Python and the
Xcode Command Line Tools. A stock Mac's /usr/bin/git only asks for those
tools, so cw prepares workspace repositories with this build instead. From
the official source archive, checked by its SHA-256, it builds git and its
HTTPS remote helper linked only to stock system libraries, and writes them
to DIR/bundle for `make macos-local-runtime GIT_BUNDLE=DIR/bundle`. Nothing
is downloaded or installed; the new output directory is kept for inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

VERSION = "2.56.0"
SOURCE_NAME = "git-%s.tar.xz" % VERSION
SOURCE_URL = "https://www.kernel.org/pub/software/scm/git/" + SOURCE_NAME
SOURCE_SHA256 = "26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3"
SOURCE_LIMIT = 32 * 1024 * 1024
# No translations, Tcl/Tk, Perl, Python, WebDAV push or Rust; compiled-in
# paths that never exist, so only GIT_EXEC_PATH and explicit config apply.
MAKE_FLAGS = ("prefix=/nonexistent/codewire-git", "NO_GETTEXT=1", "NO_TCLTK=1", "NO_PERL=1",
              "NO_PYTHON=1", "NO_EXPAT=1", "NO_RUST=1", "NO_INSTALL_HARDLINKS=1",
              "CFLAGS=-O2 -g0")
# (make target, bundle name); the HTTPS helper is the HTTP helper's binary.
TARGETS = (("git", "git"), ("git-remote-http", "git-remote-https"))
LIBRARIES = {
    "/usr/lib/libSystem.B.dylib", "/usr/lib/libcurl.4.dylib", "/usr/lib/libz.1.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices",
}
TOOL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class BuildError(Exception):
    pass


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def run(argv: list, cwd: Path, log: Path, env: dict, timeout: int = 1800) -> bytes:
    with log.open("ab") as stream:
        stream.write(("$ " + " ".join(argv) + "\n").encode())
        stream.flush()
        result = subprocess.run(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=stream, timeout=timeout, check=False)
        stream.write(result.stdout)
    if result.returncode != 0:
        raise BuildError("command exited %d: %s (see %s)" % (result.returncode, " ".join(argv), log))
    return result.stdout


def check_program(path: Path, output: Path, env: dict) -> None:
    log = output / "build.log"
    report = run(["/usr/bin/otool", "-L", str(path)], output, log, env).decode().splitlines()[1:]
    dependencies = {line.split(" (", 1)[0].strip() for line in report}
    if not dependencies <= LIBRARIES:
        raise BuildError("%s links beyond the stock system libraries: %s"
                         % (path, sorted(dependencies - LIBRARIES)))
    if run(["/usr/bin/lipo", "-archs", str(path)], output, log, env).strip() != b"arm64":
        raise BuildError("%s is not arm64-only" % path)
    run(["/usr/bin/codesign", "--verify", "--strict", str(path)], output, log, env)


def build(archive: Path, output: Path) -> dict:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise BuildError("the runtime's git is built on an Apple Silicon Mac")
    if not archive.is_absolute() or not archive.is_file() or archive.stat().st_size > SOURCE_LIMIT:
        raise BuildError("--source-archive must be an absolute %s" % SOURCE_NAME)
    if digest(archive) != SOURCE_SHA256:
        raise BuildError("%s is not the official %s (sha256 %s)" % (archive, SOURCE_NAME, SOURCE_SHA256))
    if not output.is_absolute() or output.exists() or not output.parent.is_dir():
        raise BuildError("--output must be a new absolute directory beneath an existing one")
    output.mkdir(mode=0o700)
    bundle = output / "bundle"
    bundle.mkdir(mode=0o700)
    log = output / "build.log"
    env = {"PATH": TOOL_PATH, "LC_ALL": "C", "HOME": str(output), "TMPDIR": str(output) + "/"}
    run(["/usr/bin/tar", "-xf", str(archive), "-C", str(output)], output, log, env)
    source = output / ("git-" + VERSION)
    sdk = run(["/usr/bin/xcrun", "--show-sdk-path"], output, log, env).decode().strip()
    sdk_version = run(["/usr/bin/xcrun", "--show-sdk-version"], output, log, env).decode().strip()
    run(["/usr/bin/make", "-j8", "SDKROOT=" + sdk, *MAKE_FLAGS, *(target for target, _ in TARGETS)],
        source, log, dict(env, SDKROOT=sdk))
    tools = {}
    for target, name in TARGETS:
        program = bundle / name
        shutil.copyfile(source / target, program)
        program.chmod(0o500)
        check_program(program, output, env)
        tools[name] = digest(program)
    version = run(["/usr/bin/env", "-i", str(bundle / "git"), "--version"], output, log, env)
    if version != ("git version %s\n" % VERSION).encode():
        raise BuildError("the build reports %r, not git %s" % (version, VERSION))
    result = {"version": VERSION, "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
              "make_flags": list(MAKE_FLAGS), "sdk_version": sdk_version, "tools": tools}
    (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-archive", required=True, type=Path,
                        help="absolute path to the official %s" % SOURCE_NAME)
    parser.add_argument("--output", required=True, type=Path, help="new absolute output directory")
    args = parser.parse_args(argv)
    try:
        result = build(args.source_archive, args.output)
    except (BuildError, OSError, subprocess.TimeoutExpired) as error:
        print("macos-git-tool: ERROR: %s" % error, file=sys.stderr)
        return 1
    for name, checksum in result["tools"].items():
        print("macos-git-tool: %s sha256=%s" % (name, checksum))
    print("macos-git-tool: built %s/bundle (git %s)" % (args.output, VERSION))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
