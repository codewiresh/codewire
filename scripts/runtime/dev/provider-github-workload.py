#!/usr/bin/env python3
"""One stock gh read-only request through the existing managed Unix ingress."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile


GH_BIN = Path("/usr/local/bin/gh")
EXPECTED_LOGIN = Path("/workspace/.cw-provider-github/expected-login")
SOCKET = Path("/run/codewire-host/credential.sock")
SCRATCH_PARENT = Path("/dev/shm")
CAPTURE_LIMIT = 1_048_576
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", re.ASCII)
VERSION = re.compile(
    rb"gh version 2\.97\.0 \([0-9]{4}-[0-9]{2}-[0-9]{2}\)\n"
    rb"https://github\.com/cli/cli/releases/tag/v2\.97\.0\n",
)


def private_file(path: Path, mode: int) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("invalid private file")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def capture(args: list[str], environment: dict[str, str], scratch: Path,
            label: str, duration: int) -> bytes:
    output, error = scratch / (label + ".out"), scratch / (label + ".err")
    with output.open("xb") as stdout, error.open("xb") as stderr:
        child = subprocess.Popen(
            ["/usr/bin/timeout", "--kill-after=5s", str(duration) + "s", str(GH_BIN), *args],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            env=environment, cwd=scratch, start_new_session=True,
        )
        try:
            code = child.wait(timeout=duration + 10)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
    for path in (output, error):
        private_file(path, 0o600)
        if path.stat().st_size >= CAPTURE_LIMIT:
            raise ValueError("capture exceeded bound")
    if code != 0 or error.stat().st_size:
        raise ValueError("stock command failed")
    return output.read_bytes()


def run() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAPTURE_LIMIT, CAPTURE_LIMIT))
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise ValueError("core limit unavailable")
    info = GH_BIN.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise ValueError("stock executable unavailable")
    if not stat.S_ISSOCK(SOCKET.lstat().st_mode):
        raise ValueError("managed socket unavailable")
    # The prepared native artifact/image chain owns this pinned stock binary;
    # no download, alternate executable or caller-selected endpoint is allowed.
    private_file(EXPECTED_LOGIN, 0o400)
    if EXPECTED_LOGIN.stat().st_size > 39:
        raise ValueError("invalid account hint")
    expected = EXPECTED_LOGIN.read_text(encoding="ascii")
    if LOGIN.fullmatch(expected) is None:
        raise ValueError("invalid account hint")
    if (SCRATCH_PARENT.is_symlink()
            or subprocess.check_output(
                ["/usr/bin/findmnt", "-nro", "FSTYPE", "-T", str(SCRATCH_PARENT)],
                env={"PATH": "/usr/bin:/bin"}, timeout=5,
            ) != b"tmpfs\n"):
        raise ValueError("private tmpfs unavailable")
    with tempfile.TemporaryDirectory(prefix=".cw-live-github.", dir=SCRATCH_PARENT) as name:
        scratch = Path(name)
        if stat.S_IMODE(scratch.stat().st_mode) != 0o700:
            raise ValueError("private scratch unavailable")
        config = scratch / "config.yml"
        config.write_text('version: "1"\nhttp_unix_socket: ' + str(SOCKET) + "\n", encoding="ascii")
        private_file(config, 0o600)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": name, "GH_CONFIG_DIR": name,
            "XDG_CONFIG_HOME": name, "XDG_CACHE_HOME": name, "TMPDIR": name,
            "GH_HOST": "github.com", "GH_TOKEN": "codewire-managed",
            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "LC_ALL": "C",
        }
        if VERSION.fullmatch(capture(["--version"], environment, scratch, "version", 10)) is None:
            raise ValueError("stock version mismatch")
        payload = capture(["api", "--method", "GET", "user", "--hostname", "github.com"],
                          environment, scratch, "account", 110)
        account = json.loads(payload, object_pairs_hook=unique_object)
        if (not isinstance(account, dict) or account.get("login") != expected
                or type(account.get("id")) is not int or account["id"] <= 0
                or account.get("type") != "User"):
            raise ValueError("account mismatch")


def interrupted(_signal: int, _frame: object) -> None:
    raise InterruptedError("interrupted")


def main(argv: list[str]) -> int:
    try:
        for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(number, interrupted)
        if len(argv) != 1:
            raise ValueError("unsupported arguments")
        run()
    except BaseException:
        sys.stderr.write("CW_LIVE_GITHUB_ERROR\n")
        return 1
    sys.stdout.write("CW_LIVE_GITHUB_OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
