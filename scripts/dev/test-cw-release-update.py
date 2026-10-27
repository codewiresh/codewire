#!/usr/bin/env python3
"""Observed public cw install, update and rollback journey for a release (#2064).

Run on each platform under test (a release's acceptance, Linux and macOS):

  scripts/dev/test-cw-release-update.py --from v0.3.387 --to v0.3.388
  scripts/dev/test-cw-release-update.py --from v0.3.387 --to v0.3.388 --channel

Before the release reaches Production, pass the Dev installer with
--install-url https://codewire-dev.sh/install.sh. (scripts/dev/test-cli-update.py
is the separate local `--from` journey for development builds.)

It proves, against the public release origin and the published install.sh:
- install.sh installs FROM as a managed cw for a user with nothing installed;
- `cw upgrade --version TO` (or bare `cw upgrade`, which follows the stable
  channel, with --channel) selects TO for new invocations, while FROM's
  stored bytes keep running for anything that saved their path;
- `cw upgrade rollback` selects FROM again, and `cw upgrade rollback --to TO`
  selects TO;
- `cw upgrade status --json` reports each selection exactly.

Releases before the flat command grammar spell the updater `cw update`; each
step asks the cw that runs it which spelling it has (see `Journey.updater`).

Everything runs as a new user would: its own HOME and XDG directories under a
private scratch root, a stock PATH, and no inherited Codewire environment. The
real user's managed cw and store are checked to be untouched. Where a
firewall prompts for new binaries, --before-network runs a command as the
caller with the path of the cw about to reach the network: on a Mac with
Little Snitch, for example, a pin of that exact binary. On Linux, run with
TMPDIR under a directory the host firewall already admits for that use.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

INSTALL_URL = "https://codewire.sh/install.sh"
STOCK_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class JourneyError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise JourneyError(reason)


def selects(output, tag):
    """Whether a selection's report names release `tag`: "Selected cw TAG"
    before #3548, "Upgraded cw to TAG" or "Rolled back cw to TAG" after."""
    return re.search(rf"\bcw (?:to )?{re.escape(tag)}\b", output) is not None


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


class Journey:
    def __init__(self, root):
        self.root = root
        # A new user: stock HOME defaults, no XDG overrides.
        self.bin = root / "prefix" / "bin"
        self.store = root / "home" / ".local" / "share" / "codewire" / "cli"
        self.env = {
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "PATH": f"{self.bin}:{STOCK_PATH}",
            "LC_ALL": "C",
        }
        for name in ("home", "tmp"):
            (root / name).mkdir(mode=0o700)
        self.steps = []
        self.spellings = {}

    def run(self, argv, timeout=900, operator=False):
        """Run as the journey's new user, or with operator=True as the caller."""
        started = time.monotonic()
        result = subprocess.run(argv, env=None if operator else self.env,
                                cwd=None if operator else self.env["HOME"], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout, check=False)
        self.steps.append({"argv": [str(arg) for arg in argv], "exit": result.returncode,
                           "seconds": round(time.monotonic() - started, 2)})
        if result.returncode != 0:
            raise JourneyError(f"{' '.join(map(str, argv))} exited {result.returncode}:\n"
                               f"{result.stdout[-2000:]}{result.stderr[-2000:]}")
        return result.stdout + result.stderr

    def cw(self, *args, timeout=900):
        return self.run([self.bin / "cw", *args], timeout=timeout)

    def updater(self):
        """The CLI updater command of the cw the entry selects now: `upgrade`,
        or `update` for a release from before `cw upgrade`. A cw with `cw
        upgrade` answers its help; an older one has no such command."""
        target = os.path.realpath(self.bin / "cw")
        if target not in self.spellings:
            probe = subprocess.run([target, "upgrade", "--help"], env=self.env, cwd=self.env["HOME"],
                                   stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                   timeout=60, check=False)
            self.spellings[target] = "upgrade" if probe.returncode == 0 else "update"
        return self.spellings[target]

    def status(self):
        return json.loads(self.cw(self.updater(), "status", "--json"))

    def version(self, path=None):
        return self.run([path or self.bin / "cw", "--version"]).strip()

    def selected(self, expected, previous=None):
        """The entry, status and version all name `expected` (a release tag)."""
        status = self.status()
        versions = {version["sha256"]: version.get("package_version") for version in status["versions"]}
        current = status["current"]
        require(status["consistent"] and status.get("pending") is None,
                f"the store is not consistent after selecting {expected}: {status}")
        require(versions.get(current) == expected, f"current is {versions.get(current)}, expected {expected}")
        if previous is not None:
            require(versions.get(status["previous"]) == previous,
                    f"previous is {versions.get(status['previous'])}, expected {previous}")
        entry = self.bin / "cw"
        require(entry.is_symlink(), "the cw entry is not a managed link")
        target = Path(os.path.realpath(entry))
        require(target == (self.store / "versions" / current / "cw").resolve(),
                f"the entry names {target}, not version {current}")
        require(digest(target) == current, f"the selected bytes are not {current}")
        reported = self.version()
        require(expected.lstrip("v") in reported, f"cw --version reports {reported!r}, expected {expected}")
        return current


def remove(root):
    """Remove the scratch root; stored versions are read-only by design."""
    for directory, _, _ in os.walk(root):
        os.chmod(directory, 0o700)
    shutil.rmtree(root)


def real_install():
    """The real user's managed entry and selection, to prove they are untouched."""
    home = Path(os.path.expanduser("~"))
    entry = Path(os.environ.get("XDG_BIN_HOME") or home / ".local/bin") / "cw"
    data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local/share")
    selection = data / "codewire/cli/selection.json"
    return {"entry": os.readlink(entry) if entry.is_symlink() else (entry.exists() and "file" or None),
            "selection": digest(selection) if selection.exists() else None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--from", dest="source", required=True, help="release tag installed first")
    parser.add_argument("--to", required=True, help="release tag updated to")
    parser.add_argument("--channel", action="store_true",
                        help="update with bare `cw upgrade` (`cw update` before it; stable channel); "
                             "TO must be the stable release")
    parser.add_argument("--install-url", default=INSTALL_URL)
    parser.add_argument("--before-network", help="command run with the path of a cw about to use the network")
    parser.add_argument("--keep", action="store_true", help="keep the scratch root")
    args = parser.parse_args(argv)
    for tag in (args.source, args.to):
        require(tag.startswith("v") and tag[1:].replace(".", "").isdigit(), f"not a release tag: {tag}")
    require(args.source != args.to, "--from and --to must differ")

    before = real_install()
    # A plain [a-z0-9-] name, so a host firewall rule can match the stored versions.
    # Resolved: install.sh refuses a prefix under a symbolic link such as macOS's
    # /var -> /private/var, where the default TMPDIR lives.
    base = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()).resolve()
    root = base / f"cwu-{secrets.token_hex(6)}"
    root.mkdir(mode=0o700)
    journey = Journey(root)
    report = {"from": args.source, "to": args.to, "channel": args.channel, "root": str(root)}
    try:
        installer = root / "install.sh"
        journey.run(["curl", "-fsSL", "--proto", "=https", "-o", installer, args.install_url], timeout=120)
        report["install_sh_sha256"] = digest(installer)
        output = journey.run(["sh", installer, "--version", args.source, "--prefix", root / "prefix"])
        require(f"Installed cw {args.source}" in output, f"install.sh did not report {args.source}:\n{output}")
        source_sha = journey.selected(args.source)
        report["from_sha256"] = source_sha
        source_bytes = journey.store / "versions" / source_sha / "cw"

        if args.before_network:
            journey.run([*args.before_network.split(), source_bytes], timeout=300, operator=True)
        updater = journey.updater()
        update = [updater] if args.channel else [updater, "--version", args.to]
        output = journey.cw(*update)
        require(selects(output, args.to), f"the update did not select {args.to}:\n{output}")
        target_sha = journey.selected(args.to, previous=args.source)
        report["to_sha256"] = target_sha
        # A saved path to FROM's bytes keeps running FROM.
        require(args.source.lstrip("v") in journey.version(source_bytes), "FROM's stored bytes changed")

        output = journey.cw(journey.updater(), "rollback")
        require(selects(output, args.source), f"rollback did not select {args.source}:\n{output}")
        journey.selected(args.source, previous=args.to)
        output = journey.cw(journey.updater(), "rollback", "--to", args.to)
        require(selects(output, args.to), f"rollback --to did not select {args.to}:\n{output}")
        journey.selected(args.to, previous=args.source)

        require(real_install() == before, "the real user's managed cw changed")
        report["result"] = "passed"
    except (JourneyError, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        report["result"] = "failed"
        report["error"] = str(error)
    finally:
        report["steps"] = journey.steps
        if not args.keep:
            try:
                remove(root)
            except OSError as error:
                report["result"] = "failed"
                report["error"] = f"{report.get('error', '')} the scratch root was not removed: {error}".strip()
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
