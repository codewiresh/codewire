#!/usr/bin/env python3
"""Select the pinned workspace image that `build-workspace-disk` builds (#5638).

The optional systemd override pin is:
  deployments/k8s/orchestration/workspace-systemd-image.digest

It holds one line: `unpinned` or a `sha256:` digest published for
`workspace-systemd` (Harbor and its public GHCR mirror).

- When `unpinned`, every `show` field delegates to `workspace-image-pin.py`
  (`codewire/workspace`).
- When pinned to a digest, `show` returns the `workspace-systemd` digest and
  its public GHCR and Harbor digest references so `deploy-dev.yaml` builds,
  pushes and signs the `standard` workspace disk from `workspace-systemd`
  without changing the KVM runner's zero-credential boundary.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PIN = "deployments/k8s/orchestration/workspace-systemd-image.digest"
UNPINNED = "unpinned"
PUBLIC_SYSTEMD_REPOSITORY = "ghcr.io/codewiresh/workspace-systemd"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_RE = re.compile(r"^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?$")
FIELDS = ("digest", "public-image", "harbor-image")


class PinError(Exception):
    pass


def load_workspace_pin_module():
    spec = importlib.util.spec_from_file_location(
        "workspace_image_pin",
        ROOT / "scripts/ci/images/workspace-image-pin.py",
    )
    if spec is None or spec.loader is None:
        raise PinError("workspace-image-pin.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_pin(text: str) -> str:
    """Return the pinned sha256 digest, or empty string when unpinned."""
    lines = text.split("\n")
    if len(lines) != 2 or lines[1] != "":
        raise PinError(f"{PIN} must be exactly one line")
    if lines[0] == UNPINNED:
        return ""
    if not DIGEST_RE.fullmatch(lines[0]):
        raise PinError(f"{PIN} pins {lines[0]!r}, not {UNPINNED} or a sha256 digest")
    return lines[0]


def read_pin(root: Path, commit: str | None) -> str:
    if commit is None:
        path = root / PIN
        if not path.is_file() or path.is_symlink():
            raise PinError(f"{PIN} is missing or a symlink")
        return parse_pin(path.read_text(encoding="utf-8"))
    workspace_pin = load_workspace_pin_module()
    text = workspace_pin.show_file(root, commit, PIN)
    if text is None:
        raise PinError(f"{commit} has no {PIN}")
    return parse_pin(text)


def harbor_host() -> str:
    host = os.environ.get("CODEWIRE_IMAGE_REGISTRY", "")
    if not REGISTRY_RE.fullmatch(host):
        raise PinError("CODEWIRE_IMAGE_REGISTRY must name the image registry host")
    return host


def show_field(root: Path, commit: str | None, field_name: str) -> str:
    systemd_digest = read_pin(root, commit)
    if systemd_digest:
        if field_name == "digest":
            return systemd_digest
        if field_name == "public-image":
            return f"{PUBLIC_SYSTEMD_REPOSITORY}@{systemd_digest}"
        if field_name == "harbor-image":
            return f"{harbor_host()}/codewire/workspace-systemd@{systemd_digest}"
        raise PinError(f"unknown field {field_name!r}")

    workspace_pin = load_workspace_pin_module()
    try:
        pin = workspace_pin.read_pin(root, commit)
        return str(workspace_pin.field(pin, field_name))
    except workspace_pin.PinError as error:
        raise PinError(str(error)) from None


def render_pin(root: Path, value: str) -> None:
    if value != UNPINNED and not DIGEST_RE.fullmatch(value):
        raise PinError(f"not {UNPINNED} or a sha256 digest: {value!r}")
    path = root / PIN
    if path.is_symlink():
        raise PinError(f"{PIN} is a symlink")
    path.write_text(f"{value}\n", encoding="utf-8")
    parse_pin(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", default=str(ROOT))
    commands = parser.add_subparsers(dest="command", required=True)

    show_parser = commands.add_parser("show")
    show_parser.add_argument("--commit")
    show_parser.add_argument("field", choices=FIELDS)

    check_parser = commands.add_parser("check")
    check_parser.add_argument("--commit")

    render_parser = commands.add_parser("render")
    target = render_parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--digest")
    target.add_argument("--unpinned", action="store_true")

    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "show":
            print(show_field(root, args.commit, args.field))
        elif args.command == "check":
            digest = read_pin(root, args.commit)
            if digest:
                print(f"workspace disk source: workspace-systemd ({digest})")
            else:
                print("workspace disk source: canonical workspace pin (unpinned)")
        elif args.command == "render":
            render_pin(root, UNPINNED if args.unpinned else args.digest)
    except PinError as error:
        print(f"workspace disk source: ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
