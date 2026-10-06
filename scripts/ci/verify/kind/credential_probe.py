#!/usr/bin/env python3
"""Small in-workspace credential projection probe.

It reads no provider material or Pod capability and makes no request: proxied
requests cross the workspace daemon (daemon_probe.py).
"""

import json
import os
from pathlib import Path
import stat
import sys

# Codex's default home on the persistent home volume. The workspace daemon
# writes Codewire's config.toml there, first line MANAGED_HEADER, until it
# delivers Codex's own ChatGPT login as auth.json with PLACEHOLDER in place
# of the refresh token.
CODEX_HOME = Path("/home/codewire/.codex")
MANAGED_HEADER = b"# Managed by Codewire. Delete this line to manage this file yourself."
MAX_MANAGED_CONFIG = 64 * 1024
PLACEHOLDER = "codewire-managed-no-refresh-token"
MAX_AUTH = 1024 * 1024
MODES = {"selected", "unselected"}


def managed_config(path: Path) -> bool:
    """Whether path is Codewire's daemon-written file: regular, not a symlink,
    first line exactly the managed header."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    with os.fdopen(descriptor, "rb") as source:
        contents = source.read(MAX_MANAGED_CONFIG + 1)
    return contents.split(b"\n", 1)[0] == MANAGED_HEADER


def codewire_login(path: Path) -> bool:
    """Whether path is Codewire's delivered login: a regular file, not a
    symlink, in ChatGPT mode with exactly the placeholder refresh token and
    none of the broker's refresh tokens."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    with os.fdopen(descriptor, "rb") as source:
        contents = source.read(MAX_AUTH + 1)
    if len(contents) > MAX_AUTH or b"CW_KIND_SYNTHETIC_REFRESH_" in contents:
        return False
    try:
        document = json.loads(contents)
    except ValueError:
        return False
    tokens = document.get("tokens") if isinstance(document, dict) else None
    return (document.get("auth_mode") == "chatgpt" and isinstance(tokens, dict)
            and tokens.get("refresh_token") == PLACEHOLDER)


def probe(mode: str) -> None:
    if mode not in MODES:
        raise ValueError("selection")
    # The selected client uses daemon loopback, never a Codex CA/auth override.
    selected = mode == "selected"
    if "CODEX_CA_CERTIFICATE" in os.environ:
        raise ValueError("projection")
    # An environment-token Pod renders the selection and CODEX_HOME; an
    # identity-free Pod renders neither, and this kubectl-exec'd probe then
    # sees Codex's default home. Either way the daemon owns the files there:
    # Codewire's config.toml, or Codewire's auth.json once it delivered
    # Codex's own login, and never a user's file in their place.
    rendered = (os.environ.get("CODEX_HOME"), os.environ.get("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"))
    config = CODEX_HOME / "config.toml"
    auth = CODEX_HOME / "auth.json"
    if selected:
        if (rendered not in {(None, None), (str(CODEX_HOME), "v1:codex")}
                or (os.path.lexists(config) and not managed_config(config))):
            raise ValueError("projection")
        if os.path.lexists(auth) and not codewire_login(auth):
            raise ValueError("unexpected-provider-auth-file")
    elif rendered != (None, None) or os.path.lexists(config):
        # This mode runs before any application source or profile is selected.
        raise ValueError("unexpected-unselected-client")
    elif os.path.lexists(auth):
        raise ValueError("unexpected-provider-auth-file")
    # The expected synthetic provider values must not have entered the child
    # environment.
    if any("CW_KIND_SYNTHETIC_REFRESH_" in value or "synthetic-kind-signature" in value
           for value in os.environ.values()):
        raise ValueError("provider-environment-exposure")
    print(json.dumps({"event": "credential_projection", "mode": mode}), flush=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("arguments")
        probe(sys.argv[1])
    except Exception:
        # No traceback, path or provider value leaves the workspace through a
        # diagnostic failure.
        print(json.dumps({"event": "credential_projection_failed"}), flush=True)
        sys.exit(1)
