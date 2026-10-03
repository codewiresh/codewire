#!/usr/bin/env python3
"""Small in-workspace denial/lifecycle probe; never reads provider material."""

import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import uuid

TOKEN = Path("/run/codewire-credentials/workspace/token")
ROOTS = "/run/codewire-credentials/gateway-roots/ca.crt"
# Codex's default home on the persistent home volume. The workspace daemon
# writes Codewire's config.toml there, first line MANAGED_HEADER, until it
# delivers Codex's own ChatGPT login as auth.json with PLACEHOLDER in place
# of the refresh token.
CODEX_HOME = Path("/home/codewire/.codex")
MANAGED_HEADER = b"# Managed by Codewire. Delete this line to manage this file yourself."
MAX_MANAGED_CONFIG = 64 * 1024
PLACEHOLDER = "codewire-managed-no-refresh-token"
MAX_AUTH = 1024 * 1024
MODES = {"success": 200, "revoked": 403, "unbound": 403, "missing": 401}


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


def probe(environment: str, mode: str) -> None:
    if str(uuid.UUID(environment)) != environment or mode not in {*MODES, "wrong-root"}:
        raise ValueError("selection")
    # The current selected client uses daemon loopback, not a Codex CA/auth
    # override. This separate direct-HTTPS probe still loads its fixed public
    # ROOTS below; client selection must never weaken that transport proof.
    selected = mode in {"success", "revoked"}
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
        # These modes run before any application source or profile is selected.
        raise ValueError("unexpected-unselected-client")
    elif os.path.lexists(auth):
        raise ValueError("unexpected-provider-auth-file")
    # The expected synthetic provider values must not have entered the child
    # environment. The only token read below is its bounded Pod capability.
    if any("CW_KIND_SYNTHETIC_REFRESH_" in value or "synthetic-kind-signature" in value
           for value in os.environ.values()):
        raise ValueError("provider-environment-exposure")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if mode != "wrong-root":
        context.load_verify_locations(cafile=ROOTS)
    authority = f"cw-gateway-svc-{environment}.dev-sandboxes.svc.cluster.local"
    connection = http.client.HTTPSConnection(authority, context=context, timeout=20)
    try:
        headers = {"Content-Type": "application/json"}
        if mode not in {"missing", "wrong-root"}:
            with TOKEN.open("r", encoding="ascii") as source:
                token = source.read(16 * 1024 + 1).strip()
            if not token or len(token) > 16 * 1024 or any(c.isspace() for c in token):
                raise ValueError("capability-shape")
            headers["Authorization"] = f"Bearer {token}"
        body = json.dumps({"model": "codewire-synthetic", "input": "CW_KIND_LIFECYCLE", "stream": True})
        try:
            connection.request("POST", "/v1/responses", body=body, headers=headers)
            response = connection.getresponse()
        except ssl.SSLCertVerificationError:
            if mode != "wrong-root":
                raise
            print(json.dumps({"event": "wrong_root_denied"}), flush=True)
            return
        if mode == "wrong-root":
            raise ValueError("untrusted-root-accepted")
        payload = response.read(64 * 1024 + 1)
        if response.status != MODES[mode] or len(payload) > 64 * 1024:
            raise ValueError("response-status-or-bound")
        if b"CW_KIND_SYNTHETIC_REFRESH_" in payload or b"synthetic-kind-signature" in payload:
            raise ValueError("provider-response-exposure")
        if mode == "success" and b"CWCODEX149 kind" not in payload:
            raise ValueError("response-marker")
        print(json.dumps({"event": "credential_probe", "mode": mode, "status": response.status}), flush=True)
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("arguments")
        probe(sys.argv[1], sys.argv[2])
    except Exception:
        # No traceback, URL, header, token or raw provider response leaves the
        # workspace through a diagnostic failure.
        print(json.dumps({"event": "credential_probe_failed"}), flush=True)
        sys.exit(1)
