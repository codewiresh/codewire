#!/usr/bin/env python3
"""Small in-workspace denial/lifecycle probe; never reads provider material."""

import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import uuid

TOKEN = Path("/run/codewire-credentials/workspace/token")
ROOTS = "/run/codewire-credentials/gateway-roots/ca.crt"
CODEX_HOME = Path("/run/codewire-codex/home")
MODES = {"success": 200, "revoked": 403, "unbound": 403, "missing": 401}


def probe(environment: str, mode: str) -> None:
    if str(uuid.UUID(environment)) != environment or mode not in {*MODES, "wrong-root"}:
        raise ValueError("selection")
    if os.environ.get("CODEX_HOME") != str(CODEX_HOME) or os.environ.get("CODEX_CA_CERTIFICATE") != ROOTS:
        raise ValueError("projection")
    if (CODEX_HOME / "auth.json").exists():
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
