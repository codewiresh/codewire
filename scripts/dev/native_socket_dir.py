#!/usr/bin/env python3
"""The short private socket directory cw uses for a native state root (#2735).

Mirrors `predicted` in crates/codewire-local-vmm/src/socket_dir.rs (its unit
tests run this file and compare): `<tmp>/cw-<uid>/<first 16 hex of
sha256(state root)>`, where `<tmp>` is `/tmp` on Linux and `/private/tmp` on
macOS, or the fallback `<tmp>/cw-<uid>.<suffix>` recorded in
`<state root>/socket-dir` when another user held the default name. It reads,
never creates. usage: native_socket_dir.py STATE_ROOT
"""
import hashlib
import os
import re
import sys
from pathlib import Path

RECORD = "socket-dir"


def temporary():
    return Path("/private/tmp" if sys.platform == "darwin" else "/tmp")


def predicted(state_root, uid=None):
    state_root = Path(state_root)
    uid = os.getuid() if uid is None else uid
    tmp = temporary()
    base = tmp / f"cw-{uid}"
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open(state_root / RECORD, flags), "rb") as handle:
            recorded = Path(handle.read(256).decode().rstrip("\n"))
        if recorded.parent == tmp and re.fullmatch(rf"cw-{uid}\.[A-Za-z0-9]+", recorded.name):
            base = recorded
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        pass
    digest = hashlib.sha256(os.fsencode(state_root)).hexdigest()
    return base / digest[:16]


if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.path.isabs(sys.argv[1]):
        sys.exit("usage: native_socket_dir.py ABSOLUTE_STATE_ROOT")
    print(predicted(sys.argv[1]))
