#!/usr/bin/env python3
"""One integration lane at a time per port range, testing only its own services.

Merge qualifications in different worktrees on one host use the same port
range for a lane (#2755). Two guards keep a lane from testing another run's
services:

  lock   holds a host-wide flock for one port range while the lane runs. A
         second lane waits, and logs which run holds the range. The lock is held
         by this helper process, never by an inherited descriptor, so a
         compiler-cache server or other long-lived child cannot keep it after
         the lane ends.
  owner  checks that the process listening on a port carries this run's
         token in its environment. A listener started by another run, or by
         another user, is refused.

Linux only: both read /proc.
"""

import argparse
import fcntl
import os
from pathlib import Path
import sys
import time


def lock(args):
    path = Path(args.file)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    holder = path.with_name(path.name + ".holder")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        try:
            held_by = holder.read_text().strip() or "an unnamed run"
        except OSError:
            held_by = "an unnamed run"
        print(f"[product-integration] waiting for the integration lane lock {path}, held by {held_by}",
              flush=True)
        began = time.monotonic()
        fcntl.flock(fd, fcntl.LOCK_EX)
        print(f"[product-integration] acquired {path} after {time.monotonic() - began:.0f}s", flush=True)
    holder.write_text(f"{args.label} pid={args.parent} since={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    Path(args.ready).write_text("locked\n")
    # Hold the lock until the lane's shell exits; its exit trap also stops us.
    while Path(f"/proc/{args.parent}").exists():
        time.sleep(0.5)


def listening_inodes(port):
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            local, state, inode = fields[1], fields[3], fields[9]
            if state == "0A" and int(local.rsplit(":", 1)[1], 16) == port:
                inodes.add(inode)
    return inodes


def socket_owners(inodes):
    owners, unreadable = set(), False
    wanted = {f"socket:[{inode}]" for inode in inodes}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            links = {os.readlink(fd) for fd in (entry / "fd").iterdir()}
        except OSError:
            unreadable = True
            continue
        if links & wanted:
            owners.add(int(entry.name))
    return owners, unreadable


def carries_token(pid, token):
    try:
        environ = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except OSError:
        return False
    return f"CODEWIRE_INTEGRATION_RUN_ID={token}".encode() in environ


def owner(args):
    inodes = listening_inodes(args.port)
    if not inodes:
        print(f"[product-integration] nothing listens on port {args.port}", file=sys.stderr)
        return 1
    owners, _ = socket_owners(inodes)
    if owners and all(carries_token(pid, args.token) for pid in owners):
        return 0
    found = ", ".join(str(pid) for pid in sorted(owners)) or "a process this user cannot inspect"
    print(f"::error::port {args.port} is served by {found}, not this run's {args.name}; "
          "another integration run is using this lane's ports", file=sys.stderr)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    held = commands.add_parser("lock")
    held.add_argument("--file", required=True)
    held.add_argument("--parent", type=int, required=True)
    held.add_argument("--label", required=True)
    held.add_argument("--ready", required=True)
    check = commands.add_parser("owner")
    check.add_argument("--port", type=int, required=True)
    check.add_argument("--token", required=True)
    check.add_argument("--name", required=True)
    args = parser.parse_args(argv)
    if args.command == "lock":
        lock(args)
        return 0
    return owner(args)


if __name__ == "__main__":
    sys.exit(main())
