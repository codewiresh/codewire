#!/usr/bin/env python3
"""Run a command under one GNU make jobserver of N tokens (compile once, infra#1632).

Usage: jobserver.py N -- COMMAND [ARG...]

Every Cargo the command starts, directly or through scripts, takes its rustc
jobs from the same pool: Cargo and rustc use a jobserver they find in
CARGO_MAKEFLAGS / MAKEFLAGS (--jobserver-auth=R,W) instead of sizing their
own. So several builds run side by side in separate target folders, and
whichever is still compiling gets the cores the others no longer use, while
at most N compilers (plus one implicit job per Cargo) run at once. A Cargo
that cannot reach the pool (a child that closed the descriptors) falls back
to its own CARGO_BUILD_JOBS, which the caller keeps small.
"""
import os
import sys


def main(argv):
    if len(argv) < 3 or argv[1] != "--" or not argv[0].isdigit() or not 1 <= int(argv[0]) <= 256:
        print("usage: jobserver.py N -- COMMAND [ARG...]  (1 <= N <= 256)", file=sys.stderr)
        return 2
    tokens = int(argv[0])
    read_fd, write_fd = os.pipe()
    # The protocol: each client holds one implicit token, so the pipe holds
    # the other N - 1.
    os.write(write_fd, b"+" * (tokens - 1))
    for fd in (read_fd, write_fd):
        os.set_inheritable(fd, True)
    flags = f"-j{tokens} --jobserver-fds={read_fd},{write_fd} --jobserver-auth={read_fd},{write_fd}"
    os.environ["MAKEFLAGS"] = flags
    os.environ["CARGO_MAKEFLAGS"] = flags
    os.environ.pop("MFLAGS", None)
    os.execvp(argv[2], argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
