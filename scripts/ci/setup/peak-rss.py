#!/usr/bin/env python3
"""peak-rss.py OUT -- COMMAND...: run COMMAND and write its process tree's
peak resident memory, in MiB, to OUT.

build-once runs each leg and the Rust checks under it, so the job log names
what each one held at its peak (codewire#5776: a wide, cold build reached the
pull request build VM's memory limit, and nothing said which part). The tree
is sampled every 2 s from /proc, so a shorter peak can be missed; the number
is a floor, not an exact peak. COMMAND's exit status is this script's.
"""

import os
import re
import signal
import subprocess
import sys
import threading

PAGE = os.sysconf("SC_PAGE_SIZE")
JOBSERVER_FLAG = re.compile(r"--jobserver-(?:auth|fds)=(\d+),(\d+)")


def jobserver_fds():
    """Return open pipe descriptors named by GNU make / Cargo jobserver flags.

    subprocess.Popen defaults to close_fds=True, which closes the descriptors
    jobserver.py opened for Cargo and forces every leg back to its small
    CARGO_BUILD_JOBS. Pass only the jobserver descriptors through so unrelated
    descriptors (such as flock handles) stay closed.
    """
    fds = set()
    for var in ("CARGO_MAKEFLAGS", "MAKEFLAGS"):
        flags = os.environ.get(var, "")
        for match in JOBSERVER_FLAG.finditer(flags):
            for raw in match.groups():
                fd = int(raw)
                if fd > 2:
                    try:
                        os.fstat(fd)
                    except OSError:
                        continue
                    fds.add(fd)
    return sorted(fds)


def tree_rss(root):
    """The resident bytes of ROOT and every process descended from it."""
    children = {}
    rss = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as stat:
                fields = stat.read().rsplit(")", 1)[1].split()
            # After the command name: state, ppid, ...; rss is field 24 overall.
            ppid, pages = int(fields[1]), int(fields[21])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(entry))
        rss[int(entry)] = pages * PAGE
    total, todo = 0, [root]
    while todo:
        pid = todo.pop()
        total += rss.get(pid, 0)
        todo.extend(children.get(pid, ()))
    return total


def main(argv):
    if len(argv) < 4 or argv[2] != "--":
        print("usage: peak-rss.py OUT -- COMMAND...", file=sys.stderr)
        return 2
    out, command = argv[1], argv[3:]
    child = subprocess.Popen(command, pass_fds=jobserver_fds())
    peak = 0
    done = threading.Event()

    def sample():
        nonlocal peak
        while not done.wait(2):
            peak = max(peak, tree_rss(child.pid))

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda s, _f: child.send_signal(s))
    status = child.wait()
    done.set()
    sampler.join()
    with open(out, "w") as stream:
        stream.write(f"{peak // (1024 * 1024)}\n")
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
