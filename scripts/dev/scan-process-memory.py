#!/usr/bin/env python3
"""Report whether live processes hold any of the given bytes in memory (#1911).

Usage: sudo -n scan-process-memory.py PID...  < values, one per line

Linux only: it reads /proc/PID/maps and /proc/PID/mem, so a process that is not
dumpable needs root. Values arrive on standard input, never as arguments, and
no output ever contains one: each line names a process and how many of the
values were found. Exit status: 0 none found, 1 at least one found, 2 the scan
could not read a process, which proves nothing.
"""

import os
import re
import sys

CHUNK = 1024 * 1024
# The vDSO's data pages fault on read and hold no process data.
UNREADABLE = ("[vvar]", "[vvar_vclock]", "[vsyscall]")
MAPPING = re.compile(rb"^([0-9a-f]+)-([0-9a-f]+) (r)[-w][-x][ps] \S+ \S+ \S+\s*(.*)$")


def regions(pid):
    with open(f"/proc/{pid}/maps", "rb") as maps:
        for line in maps:
            mapping = MAPPING.match(line.rstrip(b"\n"))
            if mapping and mapping.group(4).decode(errors="replace") not in UNREADABLE:
                yield int(mapping.group(1), 16), int(mapping.group(2), 16)


def scan(pid, values):
    """The values found in this process, and how many bytes were read."""
    found, total = set(), 0
    longest = max(map(len, values))
    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    try:
        for start, end in regions(pid):
            carry, offset = b"", start
            while offset < end:
                try:
                    chunk = os.pread(descriptor, min(CHUNK, end - offset), offset)
                except OSError:
                    # A page can vanish or refuse access while the process runs.
                    break
                if not chunk:
                    break
                total += len(chunk)
                window = carry + chunk
                found.update(index for index, value in enumerate(values) if value in window)
                carry = window[-(longest - 1):] if longest > 1 else b""
                offset += len(chunk)
    finally:
        os.close(descriptor)
    return found, total


def main():
    pids = sys.argv[1:]
    values = [line for line in sys.stdin.buffer.read().splitlines() if line]
    if not pids or not all(pid.isdigit() for pid in pids) or not values:
        print("usage: scan-process-memory.py PID...  < values, one per line", file=sys.stderr)
        return 2
    status = 0
    for pid in pids:
        try:
            found, total = scan(pid, values)
        except OSError as error:
            print(f"pid {pid}: not readable: {error.strerror}", file=sys.stderr)
            return 2
        if total == 0:
            print(f"pid {pid}: no memory could be read", file=sys.stderr)
            return 2
        print(f"pid {pid}: read {total} bytes, found {len(found)} of {len(values)} values")
        status = status or (1 if found else 0)
    return status


if __name__ == "__main__":
    sys.exit(main())
