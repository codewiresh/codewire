#!/usr/bin/env python3
"""Run COMMAND and record its wall time, CPU time, peak memory and peak cores.

Usage: sample-process-tree.py REPORT_JSON -- COMMAND...

Every 0.5 s it reads /proc for every process descended from COMMAND: the sum
of their resident memory (peak memory; shared pages count once per process,
so this overstates a tree that shares much) and the growth of their user and
system time (busy cores, over windows of at least 1 s). CPU time is the
children's total from getrusage, which also counts processes that exited
between samples. The command's exit status is the script's.
"""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time

TICK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")


def processes() -> dict[int, tuple[int, int, int]]:
    """pid -> (parent, cpu ticks, resident pages)."""
    table = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                fields = handle.read().rsplit(b")", 1)[1].split()
        except OSError:
            continue
        table[int(entry)] = (int(fields[1]), int(fields[11]) + int(fields[12]), int(fields[21]))
    return table


def descendants(root: int, table: dict[int, tuple[int, int, int]]) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, (parent, _, _) in table.items():
        children.setdefault(parent, []).append(pid)
    found, frontier = {root}, [root]
    while frontier:
        for child in children.get(frontier.pop(), []):
            if child not in found:
                found.add(child)
                frontier.append(child)
    return found


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: sample-process-tree.py REPORT_JSON -- COMMAND...", file=sys.stderr)
        return 2
    report, command = sys.argv[1], sys.argv[3:]
    start = time.monotonic()
    child = subprocess.Popen(command)
    peak_rss = 0
    peak_cores = 0.0
    window_cpu, window_start = 0, start
    while child.poll() is None:
        time.sleep(0.5)
        table = processes()
        tree = descendants(child.pid, table) & table.keys()
        peak_rss = max(peak_rss, sum(table[pid][2] for pid in tree) * PAGE)
        cpu = sum(table[pid][1] for pid in tree)
        now = time.monotonic()
        if now - window_start >= 1.0:
            peak_cores = max(peak_cores, max(0, cpu - window_cpu) / TICK / (now - window_start))
            window_cpu, window_start = cpu, now
    wall = time.monotonic() - start
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_seconds = usage.ru_utime + usage.ru_stime
    result = {
        "exit": child.returncode,
        "wall_seconds": round(wall, 1),
        "cpu_seconds": round(cpu_seconds, 1),
        "mean_cores": round(cpu_seconds / wall, 1) if wall else 0.0,
        "peak_cores": round(peak_cores, 1),
        "peak_rss_gib": round(peak_rss / 2**30, 2),
    }
    with open(report, "w", encoding="utf-8") as handle:
        json.dump(result, handle)
    return child.returncode


if __name__ == "__main__":
    sys.exit(main())
