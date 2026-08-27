#!/usr/bin/env python3
"""Incrementally rebuild and restart the local Rust dashboard."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WATCH_PATHS = (
    REPOSITORY_ROOT / "Cargo.lock",
    REPOSITORY_ROOT / "Cargo.toml",
    REPOSITORY_ROOT / "crates" / "codewire-dashboard-web",
    REPOSITORY_ROOT / "packages" / "codewire-design",
)
IGNORED_PARTS = {".git", ".tmp", "node_modules", "target", "__pycache__"}
POLL_SECONDS = 0.35
DEBOUNCE_SECONDS = 0.25


def watched_files() -> list[Path]:
    files: list[Path] = []
    for watch_path in WATCH_PATHS:
        if watch_path.is_file():
            files.append(watch_path)
            continue
        if not watch_path.exists():
            continue
        files.extend(
            path
            for path in watch_path.rglob("*")
            if path.is_file() and not IGNORED_PARTS.intersection(path.parts)
        )
    return files


def snapshot() -> dict[Path, tuple[int, int]]:
    state: dict[Path, tuple[int, int]] = {}
    for path in watched_files():
        try:
            metadata = path.stat()
        except FileNotFoundError:
            continue
        state[path] = (metadata.st_mtime_ns, metadata.st_size)
    return state


def changed_paths(
    previous: dict[Path, tuple[int, int]], current: dict[Path, tuple[int, int]]
) -> list[Path]:
    return sorted(
        path
        for path in previous.keys() | current.keys()
        if previous.get(path) != current.get(path)
    )


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait()


def dashboard_origin() -> str:
    return os.environ.get("CODEWIRE_PUBLIC_ORIGIN", "http://127.0.0.1:5173")


def start_dashboard() -> subprocess.Popen[bytes]:
    print(f"[dashboard-watch] building and starting {dashboard_origin()}", flush=True)
    return subprocess.Popen(
        ["cargo", "run", "--locked", "-p", "codewire-dashboard-web"],
        cwd=REPOSITORY_ROOT,
        env=os.environ.copy(),
        start_new_session=True,
    )


def stable_snapshot(initial: dict[Path, tuple[int, int]]) -> dict[Path, tuple[int, int]]:
    latest = initial
    while True:
        time.sleep(DEBOUNCE_SECONDS)
        current = snapshot()
        if current == latest:
            return current
        latest = current


def main() -> int:
    stopping = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    state = snapshot()
    process: subprocess.Popen[bytes] | None = start_dashboard()
    reported_exit: int | None = None

    try:
        while not stopping:
            time.sleep(POLL_SECONDS)
            current = snapshot()
            changes = changed_paths(state, current)
            if changes:
                state = stable_snapshot(current)
                preview = ", ".join(
                    str(path.relative_to(REPOSITORY_ROOT)) for path in changes[:4]
                )
                if len(changes) > 4:
                    preview += f", +{len(changes) - 4} more"
                print(f"[dashboard-watch] change detected: {preview}", flush=True)
                stop_process(process)
                process = start_dashboard()
                reported_exit = None
                continue

            if process is not None and process.poll() is not None:
                exit_code = process.returncode
                if reported_exit != exit_code:
                    print(
                        f"[dashboard-watch] dashboard exited with {exit_code}; waiting for a source change",
                        file=sys.stderr,
                        flush=True,
                    )
                    reported_exit = exit_code
                process = None
    finally:
        stop_process(process)

    print("[dashboard-watch] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
