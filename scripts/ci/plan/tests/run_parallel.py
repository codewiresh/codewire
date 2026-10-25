"""Run the planner's unit tests in parallel worker processes.

    python3 scripts/ci/plan/tests/run_parallel.py WORKERS

It discovers the test_*.py modules in this folder, as
`python3 -m unittest discover -s <this folder> -p 'test_*.py'` does, and
sorts the tests by id. WORKERS processes then share that list: each claims
the next unclaimed test from a locked counter, runs it, and claims again, so
a long test does not hold up the tests behind it. Each worker records the ids
it ran. The runner prints every worker's verbose output in worker order and
fails when a worker fails, or when the workers together did not run every
discovered test exactly once.
"""

from __future__ import annotations

import collections
import fcntl
import json
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
PATTERN = "test_*.py"


def discovered() -> list[unittest.TestCase]:
    """Every discovered test, sorted by id; an import failure is a test too."""

    def flatten(suite: unittest.TestSuite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test

    suite = unittest.defaultTestLoader.discover(
        str(TESTS), pattern=PATTERN, top_level_dir=str(TESTS)
    )
    return sorted(flatten(suite), key=lambda test: test.id())


def claim(counter: Path) -> int:
    """The next unclaimed index of the shared test list."""
    with counter.open("r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        index = int(handle.read())
        handle.seek(0)
        handle.write(str(index + 1))
        handle.truncate()
        return index


class ClaimedSuite(unittest.TestSuite):
    """Yields claimed tests until none is left.

    TestSuite.run still sets up and tears down each test's class and module
    as the claimed tests move between them.
    """

    def __init__(self, tests: list[unittest.TestCase], counter: Path):
        super().__init__()
        self._cleanup = False
        self._all = tests
        self._counter = counter

    def __iter__(self):
        while (index := claim(self._counter)) < len(self._all):
            yield self._all[index]


def run_worker(counter: Path, report: Path) -> int:
    ran: list[str] = []

    class RecordingResult(unittest.TextTestResult):
        def startTest(self, test: unittest.TestCase) -> None:
            ran.append(test.id())
            super().startTest(test)

    result = unittest.TextTestRunner(
        stream=sys.stderr, verbosity=2, resultclass=RecordingResult
    ).run(ClaimedSuite(discovered(), counter))
    report.write_text(json.dumps({"ran": ran, "ok": result.wasSuccessful()}))
    return 0 if result.wasSuccessful() else 1


def run_all(workers: int) -> int:
    expected = [test.id() for test in discovered()]
    workers = max(1, min(workers, len(expected)))
    started = time.monotonic()
    failed: list[str] = []
    ran: list[str] = []
    with tempfile.TemporaryDirectory(prefix="codewire-planner-tests-") as temporary:
        directory = Path(temporary)
        counter = directory / "next"
        counter.write_text("0")
        running: list[tuple[subprocess.Popen, Path, Path]] = []
        try:
            for index in range(workers):
                output = directory / f"worker-{index}.log"
                report = directory / f"worker-{index}.json"
                with output.open("wb") as log:
                    process = subprocess.Popen(
                        [sys.executable, str(Path(__file__).resolve()), "--worker", str(counter), str(report)],
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                running.append((process, output, report))
            statuses = [process.wait() for process, _, _ in running]
        finally:
            for process, _, _ in running:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        for index, ((_, output, report), status) in enumerate(zip(running, statuses)):
            print(f"=== planner unit tests: worker {index + 1} of {workers} (exit {status}) ===", flush=True)
            sys.stdout.buffer.write(output.read_bytes())
            sys.stdout.flush()
            try:
                worker = json.loads(report.read_text())
            except (OSError, ValueError) as error:
                failed.append(f"worker {index + 1} left no report: {error}")
                continue
            ran.extend(worker["ran"])
            if status or not worker["ok"]:
                failed.append(f"worker {index + 1} failed (exit {status})")

    counts = collections.Counter(ran)
    missing = sorted(set(expected) - set(counts))
    repeated = sorted(test for test, seen in counts.items() if seen > 1)
    unexpected = sorted(set(counts) - set(expected))
    if missing:
        failed.append(f"{len(missing)} discovered test(s) ran in no worker: {missing}")
    if repeated:
        failed.append(f"{len(repeated)} test(s) ran more than once: {repeated}")
    if unexpected:
        failed.append(f"{len(unexpected)} test(s) ran that discovery did not find: {unexpected}")
    print(
        f"planner unit tests: {workers} worker(s) ran {len(ran)} test(s), "
        f"{len(counts)} distinct, of {len(expected)} discovered, "
        f"in {time.monotonic() - started:.1f}s",
        flush=True,
    )
    for failure in failed:
        print(f"planner unit tests: {failure}", file=sys.stderr, flush=True)
    return 1 if failed else 0


def main(arguments: list[str]) -> int:
    if len(arguments) == 3 and arguments[0] == "--worker":
        return run_worker(Path(arguments[1]), Path(arguments[2]))
    if len(arguments) == 1 and arguments[0].isdigit() and int(arguments[0]) > 0:
        # A stop signal ends the workers too, through run_all's cleanup.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        return run_all(int(arguments[0]))
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
