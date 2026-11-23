#!/usr/bin/env python3
"""At most one standard pod-runtime image build at a time (#5602).

Deploy Dev builds the pod-runtime image only on the run that holds the
delivery turn, and that build takes 40 to 60 minutes on the trusted light
runner, longer than a delivery. So before anything else the build job runs
this: when another Deploy Dev push run on main has its "Build and push the
pod-runtime image" job running, this run builds nothing. A later delivery
builds the newest commit, so Dev's standard-VM daemon trails main by up to one
build.

Only a running job counts. A waiting, finished, cancelled or skipped one does
not, and neither does a run from before the job existed. Two builds that start
at the same moment can both see none and both build; that is rare and only
costs one extra build.

It fails open: when the API cannot be read, or reading takes longer than
READ_SECONDS, this run builds, with a warning. A rare extra build is
acceptable; a build that never runs is not. It writes in_flight=true or
in_flight=false to GITHUB_OUTPUT.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent
BUILD_JOB = "Build and push the pod-runtime image"
# Every API call is bounded by the client (30 s, killed at 60); this bounds
# the whole read, so a slow API never holds a runner long.
READ_SECONDS = 120


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The delivery turn's reading of Deploy Dev's unfinished push runs on main,
# and the receipt check's API client and job states, each with page=1.
turn = load("codewire_ci_pod_runtime_in_flight_turn", HERE / "wait-for-dev-delivery-turn.py")
verdicts = turn.verdicts


def other_build_running(api, own_run_id: int, clock=None) -> int | None:
    """The run ID of another Deploy Dev run whose pod-runtime build is running, or None."""
    clock = clock or time.monotonic
    started = clock()
    for run in sorted(turn.unfinished_main_runs(api), key=lambda record: record["id"], reverse=True):
        if run["id"] == own_run_id:
            continue
        if clock() - started > READ_SECONDS:
            raise verdicts.Unproven("read-too-slow")
        if turn.job_state(verdicts.jobs_of(api, run["id"]), BUILD_JOB, run["id"]) == "running":
            return run["id"]
    return None


def main(argv: list[str] | None = None, api_factory=None) -> int:
    if argv:
        raise SystemExit("usage: pod-runtime-build-in-flight.py")
    # Reading the other runs needs only the job token, never OIDC request credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    run_id = environ.get("GITHUB_RUN_ID", "")
    in_flight = False
    if not run_id.isdigit():
        print("::warning::the workflow run is invalid; building the pod-runtime image")
    else:
        try:
            api = (api_factory or verdicts.ForgejoAPI.from_environ)(environ)
            other = other_build_running(api, int(run_id))
        except Exception as exc:  # noqa: BLE001 - fail open: an extra build is acceptable, a missed one is not
            print(f"::warning::could not read the other Deploy Dev runs ({exc}); building the pod-runtime image")
        else:
            if other is not None:
                in_flight = True
                print(f"Deploy Dev run {other} is building the pod-runtime image; this run builds none, "
                      "and a later delivery builds the newest commit")
            else:
                print("no other pod-runtime image build is running; building")
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"in_flight={str(in_flight).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
