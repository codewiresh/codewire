#!/usr/bin/env python3
"""Fixture tests for scripts/ci/local/ci-job-plan.py, run-family.sh's planner.

The fixtures are shaped like the real sources (ci.yaml's Policy job,
`fj actions variables list` output, infra's warm-vms.yaml and a warm VM's manifest, ephemeral-ci.yaml
and dispatcher.py) with their own values, so each case asserts where a value
came from, not a copy of today's numbers. Cases:
- expressions: operators, functions, contexts and `if` with status functions;
- variables: `fj` output, values spanning lines;
- runners: main reaches the warm VM (share 16, no memory limit), pr reaches
  the dispatcher's medium ConfigMap (share 8, 7168Mi), the image resolves to
  its registry digest, host binds become empty volumes;
- the job: workflow, job and step env, the selection job's outputs, step
  flags, the checkout step, an unsupported action;
- infra layout changes fail loudly: a missing dispatcher name, a reshaped
  guest shape, a share that disagrees, an unknown label.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PLANNER = ROOT / "scripts/ci/local/ci-job-plan.py"
DIGEST = "ab" * 32

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


spec = importlib.util.spec_from_file_location("ci_job_plan", PLANNER)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)

WORKFLOW = textwrap.dedent("""\
    name: CI
    on: {push: {branches: [main]}}
    env:
      CODEWIRE_SOURCE_URL: ${{ vars.CODEWIRE_SOURCE_URL }}
      FIXED_VERSION: v1.2.3
      MISSING_VARIABLE: ${{ vars.NOT_SET }}
    jobs:
      verification-selection:
        runs-on: light
        steps:
          - run: true
      policy:
        name: Policy verification
        runs-on: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && (vars.RUNNER_TRUSTED_MEDIUM || 'unset-RUNNER_TRUSTED_MEDIUM') || (vars.RUNNER_UNTRUSTED_MEDIUM || 'unset-RUNNER_UNTRUSTED_MEDIUM') }}
        timeout-minutes: 30
        needs: [verification-selection]
        if: ${{ needs.verification-selection.outputs.policy_expected == 'true' }}
        env:
          TARGET: ${{ github.workspace }}/target
        steps:
          - name: Reuse a receipt
            if: ${{ needs.verification-selection.outputs.tested_tree_receipt == 'accepted' }}
            run: echo reused
          - uses: noel/actions-checkout@0123
            if: ${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' }}
            with:
              ref: ${{ needs.verification-selection.outputs.source_sha }}
              fetch-depth: 0
          - name: Bound
            run: scripts/ci/setup/bound-cargo-jobs.sh
          - name: Run Policy
            if: ${{ contains(needs.verification-selection.outputs.selection, '|policy|') }}
            env:
              VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}
              BASE: ${{ github.event.pull_request.base.sha }}
              SECRET: ${{ secrets.ANY }}
            run: scripts/ci/verify/run-product-verification.sh policy-core ${{ github.sha }}
          - name: Not selected
            if: ${{ contains(needs.verification-selection.outputs.selection, '|kind|') }}
            uses: noel/setup-bun@0456
          - name: Report
            if: ${{ always() && needs.verification-selection.outputs.tested_tree_receipt != 'accepted' }}
            run: echo report
          - name: On failure
            if: failure()
            run: echo failed
    """)

VARIABLES = textwrap.dedent("""\
    CODEWIRE_FORGEJO_INTERNAL_URL = https://forge.example.test
    CODEWIRE_SOURCE_URL = https://git.example.test/codewire/codewire.git
    MULTI = first
    second line
    RUNNER_TRUSTED_MEDIUM = vm-main-test
    RUNNER_UNTRUSTED_MEDIUM = untrusted-medium
    """)

VM_MAIN = textwrap.dedent(f"""\
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: vm-runner-config
    data:
      build.yaml: |
        runner:
          envs:
            CODEWIRE_CI_CPU_SHARE: "32"
        container:
          options: "-v /vm/build:/ci-cache"
        server:
          connections:
            forgejo:
              labels:
                - vm-main-build:docker://ci-job.invalid/act-node-docker:{DIGEST}
      test.yaml: |
        runner:
          envs:
            CODEWIRE_CI_CPU_SHARE: "16"
            CODEWIRE_CI_WARM_SEATS: /ci-warm
        container:
          options: "--add-host=host.docker.internal:host-gateway -v /ci-cache -v /vm/warm:/ci-warm -v /vm/handoff:/ci-handoff:ro"
        server:
          connections:
            forgejo:
              labels:
                - vm-main-test:docker://ci-job.invalid/act-node-docker:{DIGEST}
    ---
    apiVersion: apps/v1
    kind: StatefulSet
    metadata:
      name: vm
    spec:
      template:
        spec:
          initContainers:
            - name: preload
              image: registry.example.test/approved/act-node-docker@sha256:{DIGEST}
    """)


def ephemeral(medium_share: str = "8") -> str:
    return textwrap.dedent(f"""\
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: plain-runner-config
        data:
          config.yaml: |
            container:
              options: "--add-host=host.docker.internal:host-gateway"
        ---
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: medium-runner-config
        data:
          config.yaml: |
            runner:
              envs:
                CODEWIRE_CI_CPU_SHARE: "{medium_share}"
            container:
              options: "--add-host=host.docker.internal:host-gateway -v /ci-cache:/ci-cache"
        """)


def dispatcher(drop: str = "", shapes: str = "") -> str:
    source = textwrap.dedent(f"""\
        JOB_IMAGE = "registry.example.test/approved/act-node-docker@sha256:{DIGEST}"
        METAL_JOB_IMAGE_TAG = "ci-job.invalid/act-node-docker:{DIGEST}"
        METAL_CPU_SHARE_ENV = "CODEWIRE_CI_CPU_SHARE"
        METAL_CPU_SHARE = {{"medium-runner-config": 8}}
        METAL_GUEST_SHAPES = {shapes or '{"medium": {"memory_mib": 7 * 1024}}'}
        METAL_SLOTS = (
            {{"slot": 1, "class": "medium", "profile": "shared"}},
            {{"slot": 2, "class": "medium", "profile": "shared"}},
            {{"slot": 3, "class": "build", "profile": "build"}},
        )

        def metal_declared_labels(entry):
            return ("build-label",) if entry["profile"] == "build" else ("untrusted-medium",)

        def metal_runner_config(entry):
            return "plain-runner-config" if entry["profile"] == "build" else "medium-runner-config"

        def metal_job_data_mib(entry):
            return 0

        def metal_worker_resources(size, job_data_mib=0):
            memory = METAL_GUEST_SHAPES[size]["memory_mib"] + job_data_mib
            return {{"dind": {{"limits": {{"memory": f"{{memory}}Mi"}}}}}}
        """)
    if drop:
        source = source.replace(f"def {drop}(", f"def {drop}_renamed(")
    return source


def write_fixture(root: Path, *, dispatcher_source: str | None = None, medium_share: str = "8") -> Path:
    (root / "infra/forgejo-runners").mkdir(parents=True, exist_ok=True)
    (root / "ci.yaml").write_text(WORKFLOW)
    (root / "variables").write_text(VARIABLES)
    (root / "infra/forgejo-runners/warm-vms.yaml").write_text(
        "vms:\n  fixture-main-vm-0:\n    file: fixture-main-vm.yaml\n")
    (root / "infra/forgejo-runners/fixture-main-vm.yaml").write_text(VM_MAIN)
    (root / "infra/forgejo-runners/ephemeral-ci.yaml").write_text(ephemeral(medium_share))
    (root / "infra/forgejo-runners/dispatcher.py").write_text(dispatcher_source or dispatcher())
    (root / "dispatch").write_text("policy_expected=true\nstandard_expected=false\n")
    return root


def run_planner(root: Path, command: str, placement: str, *extra: str) -> subprocess.CompletedProcess:
    args = [sys.executable, "-I", "-B", str(PLANNER), command, "--workflow", str(root / "ci.yaml"),
            "--job", "policy", "--placement", placement, "--variables", str(root / "variables"),
            "--infra", str(root / "infra"), "--commit", "c" * 40, "--base", "b" * 40,
            "--branch", "topic", *extra]
    return subprocess.run(args, capture_output=True, text=True, check=False)


def exports(path: Path) -> dict[str, str]:
    """Each `export NAME=VALUE` line, as bash would read it."""
    out = subprocess.run(["bash", "-c", f'set -a; source "{path}"; env -0'], capture_output=True,
                         check=True, env={"PATH": "/usr/bin:/bin"})
    return dict(item.split("=", 1) for item in out.stdout.decode().split("\0") if "=" in item)


# --- Expressions ------------------------------------------------------------
context = {
    "github": {"event_name": "push", "ref": "refs/heads/main", "workspace": "/w", "event": {"before": ""}},
    "vars": {"A": "a", "EMPTY": ""},
    "needs": {"sel": {"outputs": {"selection": "|valid:v3|policy|rust|", "receipt": "fallback"}}},
    "secrets": {}, "env": {},
}
cases = [
    ("github.event_name == 'push' && github.ref == 'refs/heads/main'", True),
    ("github.event_name == 'PUSH'", True),  # strings compare case-insensitively
    ("github.event_name != 'push'", False),
    ("vars.EMPTY || 'fallback'", "fallback"),
    ("vars.A || 'fallback'", "a"),
    ("vars.A && 'second'", "second"),
    ("vars.EMPTY && 'second'", ""),
    ("!vars.EMPTY", True),
    ("contains(needs.sel.outputs.selection, '|policy|')", True),
    ("contains(needs.sel.outputs.selection, '|kind|')", False),
    ("startsWith(github.ref, 'refs/heads/')", True),
    ("endsWith(github.ref, '/main')", True),
    ("format('{0}-{1}', vars.A, 'b')", "a-b"),
    ("vars.MISSING", None),
    ("github.event.before == ''", True),
    ("(vars.EMPTY || vars.A) == 'a'", True),
    ("'it''s'", "it's"),
    ("1 < 2", True),
    ("secrets.ANY", None),
]
for text, expected in cases:
    got = plan.Expr(text, context).evaluate()
    check(got == expected, f"expression {text!r}: expected {expected!r}, got {got!r}")
check(plan.interpolate("x-${{ vars.A }}-${{ vars.MISSING }}-${{ true }}", context) == "x-a--true",
      "interpolation renders values, empty for null, true/false for booleans")
# A step's `if`: no status function means success() && (it).
for text, success, failure in [
    (None, True, False),
    ("vars.A == 'a'", True, False),
    ("${{ vars.A == 'b' }}", False, False),
    ("always()", True, True),
    ("${{ always() && vars.A == 'a' }}", True, True),
    ("failure()", False, True),
    ("success() || failure()", True, True),
]:
    check(plan.condition(text, context, "success") == success, f"if {text!r} while green")
    check(plan.condition(text, context, "failure") == failure, f"if {text!r} after a failure")

# --- Variables --------------------------------------------------------------
with tempfile.TemporaryDirectory(prefix="ci-job-plan.") as tmp:
    root = write_fixture(Path(tmp))
    variables = plan.read_variables(root / "variables")
    check(variables["MULTI"] == "first\nsecond line", "a variable's value may span lines")
    check(variables["RUNNER_TRUSTED_MEDIUM"] == "vm-main-test", "the line after a multi-line value starts a new variable")

    # --- Runners --------------------------------------------------------------
    main = run_planner(root, "runner", "main")
    check(main.returncode == 0, f"main runner planning failed: {main.stderr}")
    if main.returncode == 0:
        runner = json.loads(main.stdout)
        check(runner["label"] == "vm-main-test", "main's runs-on resolves through the trusted variable")
        check(runner["envs"] == {"CODEWIRE_CI_CPU_SHARE": "16", "CODEWIRE_CI_WARM_SEATS": "/ci-warm"},
              f"main takes the VM test runner's envs, got {runner['envs']}")
        check(runner["memory"] == "", "main's VM job has no per-job memory limit")
        check(runner["image"] == f"registry.example.test/approved/act-node-docker@sha256:{DIGEST}",
              f"the local image tag maps to its registry digest, got {runner['image']}")
        check(runner["docker_options"] == ["--add-host=host.docker.internal:host-gateway", "-v", "/ci-cache",
                                            "-v", "/ci-warm", "-v", "/ci-handoff"],
              f"host binds become empty volumes, got {runner['docker_options']}")
        check(runner["timeout_minutes"] == 30, "the job's timeout comes from ci.yaml")
        check(runner["origin_url"] == "https://forge.example.test/codewire/codewire",
              "the checkout's origin is the forge URL and the repository")
    pr = run_planner(root, "runner", "pr")
    check(pr.returncode == 0, f"pr runner planning failed: {pr.stderr}")
    if pr.returncode == 0:
        runner = json.loads(pr.stdout)
        check(runner["label"] == "untrusted-medium", "a pull request resolves through the untrusted variable")
        check(runner["envs"] == {"CODEWIRE_CI_CPU_SHARE": "8"}, f"pr takes the medium ConfigMap's envs, got {runner['envs']}")
        check(runner["memory"] == "7168Mi", f"pr takes the medium guest's job memory, got {runner['memory']}")
        check("medium-runner-config" in runner["source"], "the source names the ConfigMap")
        check(runner["image"].endswith(f"@sha256:{DIGEST}"), "the guest's image tag maps to its digest")

    # --- The job ----------------------------------------------------------------
    out = root / "plan-pr"
    selection = "|valid:v3|policy|complete|"
    job = run_planner(root, "job", "pr", "--selection", selection, "--dispatch", str(root / "dispatch"), "--out", str(out))
    check(job.returncode == 0, f"job planning failed: {job.stderr}")
    if job.returncode == 0:
        env = exports(out / "job.env")
        check(env.get("CODEWIRE_SOURCE_URL") == "https://git.example.test/codewire/codewire.git",
              "workflow env reads Actions variables")
        check(env.get("FIXED_VERSION") == "v1.2.3", "workflow env keeps literals")
        check(env.get("MISSING_VARIABLE") == "", "an unset variable is empty, as in CI")
        check(env.get("TARGET") == "/workspace/codewire/codewire/target", "job env reads the github context")
        check(env.get("CODEWIRE_CI_CPU_SHARE") == "8", "the runner's envs are in the job environment")
        check(env.get("RUNNER_TEMP") == "/tmp", "act's RUNNER_TEMP")
        for key, value in {"EVENT_NAME": "pull_request", "REF": "refs/pull/0/head", "SHA": "c" * 40,
                           "BASE_REF": "main", "HEAD_REF": "topic", "JOB": "policy",
                           "WORKSPACE": "/workspace/codewire/codewire"}.items():
            check(env.get(f"GITHUB_{key}") == value and env.get(f"FORGEJO_{key}") == value,
                  f"GITHUB_{key} and FORGEJO_{key} are {value!r}, got {env.get(f'GITHUB_{key}')!r}")
        check("GITHUB_TOKEN" not in env, "a local run has no job token")
        event = json.loads((out / "event.json").read_text())
        check(event["pull_request"]["base"]["sha"] == "b" * 40, "the event carries the pull request base")
        check(json.loads((out / "job.json").read_text())["selected"] is True,
              "the job's if reads the dispatch decisions")
        rows = [line.split("\t") for line in (out / "steps.tsv").read_text().splitlines()]
        check(rows == [["00", "0", "0", "Reuse a receipt"], ["02", "1", "0", "Bound"],
                       ["03", "1", "0", "Run Policy"], ["05", "1", "1", "Report"],
                       ["06", "0", "1", "On failure"]],
              f"steps keep ci.yaml's order and flags; the checkout and an unselected action drop out, got {rows}")
        step = exports(out / "03.env")
        check(step.get("VERIFICATION_SELECTION") == selection, "step env reads the selection job's outputs")
        check(step.get("BASE") == "b" * 40, "step env reads the event")
        check(step.get("SECRET") == "", "every secret is empty")
        check((out / "03.sh").read_text().strip() == f"scripts/ci/verify/run-product-verification.sh policy-core {'c' * 40}",
              "the run script is interpolated")

    # The job's if is false without the dispatch decision.
    quiet = run_planner(root, "job", "main", "--selection", selection, "--out", str(root / "plan-main"))
    check(quiet.returncode == 0 and json.loads((root / "plan-main/job.json").read_text())["selected"] is False,
          "without policy_expected the job is not selected")

    # An action that would run, other than the checkout, stops planning.
    unsupported = run_planner(root, "job", "pr", "--selection", "|valid:v3|policy|kind|complete|",
                              "--out", str(root / "plan-kind"))
    check(unsupported.returncode == 2 and "noel/setup-bun@0456" in unsupported.stderr,
          f"an unsupported action fails planning, got {unsupported.returncode}: {unsupported.stderr}")

# --- Infra layout changes fail loudly ---------------------------------------
layout_cases = [
    ("a missing dispatcher function", dict(dispatcher_source=dispatcher(drop="metal_runner_config")),
     "pr", "no longer defines metal_runner_config"),
    ("a reshaped guest shape", dict(dispatcher_source=dispatcher(shapes='{"medium": {"mem": 7}}')),
     "pr", "layout changed (KeyError"),
    ("a dispatcher that no longer imports", dict(dispatcher_source="raise RuntimeError('moved')\n"),
     "pr", "importing it failed: RuntimeError: moved"),
    ("a share that disagrees with the dispatcher", dict(medium_share="12"),
     "pr", "but dispatcher.py METAL_CPU_SHARE says 8"),
]
for name, fixture, placement, expected in layout_cases:
    with tempfile.TemporaryDirectory(prefix="ci-job-plan.") as tmp:
        root = write_fixture(Path(tmp), **fixture)
        result = run_planner(root, "runner", placement)
        check(result.returncode == 2 and expected in result.stderr and "Traceback" not in result.stderr,
              f"{name}: expected exit 2 naming {expected!r}, got {result.returncode}: {result.stderr.strip()}")
with tempfile.TemporaryDirectory(prefix="ci-job-plan.") as tmp:
    root = write_fixture(Path(tmp))
    (root / "variables").write_text(VARIABLES.replace("untrusted-medium", "untrusted-huge"))
    result = run_planner(root, "runner", "pr")
    check(result.returncode == 2 and "no runner in infra declares the label untrusted-huge" in result.stderr,
          f"an unknown label fails, got {result.returncode}: {result.stderr.strip()}")
    (root / "variables").write_text(VARIABLES.replace("RUNNER_UNTRUSTED_MEDIUM = untrusted-medium\n", ""))
    result = run_planner(root, "runner", "pr")
    check(result.returncode == 2 and "unset-RUNNER_UNTRUSTED_MEDIUM" in result.stderr,
          f"an unset runner variable fails, got {result.returncode}: {result.stderr.strip()}")

if failures:
    for failure in failures:
        print(f"test-ci-job-plan: FAIL: {failure}", file=sys.stderr)
    sys.exit(1)
print(f"[test-ci-job-plan] {len(cases)} expressions, step ifs, variables, both placements' runners, "
      f"the job plan and {len(layout_cases) + 2} infra layout failures: OK")
