#!/usr/bin/env python3
"""Structural proof of the product CI workflow (.gitea/workflows/ci.yaml).

It parses the workflow and checks the properties that decide what runs, where
and with what, never the text of a step:

- the job graph: every `needs.JOB` a job reads is in its `needs`, every
  `needs.JOB.outputs.NAME` is an output JOB declares, every `steps.ID` a step
  reads is an earlier step of its job, and Required verification waits on
  every verification group and judges its result against its expectation;
- trusted dispatch: a verification group runs only on its own `<group>_expected`
  output, which only the dispatch step writes, from the trusted base's copy of
  the dispatcher; the selector, planner and receipt check also run from that
  copy, checked out from the base without credentials; the dispatch reads
  whether its main commit was superseded, and only a push hands the selector
  the job token;
- the tested-tree receipt: every step of a group either reuses an accepted
  receipt or runs only without one;
- superseded runs: a job that does work outside the dispatched groups (the
  Kind producers) does nothing for a superseded main commit;
- closed pull requests start no verification and no Required verification;
- runners: every job names a repository-variable runner expression; a job that
  runs on a metal, build or Kind runner runs on the trusted one for a push to
  main;
  a job on the untrusted light runner holds no OIDC; every metal job bounds its
  Cargo jobs by memory and the build runner sizes its own;
- credentials and control: no `secrets.`, no `permissions:`, no job that
  cancels its own run, every family step names its selection, every job on a
  metal, build or Kind runner has a timeout within the 90-minute cleanup margin, and
  no matrix comes from another job's output (an empty matrix skips its job).

Each property rejects a mutation of the real workflow (MUTATIONS below).
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_runner_fixtures as runners  # noqa: E402

CI = ROOT / ".gitea/workflows/ci.yaml"
SELECTION = "verification-selection"
REQUIRED = "required-verification"
TRUSTED_POLICY = ".trusted-ci-policy/"
# The trusted base's copies these steps run (select, receipt, dispatch).
TRUSTED_STEPS = {"select": ("scripts/ci/select/select-verification.sh", "scripts/ci/plan/planner.py",
                            "scripts/ci/plan/apply-verification-plan.py", "scripts/ci/plan/plan-main-push.py"),
                 "receipt": ("scripts/ci/receipts/verify-tested-tree-receipt.sh",),
                 "dispatch": ("scripts/ci/select/emit-verification-matrices.sh",)}
# A metal guest bounds its Cargo jobs by its memory; a build runner sizes its own.
METAL = {runners.MEDIUM, runners.HEAVY}
BUILD = {runners.BUILD}
# Kind runs on the cloud Heavy label until it runs in a metal guest.
CLOUD = {runners.KIND}
LIGHT = {runners.UNTRUSTED_LIGHT, runners.TRUSTED_LIGHT}
KNOWN_RUNNERS = METAL | BUILD | CLOUD | LIGHT
BOUND_CARGO = "scripts/ci/setup/bound-cargo-jobs.sh"
MAX_TIMEOUT = 90
EXPECTED = re.compile(r"needs\.verification-selection\.outputs\.([a-z_]+_expected) == 'true'")
NEEDS_REF = re.compile(r"needs\.([A-Za-z0-9_-]+)\.")
NEEDS_OUTPUT = re.compile(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)")
STEPS_REF = re.compile(r"steps\.([A-Za-z0-9_-]+)\.")
FAMILY_RUNNER = re.compile(r"scripts/ci/verify/run-product-verification\.sh")


def load(text):
    workflow = yaml.safe_load(text)
    # PyYAML reads the bare key `on` as True.
    workflow["on"] = workflow.get("on") or workflow.pop(True)
    return workflow


def dump(value):
    return yaml.safe_dump(value, sort_keys=True, width=1 << 20)


def needs_of(job):
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def groups(jobs):
    """Verification groups: the jobs a dispatch expectation starts."""
    return {name: EXPECTED.search(str(job.get("if", ""))).group(1)
            for name, job in jobs.items() if EXPECTED.search(str(job.get("if", "")))}


def graph_errors(jobs):
    errors = []
    for name, job in jobs.items():
        needs = needs_of(job)
        for missing in sorted({ref for ref in NEEDS_REF.findall(dump(job)) if ref not in needs}):
            errors.append(f"{name} reads needs.{missing} without needing it")
        for producer, output in NEEDS_OUTPUT.findall(dump(job)):
            if producer in jobs and output not in (jobs[producer].get("outputs") or {}):
                errors.append(f"{name} reads needs.{producer}.outputs.{output}, which {producer} does not declare")
        seen = set()
        for index, step in enumerate(job.get("steps") or []):
            for ref in sorted(set(STEPS_REF.findall(dump({k: v for k, v in step.items() if k != "id"})))):
                if ref not in seen:
                    errors.append(f"{name} step {index} reads steps.{ref} before (or without) that step")
            if step.get("id"):
                seen.add(step["id"])
        for output, value in (job.get("outputs") or {}).items():
            for ref in STEPS_REF.findall(str(value)):
                if ref not in seen:
                    errors.append(f"{name} output {output} reads a step it does not have: {ref}")
        if name != SELECTION and SELECTION not in needs:
            errors.append(f"{name} does not need {SELECTION}, so it could run for a closed pull request")
    required = set(needs_of(jobs.get(REQUIRED, {})))
    required_text = dump(jobs.get(REQUIRED, {}))
    for name, expectation in sorted(groups(jobs).items()):
        if name not in required:
            errors.append(f"{REQUIRED} does not wait on the verification group {name}")
        # The aggregate judges each group by its result against its expectation.
        if f"needs.{name}.result" not in required_text:
            errors.append(f"{REQUIRED} does not judge the result of {name}")
        if f"needs.verification-selection.outputs.{expectation}" not in required_text:
            errors.append(f"{REQUIRED} does not read whether {name} was expected ({expectation})")
    return errors


def dispatch_errors(jobs):
    errors = []
    selection = jobs.get(SELECTION, {})
    outputs = selection.get("outputs") or {}
    steps = {step.get("id"): step for step in selection.get("steps") or [] if step.get("id")}
    for name, expectation in groups(jobs).items():
        value = str(outputs.get(expectation, ""))
        sources = set(STEPS_REF.findall(value))
        if sources != {"dispatch"}:
            errors.append(f"{name} starts on {expectation}, which steps other than dispatch decide: {value!r}")
    # A superseded main commit dispatches nothing: the dispatcher reads it.
    if "steps.superseded.outputs.superseded" not in dump(steps.get("dispatch", {}).get("env") or {}):
        errors.append("the dispatch step does not read whether its main commit was superseded")
    # Only a push hands the selector the job token; a pull request's code gets none.
    token = str((steps.get("select", {}).get("env") or {}).get("GITEA_TOKEN", ""))
    if token and token != "${{ github.event_name == 'push' && github.token || '' }}":
        errors.append(f"the selector receives the job token outside a push: {token!r}")
    for step_id, scripts in TRUSTED_STEPS.items():
        for script in scripts:
            if TRUSTED_POLICY + script not in str(steps.get(step_id, {}).get("run", "")):
                errors.append(f"selection step {step_id} does not run the trusted base's {script}")
    for step in selection.get("steps") or []:
        options = step.get("with") or {}
        if options.get("path") == TRUSTED_POLICY.rstrip("/"):
            if options.get("persist-credentials") is not False:
                errors.append("the trusted policy checkout keeps its credentials")
            if options.get("ref") not in ("${{ github.event.pull_request.base.sha }}", "${{ github.event.before }}"):
                errors.append(f"the trusted policy checkout is not the base: {options.get('ref')!r}")
    return errors


def receipt_errors(jobs):
    errors = []
    for name in groups(jobs):
        steps = jobs[name].get("steps") or []
        if not any("tested_tree_receipt == 'accepted'" in str(step.get("if", "")) for step in steps):
            errors.append(f"{name} has no step that reuses an accepted tested-tree receipt")
        for index, step in enumerate(steps):
            if "outputs.tested_tree_receipt" not in str(step.get("if", "")):
                errors.append(f"{name} step {index} ({step.get('name') or step.get('uses')}) omits the tested-tree guard")
    return errors


def superseded_errors(jobs):
    errors = []
    for name, job in jobs.items():
        if name in groups(jobs) or job.get("runs-on") in LIGHT:
            continue
        if "needs.verification-selection.outputs.superseded != 'true'" not in str(job.get("if", "")):
            errors.append(f"{name} works outside the dispatched groups but runs for a superseded main commit")
    return errors


def closed_errors(workflow):
    errors = []
    jobs = workflow["jobs"]
    if "closed" not in (workflow["on"].get("pull_request") or {}).get("types", []):
        errors.append("a closed pull request does not cancel its run")
    if not str(workflow.get("concurrency", {}).get("cancel-in-progress", "")).startswith(
            "${{ github.event_name == 'pull_request'"):
        errors.append("pull request runs no longer cancel their predecessor")
    if jobs.get(SELECTION, {}).get("if") != "${{ github.event.action != 'closed' }}":
        errors.append("a closed pull request must start no verification")
    if jobs.get(REQUIRED, {}).get("if") != "${{ always() && github.event.action != 'closed' }}":
        errors.append("Required verification must not run for a closed pull request")
    for name, job in jobs.items():
        condition = str(job.get("if", ""))
        if (name not in (SELECTION, REQUIRED) and "always()" in condition
                and "needs.verification-selection.result == 'success'" not in condition):
            errors.append(f"{name} runs always() without a successful selection")
    return errors


def runner_errors(jobs):
    errors = []
    for name, job in jobs.items():
        runner = job.get("runs-on")
        if runner not in KNOWN_RUNNERS:
            errors.append(f"{name} runs on {runner!r}, not a repository-variable runner expression")
            continue
        if runner in METAL | BUILD | CLOUD and not runner.startswith("${{ " + runners.MAIN_PUSH + " && (vars.CODEWIRE_CI_RUNNER_TRUSTED_"):
            errors.append(f"{name} does not run a push to main on its trusted runner")
        if runner in LIGHT and job.get("enable-openid-connect"):
            errors.append(f"{name} holds OIDC on the light runner")
        bounded = any(BOUND_CARGO in str(step.get("run", "")) for step in job.get("steps") or [])
        if runner in METAL and not bounded:
            errors.append(f"{name} runs on a metal guest without bounding its Cargo jobs")
        if runner in BUILD and bounded:
            errors.append(f"{name} runs on a build runner, which sizes its own Cargo jobs, yet bounds them")
        if runner in METAL | BUILD | CLOUD:
            timeout = job.get("timeout-minutes")
            if not isinstance(timeout, int) or not 0 < timeout <= MAX_TIMEOUT:
                errors.append(f"{name} timeout {timeout!r} is not within the {MAX_TIMEOUT}-minute cleanup margin")
        matrix = str((job.get("strategy") or {}).get("matrix", ""))
        if "needs." in matrix:
            errors.append(f"{name} takes its matrix from another job, which an empty output skips")
    return errors


def control_errors(text, jobs):
    errors = []
    if "secrets." in text:
        errors.append("product CI reads a repository secret")
    if re.search(r"^\s*permissions:", text, re.M):
        errors.append("product CI declares GitHub-only permissions that Forgejo ignores")
    if re.search(r"/actions/runs/[^ ]*/cancel", text):
        errors.append("a job cancels its own run")
    for name, job in jobs.items():
        for index, step in enumerate(job.get("steps") or []):
            if FAMILY_RUNNER.search(str(step.get("run", ""))) and "VERIFICATION_SELECTION" not in (step.get("env") or {}):
                errors.append(f"{name} step {index} runs a family without naming its selection")
    return errors


def check(text):
    workflow = load(text)
    jobs = workflow["jobs"]
    return (graph_errors(jobs) + dispatch_errors(jobs) + receipt_errors(jobs) + superseded_errors(jobs)
            + closed_errors(workflow) + runner_errors(jobs) + control_errors(text, jobs))


def in_job(text, job, old, new):
    """TEXT with OLD replaced by NEW once, inside JOB only."""
    start = text.index(f"\n  {job}:\n")
    end = re.compile(r"\n  [a-z0-9-]+:\n").search(text, start + 1)
    end = end.start() if end else len(text)
    block = text[start:end]
    if old not in block:
        return text
    return text[:start] + block.replace(old, new, 1) + text[end:]


def move_step(text, job, name, before):
    """Move step NAME of JOB to just before step BEFORE."""
    start = text.index(f"\n  {job}:\n")
    job_end = re.compile(r"\n  [a-z0-9-]+:\n").search(text, start + 1)
    job_end = job_end.start() + 1 if job_end else len(text)
    step = text.index(f"      - name: {name}\n", start)
    end = text.find("\n      - ", step + 1, job_end)
    end = end + 1 if end >= 0 else job_end
    body, text = text[step:end], text[:step] + text[end:]
    target = text.index(f"      - name: {before}\n", start)
    return text[:target] + body + text[target:]


TRUSTED_RUNNER = runners.MEDIUM
UNTRUSTED_MEDIUM = "${{ vars.CODEWIRE_CI_RUNNER_UNTRUSTED_MEDIUM || 'unset-CODEWIRE_CI_RUNNER_UNTRUSTED_MEDIUM' }}"
# Each mutation is a failure an earlier text pin caught, or one it missed.
MUTATIONS = {
    # The archive consumers read the compile job's outputs and result.
    "database drops rust-compile from needs": lambda t: in_job(
        t, "database", "needs: [verification-selection, rust-compile]", "needs: [verification-selection]"),
    "an output a job reads is not declared": lambda t: t.replace(
        "      database_expected: ${{ steps.dispatch.outputs.database_expected }}\n", "", 1),
    "the dispatch runs before the superseded check": lambda t: move_step(
        t, SELECTION, "Emit trusted capability dispatch decisions", "Skip a superseded main commit"),
    "an archive step reads a fetch that follows it": lambda t: move_step(
        t, "database", "Fetch and verify the database archives", "Make the fixture images present"),
    "Required verification stops waiting on a group": lambda t: in_job(
        t, REQUIRED, "      - database\n", ""),
    "Required verification ignores a group's result": lambda t: in_job(
        t, REQUIRED, "          VERIFICATION_DATABASE_RESULT: ${{ needs.database.result }}\n", ""),
    "Required verification ignores a group's expectation": lambda t: in_job(
        t, REQUIRED,
        "          VERIFICATION_DATABASE_EXPECTED: ${{ needs.verification-selection.outputs.database_expected }}\n", ""),
    "a group runs on candidate code's decision": lambda t: t.replace(
        "database_expected: ${{ steps.dispatch.outputs.database_expected }}",
        "database_expected: ${{ steps.select.outputs.database_expected }}", 1),
    "the dispatch ignores a superseded commit": lambda t: in_job(
        t, SELECTION, "          VERIFICATION_SUPERSEDED: ${{ steps.superseded.outputs.superseded }}\n", ""),
    "a pull request's selector gets the job token": lambda t: in_job(
        t, SELECTION, "GITEA_TOKEN: ${{ github.event_name == 'push' && github.token || '' }}",
        "GITEA_TOKEN: ${{ github.token }}"),
    "the dispatcher runs from the candidate": lambda t: t.replace(
        "'.trusted-ci-policy/scripts/ci/select/emit-verification-matrices.sh'",
        "'scripts/ci/select/emit-verification-matrices.sh'", 1),
    "the planner runs from the candidate": lambda t: t.replace(
        "'.trusted-ci-policy/scripts/ci/plan/planner.py'", "'scripts/ci/plan/planner.py'", 1),
    "the trusted checkout keeps credentials": lambda t: t.replace(
        "          persist-credentials: false\n", "", 1),
    "a group step loses its tested-tree guard": lambda t: in_job(
        t, "database", "        if: ${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' }}\n"
        "        run: scripts/ci/setup/bound-cargo-jobs.sh", "        run: scripts/ci/setup/bound-cargo-jobs.sh"),
    "a group loses its receipt reuse step": lambda t: in_job(
        t, "policy", "tested_tree_receipt == 'accepted'", "tested_tree_receipt != 'reused'"),
    "a Kind producer builds for a superseded commit": lambda t: in_job(
        t, "kind-product", " && needs.verification-selection.outputs.superseded != 'true'", ""),
    "a closed pull request starts verification": lambda t: t.replace(
        "    if: ${{ github.event.action != 'closed' }}\n", "", 1),
    "a job runs always() without a selection": lambda t: in_job(
        t, "database", "always() && needs.verification-selection.result == 'success' && ", "always() && "),
    "a closed pull request keeps its run": lambda t: re.sub(r"types: \[([^\]]*), closed\]", r"types: [\1]", t, count=1),
    "a job names a literal label": lambda t: in_job(t, "policy", f"runs-on: {TRUSTED_RUNNER}", "runs-on: ubuntu-latest"),
    "a main push runs on the untrusted metal": lambda t: in_job(
        t, "policy", f"runs-on: {TRUSTED_RUNNER}", f"runs-on: {UNTRUSTED_MEDIUM}"),
    "the light runner gets OIDC": lambda t: in_job(
        t, REQUIRED, f"    runs-on: {runners.UNTRUSTED_LIGHT}\n",
        f"    runs-on: {runners.UNTRUSTED_LIGHT}\n    enable-openid-connect: true\n"),
    "a metal job stops bounding Cargo": lambda t: in_job(
        t, "database", "run: scripts/ci/setup/bound-cargo-jobs.sh", "run: true"),
    "a build runner job bounds Cargo": lambda t: in_job(
        t, "rust-compile", "      - name: Verify sealed Rust toolchain\n",
        "      - name: Bound\n        if: ${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' }}\n"
        f"        run: {BOUND_CARGO}\n      - name: Verify sealed Rust toolchain\n"),
    "a heavy job loses its timeout": lambda t: in_job(t, "edge-kind", "    timeout-minutes: 45\n", ""),
    "a heavy job outlasts the cleanup margin": lambda t: in_job(
        t, "edge-kind", "    timeout-minutes: 45\n", "    timeout-minutes: 120\n"),
    "a matrix comes from a job output": lambda t: in_job(
        t, "edge-kind", "      matrix:\n",
        "      matrix: ${{ fromJSON(needs.verification-selection.outputs.selection) }}\n      unused:\n"),
    "product CI reads a secret": lambda t: in_job(
        t, "policy", "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    env:\n      TOKEN: ${{ secrets.TOKEN }}\n"),
    "product CI declares permissions": lambda t: t.replace("\njobs:\n", "\npermissions:\n  contents: read\njobs:\n", 1),
    "a job cancels its own run": lambda t: in_job(
        t, "policy", "        run: scripts/ci/verify/run-product-verification.sh policy-core",
        "        run: curl -X POST \"$GITHUB_API_URL/repos/x/actions/runs/1/cancel\"; scripts/ci/verify/run-product-verification.sh policy-core"),
    "the policy core loses its selection": lambda t: in_job(
        t, "policy", "          VERIFICATION_SELECTION: ${{ needs.verification-selection.outputs.selection }}\n", ""),
}


def main():
    text = CI.read_text()
    errors = check(text)
    if errors:
        print("test-ci-workflow-structure: FAIL\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    for name, mutate in MUTATIONS.items():
        mutated = mutate(text)
        if mutated == text:
            print(f"test-ci-workflow-structure: FAIL mutation {name!r} changed nothing", file=sys.stderr)
            return 1
        if not check(mutated):
            print(f"test-ci-workflow-structure: FAIL mutation {name!r} was not rejected", file=sys.stderr)
            return 1
    print(f"test-ci-workflow-structure: PASS jobs={len(load(text)['jobs'])} mutations_rejected={len(MUTATIONS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
