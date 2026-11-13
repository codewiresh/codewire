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

Every workflow under .gitea/workflows is held to the properties that do not
depend on what it delivers:

- its job graph resolves as above;
- every `runs-on` is a repository-variable runner expression;
- no workflow reads `secrets.` or declares `permissions:`: credentials come
  from OpenBao through job-scoped OIDC, and Forgejo ignores permissions;
- every action is pinned to a commit, the same one wherever it is used, so
  each action's pin has one owner;
- every OpenBao role names its own audience (`openbao-<role>`);
- a job that can log in to OpenBao (OIDC, its own or the workflow's, with a
  role in scope, or a `fetch-openbao-` step) runs only on a
  trusted runner, in a workflow that only a push to main or a tag, a dispatch
  or a schedule starts: never a pull request; workflow-wide OIDC likewise;
- ci.yaml runs Kind on the workspace image kind/common.sh approves, so that
  digest has one owner.

Each property rejects a mutation of the real workflows (MUTATIONS and
WORKFLOW_MUTATIONS below).
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_runner_fixtures as runners  # noqa: E402

WORKFLOWS = ROOT / ".gitea/workflows"
CI = WORKFLOWS / "ci.yaml"
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


def graph_errors(jobs, ci=True):
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
        if ci and name != SELECTION and SELECTION not in needs:
            errors.append(f"{name} does not need {SELECTION}, so it could run for a closed pull request")
    if not ci:
        return errors
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


RUNNER_EXPRESSION = re.compile(
    r"\$\{\{ (?:" + re.escape(runners.MAIN_PUSH) + r" && \(vars\.(CODEWIRE_CI_RUNNER_TRUSTED_[A-Z_]+) "
    r"\|\| 'unset-\1'\) \|\| \(vars\.(CODEWIRE_CI_RUNNER_UNTRUSTED_[A-Z_]+) \|\| 'unset-\2'\)"
    r"|vars\.(CODEWIRE_CI_RUNNER_[A-Z_]+) \|\| 'unset-\3') \}\}")
# Runners only protected work reaches: the trusted pool and the protected Mac.
TRUSTED_ONLY = {runners.TRUSTED_LIGHT, runners.MACOS}
PINNED_ACTION = re.compile(r"[^@\s]+@[0-9a-f]{40}")
ROLE_KEY = re.compile(r"OPENBAO_([A-Z]*_?)ROLE")
SAFE_TRIGGERS = {"push", "workflow_dispatch", "schedule"}


def audience_for(role):
    """The audience a role's login must name: each role name prefixed openbao-."""
    if "${{" in role:
        return re.sub(r"'(codewire-[a-z0-9-]+)'", r"'openbao-\1'", role)
    return "openbao-" + role


def roles_in_scope(workflow, job):
    """OPENBAO_*ROLE values the job's environment carries (workflow, job, steps)."""
    envs = [workflow.get("env") or {}, job.get("env") or {}]
    envs += [step.get("env") or {} for step in job.get("steps") or []]
    return [env for env in envs if any(ROLE_KEY.fullmatch(key) for key in env)]


# The pre-merge policy drift check (#3821) is the one workflow a pull request
# starts that holds OIDC, on the untrusted light runner: the owner approved its
# read-only integration for that shape on 2026-11-11, and the orchestrator
# narrowed it to this dedicated workflow the same day (option B). Its token
# reaches only codewire-policy-drift-read, the one credential that admits
# pull_request_target (infra's contract check pins that). The exception holds
# only while the workflow keeps exactly this shape, so it cannot widen: one
# job, pull_request_target alone, no OpenBao in scope, base tooling checked
# out apart from the pull request's tree, and nothing of that tree run.
POLICY_DRIFT = "policy-drift.yml"
POLICY_DRIFT_PATHS = {"${{ steps.selection.outputs.base_sha }}": ".policy-drift-base",
                      "${{ steps.selection.outputs.head_sha }}": "candidate"}
# The runner image's sealed Kyverno CLI (#3821): the check verifies these
# exact bytes before it mints its token, and never passes without running.
POLICY_DRIFT_KYVERNO_CHECK = ("printf '%s  %s\\n' 31388ab9b889429cfb48923d00e46159a9cecd30cdc906edbef725a60a7e587e "
                              '"$kyverno" |')
POLICY_DRIFT_TOKEN = '"$base/scripts/ci/setup/fetch-forgejo-policy-drift-token.sh"'


def policy_drift_errors(workflow):
    """Why policy-drift.yml is not the exact shape its OIDC exception admits."""
    errors = []
    triggers = workflow["on"] if isinstance(workflow["on"], dict) else {key: None for key in workflow["on"]}
    if set(triggers) != {"pull_request_target"}:
        errors.append(f"{POLICY_DRIFT} starts on {sorted(triggers)}, not pull_request_target alone")
    jobs = workflow["jobs"]
    if list(jobs) != ["policy-drift"]:
        return errors + [f"{POLICY_DRIFT} has jobs {list(jobs)}, not the one policy-drift job"]
    job = jobs["policy-drift"]
    steps = job.get("steps") or []
    if roles_in_scope(workflow, job) or any("fetch-openbao-" in str(step.get("run", "")) for step in steps):
        errors.append(f"{POLICY_DRIFT} reaches OpenBao")
    checkouts = {}
    for step in steps:
        if step.get("uses") == CHECKOUT:
            with_ = step.get("with") or {}
            checkouts[with_.get("ref")] = with_
    if set(checkouts) != set(POLICY_DRIFT_PATHS):
        errors.append(f"{POLICY_DRIFT} checks out {sorted(map(str, checkouts))}, not exactly base and candidate")
    for ref, path in POLICY_DRIFT_PATHS.items():
        with_ = checkouts.get(ref) or {}
        if with_.get("path") != path or with_.get("persist-credentials") is not False:
            errors.append(f"{POLICY_DRIFT} checks out {ref} at {with_.get('path')!r}, not apart at {path!r}")
    checks = [str(step.get("run", "")) for step in steps if POLICY_DRIFT_TOKEN in str(step.get("run", ""))]
    if len(checks) != 1:
        errors.append(f"{POLICY_DRIFT} mints its token in {len(checks)} steps, not one")
    else:
        run = checks[0]
        verified = run.find(POLICY_DRIFT_KYVERNO_CHECK)
        if verified < 0 or verified > run.find(POLICY_DRIFT_TOKEN):
            errors.append(f"{POLICY_DRIFT} does not verify the sealed Kyverno CLI's sha256 before minting its token")
        if re.search(r"^\s*exit 0\b", run, re.M):
            errors.append(f"{POLICY_DRIFT} can pass without running the check")
        if not run.startswith("set -euo pipefail\n"):
            errors.append(f"{POLICY_DRIFT} does not stop at its first failed command")
        if re.search(r"\|\|\s*(true|:)\s*$", run, re.M):
            errors.append(f"{POLICY_DRIFT} ignores a failed command")
    for step in steps:
        run = str(step.get("run", ""))
        # The pull request's tree is data: it appears only as the checker's
        # argument, and every script that runs is base's.
        if re.search(r"candidate(?!\")", run.replace('"$PWD/candidate"', "")):
            errors.append(f"{POLICY_DRIFT} step {step.get('name')!r} reads the candidate other than as data")
        for line in run.splitlines():
            command = line.strip().split(" ", 1)[0]
            if re.search(r"\.(sh|py)\"?$", command) and not command.startswith('"$base/'):
                errors.append(f"{POLICY_DRIFT} step {step.get('name')!r} runs {command}, not a base script")
    return errors


def workflow_errors(name, text):
    """The properties every workflow keeps, whatever it delivers."""
    errors = []
    workflow = load(text)
    jobs = workflow["jobs"]
    errors += [f"{name}: {error}" for error in graph_errors(jobs, ci=False)]
    if "secrets." in text:
        errors.append(f"{name} reads a repository secret instead of an OpenBao credential")
    if re.search(r"^\s*permissions:", text, re.M):
        errors.append(f"{name} declares GitHub-only permissions that Forgejo ignores")
    triggers = workflow["on"] if isinstance(workflow["on"], dict) else {key: None for key in workflow["on"]}
    push = triggers.get("push") or {}
    unsafe = sorted(set(triggers) - SAFE_TRIGGERS)
    if set(push.get("branches", [])) - {"main"}:
        unsafe.append(f"push to {sorted(push['branches'])}")
    drift_exception = False
    if name == POLICY_DRIFT:
        drift = policy_drift_errors(workflow)
        errors += drift
        drift_exception = not drift
    for job_name, job in jobs.items():
        runner = job.get("runs-on")
        if not isinstance(runner, str) or not RUNNER_EXPRESSION.fullmatch(runner):
            errors.append(f"{name} {job_name} runs on {runner!r}, not a repository-variable runner expression")
        for step in job.get("steps") or []:
            uses = step.get("uses")
            if uses and not PINNED_ACTION.fullmatch(uses):
                errors.append(f"{name} {job_name} uses an action not pinned to a commit: {uses}")
        for env in roles_in_scope(workflow, job):
            for key, role in env.items():
                match = ROLE_KEY.fullmatch(key)
                if match and env.get(f"OPENBAO_{match.group(1)}AUDIENCE") != audience_for(role):
                    errors.append(f"{name} {job_name} {key} does not name its own audience")
        reads_openbao = roles_in_scope(workflow, job) or any(
            "fetch-openbao-" in str(step.get("run", "")) for step in job.get("steps") or [])
        # Forgejo's resolution: a job's own setting wins over the workflow's.
        holds_oidc = job.get("enable-openid-connect", workflow.get("enable-openid-connect"))
        # An OIDC token is a credential even without an OpenBao role in scope:
        # it mints Forgejo integrations, and the publisher roles bind no job or
        # runner claim, so no job on the shared untrusted light runner holds
        # one (#3674, #3758). ci.yaml's metal jobs split by event instead.
        if holds_oidc and runner == runners.UNTRUSTED_LIGHT and not drift_exception:
            errors.append(f"{name} {job_name} holds OIDC on the untrusted light runner")
        if holds_oidc and reads_openbao:
            if unsafe:
                errors.append(f"{name} {job_name} can log in to OpenBao in a run started by {unsafe}")
    # Workflow-wide OIDC reaches every job: only runs no pull request starts.
    if workflow.get("enable-openid-connect") and unsafe and not drift_exception:
        errors.append(f"{name} grants every job OIDC in a run started by {unsafe}")
    return errors


KIND_COMMON = ROOT / "scripts/ci/verify/kind/common.sh"
KIND_DIGEST = re.compile(r"oci-approved/codewire/workspace@sha256:([0-9a-f]{64})")


def kind_image_errors(ci_text, common_text):
    """ci.yaml's Kind workspace image is the approved one common.sh owns."""
    owned = set(KIND_DIGEST.findall(common_text))
    used = set(KIND_DIGEST.findall(ci_text))
    if len(owned) != 1:
        return [f"kind/common.sh approves {len(owned)} Kind workspace images, not one"]
    return [f"ci.yaml runs Kind on {digest}, not the approved {next(iter(owned))}" for digest in sorted(used - owned)]


def action_pin_errors(texts):
    """Each action has one pin, wherever it is used."""
    pins = {}
    for name, text in texts.items():
        for action, ref in re.findall(r"uses: ([^@\s]+)@(\S+)", text):
            pins.setdefault(action, {}).setdefault(ref, []).append(name)
    return [f"{action} is pinned to {len(refs)} commits: "
            + "; ".join(f"{ref} in {', '.join(sorted(set(names)))}" for ref, names in sorted(refs.items()))
            for action, refs in pins.items() if len(refs) > 1]


def all_workflow_errors(texts, common_text=None):
    errors = []
    for name, text in sorted(texts.items()):
        errors += workflow_errors(name, text)
    common_text = KIND_COMMON.read_text() if common_text is None else common_text
    return errors + action_pin_errors(texts) + kind_image_errors(texts.get("ci.yaml", ""), common_text)


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


CHECKOUT = "noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
# Each mutation of one workflow file is a failure an earlier text pin caught,
# or one it missed.
WORKFLOW_MUTATIONS = {
    "the Dev publisher runs on the untrusted runner": ("deploy-dev.yaml", lambda t: in_job(
        t, "publish-runtime-images", f"runs-on: {runners.TRUSTED_LIGHT}", f"runs-on: {runners.UNTRUSTED_LIGHT}")),
    "a support publisher starts on a pull request": ("support-images.yaml", lambda t: t.replace(
        "on:\n  push:\n    branches: [main]\n", "on:\n  pull_request:\n  push:\n    branches: [main]\n", 1)),
    "Dev delivery starts from another branch": ("deploy-dev.yaml", lambda t: t.replace(
        "    branches: [main]\n", "    branches: [main, dev]\n", 1)),
    "a Prod role names another audience": ("deploy-prod.yaml", lambda t: t.replace(
        "  OPENBAO_GHCR_AUDIENCE: ${{ github.event_name == 'schedule' && 'openbao-codewire-source-prod-publisher-schedule'",
        "  OPENBAO_GHCR_AUDIENCE: ${{ github.event_name == 'schedule' && 'openbao-codewire-source-dev-publisher'", 1)),
    "the CLI release reads a repository secret": ("cli-release.yaml", lambda t: t.replace(
        "  OPENBAO_GITHUB_ROLE:", "  GH_TOKEN: ${{ secrets.GH_TOKEN }}\n  OPENBAO_GITHUB_ROLE:", 1)),
    "support images declare permissions": ("support-images.yaml", lambda t: t.replace(
        "\njobs:\n", "\npermissions:\n  contents: read\njobs:\n", 1)),
    "the mirror names a literal runner label": ("mirror-github.yaml", lambda t: t.replace(
        f"runs-on: {runners.TRUSTED_LIGHT}", "runs-on: ubuntu-latest", 1)),
    "the mirror moves its checkout to another commit": ("mirror-github.yaml", lambda t: t.replace(
        CHECKOUT, CHECKOUT[:-40] + "0" * 40, 1)),
    "an action follows a tag": ("deploy-dev.yaml", lambda t: t.replace(CHECKOUT, CHECKOUT[:-40] + "v4", 1)),
    "Dev signs before its descent check": ("deploy-dev.yaml", lambda t: move_step(
        t, "publish-runtime-images", "Sign the exact runtime set",
        "Require this commit to move Dev forward before signing")),
    "ci.yaml runs Kind on an unapproved workspace image": ("ci.yaml", lambda t: re.sub(
        r"(oci-approved/codewire/workspace@sha256:)[0-9a-f]{64}", r"\g<1>" + "1" * 64, t, count=1)),
    "the release schedule's workflow grants OIDC to a pull request": ("deploy-prod.yaml", lambda t: t.replace(
        "\non:\n", "\non:\n  pull_request:\n", 1)),
    "Prod's workflow grants OIDC to its untrusted jobs": ("deploy-prod.yaml", lambda t: t.replace(
        "\nenv:\n", "\nenable-openid-connect: true\n\nenv:\n", 1)),
    "Prod's release selection holds OIDC": ("deploy-prod.yaml", lambda t: in_job(
        t, "release-selection", f"    runs-on: {runners.UNTRUSTED_LIGHT}\n",
        f"    runs-on: {runners.UNTRUSTED_LIGHT}\n    enable-openid-connect: true\n")),
    "the workspace-pin bot token is read on the untrusted runner": ("support-images.yaml", lambda t: in_job(
        t, "propose-workspace-image-pin", f"runs-on: {runners.TRUSTED_LIGHT}", f"runs-on: {runners.UNTRUSTED_LIGHT}")),
    "a Dev build drops the selection it reads": ("deploy-dev.yaml", lambda t: in_job(
        t, "build-service-images", "    needs: [deploy-selection, dev-delivery-turn]\n", "")),
    "the drift check also starts on push": ("policy-drift.yml", lambda t: t.replace(
        "  pull_request_target:\n", "  push:\n    branches: [main]\n  pull_request_target:\n", 1)),
    "the drift check gains a second job": ("policy-drift.yml", lambda t: t + (
        "  second:\n    runs-on: ${{ vars.CODEWIRE_CI_RUNNER_UNTRUSTED_LIGHT || 'unset-CODEWIRE_CI_RUNNER_UNTRUSTED_LIGHT' }}\n"
        "    steps:\n      - run: true\n")),
    "the drift check reads OpenBao": ("policy-drift.yml", lambda t: t.replace(
        '          unset ACTIONS_ID_TOKEN_REQUEST_TOKEN\n',
        '          unset ACTIONS_ID_TOKEN_REQUEST_TOKEN\n          "$base/scripts/ci/setup/fetch-openbao-harbor-credentials.sh"\n', 1)),
    "the drift check runs the pull request's script": ("policy-drift.yml", lambda t: t.replace(
        '"$base/scripts/ci/verify/check-policy-drift.sh"', '"$PWD/candidate/scripts/ci/verify/check-policy-drift.sh"', 1)),
    "the drift check checks the pull request out as its working tree": ("policy-drift.yml", lambda t: t.replace(
        "          path: candidate\n", "", 1)),
    "the drift check mints its token before verifying Kyverno": ("policy-drift.yml", lambda t: t.replace(
        '          kyverno=/usr/local/libexec/kyverno-1.17.1\n',
        '          "$base/scripts/ci/setup/fetch-forgejo-policy-drift-token.sh" "$work/token"\n'
        '          kyverno=/usr/local/libexec/kyverno-1.17.1\n', 1).replace(
        '            sha256sum --check --strict --quiet -\n'
        '          "$base/scripts/ci/setup/fetch-forgejo-policy-drift-token.sh" "$work/token"\n',
        '            sha256sum --check --strict --quiet -\n', 1)),
    "the drift check drops the Kyverno hash": ("policy-drift.yml", lambda t: t.replace(
        "31388ab9b889429cfb48923d00e46159a9cecd30cdc906edbef725a60a7e587e", "", 1)),
    "the drift check pins another Kyverno": ("policy-drift.yml", lambda t: t.replace(
        "31388ab9b889429cfb48923d00e46159a9cecd30cdc906edbef725a60a7e587e", "0" * 64, 1)),
    "the drift check passes where Kyverno is missing": ("policy-drift.yml", lambda t: t.replace(
        "            exit 1\n          fi\n", "            exit 0\n          fi\n", 1)),
    "the drift check keeps going after a failed command": ("policy-drift.yml", lambda t: t.replace(
        '          set -euo pipefail\n          base="$PWD/.policy-drift-base"\n',
        '          base="$PWD/.policy-drift-base"\n', 1)),
    "the drift check ignores a Kyverno hash mismatch": ("policy-drift.yml", lambda t: t.replace(
        "            sha256sum --check --strict --quiet -\n",
        "            sha256sum --check --strict --quiet - || true\n", 1)),
    "Dev selection holds OIDC on the untrusted runner": ("deploy-dev.yaml", lambda t: in_job(
        t, "deploy-selection", f"runs-on: {runners.TRUSTED_LIGHT}", f"runs-on: {runners.UNTRUSTED_LIGHT}")),
}


def workflow_texts():
    return {path.name: path.read_text() for path in sorted(WORKFLOWS.glob("*.y*ml"))}


def main():
    text = CI.read_text()
    errors = check(text)
    texts = workflow_texts()
    errors += all_workflow_errors(texts)
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
    for name, (workflow, mutate) in WORKFLOW_MUTATIONS.items():
        mutated = mutate(texts[workflow])
        if mutated == texts[workflow]:
            print(f"test-ci-workflow-structure: FAIL mutation {name!r} changed nothing", file=sys.stderr)
            return 1
        if not all_workflow_errors(texts | {workflow: mutated}):
            print(f"test-ci-workflow-structure: FAIL mutation {name!r} was not rejected", file=sys.stderr)
            return 1
    print(f"test-ci-workflow-structure: PASS workflows={len(texts)} ci_jobs={len(load(text)['jobs'])} "
          f"mutations_rejected={len(MUTATIONS) + len(WORKFLOW_MUTATIONS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
