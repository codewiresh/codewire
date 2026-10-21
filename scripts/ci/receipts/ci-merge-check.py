#!/usr/bin/env python3
"""Bind a CI-worker merge qualification to an exact pull-request head and main.

The merge-check workflow (.gitea/workflows/merge-check.yaml) runs two jobs:

  Merge check          Pull-request code: merges the current main into the
                       exact head and runs scripts/dev/preflight.sh
                       --for-merge --emit-receipt on that tree.
  Merge-check receipt  No pull-request code: after the first job succeeded,
                       this tool, from the pull request's trusted base, checks
                       what it ran and prints the binding.

Pull-request code cannot forge the receipt:

- The receipt job executes nothing from the pull request. It runs this tool
  from a checkout of the base, and reads the candidate only as Git data.
- The first job's result comes from Forgejo, not from the job's own output.
- The receipt names the head, the main it was merged with, and the merged
  tree, which the receipt job recomputes itself.
- A pull request that changes the machinery deciding what runs and recording
  its result (TRUST_PATHS: this workflow, this tool, preflight, the selector,
  the verification runners) gets no receipt. It qualifies locally instead.

Subcommands:

  merge    CI, first job: merge the current main into the exact head, and warn
           early when the change will get no receipt.
  attest   CI, receipt job: check the first job's result and binding inputs
           and print the binding in one log group, also written for the
           run artifact.
  verify   Merger: find the newest successful merge-check run for the pull
           request's current head and check its binding against the current
           head and main. Prints ci_merge_check=pass or ci_merge_check=fail.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "codewire.ci-merge-check/v2"
WORKFLOW = "merge-check.yaml"
RECEIPT_JOB = "Merge-check receipt"
BINDING_MARKER = "CODEWIRE_MERGE_CHECK_BINDING "
MAIN_REF = "refs/remotes/origin/main"
MERGE_IDENTITY = {
    "GIT_AUTHOR_NAME": "Codewire merge check",
    "GIT_AUTHOR_EMAIL": "merge-check@ci.codewire.invalid",
    "GIT_COMMITTER_NAME": "Codewire merge check",
    "GIT_COMMITTER_EMAIL": "merge-check@ci.codewire.invalid",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
BINDING_KEYS = {
    "schema", "pr", "head", "main", "tree", "run_id", "run_number",
    "merge_check_result", "attested_by",
}
PENDING = {"waiting", "running", "blocked", "unknown"}
# Beyond the local receipt's own entrypoints and policy (local-prepush-receipt.py).
OWN_TRUST_PATHS = (
    ".gitea/workflows/merge-check.yaml",
    "scripts/ci/receipts/ci-merge-check.py",
    "scripts/ci/verify/side-by-side.sh",
)


class CheckError(RuntimeError):
    """One stable, non-sensitive reason the binding does not hold."""


def receipt_module() -> Any:
    """The local receipt tool, whose entrypoints and checks this reuses."""
    path = Path(__file__).resolve().with_name("local-prepush-receipt.py")
    spec = importlib.util.spec_from_file_location("codewire_local_prepush_receipt", path)
    if spec is None or spec.loader is None:
        raise CheckError("receipt-tool-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def trust_paths() -> tuple[str, ...]:
    module = receipt_module()
    return tuple(sorted({*module.ENTRYPOINT_PATHS, *module.POLICY_PATHS, *OWN_TRUST_PATHS}))


def run(command: Sequence[str], *, cwd: Path, env: dict[str, str] | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command), cwd=cwd, env=env, check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise CheckError(f"{command[0]}-failed: {detail.strip()[:400]}") from exc


def git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return run(["git", *args], cwd=root, env=env).stdout.strip()


def toplevel(path: Path) -> Path:
    return Path(git(path, "rev-parse", "--show-toplevel")).resolve(strict=True)


def exact_sha(value: str, what: str) -> str:
    if not SHA.match(value or ""):
        raise CheckError(f"{what}-invalid")
    return value


def commit(root: Path, revision: str) -> str:
    return exact_sha(git(root, "rev-parse", "--verify", f"{revision}^{{commit}}"), "commit")


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=root,
                 check=False)
    if result.returncode not in (0, 1):
        raise CheckError("git-state-unavailable")
    return result.returncode == 0


def merged_tree(root: Path, head: str, main: str) -> str:
    """The tree merging main into head produces, or an error on a conflict."""
    result = run(["git", "merge-tree", "--write-tree", head, main], cwd=root, check=False)
    if result.returncode == 1:
        raise CheckError("merge-conflict")
    if result.returncode != 0:
        raise CheckError("merge-tree-failed")
    return exact_sha(result.stdout.splitlines()[0].strip(), "tree")


def changed_trust_paths(root: Path, head: str, main: str) -> list[str]:
    """Trust paths the pull request itself changes (main...head)."""
    raw = run(["git", "diff", "--no-renames", "--name-only", "-z", f"{main}...{head}"],
              cwd=root).stdout
    changed = {path for path in raw.split("\0") if path}
    return sorted(changed.intersection(trust_paths()))


def write_github_output(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        raise CheckError("github-output-unavailable")
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def refuse_trust_path_change(paths: list[str]) -> None:
    if paths:
        print("::error::this pull request changes the merge check's own machinery, so a CI "
              "worker cannot qualify it; run scripts/dev/preflight.sh --for-merge "
              "--emit-receipt locally", file=sys.stderr)
        for path in paths:
            print(f"  changed: {path}", file=sys.stderr)
        raise CheckError("trust-path-changed")


def command_merge(arguments: argparse.Namespace) -> int:
    root = toplevel(Path.cwd())
    head = exact_sha(arguments.head, "head")
    if commit(root, "HEAD") != head:
        raise CheckError("checkout-is-not-the-pull-request-head")
    main = commit(root, MAIN_REF)
    # The receipt job decides; here the run only says early that it will
    # qualify the change but issue no receipt.
    machinery = changed_trust_paths(root, head, main)
    if machinery:
        print("::warning::this pull request changes the merge check's own machinery "
              f"({', '.join(machinery)}); the run qualifies it, but no receipt is issued, "
              "so it merges on a local scripts/dev/preflight.sh --for-merge run",
              file=sys.stderr)
    environment = {**os.environ, **MERGE_IDENTITY}
    result = run(["git", "merge", "--no-edit", main], cwd=root, env=environment, check=False)
    if result.returncode != 0:
        conflicts = run(["git", "diff", "--name-only", "--diff-filter=U"], cwd=root,
                        check=False).stdout.split()
        run(["git", "merge", "--abort"], cwd=root, check=False)
        print(f"::error::the pull request does not merge cleanly with main {main}; "
              "bring the branch up to date and push", file=sys.stderr)
        for path in conflicts:
            print(f"  conflict: {path}", file=sys.stderr)
        raise CheckError("merge-conflict")
    merged = commit(root, "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    if tree != merged_tree(root, head, main):
        raise CheckError("merged-tree-mismatch")
    print(f"merge-check: pull request #{arguments.pr} head {head} "
          f"{'already contains' if merged == head else 'merged with'} main {main}")
    print(f"merge-check: qualifying commit {merged} tree {tree}")
    if arguments.github_output:
        write_github_output({"head": head, "main": main, "tree": tree})
    return 0


def command_attest(arguments: argparse.Namespace) -> int:
    """The receipt job: runs from the trusted base, reads the candidate as data."""
    repo = toplevel(Path(arguments.repo))
    head = exact_sha(arguments.head, "head")
    main = exact_sha(arguments.main, "main")
    tree = exact_sha(arguments.tree, "tree")
    attested_by = exact_sha(arguments.attested_by, "attested-by")
    if arguments.result != "success":
        raise CheckError(f"merge-check-{arguments.result or 'missing'}")
    if commit(repo, "HEAD") != head:
        raise CheckError("checkout-is-not-the-pull-request-head")
    commit(repo, main)
    if not is_ancestor(repo, main, commit(repo, MAIN_REF)):
        raise CheckError("main-not-canonical")
    if merged_tree(repo, head, main) != tree:
        raise CheckError("tree-mismatch")
    refuse_trust_path_change(changed_trust_paths(repo, head, main))
    binding = {
        "schema": SCHEMA,
        "pr": arguments.pr,
        "head": head,
        "main": main,
        "tree": tree,
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER", ""),
        "merge_check_result": "success",
        "attested_by": attested_by,
    }
    binding_text = json.dumps(binding, sort_keys=True, separators=(",", ":"))
    print("::group::Codewire merge-check receipt")
    print(BINDING_MARKER + binding_text)
    print("::endgroup::")
    print(f"merge-check: pull request #{arguments.pr} head {head} qualified with main "
          f"{main} (tree {tree})")
    if arguments.output_dir:
        output = Path(arguments.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        (output / "binding.json").write_text(binding_text + "\n", encoding="utf-8")
    return 0


def ls_remote(root: Path, remote: str, ref: str) -> str:
    lines = [line.split() for line in git(root, "ls-remote", remote, ref).splitlines()]
    matches = [fields[0] for fields in lines if len(fields) == 2 and fields[1] == ref]
    if len(matches) != 1:
        raise CheckError(f"remote-ref-unavailable: {ref}")
    return exact_sha(matches[0], "remote-ref")


def fj(root: Path, *args: str) -> str:
    return run(["fj", *args], cwd=root).stdout


def fj_json(root: Path, *args: str) -> dict[str, Any]:
    try:
        document = json.loads(fj(root, *args))
    except json.JSONDecodeError as exc:
        raise CheckError("fj-output-malformed") from exc
    if not isinstance(document, dict):
        raise CheckError("fj-output-malformed")
    return document


def marked_line(log: str, marker: str) -> str:
    # Anything the receipt job prints from the candidate (a commit subject in
    # the checkout log) can add a marker line, never remove the real one, so
    # more than one line is refused.
    found = [line[line.index(marker) + len(marker):].strip()
             for line in log.splitlines() if marker in line]
    if len(found) != 1:
        raise CheckError("log-binding-missing" if not found else "log-binding-ambiguous")
    return found[0]


def check_binding(binding: Any, pr: int) -> dict[str, Any]:
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS \
            or binding["schema"] != SCHEMA or binding["pr"] != pr \
            or binding["merge_check_result"] != "success":
        raise CheckError("binding-malformed")
    for key in ("head", "main", "tree", "attested_by"):
        exact_sha(binding[key], f"binding-{key}")
    return binding


def report(values: dict[str, str]) -> None:
    for key, value in values.items():
        print(f"{key}={value}")


def command_verify(arguments: argparse.Namespace) -> int:
    root = toplevel(Path.cwd())
    facts: dict[str, str] = {"pr": str(arguments.pr)}
    try:
        head = ls_remote(root, arguments.remote, f"refs/pull/{arguments.pr}/head")
        main = ls_remote(root, arguments.remote, "refs/heads/main")
        facts.update(head=head, main=main)
        runs = fj_json(root, "actions", "runs", "list", "--workflow", WORKFLOW,
                       "--head", head, "--event", "pull_request", "--limit", "50",
                       "--output", "json").get("runs", [])
        runs = sorted(
            (item for item in runs if isinstance(item, dict)
             and item.get("ref") == f"#{arguments.pr}" and item.get("head_sha") == head),
            key=lambda item: int(item.get("id", 0)), reverse=True,
        )
        successful = [item for item in runs if item.get("status") == "success"]
        if not successful:
            if not runs:
                raise CheckError("no-run-for-head")
            status = str(runs[0].get("status"))
            facts["run_url"] = str(runs[0].get("url", ""))
            raise CheckError("run-pending" if status in PENDING else f"run-{status}")
        chosen = successful[0]
        facts["run_url"] = str(chosen.get("url", ""))
        if runs[0] is not chosen and runs[0].get("status") in PENDING:
            facts["newer_run_pending"] = str(runs[0].get("url", ""))
        view = fj_json(root, "actions", "runs", "view", str(chosen["id"]), "--output", "json")
        jobs = [job for job in view.get("jobs", []) if job.get("name") == RECEIPT_JOB]
        if len(jobs) != 1 or jobs[0].get("status") != "success":
            raise CheckError("receipt-job-not-success")
        log = fj(root, "actions", "runs", "logs", str(chosen["id"]), "--job", str(jobs[0]["id"]))
        try:
            binding = check_binding(json.loads(marked_line(log, BINDING_MARKER)), arguments.pr)
        except json.JSONDecodeError as exc:
            raise CheckError("log-binding-malformed") from exc
        if binding["head"] != head:
            raise CheckError("head-moved")
        facts.update(tested_main=binding["main"], tree=binding["tree"],
                     attested_by=binding["attested_by"])
        run(["git", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", arguments.remote,
             f"refs/pull/{arguments.pr}/head", "refs/heads/main"], cwd=root)
        for revision in (head, main, binding["main"]):
            commit(root, revision)
        if not is_ancestor(root, binding["main"], main):
            raise CheckError("main-not-canonical")
        if merged_tree(root, head, binding["main"]) != binding["tree"]:
            raise CheckError("tree-mismatch")
        if changed_trust_paths(root, head, binding["main"]):
            raise CheckError("trust-path-changed")
        if binding["main"] != main:
            module = receipt_module()
            newer = module.touched_paths(root, binding["main"], main)
            change = module.touched_paths(root, f"{binding['main']}...{head}")
            facts["main_moved_overlaps_change"] = str(
                module.main_moved_into_change(newer, change)).lower()
            raise CheckError("main-moved")
    except CheckError as exc:
        report({"ci_merge_check": "fail", "reason": str(exc), **facts})
        return 1
    report({"ci_merge_check": "pass", "reason": "exact-head-and-main", **facts})
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = result.add_subparsers(dest="command", required=True)
    merge = commands.add_parser("merge")
    merge.add_argument("--pr", type=int, required=True)
    merge.add_argument("--head", required=True)
    merge.add_argument("--github-output", action="store_true")
    attest = commands.add_parser("attest")
    attest.add_argument("--repo", required=True)
    attest.add_argument("--pr", type=int, required=True)
    attest.add_argument("--head", required=True)
    attest.add_argument("--main", required=True)
    attest.add_argument("--tree", required=True)
    attest.add_argument("--result", required=True)
    attest.add_argument("--attested-by", required=True)
    attest.add_argument("--output-dir")
    verify = commands.add_parser("verify")
    verify.add_argument("--pr", type=int, required=True)
    verify.add_argument("--remote", default="origin")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "verify":
        return command_verify(arguments)
    try:
        if arguments.command == "merge":
            return command_merge(arguments)
        return command_attest(arguments)
    except CheckError as exc:
        print(f"merge-check: {arguments.command} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
