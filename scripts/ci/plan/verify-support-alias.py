#!/usr/bin/env python3
"""Prove that a release may ship the support pair built for an earlier commit.

support-images.yaml gives a main commit its support pair as an alias of the
pair published for an earlier commit when the planner finds the base and
workspace inputs of both commits identical (apply-support-plan.py,
alias_support_pair; #3504). The aliased indexes are the earlier commit's,
unchanged, so their provenance names the commit that built them. Before a
release accepts that provenance (release-support-pair-state.sh), it derives
the same decision again from Git: this checkout's planner, the release
commit's own policy, and a published-pair candidate naming the building
commit and the release's exact index digests. The alias holds only when
apply-support-plan.py would itself alias exactly that commit and those
digests to the release commit.

Usage:
  verify-support-alias.py --repository DIR --source SHA --origin SHA \\
    --base-digest DIGEST --workspace-digest DIGEST

Exit 0 when the alias holds, 1 when it does not, 2 on invalid arguments.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


planner = _load("codewire_ci_planner_support_alias", "planner.py")
support_plan = _load("codewire_ci_apply_support_plan_alias", "apply-support-plan.py")


class AliasRefused(RuntimeError):
    pass


def _candidate(origin: str, digests: dict[str, str]) -> dict:
    # The shape resolve-published-support-pair.sh writes for a dispatch, which
    # reads the pair by its building commit's tag.
    return {
        "schema": planner.SUPPORT_CANDIDATE_SCHEMA,
        "retrieval": {"valid": True, "reasons": []},
        "images": {
            name: {
                "repository": repository,
                "tag": origin,
                "digest": digests[name],
                "revision": origin,
            }
            for name, repository in planner.SUPPORT_REPOSITORIES.items()
        },
    }


def _refusal(document: dict, outputs: dict[str, str]) -> str:
    validation = document.get("baseline", {}).get("validation", {})
    if validation.get("valid") is not True:
        reasons = "; ".join(str(reason) for reason in validation.get("reasons", []))
        return f"the published pair is not a valid baseline: {reasons or 'no reason given'}"
    states = (
        f"base {outputs['base_image_state']}, workspace {outputs['workspace_image_state']}"
    )
    degraded = document.get("degraded_reasons") or []
    if degraded:
        states += "; planner degraded: " + "; ".join(str(reason) for reason in degraded)
    return f"the support inputs differ ({states})"


def verify(
    repository: Path,
    source: str,
    origin: str,
    base_digest: str,
    workspace_digest: str,
) -> None:
    """Return when ORIGIN's pair is a valid alias for SOURCE; raise otherwise."""
    for label, value in (("source", source), ("origin", origin)):
        if not HEX40_RE.fullmatch(value):
            raise ValueError(f"{label} must be a full lowercase commit ID")
    digests = {"base": base_digest, "workspace": workspace_digest}
    for name, digest in digests.items():
        if not DIGEST_RE.fullmatch(digest):
            raise ValueError(f"the {name} digest must be an exact sha256 digest")
    if origin == source:
        raise ValueError("a pair built for the release commit itself is not an alias")

    with tempfile.TemporaryDirectory(prefix="codewire-support-alias-") as temporary:
        temp = Path(temporary)
        candidate = temp / "candidate.json"
        candidate.write_text(json.dumps(_candidate(origin, digests), sort_keys=True) + "\n")
        try:
            document = planner.plan(repository, source, source, source, candidate)
        except planner.PlannerError as exc:
            raise AliasRefused(f"the planner failed: {exc}") from exc
        if document["baseline"]["head_commit"] != source:
            raise AliasRefused("the planner did not plan the exact release commit")
        plan_path = temp / "plan.json"
        plan_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
        tree = subprocess.run(
            ["git", "rev-parse", f"{source}^{{tree}}"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        try:
            outputs = support_plan.trusted_outputs(plan_path, source, tree)
        except support_plan.AdapterError as exc:
            raise AliasRefused(f"the support plan is invalid: {exc}") from exc

    if outputs["alias_support_pair"] != "true":
        raise AliasRefused(_refusal(document, outputs))
    expected = {
        "alias_source_sha": origin,
        "alias_base_digest": base_digest,
        "alias_workspace_digest": workspace_digest,
    }
    for key, value in expected.items():
        if outputs[key] != value:
            raise AliasRefused(f"the plan aliases {key}={outputs[key]}, not {value}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--repository", required=True, help="Git checkout holding both commits")
    parser.add_argument("--source", required=True, help="the release commit")
    parser.add_argument("--origin", required=True, help="the commit the pair was built from")
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--workspace-digest", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        verify(
            Path(args.repository).resolve(),
            args.source,
            args.origin,
            args.base_digest,
            args.workspace_digest,
        )
    except ValueError as exc:
        print(f"support alias: {exc}", file=sys.stderr)
        return 2
    except AliasRefused as exc:
        print(
            f"support alias: {args.source} may not ship the pair built for {args.origin}: {exc}",
            file=sys.stderr,
        )
        return 1
    print(
        f"support alias: {args.source} has the base and workspace inputs of {args.origin}, "
        f"so the pair built for {args.origin} is its own"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
