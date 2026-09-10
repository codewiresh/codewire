#!/usr/bin/env python3
"""Select a bounded cache experiment from immutable PR event inputs, not authority."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CASES = (
    {"case": "cold", "compiler": "disabled", "layers": "disabled"},
    {"case": "compiler", "compiler": "r2", "layers": "disabled"},
    {"case": "warm-1", "compiler": "r2", "layers": "r2"},
    {"case": "warm-2", "compiler": "r2", "layers": "r2"},
)
SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)
BRANCH = re.compile(r"experiment/workspace-r2-cache/[a-z0-9][a-z0-9-]{0,63}", re.ASCII)


def requested(event):
    if not isinstance(event, dict):
        raise ValueError("invalid PR event object")
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        raise ValueError("invalid PR event")
    labels = pr.get("labels")
    if labels is None:
        labels = []
    if not isinstance(labels, list) or any(not isinstance(label, dict) for label in labels):
        raise ValueError("invalid PR labels")
    if not isinstance(pr.get("head", {}), dict) or not isinstance(pr.get("base", {}), dict):
        raise ValueError("invalid PR head/base object")
    branch = pr.get("head", {}).get("ref", "")
    if not isinstance(branch, str):
        raise ValueError("invalid PR branch")
    return bool(BRANCH.fullmatch(branch)) or any(label.get("name") == "ci/r2-cache-canary" for label in labels)


def selection(root, env):
    result = {"selected": False, "matrix": {"include": []}}
    if env.get("GITHUB_EVENT_NAME") != "pull_request":
        return result
    event_path = Path(env["GITHUB_EVENT_PATH"])
    if event_path.stat().st_size > 1024 * 1024:
        raise ValueError("PR event exceeds its bound")
    event = json.loads(event_path.read_text())
    if not requested(event) or env.get("CODEWIRE_BUILDKIT_CACHE_REQUEST") in ("local", "disabled"):
        return result
    pr = event["pull_request"]
    source = pr.get("head", {}).get("sha", "")
    expected = env.get("CODEWIRE_EXPECTED_SOURCE_SHA", "")
    tree = env.get("CODEWIRE_EXPECTED_SOURCE_TREE", "")
    number = pr.get("number", event.get("number"))
    repository = event.get("repository")
    base_repository = pr.get("base", {}).get("repo")
    if not isinstance(repository, dict) or not isinstance(base_repository, dict) \
            or repository.get("full_name") != "codewire/codewire" \
            or base_repository.get("full_name") != "codewire/codewire" \
            or env.get("GITHUB_REPOSITORY") != "codewire/codewire":
        raise ValueError("experiment requires the canonical Codewire base repository")
    if pr.get("base", {}).get("ref") != "main" or type(number) is not int or number <= 0 \
            or env.get("GITHUB_REF") != f"refs/pull/{number}/head" \
            or any(not isinstance(value, str) or not SHA.fullmatch(value) for value in (source, expected, tree)) \
            or source != expected or env.get("GITHUB_SHA") != source:
        raise ValueError("experiment requires the exact selected main-targeting PR head and tree")
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"], text=True).splitlines()
    if actual != [expected, tree]:
        raise ValueError("experiment checkout differs from the selected head/tree")
    result.update(selected=True, source_sha=source, source_tree=tree, matrix={"include": list(CASES)})
    return result


if __name__ == "__main__":
    try:
        value = selection(Path(__file__).resolve().parents[3], os.environ)
        if sys.argv[1:] == ["--github-output"]:
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write(f"workspace_cache_experiment={str(value['selected']).lower()}\n")
                output.write("workspace_cache_measurement_matrix=" + json.dumps(value["matrix"], separators=(",", ":")) + "\n")
        elif not sys.argv[1:]:
            print(json.dumps(value, sort_keys=True))
        else:
            raise ValueError("unsupported experiment selector arguments")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"workspace cache experiment: {error}", file=sys.stderr)
        sys.exit(2)
