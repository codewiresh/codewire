#!/usr/bin/env python3
"""Plan one ci.yaml job as CI would run it, from CI's own sources.

run-family.sh calls this twice. Nothing here is a second copy of CI's
environment: every value comes from one of these, read at run time.

- The workflow: ci.yaml at the commit under test, for the workflow and job
  `env`, the job's `runs-on`, `timeout-minutes` and steps.
- The Actions variables, as `fj actions variables list` prints them (variables
  only; secrets are never read, and every `secrets.*` is empty here).
- The runner a placement's `runs-on` label reaches, from infra:
  - a label a runner in a warm VM's manifest declares (warm-vms.yaml lists them)
    takes that runner's `envs`, container options and image;
  - any other label is a metal guest: dispatcher.py's own slot table, label
    and runner-config functions name its ConfigMap in ephemeral-ci.yaml (its
    `envs` and container options), its job image and its job memory limit.
- The job's steps: `run` steps run as written, with their `if` and `env`
  evaluated here; the checkout action is run-family.sh's own checkout of the
  commit under test.

    ci-job-plan.py runner --workflow F --job J --placement P --variables V --infra DIR
        prints the runner as JSON: label, image, docker options, runner envs.
    ci-job-plan.py job --workflow F --job J --placement P --variables V --infra DIR
        --commit SHA --base SHA --selection SEL --branch B --out DIR
        writes the job's environment and steps for run-job-steps.sh.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any

import yaml

WORKSPACE = "/workspace/codewire/codewire"
ACT_DIR = "/var/run/act/workflow"
CHECKOUT_ACTION = "noel/actions-checkout@"


def fail(message: str) -> None:
    print(f"ci-job-plan: {message}", file=sys.stderr)
    sys.exit(2)


# --- Forgejo Actions expressions -------------------------------------------
# The subset ci.yaml uses: literals, context paths, ! == != < <= > >= && ||,
# parentheses and the functions below. Semantics follow the Actions
# expression language: && and || return an operand, == compares strings
# case-insensitively.

TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)"
    r"|(?P<op>==|!=|<=|>=|&&|\|\||[!<>(),\[\]])"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_*][A-Za-z0-9_\-]*)*))"
)


class Expr:
    def __init__(self, text: str, context: dict[str, Any], status: str = "success"):
        self.tokens = self.tokenize(text)
        self.pos = 0
        self.context = context
        self.status = status
        self.text = text

    @staticmethod
    def tokenize(text: str) -> list[tuple[str, Any]]:
        tokens, pos = [], 0
        text = text.strip()
        while pos < len(text):
            match = TOKEN_RE.match(text, pos)
            if not match or match.end() == pos:
                fail(f"cannot parse expression at: {text[pos:]!r}")
            pos = match.end()
            kind = match.lastgroup
            value = match.group(kind)
            if kind == "str":
                value = value[1:-1].replace("''", "'")
            elif kind == "num":
                value = float(value)
            tokens.append((kind, value))
        return tokens

    def peek(self) -> tuple[str, Any] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, value: str | None = None) -> tuple[str, Any]:
        token = self.peek()
        if token is None or (value is not None and token[1] != value):
            fail(f"expected {value!r} in expression {self.text!r}")
        self.pos += 1
        return token

    def evaluate(self) -> Any:
        value = self.parse_or()
        if self.peek() is not None:
            fail(f"trailing tokens in expression {self.text!r}")
        return value

    def parse_or(self) -> Any:
        value = self.parse_and()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.parse_and()
            value = value if truthy(value) else right
        return value

    def parse_and(self) -> Any:
        value = self.parse_compare()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.parse_compare()
            value = right if truthy(value) else value
        return value

    def parse_compare(self) -> Any:
        value = self.parse_unary()
        while self.peek() in {("op", o) for o in ("==", "!=", "<", "<=", ">", ">=")}:
            op = self.take()[1]
            right = self.parse_unary()
            value = compare(value, op, right)
        return value

    def parse_unary(self) -> Any:
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        kind, value = self.take()
        if kind in {"str", "num"}:
            return value
        if (kind, value) == ("op", "("):
            inner = self.parse_or()
            self.take(")")
            return inner
        if kind != "ident":
            fail(f"unexpected {value!r} in expression {self.text!r}")
        if value in {"true", "false"}:
            return value == "true"
        if value == "null":
            return None
        if self.peek() == ("op", "("):
            self.take()
            args = []
            while self.peek() != ("op", ")"):
                args.append(self.parse_or())
                if self.peek() == ("op", ","):
                    self.take()
            self.take(")")
            return self.call(value, args)
        return self.lookup(value)

    def lookup(self, path: str) -> Any:
        node: Any = self.context
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node

    def call(self, name: str, args: list[Any]) -> Any:
        lowered = name.lower()
        if lowered == "contains":
            haystack, needle = args
            if isinstance(haystack, list):
                return any(compare(item, "==", needle) for item in haystack)
            return to_str(needle).lower() in to_str(haystack).lower()
        if lowered == "startswith":
            return to_str(args[0]).lower().startswith(to_str(args[1]).lower())
        if lowered == "endswith":
            return to_str(args[0]).lower().endswith(to_str(args[1]).lower())
        if lowered == "format":
            return re.sub(r"\{(\d+)\}", lambda m: to_str(args[1 + int(m.group(1))]), to_str(args[0]))
        if lowered == "tojson":
            return json.dumps(args[0])
        if lowered == "fromjson":
            return json.loads(to_str(args[0]))
        if lowered == "always":
            return True
        if lowered == "success":
            return self.status == "success"
        if lowered == "failure":
            return self.status == "failure"
        if lowered == "cancelled":
            return False
        fail(f"unsupported function {name}() in expression {self.text!r}")


def truthy(value: Any) -> bool:
    return value not in (None, "", 0, 0.0, False)


def to_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def compare(left: Any, op: str, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        left, right = left.lower(), right.lower()
    elif type(left) is not type(right):
        left, right = to_str(left).lower(), to_str(right).lower()
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    try:
        return {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right}[op]
    except TypeError:
        return False


EMBEDDED_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def interpolate(value: Any, context: dict[str, Any]) -> str:
    return EMBEDDED_RE.sub(lambda m: to_str(Expr(m.group(1), context).evaluate()), to_str(value))


def condition(text: Any, context: dict[str, Any], status: str) -> bool:
    """Whether a step's `if` passes when the job so far is STATUS."""
    if text is None or to_str(text).strip() == "":
        return status == "success"
    raw = to_str(text).strip()
    inner = EMBEDDED_RE.fullmatch(raw)
    raw = inner.group(1) if inner else raw
    # Without a status function, an `if` means success() && (it).
    if not re.search(r"\b(always|success|failure|cancelled)\s*\(", raw):
        if status != "success":
            return False
    return truthy(Expr(raw, context, status).evaluate())


# --- Sources ----------------------------------------------------------------

def read_variables(path: Path) -> dict[str, str]:
    """`fj actions variables list` output: NAME = VALUE, values may span lines."""
    variables: dict[str, str] = {}
    name = None
    for line in path.read_text().splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*) = (.*)$", line)
        if match:
            name = match.group(1)
            variables[name] = match.group(2)
        elif name is not None:
            variables[name] += "\n" + line
    if not variables:
        fail(f"no Actions variables in {path}")
    return variables


# What this planner reads from infra's dispatcher.py. When infra renames or
# reshapes one of them, planning stops here and names it, rather than running
# a job on a guessed runner.
DISPATCHER_CONTRACT = (
    "JOB_IMAGE", "METAL_JOB_IMAGE_TAG", "METAL_SLOTS", "METAL_GUEST_SHAPES",
    "METAL_CPU_SHARE", "METAL_CPU_SHARE_ENV",
    "metal_declared_labels", "metal_runner_config", "metal_worker_resources",
    "metal_job_data_mib",
)


def dispatcher_layout_changed(detail: str) -> None:
    fail(f"infra's forgejo-runners/dispatcher.py layout changed ({detail}); "
         "update scripts/ci/local/ci-job-plan.py to read the new layout")


def load_dispatcher(infra: Path) -> Any:
    path = infra / "forgejo-runners/dispatcher.py"
    spec = importlib.util.spec_from_file_location("forgejo_ci_dispatcher", path)
    if not path.is_file() or spec is None or spec.loader is None:
        fail(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # noqa: BLE001 - any import failure is a layout change
        dispatcher_layout_changed(f"importing it failed: {type(error).__name__}: {error}")
    missing = [name for name in DISPATCHER_CONTRACT if not hasattr(module, name)]
    if missing:
        dispatcher_layout_changed(f"it no longer defines {', '.join(missing)}")
    return module


def yaml_documents(path: Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text()) if isinstance(doc, dict)]


def docker_ref(image: str, dispatcher: Any, warm_text: str) -> str:
    """A runner label's image as a pullable registry reference by digest.

    Metal guests and main's VM preload the job image under a local tag,
    dispatcher.py's METAL_JOB_IMAGE_TAG; its registry reference is the one
    with the same digest (dispatcher.py JOB_IMAGE, a warm VM's preload).
    """
    if "@sha256:" in image:
        return image
    digest = image.rsplit(":", 1)[-1]
    candidates = {dispatcher.JOB_IMAGE}
    candidates.update(re.findall(r"[a-z0-9.\-/]+/act-node-docker@sha256:[0-9a-f]{64}", warm_text))
    for candidate in sorted(candidates):
        if candidate.endswith("@sha256:" + digest):
            return candidate
    fail(f"no registry reference for the runner image {image}")


def warm_vm_files(infra: Path) -> list[Path]:
    """Every warm VM's manifest, by the name infra's warm-vms.yaml gives it."""
    listing = yaml.safe_load((infra / "forgejo-runners/warm-vms.yaml").read_text()) or {}
    names = sorted({vm["file"] for vm in (listing.get("vms") or {}).values()})
    if not names:
        fail("infra's warm-vms.yaml lists no warm VM")
    return [infra / "forgejo-runners" / name for name in names]


def runner_for_label(label: str, infra: Path) -> dict[str, Any]:
    dispatcher = load_dispatcher(infra)
    warm_vms = warm_vm_files(infra)
    warm_text = "".join(path.read_text() for path in warm_vms)
    # A warm VM: a runner config in its manifest that declares the label.
    for path in warm_vms:
        for doc in yaml_documents(path):
            if doc.get("kind") != "ConfigMap":
                continue
            for key, text in (doc.get("data") or {}).items():
                if not key.endswith(".yaml"):
                    continue
                config = yaml.safe_load(text)
                for connection in ((config.get("server") or {}).get("connections") or {}).values():
                    for declared in connection.get("labels") or []:
                        name, _, image = declared.partition(":")
                        if name == label:
                            return {
                                "label": label,
                                "source": f"forgejo-runners/{path.name} {doc['metadata']['name']} {key}",
                                "image": docker_ref(image.removeprefix("docker://"), dispatcher, warm_text),
                                "envs": {k: to_str(v) for k, v in ((config.get("runner") or {}).get("envs") or {}).items()},
                                "options": (config.get("container") or {}).get("options") or "",
                                "memory": "",
                            }
    # A metal guest: the dispatcher's slots that declare the label.
    configs = set()
    memory = set()
    try:
        for entry in dispatcher.METAL_SLOTS:
            # A slot declares its own class's labels only, by their page
            # names (infra#2151 steps 5 and 8; dispatcher.py METAL_PAGE_LABELS).
            if label in dispatcher.metal_declared_labels(entry):
                configs.add(dispatcher.metal_runner_config(entry))
                if entry.get("class") in dispatcher.METAL_GUEST_SHAPES:
                    resources = dispatcher.metal_worker_resources(entry["class"], dispatcher.metal_job_data_mib(entry))
                    memory.add(resources["dind"]["limits"]["memory"])
    except (AttributeError, KeyError, TypeError, IndexError) as error:
        dispatcher_layout_changed(f"{type(error).__name__}: {error}")
    if not configs:
        fail(f"no runner in infra declares the label {label}")
    if len(configs) != 1 or len(memory) > 1:
        fail(f"the label {label} reaches more than one runner shape: {sorted(configs)} {sorted(memory)}")
    if not memory:
        dispatcher_layout_changed(f"no guest shape gives the label {label} a job memory limit")
    config_name = configs.pop()
    for doc in yaml_documents(infra / "forgejo-runners/ephemeral-ci.yaml"):
        if doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == config_name:
            config = yaml.safe_load(doc["data"]["config.yaml"])
            envs = {k: to_str(v) for k, v in ((config.get("runner") or {}).get("envs") or {}).items()}
            share = dispatcher.METAL_CPU_SHARE.get(config_name)
            if share is not None and envs.get(dispatcher.METAL_CPU_SHARE_ENV) != str(share):
                fail(f"{config_name} sets {dispatcher.METAL_CPU_SHARE_ENV}={envs.get(dispatcher.METAL_CPU_SHARE_ENV)}"
                     f" but dispatcher.py METAL_CPU_SHARE says {share}")
            return {
                "label": label,
                "source": f"forgejo-runners/dispatcher.py METAL_SLOTS -> ephemeral-ci.yaml {config_name}",
                "image": docker_ref(dispatcher.METAL_JOB_IMAGE_TAG, dispatcher, warm_text),
                "envs": envs,
                "options": (config.get("container") or {}).get("options") or "",
                "memory": memory.pop() if memory else "",
            }
    fail(f"ephemeral-ci.yaml has no ConfigMap {config_name}")


def docker_options(options: str) -> tuple[list[str], list[str]]:
    """The runner's container options for a local `docker run`.

    A host bind (SOURCE:TARGET) names a path on the CI host, such as a warm
    cache; locally TARGET is an empty anonymous volume, so the job starts cold.
    """
    words, notes, out = shlex.split(options), [], []
    i = 0
    while i < len(words):
        word = words[i]
        if word in {"-v", "--volume"} and i + 1 < len(words):
            spec = words[i + 1]
            parts = spec.split(":")
            if len(parts) >= 2:
                out += ["-v", parts[1]]
                notes.append(f"{spec}: host path absent locally; {parts[1]} is an empty volume")
            else:
                out += ["-v", spec]
            i += 2
            continue
        out.append(word)
        i += 1
    return out, notes


def github_context(args: argparse.Namespace, variables: dict[str, str], workflow: dict[str, Any]) -> dict[str, Any]:
    server = variables.get("CODEWIRE_FORGEJO_INTERNAL_URL", "").rstrip("/")
    source = variables.get("CODEWIRE_SOURCE_URL", "")
    repository = re.sub(r"\.git$", "", source.rstrip("/")).split("/")[-2:]
    repository = "/".join(repository) if len(repository) == 2 else "codewire/codewire"
    commit = getattr(args, "commit", "") or ""
    base = getattr(args, "base", "") or ""
    branch = getattr(args, "branch", "") or "local"
    if args.placement == "main":
        event_name, ref, ref_name = "push", "refs/heads/main", "main"
        event = {"ref": ref, "before": base, "after": commit,
                 "repository": {"full_name": repository, "default_branch": "main"}}
        base_ref = head_ref = ""
    else:
        event_name, ref, ref_name = "pull_request", "refs/pull/0/head", "0/head"
        event = {"action": "synchronize", "number": 0,
                 "pull_request": {"number": 0, "labels": [],
                                  "base": {"ref": "main", "sha": base},
                                  "head": {"ref": branch, "sha": commit}},
                 "repository": {"full_name": repository, "default_branch": "main"}}
        base_ref, head_ref = "main", branch
    return {
        "event_name": event_name, "ref": ref, "ref_name": ref_name, "ref_type": "branch",
        "sha": commit, "event": event, "workspace": WORKSPACE, "repository": repository,
        "repository_owner": repository.split("/")[0], "server_url": server,
        "api_url": f"{server}/api/v1", "workflow": to_str(workflow.get("name")), "job": args.job,
        "base_ref": base_ref, "head_ref": head_ref, "run_id": "0", "run_number": "0",
        "run_attempt": "1", "actor": "run-family", "token": "",
    }


def load_job(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    workflow = yaml.safe_load(Path(args.workflow).read_text())
    job = (workflow.get("jobs") or {}).get(args.job)
    if job is None:
        fail(f"ci.yaml has no job {args.job!r}; its jobs: {', '.join(workflow.get('jobs') or {})}")
    return workflow, job


def resolve_runner(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    workflow, job = load_job(args)
    variables = read_variables(Path(args.variables))
    context = {"github": github_context(args, variables, workflow), "vars": variables,
               "secrets": {}, "inputs": {}, "matrix": {}, "needs": {}, "env": {}}
    label = interpolate(job.get("runs-on"), context)
    if label.startswith("unset-"):
        fail(f"runs-on resolved to {label}: the Actions variable is not set")
    runner = runner_for_label(label, Path(args.infra))
    return workflow, job, runner, variables


def command_runner(args: argparse.Namespace) -> None:
    workflow, job, runner, variables = resolve_runner(args)
    github = github_context(args, variables, workflow)
    runner["origin_url"] = f"{github['server_url']}/{github['repository']}"
    options, notes = docker_options(runner["options"])
    runner["docker_options"] = options
    runner["notes"] = notes
    runner["timeout_minutes"] = int(job.get("timeout-minutes") or 360)
    print(json.dumps(runner))


def shell_exports(env: dict[str, str]) -> str:
    lines = []
    for name, value in env.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            fail(f"invalid environment name {name!r}")
        lines.append(f"export {name}={shlex.quote(value)}")
    return "\n".join(lines) + "\n"


def command_job(args: argparse.Namespace) -> None:
    workflow, job, runner, variables = resolve_runner(args)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    github = github_context(args, variables, workflow)
    needs = {name: {"outputs": {}, "result": "success"} for name in to_list(job.get("needs"))}
    if "verification-selection" in needs:
        # The selection job's outputs a local run has: its dispatch decisions,
        # the selection, the commit, and the receipt's fallback (a local run
        # never reuses a tested-tree receipt).
        outputs = needs["verification-selection"]["outputs"]
        if args.dispatch:
            for line in Path(args.dispatch).read_text().splitlines():
                name, sep, value = line.partition("=")
                if sep:
                    outputs[name] = value
        outputs.update({
            "selection": args.selection, "source_sha": args.commit, "tested_tree_receipt": "fallback",
            "push_verified_base": args.base if args.placement == "main" else "",
        })
    context = {"github": github, "vars": variables, "secrets": {}, "inputs": {},
               "matrix": {}, "needs": needs, "env": {}, "runner": {"os": "Linux", "arch": "X64", "temp": "/tmp"}}

    job_if = job.get("if")
    selected = True if job_if is None else condition(job_if, context, "success")

    # The environment in the order Forgejo Runner layers it: the runner's
    # envs, act's container variables, the workflow env, the job env and the
    # github context; GITHUB_ENV writes and each step's env follow at run time.
    env: dict[str, str] = dict(runner["envs"])
    env.update({"RUNNER_TOOL_CACHE": "/opt/hostedtoolcache", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
                "RUNNER_TEMP": "/tmp", "LANG": "C.UTF-8",
                "ImageOS": re.split(r"\.", runner["label"].replace("-", "", 1), maxsplit=1)[0]})
    for name, value in (workflow.get("env") or {}).items():
        env[name] = interpolate(value, context)
        context["env"][name] = env[name]
    for name, value in (job.get("env") or {}).items():
        env[name] = interpolate(value, context)
        context["env"][name] = env[name]
    env["CI"] = "true"
    for key, value in {"WORKFLOW": github["workflow"], "RUN_ATTEMPT": github["run_attempt"],
                       "RUN_ID": github["run_id"], "RUN_NUMBER": github["run_number"], "ACTIONS": "true",
                       "ACTOR": github["actor"], "REPOSITORY": github["repository"],
                       "EVENT_NAME": github["event_name"], "EVENT_PATH": f"{ACT_DIR}/event.json",
                       "WORKSPACE": WORKSPACE, "SHA": args.commit, "REF": github["ref"],
                       "REF_NAME": github["ref_name"], "REF_TYPE": "branch", "JOB": args.job,
                       "REPOSITORY_OWNER": github["repository_owner"], "BASE_REF": github["base_ref"],
                       "HEAD_REF": github["head_ref"], "SERVER_URL": github["server_url"],
                       "API_URL": github["api_url"]}.items():
        env[f"GITHUB_{key}"] = value
        env[f"FORGEJO_{key}"] = value
    (out / "job.env").write_text(shell_exports(env))
    (out / "event.json").write_text(json.dumps(github["event"]))

    manifest = []
    for index, step in enumerate(job.get("steps") or []):
        name = to_str(step.get("name") or step.get("uses") or f"step {index + 1}")
        on_success = condition(step.get("if"), context, "success")
        on_failure = condition(step.get("if"), context, "failure")
        if "uses" in step:
            uses = to_str(step["uses"])
            if not (on_success or on_failure):
                continue
            if uses.startswith(CHECKOUT_ACTION):
                with_ = {k: interpolate(v, context) for k, v in (step.get("with") or {}).items()}
                if with_.get("ref", args.commit) != args.commit or with_.get("path"):
                    fail(f"step {name!r} checks out {with_}; run-family.sh checks out only {args.commit} at the workspace")
                continue  # run-family.sh's checkout stands for it.
            fail(f"step {name!r} uses {uses}, which run-family.sh cannot run")
        if step.get("shell") not in (None, "bash"):
            fail(f"step {name!r} uses shell {step['shell']}; only bash is supported")
        if step.get("working-directory"):
            fail(f"step {name!r} sets working-directory; not supported")
        step_env = {k: interpolate(v, context) for k, v in (step.get("env") or {}).items()}
        number = f"{index:02d}"
        (out / f"{number}.env").write_text(shell_exports(step_env))
        (out / f"{number}.sh").write_text(interpolate(step.get("run", ""), context) + "\n")
        manifest.append("\t".join([number, "1" if on_success else "0", "1" if on_failure else "0",
                                   name.replace("\t", " ").replace("\n", " ")]))
    (out / "steps.tsv").write_text("\n".join(manifest) + "\n")
    (out / "job.json").write_text(json.dumps({"selected": selected, "job_if": to_str(job_if)}))


def to_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("runner", "job"):
        p = sub.add_parser(command)
        p.add_argument("--workflow", required=True)
        p.add_argument("--job", required=True)
        p.add_argument("--placement", choices=("main", "pr"), required=True)
        p.add_argument("--variables", required=True)
        p.add_argument("--infra", required=True)
        p.add_argument("--commit", default="")
        p.add_argument("--base", default="")
        p.add_argument("--branch", default="")
        if command == "job":
            p.add_argument("--selection", required=True)
            p.add_argument("--dispatch", default="", help="emit-verification-matrices.sh's outputs")
            p.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.command == "runner":
        command_runner(args)
    else:
        command_job(args)


if __name__ == "__main__":
    main()
