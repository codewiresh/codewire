#!/usr/bin/env python3
"""Structural proof of the cw release workflow's capability boundaries.

Compilation runs in a job with no OIDC, signing, mirror or R2 capability; the
macOS pair and the VZ helper are Developer ID-signed and notarized by jobs
that compile nothing and hold only the Apple keys, the helper before the
runtime is packed and only when no release signed its recipe; the
signing/publishing job needs a successful build; R2 publication is opt-in and
inactive or unknown route values refuse before acquiring a credential; promotion
defaults to none. Each property rejects a mutated workflow. The exact route guard
is also exercised with a private fake credential reader, without credentials.
"""

import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_runner_fixtures as runners  # noqa: E402

# The exact runs-on values: runner labels are repository Actions variables.
TRUSTED_LIGHT = runners.TRUSTED_LIGHT
UNTRUSTED_LIGHT = runners.UNTRUSTED_LIGHT
MACOS = runners.MACOS
HEAVY = runners.HEAVY
WORKFLOW = ROOT / ".gitea/workflows/cli-release.yaml"
DRY_RUN = ROOT / ".gitea/workflows/cw-release-dry-run.yaml"
CI = ROOT / ".gitea/workflows/ci.yaml"
# The macOS pair links Apple frameworks and is built natively on the protected
# macOS runner; the Linux pair is built beside the four-target assembly.
DARWIN_TARGETS = "aarch64-apple-darwin x86_64-apple-darwin"
LINUX_TARGETS = "x86_64-unknown-linux-musl aarch64-unknown-linux-gnu"
# Each Linux cw builds in its own job, beside the macOS pair, compiled on the
# trusted BuildKit builder (#3119): the job's one capability is the OIDC login
# for the builder's client certificate, under the workflow's own build role,
# and the owner's in-job recovery is off unless the repository variable names
# the run's commit.
LINUX_BUILDS = (("build-linux-musl", "x86_64-unknown-linux-musl"), ("build-linux-gnu", "aarch64-unknown-linux-gnu"))
RELEASE_BUILD_ROLE = "codewire-source-cli-release-build"
DRY_RUN_BUILD_ROLE = "codewire-source-release-dry-run-build"
IN_JOB_RECOVERY = "      CODEWIRE_IN_JOB_BUILD: ${{ vars.CODEWIRE_IN_JOB_BUILD_SHA == github.sha && '1' || '0' }}\n"
# The dry run builds the commit its main-only guard chose (dispatch-source.sh).
DRY_RUN_SOURCE = "${{ needs.protected-main.outputs.source_sha }}"
DRY_RUN_IN_JOB_RECOVERY = ("      CODEWIRE_IN_JOB_BUILD: ${{ vars.CODEWIRE_IN_JOB_BUILD_SHA == "
                           "needs.protected-main.outputs.source_sha && '1' || '0' }}\n")


def by_event(name):
    """A role name chosen by how the run started: the schedule has its own twin (#2892)."""
    return f"${{{{ github.event_name == 'schedule' && '{name}-schedule' || '{name}' }}}}"


def builder_login(role, scheduled=False):
    """The exact OIDC grant and env of a Linux cw build job; a release's has a
    schedule twin, the dry run's does not."""
    name = by_event if scheduled else (lambda value: value)
    return (f"    enable-openid-connect: true\n    timeout-minutes: 60\n    env:\n"
            f"      OPENBAO_ROLE: {name(role)}\n      OPENBAO_AUDIENCE: {name('openbao-' + role)}\n")


def linux_build_errors(block, job, target, role, source, version, recovery=IN_JOB_RECOVERY):
    """A Linux cw build job: the builder login, the recovery switch, exactly its target."""
    errors = []
    if (builder_login(role, scheduled=role != DRY_RUN_BUILD_ROLE) not in block
            or block.count("OPENBAO_ROLE:") != 1):
        errors.append(f"{job} does not log in to the trusted builder as exactly {role}")
    if recovery not in block:
        errors.append(f"{job} does not keep the in-job build for the owner's recovery only")
    if f'run: scripts/ci/release/build-cw-linux.sh {source} "{version}" {target} .cw-linux\n' not in block:
        errors.append(f"{job} does not build exactly the {target} cw")
    for capability in CAPABILITIES + MACOS_SIGNING:
        if capability != "enable-openid-connect" and capability in block:
            errors.append(f"{job} holds capability {capability}")
    # build-cw-linux.sh drops the ID-token request credentials after the one
    # login; no step may hand them on.
    if "ACTIONS_ID_TOKEN_REQUEST" in block or "ACTIONS_RUNTIME_TOKEN" in block:
        errors.append(f"{job} hands on the job's OIDC request or runtime credentials")
    return errors
GPG = ("CW_RELEASE_GPG_PRIVATE_KEY", "CW_RELEASE_GPG_PASSPHRASE", "CW_RELEASE_GPG_KEY_ID")
CAPABILITIES = ("enable-openid-connect", "secrets.", "fetch-openbao-", "sign-cw-release", "cw_release_r2",
                "mint-github-app-token", "publish-cw-release", "GH_MIRROR_TOKEN_FILE")
# macOS signing runs only in its own jobs (the dry run's run a stand-in).
MACOS_SIGNING = ("sign-macos-cw", "sign-macos-helper", "rcodesign")
# Where the release signs the VZ helper (#1905): exactly the release source's
# entitlements.
RELEASE_ENTITLEMENTS = ".release-source/crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist"
HELPER_IF = "        if: needs.build-helper-darwin.outputs.unsigned_sha256 != ''\n"
# What the macOS signing job must never hold: release OpenPGP, mirror and R2.
NOT_IN_MACOS_SIGNING = ("secrets.", "fetch-openbao-release-signing-key", "fetch-openbao-releases-r2",
                        "fetch-openbao-github-mirror", "sign-cw-release", "cw_release_r2", "mint-github-app-token",
                        "publish-cw-release", "GH_MIRROR_TOKEN_FILE", "cargo ")


def sealed_targets():
    """The Rust targets the sealed CI runner image ships (assert-ci-runner-image.sh)."""
    text = (ROOT / "scripts/ci/setup/assert-ci-runner-image.sh").read_text()
    block = re.search(r"^readonly -a rust_targets=\(\n(.*?)^\)$", text, re.M | re.S).group(1)
    host = re.search(r"^readonly rust_host='([^']+)'$", text, re.M).group(1)
    return {host if line.strip() == '"$rust_host"' else line.strip() for line in block.splitlines()}


def runner_targets_sealed(text):
    """Every Rust target built on a pool runner is one its sealed toolchain ships."""
    unsealed = []
    for name, block in jobs(text).items():
        if "    runs-on: " + MACOS + "\n" in block:
            continue
        for targets in re.findall(r"CW_RELEASE_TARGETS='([^']*)'", block):
            unsealed += [target for target in targets.split() if target not in sealed_targets()]
        # The owner's in-job recovery builds a Linux cw on the runner itself.
        unsealed += [target for target in re.findall(r"scripts/ci/release/build-cw-linux\.sh \S+ \S+ (\S+) ", block)
                     if target not in sealed_targets()]
        unsealed += re.findall(r"cargo [^\n]*--target[ =](\S+)", block)
        if re.search(r"\brustup\b", block):
            unsealed.append(f"{name}: rustup")
    return unsealed


def jobs(text):
    """Split the jobs: mapping into name -> block text."""
    body = text.split("\njobs:\n", 1)[1]
    blocks, name = {}, None
    for line in body.splitlines():
        match = re.fullmatch(r"  ([a-z0-9-]+):", line)
        if match:
            name = match.group(1)
            blocks[name] = []
        elif name:
            blocks[name].append(line)
    return {key: "\n".join(value) for key, value in blocks.items()}


def steps(block):
    """Step name (or uses) -> step text, in order."""
    result, current = [], None
    for line in block.splitlines():
        if line.startswith("      - "):
            current = [line]
            result.append(current)
        elif current is not None:
            current.append(line)
    named = []
    for lines in result:
        text = "\n".join(lines)
        match = re.search(r"- name: (.+)", text) or re.search(r"- uses: (\S+)", text)
        named.append((match.group(1), text))
    return named


def linked_crates(root=ROOT, package="crates/codewire-cli-bin"):
    """The workspace crates PACKAGE links: its normal and build path
    dependencies of every target, transitively (dev dependencies excluded)."""
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"].get("dependencies", {})
    seen, pending = set(), [package]
    while pending:
        directory = pending.pop()
        if directory in seen:
            continue
        seen.add(directory)
        manifest = tomllib.loads((root / directory / "Cargo.toml").read_text())
        tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
        for target in manifest.get("target", {}).values():
            tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
        for table in tables:
            for name, spec in table.items():
                if not isinstance(spec, dict):
                    continue
                if spec.get("workspace") is True:
                    shared = workspace.get(name)
                    if isinstance(shared, dict) and "path" in shared:
                        pending.append(posixpath.normpath(shared["path"]))
                elif "path" in spec:
                    pending.append(posixpath.normpath(posixpath.join(directory, spec["path"])))
    return seen


def actions_value(template, context):
    """TEMPLATE as Actions renders it, for the expression forms the concurrency
    blocks use: github context values, quoted strings, ==, && and ||. A value
    that is one whole expression keeps its type."""
    def evaluate(expression):
        python = re.sub(r"github\.[a-z_]+", lambda match: repr(context[match.group(0)]), expression)
        python = python.replace("&&", " and ").replace("||", " or ")
        if not re.fullmatch(r"(?:\s|'[^']*'|==|!=|and|or|\(|\))*", python):
            raise ValueError(f"unsupported expression {expression!r}")
        return eval(python, {"__builtins__": {}}, {})  # noqa: S307 - checked above
    whole = re.fullmatch(r"\$\{\{(.*?)\}\}", template.strip())
    if whole:
        return evaluate(whole.group(1))
    return re.sub(r"\$\{\{(.*?)\}\}", lambda match: str(evaluate(match.group(1))), template)


def concurrency_by_event(text, events, ref="refs/heads/main", workflow=""):
    """EVENT -> (group, cancel-in-progress) for the workflow's top-level block."""
    block = re.search(r"^concurrency:\n  group: (.+)\n  cancel-in-progress: (.+)$", text, re.M)
    if not block:
        return {}
    result = {}
    for event in events:
        context = {"github.event_name": event, "github.ref": ref, "github.workflow": workflow}
        result[event] = (actions_value(block.group(1), context), actions_value(block.group(2), context))
    return result


# Pushes, schedules and dispatches each have their own group. A newer push to
# main cancels a push run (#2893) and a newer schedule a scheduled run; a
# dispatch never cancels another run (owner decision 2026-10-20).
DRY_RUN_CONCURRENCY = {
    "push": ("cw-release-dry-run-refs/heads/main", True),
    "schedule": ("cw-release-dry-run-refs/heads/main-schedule", True),
    "workflow_dispatch": ("cw-release-dry-run-refs/heads/main-dispatch", False),
}


def push_paths(text):
    """The dry run's push paths, in order."""
    block = re.search(r"^    paths:\n((?:      - .+\n)+)", text, re.M)
    return [line.strip()[2:].strip("'") for line in block.group(1).splitlines()] if block else []


def covered(entry, paths):
    """Whether a push path covers ENTRY: a file, a `dir/` or a `dir/**`."""
    prefix = entry[:-2] if entry.endswith("/**") else entry
    return any(path == entry or (path.endswith("/**") and prefix.startswith(path[:-2])) for path in paths)


def dry_run_path_errors(text):
    """A dry run starts exactly for a change to what a release builds."""
    errors = []
    paths = push_paths(text)
    crates = {path[:-3] for path in paths if path.startswith("crates/")}
    linked = linked_crates()
    if crates != linked:
        errors.append("the dry run's crate paths are not exactly the crates cw links: missing "
                      f"{sorted(linked - crates)}, extra {sorted(crates - linked)}")
    sys.path.insert(0, str(ROOT / "scripts/ci/release"))
    import local_runtime_parts  # noqa: E402
    graph = json.loads((ROOT / "scripts/ci/plan/artifact-graph.json").read_text())
    inputs = [pattern for patterns in graph["artifacts"]["cw_cli_release_assets"]["package_inputs"].values()
              for pattern in patterns]
    for entry in list(local_runtime_parts.RUNTIME_INPUTS) + inputs:
        if not covered(entry, paths):
            errors.append(f"a change to {entry}, which a release build reads, starts no dry run")
    return errors


def external_download_errors(text):
    """Every external download is bounded and retried (#2691)."""
    errors = []
    header = text.split("\njobs:\n", 1)[0]
    # Cargo's git dependency fetches from github.com fail a stalled connect,
    # TLS handshake or transfer in 20 s and retry, instead of hanging.
    for line in ("  CARGO_HTTP_TIMEOUT: '20'\n", "  CARGO_NET_RETRY: '5'\n"):
        if line not in header:
            errors.append(f"workflow env lacks the cargo network bound {line.strip()!r}")
    if re.search(r"^\s+(?:[A-Z_]+=\S+ )*(?:curl|wget)\b", text, re.M):
        errors.append("a step downloads with an unbounded curl or wget instead of fetch-pinned.sh")
    for job, block in jobs(text).items():
        for name, step in steps(block):
            if name == "Install protoc (pinned)" or "zig_url=" in step:
                if "scripts/ci/release/fetch-pinned.sh " not in step:
                    errors.append(f"{job}: {name!r} does not fetch through fetch-pinned.sh")
    return errors


# A failed job reports "failure" with its whole log, and the other jobs finish:
# no release job cancels its own run (#3119 A17; owner, 2026-10-21: "Remove
# all, after the tag"). A cancel turned the failure into "cancelled", cut the
# failing job's log (infra#1229) and cancelled the jobs still building.
RUN_CANCEL = re.compile(r"/actions/runs/[^\s\"']*/cancel")


def run_cancel_errors(text, workflow):
    """Errors if the workflow asks Forgejo to cancel its own run."""
    return [f"{workflow} cancels its own run"] if RUN_CANCEL.search(text) else []


def add_cancel(text, job, condition="${{ failure() }}"):
    """TEXT with a step at the end of JOB that cancels the run on failure."""
    start = text.index(f"\n  {job}:\n")
    end = re.compile(r"\n  [a-z0-9-]+:\n").search(text, start + 1)
    end = end.start() if end else len(text)
    step = ("\n      - name: Cancel the run after this failure\n"
            f"        if: {condition}\n"
            "        run: curl --silent --request POST --max-time 20 "
            "\"${GITHUB_SERVER_URL}/api/v1/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/cancel\"")
    return text[:start] + text[start:end].rstrip("\n") + step + text[end:]


def check(text, ci_text):
    errors = []
    # Forgejo runners set no RUNNER_NAME: a step that requires it fails the
    # first release whose source signs the VZ helper.
    if "${RUNNER_NAME:?}" in text or text.count("${RUNNER_NAME:-$(hostname -s)}") != 2:
        errors.append("runner provenance must fall back to the host name, never require RUNNER_NAME")

    def need(condition, message):
        if not condition:
            errors.append(message)

    errors.extend(external_download_errors(text))
    header = text.split("\njobs:\n", 1)[0]
    need("enable-openid-connect" not in header, "OIDC is enabled for every job")
    need(re.findall(r"^  CW_RELEASE_R2_ROUTE_ADMITTED: '([^'\n]*)'$", header, re.M) == ["true"],
         "the R2 route is not exactly the admitted true value")
    # A dispatch delivers what the schedule delivers: a recovery left without
    # them once missed releases.codewire.sh (v0.4.17, #4444).
    need(re.search(r"r2_publication:\n(?:        .*\n)*?        default: immutable", header) is not None,
         "a dispatched release does not default to its R2 publication")
    need(re.search(r"r2_promote_channel:\n(?:        .*\n)*?        default: stable", header) is not None,
         "a dispatched release does not default to moving stable")
    need("tags:" not in header, "tag-owned workflow code may release")
    blocks = jobs(text)
    need(list(blocks) == ["pending", "release-selection", "build-runtime-linux", "build-helper-darwin", "sign-helper",
                          "pack-runtime", "build-darwin", "sign-darwin", "build-linux-musl", "build-linux-gnu",
                          "build-release", "package-release"], "unexpected job set")
    runtime, darwin = blocks.get("build-runtime-linux", ""), blocks.get("build-darwin", "")
    pack = blocks.get("pack-runtime", "")
    linux_builds = {target: blocks.get(job, "") for job, target in LINUX_BUILDS}
    macos_signing = blocks.get("sign-darwin", "")
    helper_build, helper_signing = blocks.get("build-helper-darwin", ""), blocks.get("sign-helper", "")
    build, package = blocks.get("build-release", ""), blocks.get("package-release", "")

    # The local VM runtime every release cw embeds (#2539, #2733): built from the release
    # source's own scripts, slow parts included on a cache miss, by jobs with
    # no capability; only the publishing job records the parts it built.
    need("    needs: [release-selection]\n    runs-on: " + TRUSTED_LIGHT + "\n" in runtime,
         "the runtime's Linux side does not follow release selection on a protected runner")
    # Both kernels, guest roots and cw runtimes fit; a wedged build cannot hold
    # a release near the protected pool's 330-minute limit (#2733).
    need(re.findall(r"^    timeout-minutes: ([0-9]+)$", runtime, re.M) == ["165"],
         "the runtime's Linux side is not bounded at 165 minutes")
    for capability in CAPABILITIES + MACOS_SIGNING:
        need(capability not in runtime, f"runtime build job holds capability {capability}")
    runtime_build = dict(steps(runtime)).get("Build the Linux side", "")
    need("        working-directory: .release-source\n" in runtime_build
         and "scripts/ci/release/build-local-runtime.sh linux --source-sha" in runtime_build
         and 'LOCAL_RUNTIME_JOB_CONTAINER="${HOSTNAME:?}"' in runtime_build,
         "the runtime's Linux side is not built by the release source's own scripts in this job's container")
    # Its cw runtimes and the linux fragment name the selected release
    # (#2733): the source commit every cw embeds and the release version.
    need("          RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}\n" in runtime_build
         and "          SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}\n" in runtime_build
         and 'linux --source-sha "$SOURCE_SHA" \\\n            --version "$RELEASE_TAG" --output "$work/linux"'
         in runtime_build,
         "the runtime's Linux side does not build its cws from the selected release commit and version")
    need("LOCAL_RUNTIME_NO_BUILD" not in text, "a release refuses to build an uncached runtime part")
    need(not runner_targets_sealed(text), "a Linux runner job needs a Rust target or rustup change its sealed "
         f"toolchain lacks: {runner_targets_sealed(text)}")
    for upload, job in (("Hand the Linux side to the macOS build", runtime),
                        ("Hand the local runtime to the cw builds", pack),
                        ("Hand the runtime part records to publication", pack),
                        *(("Hand the cw to packaging", block) for block in linux_builds.values())):
        need("          include-hidden-files: true\n" in dict(steps(job)).get(upload, ""),
             f"{upload!r} skips its hidden path")
    need("    needs: [release-selection, build-runtime-linux, build-helper-darwin, sign-helper]\n" in pack,
         "the runtime pack does not depend on release selection, the runtime's Linux side and the signed helper")
    mac_runtime = dict(steps(pack)).get("Build the local VM runtime", "")
    need('[ "$(shasum -a 256 ../.local-runtime-linux/runtime-linux.tar | cut -c1-64)" = "$LINUX_SHA256" ]'
         in mac_runtime and "scripts/ci/release/build-local-runtime.sh macos" in mac_runtime
         and 'cp -R "$work/macos/runtime/." ../.local-runtime/' in mac_runtime
         and "          name: cw-release-runtime-${{ github.run_id }}\n          path: .local-runtime/\n" in pack,
         "the runtime pack does not bind the received Linux side and hand over the runtime it packs")
    need("records_sha256" in pack and "name: cw-release-runtime-records-${{ github.run_id }}" in pack,
         "the runtime pack does not hand over and bind its runtime part records")
    # Every release cw embeds the one document pack-runtime packs (#2733).
    need("      document_sha256: ${{ steps.runtime.outputs.document_sha256 }}\n" in pack
         and '"$(shasum -a 256 ../.local-runtime/local-runtime.json | cut -c1-64)" >> "$GITHUB_OUTPUT"'
         in mac_runtime,
         "the runtime pack does not bind the runtime document every cw embeds")
    # That document is the one output the four cw builds wait for: the macOS
    # pair and each Linux cw build at the same time from exactly it.
    need("    needs: [release-selection, pack-runtime]\n    runs-on: " + MACOS + "\n" in darwin
         and "    runs-on: " + MACOS + "\n" in pack,
         "the macOS pair does not build on the Mac as soon as the runtime is packed")
    for job, block, digest in (("build-darwin", darwin, "shasum -a 256"),
                               *((job, blocks.get(job, ""), "sha256sum") for job, _ in LINUX_BUILDS)):
        verify = dict(steps(block)).get("Verify the received runtime is the packed runtime", "")
        need("          name: cw-release-runtime-${{ github.run_id }}\n          path: .local-runtime\n" in block
             and "          DOCUMENT_SHA256: ${{ needs.pack-runtime.outputs.document_sha256 }}\n" in verify
             and f'[ "$({digest} .local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]' in verify
             and 'echo "CW_RELEASE_LOCAL_RUNTIME_DIR=$PWD/.local-runtime" >> "$GITHUB_ENV"' in verify,
             f"{job} may embed a runtime other than the one pack-runtime packed")
    for job, target in LINUX_BUILDS:
        block = blocks.get(job, "")
        need("    needs: [release-selection, pack-runtime]\n    runs-on: " + TRUSTED_LIGHT + "\n" in block,
             f"{job} does not build on a protected runner as soon as the runtime is packed")
        errors.extend(linux_build_errors(block, job, target, RELEASE_BUILD_ROLE, ".release-source", "$RELEASE_TAG"))
        need("      cw_sha256: ${{ steps.build.outputs.cw_sha256 }}\n" in block
             and f"name: cw-release-{target}-${{{{ github.run_id }}}}" in block,
             f"{job} does not hand over and bind its cw")
    # Every release cw is compiled exactly once, in its own build job.
    built = [target for block in blocks.values()
             for targets in re.findall(r"CW_RELEASE_TARGETS='([^']*)'", block) for target in targets.split()]
    built += [target for block in blocks.values()
              for target in re.findall(r"scripts/ci/release/build-cw-linux\.sh \S+ \S+ (\S+) ", block)]
    need(sorted(built) == sorted(DARWIN_TARGETS.split() + LINUX_TARGETS.split()),
         f"the release targets are not each built exactly once: {sorted(built)}")
    for capability in CAPABILITIES + MACOS_SIGNING:
        need(capability not in pack, f"runtime pack job holds capability {capability}")
    need([job for job, body in blocks.items() if "local_runtime_parts.py publish" in body] == ["package-release"]
         and [step for step, body in steps(package) if "local_runtime_parts.py publish" in body]
         == ["Record the runtime parts this release built"],
         "runtime part records are written outside the publishing step")
    need("    runs-on: " + MACOS + "\n" in darwin, "the macOS build does not run on the protected Mac runner")
    for capability in CAPABILITIES + MACOS_SIGNING:
        need(capability not in darwin, f"macOS build job holds capability {capability}")
    need(f"CW_RELEASE_TARGETS='{DARWIN_TARGETS}'" in darwin, "the macOS build does not build exactly the Mac pair")
    need("darwin_sums_sha256" in darwin and "name: cw-release-darwin-${{ github.run_id }}" in darwin,
         "the macOS build does not hand over and bind its pair")

    # The VZ helper (#1905): built on the Mac from the release source with no
    # capability, Developer ID-signed by a job that holds only the Apple keys,
    # and packed by the macOS build only as the exact signed bytes, with the
    # recipe and provenance of this run; or taken from the parts cache.
    need("    needs: [release-selection]\n    runs-on: " + MACOS + "\n" in helper_build
         and not re.search(r"^    if:", helper_build, re.M),
         "the helper build does not follow release selection on the protected Mac runner")
    for capability in CAPABILITIES + MACOS_SIGNING:
        need(capability not in helper_build, f"helper build job holds capability {capability}")
    helper_step = dict(steps(helper_build)).get("Build the helper unless its recipe is signed", "")
    need("        working-directory: .release-source\n" in helper_step
         and 'scripts/ci/release/build-local-runtime.sh helper --output "$work"' in helper_step
         and "if ! grep -q '\"vz-runner-macos\"' scripts/ci/release/local_runtime_parts.py; then" in helper_step,
         "the helper is not built by the release source's own scripts")
    need("unsigned_sha256" in helper_step and "name: cw-release-vz-runner-unsigned-${{ github.run_id }}" in helper_build
         and "          include-hidden-files: true\n" in dict(steps(helper_build)).get(
             "Hand the unsigned helper to signing", ""),
         "the helper build does not hand over and bind the unsigned helper")
    need("    needs: [release-selection, build-helper-darwin]\n    runs-on: " + TRUSTED_LIGHT + "\n"
         "    enable-openid-connect: true\n" in helper_signing and not re.search(r"^    if:", helper_signing, re.M),
         "helper signing does not follow the helper build on a protected runner with its OIDC exchange")
    need(all(HELPER_IF in step or HELPER_IF.removesuffix("\n") + " && failure()\n" in step
             for name, step in steps(helper_signing)
             if not name.startswith("noel/actions-checkout@")
             or "path: .release-source" in step),
         "helper signing acts without an unsigned helper to sign")
    need("name: cw-release-vz-runner-unsigned-${{ github.run_id }}" in helper_signing
         and "UNSIGNED_SHA256: ${{ needs.build-helper-darwin.outputs.unsigned_sha256 }}" in helper_signing
         and '[ "$(sha256sum vz-runner-unsigned/codewire-vz-runner | cut -c1-64)" = "$UNSIGNED_SHA256" ]'
         in helper_signing, "helper signing does not bind the received helper to the built helper")
    helper_sign = dict(steps(helper_signing)).get("Sign and notarize the helper", "")
    need(f"            vz-runner-unsigned/codewire-vz-runner \\\n            {RELEASE_ENTITLEMENTS} vz-runner-signed"
         in helper_sign, "the helper is not signed with exactly the release source's entitlements")
    need("signed_sha256" in helper_sign and "name: cw-release-vz-runner-signed-${{ github.run_id }}" in helper_signing,
         "helper signing does not hand over and bind the signed helper")
    need("swift " not in helper_signing, "the helper signing job compiles")
    mac_receive = dict(steps(pack)).get("Receive the signed VZ helper", "")
    need("        if: needs.sign-helper.outputs.signed_sha256 != ''\n" in mac_receive
         and "name: cw-release-vz-runner-signed-${{ github.run_id }}" in mac_receive
         and "cw-release-vz-runner-unsigned" not in pack and "cw-release-vz-runner" not in darwin,
         "the macOS build may pack a helper other than the signed one")
    need("          SIGNED_HELPER_SHA256: ${{ needs.sign-helper.outputs.signed_sha256 }}\n" in mac_runtime
         and '[ "$(shasum -a 256 ../.vz-runner-signed/codewire-vz-runner | cut -c1-64)" = "$SIGNED_HELPER_SHA256" ]'
         in mac_runtime, "the macOS build does not bind the received helper to the signed helper")
    need("          HELPER_RECIPE: ${{ needs.build-helper-darwin.outputs.recipe }}\n" in mac_runtime
         and '--set "source_sha=$SOURCE_SHA"' in mac_runtime
         and 'helper=(--helper "$work/vz-runner-signed")' in mac_runtime
         and '${helper[@]+"${helper[@]}"} --output "$work/macos"' in mac_runtime,
         "the macOS build does not pack the signed helper with its recipe and this run's provenance")

    # Developer ID signing and notarization (#2064): after the macOS build,
    # before any identity binds the bytes, holding only the Apple keys.
    need("    needs: [release-selection, build-darwin]\n    runs-on: " + TRUSTED_LIGHT + "\n"
         "    enable-openid-connect: true\n" in macos_signing and not re.search(r"^    if:", macos_signing, re.M),
         "macOS signing does not follow the macOS build on a protected runner with its OIDC exchange")
    for job, block, step, signer in (
            ("macOS", macos_signing, "Sign and notarize the macOS pair",
             "sign-macos-cw.sh .rcodesign/rcodesign \"$macos_work/keys\""),
            ("helper", helper_signing, "Sign and notarize the helper",
             "sign-macos-helper.sh .rcodesign/rcodesign \"$macos_work/keys\"")):
        for capability in NOT_IN_MACOS_SIGNING:
            need(capability not in block, f"{job} signing job holds capability {capability}")
        for name in GPG:
            need(name not in block, f"{job} signing job holds {name}")
        install = dict(steps(block)).get("Install rcodesign (pinned)", "")
        need('"$RCODESIGN_X86_64_LINUX_SHA256" rcodesign.tar.gz' in install
             and "scripts/ci/release/fetch-pinned.sh" in install,
             f"{job} signing does not check rcodesign against its pinned digest")
        signing = dict(steps(block)).get(step, "")
        need([name for name, body in steps(block) if "fetch-openbao-macos-signing.sh" in body] == [step],
             f"the Apple keys are read outside the {job} signing step")
        marks = [signing.find(mark) for mark in ("          trap cleanup_macos_keys EXIT\n",
                                                'fetch-openbao-macos-signing.sh "$macos_work/keys"', signer,
                                                "          cleanup_macos_keys\n")]
        need(-1 not in marks and marks == sorted(marks),
             f"the {job} signing job's Apple keys are not trapped, read, used and shredded in that order")
        need('find "$macos_work" -type f -exec shred -u {} +' in signing,
             f"the {job} signing job's Apple keys are not shredded")
    need("name: cw-release-darwin-${{ github.run_id }}" in macos_signing
         and "UNSIGNED_SUMS_SHA256: ${{ needs.build-darwin.outputs.darwin_sums_sha256 }}" in macos_signing
         and '[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$UNSIGNED_SUMS_SHA256" ]' in macos_signing,
         "macOS signing does not bind the received pair to the built pair")
    install = dict(steps(macos_signing)).get("Install rcodesign (pinned)", "")
    need(re.search(r"^  RCODESIGN_X86_64_LINUX_SHA256: [0-9a-f]{64}$", header, re.M) is not None
         and '"$RCODESIGN_X86_64_LINUX_SHA256" rcodesign.tar.gz' in install
         and "scripts/ci/release/fetch-pinned.sh" in install,
         "rcodesign is not checked against its pinned digest")
    signing = dict(steps(macos_signing)).get("Sign and notarize the macOS pair", "")
    need([job for job, body in blocks.items() if "fetch-openbao-macos-signing.sh" in body]
         == ["sign-helper", "sign-darwin"], "the Apple keys are read outside the macOS signing jobs")
    need("darwin_sums_sha256" in signing and "name: cw-release-darwin-signed-${{ github.run_id }}" in macos_signing,
         "macOS signing does not hand over and bind the signed pair")
    need("rcodesign-stand-in" not in text, "the release signs with the rcodesign stand-in")

    # pack-runtime for the runtime document's digest, sign-darwin for the
    # signed pair and each Linux build for its cw.
    need("    needs: [release-selection, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]\n" in build,
         "packaging does not wait for the runtime, the signed macOS pair and both Linux cws")
    linux_received = dict(steps(build)).get("Verify the received Linux cws are the built cws", "")
    need("          MUSL_SHA256: ${{ needs.build-linux-musl.outputs.cw_sha256 }}\n" in linux_received
         and "          GNU_SHA256: ${{ needs.build-linux-gnu.outputs.cw_sha256 }}\n" in linux_received
         and '[ "$(sha256sum "dist-linux/$asset" | cut -c1-64)" = "${pair#*=}" ]' in linux_received
         and all(f"name: cw-release-{target}-${{{{ github.run_id }}}}" in build for _, target in LINUX_BUILDS),
         "packaging does not bind each received Linux cw to the cw its job built")
    need("name: cw-release-darwin-signed-${{ github.run_id }}" in build
         and "name: cw-release-darwin-${{ github.run_id }}" not in build
         and "DARWIN_SUMS_SHA256: ${{ needs.sign-darwin.outputs.darwin_sums_sha256 }}" in build,
         "build does not package exactly the signed macOS pair")
    for capability in CAPABILITIES + MACOS_SIGNING:
        need(capability not in build, f"build job holds capability {capability}")
    for capability in MACOS_SIGNING:
        need(capability not in package, f"publication job holds macOS signing {capability}")
    need("CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin" in build and "cargo zigbuild" not in build,
         "packaging does not prepare exactly the four imported cws without building one")
    need('[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]' in build,
         "the received macOS pair is not checked against the built pair")
    need("cw_release.py verify --dist dist/cw-release --unsigned" in build, "build does not verify its delivery")
    received = dict(steps(build)).get("Verify the received macOS pair is the signed pair", "")
    packaged = dict(steps(build)).get("Package unsigned release delivery", "")
    need("          DOCUMENT_SHA256: ${{ needs.pack-runtime.outputs.document_sha256 }}\n" in received
         and '[ "$(sha256sum dist-darwin/local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]'
         in received and "[ ! -e dist-darwin/local-runtime ]" in received,
         "the macOS pair may carry a runtime other than the one pack-runtime packed")
    need("          DOCUMENT_SHA256: ${{ needs.pack-runtime.outputs.document_sha256 }}\n" in packaged
         and 'grep -q "^cw-release: local runtime document_sha256=$DOCUMENT_SHA256 " <<<"$verified"' in packaged,
         "build does not require its delivery to carry the packed runtime document")
    need("delivery_sha256" in build, "build does not bind its delivery digest")
    need("cargo build --locked --release -p codewire-cw-release \\\n"
         "            --example verify-release-signatures" in build and "verifier_sha256" in build
         and "name: cw-release-verifier-${{ github.run_id }}" in build,
         "build does not compile, bind and hand over cw's release-signature verifier")
    verifier_upload = dict(steps(build)).get("Hand the signature verifier to signing", "")
    need("          path: .release-verifier/\n" in verifier_upload
         and "          include-hidden-files: true\n" in verifier_upload,
         "the hidden verifier directory is not uploaded (the upload action skips hidden paths)")

    need("    needs: [release-selection, pack-runtime, build-release]" in package,
         "signing does not need a successful build")
    need("    enable-openid-connect: true" in package, "publication job lacks its OIDC exchange")
    need(not re.search(r"^    if:", package, re.M), "publication job can run without a successful build")
    names = [name for name, _ in steps(package)]
    order = ["Receive the unsigned delivery", "Verify the received delivery is the built delivery",
             "Receive cw's release-signature verifier", "Verify the received verifier is the built verifier",
             "Reuse an already-published signed R2 release", "Sign release delivery",
             "Verify the signed delivery with cw's built-in verifier",
             "Refuse to change an already-published release",
             "Publish immutable R2 release objects", "Receive the runtime part records",
             "Record the runtime parts this release built", "Remove the R2 publisher credential",
             "Publish signed release assets"]
    positions = [names.index(name) if name in names else -1 for name in order]
    need(-1 not in positions and positions == sorted(positions), "publication steps are missing or reordered")
    need(names and names[-1] == "Publish signed release assets", "work follows mirror publication")
    by_name = dict(steps(package))
    need("secrets." not in text, "the release workflow reads a Forgejo Actions secret")
    # Before anything is written, every R2 run included, a tag whose published
    # assets differ from this delivery stops the run (#4444).
    unchanged = by_name.get("Refuse to change an already-published release", "")
    need("        if:" not in unchanged, "the published-asset check is conditional")
    need('../scripts/ci/release/publish-cw-release.sh --check-unchanged "$RELEASE_TAG" dist/cw-release' in unchanged
         and "GITEA_TOKEN: ${{ github.token }}" in unchanged, "the published-asset check does not compare the delivery")
    need("fetch-openbao" not in unchanged and "GH_MIRROR" not in unchanged,
         "the published-asset check holds more than the job token")
    sign = by_name.get("Sign release delivery", "")
    need([step for step, body in steps(package) if "fetch-openbao-release-signing-key.sh" in body]
         == ["Sign release delivery"], "the signing key is read outside the signing step")
    # cw refuses signatures GnuPG accepts (armor headers, subkeys, more than
    # one packet), so its exact built verifier must admit the signed bytes
    # before any immutable publication. The signing job compiles nothing.
    need("cargo " not in package, "the signing job compiles code while it holds release capabilities")
    need('[ "$(sha256sum .release-verifier/verify-release-signatures | cut -c1-64)" = "$VERIFIER_SHA256" ]'
         in by_name.get("Verify the received verifier is the built verifier", ""),
         "the received verifier is not checked against the built digest")
    compiled = re.findall(r'^const TRUST_FINGERPRINT: &str = "([0-9A-F]{40})";$',
                          (ROOT / "crates/codewire-cli/src/public_fetch.rs").read_text(), re.M)
    builtin = by_name.get("Verify the signed delivery with cw's built-in verifier", "")
    need(len(compiled) == 1 and "../.release-verifier/verify-release-signatures apps/cli/GPG_PUBLIC_KEY.asc \\\n"
         f"            {compiled[0]} dist/cw-release" in builtin,
         "the built-in verifier does not check the delivery against cw's compiled release key")
    need("if:" not in builtin, "the built-in verifier is conditional")
    for name in GPG:
        need(text.count(name) == sign.count(name) > 0, f"{name} appears outside the signing step")
    marks = [sign.find(mark) for mark in ("          trap cleanup_signing EXIT\n",
                                         "fetch-openbao-release-signing-key.sh \"$signing_work/key\"",
                                         "verify-cw-release-signing-key.sh apps/cli/GPG_PUBLIC_KEY.asc",
                                         "sign-cw-release.sh dist/cw-release",
                                         "          cleanup_signing\n")]
    need(-1 not in marks and marks == sorted(marks),
         "the signing key is not trapped, read, checked, used and shredded in that order")
    need("find \"$signing_work\" -type f -exec shred -u {} +" in sign, "the signing key is not shredded")
    probe = by_name.get("Reuse an already-published signed R2 release", "")
    publish = by_name.get("Publish immutable R2 release objects", "")
    for step in (probe, publish):
        need("if: ${{ needs.release-selection.outputs.r2_publication == 'immutable' }}" in step, "an R2 step is not opt-in")
        need("always()" not in step and "failure()" not in step, "an R2 step runs after failure")
    admitted = probe.find("[ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ]")
    fetch = probe.find("fetch-openbao-releases-r2-credentials.sh")
    need(0 <= admitted < fetch, "the R2 credential is read before the route admission check")
    need([step for step, body in steps(package) if "fetch-openbao-releases-r2-credentials.sh" in body]
         == ["Reuse an already-published signed R2 release"], "the R2 credential is read in an unexpected step")
    records = by_name.get("Record the runtime parts this release built", "")
    need("if: ${{ needs.release-selection.outputs.r2_publication == 'immutable' && needs.pack-runtime.outputs.records_sha256 != '' }}"
         in records and "always()" not in records, "runtime part records are written without R2 publication")
    need('[ "$(sha256sum ../.runtime-records/runtime-records.tar | cut -c1-64)" = "$RECORDS_SHA256" ]' in records,
         "the received runtime part records are not checked against the built records")
    need('if [ "$CW_RELEASE_R2_STATE" = retained ]; then' in records
         and "printf 'CW_RELEASE_R2_STATE=%s\\n' \"$state\" >> \"$GITHUB_ENV\"" in probe,
         "a retained release writes records for blobs it did not publish")
    need("--promote \"$PROMOTE_CHANNEL\"" in publish and "PROMOTE_CHANNEL: ${{ needs.release-selection.outputs.r2_promote_channel }}"
         in publish, "promotion is not the explicit input")
    need("cw_release.py digest --dist dist/cw-release)\" = \"$DELIVERY_SHA256\" ]"
         in by_name.get("Verify the received delivery is the built delivery", ""),
         "received delivery is not checked against the built digest")
    mirror = by_name.get("Publish signed release assets", "")
    need("fetch-openbao-github-mirror-credentials.sh" in mirror and "mint-github-app-token.sh" in mirror,
         "GitHub mirror no longer uses the OIDC GitHub App boundary")
    need(mirror.rstrip().endswith('../scripts/ci/release/publish-cw-release.sh "$RELEASE_TAG" dist/cw-release'),
         "mirror publication is not the final command")
    need(not re.search(r"ghp_|github_pat_|ssh-key|SSH_PRIVATE_KEY|secrets\.(GH|GITHUB)_", text),
         "a PAT or SSH deploy key appears")
    for action in ("actions-upload-artifact@", "actions-download-artifact@"):
        refs = set(re.findall(r"(?<![\w./-])noel/" + action + r"[0-9a-f]{40}", text))
        need(len(refs) == 1 and refs <= set(re.findall(r"(?<![\w./-])noel/" + action + r"[0-9a-f]{40}",
                                                       ci_text)), f"{action} is not the pinned mirrored action")
    errors.extend(run_cancel_errors(text, "cli-release.yaml"))
    return errors


MUTATIONS = {
    "helper build requires RUNNER_NAME": lambda t: t.replace(
        "${RUNNER_NAME:-$(hostname -s)}", "${RUNNER_NAME:?}", 1),
    "release Linux side without a job limit": lambda t: t.replace("    timeout-minutes: 165\n", "", 1),
    "release Linux side at the pool limit": lambda t: t.replace(
        "    timeout-minutes: 165\n", "    timeout-minutes: 330\n", 1),
    "runtime document not handed over": lambda t: t.replace(
        "      document_sha256: ${{ steps.runtime.outputs.document_sha256 }}\n", "", 1),
    "received runtime document unchecked": lambda t: t.replace(
        '            [ "$(sha256sum dist-darwin/local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]\n',
        "            true\n", 1),
    "delivery runtime document unchecked": lambda t: t.replace(
        '            grep -q "^cw-release: local runtime document_sha256=$DOCUMENT_SHA256 " <<<"$verified"\n',
        "            true\n", 1),
    "unbounded cargo git fetch": lambda t: t.replace("  CARGO_HTTP_TIMEOUT: '20'\n", "", 1),
    "cargo git fetch without retries": lambda t: t.replace("  CARGO_NET_RETRY: '5'\n", "", 1),
    "unbounded protoc download": lambda t: t.replace(
        "          scripts/ci/release/fetch-pinned.sh \"https://github.com/protocolbuffers",
        "          curl -fsSL -o /tmp/protoc.zip \"https://github.com/protocolbuffers", 1),
    "global OIDC": lambda t: t.replace("\n\nenv:\n", "\n\nenable-openid-connect: true\n\nenv:\n", 1),
    "OIDC in build": lambda t: t.replace("    runs-on: " + TRUSTED_LIGHT + "\n    timeout-minutes: 30\n",
                                         "    runs-on: " + TRUSTED_LIGHT + "\n    enable-openid-connect: true\n"
                                         "    timeout-minutes: 30\n", 1),
    "OIDC in macOS build": lambda t: t.replace("    runs-on: " + MACOS + "\n    timeout-minutes: 60\n",
                                               "    runs-on: " + MACOS + "\n    enable-openid-connect: true\n"
                                               "    timeout-minutes: 60\n", 1),
    "OIDC in runtime pack": lambda t: t.replace("    runs-on: " + MACOS + "\n    timeout-minutes: 45\n",
                                                "    runs-on: " + MACOS + "\n    enable-openid-connect: true\n"
                                                "    timeout-minutes: 45\n", 1),
    "Linux cw build under the signing role": lambda t: t.replace(
        f"      OPENBAO_ROLE: {by_event(RELEASE_BUILD_ROLE)}\n",
        f"      OPENBAO_ROLE: {by_event('codewire-source-cli-release-signing')}\n", 1),
    "Linux cw build with a second role": lambda t: t.replace(
        f"      OPENBAO_ROLE: {by_event(RELEASE_BUILD_ROLE)}\n",
        f"      OPENBAO_ROLE: {by_event(RELEASE_BUILD_ROLE)}\n      OPENBAO_ROLE_R2: codewire-source-cli-releases-r2\n", 1),
    "scheduled Linux cw build under the dispatch role": lambda t: t.replace(
        f"'{RELEASE_BUILD_ROLE}-schedule'", f"'{RELEASE_BUILD_ROLE}'", 1),
    "Linux cw build role chosen by the actor": lambda t: t.replace(
        f"      OPENBAO_ROLE: ${{{{ github.event_name == 'schedule' && '{RELEASE_BUILD_ROLE}",
        f"      OPENBAO_ROLE: ${{{{ github.actor == 'forgejo-actions' && '{RELEASE_BUILD_ROLE}", 1),
    "Linux cw built in the job by default": lambda t: t.replace(IN_JOB_RECOVERY, "      CODEWIRE_IN_JOB_BUILD: '1'\n", 1),
    "Linux cw build hands on the OIDC request token": lambda t: t.replace(
        "          CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}\n"
        "        run: scripts/ci/release/build-cw-linux.sh",
        "          CW_RELEASE_TAG_OBJECT_SHA: ${{ needs.release-selection.outputs.tag_object_sha }}\n"
        "          BUILD_OIDC: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}\n"
        "        run: scripts/ci/release/build-cw-linux.sh", 1),
    "Linux cw build reads the signing key": lambda t: t.replace(
        'run: scripts/ci/release/build-cw-linux.sh .release-source "$RELEASE_TAG" x86_64-unknown-linux-musl .cw-linux\n',
        'run: scripts/ci/setup/fetch-openbao-release-signing-key.sh && scripts/ci/release/build-cw-linux.sh '
        '.release-source "$RELEASE_TAG" x86_64-unknown-linux-musl .cw-linux\n', 1),
    "macOS pair waits for the Linux cws": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime]\n    runs-on: " + MACOS + "\n",
        "    needs: [release-selection, pack-runtime, build-linux-musl]\n    runs-on: " + MACOS + "\n", 1),
    "Linux cw waits for the macOS pair": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime]\n    runs-on: " + TRUSTED_LIGHT + "\n",
        "    needs: [release-selection, pack-runtime, build-darwin]\n    runs-on: " + TRUSTED_LIGHT + "\n", 1),
    "Linux cw built twice": lambda t: t.replace(
        '"$RELEASE_TAG" aarch64-unknown-linux-gnu .cw-linux', '"$RELEASE_TAG" x86_64-unknown-linux-musl .cw-linux', 1),
    "packaging compiles the Linux pair": lambda t: t.replace(
        "CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin",
        f"CW_RELEASE_BUILD_CMD='cargo zigbuild' CW_RELEASE_TARGETS='{LINUX_TARGETS}' CW_RELEASE_IMPORT_DIR=dist-darwin",
        1),
    "packaging before a Linux cw": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]\n",
        "    needs: [release-selection, pack-runtime, sign-darwin, build-linux-musl]\n", 1),
    "unbound Linux cw": lambda t: t.replace(
        '[ "$(sha256sum "dist-linux/$asset" | cut -c1-64)" = "${pair#*=}" ]', "true", 1),
    "Linux cw bound to another job": lambda t: t.replace(
        "GNU_SHA256: ${{ needs.build-linux-gnu.outputs.cw_sha256 }}",
        "GNU_SHA256: ${{ needs.build-linux-musl.outputs.cw_sha256 }}", 1),
    "Linux cw not handed over": lambda t: t.replace(
        "          name: cw-release-aarch64-unknown-linux-gnu-${{ github.run_id }}\n          path: .cw-linux/\n",
        "          name: cw-release-gnu-${{ github.run_id }}\n          path: .cw-linux/\n", 1),
    "macOS pair from an unbound runtime": lambda t: t.replace(
        '[ "$(shasum -a 256 .local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]', "true", 1),
    "Linux cw from an unbound runtime": lambda t: nth_replace(
        t, '[ "$(sha256sum .local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]', "true", 2),
    "Linux cw without the runtime": lambda t: nth_replace(
        t, '          echo "CW_RELEASE_LOCAL_RUNTIME_DIR=$PWD/.local-runtime" >> "$GITHUB_ENV"\n', "", 3),
    "runtime pack not handed over": lambda t: t.replace(
        "          name: cw-release-runtime-${{ github.run_id }}\n          path: .local-runtime/\n",
        "          name: cw-release-runtime-${{ github.run_id }}\n          path: .local-runtime/local-runtime.json\n", 1),
    "hidden runtime skipped": lambda t: t.replace(
        "          path: .local-runtime/\n          include-hidden-files: true\n", "          path: .local-runtime/\n", 1),
    "macOS build on a pool runner": lambda t: t.replace("    runs-on: " + MACOS + "\n", "    runs-on: " + TRUSTED_LIGHT + "\n", 1),
    "unbound macOS pair": lambda t: t.replace(
        '[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]', 'true', 1),
    "build without the signed pair": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]",
        "    needs: [release-selection, pack-runtime, build-linux-musl, build-linux-gnu]", 1),
    "build before signing": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]",
        "    needs: [release-selection, pack-runtime, build-darwin, build-linux-musl, build-linux-gnu]", 1),
    "build from the unsigned pair": lambda t: t.replace(
        "          name: cw-release-darwin-signed-${{ github.run_id }}\n          path: .release-source/dist-darwin\n",
        "          name: cw-release-darwin-${{ github.run_id }}\n          path: .release-source/dist-darwin\n", 1),
    "build binds the unsigned digest": lambda t: t.replace(
        "DARWIN_SUMS_SHA256: ${{ needs.sign-darwin.outputs.darwin_sums_sha256 }}",
        "DARWIN_SUMS_SHA256: ${{ needs.build-darwin.outputs.darwin_sums_sha256 }}", 1),
    "signing without the macOS build": lambda t: t.replace(
        "    name: Sign and notarize the macOS cw pair\n    needs: [release-selection, build-darwin]\n",
        "    name: Sign and notarize the macOS cw pair\n    needs: [release-selection]\n", 1),
    "macOS signing after failure": lambda t: t.replace(
        "    name: Sign and notarize the macOS cw pair\n    needs: [release-selection, build-darwin]\n",
        "    name: Sign and notarize the macOS cw pair\n    needs: [release-selection, build-darwin]\n"
        "    if: always()\n", 1),
    "unbound unsigned pair": lambda t: t.replace(
        '[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$UNSIGNED_SUMS_SHA256" ]', "true", 1),
    "unpinned rcodesign": lambda t: t.replace(
        '"$RCODESIGN_X86_64_LINUX_SHA256" rcodesign.tar.gz', '"" rcodesign.tar.gz', 1),
    "macOS signing compiles": lambda t: t.replace(
        "          .rcodesign/rcodesign --version\n",
        "          .rcodesign/rcodesign --version\n          cargo install --locked apple-codesign\n", 1),
    "release key in macOS signing": lambda t: t.replace(
        '          scripts/ci/setup/fetch-openbao-macos-signing.sh "$macos_work/keys"\n',
        '          scripts/ci/setup/fetch-openbao-macos-signing.sh "$macos_work/keys"\n'
        '          ../scripts/ci/setup/fetch-openbao-release-signing-key.sh "$macos_work/key"\n', 1),
    "Apple keys in publication": lambda t: t.replace(
        "          export GH_MIRROR_TOKEN_FILE=\"$github_work/token\"\n",
        "          export GH_MIRROR_TOKEN_FILE=\"$github_work/token\"\n"
        "          ../scripts/ci/setup/fetch-openbao-macos-signing.sh \"$github_work/apple\"\n", 1),
    "Apple keys not shredded": lambda t: t.replace("          trap cleanup_macos_keys EXIT\n", "", 1),
    "release signs with the stand-in": lambda t: t.replace(
        '          scripts/ci/release/sign-macos-cw.sh .rcodesign/rcodesign "$macos_work/keys" \\\n',
        '          scripts/ci/tests/fixtures/rcodesign-stand-in.sh --install "$macos_work/stand-in"\n'
        '          scripts/ci/release/sign-macos-cw.sh "$macos_work/stand-in/bin/rcodesign" "$macos_work/keys" \\\n'
        '          # .rcodesign/rcodesign "$macos_work/keys"\n', 1),
    "Apple keys outlive signing": lambda t: t.replace("          cleanup_macos_keys\n          trap - EXIT\n",
                                                       "          trap - EXIT\n", 1),
    "signed pair not handed over": lambda t: t.replace(
        "          name: cw-release-darwin-signed-${{ github.run_id }}\n          path: dist-darwin-signed/\n",
        "          name: cw-release-darwin-${{ github.run_id }}\n          path: dist-darwin-signed/\n", 1),
    "helper signing without the helper build": lambda t: t.replace(
        "    needs: [release-selection, build-helper-darwin]\n", "    needs: [release-selection]\n", 1),
    "helper signing after failure": lambda t: t.replace(
        "    name: Sign and notarize the VZ helper\n    needs: [release-selection, build-helper-darwin]\n",
        "    name: Sign and notarize the VZ helper\n    needs: [release-selection, build-helper-darwin]\n"
        "    if: always()\n", 1),
    "helper signing without a helper": lambda t: t.replace(
        "      - name: Sign and notarize the helper\n        id: sign\n"
        "        if: needs.build-helper-darwin.outputs.unsigned_sha256 != ''\n",
        "      - name: Sign and notarize the helper\n        id: sign\n", 1),
    "unbound unsigned helper": lambda t: t.replace(
        '[ "$(sha256sum vz-runner-unsigned/codewire-vz-runner | cut -c1-64)" = "$UNSIGNED_SHA256" ]', "true", 1),
    "helper signed with the workflow's entitlements": lambda t: t.replace(
        "            .release-source/crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist",
        "            crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist", 1),
    "OIDC in helper build": lambda t: t.replace(
        "    needs: [release-selection]\n    runs-on: " + MACOS + "\n",
        "    needs: [release-selection]\n    runs-on: " + MACOS + "\n    enable-openid-connect: true\n", 1),
    "Apple keys in the helper build": lambda t: t.replace(
        '          scripts/ci/release/build-local-runtime.sh helper --output "$work"\n',
        '          scripts/ci/release/build-local-runtime.sh helper --output "$work"\n'
        '          scripts/ci/setup/fetch-openbao-macos-signing.sh "$work/keys"\n', 1),
    "helper built from the workflow's scripts": lambda t: t.replace(
        "      - name: Build the helper unless its recipe is signed\n        id: build\n"
        "        working-directory: .release-source\n",
        "      - name: Build the helper unless its recipe is signed\n        id: build\n", 1),
    "helper signing compiles": lambda t: t.replace(
        "          scripts/ci/release/sign-macos-helper.sh .rcodesign/rcodesign",
        "          swift build -c release --package-path .release-source/crates/codewire-local-vmm/macos-vz-runner\n"
        "          scripts/ci/release/sign-macos-helper.sh .rcodesign/rcodesign", 1),
    "macOS build without the signed helper": lambda t: t.replace(
        "    needs: [release-selection, build-runtime-linux, build-helper-darwin, sign-helper]\n",
        "    needs: [release-selection, build-runtime-linux, build-helper-darwin]\n", 1),
    "macOS build packs the unsigned helper": lambda t: t.replace(
        "          name: cw-release-vz-runner-signed-${{ github.run_id }}\n          path: .vz-runner-signed\n",
        "          name: cw-release-vz-runner-unsigned-${{ github.run_id }}\n          path: .vz-runner-signed\n", 1),
    "unbound signed helper": lambda t: t.replace(
        '[ "$(shasum -a 256 ../.vz-runner-signed/codewire-vz-runner | cut -c1-64)" = "$SIGNED_HELPER_SHA256" ]',
        "true", 1),
    "helper provenance from the workflow commit": lambda t: t.replace(
        '--set "source_sha=$SOURCE_SHA"', '--set "source_sha=$GITHUB_SHA"', 1),
    "signed helper not packed": lambda t: t.replace(
        '            helper=(--helper "$work/vz-runner-signed")\n', "", 1),
    "cw Apple keys not shredded": lambda t: nth_replace(t, "          trap cleanup_macos_keys EXIT\n", "", 2),
    "cw Apple keys outlive signing": lambda t: nth_replace(
        t, "          cleanup_macos_keys\n          trap - EXIT\n", "          trap - EXIT\n", 2),
    "unpinned cw rcodesign": lambda t: nth_replace(
        t, '"$RCODESIGN_X86_64_LINUX_SHA256" rcodesign.tar.gz', '"" rcodesign.tar.gz', 2),
    "cw signing compiles": lambda t: nth_replace(
        t, "          .rcodesign/rcodesign --version\n",
        "          .rcodesign/rcodesign --version\n          cargo install --locked apple-codesign\n", 2),
    "secret in build": lambda t: t.replace("          RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}\n"
                                           "          CW_RELEASE_SOURCE_SHA",
                                           "          RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}\n"
                                           "          CW_RELEASE_GPG_PRIVATE_KEY: ${{ secrets.CW_RELEASE_GPG_PRIVATE_KEY }}\n"
                                           "          CW_RELEASE_SOURCE_SHA", 1),
    "route inactive": lambda t: t.replace("CW_RELEASE_R2_ROUTE_ADMITTED: 'true'", "CW_RELEASE_R2_ROUTE_ADMITTED: 'false'"),
    "route unknown": lambda t: t.replace("CW_RELEASE_R2_ROUTE_ADMITTED: 'true'", "CW_RELEASE_R2_ROUTE_ADMITTED: 'unknown'"),
    "promotion default": lambda t: t.replace("        default: stable\n        options: [none, stable]",
                                             "        default: none\n        options: [none, stable]"),
    "publication default": lambda t: t.replace("        default: immutable\n        options: [none, immutable]",
                                               "        default: none\n        options: [none, immutable]"),
    "credential before admission": lambda t: t.replace(
        "          r2_work=\"${RUNNER_TEMP:?}/codewire-release-r2\"\n          mkdir -m 0700 \"$r2_work\"\n"
        "          ../scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh \"$r2_work/aws-credentials\"\n", "", 1)
    .replace("          set -euo pipefail\n          [ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ] || {",
             "          set -euo pipefail\n          ../scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh x\n"
             "          [ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ] || {", 1),
    "publish after failed build": lambda t: t.replace(
        "    needs: [release-selection, pack-runtime, build-release]",
        "    needs: [release-selection, pack-runtime, build-release]\n    if: always()", 1),
    "signing without build": lambda t: t.replace("    needs: [release-selection, pack-runtime, build-release]",
                                                 "    needs: [release-selection, pack-runtime]", 1),
    "OIDC in runtime build": lambda t: t.replace(
        "    needs: [release-selection]\n    runs-on: " + TRUSTED_LIGHT + "\n",
        "    needs: [release-selection]\n    runs-on: " + TRUSTED_LIGHT + "\n    enable-openid-connect: true\n", 1),
    "release skips uncached parts": lambda t: t.replace(
        'TMPDIR="$work/tmp" LOCAL_RUNTIME_JOB_CONTAINER',
        'TMPDIR="$work/tmp" LOCAL_RUNTIME_NO_BUILD=1 LOCAL_RUNTIME_JOB_CONTAINER', 1),
    "Linux side from the workflow commit": lambda t: t.replace(
        "          SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}\n        run: |\n"
        "          set -euo pipefail\n          if [ ! -f scripts/ci/release/build-local-runtime.sh ]",
        "          SOURCE_SHA: ${{ github.sha }}\n        run: |\n"
        "          set -euo pipefail\n          if [ ! -f scripts/ci/release/build-local-runtime.sh ]", 1),
    "Linux side cws of another version": lambda t: t.replace(
        '--version "$RELEASE_TAG" --output "$work/linux"', '--version v0.0.0 --output "$work/linux"', 1),
    "runtime from the workflow's scripts": lambda t: t.replace(
        "      - name: Build the Linux side\n        id: build\n        working-directory: .release-source\n",
        "      - name: Build the Linux side\n        id: build\n", 1),
    "macOS build without the Linux side": lambda t: t.replace(
        "    needs: [release-selection, build-runtime-linux, build-helper-darwin, sign-helper]",
        "    needs: [release-selection, build-helper-darwin, sign-helper]", 1),
    "unbound Linux side": lambda t: t.replace(
        '[ "$(shasum -a 256 ../.local-runtime-linux/runtime-linux.tar | cut -c1-64)" = "$LINUX_SHA256" ]',
        "true", 1),
    "records written by a build job": lambda t: t.replace(
        '          tar -C "$work" -cf "$work/runtime-linux.tar" linux\n',
        '          tar -C "$work" -cf "$work/runtime-linux.tar" linux\n'
        '          python3 scripts/ci/release/local_runtime_parts.py publish --dist x --records y --credentials z\n', 1),
    "records before their blobs": lambda t: move_step(
        t, "Record the runtime parts this release built", "Publish immutable R2 release objects"),
    "records without R2 publication": lambda t: t.replace(
        "        if: ${{ needs.release-selection.outputs.r2_publication == 'immutable' && needs.pack-runtime.outputs.records_sha256 != '' }}\n"
        "        working-directory: .release-source\n",
        "        if: ${{ needs.pack-runtime.outputs.records_sha256 != '' }}\n"
        "        working-directory: .release-source\n", 1),
    "unbound records": lambda t: t.replace('= "$RECORDS_SHA256" ]', "] || true", 1),
    "records on a retained retry": lambda t: t.replace('if [ "$CW_RELEASE_R2_STATE" = retained ]; then',
                                                       "if false; then", 1),
    "unsealed Linux target": lambda t: t.replace('"$RELEASE_TAG" x86_64-unknown-linux-musl .cw-linux',
                                                 '"$RELEASE_TAG" riscv64gc-unknown-linux-gnu .cw-linux', 1),
    "rustup on the runner": lambda t: t.replace(
        "          SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}\n"
        "        run: |\n          set -euo pipefail\n",
        "          SOURCE_SHA: ${{ needs.release-selection.outputs.source_sha }}\n"
        "        run: |\n          set -euo pipefail\n          rustup target add aarch64-unknown-linux-musl\n", 1),
    "one Mac target": lambda t: t.replace(f"CW_RELEASE_TARGETS='{DARWIN_TARGETS}'",
                                          "CW_RELEASE_TARGETS='aarch64-apple-darwin'", 1),
    "no macOS import": lambda t: t.replace("CW_RELEASE_IMPORT_DIR=dist-darwin", "CW_RELEASE_IMPORT_DIR=", 1),
    "Forgejo signing secret": lambda t: t.replace(
        "      - name: Sign release delivery\n        working-directory: .release-source\n",
        "      - name: Sign release delivery\n        working-directory: .release-source\n        env:\n"
        "          CW_RELEASE_GPG_PASSPHRASE: ${{ secrets.CW_RELEASE_GPG_PASSPHRASE }}\n", 1),
    "signing key in mirror step": lambda t: t.replace(
        "          export GH_MIRROR_TOKEN_FILE=\"$github_work/token\"\n",
        "          export GH_MIRROR_TOKEN_FILE=\"$github_work/token\"\n"
        "          ../scripts/ci/setup/fetch-openbao-release-signing-key.sh \"$github_work/key\"\n", 1),
    "signing key not shredded": lambda t: t.replace("          trap cleanup_signing EXIT\n", "", 1),
    "hidden verifier skipped": lambda t: t.replace(
        "          # included, unless asked; without this the verifier never uploads.\n"
        "          include-hidden-files: true\n",
        "          # included, unless asked; without this the verifier never uploads.\n", 1),
    "hidden Linux side skipped": lambda t: t.replace(
        "          path: .local-runtime/runtime-linux.tar\n          # The upload action skips hidden paths unless asked.\n"
        "          include-hidden-files: true\n",
        "          path: .local-runtime/runtime-linux.tar\n", 1),
    "hidden records skipped": lambda t: t.replace(
        "          path: .runtime-records/runtime-records.tar\n          include-hidden-files: true\n",
        "          path: .runtime-records/runtime-records.tar\n", 1),
    "signing key outlives signing": lambda t: t.replace("          cleanup_signing\n          trap - EXIT\n",
                                                         "          trap - EXIT\n", 1),
    "no built-in verification": lambda t: re.sub(
        r"      - name: Verify the signed delivery with cw's built-in verifier\n(?:        .*\n|\n(?=        ))*\n",
        "", t, count=1),
    "built-in verification after R2 publication": lambda t: move_step(
        t, "Verify the signed delivery with cw's built-in verifier", "Remove the R2 publisher credential"),
    "unbound verifier": lambda t: t.replace('= "$VERIFIER_SHA256" ]', "] || true", 1),
    "no published-asset check": lambda t: re.sub(
        r"      - name: Refuse to change an already-published release\n(?:        .*\n|\n(?=        ))*",
        "", t, count=1),
    "published-asset check after R2 publication": lambda t: move_step(
        t, "Refuse to change an already-published release", "Remove the R2 publisher credential"),
    "conditional published-asset check": lambda t: t.replace(
        "      - name: Refuse to change an already-published release\n",
        "      - name: Refuse to change an already-published release\n"
        "        if: ${{ needs.release-selection.outputs.r2_publication == 'immutable' }}\n", 1),
    "published-asset check without the comparison": lambda t: t.replace(
        "publish-cw-release.sh --check-unchanged", "publish-cw-release.sh --help", 1),
    "verifier compiled while signing": lambda t: t.replace(
        "          ../.release-verifier/verify-release-signatures",
        "          cargo run --locked -p codewire-cw-release --example verify-release-signatures --\n"
        "          ../.release-verifier/verify-release-signatures", 1),
    "conditional verification": lambda t: t.replace(
        "      - name: Verify the signed delivery with cw's built-in verifier\n",
        "      - name: Verify the signed delivery with cw's built-in verifier\n"
        "        if: ${{ needs.release-selection.outputs.r2_publication == 'immutable' }}\n", 1),
    "verification by another key": lambda t: t.replace(
        "            A38FF6BC6623FCA611A7A32B5EFBF0F4A5870815 dist/cw-release",
        "            0000000000000000000000000000000000000000 dist/cw-release", 1),
    "release target build cancels its run": lambda t: add_cancel(t, "build-linux-gnu"),
    "release macOS signing cancels its run": lambda t: add_cancel(t, "sign-darwin"),
}


def nth_replace(text, old, new, n):
    """Replace only the Nth occurrence of `old` (1-based)."""
    start = -1
    for _ in range(n):
        start = text.find(old, start + 1)
        if start < 0:
            return text
    return text[:start] + new + text[start + len(old):]


def in_job(text, job, old, new):
    """TEXT with OLD replaced by NEW once, inside JOB only."""
    start = text.index(f"\n  {job}:\n")
    end = re.compile(r"\n  [a-z0-9-]+:\n").search(text, start + 1)
    end = end.start() if end else len(text)
    return text[:start] + text[start:end].replace(old, new, 1) + text[end:]


def move_step(text, name, before):
    """Move step `name` (and its body) to just before step `before`."""
    start = text.index(f"      - name: {name}\n")
    end = text.index("\n      - ", start + 1) + 1
    step, text = text[start:end], text[:start] + text[end:]
    target = text.index(f"      - name: {before}\n")
    return text[:target] + step + text[target:]


def route_guard_cases(text):
    """Run the existing pre-read shell through its first credential-reader call."""
    probe = dict(steps(jobs(text)["package-release"]))["Reuse an already-published signed R2 release"]
    shell = probe.split("        run: |\n", 1)[1]
    lines = shell.splitlines()
    fetch = '../scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh "$r2_work/aws-credentials"'
    matches = [index for index, line in enumerate(lines) if line == "          " + fetch]
    if len(matches) != 1 or any(not line.startswith("          ") for line in lines[:matches[0] + 1]):
        raise ValueError("the exact pre-read route prefix was not found")
    prefix = "\n".join(line[10:] for line in lines[:matches[0] + 1]) + "\n"
    temp_root = ROOT / ".tmp"
    temp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cw-release-route-", dir=temp_root) as directory:
        work = Path(directory)
        source = work / ".release-source"
        source.mkdir(mode=0o700)
        home = work / "home"
        home.mkdir(mode=0o700)
        fake = work / "scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh"
        fake.parent.mkdir(parents=True)
        fake.write_text('#!/bin/sh\nset -eu\n[ "$#" = 1 ]\nprintf \'%s\\n\' "$1" > "$CREDENTIAL_CALL"\n')
        fake.chmod(0o700)
        cases = (("true", "true"), ("false", "false"), ("unknown", "unknown"),
                 ("empty", ""), ("unset", None))
        for name, value in cases:
            runner_temp = work / name
            runner_temp.mkdir(mode=0o700)
            witness = runner_temp / "credential-call"
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C",
                   "RUNNER_TEMP": str(runner_temp), "CREDENTIAL_CALL": str(witness)}
            if value is not None:
                env["CW_RELEASE_R2_ROUTE_ADMITTED"] = value
            result = subprocess.run(["/usr/bin/bash", "-c", prefix], cwd=source, env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=600, check=False)
            credential_dir = runner_temp / "codewire-release-r2"
            if value == "true":
                expected_call = str(credential_dir / "aws-credentials") + "\n"
                if (result.returncode != 0 or not witness.is_file()
                        or witness.read_text() != expected_call
                        or credential_dir.stat().st_uid != os.geteuid()
                        or credential_dir.stat().st_mode & 0o777 != 0o700):
                    raise RuntimeError("the admitted route did not reach exactly one private reader")
            elif result.returncode == 0 or witness.exists() or credential_dir.exists():
                raise RuntimeError(f"route {name} did not refuse before credential setup/read")
        return len(cases)


def check_dry_run(text, release):
    """main builds and verifies the four-target delivery the way a release does."""
    errors = []

    def need(condition, message):
        if not condition:
            errors.append(message)

    errors.extend(external_download_errors(text))
    blocks = jobs(text)
    need(list(blocks) == ["protected-main", "superseded", "build-runtime-linux", "build-helper-darwin",
                          "sign-helper", "pack-runtime", "build-darwin", "sign-darwin", "build-linux-musl",
                          "build-linux-gnu", "assemble"], "unexpected dry-run job set")
    # A wedged step must fail within its job's limit instead of holding the
    # one-at-a-time dry-run queue until the runner's 330-minute limit.
    for job, limit in (("build-runtime-linux", 75), ("build-helper-darwin", 30), ("sign-helper", 20),
                       ("pack-runtime", 30), ("build-darwin", 60), ("sign-darwin", 20),
                       ("build-linux-musl", 60), ("build-linux-gnu", 60), ("assemble", 30)):
        found = re.findall(r"^    timeout-minutes: ([0-9]+)$", blocks.get(job, ""), re.M)
        need(found == [str(limit)], f"dry-run job {job} lacks its {limit}-minute limit")
    # A newer main push cancels a superseded push run, queued or building
    # (#2893), and a newer schedule an older scheduled run. A dispatch never
    # cancels another run, and none of the three cancels or waits for another.
    try:
        groups = concurrency_by_event(text, DRY_RUN_CONCURRENCY)
    except (KeyError, ValueError, SyntaxError) as error:
        groups = {"error": str(error)}
    need(groups == DRY_RUN_CONCURRENCY,
         f"dry-run concurrency per event is {groups}, not {DRY_RUN_CONCURRENCY}")
    need(len({group for group, _ in groups.values()}) == 3,
         "a push, a schedule and a dispatch on main share a dry-run concurrency group")
    # The schedule (owner decision 2026-10-20): every four hours, building
    # only when a push path changed since the last successful scheduled run.
    need("  workflow_dispatch:\n" in text and "  schedule:\n    - cron: '45 */4 * * *'\n" in text,
         "the dry run is not dispatchable and scheduled every four hours")
    guard, runtime = blocks.get("protected-main", ""), blocks.get("build-runtime-linux", "")
    superseded = blocks.get("superseded", "")
    darwin, assemble = blocks.get("build-darwin", ""), blocks.get("assemble", "")
    pack = blocks.get("pack-runtime", "")
    helper_build, helper_sign = blocks.get("build-helper-darwin", ""), blocks.get("sign-helper", "")
    # The guard refuses every ref but main before it checks anything out, then
    # chooses, with main's own checkout, the commit every later job builds:
    # main's head, or the earlier main commit a dispatch names.
    guard_steps = steps(guard)
    need("    runs-on: " + UNTRUSTED_LIGHT + "\n" in guard and len(guard_steps) == 3
         and guard_steps[0][0] == "Refuse anything but protected main"
         and "[ \"$GITHUB_REF\" = 'refs/heads/main' ]" in guard_steps[0][1]
         and "[ \"$GITHUB_REF_NAME\" = 'main' ]" in guard_steps[0][1] and not re.search(r"^\s+if:", guard, re.M),
         "the dry run does not refuse every ref but main before the protected builders")
    need(len(guard_steps) == 3 and "actions-checkout" in guard_steps[1][0]
         and "          fetch-depth: 0\n" in guard_steps[1][1] and "ref:" not in guard_steps[1][1]
         and "        id: source\n" in guard_steps[2][1]
         and "          DISPATCH_SOURCE_SHA: ${{ github.event.inputs.source_sha }}\n" in guard_steps[2][1]
         and "        run: scripts/ci/select/dispatch-source.sh .gitea/workflows/cw-release-dry-run.yaml"
         in guard_steps[2][1]
         and "      source_sha: ${{ steps.source.outputs.source_sha }}\n" in guard,
         "the dry run does not choose its commit with the checked-in rule from main's own checkout")
    for job, body in blocks.items():
        if job == "protected-main":
            continue
        need(f"      SOURCE_SHA: {DRY_RUN_SOURCE}\n" in body
             and body.count("actions-checkout@") == body.count(f"          ref: {DRY_RUN_SOURCE}\n") > 0,
             f"dry-run job {job} does not check out exactly the commit the guard chose")
    need("    needs: [protected-main, superseded, build-runtime-linux, build-helper-darwin, sign-helper]\n"
         in pack, "the runtime pack does not wait for the main-only guard, the runtime's Linux side and the helper")
    # As in a release, the packed runtime is the one output the macOS pair
    # and each Linux cw wait for; they then build at the same time.
    for job, runner in (("build-darwin", MACOS), ("build-linux-musl", TRUSTED_LIGHT),
                        ("build-linux-gnu", TRUSTED_LIGHT)):
        need("    needs: [protected-main, pack-runtime]\n    if: needs.pack-runtime.outputs.superseded == 'false'\n"
             f"    runs-on: {runner}\n" in blocks.get(job, ""),
             f"dry-run job {job} does not build as soon as the runtime is packed")
        verify = dict(steps(blocks.get(job, ""))).get("Verify the received runtime is the packed runtime", "")
        need("          DOCUMENT_SHA256: ${{ needs.pack-runtime.outputs.document_sha256 }}\n" in verify
             and '.local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]' in verify
             and 'echo "CW_RELEASE_LOCAL_RUNTIME_DIR=$PWD/.local-runtime" >> "$GITHUB_ENV"' in verify,
             f"dry-run job {job} may embed a runtime other than the packed one")
    for job, target in LINUX_BUILDS:
        errors.extend(linux_build_errors(blocks.get(job, ""), f"dry-run job {job}", target, DRY_RUN_BUILD_ROLE,
                                         ".", "$DRY_RUN_VERSION", DRY_RUN_IN_JOB_RECOVERY))
        need(f"name: cw-dry-run-{target}-${{{{ github.run_id }}}}" in blocks.get(job, "")
             and f"name: cw-dry-run-{target}-${{{{ github.run_id }}}}" in assemble,
             f"dry-run job {job} does not build and hand over exactly the {target} cw")
    need("    needs: [protected-main, superseded]\n    if: needs.superseded.outputs.superseded == 'false'\n"
         "    runs-on: " + MACOS + "\n" in helper_build,
         "the helper build does not wait for the main-only guard on the protected Mac runner")
    need("    needs: [protected-main, superseded]\n" in runtime and "    runs-on: " + TRUSTED_LIGHT + "\n" in runtime,
         "the runtime's Linux side does not wait for the main-only guard on a protected runner")
    # Forgejo keeps every queued run. Only the newest queued commit needs the
    # protected builders and the Mac; the checked-in rule says when an older
    # one may skip without losing a check (test-dry-run-superseded.sh).
    skip_unless_newest = "    if: needs.superseded.outputs.superseded == 'false'"
    need(skip_unless_newest + "\n" in runtime and skip_unless_newest + "\n" in helper_build
         and skip_unless_newest + " && needs.build-runtime-linux.outputs.superseded == 'false'"
         " && needs.build-helper-darwin.outputs.superseded == 'false'\n" in pack,
         "a superseded dry run still reaches the protected builders or the Mac")
    # Main may move on while a run waits for a builder (the Mac waits behind a
    # release or another run): each builder job decides again, by the same
    # checked-in rule, before anything else, every later step follows that
    # decision, and so do the jobs after it.
    recheck = ("      - name: Skip a superseded commit\n        id: superseded\n        env:\n"
               "          BEFORE: ${{ github.event.before }}\n"
               '        run: scripts/ci/release/dry-run-superseded.sh "$SOURCE_SHA" "$BEFORE"')
    gate = re.compile(r"^        if: steps\.superseded\.outputs\.superseded == 'false'( && |$)", re.M)
    for job in ("build-runtime-linux", "build-helper-darwin", "pack-runtime", "build-darwin", "build-linux-musl",
                "build-linux-gnu", "assemble"):
        named = steps(blocks.get(job, ""))
        need(len(named) > 2 and "actions-checkout" in named[0][0] and named[1][1].startswith(recheck),
             f"dry-run job {job} does not decide supersession again before its first step")
        for name, body in named[2:]:
            need(gate.search(body) is not None, f"dry-run job {job} step {name!r} runs for a superseded commit")
    for job in ("build-runtime-linux", "build-helper-darwin", "pack-runtime", "build-darwin", "build-linux-musl",
                "build-linux-gnu"):
        need("      superseded: ${{ steps.superseded.outputs.superseded }}\n" in blocks.get(job, ""),
             f"dry-run job {job} does not hand its supersession decision on")
    need("    if: needs.build-darwin.outputs.superseded == 'false'\n" in blocks.get("sign-darwin", ""),
         "the dry-run macOS signing runs after the Mac found the commit superseded")
    need("    if: needs.build-helper-darwin.outputs.superseded == 'false'\n" in helper_sign,
         "the dry-run helper signing runs after the helper build found the commit superseded")
    need("    if: needs.build-linux-musl.outputs.superseded == 'false'"
         " && needs.build-linux-gnu.outputs.superseded == 'false'\n" in assemble,
         "the dry-run assembly runs after a Linux cw build found the commit superseded")
    errors.extend(dry_run_path_errors(text))
    need("    needs: [protected-main]\n    runs-on: " + UNTRUSTED_LIGHT + "\n" in superseded
         and not re.search(r"^    if:", superseded, re.M)
         and "      superseded: ${{ steps.canonical.outputs.superseded }}\n" in superseded
         and "          BEFORE: ${{ github.event.before }}\n" in superseded
         and 'run: scripts/ci/release/dry-run-superseded.sh "$SOURCE_SHA" "$BEFORE"' in superseded,
         "the dry run does not decide supersession with the checked-in rule after the main-only guard")
    # Before supersession, the checked-in rule decides whether the run builds
    # at all: a push to main only while main-push-switch.sh says so (owner
    # decision 2026-10-20), a schedule only when a push path changed since the
    # last successful scheduled run. A run that builds nothing skips the
    # supersession step, so every builder job skips.
    decided = steps(superseded)
    need([name for name, _ in decided][1:] == [
            "Find the last successful scheduled dry run", "Decide whether this run builds",
            "Skip a superseded commit"],
         "the dry run does not find the schedule baseline, then decide whether it builds, before supersession")
    decided = dict(decided)
    need("        id: schedule-baseline\n        if: github.event_name == 'schedule'\n        env:\n"
         "          GITEA_TOKEN: ${{ github.token }}\n        run: python3 -I -B "
         "scripts/ci/select/last-scheduled-run.py --workflow cw-release-dry-run.yaml --github-output"
         in decided.get("Find the last successful scheduled dry run", "")
         and text.count("${{ github.token }}") == 1,
         "the dry run reads its last scheduled run other than once, on a schedule, with the job token")
    need("        id: deferral\n        env:\n"
         "          SCHEDULE_BASELINE_SHA: ${{ steps.schedule-baseline.outputs.schedule_baseline }}\n"
         '        run: scripts/ci/release/dry-run-deferral.sh "$SOURCE_SHA"'
         in decided.get("Decide whether this run builds", ""),
         "the dry run does not decide whether it builds with the checked-in rule and the schedule baseline")
    need("        id: canonical\n        if: steps.deferral.outputs.build == 'true'\n"
         in decided.get("Skip a superseded commit", ""),
         "a deferred or unchanged dry run still reaches the builders")
    # The runtime is built when one of its inputs changed, from cached slow
    # parts only; otherwise each side checks its slow parts are cached.
    select = dict(steps(runtime)).get("Select the local runtime check", "")
    need("          mode=full\n" in select
         and "python3 scripts/ci/release/local_runtime_parts.py runtime-mode" in select,
         "the dry run does not select the runtime build from the runtime's inputs")
    linux_build = dict(steps(runtime)).get("Build the Linux side from cached parts", "")
    mac_build = dict(steps(pack)).get("Build the local VM runtime from cached parts", "")
    need("LOCAL_RUNTIME_NO_BUILD=1" in linux_build and "LOCAL_RUNTIME_NO_BUILD=1" in mac_build,
         "the dry run builds slow runtime parts")
    need('build-local-runtime.sh linux --source-sha "$SOURCE_SHA" \\\n'
         '            --version "$DRY_RUN_VERSION" --output "$work/linux"' in linux_build,
         "the dry-run Linux side does not build its cws from this commit and the dry-run version")
    need("build-local-runtime.sh linux --check" in runtime and "build-local-runtime.sh macos --check" in pack,
         "the dry run does not check the slow parts are cached")
    need('[ "$(shasum -a 256 .local-runtime-linux/runtime-linux.tar | cut -c1-64)" = "$LINUX_SHA256" ]' in mac_build,
         "the dry-run macOS build does not bind the received Linux side")
    need('grep -q "^cw-release: local runtime document_sha256=$DOCUMENT_SHA256 " <<<"$verified"' in assemble
         and "[ ! -e dist/cw-release/delivery/local-runtime ]" in assemble
         and '[ "$(sha256sum dist-darwin/local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]'
         in assemble and "      document_sha256: ${{ steps.runtime.outputs.document_sha256 }}\n" in pack
         and 'cp -R "$work/macos/runtime/." .local-runtime/' in mac_build
         and "          name: cw-dry-run-runtime-${{ github.run_id }}\n          path: .local-runtime/\n" in pack,
         "the dry run does not check the delivery embeds exactly the runtime it built")
    # No job holds a credential but the two Linux builds' login for the
    # trusted builder's client certificate (#3119).
    # The push paths name the builder's scripts, which hold no capability.
    without_builder_login = re.sub(r"^      - '[^'\n]*'\n", "", text.replace(builder_login(DRY_RUN_BUILD_ROLE), "", 2),
                                   flags=re.M)
    for capability in CAPABILITIES:
        need(capability not in without_builder_login, f"dry run holds capability {capability}")
    need(text.count("OPENBAO_ROLE:") == 2 and text.count(builder_login(DRY_RUN_BUILD_ROLE)) == 2,
         "the dry run holds an OIDC role other than the Linux builds' builder login")
    need("    runs-on: " + MACOS + "\n" in darwin and "    runs-on: " + MACOS + "\n" in pack,
         "the dry-run macOS build is not on the protected Mac runner")
    need(f"CW_RELEASE_TARGETS='{DARWIN_TARGETS}'" in darwin, "the dry-run macOS build is not the Mac pair")
    need("    needs: [protected-main, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]\n" in assemble
         and "    runs-on: " + TRUSTED_LIGHT + "\n" in assemble,
         "the dry-run assembly does not follow the macOS signing job and both Linux cws on a protected runner")
    linux_received = dict(steps(assemble)).get("Verify the received Linux cws are the built cws", "")
    need("          MUSL_SHA256: ${{ needs.build-linux-musl.outputs.cw_sha256 }}\n" in linux_received
         and "          GNU_SHA256: ${{ needs.build-linux-gnu.outputs.cw_sha256 }}\n" in linux_received
         and '[ "$(sha256sum "dist-linux/$asset" | cut -c1-64)" = "${pair#*=}" ]' in linux_received,
         "the dry-run assembly does not bind each received Linux cw")
    # The release's macOS signing job, with the rcodesign stand-in in place of
    # Apple: the same pinned install and signer, never a key or a signature.
    sign = blocks.get("sign-darwin", "")
    need([job for job, body in blocks.items() if any(token in body for token in MACOS_SIGNING)]
         == ["sign-helper", "sign-darwin"], "the dry run signs outside its macOS signing jobs")
    # The release's helper jobs with the stand-in. The macOS build packs only
    # a helper a release signed: never the dry run's own (#1905).
    need('scripts/ci/release/build-local-runtime.sh helper --output "$work"' in helper_build
         and "name: cw-dry-run-vz-runner-unsigned-${{ github.run_id }}" in helper_build
         and "unsigned_sha256" in helper_build,
         "the dry run does not build and hand over the helper as a release does")
    need("    needs: [protected-main, build-helper-darwin]\n"
         "    if: needs.build-helper-darwin.outputs.superseded == 'false'\n    runs-on: " + TRUSTED_LIGHT + "\n" in helper_sign
         and "enable-openid-connect" not in helper_sign,
         "the dry-run helper signing does not follow the helper build on a protected runner without OIDC")
    need("UNSIGNED_SHA256: ${{ needs.build-helper-darwin.outputs.unsigned_sha256 }}" in helper_sign
         and '[ "$(sha256sum vz-runner-unsigned/codewire-vz-runner | cut -c1-64)" = "$UNSIGNED_SHA256" ]'
         in helper_sign, "the dry-run helper signing does not bind the built helper")
    helper_stand_in = dict(steps(helper_sign)).get("Sign the helper with the rcodesign stand-in", "")
    need('scripts/ci/tests/fixtures/rcodesign-stand-in.sh --install "$stand_in"' in helper_stand_in
         and 'scripts/ci/release/sign-macos-helper.sh "$stand_in/bin/rcodesign" "$stand_in/keys"' in helper_stand_in
         and ".rcodesign/rcodesign \"" not in helper_stand_in
         and "'sign verify print-signature-info encode-app-store-connect-api-key notary-submit ' ]"
         in helper_stand_in, "the dry run does not run the helper signer against the stand-in and check its calls")
    need("vz-runner-signed" not in pack and "--helper" not in pack and "vz-runner" not in darwin
         and "vz-runner" not in assemble,
         "the dry run packs a helper no release signed")
    release_jobs = jobs(release)
    release_header, header = release.split("\njobs:\n", 1)[0], text.split("\njobs:\n", 1)[0]
    pins = [re.findall(r"^  (RCODESIGN_[A-Z0-9_]+: \S+)$", part, re.M) for part in (release_header, header)]
    need(len(pins[0]) == 2 and pins[0] == pins[1], "the dry run does not pin the release's rcodesign")
    need("    needs: [protected-main, build-darwin]\n    if: needs.build-darwin.outputs.superseded == 'false'\n"
         "    runs-on: " + TRUSTED_LIGHT + "\n" in sign,
         "the dry-run macOS signing does not follow the macOS build on a protected runner")
    need(dict(steps(sign)).get("Install rcodesign (pinned)")
         == dict(steps(release_jobs.get("sign-darwin", ""))).get("Install rcodesign (pinned)", "")
         and dict(steps(helper_sign)).get("Install rcodesign (pinned)")
         == dict(steps(release_jobs.get("sign-helper", ""))).get("Install rcodesign (pinned)", ""),
         "the dry run does not install rcodesign exactly as the release does")
    stand_in = dict(steps(sign)).get("Sign the macOS pair with the rcodesign stand-in", "")
    need('scripts/ci/tests/fixtures/rcodesign-stand-in.sh --install "$stand_in"' in stand_in
         and 'scripts/ci/release/sign-macos-cw.sh "$stand_in/bin/rcodesign" "$stand_in/keys"' in stand_in
         and ".rcodesign/rcodesign \"" not in stand_in
         and "'sign sign verify print-signature-info verify print-signature-info encode-app-store-connect-api-key "
             "notary-submit ' ]" in stand_in,
         "the dry run does not run the signer against the stand-in and check its calls")
    need("UNSIGNED_SUMS_SHA256: ${{ needs.build-darwin.outputs.darwin_sums_sha256 }}" in sign
         and '[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$UNSIGNED_SUMS_SHA256" ]' in sign
         and "name: cw-dry-run-darwin-signed-${{ github.run_id }}" in sign,
         "the dry-run macOS signing does not bind the built pair and hand over its own")
    need("name: cw-dry-run-darwin-signed-${{ github.run_id }}" in assemble
         and "name: cw-dry-run-darwin-${{ github.run_id }}" not in assemble
         and "DARWIN_SUMS_SHA256: ${{ needs.sign-darwin.outputs.darwin_sums_sha256 }}" in assemble,
         "the dry-run assembly does not package exactly the stand-in-signed pair")
    need("CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin" in assemble and "cargo zigbuild" not in assemble,
         "the dry-run assembly does not prepare exactly the four imported cws")
    need('[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]' in assemble,
         "the dry-run assembly does not bind the received macOS pair")
    need('verified targets=4 version=$DRY_RUN_VERSION runtime_equal=true signed=false' in assemble,
         "the dry run does not verify the four-target delivery")
    need(not runner_targets_sealed(text), "a dry-run Linux runner job needs a Rust target or rustup change its "
         f"sealed toolchain lacks: {runner_targets_sealed(text)}")
    need("    branches: [main]" in text and "pull_request" not in text,
         "the dry run is not limited to main")
    errors.extend(run_cancel_errors(text, "cw-release-dry-run.yaml"))
    return errors


# The dry run gates every build step on supersession; so does its injected cancel.
DRY_RUN_CANCEL_IF = "steps.superseded.outputs.superseded == 'false' && failure()"
DRY_RUN_MUTATIONS = {
    "Linux side without a job limit": lambda t: t.replace("    timeout-minutes: 75\n", "", 1),
    "dry-run Linux side from another commit": lambda t: t.replace(
        'linux --source-sha "$SOURCE_SHA"', 'linux --source-sha "$BEFORE"', 1),
    "dry-run Linux side with another version": lambda t: t.replace(
        '--version "$DRY_RUN_VERSION" --output "$work/linux"', '--version v9.9.9 --output "$work/linux"', 1),
    "macOS build without a job limit": lambda t: t.replace("    timeout-minutes: 60\n", "", 1),
    "assembly at the runner limit": lambda t: in_job(t, "assemble", "    timeout-minutes: 30\n",
                                                     "    timeout-minutes: 330\n"),
    "dry run without cargo network bounds": lambda t: t.replace("  CARGO_HTTP_TIMEOUT: '20'\n", "", 1),
    "dry run with an unbounded protoc download": lambda t: t.replace(
        "          scripts/ci/release/fetch-pinned.sh \"https://github.com/protocolbuffers",
        "          curl -fsSL -o \"$HOME/protoc.zip\" \"https://github.com/protocolbuffers", 1),
    "dry run a dispatch can cancel": lambda t: re.sub(
        r"^  cancel-in-progress: .*\n", "  cancel-in-progress: true\n", t, count=1, flags=re.M),
    "dry run a newer push never cancels": lambda t: re.sub(
        r"^  cancel-in-progress: .*\n", "  cancel-in-progress: ${{ github.event_name == 'schedule' }}\n", t,
        count=1, flags=re.M),
    "dry run a newer schedule never cancels": lambda t: re.sub(
        r"^  cancel-in-progress: .*\n", "  cancel-in-progress: ${{ github.event_name == 'push' }}\n", t,
        count=1, flags=re.M),
    "dry run without a concurrency group": lambda t: re.sub(r"^  group: .*\n", "", t, count=1, flags=re.M),
    "schedule shares the push group": lambda t: t.replace(
        "github.event_name == 'schedule' && '-schedule' || ", "", 1),
    "dispatch shares the push group": lambda t: t.replace(
        "github.event_name == 'workflow_dispatch' && '-dispatch' || ", "", 1),
    "no schedule": lambda t: t.replace("  schedule:\n    - cron: '45 */4 * * *'\n", "", 1),
    "deferred push still builds": lambda t: in_job(
        t, "superseded", "        if: steps.deferral.outputs.build == 'true'\n", ""),
    "deferral without the checked-in rule": lambda t: t.replace(
        'run: scripts/ci/release/dry-run-deferral.sh "$SOURCE_SHA"', 'run: echo build=true >> "$GITHUB_OUTPUT"', 1),
    "schedule baseline read on every event": lambda t: t.replace(
        "        id: schedule-baseline\n        if: github.event_name == 'schedule'\n",
        "        id: schedule-baseline\n", 1),
    "schedule baseline of another workflow": lambda t: t.replace(
        "last-scheduled-run.py --workflow cw-release-dry-run.yaml", "last-scheduled-run.py --workflow ci.yaml", 1),
    "deferral without the schedule baseline": lambda t: t.replace(
        "          SCHEDULE_BASELINE_SHA: ${{ steps.schedule-baseline.outputs.schedule_baseline }}\n", "", 1),
    "job token beyond the schedule baseline": lambda t: in_job(
        t, "assemble", "    runs-on: " + TRUSTED_LIGHT + "\n",
        "    runs-on: " + TRUSTED_LIGHT + "\n    env:\n      GITEA_TOKEN: ${{ github.token }}\n"),
    "pull requests": lambda t: t.replace("on:\n  push:", "on:\n  pull_request:\n  push:", 1),
    "secret": lambda t: t.replace("    runs-on: " + TRUSTED_LIGHT + "\n", "    runs-on: " + TRUSTED_LIGHT + "\n    env:\n"
                                  "      KEY: ${{ secrets.CW_RELEASE_GPG_PRIVATE_KEY }}\n", 1),
    "pool Mac": lambda t: t.replace("    runs-on: " + MACOS + "\n", "    runs-on: " + HEAVY + "\n", 1),
    "signer in the dry-run assembly": lambda t: t.replace(
        "          CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin \\\n",
        "          CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin \\\n"
        "            CW_SIGN=scripts/ci/release/sign-macos-cw.sh \\\n", 1),
    "no verification": lambda t: t.replace("runtime_equal=true signed=false", "runtime_equal=true", 1),
    "no main guard": lambda t: t.replace("          [ \"$GITHUB_REF\" = 'refs/heads/main' ]\n", "", 1),
    "guard skipped": lambda t: t.replace("    name: Refuse anything but protected main\n    runs-on: " + UNTRUSTED_LIGHT + "\n",
                                         "    name: Refuse anything but protected main\n    runs-on: " + UNTRUSTED_LIGHT + "\n"
                                         "    if: github.event_name == 'push'\n", 1),
    "Mac build without the guard": lambda t: t.replace(
        "    needs: [protected-main, superseded, build-runtime-linux, build-helper-darwin, sign-helper]\n",
        "    needs: [superseded, build-runtime-linux, build-helper-darwin, sign-helper]\n", 1),
    "Mac build without the helper jobs": lambda t: t.replace(
        "    needs: [protected-main, superseded, build-runtime-linux, build-helper-darwin, sign-helper]\n",
        "    needs: [protected-main, superseded, build-runtime-linux]\n", 1),
    "helper build without the guard": lambda t: t.replace(
        "    name: Build the VZ helper for signing\n    needs: [protected-main, superseded]\n",
        "    name: Build the VZ helper for signing\n    needs: [superseded]\n", 1),
    "helper build of a superseded commit": lambda t: in_job(
        t, "build-helper-darwin", "    if: needs.superseded.outputs.superseded == 'false'\n", ""),
    "helper build does not decide again": lambda t: in_job(
        t, "build-helper-darwin", "        id: superseded\n", "        id: decided\n"),
    "helper builds for a superseded commit": lambda t: in_job(
        t, "build-helper-darwin", "        id: build\n        if: steps.superseded.outputs.superseded == 'false'\n",
        "        id: build\n"),
    "helper hides its decision": lambda t: in_job(
        t, "build-helper-darwin", "      superseded: ${{ steps.superseded.outputs.superseded }}\n", ""),
    "helper signing ignores the helper's decision": lambda t: t.replace(
        "    if: needs.build-helper-darwin.outputs.superseded == 'false'\n    runs-on: " + TRUSTED_LIGHT + "\n",
        "    runs-on: " + TRUSTED_LIGHT + "\n", 1),
    "Mac ignores the helper's decision": lambda t: in_job(
        t, "pack-runtime", " && needs.build-helper-darwin.outputs.superseded == 'false'", ""),
    "dry run packs its stand-in-signed helper": lambda t: t.replace(
        "          LOCAL_RUNTIME_NO_BUILD=1 scripts/ci/release/build-local-runtime.sh macos --linux \"$work/linux\" \\\n",
        "          LOCAL_RUNTIME_NO_BUILD=1 scripts/ci/release/build-local-runtime.sh macos --linux \"$work/linux\" \\\n"
        "            --helper \"$PWD/vz-runner-signed\" \\\n", 1),
    "dry-run helper signing with the real rcodesign": lambda t: t.replace(
        'scripts/ci/release/sign-macos-helper.sh "$stand_in/bin/rcodesign" "$stand_in/keys"',
        'scripts/ci/release/sign-macos-helper.sh .rcodesign/rcodesign "$stand_in/keys"', 1),
    "dry-run helper signing with OIDC": lambda t: t.replace(
        "    if: needs.build-helper-darwin.outputs.superseded == 'false'\n    runs-on: " + TRUSTED_LIGHT + "\n",
        "    if: needs.build-helper-darwin.outputs.superseded == 'false'\n    runs-on: " + TRUSTED_LIGHT + "\n"
        "    enable-openid-connect: true\n", 1),
    "unbound dry-run unsigned helper": lambda t: t.replace(
        '[ "$(sha256sum vz-runner-unsigned/codewire-vz-runner | cut -c1-64)" = "$UNSIGNED_SHA256" ]', "true", 1),
    "dry-run cw stand-in calls unchecked": lambda t: re.sub(
        r"          # Two signatures, each verified and read, then one notarization\.\n.*?\n.*?\n", "", t, count=1,
        flags=re.S),
    "dry-run cw rcodesign installed differently": lambda t: nth_replace(
        t, "          .rcodesign/rcodesign --version\n", "", 2),
    "runtime build without the guard": lambda t: t.replace(
        "    needs: [protected-main, superseded]\n", "    needs: [superseded]\n", 1),
    "Mac builds a superseded commit": lambda t: in_job(
        t, "pack-runtime", "    if: needs.superseded.outputs.superseded == 'false' && "
        "needs.build-runtime-linux.outputs.superseded == 'false' && "
        "needs.build-helper-darwin.outputs.superseded == 'false'\n", ""),
    "Mac ignores the Linux side's decision": lambda t: in_job(
        t, "pack-runtime", " && needs.build-runtime-linux.outputs.superseded == 'false'", ""),
    "macOS pair ignores the pack's decision": lambda t: in_job(
        t, "build-darwin", "    if: needs.pack-runtime.outputs.superseded == 'false'\n", ""),
    "Linux cw ignores the pack's decision": lambda t: in_job(
        t, "build-linux-gnu", "    if: needs.pack-runtime.outputs.superseded == 'false'\n", ""),
    "dry-run Linux cw under the cli-release role": lambda t: in_job(
        t, "build-linux-gnu", f"      OPENBAO_ROLE: {DRY_RUN_BUILD_ROLE}\n", f"      OPENBAO_ROLE: {RELEASE_BUILD_ROLE}\n"),
    "dry-run Linux cw built in the job by default": lambda t: in_job(
        t, "build-linux-musl", DRY_RUN_IN_JOB_RECOVERY, "      CODEWIRE_IN_JOB_BUILD: '1'\n"),
    "dry-run assembly logs in to the builder": lambda t: in_job(
        t, "assemble", "    runs-on: " + TRUSTED_LIGHT + "\n",
        "    runs-on: " + TRUSTED_LIGHT + "\n" + builder_login(DRY_RUN_BUILD_ROLE).replace("    timeout-minutes: 60\n", "")),
    "Linux cw does not decide again": lambda t: in_job(t, "build-linux-musl", "        id: superseded\n",
                                                       "        id: decided\n"),
    "Linux cw built for a superseded commit": lambda t: in_job(
        t, "build-linux-gnu", "      - name: Build the cw\n        id: build\n"
        "        if: steps.superseded.outputs.superseded == 'false'\n",
        "      - name: Build the cw\n        id: build\n"),
    "assembly ignores a Linux cw's decision": lambda t: in_job(
        t, "assemble", " && needs.build-linux-gnu.outputs.superseded == 'false'", ""),
    "dry-run macOS pair waits for the Linux cws": lambda t: in_job(
        t, "build-darwin", "    needs: [protected-main, pack-runtime]\n",
        "    needs: [protected-main, pack-runtime, build-linux-musl]\n"),
    "dry-run Linux cw from an unbound runtime": lambda t: in_job(
        t, "build-linux-musl", '[ "$(sha256sum .local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]',
        "true"),
    "dry-run Linux cw unbound": lambda t: in_job(
        t, "assemble", '[ "$(sha256sum "dist-linux/$asset" | cut -c1-64)" = "${pair#*=}" ]', "true"),
    "dry-run assembly compiles": lambda t: t.replace(
        "          CW_RELEASE_TARGETS=none CW_RELEASE_IMPORT_DIR=dist-darwin \\\n",
        f"          CW_RELEASE_BUILD_CMD='cargo zigbuild' CW_RELEASE_TARGETS='{LINUX_TARGETS}' "
        "CW_RELEASE_IMPORT_DIR=dist-darwin \\\n", 1),
    "Mac does not decide again": lambda t: in_job(t, "build-darwin", "        id: superseded\n",
                                                  "        id: decided\n"),
    "Mac decides again without its push's own changes": lambda t: in_job(
        t, "build-darwin", "          BEFORE: ${{ github.event.before }}\n", "          BEFORE: ''\n"),
    "Mac builds the pair for a superseded commit": lambda t: in_job(
        t, "build-darwin", "      - name: Build the macOS pair\n        id: build\n"
        "        if: steps.superseded.outputs.superseded == 'false'\n",
        "      - name: Build the macOS pair\n        id: build\n"),
    "Linux side does not decide again": lambda t: in_job(
        t, "build-runtime-linux", '        run: scripts/ci/release/dry-run-superseded.sh "$SOURCE_SHA" "$BEFORE"\n',
        "        run: echo superseded=false >> \"$GITHUB_OUTPUT\"\n"),
    "Linux side hides its decision": lambda t: in_job(
        t, "build-runtime-linux", "      superseded: ${{ steps.superseded.outputs.superseded }}\n", ""),
    "Linux side selects for a superseded commit": lambda t: in_job(
        t, "build-runtime-linux", "        id: select\n        if: steps.superseded.outputs.superseded == 'false'\n",
        "        id: select\n"),
    "assembly does not decide again": lambda t: in_job(
        t, "assemble", "      - name: Skip a superseded commit\n", "      - name: Skip nothing\n"),
    "assembly packages a superseded commit": lambda t: in_job(
        t, "assemble", "      - name: Package and verify the unsigned delivery\n"
        "        if: steps.superseded.outputs.superseded == 'false'\n",
        "      - name: Package and verify the unsigned delivery\n"),
    "signing ignores the Mac's decision": lambda t: t.replace(
        "    if: needs.build-darwin.outputs.superseded == 'false'\n", "", 1),
    "a cw crate starts no dry run": lambda t: t.replace("      - 'crates/codewire-local-vmm/**'\n", "", 1),
    "a server crate starts a dry run": lambda t: t.replace(
        "      - 'crates/codewire-access/**'\n",
        "      - 'crates/codewire-access/**'\n      - 'crates/codewire-dashboard-web/**'\n", 1),
    "cw's embedded release key starts no dry run": lambda t: t.replace(
        "      - 'apps/cli/GPG_PUBLIC_KEY.asc'\n", "", 1),
    "a runtime recipe starts no dry run": lambda t: t.replace(
        "      - 'scripts/dev/macos-git-tool.py'\n", "", 1),
    "every crate starts a dry run": lambda t: re.sub(
        r"(      - 'crates/[^']+'\n)+", "      - 'crates/**'\n", t, count=1),
    "runtime builds a superseded commit": lambda t: t.replace(
        "    if: needs.superseded.outputs.superseded == 'false'\n    runs-on: " + TRUSTED_LIGHT + "\n",
        "    runs-on: " + TRUSTED_LIGHT + "\n", 1),
    "supersession before the guard": lambda t: t.replace(
        "    name: Skip a superseded commit\n    needs: [protected-main]\n",
        "    name: Skip a superseded commit\n", 1),
    "supersession without the checked-in rule": lambda t: t.replace(
        'run: scripts/ci/release/dry-run-superseded.sh "$SOURCE_SHA" "$BEFORE"',
        "run: echo superseded=true >> \"$GITHUB_OUTPUT\"", 1),
    "guard checks out before it refuses other refs": lambda t: in_job(
        t, "protected-main", "    steps:\n      - name: Refuse anything but protected main\n",
        "    steps:\n      - uses: " + re.search(r"noel/actions-checkout@[0-9a-f]{40}", t).group(0) + "\n\n"
        "      - name: Refuse anything but protected main\n"),
    "guard chooses from the dispatched source's own checkout": lambda t: in_job(
        t, "protected-main", "          fetch-depth: 0\n",
        "          ref: ${{ github.event.inputs.source_sha }}\n          fetch-depth: 0\n"),
    "guard takes the dispatched source unchecked": lambda t: t.replace(
        "        run: scripts/ci/select/dispatch-source.sh .gitea/workflows/cw-release-dry-run.yaml",
        '        run: echo "source_sha=$DISPATCH_SOURCE_SHA" >> "$GITHUB_OUTPUT"', 1),
    "dry-run Linux cw builds main's head": lambda t: in_job(
        t, "build-linux-musl", f"          ref: {DRY_RUN_SOURCE}\n", ""),
    "dry-run signing checks out main's head": lambda t: in_job(
        t, "sign-darwin", f"        with:\n          ref: {DRY_RUN_SOURCE}\n", ""),
    "dry-run in-job recovery keyed to main's head": lambda t: in_job(
        t, "build-linux-gnu", DRY_RUN_IN_JOB_RECOVERY, IN_JOB_RECOVERY),
    "supersession without the push's own changes": lambda t: t.replace(
        "          BEFORE: ${{ github.event.before }}\n        run: scripts/ci/release/dry-run-superseded.sh",
        "          BEFORE: ''\n        run: scripts/ci/release/dry-run-superseded.sh", 1),
    "Linux dry run builds slow parts": lambda t: t.replace(
        'TMPDIR="$work/tmp" LOCAL_RUNTIME_NO_BUILD=1 ', 'TMPDIR="$work/tmp" ', 1),
    "Mac dry run builds slow parts": lambda t: t.replace(
        "          LOCAL_RUNTIME_NO_BUILD=1 scripts/ci/release/build-local-runtime.sh macos",
        "          scripts/ci/release/build-local-runtime.sh macos", 1),
    "runtime never selected": lambda t: t.replace("          mode=full\n", "          mode=parts\n", 1),
    "no parts check": lambda t: t.replace("build-local-runtime.sh macos --check", "true", 1),
    "unbound dry-run Linux side": lambda t: t.replace('= "$LINUX_SHA256" ]', "] || true", 1),
    "dry-run rustup on the runner": lambda t: t.replace(
        "      - name: Build the Linux side from cached parts\n        id: build\n"
        "        if: steps.superseded.outputs.superseded == 'false' && steps.select.outputs.mode == 'full'\n"
        "        run: |\n          set -euo pipefail\n",
        "      - name: Build the Linux side from cached parts\n        id: build\n"
        "        if: steps.superseded.outputs.superseded == 'false' && steps.select.outputs.mode == 'full'\n"
        "        run: |\n          set -euo pipefail\n"
        "          rustup target add aarch64-unknown-linux-musl\n", 1),
    "dry-run assembly from the unsigned pair": lambda t: t.replace(
        "          name: cw-dry-run-darwin-signed-${{ github.run_id }}\n          path: dist-darwin\n",
        "          name: cw-dry-run-darwin-${{ github.run_id }}\n          path: dist-darwin\n", 1),
    "dry-run assembly skips signing": lambda t: t.replace(
        "    needs: [protected-main, pack-runtime, sign-darwin, build-linux-musl, build-linux-gnu]\n",
        "    needs: [protected-main, pack-runtime, build-linux-musl, build-linux-gnu]\n", 1),
    "dry-run assembly binds the unsigned digest": lambda t: t.replace(
        "DARWIN_SUMS_SHA256: ${{ needs.sign-darwin.outputs.darwin_sums_sha256 }}",
        "DARWIN_SUMS_SHA256: ${{ needs.build-darwin.outputs.darwin_sums_sha256 }}", 1),
    "dry-run signing with OIDC": lambda t: t.replace(
        "    name: Sign the macOS pair with the rcodesign stand-in (never signs)\n"
        "    needs: [protected-main, build-darwin]\n    if: needs.build-darwin.outputs.superseded == 'false'\n"
        "    runs-on: " + TRUSTED_LIGHT + "\n",
        "    name: Sign the macOS pair with the rcodesign stand-in (never signs)\n"
        "    needs: [protected-main, build-darwin]\n    if: needs.build-darwin.outputs.superseded == 'false'\n"
        "    runs-on: " + TRUSTED_LIGHT + "\n    enable-openid-connect: true\n", 1),
    "dry run reads the Apple keys": lambda t: t.replace(
        '          scripts/ci/tests/fixtures/rcodesign-stand-in.sh --install "$stand_in"\n',
        '          scripts/ci/tests/fixtures/rcodesign-stand-in.sh --install "$stand_in"\n'
        '          scripts/ci/setup/fetch-openbao-macos-signing.sh "$stand_in/apple"\n', 1),
    "dry run signs with the real rcodesign": lambda t: t.replace(
        'scripts/ci/release/sign-macos-cw.sh "$stand_in/bin/rcodesign" "$stand_in/keys"',
        'scripts/ci/release/sign-macos-cw.sh .rcodesign/rcodesign "$stand_in/keys"', 1),
    "dry-run stand-in calls unchecked": lambda t: re.sub(
        r"          \[ \"\$\(cut -d' ' -f1 \"\$stand_in/calls\".*?\n.*?\n", "", t, count=1, flags=re.S),
    "dry-run rcodesign pin differs": lambda t: t.replace(
        "RCODESIGN_X86_64_LINUX_SHA256: dbe85ced", "RCODESIGN_X86_64_LINUX_SHA256: 00000000", 1),
    "dry-run rcodesign installed differently": lambda t: t.replace(
        "          .rcodesign/rcodesign --version\n", "", 1),
    "dry-run signing without the macOS build": lambda t: t.replace(
        "    name: Sign the macOS pair with the rcodesign stand-in (never signs)\n"
        "    needs: [protected-main, build-darwin]\n",
        "    name: Sign the macOS pair with the rcodesign stand-in (never signs)\n"
        "    needs: [protected-main]\n", 1),
    "embedded runtime unchecked": lambda t: t.replace(
        '            grep -q "^cw-release: local runtime document_sha256=$DOCUMENT_SHA256 " <<<"$verified"\n',
        "            true\n", 1),
    "received runtime unchecked": lambda t: t.replace(
        '            [ "$(sha256sum dist-darwin/local-runtime/local-runtime.json | cut -c1-64)" = "$DOCUMENT_SHA256" ]\n',
        "            true\n", 1),
    "dry-run target build cancels its run": lambda t: add_cancel(t, "build-linux-musl", DRY_RUN_CANCEL_IF),
    "dry-run macOS build cancels its run": lambda t: add_cancel(t, "build-darwin", DRY_RUN_CANCEL_IF),
}


def main():
    text, ci_text = WORKFLOW.read_text(), CI.read_text()
    errors = check(text, ci_text)
    dry_run = DRY_RUN.read_text()
    errors += check_dry_run(dry_run, text)
    for name, mutate in DRY_RUN_MUTATIONS.items():
        mutated = mutate(dry_run)
        if mutated == dry_run or not check_dry_run(mutated, text):
            errors.append(f"dry-run mutation {name!r} was not rejected")
    if errors:
        print("test-cli-release-workflow: FAIL\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    for name, mutate in MUTATIONS.items():
        mutated = mutate(text)
        if mutated == text or not check(mutated, ci_text):
            print(f"test-cli-release-workflow: FAIL mutation {name!r} was not rejected", file=sys.stderr)
            return 1
    try:
        route_cases = route_guard_cases(text)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"test-cli-release-workflow: FAIL pre-read route proof: {error}", file=sys.stderr)
        return 1
    print(f"test-cli-release-workflow: PASS properties=accepted mutations_rejected={len(MUTATIONS)} "
          f"dry_run_mutations_rejected={len(DRY_RUN_MUTATIONS)} "
          f"pre_read_route_cases={route_cases}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
