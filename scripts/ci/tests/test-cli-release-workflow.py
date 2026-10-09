#!/usr/bin/env python3
"""Structural proof of the cw release workflow's capability boundaries.

Compilation runs in a job with no OIDC, signing, mirror or R2 capability; the
signing/publishing job needs a successful build; R2 publication is opt-in and
inactive or unknown route values refuse before acquiring a credential; promotion
defaults to none. Each property rejects a mutated workflow. The exact route guard
is also exercised with a private fake credential reader, without credentials.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".gitea/workflows/cli-release.yaml"
CI = ROOT / ".gitea/workflows/ci.yaml"
TARGETS = "x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
GPG = ("CW_RELEASE_GPG_PRIVATE_KEY", "CW_RELEASE_GPG_PASSPHRASE", "CW_RELEASE_GPG_KEY_ID")
CAPABILITIES = ("enable-openid-connect", "secrets.", "fetch-openbao-", "sign-cw-release", "cw_release_r2",
                "mint-github-app-token", "publish-cw-release", "GH_MIRROR_TOKEN_FILE")


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


def check(text, ci_text):
    errors = []

    def need(condition, message):
        if not condition:
            errors.append(message)

    header = text.split("\njobs:\n", 1)[0]
    need("enable-openid-connect" not in header, "OIDC is enabled for every job")
    need(re.findall(r"^  CW_RELEASE_R2_ROUTE_ADMITTED: '([^'\n]*)'$", header, re.M) == ["true"],
         "the R2 route is not exactly the admitted true value")
    need(re.search(r"r2_publication:\n(?:        .*\n)*?        default: none", header) is not None,
         "R2 publication does not default to none")
    need(re.search(r"r2_promote_channel:\n(?:        .*\n)*?        default: none", header) is not None,
         "channel promotion does not default to none")
    need("tags:" not in header, "tag-owned workflow code may release")
    blocks = jobs(text)
    need(list(blocks) == ["release-selection", "build-release", "package-release"], "unexpected job set")
    build, package = blocks.get("build-release", ""), blocks.get("package-release", "")

    need("    needs: [release-selection]" in build, "build does not depend on release selection")
    for capability in CAPABILITIES:
        need(capability not in build, f"build job holds capability {capability}")
    need(f"CW_RELEASE_TARGETS='{TARGETS}'" in build, "build does not package the four release targets")
    need("cw_release.py verify --dist dist/cw-release --unsigned" in build, "build does not verify its delivery")
    need("delivery_sha256" in build, "build does not bind its delivery digest")

    need("    needs: [release-selection, build-release]" in package, "signing does not need a successful build")
    need("    enable-openid-connect: true" in package, "publication job lacks its OIDC exchange")
    need(not re.search(r"^    if:", package, re.M), "publication job can run without a successful build")
    names = [name for name, _ in steps(package)]
    order = ["Receive the unsigned delivery", "Verify the received delivery is the built delivery",
             "Reuse an already-published signed R2 release", "Verify release signing key", "Sign release delivery",
             "Publish immutable R2 release objects", "Remove the R2 publisher credential",
             "Publish signed release assets"]
    positions = [names.index(name) if name in names else -1 for name in order]
    need(-1 not in positions and positions == sorted(positions), "publication steps are missing or reordered")
    need(names and names[-1] == "Publish signed release assets", "work follows mirror publication")
    by_name = dict(steps(package))
    for name in GPG:
        holders = [step for step, body in steps(package) if f"{name}: ${{{{ secrets.{name} }}}}" in body]
        need(holders == ["Verify release signing key", "Sign release delivery"],
             f"{name} reaches steps other than key verification and signing")
        need(text.count(f"secrets.{name}") == 2, f"{name} appears outside the two signing steps")
    probe = by_name.get("Reuse an already-published signed R2 release", "")
    publish = by_name.get("Publish immutable R2 release objects", "")
    for step in (probe, publish):
        need("if: ${{ inputs.r2_publication == 'immutable' }}" in step, "an R2 step is not opt-in")
        need("always()" not in step and "failure()" not in step, "an R2 step runs after failure")
    admitted = probe.find("[ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ]")
    fetch = probe.find("fetch-openbao-releases-r2-credentials.sh")
    need(0 <= admitted < fetch, "the R2 credential is read before the route admission check")
    need([step for step, body in steps(package) if "fetch-openbao-releases-r2-credentials.sh" in body]
         == ["Reuse an already-published signed R2 release"], "the R2 credential is read in an unexpected step")
    need("--promote \"$PROMOTE_CHANNEL\"" in publish and "PROMOTE_CHANNEL: ${{ inputs.r2_promote_channel }}"
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
        refs = set(re.findall(r"https://git\.example\.invalid/noel/" + action + r"[0-9a-f]{40}", text))
        need(len(refs) == 1 and refs <= set(re.findall(r"https://git\.example\.invalid/noel/" + action + r"[0-9a-f]{40}",
                                                       ci_text)), f"{action} is not the pinned mirrored action")
    return errors


MUTATIONS = {
    "global OIDC": lambda t: t.replace("permissions:\n  contents: read\n",
                                       "permissions:\n  contents: read\n\nenable-openid-connect: true\n", 1),
    "OIDC in build": lambda t: t.replace("    runs-on: ci-protected\n    outputs:",
                                         "    runs-on: ci-protected\n    enable-openid-connect: true\n    outputs:", 1),
    "secret in build": lambda t: t.replace("          RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}\n"
                                           "          CW_RELEASE_SOURCE_SHA",
                                           "          RELEASE_TAG: ${{ needs.release-selection.outputs.release_tag }}\n"
                                           "          CW_RELEASE_GPG_PRIVATE_KEY: ${{ secrets.CW_RELEASE_GPG_PRIVATE_KEY }}\n"
                                           "          CW_RELEASE_SOURCE_SHA", 1),
    "route inactive": lambda t: t.replace("CW_RELEASE_R2_ROUTE_ADMITTED: 'true'", "CW_RELEASE_R2_ROUTE_ADMITTED: 'false'"),
    "route unknown": lambda t: t.replace("CW_RELEASE_R2_ROUTE_ADMITTED: 'true'", "CW_RELEASE_R2_ROUTE_ADMITTED: 'unknown'"),
    "promotion default": lambda t: t.replace("        default: none\n        options: [none, stable]",
                                             "        default: stable\n        options: [none, stable]"),
    "credential before admission": lambda t: t.replace(
        "          r2_work=\"${RUNNER_TEMP:?}/codewire-release-r2\"\n          mkdir -m 0700 \"$r2_work\"\n"
        "          ../scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh \"$r2_work/aws-credentials\"\n", "", 1)
    .replace("          set -euo pipefail\n          [ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ] || {",
             "          set -euo pipefail\n          ../scripts/ci/setup/fetch-openbao-releases-r2-credentials.sh x\n"
             "          [ \"$CW_RELEASE_R2_ROUTE_ADMITTED\" = 'true' ] || {", 1),
    "publish after failed build": lambda t: t.replace("    needs: [release-selection, build-release]",
                                                      "    needs: [release-selection, build-release]\n    if: always()", 1),
    "signing without build": lambda t: t.replace("    needs: [release-selection, build-release]",
                                                 "    needs: [release-selection]", 1),
    "three targets": lambda t: t.replace(TARGETS, TARGETS.rsplit(" ", 1)[0], 1),
}


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
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
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


def main():
    text, ci_text = WORKFLOW.read_text(), CI.read_text()
    errors = check(text, ci_text)
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
          f"pre_read_route_cases={route_cases}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
