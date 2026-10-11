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
DRY_RUN = ROOT / ".gitea/workflows/cw-release-dry-run.yaml"
CI = ROOT / ".gitea/workflows/ci.yaml"
# The macOS pair links Apple frameworks and is built natively on the protected
# macos-arm64 runner; the Linux pair is built beside the four-target assembly.
DARWIN_TARGETS = "aarch64-apple-darwin x86_64-apple-darwin"
LINUX_TARGETS = "x86_64-unknown-linux-musl aarch64-unknown-linux-gnu"
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
    need(list(blocks) == ["release-selection", "build-darwin", "build-release", "package-release"],
         "unexpected job set")
    darwin = blocks.get("build-darwin", "")
    build, package = blocks.get("build-release", ""), blocks.get("package-release", "")

    need("    needs: [release-selection]" in darwin, "the macOS build does not depend on release selection")
    need("    runs-on: macos-arm64\n" in darwin, "the macOS build does not run on the protected Mac runner")
    for capability in CAPABILITIES:
        need(capability not in darwin, f"macOS build job holds capability {capability}")
    need(f"CW_RELEASE_TARGETS='{DARWIN_TARGETS}'" in darwin, "the macOS build does not build exactly the Mac pair")
    need("darwin_sums_sha256" in darwin and "name: cw-release-darwin-${{ github.run_id }}" in darwin,
         "the macOS build does not hand over and bind its pair")

    need("    needs: [release-selection, build-darwin]" in build,
         "build does not depend on release selection and the macOS build")
    for capability in CAPABILITIES:
        need(capability not in build, f"build job holds capability {capability}")
    need(f"CW_RELEASE_TARGETS='{LINUX_TARGETS}'" in build and "CW_RELEASE_IMPORT_DIR=dist-darwin" in build,
         "build does not package the four release targets from the Linux and macOS pairs")
    need('[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]' in build,
         "the received macOS pair is not checked against the built pair")
    need("cw_release.py verify --dist dist/cw-release --unsigned" in build, "build does not verify its delivery")
    need("delivery_sha256" in build, "build does not bind its delivery digest")
    need("cargo build --locked --release -p codewire-cw-release \\\n"
         "            --example verify-release-signatures" in build and "verifier_sha256" in build
         and "name: cw-release-verifier-${{ github.run_id }}" in build,
         "build does not compile, bind and hand over cw's release-signature verifier")
    verifier_upload = dict(steps(build)).get("Hand the signature verifier to signing", "")
    need("          path: .release-verifier/\n" in verifier_upload
         and "          include-hidden-files: true\n" in verifier_upload,
         "the hidden verifier directory is not uploaded (the upload action skips hidden paths)")

    need("    needs: [release-selection, build-release]" in package, "signing does not need a successful build")
    need("    enable-openid-connect: true" in package, "publication job lacks its OIDC exchange")
    need(not re.search(r"^    if:", package, re.M), "publication job can run without a successful build")
    names = [name for name, _ in steps(package)]
    order = ["Receive the unsigned delivery", "Verify the received delivery is the built delivery",
             "Receive cw's release-signature verifier", "Verify the received verifier is the built verifier",
             "Reuse an already-published signed R2 release", "Sign release delivery",
             "Verify the signed delivery with cw's built-in verifier",
             "Publish immutable R2 release objects", "Remove the R2 publisher credential",
             "Publish signed release assets"]
    positions = [names.index(name) if name in names else -1 for name in order]
    need(-1 not in positions and positions == sorted(positions), "publication steps are missing or reordered")
    need(names and names[-1] == "Publish signed release assets", "work follows mirror publication")
    by_name = dict(steps(package))
    need("secrets." not in text, "the release workflow reads a Forgejo Actions secret")
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
    "OIDC in macOS build": lambda t: t.replace("    runs-on: macos-arm64\n    outputs:",
                                               "    runs-on: macos-arm64\n    enable-openid-connect: true\n    outputs:", 1),
    "macOS build on a pool runner": lambda t: t.replace("    runs-on: macos-arm64\n", "    runs-on: ci-protected\n", 1),
    "unbound macOS pair": lambda t: t.replace(
        '[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]', 'true', 1),
    "build without the macOS pair": lambda t: t.replace("    needs: [release-selection, build-darwin]",
                                                        "    needs: [release-selection]", 1),
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
    "hidden verifier skipped": lambda t: t.replace("          include-hidden-files: true\n", "", 1),
    "signing key outlives signing": lambda t: t.replace("          cleanup_signing\n          trap - EXIT\n",
                                                         "          trap - EXIT\n", 1),
    "no built-in verification": lambda t: re.sub(
        r"      - name: Verify the signed delivery with cw's built-in verifier\n(?:        .*\n|\n(?=        ))*\n",
        "", t, count=1),
    "built-in verification after R2 publication": lambda t: move_step(
        t, "Verify the signed delivery with cw's built-in verifier", "Remove the R2 publisher credential"),
    "unbound verifier": lambda t: t.replace('= "$VERIFIER_SHA256" ]', "] || true", 1),
    "verifier compiled while signing": lambda t: t.replace(
        "          ../.release-verifier/verify-release-signatures",
        "          cargo run --locked -p codewire-cw-release --example verify-release-signatures --\n"
        "          ../.release-verifier/verify-release-signatures", 1),
    "conditional verification": lambda t: t.replace(
        "      - name: Verify the signed delivery with cw's built-in verifier\n",
        "      - name: Verify the signed delivery with cw's built-in verifier\n"
        "        if: ${{ inputs.r2_publication == 'immutable' }}\n", 1),
    "verification by another key": lambda t: t.replace(
        "            A38FF6BC6623FCA611A7A32B5EFBF0F4A5870815 dist/cw-release",
        "            0000000000000000000000000000000000000000 dist/cw-release", 1),
}


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


def check_dry_run(text):
    """main builds and verifies the four-target delivery the way a release does."""
    errors = []

    def need(condition, message):
        if not condition:
            errors.append(message)

    blocks = jobs(text)
    need(list(blocks) == ["protected-main", "build-darwin", "assemble"], "unexpected dry-run job set")
    guard = blocks.get("protected-main", "")
    darwin, assemble = blocks.get("build-darwin", ""), blocks.get("assemble", "")
    need("    runs-on: ci-lite\n" in guard and "actions-checkout" not in guard
         and "[ \"$GITHUB_REF\" = 'refs/heads/main' ]" in guard
         and "[ \"$GITHUB_REF_NAME\" = 'main' ]" in guard and not re.search(r"^\s+if:", guard, re.M),
         "the dry run does not refuse every ref but main before the protected builders")
    need("    needs: [protected-main]\n" in darwin, "the macOS build does not wait for the main-only guard")
    for capability in CAPABILITIES:
        need(capability not in text, f"dry run holds capability {capability}")
    need("    runs-on: macos-arm64\n" in darwin, "the dry-run macOS build is not on the protected Mac runner")
    need(f"CW_RELEASE_TARGETS='{DARWIN_TARGETS}'" in darwin, "the dry-run macOS build is not the Mac pair")
    need("    needs: [protected-main, build-darwin]" in assemble and "    runs-on: ci-protected\n" in assemble,
         "the dry-run assembly does not follow the macOS build on a protected runner")
    need(f"CW_RELEASE_TARGETS='{LINUX_TARGETS}'" in assemble and "CW_RELEASE_IMPORT_DIR=dist-darwin" in assemble,
         "the dry-run assembly does not package the four targets")
    need('[ "$(sha256sum dist-darwin/SHA256SUMS | cut -c1-64)" = "$DARWIN_SUMS_SHA256" ]' in assemble,
         "the dry-run assembly does not bind the received macOS pair")
    need('verified targets=4 version=$DRY_RUN_VERSION runtime_equal=true signed=false' in assemble,
         "the dry run does not verify the four-target delivery")
    need("    branches: [main]" in text and "pull_request" not in text,
         "the dry run is not limited to main")
    return errors


DRY_RUN_MUTATIONS = {
    "pull requests": lambda t: t.replace("on:\n  push:", "on:\n  pull_request:\n  push:", 1),
    "secret": lambda t: t.replace("    runs-on: ci-protected\n", "    runs-on: ci-protected\n    env:\n"
                                  "      KEY: ${{ secrets.CW_RELEASE_GPG_PRIVATE_KEY }}\n", 1),
    "pool Mac": lambda t: t.replace("    runs-on: macos-arm64\n", "    runs-on: ci-heavy\n", 1),
    "no verification": lambda t: t.replace("runtime_equal=true signed=false", "runtime_equal=true", 1),
    "no main guard": lambda t: t.replace("          [ \"$GITHUB_REF\" = 'refs/heads/main' ]\n", "", 1),
    "guard skipped": lambda t: t.replace("    name: Refuse anything but protected main\n    runs-on: ci-lite\n",
                                         "    name: Refuse anything but protected main\n    runs-on: ci-lite\n"
                                         "    if: github.event_name == 'push'\n", 1),
    "Mac build without the guard": lambda t: t.replace("    needs: [protected-main]\n    runs-on: macos-arm64",
                                                       "    runs-on: macos-arm64", 1),
}


def main():
    text, ci_text = WORKFLOW.read_text(), CI.read_text()
    errors = check(text, ci_text)
    dry_run = DRY_RUN.read_text()
    errors += check_dry_run(dry_run)
    for name, mutate in DRY_RUN_MUTATIONS.items():
        mutated = mutate(dry_run)
        if mutated == dry_run or not check_dry_run(mutated):
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
