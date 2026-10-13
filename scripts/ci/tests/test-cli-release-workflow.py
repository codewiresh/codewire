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
        if "    runs-on: macos-arm64\n" in block:
            continue
        for targets in re.findall(r"CW_RELEASE_TARGETS='([^']*)'", block):
            unsealed += [target for target in targets.split() if target not in sealed_targets()]
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


def check(text, ci_text):
    errors = []

    def need(condition, message):
        if not condition:
            errors.append(message)

    errors.extend(external_download_errors(text))
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
    need(list(blocks) == ["release-selection", "build-runtime-linux", "build-darwin", "build-release",
                          "package-release"], "unexpected job set")
    runtime, darwin = blocks.get("build-runtime-linux", ""), blocks.get("build-darwin", "")
    build, package = blocks.get("build-release", ""), blocks.get("package-release", "")

    # The local VM runtime the arm64 cw embeds (#2539): built from the release
    # source's own scripts, slow parts included on a cache miss, by jobs with
    # no capability; only the publishing job records the parts it built.
    need("    needs: [release-selection]\n    runs-on: ci-protected\n" in runtime,
         "the runtime's Linux side does not follow release selection on a protected runner")
    for capability in CAPABILITIES:
        need(capability not in runtime, f"runtime build job holds capability {capability}")
    runtime_build = dict(steps(runtime)).get("Build the Linux side", "")
    need("        working-directory: .release-source\n" in runtime_build
         and "scripts/ci/release/build-local-runtime.sh linux --output" in runtime_build
         and 'LOCAL_RUNTIME_JOB_CONTAINER="${HOSTNAME:?}"' in runtime_build,
         "the runtime's Linux side is not built by the release source's own scripts in this job's container")
    need("LOCAL_RUNTIME_NO_BUILD" not in text, "a release refuses to build an uncached runtime part")
    need(not runner_targets_sealed(text), "a Linux runner job needs a Rust target or rustup change its sealed "
         f"toolchain lacks: {runner_targets_sealed(text)}")
    for upload, job in (("Hand the Linux side to the macOS build", runtime),
                        ("Hand the runtime part records to publication", darwin)):
        need("          include-hidden-files: true\n" in dict(steps(job)).get(upload, ""),
             f"{upload!r} skips its hidden path")
    need("    needs: [release-selection, build-runtime-linux]" in darwin,
         "the macOS build does not depend on release selection and the runtime's Linux side")
    mac_runtime = dict(steps(darwin)).get("Build the local VM runtime", "")
    need('[ "$(shasum -a 256 ../.local-runtime-linux/runtime-linux.tar | cut -c1-64)" = "$LINUX_SHA256" ]'
         in mac_runtime and "scripts/ci/release/build-local-runtime.sh macos" in mac_runtime
         and 'CW_RELEASE_LOCAL_RUNTIME_DIR=$work/macos/runtime' in mac_runtime,
         "the macOS build does not bind the received Linux side and embed the runtime it packs")
    need("records_sha256" in darwin and "name: cw-release-runtime-records-${{ github.run_id }}" in darwin,
         "the macOS build does not hand over and bind its runtime part records")
    need([job for job, body in blocks.items() if "local_runtime_parts.py publish" in body] == ["package-release"]
         and [step for step, body in steps(package) if "local_runtime_parts.py publish" in body]
         == ["Record the runtime parts this release built"],
         "runtime part records are written outside the publishing step")
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

    need("    needs: [release-selection, build-darwin, build-release]" in package,
         "signing does not need a successful build")
    need("    enable-openid-connect: true" in package, "publication job lacks its OIDC exchange")
    need(not re.search(r"^    if:", package, re.M), "publication job can run without a successful build")
    names = [name for name, _ in steps(package)]
    order = ["Receive the unsigned delivery", "Verify the received delivery is the built delivery",
             "Receive cw's release-signature verifier", "Verify the received verifier is the built verifier",
             "Reuse an already-published signed R2 release", "Sign release delivery",
             "Verify the signed delivery with cw's built-in verifier",
             "Publish immutable R2 release objects", "Receive the runtime part records",
             "Record the runtime parts this release built", "Remove the R2 publisher credential",
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
    records = by_name.get("Record the runtime parts this release built", "")
    need("if: ${{ inputs.r2_publication == 'immutable' && needs.build-darwin.outputs.records_sha256 != '' }}"
         in records and "always()" not in records, "runtime part records are written without R2 publication")
    need('[ "$(sha256sum ../.runtime-records/runtime-records.tar | cut -c1-64)" = "$RECORDS_SHA256" ]' in records,
         "the received runtime part records are not checked against the built records")
    need('if [ "$CW_RELEASE_R2_STATE" = retained ]; then' in records
         and "printf 'CW_RELEASE_R2_STATE=%s\\n' \"$state\" >> \"$GITHUB_ENV\"" in probe,
         "a retained release writes records for blobs it did not publish")
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
    "unbounded cargo git fetch": lambda t: t.replace("  CARGO_HTTP_TIMEOUT: '20'\n", "", 1),
    "cargo git fetch without retries": lambda t: t.replace("  CARGO_NET_RETRY: '5'\n", "", 1),
    "unbounded protoc download": lambda t: t.replace(
        "          scripts/ci/release/fetch-pinned.sh \"https://github.com/protocolbuffers",
        "          curl -fsSL -o /tmp/protoc.zip \"https://github.com/protocolbuffers", 1),
    "unbounded zig download": lambda t: t.replace(
        'scripts/ci/release/fetch-pinned.sh "$zig_url"', 'curl -fsSLo zig.tar.xz "$zig_url" #', 1),
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
    "publish after failed build": lambda t: t.replace(
        "    needs: [release-selection, build-darwin, build-release]",
        "    needs: [release-selection, build-darwin, build-release]\n    if: always()", 1),
    "signing without build": lambda t: t.replace("    needs: [release-selection, build-darwin, build-release]",
                                                 "    needs: [release-selection, build-darwin]", 1),
    "OIDC in runtime build": lambda t: t.replace(
        "    needs: [release-selection]\n    runs-on: ci-protected\n",
        "    needs: [release-selection]\n    runs-on: ci-protected\n    enable-openid-connect: true\n", 1),
    "release skips uncached parts": lambda t: t.replace(
        'TMPDIR="$work/tmp" LOCAL_RUNTIME_JOB_CONTAINER',
        'TMPDIR="$work/tmp" LOCAL_RUNTIME_NO_BUILD=1 LOCAL_RUNTIME_JOB_CONTAINER', 1),
    "runtime from the workflow's scripts": lambda t: t.replace(
        "      - name: Build the Linux side\n        id: build\n        working-directory: .release-source\n",
        "      - name: Build the Linux side\n        id: build\n", 1),
    "macOS build without the Linux side": lambda t: t.replace(
        "    needs: [release-selection, build-runtime-linux]", "    needs: [release-selection]", 1),
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
        "        if: ${{ inputs.r2_publication == 'immutable' && needs.build-darwin.outputs.records_sha256 != '' }}\n"
        "        working-directory: .release-source\n",
        "        if: ${{ needs.build-darwin.outputs.records_sha256 != '' }}\n"
        "        working-directory: .release-source\n", 1),
    "unbound records": lambda t: t.replace('= "$RECORDS_SHA256" ]', "] || true", 1),
    "records on a retained retry": lambda t: t.replace('if [ "$CW_RELEASE_R2_STATE" = retained ]; then',
                                                       "if false; then", 1),
    "unsealed Linux target": lambda t: t.replace(f"CW_RELEASE_TARGETS='{LINUX_TARGETS}'",
                                                 f"CW_RELEASE_TARGETS='{LINUX_TARGETS} aarch64-unknown-linux-musl'", 1),
    "rustup on the runner": lambda t: t.replace(
        "      - name: Build the Linux side\n        id: build\n        working-directory: .release-source\n"
        "        run: |\n          set -euo pipefail\n",
        "      - name: Build the Linux side\n        id: build\n        working-directory: .release-source\n"
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

    errors.extend(external_download_errors(text))
    blocks = jobs(text)
    need(list(blocks) == ["protected-main", "superseded", "build-runtime-linux", "build-darwin", "assemble"],
         "unexpected dry-run job set")
    # A wedged step must fail within its job's limit instead of holding the
    # one-at-a-time dry-run queue until the runner's 330-minute limit.
    for job, limit in (("build-runtime-linux", 30), ("build-darwin", 60), ("assemble", 90)):
        found = re.findall(r"^    timeout-minutes: ([0-9]+)$", blocks.get(job, ""), re.M)
        need(found == [str(limit)], f"dry-run job {job} lacks its {limit}-minute limit")
    # Forgejo cancels the older push run of a workflow with no `concurrency`
    # block. With a group and `cancel-in-progress: false`, runs queue in push
    # order and each one finishes.
    need("\nconcurrency:\n  group: cw-release-dry-run-${{ github.ref }}\n  cancel-in-progress: false\n\n" in text,
         "a newer main push can cancel a running dry run")
    guard, runtime = blocks.get("protected-main", ""), blocks.get("build-runtime-linux", "")
    superseded = blocks.get("superseded", "")
    darwin, assemble = blocks.get("build-darwin", ""), blocks.get("assemble", "")
    need("    runs-on: ci-lite\n" in guard and "actions-checkout" not in guard
         and "[ \"$GITHUB_REF\" = 'refs/heads/main' ]" in guard
         and "[ \"$GITHUB_REF_NAME\" = 'main' ]" in guard and not re.search(r"^\s+if:", guard, re.M),
         "the dry run does not refuse every ref but main before the protected builders")
    need("    needs: [protected-main, superseded, build-runtime-linux]\n" in darwin,
         "the macOS build does not wait for the main-only guard and the runtime's Linux side")
    need("    needs: [protected-main, superseded]\n" in runtime and "    runs-on: ci-protected\n" in runtime,
         "the runtime's Linux side does not wait for the main-only guard on a protected runner")
    # Forgejo keeps every queued run. Only the newest queued commit needs the
    # protected builders and the Mac; the checked-in rule says when an older
    # one may skip without losing a check (test-dry-run-superseded.sh).
    skip_unless_newest = "    if: needs.superseded.outputs.superseded == 'false'\n"
    need(skip_unless_newest in runtime and skip_unless_newest in darwin,
         "a superseded dry run still reaches the protected builders or the Mac")
    need("    needs: [protected-main]\n    runs-on: ci-lite\n" in superseded
         and not re.search(r"^\s+if:", superseded, re.M)
         and "      superseded: ${{ steps.canonical.outputs.superseded }}\n" in superseded
         and "          BEFORE: ${{ github.event.before }}\n" in superseded
         and 'run: scripts/ci/release/dry-run-superseded.sh "$GITHUB_SHA" "$BEFORE"' in superseded,
         "the dry run does not decide supersession with the checked-in rule after the main-only guard")
    # The runtime is built when one of its inputs changed, from cached slow
    # parts only; otherwise each side checks its slow parts are cached.
    select = dict(steps(runtime)).get("Select the local runtime check", "")
    need("          mode=full\n" in select
         and "python3 scripts/ci/release/local_runtime_parts.py runtime-mode" in select,
         "the dry run does not select the runtime build from the runtime's inputs")
    linux_build = dict(steps(runtime)).get("Build the Linux side from cached parts", "")
    mac_build = dict(steps(darwin)).get("Build the local VM runtime from cached parts", "")
    need("LOCAL_RUNTIME_NO_BUILD=1" in linux_build and "LOCAL_RUNTIME_NO_BUILD=1" in mac_build,
         "the dry run builds slow runtime parts")
    need("build-local-runtime.sh linux --check" in runtime and "build-local-runtime.sh macos --check" in darwin,
         "the dry run does not check the slow parts are cached")
    need('[ "$(shasum -a 256 .local-runtime-linux/runtime-linux.tar | cut -c1-64)" = "$LINUX_SHA256" ]' in mac_build,
         "the dry-run macOS build does not bind the received Linux side")
    need("grep -q '^cw-release: local runtime document_sha256=' <<<\"$verified\"" in assemble
         and "[ ! -e dist/cw-release/delivery/local-runtime ]" in assemble,
         "the dry run does not check the delivery embeds exactly the runtime it built")
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
    need(not runner_targets_sealed(text), "a dry-run Linux runner job needs a Rust target or rustup change its "
         f"sealed toolchain lacks: {runner_targets_sealed(text)}")
    need("    branches: [main]" in text and "pull_request" not in text,
         "the dry run is not limited to main")
    return errors


DRY_RUN_MUTATIONS = {
    "Linux side without a job limit": lambda t: t.replace("    timeout-minutes: 30\n", "", 1),
    "macOS build without a job limit": lambda t: t.replace("    timeout-minutes: 60\n", "", 1),
    "assembly at the runner limit": lambda t: t.replace("    timeout-minutes: 90\n", "    timeout-minutes: 330\n", 1),
    "dry run without cargo network bounds": lambda t: t.replace("  CARGO_HTTP_TIMEOUT: '20'\n", "", 1),
    "dry run with an unbounded protoc download": lambda t: t.replace(
        "          scripts/ci/release/fetch-pinned.sh \"https://github.com/protocolbuffers",
        "          curl -fsSL -o \"$HOME/protoc.zip\" \"https://github.com/protocolbuffers", 1),
    "cancellable dry run": lambda t: t.replace("  cancel-in-progress: false\n", "  cancel-in-progress: true\n", 1),
    "dry run without a concurrency group": lambda t: t.replace(
        "  group: cw-release-dry-run-${{ github.ref }}\n", "", 1),
    "pull requests": lambda t: t.replace("on:\n  push:", "on:\n  pull_request:\n  push:", 1),
    "secret": lambda t: t.replace("    runs-on: ci-protected\n", "    runs-on: ci-protected\n    env:\n"
                                  "      KEY: ${{ secrets.CW_RELEASE_GPG_PRIVATE_KEY }}\n", 1),
    "pool Mac": lambda t: t.replace("    runs-on: macos-arm64\n", "    runs-on: ci-heavy\n", 1),
    "no verification": lambda t: t.replace("runtime_equal=true signed=false", "runtime_equal=true", 1),
    "no main guard": lambda t: t.replace("          [ \"$GITHUB_REF\" = 'refs/heads/main' ]\n", "", 1),
    "guard skipped": lambda t: t.replace("    name: Refuse anything but protected main\n    runs-on: ci-lite\n",
                                         "    name: Refuse anything but protected main\n    runs-on: ci-lite\n"
                                         "    if: github.event_name == 'push'\n", 1),
    "Mac build without the guard": lambda t: t.replace(
        "    needs: [protected-main, superseded, build-runtime-linux]\n",
        "    needs: [superseded, build-runtime-linux]\n", 1),
    "runtime build without the guard": lambda t: t.replace(
        "    needs: [protected-main, superseded]\n", "    needs: [superseded]\n", 1),
    "Mac builds a superseded commit": lambda t: t.replace(
        "    if: needs.superseded.outputs.superseded == 'false'\n    runs-on: macos-arm64\n",
        "    runs-on: macos-arm64\n", 1),
    "runtime builds a superseded commit": lambda t: t.replace(
        "    if: needs.superseded.outputs.superseded == 'false'\n    runs-on: ci-protected\n",
        "    runs-on: ci-protected\n", 1),
    "supersession before the guard": lambda t: t.replace(
        "    name: Skip a superseded commit\n    needs: [protected-main]\n",
        "    name: Skip a superseded commit\n", 1),
    "supersession without the checked-in rule": lambda t: t.replace(
        'run: scripts/ci/release/dry-run-superseded.sh "$GITHUB_SHA" "$BEFORE"',
        "run: echo superseded=true >> \"$GITHUB_OUTPUT\"", 1),
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
        "        if: steps.select.outputs.mode == 'full'\n        run: |\n          set -euo pipefail\n",
        "      - name: Build the Linux side from cached parts\n        id: build\n"
        "        if: steps.select.outputs.mode == 'full'\n        run: |\n          set -euo pipefail\n"
        "          rustup target add aarch64-unknown-linux-musl\n", 1),
    "embedded runtime unchecked": lambda t: t.replace(
        "            grep -q '^cw-release: local runtime document_sha256=' <<<\"$verified\"\n",
        "            true\n", 1),
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
