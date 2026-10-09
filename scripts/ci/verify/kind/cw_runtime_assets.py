#!/usr/bin/env python3
"""Hold original producer inputs across the retained public CW journey.

This admits assets and their original compiler evidence. The child owns the
actual public create/session/update/cleanup checks; this helper cannot confer
Pod, image, cache, provider, or runtime qualification by itself.
"""

import argparse
from contextlib import ExitStack, closing, contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tempfile
import time


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
# Covers the existing bounded setup waits, the 900s continuous client journey
# and public terminal cleanup. This is an operation bound, not worker lifetime.
JOURNEY_SECONDS = 3600


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = load("kind_cw_original_producer", ROOT / "scripts/ci/images/build-cw-runtime-source.py")
source, release, owner = driver.source, driver.release, driver.owner


class ProfileLock:
    """Retain only the selected profile's original flock description."""

    def __init__(self, environment):
        self.parent = None
        self.fd = None
        try:
            cluster = environment.get("CLUSTER", "")
            daemon = environment.get("KIND_PROFILE_DOCKER_ID", "")
            value = environment.get("KIND_PROFILE_LOCK_FD", "")
            source.require(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,47}[a-z0-9])?", cluster)
                           and environment.get("KIND_CLUSTER_NAME") == cluster
                           and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", daemon)
                           and re.fullmatch(r"[0-9]{1,9}", value),
                           "CW journey profile lock selectors refused")
            profile = source.asset.path_arg(environment.get("KIND_PROFILE_PATH", ""))
            source.require(profile.name == "profile.json" and profile.parent.name == cluster
                           and profile.parent.parent.name == hashlib.sha256(daemon.encode()).hexdigest(),
                           "CW journey lock differs from the selected profile namespace")
            self.path = profile.parent / "operation.lock"
            self.root = profile.parent.parent.parent
            self.cluster, self.daemon = cluster, daemon
            source.require(environment.get("KIND_PROFILE_LOCK_FILE") == str(self.path)
                           and environment.get("CODEWIRE_KIND_PROFILE_ROOT", str(self.root)) == str(self.root),
                           "CW journey lock path differs from its selected profile")
            original = int(value)
            source.require(original > 2, "CW journey lock descriptor is not an inherited profile FD")
            self.parent = source.asset.Parent(self.path.parent)
            self.fd = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 3)
            info = os.fstat(self.fd)
            source.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                           and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                           "CW journey lock is not an owned mode0600 regular file")
            self.metadata = source.asset.stamp(info)
            self.revalidate()
            # Same-description acquisition cannot deadlock on the parent's
            # lock. A separately opened conflicting description must refuse.
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise

    def revalidate(self):
        self.parent.revalidate()
        current = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        source.require(source.asset.stamp(current) == self.metadata
                       == source.asset.stamp(os.fstat(self.fd))
                       and os.readlink(f"/proc/self/fd/{self.fd}") == str(self.path),
                       "CW journey original profile lock name/inode changed")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            self.parent.close()
            self.parent = None


class LockedSubprocess:
    """Private c0 adapter; never mutate the Python subprocess module."""

    def __init__(self, original, profile):
        self.original, self.profile = original, profile

    def __getattr__(self, name):
        return getattr(self.original, name)

    def Popen(self, *args, **kwargs):
        source.require("pass_fds" not in kwargs and kwargs.get("close_fds", True) is True,
                       "CW journey subprocess descriptor contract differs")
        self.profile.revalidate()
        return self.original.Popen(*args, **{**kwargs, "close_fds": True,
                                            "pass_fds": (self.profile.fd,)})


def run_journey(profile, command, environment, task):
    profile.revalidate()
    original = owner.subprocess
    owner.subprocess = LockedSubprocess(original, profile)
    try:
        return owner.run_owned(command, ROOT, environment, task / "journey.log",
                               time.monotonic() + JOURNEY_SECONDS)
    finally:
        owner.subprocess = original
        profile.revalidate()


class JourneyFailure(ValueError):
    def __init__(self, status):
        super().__init__("retained CW journey failed; preserve its original request IDs and evidence")
        self.status = status


def failed_completion(error, command, task):
    """Retain the c0 failure; never turn salvage or an unknown result green."""
    prefix = "kernel command failed after owned-family cleanup: "
    source.require(str(error).startswith(prefix), "CW journey process completion is unknown")
    result = json.loads(str(error)[len(prefix):])
    source.require(type(result) is dict and set(result) == {
        "command", "exit", "elapsed_seconds", "log", "log_sha256", "timed_out",
        "interrupted", "unexpected_family", "cleanup_unknown"}
        and result["command"] == command and result["log"] == str(task / "journey.log")
        and type(result["exit"]) is int and -128 <= result["exit"] <= 255
        and all(type(result[key]) is bool for key in (
            "timed_out", "interrupted", "unexpected_family", "cleanup_unknown")),
        "CW journey process result fields refused")
    if result["cleanup_unknown"] or result["unexpected_family"]:
        status = 70
    elif result["interrupted"]:
        status = 128 + owner.STOP if owner.STOP is not None else 1
    elif result["timed_out"]:
        status = 124
    else:
        status = result["exit"] if result["exit"] > 0 else 128 - result["exit"]
        if result["exit"] == 0:
            status = 1
    with closing(source.asset.Parent(task)) as parent:
        source.asset.write_new(parent.fd, "process-failed.json", release.canonical(result), 0o400)
    return JourneyFailure(status)


def evidence(held):
    return {key: held.evidence()[key] for key in ("path", "sha256", "size")}


@contextmanager
def admitted_inputs(source_root, selected_sha, selections):
    """Reuse the production full eight-export admission, without compilation."""
    source_root = source.asset.path_arg(str(source_root))
    source.require(release.is_hex(selected_sha, 40)
                   and source.git(source_root, ["rev-parse", "HEAD"]).strip().decode() == selected_sha,
                   "CW journey current source selection refused")
    source.require(set(selections) == {"release_a", "release_b", "support_cw"},
                   "CW journey requires original release A/B and CI support producers")
    with ExitStack() as stack:
        retained = {}
        entries = {}
        headers = []
        for name in ("release_a", "release_b", "support_cw"):
            selected = selections[name]
            fields = {"build_json", "build_sha256"}
            if name != "support_cw":
                fields.add("sha256")
            source.require(type(selected) is dict
                           and set(selected) == fields
                           and release.is_hex(selected["build_sha256"], 64)
                           and (name == "support_cw" or release.is_hex(selected["sha256"], 64)),
                           "CW journey producer pins refused")
            path = source.asset.path_arg(selected["build_json"])
            source.require(path.name == "build.json", "CW journey requires the original build.json receipt")
            header = stack.enter_context(closing(source.HeldSourceFile(path, release.MAX_JSON)))
            headers.append(header)
            source.require(header.sha256 == selected["build_sha256"],
                           "CW journey build receipt differs from its external pin")
            model = release.parse_canonical(header.data)
            source.require(type(model) is dict and release.valid_version(model.get("version")),
                           "CW journey producer version refused")
            profile = "ci" if name == "support_cw" else "release"
            admitted = stack.enter_context(driver.reopen(
                path, selected["build_sha256"], source_root, selected_sha, profile, model["version"]))
            retained[name] = admitted
            summary = admitted.summary
            source.require((name == "support_cw" or summary["payload"]["sha256"] == selected["sha256"])
                           and summary["payload"]["target"] == "x86_64-unknown-linux-musl"
                           and summary["source"]["revision"] == selected_sha,
                           "CW journey payload differs from its explicit pin")
            header.revalidate(content=True)
            entries[name] = {
                "release_dir": str(admitted.path / "assets"),
                "identity": summary["payload"],
                "build_receipt": evidence(admitted.files["receipt"]),
                "producer_receipt": evidence(admitted.files["asset/producer.json"]),
                "image": evidence(admitted.files["asset/cw.oci.tar"]),
                "index_sha256": summary["index_sha256"],
                "compilation_source": summary["source"],
                "profile": summary["profile"],
                "version": summary["version"],
                "build_ref": summary["build_ref"],
            }
        source.require(entries["release_a"]["identity"]["sha256"]
                       != entries["release_b"]["identity"]["sha256"]
                       and entries["release_a"]["version"] != entries["release_b"]["version"],
                       "CW journey requires distinct A/B bytes and versions")
        source.require(entries["release_a"]["identity"]["rustc"]
                       == entries["release_b"]["identity"]["rustc"],
                       "CW journey release A/B compiler identities differ")
        current = retained["release_a"].summary["current_source"]
        source.require(all(release.canonical(current) == release.canonical(item.summary["current_source"])
                           for item in retained.values()),
                       "CW journey producers disagree on current source")
        witness = {"schema_version": 1, "source_sha": selected_sha,
                   "current_source": current, **entries}

        def revalidate():
            for original in retained.values():
                original.revalidate()
            for held in headers:
                held.revalidate(content=True)

        # The original producer owns all export, source, prerequisite,
        # dep-info, metadata and log validation. Extra receipt FDs stay held.
        revalidate()
        yield witness, revalidate
        revalidate()


def stage_release(task, name, entry):
    """The client's release directory: the admitted executable beside its
    canonical cw-runtime.json, the two files the cw image carries. Producers
    keep the identity in their receipts, so it is written here once; the
    original receipts stay the witness's evidence."""
    identity = entry["identity"]
    with closing(source.HeldSourceFile(Path(entry["release_dir"]) / "cw", identity["size"])) as held:
        source.require(held.sha256 == identity["sha256"] and len(held.data) == identity["size"],
                       "CW journey executable differs from its admitted identity")
        data = held.data
    directory = task / name.replace("_", "-")
    owner.private_directory(directory)
    with closing(source.asset.Parent(directory)) as parent:
        source.asset.write_new(parent.fd, "cw", data, 0o500)
        source.asset.write_new(parent.fd, "cw-runtime.json", release.canonical(identity), 0o400)
    return directory


def child_environment(task, witness, witness_path, witness_sha256, profile):
    # Keep only checked-in topology/tool controls; use an isolated HOME and
    # the coordinator's already-owned Docker configuration if supplied.
    allowed = {
        "PATH", "CLUSTER", "KIND_CLUSTER_NAME", "KIND_PUBLIC_ORIGIN",
        "KIND_BROWSER_API_ORIGIN", "KIND_INGRESS_HOST_PORT", "KIND_INGRESS_HTTP_HOST_PORT",
        "KIND_INGRESS_TLS_HOST_PORT", "KIND_TEMPORAL_HOST_PORT",
        "KIND_ORCHESTRATION_HOST_PORT", "KIND_COORDINATOR_DIRECT_HOST_PORT",
        "KIND_POSTGRES_HOST_PORT", "KIND_WATCH_HOST_PORT", "KIND_COORDINATOR_HOST_PORT",
        "KIND_INGRESS_URL", "KIND_INGRESS_TLS_URL", "KIND_ORCHESTRATION_URL",
        "KIND_ORCHESTRATION_HTTP_URL", "KIND_TEMPORAL_ADDRESS", "KIND_TEMPORAL_FRONTEND_URL",
        "KIND_COORDINATOR_DIRECT_URL", "KIND_DATABASE_URL", "KIND_WATCH_ADDR", "KIND_CONFIG", "RUN_DIR",
        "KIND_RETAINED_USE_CLUSTER_WORKSPACE", "KIND_PROFILE_LOCK_TIMEOUT_SECONDS",
        "KIND_WORKSPACE_IMAGE", "KIND_DIND_IMAGE", "KIND_WORKSPACE_LOCAL_IMAGE",
        "KIND_DIND_LOCAL_IMAGE", "APPROVED_KIND_WORKSPACE_IMAGE", "APPROVED_KIND_DIND_IMAGE",
        "CARGO_CI_DIR", "CODEWIRE_KIND_PRODUCT_IMAGE_MODE",
        "CODEWIRE_KIND_EXPECTED_SOURCE_SHA", "CODEWIRE_KIND_SEALED_IMAGES",
        "CODEWIRE_KIND_SEALED_IMAGE_POLICY", "CODEWIRE_KIND_RUNTIME_IMAGE",
        "CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256",
        "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
        "DOCKER_API_VERSION", "CODEWIRE_DOCKER_BIN", "CODEWIRE_KIND_SMOKE_DIR",
        "CODEWIRE_KIND_CREDENTIAL_FIXTURE", "CI", "GITHUB_ACTIONS",
        "CW_RUNTIME_MANAGED_AGENTS",
    }
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update({
        "PATH": environment.get("PATH", "/usr/bin:/bin"),
        "HOME": str(task / "home"), "TMPDIR": str(task / "tmp"),
        "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "SMOKE_CW_INPUT_WITNESS_FILE": str(witness_path),
        "SMOKE_CW_INPUT_WITNESS_SHA256": witness_sha256,
        "CODEWIRE_KIND_PROFILE_ROOT": str(profile.root),
        "KIND_PROFILE_PATH": str(profile.path.with_name("profile.json")),
        "KIND_PROFILE_DOCKER_ID": profile.daemon,
        "KIND_PROFILE_LOCK_FILE": str(profile.path), "KIND_PROFILE_LOCK_FD": str(profile.fd),
        "KUBECONFIG": str(profile.path.with_name("kubeconfig")),
        "KUBE_CONTEXT": "kind-" + profile.cluster,
    })
    for suffix, name in (("A", "release_a"), ("B", "release_b")):
        environment["SMOKE_CW_RELEASE_" + suffix] = witness[name]["release_dir"]
        environment["SMOKE_CW_SHA256_" + suffix] = witness[name]["identity"]["sha256"]
    return environment


class Single(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if getattr(namespace, self.dest, None) is not None or not value:
            parser.error("each CW input must be supplied exactly once with a nonempty value")
        setattr(namespace, self.dest, value)


def arguments(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source-sha", action=Single, required=True)
    for which in ("a", "b"):
        parser.add_argument("--" + which + "-build-json", action=Single, required=True)
        parser.add_argument("--" + which + "-build-sha256", action=Single, required=True)
        parser.add_argument("--" + which + "-sha256", action=Single, required=True)
    parser.add_argument("--support-build-json", action=Single, required=True)
    parser.add_argument("--support-build-sha256", action=Single, required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    selections = {
        "release_" + which: {
            "build_json": getattr(args, which + "_build_json"),
            "build_sha256": getattr(args, which + "_build_sha256"),
            "sha256": getattr(args, which + "_sha256"),
        } for which in ("a", "b")
    }
    selections["support_cw"] = {"build_json": args.support_build_json,
                               "build_sha256": args.support_build_sha256}
    task = None
    result = None
    # Assets and real current source must admit before temporary state or any
    # Kind/API command is allocated or dispatched.
    with admitted_inputs(ROOT, args.source_sha, selections) as (witness, revalidate), \
            closing(ProfileLock(os.environ)) as profile:
        task = Path(tempfile.mkdtemp(prefix="kind-cw-runtime.", dir=ROOT / ".tmp"))
        os.chmod(task, 0o700)
        for name in ("home", "tmp"):
            owner.private_directory(task / name)
        for name in ("release_a", "release_b", "support_cw"):
            witness[name]["release_dir"] = str(stage_release(task, name, witness[name]))
        raw = release.canonical(witness)
        source.require(len(raw) <= 64 * 1024, "CW journey witness exceeds its closed bound")
        with closing(source.asset.Parent(task)) as parent:
            source.asset.write_new(parent.fd, "inputs.json", raw, 0o400)
        witness_path = task / "inputs.json"
        witness_sha256 = hashlib.sha256(raw).hexdigest()
        command = [
            "/usr/bin/bash", "-ceu",
            'source "$1"; run_admitted_cw_runtime_journey "$2"',
            "--", str(ROOT / "scripts/ci/verify/kind/suites/cw-runtime.sh"), str(task),
        ]
        owner.arm_custody()
        for which in (signal.SIGINT, signal.SIGTERM):
            signal.signal(which, owner.on_signal)
        revalidate()
        environment = child_environment(task, witness, witness_path, witness_sha256, profile)
        try:
            with closing(source.asset.HeldFile(witness_path, 64 * 1024,
                         {"sha256": witness_sha256, "size": len(raw)})) as held_witness:
                try:
                    result = run_journey(profile, command, environment, task)
                except ValueError as error:
                    raise failed_completion(error, command, task) from None
                # This records actual child completion, not aggregate runtime
                # qualification. Later source/witness failures remain failures.
                with closing(source.asset.Parent(task)) as parent:
                    source.asset.write_new(parent.fd, "process.json", release.canonical(result), 0o400)
                revalidate()
                held_witness.revalidate(content=True)
                source.require(owner.STOP is None, "CW journey interrupted before final admission")
        except BaseException:
            print("::error::retained CW journey failed; original evidence retained at " + str(task),
                  file=sys.stderr)
            raise
        finally:
            # This log contains only the checked-in synthetic journey's public
            # results. Do not render any producer receipt or configuration.
            if task is not None and (task / "journey.log").is_file():
                with (task / "journey.log").open("rb") as log:
                    while chunk := log.read(64 * 1024):
                        sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
    # Both context exits revalidate their original held inputs. This event is
    # reachable only after those checks and the original c0 ECHILD closure.
    source.require(owner.STOP is None, "CW journey interrupted before final completion")
    print(json.dumps({"event": "cw-runtime-suite-complete", "task": str(task),
                      "input_witness_sha256": witness_sha256,
                      "normal_cleanup": result["cleanup_unknown"] is False
                      and result["unexpected_family"] is False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, release.ReleaseError) as error:
        # Closed admission diagnostics; never print receipt JSON, provider
        # configuration, child environment, or a traceback carrying locals.
        print("::error::CW runtime suite refused: " + str(error), file=sys.stderr)
        raise SystemExit(error.status if isinstance(error, JourneyFailure) else 1) from None
