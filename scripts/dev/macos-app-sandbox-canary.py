#!/usr/bin/env python3
"""Build and run the fixed no-VM macOS App Sandbox canary experiment.

The experiment uses only a synthetic file and test-owned app bundles. It is a
falsification probe for one NSWorkspace deputy path, not App Sandbox or product
confinement qualification. All run artifacts are intentionally retained.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import uuid


PRODUCTS = (
    "sandbox-experiment-owner",
    "sandbox-candidate",
    "canary-deputy",
)
EXPERIMENT = "macos-app-sandbox-canary"
MAX_OUTPUT_BYTES = 64 * 1024
MAX_PRODUCT_BYTES = 256 * 1024 * 1024
OWNER_TIMEOUT_SECONDS = 85
VALID_OBSERVATIONS = frozenset({"succeeded", "denied", "failed", "unknown", "not-run"})
RESULT_KEYS = frozenset(
    {
        "schemaVersion",
        "experiment",
        "property",
        "completion",
        "artifacts",
        "controlDirectRead",
        "controlDeputyRead",
        "candidateDirectRead",
        "candidateDeputyRead",
    }
)


class ExperimentFailure(RuntimeError):
    pass


def file_identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev, status.st_ino, status.st_uid, status.st_gid, status.st_mode,
        status.st_nlink, status.st_size, status.st_mtime_ns, status.st_ctime_ns,
    )


class AdmittedProduct:
    def __init__(self, path: Path, descriptor: int, status: os.stat_result, sha256: str):
        self.path = path
        self.descriptor = descriptor
        self.status = status
        self.sha256 = sha256

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def revalidate(self) -> None:
        identity = file_identity(self.status)
        if (
            self.descriptor < 0
            or file_identity(os.fstat(self.descriptor)) != identity
            or file_identity(os.stat(self.path, follow_symlinks=False)) != identity
        ):
            raise ExperimentFailure("admitted build product changed")
        require_no_quarantine(self.descriptor)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_private(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ExperimentFailure("short private artifact write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_private(path: Path, content: bytes) -> None:
    temporary = path.with_name(path.name + ".next")
    write_private(temporary, content)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def digest_fd(descriptor: int, size: int | None = None) -> str:
    if size is None:
        size = os.fstat(descriptor).st_size
    if not 0 <= size <= MAX_PRODUCT_BYTES:
        raise ExperimentFailure("artifact size is invalid")
    checksum = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise ExperimentFailure("artifact shortened while reading")
        checksum.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise ExperimentFailure("artifact grew while reading")
    return checksum.hexdigest()


def resolved_existing_directory(value: str, label: str, *, private: bool = False) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute():
        raise ExperimentFailure(f"{label} must be absolute")
    resolved = supplied.resolve(strict=True)
    if supplied != resolved or not resolved.is_dir():
        raise ExperimentFailure(f"{label} must be a canonical non-symlink directory")
    status = resolved.stat()
    if status.st_uid != os.getuid() or status.st_mode & 0o022:
        raise ExperimentFailure(f"{label} must be owner-controlled")
    if private and stat.S_IMODE(status.st_mode) != 0o700:
        raise ExperimentFailure(f"{label} must have mode 0700")
    return resolved


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def forbidden_run_roots() -> list[Path]:
    home = Path.home().resolve()
    return [
        Path("/tmp"),
        Path("/private/tmp"),
        Path("/var/tmp"),
        *(home / name for name in ("Desktop", "Documents", "Downloads")),
    ]


def validate_run_roots(build_value: str, artifact_value: str) -> tuple[Path, Path, Path]:
    build_root = resolved_existing_directory(build_value, "build root")
    artifact_root = Path(artifact_value)
    if not artifact_root.is_absolute() or artifact_root.exists() or artifact_root.is_symlink():
        raise ExperimentFailure("artifact root must be an absent absolute path")
    parent = resolved_existing_directory(str(artifact_root.parent), "artifact parent", private=True)
    if artifact_root.parent != parent or artifact_root.name in {"", ".", ".."}:
        raise ExperimentFailure("artifact root must use its canonical private parent")

    if any(is_within(artifact_root, root) for root in forbidden_run_roots()):
        raise ExperimentFailure("artifact and canary roots must avoid broad or TCC locations")

    canary_root = parent / f".{artifact_root.name}-canary"
    if (
        canary_root.exists()
        or canary_root.is_symlink()
        or is_within(canary_root, artifact_root)
        or is_within(canary_root, build_root)
        or any(component.suffix == ".app" for component in canary_root.parents)
    ):
        raise ExperimentFailure("separate canary root is unavailable")
    return build_root, artifact_root, canary_root


def exact_product(build_root: Path, name: str) -> AdmittedProduct:
    path = build_root / name
    if path.is_symlink():
        raise ExperimentFailure("build product must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or status.st_mode & 0o022
            or not status.st_mode & stat.S_IXUSR
            or not 0 < status.st_size <= MAX_PRODUCT_BYTES
        ):
            raise ExperimentFailure("build product identity is invalid")
        require_no_quarantine(descriptor)
        product = AdmittedProduct(path, descriptor, status, digest_fd(descriptor, status.st_size))
        product.revalidate()
        return product
    except BaseException:
        os.close(descriptor)
        raise


def quarantine_attribute_size(path: Path | int) -> int:
    # Apple's system Python does not expose os.getxattr. Use the public Darwin
    # ABI, querying only attribute size/presence; never retrieve its contents.
    if sys.platform != "darwin":
        raise ExperimentFailure("quarantine observation requires Darwin")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    if isinstance(path, int):
        query = library.fgetxattr
        query.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_uint32, ctypes.c_int,
        ]
        target: int | bytes = path
        options = 0
    else:
        query = library.getxattr
        query.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_uint32, ctypes.c_int,
        ]
        target = os.fsencode(path)
        options = 0x0001  # XATTR_NOFOLLOW from the public sys/xattr.h.
    query.restype = ctypes.c_ssize_t
    ctypes.set_errno(0)
    result = query(target, b"com.apple.quarantine", None, 0, 0, options)
    if result < 0:
        raise OSError(ctypes.get_errno() or errno.EIO, "quarantine observation failed")
    return result


def require_no_quarantine(path: Path | int) -> None:
    try:
        quarantine_attribute_size(path)
    except OSError as error:
        # Darwin reports ENOATTR; platforms without it use ENODATA. Numeric
        # errno values are not portable and unsupported observation is not absence.
        missing = getattr(errno, "ENOATTR", getattr(errno, "ENODATA", None))
        if missing is None or error.errno != missing:
            raise
        return
    raise ExperimentFailure("quarantined artifacts are not admitted")


def copy_executable(source: AdmittedProduct, destination: Path) -> str:
    source.revalidate()
    destination_fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
    )
    checksum = hashlib.sha256()
    try:
        offset = 0
        while offset < source.status.st_size:
            chunk = os.pread(
                source.descriptor, min(1024 * 1024, source.status.st_size - offset), offset
            )
            if not chunk:
                raise ExperimentFailure("admitted product shortened during copy")
            offset += len(chunk)
            checksum.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise ExperimentFailure("short executable copy")
                view = view[written:]
        os.fsync(destination_fd)
        source.revalidate()
        if (
            os.pread(source.descriptor, 1, source.status.st_size)
            or checksum.hexdigest() != source.sha256
        ):
            raise ExperimentFailure("admitted product bytes changed during copy")
    finally:
        os.close(destination_fd)
    return checksum.hexdigest()


def info_plist(identifier: str, executable: str, name: str) -> bytes:
    return plistlib.dumps(
        {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleExecutable": executable,
            "CFBundleIdentifier": identifier,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": name,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "LSBackgroundOnly": True,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )


def make_bundle(
    root: Path, name: str, identifier: str, product: AdmittedProduct
) -> tuple[Path, Path, str]:
    bundle = root / f"{name}.app"
    executable = bundle / "Contents" / "MacOS" / product.path.name
    executable.parent.mkdir(parents=True, mode=0o700)
    (bundle / "Contents" / "Resources").mkdir(mode=0o700)
    binary_hash = copy_executable(product, executable)
    write_private(bundle / "Contents" / "Info.plist", info_plist(identifier, product.path.name, name))
    return bundle, executable, binary_hash


def run_checked(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT_BYTES:
        raise ExperimentFailure("fixed artifact command failed")
    return result


def sign_bundle(bundle: Path, identifier: str, entitlements: Path | None = None) -> None:
    command = ["codesign", "--force", "--sign", "-", "--identifier", identifier]
    if entitlements is not None:
        command.extend(["--entitlements", str(entitlements)])
    command.append(str(bundle))
    run_checked(command)


def read_entitlements(bundle: Path) -> dict[str, object]:
    result = run_checked(["codesign", "-d", "--entitlements", ":-", str(bundle)])
    xml = result.stdout.find(b"<?xml")
    if xml < 0:
        return {}
    try:
        value = plistlib.loads(result.stdout[xml:])
    except plistlib.InvalidFileException as error:
        raise ExperimentFailure("signed entitlements are malformed") from error
    if not isinstance(value, dict):
        raise ExperimentFailure("signed entitlements are malformed")
    return value


def verify_bundle(bundle: Path, identifier: str, entitlements: dict[str, object]) -> str:
    run_checked(["codesign", "--verify", "--strict", str(bundle)])
    actual = read_entitlements(bundle)
    if actual != entitlements:
        raise ExperimentFailure("signed entitlements do not match the fixed profile")
    details = run_checked(["codesign", "-d", "--verbose=4", str(bundle)]).stdout
    if f"Identifier={identifier}".encode() not in details:
        raise ExperimentFailure("signed identifier does not match")
    hashes = re.findall(rb"^CDHash=([0-9a-f]+)$", details, flags=re.MULTILINE)
    if len(hashes) != 1:
        raise ExperimentFailure("signed code hash is unavailable")
    for path in [bundle, *bundle.rglob("*")]:
        require_no_quarantine(path)
    return hashes[0].decode()


def child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))


def validate_result(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != RESULT_KEYS:
        raise ExperimentFailure("owner result schema is invalid")
    if (
        type(value.get("schemaVersion")) is not int
        or value.get("schemaVersion") != 1
        or value.get("experiment") != EXPERIMENT
        or value.get("property") not in {"falsified", "not-falsified", "inconclusive"}
        or value.get("completion") not in {"complete", "unknown"}
        or value.get("artifacts") != "retained"
        or any(
            value.get(key) not in VALID_OBSERVATIONS
            for key in RESULT_KEYS
            if key.endswith("Read")
        )
    ):
        raise ExperimentFailure("owner result values are invalid")
    if value["property"] == "not-falsified" and value["completion"] != "complete":
        raise ExperimentFailure("an incomplete experiment cannot support the hypothesis")
    if value["property"] == "not-falsified" and (
        value["controlDirectRead"] != "succeeded"
        or value["controlDeputyRead"] != "succeeded"
        or value["candidateDirectRead"] != "denied"
        or value["candidateDeputyRead"] != "denied"
    ):
        raise ExperimentFailure("support lacks complete controls and candidate denials")
    if value["property"] == "falsified" and not (
        value["controlDirectRead"] == "succeeded"
        and value["controlDeputyRead"] == "succeeded"
        and (
            value["candidateDirectRead"] == "succeeded"
            or (
                value["candidateDirectRead"] == "denied"
                and value["candidateDeputyRead"] == "succeeded"
            )
        )
    ):
        raise ExperimentFailure("falsification lacks a forbidden read")
    return value


def terminate_owned_group(process: subprocess.Popen[bytes]) -> None:
    # execute_owner establishes default SIGCHLD before spawn. This standalone,
    # single-threaded process is the exclusive reaper. A live poll followed by
    # exit leaves a retained zombie pinning the PID until our next wait/poll.
    # Never signal a reaped or unknown child, including before escalation.
    for signum in (signal.SIGTERM, signal.SIGKILL):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue
    raise ExperimentFailure("owned child completion is unknown")


def read_bounded(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or status.st_mode & 0o077
        ):
            raise ExperimentFailure("owner output identity is invalid")
        value = os.read(descriptor, MAX_OUTPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(value) > MAX_OUTPUT_BYTES:
        raise ExperimentFailure("owner output exceeded its bound")
    return value


def read_counterexample(checkpoint: Path, nonce: str) -> dict[str, object] | None:
    try:
        payload = read_bounded(checkpoint)
        value = json.loads(payload)
        if (
            not isinstance(value, dict)
            or set(value) != {"schemaVersion", "experiment", "nonce", "result"}
            or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1
            or value["experiment"] != EXPERIMENT
            or value["nonce"] != nonce
            or payload != canonical_json(value) + b"\n"
        ):
            return None
        result = dict(validate_result(value["result"]))
        if result["property"] != "falsified":
            return None
        result["completion"] = "unknown"
        return result
    except (ExperimentFailure, OSError, ValueError, TypeError):
        return None


def execute_owner(
    executable: Path, configuration: Path, logs: Path, *, checkpoint: Path, nonce: str
) -> dict[str, object]:
    # Actively reset inherited SIG_IGN/SA_NOCLDWAIT before spawning; querying
    # the disposition alone cannot establish retained-child semantics.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    stdout_path = logs / "owner.stdout"
    stderr_path = logs / "owner.stderr"
    stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        process = subprocess.Popen(
            [str(executable), str(configuration)],
            cwd=logs.parent,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            start_new_session=True,
            preexec_fn=child_limits,
        )
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    result: dict[str, object] | None = None
    try:
        try:
            process.wait(timeout=OWNER_TIMEOUT_SECONDS)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            terminate_owned_group(process)
            raise ExperimentFailure("owner completion is unknown")
        stdout = read_bounded(stdout_path)
        if process.returncode != 0 or stdout.count(b"\n") != 1 or not stdout.endswith(b"\n"):
            raise ExperimentFailure("owner did not return one canonical result")
        parsed = dict(validate_result(json.loads(stdout)))
        if stdout[:-1] != canonical_json(parsed):
            raise ExperimentFailure("owner result is not canonical")
        result = parsed
        _ = read_bounded(stderr_path)
    except (ExperimentFailure, OSError, subprocess.SubprocessError, ValueError, TypeError):
        if result is not None and result["property"] == "falsified":
            result["completion"] = "unknown"
            return result
        retained = read_counterexample(checkpoint, nonce)
        if retained is None:
            raise
        return retained
    retained = read_counterexample(checkpoint, nonce)
    if retained is not None and result["property"] != "falsified":
        return retained
    return result


def run(arguments: argparse.Namespace) -> tuple[dict[str, object], int]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ExperimentFailure("the sandbox canary experiment requires Apple Silicon macOS")
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    build_root, artifact_root, canary_root = validate_run_roots(
        arguments.build_root, arguments.artifact_root
    )
    products: dict[str, AdmittedProduct] = {}
    try:
        for name in PRODUCTS:
            products[name] = exact_product(build_root, name)
        return run_admitted(artifact_root, canary_root, products)
    finally:
        for product in products.values():
            product.close()


def run_admitted(
    artifact_root: Path, canary_root: Path, products: dict[str, AdmittedProduct]
) -> tuple[dict[str, object], int]:

    nonce = uuid.uuid4().hex
    identifiers = {
        "owner": f"dev.codewire.sandbox-canary.owner.{nonce}",
        "control": f"dev.codewire.sandbox-canary.control.{nonce}",
        "candidate": f"dev.codewire.sandbox-canary.candidate.{nonce}",
        "deputy": f"dev.codewire.sandbox-canary.deputy.{nonce}",
    }
    artifact_root.mkdir(mode=0o700)
    canary_root.mkdir(mode=0o700)
    bundles = artifact_root / "bundles"
    logs = artifact_root / "logs"
    run_root = artifact_root / "run"
    bundles.mkdir(mode=0o700)
    logs.mkdir(mode=0o700)
    run_root.mkdir(mode=0o700)

    receipt_path = artifact_root / "receipt.json"
    receipt = {
        "schemaVersion": 1,
        "experiment": EXPERIMENT,
        "status": "assembling",
        "artifacts": "retained",
        "artifactRoot": str(artifact_root),
        "canaryRoot": str(canary_root),
        "identifiers": identifiers,
    }
    write_private(receipt_path, canonical_json(receipt))

    canary_path = canary_root / "synthetic-credential"
    canary_bytes = os.urandom(64)
    write_private(canary_path, canary_bytes)
    canary_fd = os.open(canary_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        initial_status = os.fstat(canary_fd)
        expected_hash = digest_fd(canary_fd)

        owner_bundle, owner_executable, owner_hash = make_bundle(
            bundles, "Owner", identifiers["owner"], products["sandbox-experiment-owner"]
        )
        control_bundle, control_executable, candidate_source_hash = make_bundle(
            bundles, "Control", identifiers["control"], products["sandbox-candidate"]
        )
        candidate_bundle, candidate_executable, second_candidate_hash = make_bundle(
            bundles, "Candidate", identifiers["candidate"], products["sandbox-candidate"]
        )
        if candidate_source_hash != second_candidate_hash:
            raise ExperimentFailure("control and candidate executable bytes differ")

        helper_root = candidate_bundle / "Contents" / "Helpers"
        helper_root.mkdir(mode=0o700)
        deputy_bundle, deputy_executable, deputy_hash = make_bundle(
            helper_root, "Deputy", identifiers["deputy"], products["canary-deputy"]
        )
        endpoint_path = run_root / "deputy.sock"
        if len(os.fsencode(endpoint_path)) >= 104:
            raise ExperimentFailure("artifact root is too long for the fixed Unix endpoint")
        deputy_configuration = {
            "schemaVersion": 1,
            "nonce": nonce,
            "endpointPath": str(endpoint_path),
            "canaryPath": str(canary_path),
        }
        write_private(
            deputy_bundle / "Contents" / "Resources" / "run-config.json",
            canonical_json(deputy_configuration),
        )
        candidate_entitlements = run_root / "candidate-entitlements.plist"
        write_private(
            candidate_entitlements,
            plistlib.dumps(
                {"com.apple.security.app-sandbox": True},
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            ),
        )

        sign_bundle(deputy_bundle, identifiers["deputy"])
        sign_bundle(candidate_bundle, identifiers["candidate"], candidate_entitlements)
        sign_bundle(control_bundle, identifiers["control"])
        sign_bundle(owner_bundle, identifiers["owner"])
        bundle_hashes = {
            "deputy": verify_bundle(deputy_bundle, identifiers["deputy"], {}),
            "candidate": verify_bundle(
                candidate_bundle,
                identifiers["candidate"],
                {"com.apple.security.app-sandbox": True},
            ),
            "control": verify_bundle(control_bundle, identifiers["control"], {}),
            "owner": verify_bundle(owner_bundle, identifiers["owner"], {}),
        }

        owner_configuration = {
            "schemaVersion": 1,
            "nonce": nonce,
            "canaryPath": str(canary_path),
            "expectedCanarySHA256": expected_hash,
            "endpointPath": str(endpoint_path),
            "controlExecutable": str(control_executable),
            "candidateExecutable": str(candidate_executable),
            "deputyBundlePath": str(deputy_bundle),
            "deputyExecutable": str(deputy_executable),
            "controlBundleIdentifier": identifiers["control"],
            "candidateBundleIdentifier": identifiers["candidate"],
            "deputyBundleIdentifier": identifiers["deputy"],
            "controlCDHash": bundle_hashes["control"],
            "candidateCDHash": bundle_hashes["candidate"],
            "deputyCDHash": bundle_hashes["deputy"],
            "checkpointPath": str(run_root / "owner-checkpoint.json"),
        }
        configuration_path = run_root / "owner-config.json"
        write_private(configuration_path, canonical_json(owner_configuration))
        receipt.update(
            {
                "status": "started",
                "executableSHA256": {
                    "owner": owner_hash,
                    "candidate": candidate_source_hash,
                    "deputy": deputy_hash,
                },
                "bundleCDHash": bundle_hashes,
                "system": {
                    "macOS": run_checked(["sw_vers", "-productVersion"])
                    .stdout.decode()
                    .strip(),
                    "sdk": run_checked(["xcrun", "--show-sdk-version"])
                    .stdout.decode()
                    .strip(),
                },
            }
        )
        replace_private(receipt_path, canonical_json(receipt))

        result = execute_owner(
            owner_executable, configuration_path, logs,
            checkpoint=run_root / "owner-checkpoint.json", nonce=nonce,
        )
        try:
            final_status = os.stat(canary_path, follow_symlinks=False)
            unchanged: bool | None = (
                stat.S_ISREG(final_status.st_mode)
                and final_status.st_uid == initial_status.st_uid
                and final_status.st_gid == initial_status.st_gid
                and final_status.st_dev == initial_status.st_dev
                and final_status.st_ino == initial_status.st_ino
                and final_status.st_nlink == initial_status.st_nlink == 1
                and final_status.st_size == initial_status.st_size
                and stat.S_IMODE(final_status.st_mode)
                == stat.S_IMODE(initial_status.st_mode)
                == 0o600
                and final_status.st_mtime_ns == initial_status.st_mtime_ns
                and digest_fd(canary_fd) == expected_hash
            )
        except FileNotFoundError:
            unchanged = False
        except (OSError, ExperimentFailure):
            unchanged = None
        if unchanged is not True:
            if result["property"] != "falsified":
                result["property"] = "inconclusive"
            result["completion"] = "unknown"
        receipt.update(
            {
                "status": "completed" if result["completion"] == "complete" else "unknown",
                "result": result,
                "canaryUnchanged": unchanged,
            }
        )
        try:
            replace_private(receipt_path, canonical_json(receipt))
        except OSError:
            if result["property"] != "falsified":
                raise
        if result["property"] == "not-falsified" and result["completion"] == "complete":
            return result, 0
        if result["property"] == "falsified":
            return result, 2
        return result, 1
    finally:
        os.close(canary_fd)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        result, status = run(parse_arguments(argv))
    except (ExperimentFailure, OSError, subprocess.SubprocessError, ValueError):
        result = {
            "schemaVersion": 1,
            "experiment": EXPERIMENT,
            "property": "inconclusive",
            "completion": "unknown",
            "artifacts": "retained",
            "controlDirectRead": "unknown",
            "controlDeputyRead": "unknown",
            "candidateDirectRead": "unknown",
            "candidateDeputyRead": "unknown",
        }
        status = 1
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
