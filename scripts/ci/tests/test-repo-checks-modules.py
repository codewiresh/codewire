#!/usr/bin/env python3
"""Golden compatibility fixture for the repository-policy dispatcher."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/checks/repo_checks.py"
sys.path.insert(0, str(CHECKER.parent))

from repo_policy import (  # noqa: E402 - dispatcher directory is the import root
    edge_routing,
    idp_security,
    licensing,
    mesh,
    orchestration_security,
    permanent_raw,
    production,
    proto,
    source_classification,
)


COMMANDS = {
    "connect-edge-routing": (edge_routing.check_connect_edge_routing, "connect edge routing: OK", True),
    "permanent-raw-surface": (
        permanent_raw.check_permanent_raw_surface,
        "permanent raw surface: OK",
        True,
    ),
    "mesh-surface-freeze": (mesh.check_mesh_surface_freeze, "mesh final surface: OK", True),
    "proto-package-boundaries": (
        proto.check_proto_package_boundaries,
        "proto package boundaries: OK",
        True,
    ),
    "license-map": (licensing.check_license_map, "license map: OK", False),
    "rust-validation-source": (
        source_classification.check_rust_validation_source,
        "rust validation source: OK",
        False,
    ),
    "retired-reference-source": (
        source_classification.check_retired_reference_source,
        "retired reference guard: OK",
        False,
    ),
    "go-source-classification": (
        source_classification.check_go_source_classification,
        "Go source classification guard: OK",
        False,
    ),
    "production-source-ownership": (
        production.check_production_source_ownership,
        "production source ownership: OK",
        True,
    ),
    "orchestration-host-key-authz": (
        orchestration_security.check_orchestration_host_key_authz,
        "orchestration host-key authorization: OK",
        True,
    ),
    "idp-signing-kek-isolation": (
        idp_security.check_idp_signing_kek_isolation,
        "idp signing KEK isolation: static OK",
        False,
    ),
}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_success(command: str, expected: str, self_test: bool) -> None:
    args = [command]
    if self_test:
        args.append("--self-test")
    result = run(*args)
    if result.returncode != 0 or expected not in result.stdout:
        raise AssertionError(
            f"{command}: expected exit 0 and {expected!r}; exit={result.returncode}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )


def main() -> None:
    help_result = run("--help")
    if help_result.returncode != 0:
        raise AssertionError(f"--help failed: {help_result.stderr}")
    for command, (checker, _expected, _self_test) in COMMANDS.items():
        if command not in help_result.stdout:
            raise AssertionError(f"--help no longer exposes {command}")
        if not checker.__module__.startswith("repo_policy."):
            raise AssertionError(f"{command} is not owned by a policy-domain module")
        assert_success(command, _expected, _self_test)

    invalid = run("not-a-policy-command")
    if invalid.returncode != 2 or "invalid choice" not in invalid.stderr:
        raise AssertionError(
            f"invalid command contract changed: exit={invalid.returncode}; stderr={invalid.stderr!r}"
        )

    print(f"repo policy module fixture: OK ({len(COMMANDS)} commands)")


if __name__ == "__main__":
    main()
