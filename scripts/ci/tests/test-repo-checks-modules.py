#!/usr/bin/env python3
"""Golden compatibility fixture for the repository-policy dispatcher."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


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
    ses_security,
    turnstile_security,
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
    "ses-email-isolation": (
        ses_security.check_ses_sender_isolation,
        "ses email isolation: static OK",
        False,
    ),
    "turnstile-access-projection": (
        turnstile_security.check_turnstile_access_projection,
        "turnstile access projection: static OK",
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


def assert_turnstile_negative_fixtures() -> None:
    overlays = [
        "deployments/k8s/overlays/dev",
        "deployments/k8s/overlays/production",
        "deployments/k8s/overlays/local-kind",
        "deployments/k8s/overlays/local-kind-static",
    ]
    rendered = {
        overlay: subprocess.run(
            ["kustomize", "build", overlay],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        for overlay in overlays
    }

    def assert_rejected(
        label: str,
        overlay: str,
        old: str,
        new: str,
        expected: str,
    ) -> None:
        fixture = rendered.copy()
        if fixture[overlay].count(old) != 1:
            raise AssertionError(f"{label}: fixture mutation target is not unique")
        fixture[overlay] = fixture[overlay].replace(old, new)

        def fake_run(args: list[str], **_: object) -> SimpleNamespace:
            if args[:2] != ["kustomize", "build"] or args[2] not in fixture:
                raise AssertionError(f"{label}: unexpected command {args!r}")
            return SimpleNamespace(stdout=fixture[args[2]])

        stderr = io.StringIO()
        with patch.object(turnstile_security, "run", side_effect=fake_run), redirect_stderr(stderr):
            result = turnstile_security.check_turnstile_access_projection(None)
        if result != 1 or expected not in stderr.getvalue():
            raise AssertionError(
                f"{label}: expected rejection containing {expected!r}; "
                f"exit={result}; stderr={stderr.getvalue()!r}"
            )

    dev = "deployments/k8s/overlays/dev"
    production = "deployments/k8s/overlays/production"
    assert_rejected(
        "missing-dev-widget-key",
        dev,
        "  TURNSTILE_SITE_KEY: 0x4AAAAAAE2ghrxixpYKpljB\n",
        '  TURNSTILE_SITE_KEY: ""\n',
        "hostname-bound Dev key",
    )
    assert_rejected(
        "wrong-idp-secret",
        dev,
        "              name: codewire-idp-turnstile\n",
        "              name: codewire-idp-turnstile-wrong\n",
        "IdP must require only TURNSTILE_SECRET_KEY",
    )
    assert_rejected(
        "optional-idp-secret",
        dev,
        "              name: codewire-idp-turnstile\n",
        "              name: codewire-idp-turnstile\n              optional: true\n",
        "IdP must require only TURNSTILE_SECRET_KEY",
    )
    assert_rejected(
        "wrong-idp-hostname",
        dev,
        "        - name: FRONTEND_URL\n          value: https://codewire-dev.sh\n",
        "        - name: FRONTEND_URL\n          value: https://wrong.invalid\n",
        "bind Turnstile verification to https://codewire-dev.sh",
    )
    assert_rejected(
        "active-production-widget",
        production,
        '  TURNSTILE_SITE_KEY: ""\n',
        "  TURNSTILE_SITE_KEY: 0x4AAAAAAE2ghrxixpYKpljB\n",
        "must contain an empty value",
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

    assert_turnstile_negative_fixtures()

    invalid = run("not-a-policy-command")
    if invalid.returncode != 2 or "invalid choice" not in invalid.stderr:
        raise AssertionError(
            f"invalid command contract changed: exit={invalid.returncode}; stderr={invalid.stderr!r}"
        )

    print(f"repo policy module fixture: OK ({len(COMMANDS)} commands)")


if __name__ == "__main__":
    main()
