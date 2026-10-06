from .shared import *


# ---------------------------------------------------------------------------
# Package license policy

def check_license_map(_args: argparse.Namespace) -> int:
    failures: list[str] = []

    canonical_licenses = {
        "AGPL-3.0-only": (
            "LICENSE",
            "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0",
        ),
        "MIT": (
            "LICENSE-MIT",
            "9d7d7be3a6331ef710cf4747b47584de9cad5fb2cbd135f5c455039eb414c97f",
        ),
        "Apache-2.0": (
            "LICENSE-APACHE",
            "f31c91d1278c0590110d023f34ecc5825ec897dd3aa4693cc374fd6c4b86914d",
        ),
        "BSD-3-Clause": (
            "LICENSE-BSD-3-CLAUSE",
            "1dba73130cc42806fcd2a72bc3452bcb72e82d525fcad1cc80af795b880302ba",
        ),
    }

    def toml(rel: str) -> dict[str, Any]:
        with (ROOT / rel).open("rb") as handle:
            return tomllib.load(handle)

    def check_copy(rel: str, license_name: str) -> None:
        canonical_rel = canonical_licenses[license_name][0]
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"{rel}: missing packaged {license_name} text")
            return
        if path.read_bytes() != (ROOT / canonical_rel).read_bytes():
            failures.append(f"{rel}: differs from canonical {canonical_rel}")

    for license_name, (rel, expected_sha256) in canonical_licenses.items():
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"{rel}: missing canonical {license_name} text")
            continue
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            failures.append(
                f"{rel}: canonical {license_name} text hash {actual_sha256}, "
                f"expected {expected_sha256}"
            )

    root_manifest = toml("Cargo.toml")
    workspace_license = root_manifest.get("workspace", {}).get("package", {}).get("license")
    if workspace_license != "AGPL-3.0-only":
        failures.append(
            f"Cargo.toml: workspace license {workspace_license!r}, expected 'AGPL-3.0-only'"
        )

    cargo_declarations = {
        "crates/codewire-access/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-admin-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-billing/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-cli-bin/Cargo.toml": "workspace",
        "crates/codewire-cli/Cargo.toml": "workspace",
        "crates/codewire-client/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-coordinator/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-credential-bridge/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-credential-broker/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-credential-service/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-dashboard-web/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-daemon/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-daemon-bridge/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-derp/Cargo.toml": "BSD-3-Clause",
        "crates/codewire-egress-broker/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-egress-policy/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-desktop/Cargo.toml": "MIT",
        "crates/codewire-email/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-gateway-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-gateway/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-idp/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-local-credentials/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-local-vmm/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-mesh/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-netstack/Cargo.toml": "BSD-3-Clause",
        "crates/codewire-oidc/Cargo.toml": "MIT OR Apache-2.0",
        "crates/codewire-orchestration/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-platform-credentials/Cargo.toml": "workspace",
        "crates/codewire-project-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-project/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-protected-store/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-proto/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-server-core/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-tailnet/Cargo.toml": "BSD-3-Clause",
        "crates/codewire-tls/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-types/Cargo.toml": "MIT",
        "crates/codewire-udp-relay/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-ui/Cargo.toml": "MIT",
        "crates/codewire-vmm-guest-probe/Cargo.toml": "AGPL-3.0-only",
        "crates/codewire-workload-secrets/Cargo.toml": "workspace",
        "crates/codewire-workspace-access/Cargo.toml": "AGPL-3.0-only",
    }
    actual_cargo_manifests = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "crates").glob("*/Cargo.toml")
    }
    if actual_cargo_manifests != set(cargo_declarations):
        failures.append(
            "Cargo package inventory differs from the accepted license map: "
            f"missing={sorted(set(cargo_declarations) - actual_cargo_manifests)}, "
            f"unclassified={sorted(actual_cargo_manifests - set(cargo_declarations))}"
        )

    for rel, declaration in cargo_declarations.items():
        package = toml(rel).get("package", {})
        actual = package.get("license")
        expected = {"workspace": True} if declaration == "workspace" else declaration
        if actual != expected:
            failures.append(f"{rel}: license declaration {actual!r}, expected {expected!r}")
        effective = "AGPL-3.0-only" if declaration == "workspace" else declaration
        crate_dir = Path(rel).parent
        if effective == "MIT OR Apache-2.0":
            check_copy((crate_dir / "LICENSE-MIT").as_posix(), "MIT")
            check_copy((crate_dir / "LICENSE-APACHE").as_posix(), "Apache-2.0")
        else:
            check_copy((crate_dir / "LICENSE").as_posix(), effective)

    docker_workspace_licenses = {
        "deployments/docker/gateway.Cargo.toml": "AGPL-3.0-only",
        "deployments/docker/derp.Cargo.toml": "BSD-3-Clause",
    }
    for rel, expected in docker_workspace_licenses.items():
        actual = toml(rel).get("workspace", {}).get("package", {}).get("license")
        if actual != expected:
            failures.append(f"{rel}: workspace license {actual!r}, expected {expected!r}")

    npm_licenses = {
        "package.json": "AGPL-3.0-only",
        "apps/dashboard/package.json": "AGPL-3.0-only",
        "libs/sdk-ts/package.json": "MIT",
        "packages/codewire-proto-ts/package.json": "MIT",
    }
    actual_package_json = {
        rel
        for rel in git_source_files()
        if rel == "package.json" or rel.endswith("/package.json")
    }
    if actual_package_json != set(npm_licenses):
        failures.append(
            "npm package inventory differs from the accepted license map: "
            f"missing={sorted(set(npm_licenses) - actual_package_json)}, "
            f"unclassified={sorted(actual_package_json - set(npm_licenses))}"
        )
    for rel, expected in npm_licenses.items():
        actual = read_json(rel).get("license")
        if actual != expected:
            failures.append(f"{rel}: license {actual!r}, expected {expected!r}")
        if rel == "package.json":
            check_copy("LICENSE", expected)
        else:
            check_copy((Path(rel).parent / "LICENSE").as_posix(), expected)

    python_licenses = {
        "libs/sdk-python/pyproject.toml": (
            "MIT",
            ["LICENSE", "LICENSE-APACHE"],
        ),
    }
    actual_pyprojects = {
        rel for rel in git_source_files() if rel.endswith("pyproject.toml")
    }
    if actual_pyprojects != set(python_licenses):
        failures.append(
            "Python package inventory differs from the accepted license map: "
            f"missing={sorted(set(python_licenses) - actual_pyprojects)}, "
            f"unclassified={sorted(actual_pyprojects - set(python_licenses))}"
        )
    for rel, (expected, expected_files) in python_licenses.items():
        project = toml(rel).get("project", {})
        if project.get("license") != expected:
            failures.append(
                f"{rel}: license {project.get('license')!r}, expected {expected!r}"
            )
        if project.get("license-files") != expected_files:
            failures.append(
                f"{rel}: license-files {project.get('license-files')!r}, "
                f"expected {expected_files!r}"
            )
        package_dir = Path(rel).parent
        check_copy((package_dir / "LICENSE").as_posix(), expected)
        if "LICENSE-APACHE" in expected_files:
            check_copy(
                (package_dir / "LICENSE-APACHE").as_posix(),
                "Apache-2.0",
            )

    go_licenses = {
        "libs/gen-go/go.mod": "MIT",
        "libs/sdk-go/go.mod": "MIT",
        "libs/tailnet/go.mod": "BSD-3-Clause",
        "tests/contract/go.mod": "AGPL-3.0-only",
    }
    actual_go_modules = {rel for rel in git_source_files() if rel.endswith("go.mod")}
    if actual_go_modules != set(go_licenses):
        failures.append(
            "Go module inventory differs from the accepted license map: "
            f"missing={sorted(set(go_licenses) - actual_go_modules)}, "
            f"unclassified={sorted(actual_go_modules - set(go_licenses))}"
        )
    for rel, expected in go_licenses.items():
        check_copy((Path(rel).parent / "LICENSE").as_posix(), expected)

    apache_copies = [
        "crates/codewire-admin-proto/LICENSE-APACHE",
        "crates/codewire-proto/LICENSE-APACHE",
        "libs/gen-go/LICENSE-APACHE",
        "libs/gen-python/LICENSE-APACHE",
        "libs/sdk-python/LICENSE-APACHE",
        "packages/codewire-proto-ts/LICENSE-APACHE",
        "proto/LICENSE-APACHE",
    ]
    for rel in apache_copies:
        check_copy(rel, "Apache-2.0")

    claims = {
        "README.md": [
            "Open source under AGPL-3.0-only.",
            "Codewire is licensed under AGPL-3.0-only.",
        ],
        "crates/README.md": [
            "The root workspace default is **AGPL-3.0-only**.",
            "a combined distribution must therefore satisfy the",
            "AGPL-3.0-only obligations for the combined work.",
        ],
        "apps/cli/nfpm.yaml": ["license: AGPL-3.0-only"],
        "apps/cli/aur/PKGBUILD": ["license=('AGPL-3.0-only')"],
        "aur/PKGBUILD": ["license=('MIT')"],
    }
    for rel, expected_fragments in claims.items():
        text = read_text(rel)
        for fragment in expected_fragments:
            if fragment not in text:
                failures.append(f"{rel}: missing accepted license claim {fragment!r}")
    check_copy("apps/cli/LICENSE", "AGPL-3.0-only")

    if failures:
        for failure in failures:
            print(f"license map: {failure}", file=sys.stderr)
        return 1
    print(
        "license map: OK "
        f"({len(cargo_declarations)} Cargo packages, "
        f"{len(npm_licenses)} npm packages, "
        f"{len(python_licenses)} Python packages, "
        f"{len(go_licenses)} Go modules)"
    )
    return 0
