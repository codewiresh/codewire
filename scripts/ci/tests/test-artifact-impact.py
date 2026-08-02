#!/usr/bin/env python3
"""Focused cumulative artifact-impact selector fixtures."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
CLASSIFIER = ROOT / "scripts/ci/select/artifact-impact.py"


def run(
    args: list[str],
    *,
    cwd: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        env={**os.environ, "CARGO_NET_OFFLINE": "true"},
    )


class Fixture:
    def __init__(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="codewire-artifact-impact."))
        self.repo = self.temp / "repo"
        run(["git", "clone", "--quiet", "--shared", str(ROOT), str(self.repo)], cwd=ROOT)
        run(["git", "config", "user.name", "Artifact Impact Test"], cwd=self.repo)
        run(
            ["git", "config", "user.email", "artifact-impact@example.invalid"],
            cwd=self.repo,
        )
        run(["git", "config", "commit.gpgsign", "false"], cwd=self.repo)
        # Each fixture creates many commits.  Disable Git's background
        # maintenance so it cannot recreate a file while close() removes the
        # disposable clone.
        run(["git", "config", "maintenance.auto", "false"], cwd=self.repo)
        run(["git", "config", "gc.auto", "0"], cwd=self.repo)
        self.base = run(["git", "rev-parse", "HEAD"], cwd=self.repo).stdout.strip()

    def close(self) -> None:
        # A Git process started before the local maintenance setting took
        # effect can still finish asynchronously.  Retry only that transient
        # directory-entry race; every other cleanup error remains a failure.
        for attempt in range(5):
            try:
                shutil.rmtree(self.temp)
                return
            except OSError as error:
                if error.errno != errno.ENOTEMPTY or attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def reset(self, name: str) -> None:
        run(["git", "reset", "--hard", self.base], cwd=self.repo)
        run(["git", "clean", "-fdx"], cwd=self.repo)
        run(["git", "checkout", "-B", f"case-{name}", self.base], cwd=self.repo)

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], cwd=self.repo)
        run(["git", "commit", "--quiet", "-m", message], cwd=self.repo)
        return run(["git", "rev-parse", "HEAD"], cwd=self.repo).stdout.strip()

    def append(self, path: str, value: str) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as stream:
            stream.write(value)

    def replace(self, path: str, before: str, after: str) -> None:
        target = self.repo / path
        content = target.read_text(encoding="utf-8")
        if before not in content:
            raise AssertionError(f"{before!r} missing from {path}")
        target.write_text(content.replace(before, after, 1), encoding="utf-8")

    def select(
        self,
        mode: str,
        base: str,
        head: str,
    ) -> dict[str, str]:
        result = run(
            [
                "python3",
                str(CLASSIFIER),
                "select",
                "--mode",
                mode,
                "--base",
                base,
                "--head",
                head,
            ],
            cwd=self.repo,
        )
        return dict(
            line.split("=", 1)
            for line in result.stdout.splitlines()
            if "=" in line
        )

    def assert_selected(
        self,
        name: str,
        expected: bool,
        *,
        mode: str = "runtime",
        base: str | None = None,
        head: str | None = None,
    ) -> dict[str, str]:
        result = self.select(mode, base or self.base, head or self.head())
        actual = result.get("selected")
        expected_text = "true" if expected else "false"
        if actual != expected_text:
            raise AssertionError(
                f"{name}: expected selected={expected_text}, got {result}"
            )
        return result

    def head(self) -> str:
        return run(["git", "rev-parse", "HEAD"], cwd=self.repo).stdout.strip()


def main() -> None:
    fixture = Fixture()
    try:
        fixture.assert_selected(
            "empty range",
            False,
            base=fixture.base,
            head=fixture.base,
        )

        fixture.reset("docs")
        fixture.append("docs/selector-neutral.md", "neutral\n")
        fixture.commit("docs only")
        fixture.assert_selected("repository docs", False)

        fixture.reset("unknown")
        fixture.append("unexplained/new-surface.txt", "ordinary\n")
        fixture.commit("ordinary unknown")
        fixture.assert_selected("ordinary unknown", False)

        fixture.reset("license")
        fixture.append("crates/codewire-cli/LICENSE-TEST", "synthetic legal text\n")
        fixture.commit("legal text")
        fixture.assert_selected("runtime legal text", False)
        fixture.assert_selected("support legal text", False, mode="support")

        fixture.reset("cargo-presentation")
        fixture.replace(
            "Cargo.toml",
            'authors = ["Sonica"]',
            'authors = ["Sonica Contributors"]',
        )
        fixture.commit("cargo presentation")
        fixture.assert_selected("runtime Cargo presentation", False)
        fixture.assert_selected("support Cargo presentation", False, mode="support")

        fixture.reset("cargo-version")
        fixture.replace("Cargo.toml", 'version = "0.1.0"', 'version = "0.1.1"')
        fixture.commit("cargo version")
        fixture.assert_selected("runtime Cargo version", True)
        fixture.assert_selected("support Cargo version", True, mode="support")

        fixture.reset("npm-presentation")
        package_path = fixture.repo / "package.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
        package["license"] = "AGPL-3.0-or-later"
        package_path.write_text(
            json.dumps(package, indent=2) + "\n",
            encoding="utf-8",
        )
        fixture.commit("npm presentation")
        fixture.assert_selected("npm presentation", False)

        fixture.reset("npm-dependency")
        fixture.replace(
            "package.json",
            '"turbo": "2.9.16"',
            '"turbo": "2.9.17"',
        )
        fixture.commit("npm dependency")
        fixture.assert_selected("npm dependency", True)

        fixture.reset("rust-source")
        fixture.append("crates/codewire-cli/src/lib.rs", "\n// selector fixture\n")
        fixture.commit("runtime source")
        fixture.assert_selected("runtime Rust source", True)
        fixture.assert_selected("support Rust source", True, mode="support")

        fixture.reset("rust-test")
        fixture.append("crates/codewire-cli/tests/selector-neutral.rs", "// test\n")
        fixture.commit("test only")
        fixture.assert_selected("runtime test-only path", False)
        fixture.assert_selected("support test-only path", False, mode="support")

        fixture.reset("dashboard")
        fixture.append("apps/dashboard/src/selector-fixture.ts", "export {};\n")
        fixture.commit("dashboard source")
        fixture.assert_selected("dashboard source", True)

        fixture.reset("dashboard-design")
        fixture.append("packages/codewire-design/styles.css", "\n/* selector fixture */\n")
        fixture.commit("dashboard design source")
        fixture.assert_selected("dashboard design source", True)

        fixture.reset("product-docs")
        fixture.append("apps/docs/src/content/docs/selector-fixture.md", "# Built\n")
        fixture.commit("built docs source")
        fixture.assert_selected("built product docs", True)

        fixture.reset("dev-render")
        fixture.append(
            "deployments/k8s/base/namespace.yaml",
            "\n# selector fixture\n",
        )
        fixture.commit("dev render source")
        fixture.assert_selected("transitive dev render", True)

        fixture.reset("prod-only")
        fixture.append(
            "deployments/k8s/overlays/prod/kustomization.yaml",
            "\n# selector fixture\n",
        )
        fixture.commit("production only")
        fixture.assert_selected("production-only state", False)

        fixture.reset("local-kind")
        fixture.append(
            "deployments/k8s/overlays/local-kind/kustomization.yaml",
            "\n# selector fixture\n",
        )
        fixture.commit("local kind only")
        fixture.assert_selected("local-kind-only state", False)

        fixture.reset("local-image-helper")
        fixture.append(
            "scripts/ci/images/build-local-image.sh",
            "\n# local verification fixture\n",
        )
        local_image_head = fixture.commit("local image verification helper")
        fixture.assert_selected("local image helper runtime", False)
        fixture.assert_selected(
            "local image helper support",
            False,
            mode="support",
        )
        fixture.append("docs/local-image-neutral.md", "neutral\n")
        cumulative_local_head = fixture.commit("neutral follow-up")
        fixture.assert_selected(
            "cumulative local image helper range",
            False,
            base=fixture.base,
            head=cumulative_local_head,
        )
        fixture.assert_selected(
            "neutral range after local image helper",
            False,
            base=local_image_head,
            head=cumulative_local_head,
        )

        fixture.reset("image-publication-helper")
        fixture.append(
            "scripts/ci/images/build-push-image.sh",
            "\n# publication fixture\n",
        )
        fixture.commit("image publication helper")
        publication = fixture.assert_selected("publication helper runtime", True)
        if "image-publication" not in publication.get("matched_categories", ""):
            raise AssertionError(
                f"publication helper category mismatch: {publication}"
            )
        fixture.assert_selected(
            "publication helper support",
            True,
            mode="support",
        )

        fixture.reset("support-base")
        fixture.append("images/base/entrypoint.sh", "\n# selector fixture\n")
        fixture.commit("support base")
        fixture.assert_selected("support base input", True, mode="support")
        fixture.assert_selected("support input is not dev runtime", False)

        fixture.reset("rename")
        source = fixture.repo / "crates/codewire-cli/src/lib.rs"
        renamed = fixture.repo / "crates/codewire-cli/src/lib-renamed.rs"
        source.rename(renamed)
        fixture.commit("rename runtime source")
        fixture.assert_selected("runtime source rename", True)

        fixture.reset("cumulative")
        fixture.append("crates/codewire-cli/src/lib.rs", "\n// material A\n")
        material = fixture.commit("material A")
        fixture.append("docs/cumulative-neutral.md", "neutral B\n")
        cumulative_head = fixture.commit("neutral B")
        fixture.assert_selected(
            "latest commit alone",
            False,
            base=material,
            head=cumulative_head,
        )
        fixture.assert_selected(
            "deployed cumulative range",
            True,
            base=fixture.base,
            head=cumulative_head,
        )

        fixture.reset("nonancestor-side")
        fixture.append("docs/side.md", "side\n")
        side = fixture.commit("side")
        fixture.reset("nonancestor-head")
        fixture.append("docs/head.md", "head\n")
        nonancestor_head = fixture.commit("head")
        result = fixture.assert_selected(
            "non-ancestor baseline",
            True,
            base=side,
            head=nonancestor_head,
        )
        if result.get("reason") != "baseline_not_ancestor":
            raise AssertionError(f"non-ancestor reason mismatch: {result}")

        invalid = fixture.assert_selected(
            "invalid baseline",
            True,
            base="f" * 40,
            head=nonancestor_head,
        )
        if invalid.get("reason") != "baseline_invalid":
            raise AssertionError(f"invalid baseline reason mismatch: {invalid}")

        fixture.reset("malformed-manifest")
        fixture.append("Cargo.toml", "\n[malformed\n")
        fixture.commit("malformed relevant manifest")
        malformed = fixture.assert_selected("malformed relevant manifest", True)
        if malformed.get("reason") != "relevant_definition_ambiguous":
            raise AssertionError(f"malformed manifest reason mismatch: {malformed}")

        fixture.reset("contract")
        fixture.append("new-runtime-input.txt", "runtime\n")
        dockerfile = fixture.repo / "deployments/docker/mesh.Dockerfile"
        content = dockerfile.read_text(encoding="utf-8")
        dockerfile.write_text(
            content.replace(
                "COPY proto ./proto",
                "COPY proto ./proto\nCOPY new-runtime-input.txt ./new-runtime-input.txt",
                1,
            ),
            encoding="utf-8",
        )
        fixture.commit("new Docker source root")
        fixture.assert_selected("new Docker source root", True)
        contract = run(
            [
                "python3",
                str(CLASSIFIER),
                "check-contract",
                "--mode",
                "runtime",
            ],
            cwd=fixture.repo,
            check=False,
        )
        if contract.returncode == 0 or "uncovered source root" not in contract.stderr:
            raise AssertionError(
                f"uncovered Docker root did not fail contract: {contract.stderr}"
            )

        fixture.reset("kustomize-contract")
        fixture.replace(
            "deployments/k8s/overlays/dev/kustomization.yaml",
            "resources:\n  - ../../base",
            "resources: [../../base]",
        )
        fixture.commit("unsupported Kustomize source form")
        kustomize = fixture.assert_selected("ambiguous Kustomize contract", True)
        if kustomize.get("reason") != "relevant_definition_ambiguous":
            raise AssertionError(f"Kustomize ambiguity reason mismatch: {kustomize}")
        kustomize_contract = run(
            [
                "python3",
                str(CLASSIFIER),
                "check-contract",
                "--mode",
                "runtime",
            ],
            cwd=fixture.repo,
            check=False,
        )
        if (
            kustomize_contract.returncode == 0
            or "inline Kustomize file list" not in kustomize_contract.stderr
        ):
            raise AssertionError(
                "unsupported Kustomize source form did not fail the contract"
            )
    finally:
        fixture.close()

    print("[test-artifact-impact] cumulative and semantic fixtures passed")


if __name__ == "__main__":
    main()
