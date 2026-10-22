#!/usr/bin/env python3
"""Focused contracts for the parallel Kind build workflow and consumer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".gitea/workflows/ci.yaml"
COMMON = ROOT / "scripts/ci/verify/kind/common.sh"
CREDENTIALS = ROOT / "scripts/ci/verify/kind/credentials.sh"
INTEGRATED = ROOT / "scripts/ci/verify/kind/suites/integrated.sh"
SELECTOR = ROOT / "scripts/ci/select/select-verification.sh"

CHECKOUT = (
    "https://git.example.invalid/noel/actions-checkout@"
    "34e114876b0b11c390a56381ad16ebd13914f8d5"
)
UPLOAD = (
    "https://git.example.invalid/noel/actions-upload-artifact@"
    "c6a3b2bd78b3985e4b2f15397fec357f0fd808de"
)
DOWNLOAD = (
    "https://git.example.invalid/noel/actions-download-artifact@"
    "ad191675b41f6a5b46da9a048cb6893812da158b"
)
PRODUCERS = {
    "kind-workspace": "workspace",
    "kind-product": "product",
    "kind-daemon": "daemon",
    "kind-smokes": "smokes",
}
# A superseded main run builds no Kind producer; main's newer run does.
PRODUCER_IF = (
    "${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' "
    "&& needs.verification-selection.outputs.superseded != 'true' "
    "&& contains(needs.verification-selection.outputs.selection, '|kind|') }}"
)
# A pinned workspace has no producer job: each shard writes its pin record.
PINNED = "needs.verification-selection.outputs.kind_workspace_source == 'pinned'"
WORKSPACE_PRODUCER_IF = PRODUCER_IF.removesuffix(" }}") + (
    " && needs.verification-selection.outputs.kind_workspace_source != 'pinned' }}"
)
KIND_STEP_IF = (
    "${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' "
    "&& contains(needs.verification-selection.outputs.selection, '|kind|') }}"
)


def named_step(job: dict, name: str) -> dict:
    matches = [step for step in job["steps"] if step.get("name") == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one step named {name!r}, got {len(matches)}")
    return matches[0]


def action_steps(job: dict, action: str) -> list[dict]:
    return [step for step in job["steps"] if step.get("uses") == action]


def selection_fields(output: str) -> tuple[str, set[str], str]:
    fields = dict(line.split("=", 1) for line in output.splitlines())
    envelope = fields["selection"]
    if not envelope.startswith("|valid:v3|") or not envelope.endswith("|complete|"):
        raise AssertionError(f"invalid selection envelope: {envelope}")
    tokens = set(envelope.removeprefix("|valid:v3|").removesuffix("complete|").split("|"))
    tokens.discard("")
    return fields["classification"], tokens, fields["required_local_mode"]


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        cls.jobs = cls.workflow["jobs"]

    def test_producers_are_independent_exact_head_builds(self) -> None:
        for job_name, group in PRODUCERS.items():
            with self.subTest(job=job_name):
                job = self.jobs[job_name]
                self.assertEqual(job["needs"], ["verification-selection"])
                self.assertEqual(
                    job["if"], WORKSPACE_PRODUCER_IF if job_name == "kind-workspace" else PRODUCER_IF)
                expected_outputs = {
                    "artifact_name": "${{ steps.export.outputs.artifact_name }}",
                    "manifest_sha256": "${{ steps.export.outputs.manifest_sha256 }}",
                }
                self.assertEqual(
                    job["outputs"],
                    expected_outputs,
                )
                checkouts = action_steps(job, CHECKOUT)
                self.assertEqual(len(checkouts), 1)
                self.assertEqual(
                    [step for step in job["steps"]
                     if "actions-checkout@" in step.get("uses", "")],
                    checkouts,
                )
                self.assertEqual(checkouts[0].get("with"), {
                    "ref": "${{ github.sha }}",
                    "persist-credentials": False,
                })
                export = named_step(job, next(
                    step["name"] for step in job["steps"] if step.get("id") == "export"
                ))
                self.assertRegex(
                    export["run"],
                    rf"(?:^|\s)python3 -B scripts/ci/verify/kind-build-artifacts\.py "
                    rf"produce {group} \"\$RUNNER_TEMP/kind-{group}-out\"$",
                )

    def test_native_uploads_follow_successful_exports(self) -> None:
        for job_name, group in PRODUCERS.items():
            with self.subTest(job=job_name):
                job = self.jobs[job_name]
                uploads = action_steps(job, UPLOAD)
                self.assertEqual(len(uploads), 1)
                self.assertEqual(
                    [step for step in job["steps"]
                     if "actions-upload-artifact@" in step.get("uses", "")],
                    uploads,
                )
                upload = uploads[0]
                self.assertNotIn("if", upload, "upload must retain default success() semantics")
                self.assertNotIn("continue-on-error", upload)
                self.assertEqual(upload["with"], {
                    "name": "${{ steps.export.outputs.artifact_name }}",
                    "path": f"${{{{ runner.temp }}}}/kind-{group}-out/",
                    "if-no-files-found": "error",
                    "retention-days": 1,
                })
                export_index = next(
                    index for index, step in enumerate(job["steps"])
                    if step.get("id") == "export"
                )
                self.assertGreater(job["steps"].index(upload), export_index)

    def test_service_and_daemon_images_build_on_separate_producers(self) -> None:
        product = named_step(self.jobs["kind-product"], "Build exact Kind service images")
        self.assertEqual(product["run"], "scripts/ci/images/build-kind-images.sh dashboard services mesh")
        daemon = named_step(self.jobs["kind-daemon"], "Build exact Kind daemon image")
        self.assertEqual(daemon["run"], "scripts/ci/images/build-kind-images.sh daemon")
        for job_name in ("kind-product", "kind-daemon"):
            with self.subTest(job=job_name):
                job = self.jobs[job_name]
                # A main push's Heavy jobs take the runners reserved for main.
                self.assertEqual(job["runs-on"], "${{ github.event_name == 'push' && "
                                 "github.ref == 'refs/heads/main' && 'ci-heavy-main' || 'ci-heavy' }}")
                cache = named_step(job, "Select existing compiler cache")
                clean = named_step(job, "Clean compiler cache credentials")
                self.assertEqual(clean["if"], "${{ always() }}")
                self.assertLess(job["steps"].index(cache), job["steps"].index(clean))

    def test_kind_workspace_takes_the_pin_unless_the_definition_changed(self) -> None:
        selection = self.jobs["verification-selection"]
        self.assertEqual(
            selection["outputs"]["kind_workspace_source"],
            "${{ steps.kind-workspace.outputs.kind_workspace_source }}",
        )
        choose = next(step for step in selection["steps"] if step.get("id") == "kind-workspace")
        self.assertIn("kind-build-artifacts.py workspace-source", choose["run"])
        self.assertIn('--head "$GITHUB_SHA" --base "$base" --github-output', choose["run"])
        self.assertEqual(choose["env"], {
            "PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
            "PUSH_BEFORE_SHA": "${{ github.event.before }}",
        })
        for event, expected in (("pull_request", "pr-base"), ("push", "push-before"),
                                ("workflow_dispatch", ""), ("schedule", "")):
            with self.subTest(event=event):
                script = choose["run"].replace(
                    "python3 -B scripts/ci/verify/kind-build-artifacts.py workspace-source",
                    'printf "%s\\n"')
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c", script],
                    env={"PATH": os.environ["PATH"], "GITHUB_EVENT_NAME": event,
                         "GITHUB_SHA": "head", "PR_BASE_SHA": "pr-base",
                         "PUSH_BEFORE_SHA": "push-before"},
                    capture_output=True, text=True, check=True,
                )
                self.assertEqual(result.stdout.splitlines(),
                                 ["--head", "head", "--base", expected, "--github-output"])

        # A pinned workspace dispatches no producer job; the job that runs
        # always builds the exact source, with no per-step source condition.
        job = self.jobs["kind-workspace"]
        self.assertEqual(job["if"], WORKSPACE_PRODUCER_IF)
        self.assertNotIn("CODEWIRE_KIND_WORKSPACE_SOURCE", job.get("env", {}))
        for step in job["steps"]:
            self.assertNotIn("CODEWIRE_KIND_WORKSPACE_SOURCE", step.get("if", ""))
        build = named_step(job, "Build and verify exact source workspace")
        self.assertEqual(build["run"], "scripts/ci/verify/verify-workspace-image.sh")
        self.assertEqual(named_step(job, "Export verified workspace")["run"],
                         'python3 -B scripts/ci/verify/kind-build-artifacts.py produce workspace '
                         '"$RUNNER_TEMP/kind-workspace-out"')

        # Each shard writes the pin record with the same producer, into the
        # same private input directory a download would fill, and binds its
        # own manifest digest; it downloads no workspace when pinned.
        edge = self.jobs["edge-kind"]
        record = named_step(edge, "Write the pinned workspace record")
        self.assertEqual(record["id"], "pinned-workspace")
        self.assertEqual(record["if"], KIND_STEP_IF.removesuffix(" }}") + " && " + PINNED + " }}")
        self.assertEqual(record["env"], {"CODEWIRE_KIND_WORKSPACE_SOURCE": "pinned"})
        self.assertEqual(record["run"],
                         'python3 -B scripts/ci/verify/kind-build-artifacts.py produce workspace '
                         '"$CODEWIRE_KIND_ARTIFACT_ROOT/workspace"')
        guard = named_step(edge, "Require fresh artifact download directories outside the checkout")
        gate = named_step(edge, "Run the shard Kind gate")
        self.assertLess(edge["steps"].index(guard), edge["steps"].index(record))
        self.assertLess(edge["steps"].index(record), edge["steps"].index(gate))
        self.assertEqual(
            gate["env"]["CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256"],
            "${{ " + PINNED + " && steps.pinned-workspace.outputs.manifest_sha256 "
            "|| needs.kind-workspace.outputs.manifest_sha256 }}",
        )

    def test_smoke_producer_installs_pinned_protoc_before_build(self) -> None:
        producer = self.jobs["kind-smokes"]
        install = named_step(producer, "Install pinned protoc for Rust compilation")
        build = named_step(producer, "Build all host smoke and contract binaries")
        self.assertLess(producer["steps"].index(install), producer["steps"].index(build))
        self.assertIn("protoc-35.1-linux-x86_64.zip", install["run"])
        self.assertIn(
            "6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7",
            install["run"],
        )
        self.assertFalse(any(
            step.get("name") == "Install pinned protoc for Rust compilation"
            for step in self.jobs["edge-kind"]["steps"]
        ))

    def test_edge_kind_waits_for_exact_successful_producers(self) -> None:
        edge = self.jobs["edge-kind"]
        self.assertEqual(
            edge["needs"],
            ["verification-selection", "kind-workspace", "kind-product", "kind-daemon", "kind-smokes"],
        )
        expected_if = (
            "${{ always() && needs.verification-selection.result == 'success' && "
            "needs.verification-selection.outputs.edge_kind_expected == 'true' && "
            "(needs.verification-selection.outputs.tested_tree_receipt == 'accepted' || "
            "!contains(needs.verification-selection.outputs.selection, '|kind|') || "
            "((needs.kind-workspace.result == 'success' || "
            "(needs.verification-selection.outputs.kind_workspace_source == 'pinned' && "
            "needs.kind-workspace.result == 'skipped')) && "
            "needs.kind-product.result == 'success' && "
            "needs.kind-daemon.result == 'success' && "
            "needs.kind-smokes.result == 'success')) }}"
        )
        self.assertEqual(" ".join(edge["if"].split()), " ".join(expected_if.split()))

        def admitted(*, selection_ok: bool = True, expected: bool = True,
                     receipt: bool = False, kind: bool = True, pinned: bool = False,
                     producer_results: tuple[str, ...] = ("success",) * 4) -> bool:
            workspace, *others = producer_results
            workspace_ok = workspace == "success" or (pinned and workspace == "skipped")
            return (selection_ok and expected
                    and (receipt or not kind
                         or (workspace_ok and all(item == "success" for item in others))))

        self.assertTrue(admitted(kind=False, producer_results=("skipped",) * 4))
        self.assertTrue(admitted(kind=True, producer_results=("success",) * 4))
        self.assertFalse(admitted(kind=True, producer_results=("success", "failure", "success", "success")))
        self.assertFalse(admitted(kind=True, producer_results=("success", "success", "skipped", "success")))
        self.assertTrue(admitted(receipt=True, producer_results=("skipped",) * 4))
        self.assertFalse(admitted(selection_ok=False, kind=False, producer_results=("skipped",) * 4))
        self.assertTrue(admitted(pinned=True, producer_results=("skipped",) + ("success",) * 3))
        self.assertFalse(admitted(pinned=False, producer_results=("skipped",) + ("success",) * 3))
        self.assertFalse(admitted(pinned=True, producer_results=("failure",) + ("success",) * 3))

    def test_kind_consumer_selects_a_private_saved_profile(self) -> None:
        edge = self.jobs["edge-kind"]
        kind = named_step(edge, "Run the shard Kind gate")
        self.assertEqual(kind["if"], KIND_STEP_IF)
        self.assertEqual(kind.get("env"), {
            "KIND_CLUSTER_NAME": "codewire-e2e-ci-${{ github.run_id }}-${{ matrix.shard.slug }}",
            "CLUSTER": "codewire-e2e-ci-${{ github.run_id }}-${{ matrix.shard.slug }}",
            "CODEWIRE_KIND_PROFILE_ROOT": "${{ runner.temp }}/kind-profiles",
            "KIND_SHARD_SUITES": "${{ matrix.shard.suites }}",
            "CODEWIRE_KIND_DASHBOARD_WORKERS": "${{ matrix.shard.playwright_workers }}",
            "CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256": (
                "${{ " + PINNED + " && steps.pinned-workspace.outputs.manifest_sha256 "
                "|| needs.kind-workspace.outputs.manifest_sha256 }}"),
        })
        self.assertNotIn("CLUSTER", edge["env"],
                         "static fixtures must not inherit an uncreated profile")

    def test_consumer_downloads_bound_manifests_outside_checkout(self) -> None:
        edge = self.jobs["edge-kind"]
        self.assertEqual(edge["env"]["CODEWIRE_KIND_PRODUCT_IMAGE_MODE"], "prebuilt-ci")
        # Forgejo resolves job-level env before the runner context exists.
        self.assertNotIn("CODEWIRE_KIND_ARTIFACT_ROOT", edge["env"])
        for job_name, group in PRODUCERS.items():
            if group == "workspace":
                # Bound by the gate step, from the shard's pin record when pinned.
                self.assertNotIn("CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256", edge["env"])
                continue
            self.assertEqual(
                edge["env"][f"CODEWIRE_KIND_{group.upper()}_MANIFEST_SHA256"],
                f"${{{{ needs.{job_name}.outputs.manifest_sha256 }}}}",
            )

        guard = named_step(edge, "Require fresh artifact download directories outside the checkout")
        self.assertEqual(guard["if"], KIND_STEP_IF)
        for contract in (
            'CODEWIRE_KIND_ARTIFACT_ROOT="$RUNNER_TEMP/kind-inputs"',
            'test ! -e "$CODEWIRE_KIND_ARTIFACT_ROOT"',
            'test ! -L "$CODEWIRE_KIND_ARTIFACT_ROOT"',
            'case "$(realpath "$RUNNER_TEMP")" in',
            '"$GITHUB_WORKSPACE"|"$GITHUB_WORKSPACE"/*) exit 1',
            'mkdir -m 700 "$CODEWIRE_KIND_ARTIFACT_ROOT"',
            '''printf 'CODEWIRE_KIND_ARTIFACT_ROOT=%s\\n' "$CODEWIRE_KIND_ARTIFACT_ROOT" >> "$GITHUB_ENV"''',
        ):
            self.assertIn(contract, guard["run"])

        guard_index = edge["steps"].index(guard)
        downloads = action_steps(edge, DOWNLOAD)
        self.assertEqual(len(downloads), 4)
        self.assertEqual(
            [step for step in edge["steps"]
             if "actions-download-artifact@" in step.get("uses", "")],
            downloads,
        )
        for job_name, group in PRODUCERS.items():
            with self.subTest(group=group):
                matches = [step for step in downloads
                           if step["with"].get("path") == f"${{{{ runner.temp }}}}/kind-inputs/{group}"]
                self.assertEqual(len(matches), 1)
                download = matches[0]
                self.assertGreater(edge["steps"].index(download), guard_index)
                self.assertEqual(
                    download["if"],
                    KIND_STEP_IF.removesuffix(" }}")
                    + " && needs.verification-selection.outputs.kind_workspace_source != 'pinned' }}"
                    if group == "workspace" else KIND_STEP_IF)
                self.assertEqual(
                    download["with"]["name"],
                    f"${{{{ needs.{job_name}.outputs.artifact_name }}}}",
                )

    def test_consumer_has_no_build_or_cache_fallback(self) -> None:
        edge = self.jobs["edge-kind"]
        commands = "\n".join(
            step.get("run", "") for step in edge["steps"] if "run" in step
        )
        for forbidden in (
            "build-kind-images.sh",
            "build-kind-smokes.sh",
            "verify-workspace-image.sh",
            "rehearse-build-local-image.sh",
            "select-untrusted-rust-cache.sh",
            "finish-untrusted-rust-cache.sh",
            "cargo build",
            "cargo test",
        ):
            self.assertNotIn(forbidden, commands)
        shard = named_step(edge, "Run the shard Kind gate")
        self.assertIn('scripts/ci/verify/kind-e2e.sh shard "${suites[@]}"', shard["run"])

    def test_edge_kind_shards_cover_the_gate_on_per_shard_clusters(self) -> None:
        edge = self.jobs["edge-kind"]
        self.assertEqual(edge["timeout-minutes"], 45)
        self.assertEqual(
            edge["name"], "Edge / Kind verification (${{ matrix.shard.slug }})",
        )
        expected_shards = [
            {
                "slug": "environment",
                "suites": "workspace-services final-fencing runtime-acceptance",
            },
            {
                "slug": "dashboard",
                "suites": "dashboard-browser",
                "playwright_workers": 4,
            },
            # The credentials suite is the gate's longest; it runs alone so
            # the gate's wall time is not its sum with the workspace suites.
            {"slug": "workspace", "suites": "credentials"},
            {"slug": "edge", "suites": "edge-contract integrated"},
        ]
        self.assertEqual(
            edge["strategy"],
            {"fail-fast": True, "matrix": {"shard": expected_shards}},
        )

        cluster_name = "codewire-e2e-ci-${{ github.run_id }}-${{ matrix.shard.slug }}"
        kind_step_names = (
            "Run the shard Kind gate",
            "Delete the shard Kind cluster",
        )
        for step_name in kind_step_names:
            with self.subTest(step=step_name):
                step = named_step(edge, step_name)
                self.assertEqual(step["env"]["KIND_CLUSTER_NAME"], cluster_name)
                self.assertEqual(step["env"]["CLUSTER"], cluster_name)
                self.assertEqual(step["env"]["CODEWIRE_KIND_PROFILE_ROOT"],
                                 "${{ runner.temp }}/kind-profiles")
        shard = named_step(edge, "Run the shard Kind gate")
        self.assertIn('scripts/ci/verify/kind-e2e.sh shard "${suites[@]}"', shard["run"])
        self.assertEqual(
            shard["env"]["CODEWIRE_KIND_DASHBOARD_WORKERS"],
            "${{ matrix.shard.playwright_workers }}",
        )
        indices = [edge["steps"].index(named_step(edge, name)) for name in kind_step_names]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(
            named_step(edge, "Delete the shard Kind cluster")["run"],
            'scripts/ci/verify/kind-e2e.sh down || true',
        )
        # A failed dashboard leg uploads its Playwright test results before
        # teardown; no other leg has browser output to preserve.
        upload = named_step(edge, "Upload dashboard browser test results on failure")
        self.assertEqual(upload["uses"], UPLOAD)
        self.assertEqual(
            upload["if"],
            "${{ failure() && needs.verification-selection.outputs.tested_tree_receipt != 'accepted'"
            " && matrix.shard.slug == 'dashboard' }}",
        )
        self.assertEqual(upload["with"], {
            "name": "kind-dashboard-test-results-${{ github.run_id }}-${{ matrix.shard.slug }}",
            "path": "apps/dashboard/test-results/",
            "if-no-files-found": "ignore",
            "retention-days": 5,
        })
        self.assertLess(
            edge["steps"].index(upload),
            edge["steps"].index(named_step(edge, "Delete the shard Kind cluster")),
        )
        # Every dashboard run, green or red, uploads its JSON report: per-test
        # durations, retries and outcomes (#2974).
        report = named_step(edge, "Upload dashboard browser JSON report")
        self.assertEqual(report["uses"], UPLOAD)
        self.assertEqual(
            report["if"],
            "${{ always() && needs.verification-selection.outputs.tested_tree_receipt != 'accepted'"
            " && contains(needs.verification-selection.outputs.selection, '|kind|')"
            " && matrix.shard.slug == 'dashboard' }}",
        )
        self.assertEqual(report["with"], {
            "name": "kind-dashboard-json-report-${{ github.run_id }}-${{ matrix.shard.slug }}",
            "path": "apps/dashboard/test-report/",
            "if-no-files-found": "ignore",
            "retention-days": 14,
        })
        config = (ROOT / "apps/dashboard/playwright.config.ts").read_text(encoding="utf-8")
        self.assertIn(
            '["json", { outputFile: path.join(dashboardDir, "test-report/results.json") }]', config,
        )
        self.assertLess(
            edge["steps"].index(report),
            edge["steps"].index(named_step(edge, "Delete the shard Kind cluster")),
        )

        # Edge static verification needs no cluster: it runs once, in tooling,
        # so an edge-only selection starts no Kind leg. The locked browser
        # host dependencies belong only to the dashboard leg.
        self.assertNotIn(
            "Run Edge static verification and selected Kind tool tests", [step.get("name") for step in edge["steps"]],
        )
        self.assertIn(
            "contains(needs.verification-selection.outputs.selection, '|edge_kind|')",
            named_step(self.jobs["tooling"], "Run Edge static verification and selected Kind tool tests")["if"],
        )
        for step_name in ("Install locked dashboard browser-test dependencies",):
            self.assertIn(
                "matrix.shard.slug == 'dashboard'", named_step(edge, step_name)["if"],
            )
        bun = [step for step in edge["steps"] if "setup-bun@" in step.get("uses", "")]
        self.assertEqual(len(bun), 1)
        self.assertIn("matrix.shard.slug == 'dashboard'", bun[0]["if"])

        # Every mapped suite dispatches to a retained suite, and their union
        # covers every probe group of the serial integrated gate: edge/host-key
        # (edge-contract), coordinator and billing (integrated), credentials
        # bootstrap and native (credentials), workspace services and Temporal
        # workflow (workspace-services), final fencing, dashboard browser, and
        # TTL acceptance. Sandbox supply-chain provenance is covered only
        # nested inside that TTL acceptance, while its product-created
        # workspace is alive; no shard invokes it standalone because every
        # workspace-service fixture self-cleans. The serial gate's remaining
        # static step, ingress_path_drift_check, runs inside run_kind_up ahead
        # of every shard's image build.
        dispatcher = (ROOT / "scripts/ci/verify/kind-e2e.sh").read_text(encoding="utf-8")
        suites = [suite for shard in expected_shards for suite in shard["suites"].split()]
        for suite in suites:
            with self.subTest(suite=suite):
                self.assertIn(f"\n    {suite})\n", dispatcher)
        self.assertEqual(set(suites), {
            "edge-contract", "integrated", "credentials", "workspace-services",
            "final-fencing", "dashboard-browser", "runtime-acceptance",
        })
        self.assertNotIn("sandbox-supply-chain", suites)
        ttl_smoke = (ROOT / "crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs")
        self.assertIn('.args(["suite", "sandbox-supply-chain"])',
                      ttl_smoke.read_text(encoding="utf-8"))
        up_source = (ROOT / "scripts/ci/verify/kind/suites/up.sh").read_text(encoding="utf-8")
        up_body = up_source.split("run_kind_up() {", 1)[1]
        self.assertLess(
            up_body.index("ingress_path_drift_check"),
            up_body.index("build_images_and_smokes"),
        )
        self.assertIn("edge-kind", self.jobs["required-verification"]["needs"])

    def test_shard_teardown_requires_the_saved_cluster_identity(self) -> None:
        edge = self.jobs["edge-kind"]
        shard = named_step(edge, "Run the shard Kind gate")
        teardown = named_step(edge, "Delete the shard Kind cluster")
        self.assertEqual(shard["env"]["CLUSTER"], teardown["env"]["CLUSTER"])
        self.assertEqual(shard["env"]["CODEWIRE_KIND_PROFILE_ROOT"],
                         teardown["env"]["CODEWIRE_KIND_PROFILE_ROOT"])
        self.assertEqual(teardown["run"], "scripts/ci/verify/kind-e2e.sh down || true")
        for step in edge["steps"]:
            self.assertNotIn("kind delete cluster", step.get("run", ""))

    def test_download_guard_exports_only_a_fresh_external_directory(self) -> None:
        guard = named_step(
            self.jobs["edge-kind"],
            "Require fresh artifact download directories outside the checkout",
        )["run"]
        for case in ("fresh", "existing", "symlink", "checkout", "inside-checkout"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workspace = root / "checkout"
                workspace.mkdir()
                runtime = (workspace if case == "checkout" else
                           workspace / "temp" if case == "inside-checkout" else
                           root / "temp")
                runtime.mkdir(exist_ok=True)
                artifact_root = runtime / "kind-inputs"
                if case == "existing":
                    artifact_root.mkdir()
                elif case == "symlink":
                    artifact_root.symlink_to(root / "missing")
                env_file = root / "github-env"
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c", guard],
                    env={
                        "PATH": os.environ["PATH"],
                        "RUNNER_TEMP": str(runtime),
                        "GITHUB_WORKSPACE": str(workspace),
                        "GITHUB_ENV": str(env_file),
                    },
                    capture_output=True, text=True, check=False,
                )
                if case == "fresh":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(artifact_root.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(
                        env_file.read_text(encoding="utf-8"),
                        f"CODEWIRE_KIND_ARTIFACT_ROOT={artifact_root}\n",
                    )
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(env_file.exists())

    def test_integrated_runtime_order_remains_atomic(self) -> None:
        source = INTEGRATED.read_text(encoding="utf-8")
        body = source.split("  trap cleanup EXIT", 1)[1].split('  log "green"', 1)[0]
        calls = [call for call in re.findall(r"^  ([a-z][a-z0-9_]*)(?: \|\| return \$\?)?$", body, flags=re.MULTILINE) if call != "fi"]
        self.assertEqual(calls, [
            "ingress_path_drift_check",
            "build_images_and_smokes",
            "create_cluster",
            "load_images_into_kind",
            "deploy_overlay",
            "orchestration_authorization_smoke",
            "edge_routing_probes",
            "connect_edge_probes",
            "coordinator_runtime_smokes",
            "billing_contract_through_ingress",
            "deploy_agent_sandbox_and_smoke",
            "dashboard_browser_e2e",
            "rust_reconciler_ttl_e2e",
        ])


class CoordinatorFixtureLifetimeTests(unittest.TestCase):
    """Execute the real owner with synthetic commands, never a live cluster."""

    @staticmethod
    def owner_source() -> str:
        source = COMMON.read_text(encoding="utf-8")
        return source.split("coordinator_runtime_smokes() {", 1)[1].split(
            "\ncoordinator_ingress_smoke() {", 1
        )[0]

    def run_owner(self, failure: str = "", premature_cleanup: bool = False):
        body = self.owner_source()
        if premature_cleanup:
            # Reproduce the prior lifetime, not a weaker coordinator: retire
            # and remove the backend immediately before the public consumers.
            body = body.replace(
                "    mesh_product_connect_ownership_smoke\n",
                "    printf stopped >\"$FIXTURE/state\"\n"
                "    rm -f \"$FIXTURE/backend\"\n"
                "    mesh_product_connect_ownership_smoke\n",
                1,
            )
        harness = r'''
set -euo pipefail
NS=codewire-e2e
ROOT=/synthetic-codewire
KIND_INGRESS_URL=http://127.0.0.1:8090
KIND_COORDINATOR_DIRECT_URL=http://127.0.0.1:18092
KIND_POSTGRES_LOCAL_IMAGE=synthetic-postgres
CARGO_CI_DIR=/synthetic-codewire/target/ci
PROBE_HEADERS="$FIXTURE/headers"
printf stopped >"$FIXTURE/state"
record() { printf '%s\n' "$1" >>"$FIXTURE/events"; }
log() { :; }
sleep() { /usr/bin/sleep 0.01; }
kubectl_apply() {
  if [ "${!#}" = - ]; then
    local manifest
    manifest="$(cat)"
    case "$manifest" in
      *$'\nkind: SandboxClaim\n'*)
        record runtime-created
        touch "$FIXTURE/runtime"
        ;;
      *$'\nkind: Sandbox\n'*|*$'\nkind: Pod\n'*) [ -f "$FIXTURE/runtime" ] || return 61 ;;
      *) return 61 ;;
    esac
    printf '%s\n---\n' "$manifest" >>"$FIXTURE/objects.yaml"
  fi
}
kubectl() {
  local args="$*" sql state
  case "$args" in
    *' exec -i deploy/postgres '*)
      sql="$(cat)"
      if [[ "$sql" == *"state = 'stopped'"* ]]; then
        record retire
        printf '%s\n' "$sql" >"$FIXTURE/retire.sql"
        [ "$FAILURE" != retirement ] || return 41
        printf stopped >"$FIXTURE/state"
        rm -f "$FIXTURE/backend"
      else
        record admit
        printf '%s\n' "$sql" >"$FIXTURE/admit.sql"
        [ -f "$FIXTURE/runtime" ] || return 62
        touch "$FIXTURE/backend"
        printf running >"$FIXTURE/state"
      fi
      ;;
    *' get pod '*) printf '10.244.0.9' ;;
    *' get sandboxclaim '*) printf 'claim-uid' ;;
    *' get sandbox '*) printf 'sandbox-uid' ;;
    *' get configmap codewire-orchestration-internal-roots '*)
      printf '%s\n' '-----BEGIN CERTIFICATE-----' 'synthetic' '-----END CERTIFICATE-----'
      ;;
    *' port-forward '*)
      printf 'Forwarding from 127.0.0.1:23456 -> 8088\n'
      exec /usr/bin/sleep 60
      ;;
    *' delete sandboxclaim '*|*' delete sandbox '*|*' delete pod '*)
      if [ -f "$FIXTURE/runtime" ] && [ "$(<"$FIXTURE/state")" = stopped ]; then
        record runtime-deleted
        rm -f "$FIXTURE/runtime"
      fi
      ;;
    *' patch sandboxclaim '*) printf '%s\n' "${!#}" >"$FIXTURE/claim-status.json" ;;
    'wait '*|*' wait '*) : ;;
    *) printf 'unexpected synthetic kubectl: %s\n' "$args" >&2; return 63 ;;
  esac
}
peer_token_for_environment() {
  [ "$1" = 00000000-0000-4000-8000-000000000501 ] || return 65
  printf synthetic-peer
}
curl_settled() {
  PROBE_BODY='{"code":"unauthenticated"}'
  if [[ "$*" == *:23456:127.0.0.1* && "$*" == *https://codewire-orchestration.*:23456/* ]]; then
    [ -f "$FIXTURE/backend" ] && [ "$(<"$FIXTURE/state")" = running ] || return 64
    record internal
    PROBE_CODE=401
    [ "$FAILURE" != internal ] || PROBE_CODE=200
    printf 'x-codewire-service: codewire-orchestration-internal\n' >"$PROBE_HEADERS"
  else
    PROBE_CODE=404
    printf 'x-codewire-service: codewire-orchestration\n' >"$PROBE_HEADERS"
  fi
}
mesh_product_connect_ownership_smoke() {
  record mesh
  [ "$FAILURE" != mesh ] || return 33
}
coordinator_ingress_smoke() {
  [ -f "$FIXTURE/backend" ] && [ "$(<"$FIXTURE/state")" = running ] || return 66
  [ "$KIND_COORDINATOR_SIDECAR_TOKEN" = synthetic-peer ] || return 68
  record coordinator
  [ "$FAILURE" != coordinator ] || return 37
}
'''
        with tempfile.TemporaryDirectory(prefix="codewire-coordinator-lifetime-") as directory:
            fixture = Path(directory)
            result = subprocess.run(
                ["bash", "-c", harness + "\ncoordinator_runtime_smokes() {" + body
                 + "\ncoordinator_runtime_smokes\nrecord downstream\n"],
                env={"PATH": os.environ["PATH"], "FIXTURE": directory, "FAILURE": failure},
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertTrue((fixture / "events").exists(), result.stderr)
            events = (fixture / "events").read_text().splitlines()
            sql = {
                name: (fixture / f"{name}.sql").read_text()
                for name in ("admit", "retire")
                if (fixture / f"{name}.sql").exists()
            }
            runtime = {
                name: (fixture / name).read_text()
                for name in ("objects.yaml", "claim-status.json")
                if (fixture / name).exists()
            }
            return result, events, sql, runtime

    def test_shared_runtime_survives_every_consumer_then_retires(self) -> None:
        result, events, sql, _ = self.run_owner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [
            "runtime-created", "admit", "internal", "internal", "mesh", "coordinator",
            "retire", "runtime-deleted", "downstream",
        ])
        for transaction in sql.values():
            self.assertTrue(transaction.startswith("BEGIN;\n"))
            self.assertTrue(transaction.endswith("COMMIT;\n"))
        self.assertLess(sql["admit"].index("INSERT INTO sandbox_environment_backend"),
                        sql["admit"].index("SET state = 'running'"))
        self.assertLess(sql["retire"].index("SET state = 'stopped'"),
                        sql["retire"].index("DELETE FROM sandbox_environment_backend"))

    def test_prior_premature_cleanup_is_rejected(self) -> None:
        result, events, _, _ = self.run_owner(premature_cleanup=True)
        self.assertEqual(result.returncode, 66, result.stderr)
        self.assertIn("mesh", events)
        self.assertNotIn("coordinator", events)
        self.assertNotIn("downstream", events)
        self.assertEqual(events.count("retire"), 1)

    def test_probe_failures_preserve_status_and_always_cleanup(self) -> None:
        for failure, status, absent in (
            ("internal", 1, "mesh"), ("mesh", 33, "coordinator"),
            ("coordinator", 37, "downstream"),
        ):
            with self.subTest(failure=failure):
                result, events, _, _ = self.run_owner(failure=failure)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(events.count("retire"), 1)
                self.assertEqual(events.count("runtime-deleted"), 1)
                self.assertNotIn(absent, events)
                self.assertNotIn("downstream", events)

    def test_runtime_is_reachable_only_through_the_bound_chain(self) -> None:
        # Program #2238 B2: orchestration resolves the workspace Pod through
        # Claim status -> bound Sandbox -> the Pod that Sandbox controls, with
        # no Claim-name fallback. The admitted fixture must be that chain.
        result, _, sql, runtime = self.run_owner()
        self.assertEqual(result.returncode, 0, result.stderr)
        objects = [item for item in yaml.safe_load_all(runtime["objects.yaml"]) if item]
        by_kind: dict[str, list[dict]] = {}
        for item in objects:
            by_kind.setdefault(item["kind"], []).append(item)
        [claim] = by_kind["SandboxClaim"]
        [sandbox] = by_kind["Sandbox"]
        claim_name = claim["metadata"]["name"]
        self.assertEqual(claim_name, "sandbox-00000000-0000-4000-8000-000000000501")

        status = json.loads(runtime["claim-status.json"])["status"]
        self.assertEqual(status["sandbox"]["name"], sandbox["metadata"]["name"])
        self.assertIn({"type": "Ready", "status": "True"},
                      [{"type": c["type"], "status": c["status"]} for c in status["conditions"]])
        self.assertEqual(sandbox["metadata"]["ownerReferences"], [{
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
            "name": claim_name, "uid": "claim-uid", "controller": True,
        }])

        pod_name = sandbox["metadata"]["annotations"]["agents.x-k8s.io/pod-name"]
        self.assertNotEqual(pod_name, claim_name)
        [workspace] = [pod for pod in by_kind["Pod"] if pod["metadata"]["name"] == pod_name]
        self.assertEqual(workspace["metadata"]["labels"]["codewire.sh/type"], "workspace")
        self.assertEqual(workspace["metadata"]["ownerReferences"], [{
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "name": sandbox["metadata"]["name"], "uid": "sandbox-uid", "controller": True,
        }])
        self.assertIn(f"'codewire-e2e', '{pod_name}', '10.244.0.9'", sql["admit"])

    def test_retirement_failure_cannot_pass_or_remove_live_runtime(self) -> None:
        result, events, _, _ = self.run_owner(failure="retirement")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed to retire", result.stderr)
        self.assertNotIn("runtime-deleted", events)
        self.assertNotIn("downstream", events)

    def test_seed_is_not_running_before_runtime_admission(self) -> None:
        seed = (ROOT / "tests/e2e/kind/coordinator-seed.sql").read_text()
        self.assertIn("state, desired_state, name", seed)
        self.assertRegex(seed, r"'sandbox',\s*'stopped',\s*'stopped',")
        # A peer token is refused at generation 0, the column default.
        self.assertRegex(seed, r"environment_operation_generation\n\)")
        self.assertRegex(seed, r"'::jsonb,\s*1\s*\);")

    def test_peer_token_matches_the_coordinator_wire_vector(self) -> None:
        # The Rust issuer pins an independently computed vector; the shell
        # minter must produce exactly that token for the same claims.
        rust = (ROOT / "crates/codewire-server-core/src/peer_token.rs").read_text()
        secret = re.search(r'const SECRET: &str = "([^"]+)";', rust).group(1)
        environment = re.search(r'const ENVIRONMENT: &str = "([^"]+)";', rust).group(1)
        now = int(re.search(r"const NOW: i64 = ([0-9_]+);", rust).group(1).replace("_", ""))
        pinned = re.search(r'const PINNED: &str = "([^"]+)";', rust).group(1)
        self.assertIn("issue(SECRET, ENVIRONMENT, 7, NOW + 600)", rust)
        source = COMMON.read_text(encoding="utf-8")
        function = "peer_token() {" + source.split("\npeer_token() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        result = subprocess.run(
            ["bash", "-c", function + 'peer_token "$@"', "peer-token",
             secret, environment, "7", str(now + 600)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, pinned)
        refused = subprocess.run(
            ["bash", "-c", function + 'peer_token "$@"', "peer-token",
             secret, environment, "0", str(now + 600)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(refused.stdout, "")


def actions_value(template: str, context: dict[str, str]):
    """TEMPLATE as Actions renders it, for the forms the concurrency block and
    runner labels use: github context values, quoted strings, ==, && and ||.
    A value that is one whole expression keeps its type."""
    def evaluate(expression: str):
        python = re.sub(r"github\.[a-z_]+", lambda match: repr(context[match.group(0)]), expression)
        python = python.replace("&&", " and ").replace("||", " or ")
        if not re.fullmatch(r"(?:\s|'[^']*'|==|!=|and|or|\(|\))*", python):
            raise AssertionError(f"unsupported expression {expression!r}")
        return eval(python, {"__builtins__": {}}, {})  # noqa: S307 - checked above
    whole = re.fullmatch(r"\$\{\{(.*?)\}\}", template.strip())
    if whole:
        return evaluate(whole.group(1))
    return re.sub(r"\$\{\{(.*?)\}\}", lambda match: str(evaluate(match.group(1))), template)


class MainPushDeferralContractTests(unittest.TestCase):
    """Kind leaves the push to main for a schedule (owner decision 2026-10-20).

    The selector drops Kind from a push to main while
    scripts/ci/select/main-push-switch.sh says so (test-select-verification.sh
    proves the selections). The workflow runs Kind every four hours against the
    latest main, in a concurrency group of its own, on the shared Heavy pool.
    """

    EVENTS = {
        "push": "refs/heads/main",
        "pull_request": "refs/pull/7/head",
        "schedule": "refs/heads/main",
        "workflow_dispatch": "refs/heads/main",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def context(self, event: str) -> dict[str, str]:
        return {"github.event_name": event, "github.ref": self.EVENTS[event],
                "github.workflow": self.workflow["name"]}

    def test_kind_is_scheduled_every_four_hours(self) -> None:
        triggers = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual(triggers["schedule"], [{"cron": "15 */4 * * *"}])
        self.assertEqual(triggers["push"], {"branches": ["main"]})
        self.assertIn("workflow_dispatch", triggers)

    def test_scheduled_and_dispatched_runs_never_cancel_or_wait_for_main(self) -> None:
        concurrency = self.workflow["concurrency"]
        rendered = {
            event: (actions_value(concurrency["group"], self.context(event)),
                    actions_value(concurrency["cancel-in-progress"], self.context(event)))
            for event in self.EVENTS
        }
        self.assertEqual(rendered, {
            # Main runs finish and queue one behind another.
            "push": ("ci-CI-refs/heads/main", False),
            # A newer pull-request push supersedes its older run.
            "pull_request": ("ci-CI-refs/pull/7/head", True),
            # A newer schedule supersedes an older scheduled run only.
            "schedule": ("ci-CI-refs/heads/main-schedule", True),
            # A dispatched release candidate never cancels or waits for main.
            "workflow_dispatch": ("ci-CI-refs/heads/main-dispatch", False),
        })
        # On main, a push, a schedule and a dispatch each have their own
        # group, so a long Kind run never holds a push to main behind it.
        on_main = [rendered[event][0] for event in ("push", "schedule", "workflow_dispatch")]
        self.assertEqual(len(set(on_main)), 3, on_main)

    def test_scheduled_kind_takes_the_shared_heavy_pool(self) -> None:
        for job_id in ("kind-workspace", "kind-product", "kind-daemon", "kind-smokes", "edge-kind"):
            with self.subTest(job=job_id):
                runs_on = self.workflow["jobs"][job_id]["runs-on"]
                self.assertEqual(actions_value(runs_on, self.context("schedule")), "ci-heavy")
                self.assertEqual(actions_value(runs_on, self.context("push")), "ci-heavy-main")

    def test_only_a_scheduled_run_reads_its_baseline(self) -> None:
        steps = self.workflow["jobs"]["verification-selection"]["steps"]
        ids = [step.get("id") for step in steps]
        baseline = steps[ids.index("schedule-baseline")]
        self.assertLess(ids.index("schedule-baseline"), ids.index("select"))
        self.assertEqual(baseline["if"], "${{ github.event_name == 'schedule' }}")
        self.assertEqual(baseline["env"], {"GITEA_TOKEN": "${{ github.token }}"})
        self.assertEqual(
            baseline["run"],
            "python3 -I -B scripts/ci/select/last-scheduled-run.py --workflow ci.yaml --github-output")
        select = steps[ids.index("select")]
        self.assertEqual(select["env"]["SCHEDULE_BASELINE_SHA"],
                         "${{ steps.schedule-baseline.outputs.schedule_baseline }}")
        # The selection step's own token is still a push's alone.
        self.assertEqual(select["env"]["GITEA_TOKEN"],
                         "${{ github.event_name == 'push' && github.token || '' }}")

    def test_the_switch_is_one_checked_in_setting(self) -> None:
        switch = ROOT / "scripts/ci/select/main-push-switch.sh"
        settings = re.findall(r"^([A-Z_]+)=(.*)$", switch.read_text(encoding="utf-8"), re.M)
        self.assertEqual(len(settings), 1)
        self.assertEqual(settings[0][0], "MAIN_PUSH_RUNS_KIND_AND_DRY_RUN")
        self.assertIn(settings[0][1], ("true", "false"))
        selector = SELECTOR.read_text(encoding="utf-8")
        self.assertIn('main_push_switch="$selector_root/scripts/ci/select/main-push-switch.sh"', selector)
        deferral = (ROOT / "scripts/ci/release/dry-run-deferral.sh").read_text(encoding="utf-8")
        self.assertIn('source "$ROOT/scripts/ci/select/main-push-switch.sh"', deferral)
        # Neither workflow carries a second copy of the setting.
        for workflow in (WORKFLOW, ROOT / ".gitea/workflows/cw-release-dry-run.yaml"):
            self.assertNotIn("MAIN_PUSH_RUNS_KIND_AND_DRY_RUN", workflow.read_text(encoding="utf-8"))


class SelectorContractTests(unittest.TestCase):
    def select(self, changed: list[str]) -> tuple[str, set[str], str]:
        environment = os.environ.copy()
        environment.pop("GITHUB_OUTPUT", None)
        environment.pop("GITHUB_EVENT_PATH", None)
        environment.update({
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/2065/head",
            "KIND_E2E_OPT_IN": "true",
        })
        result = subprocess.run(
            [str(SELECTOR), "-"],
            cwd=ROOT,
            env=environment,
            input="".join(f"{item}\n" for item in changed),
            text=True,
            capture_output=True,
            check=True,
        )
        return selection_fields(result.stdout)

    def test_every_new_kind_artifact_path_selects_kind(self) -> None:
        changed = [
            "scripts/ci/verify/kind-build-artifacts.py",
            "scripts/ci/images/build-kind-smokes.sh",
            "scripts/ci/tests/test-kind-build-artifacts.py",
            "scripts/ci/tests/test-kind-build-workflow.py",
            "scripts/ci/tests/test-build-kind-smokes.sh",
        ]
        for candidate in changed:
            with self.subTest(candidate=candidate):
                classification, tokens, mode = self.select([candidate])
                self.assertEqual(classification, "changed")
                self.assertTrue({"edge_kind", "kind", "policy"}.issubset(tokens))
                # Kind is never a local merge mode (merge-gate.tsv).
                self.assertEqual(mode, "default")

    def test_unknown_future_python_path_still_fails_closed(self) -> None:
        classification, tokens, mode = self.select(["future/kind-build-artifacts.py"])
        self.assertEqual(classification, "unclassified")
        self.assertTrue({
            "edge_kind", "kind", "policy", "release", "security", "web",
        }.issubset(tokens))
        self.assertEqual(mode, "full")

    def test_mixed_cache_authority_path_retains_security_selection(self) -> None:
        classification, tokens, mode = self.select([
            "scripts/ci/verify/kind-build-artifacts.py",
            "scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh",
        ])
        self.assertEqual(classification, "changed")
        self.assertTrue({
            "edge_kind", "kind", "policy", "policy_shell", "security",
        }.issubset(tokens))
        self.assertEqual(mode, "default")


class CommonConsumerContractTests(unittest.TestCase):
    def test_prebuilt_ci_and_release_runtime_boundaries(self) -> None:
        (ROOT / ".tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="kind-build-workflow-", dir=ROOT / ".tmp"
        ) as temporary:
            fixture = Path(temporary) / "repository"
            (fixture / "scripts/ci/verify/kind").mkdir(parents=True)
            (fixture / "scripts/ci/images").mkdir(parents=True)
            (fixture / "tests/e2e/kind").mkdir(parents=True)
            shutil.copy2(COMMON, fixture / "scripts/ci/verify/kind/common.sh")
            shutil.copy2(CREDENTIALS, fixture / "scripts/ci/verify/kind/credentials.sh")
            # common.sh reads its default workspace image from the published pin.
            for relative in (
                "scripts/ci/images/workspace-image-pin.py",
                "crates/codewire-workspace-image/src/pin.rs",
            ):
                (fixture / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, fixture / relative)
            for relative in (
                "scripts/ci/verify/playwright-browser-runtime.sh",
                "scripts/ci/verify/kind-host-runtime.sh",
            ):
                (fixture / relative).write_text("", encoding="utf-8")
            (fixture / "tests/e2e/kind/credential-broker.sql").write_text(
                "-- synthetic fixture\n", encoding="utf-8"
            )
            executable_scripts = {
                "scripts/ci/verify/resolve-cargo-target-dir.sh": """
                    #!/usr/bin/env bash
                    printf '%s/target\n' "$FIXTURE_ROOT"
                """,
                "scripts/ci/verify/dashboard-image.sh": """
                    #!/usr/bin/env bash
                    printf 'dashboard %s\n' "$*" >>"$CALLS"
                """,
                "scripts/ci/images/build-kind-smokes.sh": """
                    #!/usr/bin/env bash
                    printf 'forbidden-host-build %s\n' "$*" >>"$CALLS"
                    exit 97
                """,
                "scripts/ci/verify/run-host-rust-build.sh": """
                    #!/usr/bin/env bash
                    printf 'forbidden-host-wrapper %s\n' "$*" >>"$CALLS"
                    exit 96
                """,
                "bin/billing-test": """
                    #!/usr/bin/env bash
                    set -euo pipefail
                    [[ "$BILLING_BASE_URL" == http://kind.invalid ]]
                    [[ "$BILLING_ADMIN_SESSION_TOKEN" == contract-admin-session-token ]]
                    [[ "$BILLING_USER_SESSION_TOKEN" == contract-user-session-token ]]
                    [[ "$BILLING_SEEDED" == 1 && "$BILLING_SKIP_HEALTH" == 1 ]]
                    printf 'billing-args %s\n' "$*" >>"$CALLS"
                    printf 'test result: ok. %s passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' \
                      "$BILLING_PASSED_COUNT"
                """,
                "apps/dashboard/node_modules/.bin/playwright": """
                    #!/usr/bin/env bash
                    set -euo pipefail
                    printf 'browser-credential-fixture %s\n' \
                      "$PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE" >>"$CALLS"
                    printf 'browser-playwright %s\n' "$*" >>"$CALLS"
                    printf 'browser-json %s\n' "${PLAYWRIGHT_JSON_OUTPUT_FILE:-config}" >>"$CALLS"
                    case " $* " in
                      *' --grep-invert @quarantine '*) exit "${FAKE_BLOCKING_STATUS:-0}" ;;
                      *' --grep @quarantine '*) exit "${FAKE_QUARANTINE_STATUS:-0}" ;;
                    esac
                """,
                "bin/chromium": """
                    #!/usr/bin/env bash
                    exit 0
                """,
            }
            for relative, contents in executable_scripts.items():
                destination = fixture / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(textwrap.dedent(contents).lstrip(), encoding="utf-8")
                destination.chmod(0o755)

            harness = fixture / "fixture.sh"
            harness.write_text(textwrap.dedent(r"""
                #!/usr/bin/env bash
                set -euo pipefail
                export ROOT="$FIXTURE_ROOT"
                export RUN_DIR="$FIXTURE_ROOT/run"
                export KIND_CLUSTER_NAME=codewire-e2e-ci
                export KIND_WORKSPACE_IMAGE=sealed-workspace:fixture
                export KIND_INGRESS_CONTROLLER_IMAGE=''
                export KIND_INGRESS_CERTGEN_IMAGE=''
                export KIND_AGENT_SANDBOX_IMAGE=''
                export KIND_DIND_IMAGE=sealed-dind:fixture
                # The harness inherits the caller's environment; request the
                # default host topology so a shifted caller's port set cannot
                # leak into the sourced production defaults.
                export KIND_INGRESS_HOST_PORT=8090
                export KIND_INGRESS_TLS_HOST_PORT=10443
                export KIND_TEMPORAL_HOST_PORT=7233
                export KIND_ORCHESTRATION_HOST_PORT=8084
                export KIND_COORDINATOR_DIRECT_HOST_PORT=18092
                export KIND_POSTGRES_HOST_PORT=25432
                mkdir -p "$RUN_DIR" "$FIXTURE_ROOT/artifacts"
                source "$ROOT/scripts/ci/verify/kind/common.sh"
                # Publication locking has its own real-lock/profile fixture.
                # This fixture owns only the closed producer/consumer calls.
                acquire_kind_build_publication_lock() { :; }
                release_kind_build_publication_lock() { :; }

                record() { printf '%s\n' "$*" >>"$CALLS"; }
                fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 1; }
                log() { record "log $*"; }
                prepare_kind_support_images() { record prepare-support; }
                assert_prebuilt_release_product_images() { record assert-release; }

                python3() {
                  if [[ "${2:-}" == consume ]]; then
                    local expected
                    case "$3" in
                      workspace) expected=workspace-digest ;;
                      product) expected=product-digest ;;
                      daemon) expected=daemon-digest ;;
                      smokes) expected=smokes-digest ;;
                      *) return 95 ;;
                    esac
                    [[ "$EXPECTED_MANIFEST_SHA256" == "$expected" ]] || return 94
                    record "consume $3 $4 $EXPECTED_MANIFEST_SHA256"
                    [[ "${FAIL_GROUP:-}" != "$3" ]] || return 41
                    return 0
                  fi
                  if [[ "${2:-}" == reuse ]]; then
                    record "workspace-reuse $*"
                    printf 'codewire-workspace:verified-fixture\n'
                    return 0
                  fi
                  if [[ "$*" == "$ROOT/scripts/ci/verify/kind-build-artifacts.py workspace-image" ]]; then
                    record "workspace-select $*"
                    printf 'codewire-workspace:verified-fixture\n'
                    return 0
                  fi
                  return 93
                }

                export CODEWIRE_KIND_ARTIFACT_ROOT="$FIXTURE_ROOT/artifacts"
                export CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256=workspace-digest
                export CODEWIRE_KIND_PRODUCT_MANIFEST_SHA256=product-digest
                export CODEWIRE_KIND_DAEMON_MANIFEST_SHA256=daemon-digest
                export CODEWIRE_KIND_SMOKES_MANIFEST_SHA256=smokes-digest

                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci build_images_and_smokes
                [[ "$(grep -c '^consume ' "$CALLS")" -eq 4 ]] || fail 'consumer omitted a group'
                grep -Fxq "consume workspace $FIXTURE_ROOT/artifacts/workspace workspace-digest" "$CALLS"
                grep -Fxq "consume product $FIXTURE_ROOT/artifacts/product product-digest" "$CALLS"
                grep -Fxq "consume daemon $FIXTURE_ROOT/artifacts/daemon daemon-digest" "$CALLS"
                grep -Fxq "consume smokes $FIXTURE_ROOT/artifacts/smokes smokes-digest" "$CALLS"
                grep -Fxq 'dashboard codewire-dashboard:e2e' "$CALLS"
                grep -Fxq prepare-support "$CALLS"
                ! grep -q '^forbidden-host-' "$CALLS"

                : >"$CALLS"
                set +e
                (set -e; FAIL_GROUP=product CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci \
                  build_images_and_smokes)
                status=$?
                set -e
                [[ "$status" -eq 41 ]] || fail "consumer failure changed status: $status"
                printf '%s\n' \
                  "consume workspace $FIXTURE_ROOT/artifacts/workspace workspace-digest" \
                  "consume product $FIXTURE_ROOT/artifacts/product product-digest" \
                  >"$FIXTURE_ROOT/expected-failure-calls"
                grep '^consume ' "$CALLS" | cmp -s - "$FIXTURE_ROOT/expected-failure-calls" ||
                  fail 'consumer continued after a rejected producer group'
                ! grep -Eq '^(dashboard|prepare-support|forbidden-host-)' "$CALLS"

                validate_sealed_kind_images() { return 1; }
                : >"$CALLS"
                workspace="$(CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci kind_workspace_runtime_image)"
                [[ "$workspace" == codewire-workspace:verified-fixture ]]
                grep -q '^workspace-reuse ' "$CALLS" ||
                  fail "build-ci skipped source workspace reuse"
                ! grep -q '^workspace-select ' "$CALLS"
                # Prebuilt CI follows the consumed artifact: the exact-source
                # receipt or the published pin, proven by the same helper.
                : >"$CALLS"
                workspace="$(CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci kind_workspace_runtime_image)"
                [[ "$workspace" == codewire-workspace:verified-fixture ]]
                grep -q '^workspace-select ' "$CALLS" ||
                  fail "prebuilt-ci skipped the consumed workspace selection"
                : >"$CALLS"
                workspace="$(CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release kind_workspace_runtime_image)"
                [[ "$workspace" == sealed-workspace:fixture ]]
                ! grep -q '^workspace-reuse ' "$CALLS"

                kind() { record "kind $*"; }
                wait_for_kind_api_after_image_load() { record wait-api; }
                load_kind_credential_support_images() { record load-credential-support; }
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" load_images_into_kind
                  grep -Fq 'kind load docker-image --name codewire-e2e-ci codewire-workspace:verified-fixture' "$CALLS" ||
                    fail "$mode skipped source workspace load"
                done
                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release load_images_into_kind
                ! grep -Fq 'codewire-workspace:verified-fixture' "$CALLS"
                ! grep -q '^workspace-reuse ' "$CALLS"

                # The five sealed platform images are proven in every mode, but
                # the approved workspace is imported only where it runs: in
                # release-image mode. CI and source runs load their own.
                validate_sealed_kind_images() { return 0; }
                docker() { record "docker $*"; }
                for mode in build-ci prebuilt-ci prebuilt-release; do
                  : >"$CALLS"
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" load_images_into_kind
                  grep -Fxq "docker image tag $KIND_WORKSPACE_IMAGE $KIND_WORKSPACE_LOCAL_IMAGE" "$CALLS" ||
                    fail "$mode did not prove the approved workspace"
                  grep -Fxq "kind load docker-image --name codewire-e2e-ci $KIND_DIND_LOCAL_IMAGE" "$CALLS" ||
                    fail "$mode skipped a sealed platform image"
                  if [[ "$mode" == prebuilt-release ]]; then
                    grep -Fxq "kind load docker-image --name codewire-e2e-ci $KIND_WORKSPACE_LOCAL_IMAGE" "$CALLS" ||
                      fail 'release mode did not import its approved workspace'
                  else
                    ! grep -Fq "kind load docker-image --name codewire-e2e-ci $KIND_WORKSPACE_LOCAL_IMAGE" "$CALLS" ||
                      fail "$mode imported the unused approved workspace"
                    grep -Fxq 'kind load docker-image --name codewire-e2e-ci codewire-workspace:verified-fixture' "$CALLS" ||
                      fail "$mode skipped its selected workspace"
                  fi
                done
                validate_sealed_kind_images() { return 1; }

                docker() {
                  record "docker $*"
                  case "$*" in
                    *dev.codewire.build.profile*) printf 'runtime\n' ;;
                    *dev.codewire.promotable*) printf 'false\n' ;;
                    *) return 92 ;;
                  esac
                }
                kubectl() { record "kubectl $*"; cat >/dev/null || true; }
                kubectl_apply() { record "kubectl-apply $*"; }
                # The ingress-origin render has its own fixtures; here only
                # the rendered copy, not the checked-in patch, may be applied.
                render_kind_credential_fixture_patch() {
                  record render-credential-fixture-patch
                  printf '%s\n' "$RUN_DIR/credential-fixture-patch.yaml"
                }
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" start_kind_credential_fixture
                  grep -q '^docker image inspect ' "$CALLS" ||
                    fail "$mode skipped credential image proof"
                  grep -q '^kubectl .*deployment/codewire-credential-service' "$CALLS" ||
                    fail "$mode skipped synthetic credential fixture"
                  grep -Fq -- "--patch-file $RUN_DIR/credential-fixture-patch.yaml" "$CALLS" ||
                    fail "$mode did not apply the rendered credential fixture patch"
                done
                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release start_kind_credential_fixture
                ! grep -Eq '^(docker|kubectl|kubectl-apply) ' "$CALLS"

                kind_workspace_runtime_image() { record native-workspace-entry; return 43; }
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  set +e
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" kind_credential_native_smoke
                  status=$?
                  set -e
                  [[ "$status" -eq 43 ]] || fail "$mode skipped native credential smoke entry"
                  grep -Fxq native-workspace-entry "$CALLS"
                done
                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release kind_credential_native_smoke
                ! grep -Fxq native-workspace-entry "$CALLS"

                kind_workspace_runtime_image() { printf 'codewire-workspace:verified-fixture\n'; }
                prepare_playwright_browser_runtime() {
                  export CODEWIRE_PLAYWRIGHT_USE_DEV_SHM=0
                }
                resolve_pinned_playwright_chromium() {
                  printf '%s\n' "$PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
                }
                require_get_code() { :; }
                kubectl() {
                  record "dashboard-kubectl $*"
                  printf '%s\n' '{"spec":{"template":{"spec":{"containers":[{"name":"credential-service","command":["/codewire-kind-fixtures/credential-service"],"args":["--exact","runtime::kind::serve_kind_credential_fixture","--ignored","--nocapture","--test-threads=1"],"env":[{"name":"CODEWIRE_KIND_CREDENTIAL_FIXTURE","value":"1"}]}]}}}}'
                }
                export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$FIXTURE_ROOT/bin/chromium"
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" dashboard_browser_e2e
                  grep -Fxq 'browser-credential-fixture 1' "$CALLS" ||
                    fail "$mode omitted the browser credential fixture"
                  grep -q '^dashboard-kubectl ' "$CALLS" ||
                    fail "$mode skipped exact synthetic deployment admission"
                  grep -Fq -- '--workers=1' "$CALLS" ||
                    fail "$mode did not keep the single-worker default"
                done
                : >"$CALLS"
                CODEWIRE_KIND_DASHBOARD_WORKERS=4 dashboard_browser_e2e
                grep -Fq -- '--workers=4' "$CALLS" ||
                  fail 'dashboard leg does not thread CODEWIRE_KIND_DASHBOARD_WORKERS'
                # #2974: make kind-test may run part of the suite; each
                # selection maps to exact Playwright arguments, and anything
                # else is refused before Playwright starts.
                mkdir -p "$ROOT/apps/dashboard/e2e"
                : >"$ROOT/apps/dashboard/e2e/ssr-dashboard.read.ssr.ts"
                : >"$ROOT/apps/dashboard/e2e/ssr-dashboard.routes.ssr.ts"
                changed_base="$(printf 'a%.0s' {1..40})"
                for selection_case in \
                    "specs ssr-dashboard.read.ssr.ts ssr-dashboard.routes.ssr.ts|apps/dashboard/e2e/ssr-dashboard.read.ssr.ts apps/dashboard/e2e/ssr-dashboard.routes.ssr.ts" \
                    "smoke|--grep @smoke --project=dashboard-ssr-desktop" \
                    "light|--grep-invert @kind-heavy" \
                    "only-changed ${changed_base}|--only-changed=${changed_base}"; do
                  : >"$CALLS"
                  KIND_DASHBOARD_SELECTION="${selection_case%%|*}" dashboard_browser_e2e
                  grep -Fq -- "--workers=1 ${selection_case#*|}" "$CALLS" ||
                    fail "dashboard selection ${selection_case%%|*} lost its Playwright arguments"
                  grep -Fq 'not the whole suite' "$CALLS" ||
                    fail "dashboard selection ${selection_case%%|*} did not say it is part of the suite"
                done
                for refused_selection in 'specs ../escape.ssr.ts' 'specs ssr-dashboard.missing.ssr.ts' \
                    'only-changed main' 'fast'; do
                  : >"$CALLS"
                  set +e
                  (set -e; KIND_DASHBOARD_SELECTION="$refused_selection" dashboard_browser_e2e >/dev/null)
                  refused_status=$?
                  set -e
                  [[ "$refused_status" -eq 2 ]] || fail "dashboard selection ${refused_selection} was not refused"
                  ! grep -q '^browser-playwright ' "$CALLS" ||
                    fail "dashboard selection ${refused_selection} started Playwright"
                done
                rm -r "$ROOT/apps/dashboard/e2e"
                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release dashboard_browser_e2e
                grep -Fxq 'browser-credential-fixture 0' "$CALLS"
                ! grep -q '^dashboard-kubectl ' "$CALLS"

                # #2975: quarantined tests leave the blocking run, then run
                # after it without failing the suite. Without one quarantined
                # spec there is no second run.
                : >"$CALLS"
                dashboard_browser_e2e
                [ "$(grep -c '^browser-playwright ' "$CALLS")" -eq 1 ] ||
                  fail 'a suite with nothing quarantined ran Playwright twice'
                grep -Fq -- '--workers=1 --grep-invert @quarantine' "$CALLS" ||
                  fail 'the blocking run does not leave quarantined tests out'
                grep -Fxq 'browser-json config' "$CALLS" ||
                  fail 'the blocking run does not write the configured JSON report'
                mkdir -p "$ROOT/apps/dashboard/e2e"
                printf '%s\n' 'test("flaky", quarantine(2990, "2026-11-03"), async () => {});' \
                  >"$ROOT/apps/dashboard/e2e/ssr-dashboard.flaky.ssr.ts"
                for quarantine_status in 0 1; do
                  : >"$CALLS"
                  FAKE_QUARANTINE_STATUS="$quarantine_status" dashboard_browser_e2e >"$FIXTURE_ROOT/quarantine.out"
                  [ "$(grep -c '^browser-playwright ' "$CALLS")" -eq 2 ] ||
                    fail 'quarantined tests did not run after the blocking run'
                  grep -Fq -- "--grep @quarantine --pass-with-no-tests --reporter=line,json --output=$ROOT/apps/dashboard/test-report/quarantine-results" "$CALLS" ||
                    fail 'the quarantine run does not select only quarantined tests'
                  grep -Fxq "browser-json $ROOT/apps/dashboard/test-report/quarantine.json" "$CALLS" ||
                    fail 'the quarantine run does not write its own JSON report'
                done
                grep -Fq '::warning::quarantined dashboard tests failed; they do not block' "$FIXTURE_ROOT/quarantine.out" ||
                  fail 'a failed quarantine run is not reported'
                # A partial make kind-test run (#2974) leaves quarantined tests
                # out too, and runs no quarantine pass; `light` folds both
                # exclusions into its one --grep-invert.
                : >"$ROOT/apps/dashboard/e2e/ssr-dashboard.read.ssr.ts"
                for partial_case in "smoke|--grep @smoke --project=dashboard-ssr-desktop --grep-invert @quarantine" \
                    "light|--grep-invert @kind-heavy|@quarantine" \
                    "specs ssr-dashboard.read.ssr.ts|apps/dashboard/e2e/ssr-dashboard.read.ssr.ts --grep-invert @quarantine"; do
                  : >"$CALLS"
                  KIND_DASHBOARD_SELECTION="${partial_case%%|*}" dashboard_browser_e2e >/dev/null
                  [ "$(grep -c '^browser-playwright ' "$CALLS")" -eq 1 ] ||
                    fail "a partial ${partial_case%%|*} run ran the quarantine pass"
                  grep -Fxq "browser-playwright test --config $ROOT/apps/dashboard/playwright.config.ts --workers=1 ${partial_case#*|}" "$CALLS" ||
                    fail "a partial ${partial_case%%|*} run lost its arguments or the quarantine exclusion"
                done
                : >"$CALLS"
                set +e
                (set -e; FAKE_BLOCKING_STATUS=1 dashboard_browser_e2e >/dev/null)
                blocking_status=$?
                set -e
                [[ "$blocking_status" -ne 0 ]] || fail 'a failed blocking run did not fail the suite'
                [ "$(grep -c '^browser-playwright ' "$CALLS")" -eq 1 ] ||
                  fail 'quarantined tests ran after a failed blocking run'
                rm -r "$ROOT/apps/dashboard/e2e"

                jq() {
                  [[ "$*" == *'.target.name == "wire_contract"'* ]]
                  [[ "$*" == *'if length == 1 then .[0]'* ]]
                  record billing-json-selection
                  printf '%s/bin/billing-test\n' "$FIXTURE_ROOT"
                }
                export KIND_INGRESS_URL=http://kind.invalid
                export BILLING_PASSED_COUNT=1
                : >"$CALLS"
                billing_contract_through_ingress >/dev/null
                grep -Fxq billing-json-selection "$CALLS"
                grep -Fxq 'billing-args configured_billing_wire_contract --ignored --exact --nocapture' "$CALLS"
                ! grep -q '^forbidden-host-wrapper ' "$CALLS"
                export BILLING_PASSED_COUNT=0
                set +e
                (set -e; billing_contract_through_ingress >/dev/null 2>&1)
                status=$?
                set -e
                [[ "$status" -ne 0 ]] || fail 'billing accepted a zero-pass direct libtest result'
            """).lstrip(), encoding="utf-8")
            harness.chmod(0o755)
            calls = fixture / "calls"
            environment = os.environ.copy()
            # This consumer fixture selects the legacy cluster above; a caller's
            # saved-profile selector belongs to its separate profile fixtures.
            environment.pop("CLUSTER", None)
            environment.update({"FIXTURE_ROOT": str(fixture), "CALLS": str(calls)})
            result = subprocess.run(
                ["bash", str(harness)],
                cwd=fixture,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
