#!/usr/bin/env python3
"""Focused contracts for the parallel Kind build workflow and consumer."""

from __future__ import annotations

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
    "kind-smokes": "smokes",
}
PRODUCER_IF = (
    "${{ needs.verification-selection.outputs.tested_tree_receipt != 'accepted' "
    "&& contains(needs.verification-selection.outputs.selection, '|kind|') }}"
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
                self.assertEqual(job["if"], PRODUCER_IF)
                expected_outputs = {
                    "artifact_name": "${{ steps.export.outputs.artifact_name }}",
                    "manifest_sha256": "${{ steps.export.outputs.manifest_sha256 }}",
                }
                if job_name == "kind-workspace":
                    expected_outputs["workspace_cache_seed"] = (
                        "${{ steps.cache-seed-report.outputs.workspace_cache_seed }}"
                    )
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
            ["verification-selection", "kind-workspace", "kind-product", "kind-smokes"],
        )
        expected_if = (
            "${{ always() && needs.verification-selection.result == 'success' && "
            "needs.verification-selection.outputs.edge_kind_expected == 'true' && "
            "(needs.verification-selection.outputs.tested_tree_receipt == 'accepted' || "
            "!contains(needs.verification-selection.outputs.selection, '|kind|') || "
            "(needs.kind-workspace.result == 'success' && "
            "needs.kind-product.result == 'success' && "
            "needs.kind-smokes.result == 'success')) }}"
        )
        self.assertEqual(" ".join(edge["if"].split()), " ".join(expected_if.split()))

        def admitted(*, selection_ok: bool = True, expected: bool = True,
                     receipt: bool = False, kind: bool = True,
                     producer_results: tuple[str, str, str] = ("success",) * 3) -> bool:
            return (selection_ok and expected
                    and (receipt or not kind or all(item == "success" for item in producer_results)))

        self.assertTrue(admitted(kind=False, producer_results=("skipped",) * 3))
        self.assertTrue(admitted(kind=True, producer_results=("success",) * 3))
        self.assertFalse(admitted(kind=True, producer_results=("success", "failure", "success")))
        self.assertFalse(admitted(kind=True, producer_results=("success", "skipped", "success")))
        self.assertTrue(admitted(receipt=True, producer_results=("skipped",) * 3))
        self.assertFalse(admitted(selection_ok=False, kind=False, producer_results=("skipped",) * 3))

    def test_consumer_downloads_bound_manifests_outside_checkout(self) -> None:
        edge = self.jobs["edge-kind"]
        self.assertEqual(edge["env"]["CODEWIRE_KIND_PRODUCT_IMAGE_MODE"], "prebuilt-ci")
        # Forgejo resolves job-level env before the runner context exists.
        self.assertNotIn("CODEWIRE_KIND_ARTIFACT_ROOT", edge["env"])
        for job_name, group in PRODUCERS.items():
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
        self.assertEqual(len(downloads), 3)
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
                self.assertEqual(download["if"], KIND_STEP_IF)
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
        self.assertEqual(named_step(edge, "Run Kind")["run"], "scripts/ci/verify/kind-e2e.sh")

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
            "host_key_authorization_smoke",
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
    [[ "$manifest" == *'kind: SandboxClaim'* ]] || return 61
    record runtime-created
    touch "$FIXTURE/runtime"
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
    *' exec cw-binding-gateway-'*)
      printf '%s\n' '{"environmentId":"00000000-0000-4000-8000-000000000501","workspacePodIp":"10.244.0.9","appPorts":[3000],"sidecarToken":"synthetic"}'
      ;;
    *' port-forward '*)
      printf 'Forwarding from 127.0.0.1:23456 -> 8085\n'
      exec /usr/bin/sleep 60
      ;;
    *' delete sandboxclaim '*|*' delete pod '*)
      if [ -f "$FIXTURE/runtime" ] && [ "$(<"$FIXTURE/state")" = stopped ]; then
        record runtime-deleted
        rm -f "$FIXTURE/runtime"
      fi
      ;;
    'wait '*|*' wait '*|*' patch sandboxclaim '*) : ;;
    *) printf 'unexpected synthetic kubectl: %s\n' "$args" >&2; return 63 ;;
  esac
}
curl_settled() {
  PROBE_BODY='{"code":"unauthenticated"}'
  if [[ "$*" == *127.0.0.1:23456* ]]; then
    PROBE_CODE=401
    printf 'x-codewire-service: codewire-orchestration-internal\n' >"$PROBE_HEADERS"
  else
    PROBE_CODE=404
    printf 'x-codewire-service: codewire-orchestration\n' >"$PROBE_HEADERS"
  fi
}
timeout() {
  [ -f "$FIXTURE/backend" ] && [ "$(<"$FIXTURE/state")" = running ] || return 64
  [ "$FAILURE" != internal ] || return 31
  record internal
}
mesh_product_connect_ownership_smoke() {
  record mesh
  [ "$FAILURE" != mesh ] || return 33
}
coordinator_ingress_smoke() {
  [ -f "$FIXTURE/backend" ] && [ "$(<"$FIXTURE/state")" = running ] || return 66
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
            return result, events, sql

    def test_shared_runtime_survives_every_consumer_then_retires(self) -> None:
        result, events, sql = self.run_owner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [
            "runtime-created", "admit", "internal", "mesh", "coordinator",
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
        result, events, _ = self.run_owner(premature_cleanup=True)
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
                result, events, _ = self.run_owner(failure=failure)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(events.count("retire"), 1)
                self.assertEqual(events.count("runtime-deleted"), 1)
                self.assertNotIn(absent, events)
                self.assertNotIn("downstream", events)

    def test_retirement_failure_cannot_pass_or_remove_live_runtime(self) -> None:
        result, events, _ = self.run_owner(failure="retirement")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed to retire", result.stderr)
        self.assertNotIn("runtime-deleted", events)
        self.assertNotIn("downstream", events)

    def test_seed_is_not_running_before_runtime_admission(self) -> None:
        seed = (ROOT / "tests/e2e/kind/coordinator-seed.sql").read_text()
        self.assertIn("state, desired_state, name", seed)
        self.assertRegex(seed, r"'sandbox',\s*'stopped',\s*'stopped',")


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
                self.assertEqual(mode, "kind")

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
        self.assertEqual(mode, "kind")


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
                  return 93
                }

                export CODEWIRE_KIND_ARTIFACT_ROOT="$FIXTURE_ROOT/artifacts"
                export CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256=workspace-digest
                export CODEWIRE_KIND_PRODUCT_MANIFEST_SHA256=product-digest
                export CODEWIRE_KIND_SMOKES_MANIFEST_SHA256=smokes-digest

                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci build_images_and_smokes
                [[ "$(grep -c '^consume ' "$CALLS")" -eq 3 ]] || fail 'consumer omitted a group'
                grep -Fxq "consume workspace $FIXTURE_ROOT/artifacts/workspace workspace-digest" "$CALLS"
                grep -Fxq "consume product $FIXTURE_ROOT/artifacts/product product-digest" "$CALLS"
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
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  workspace="$(CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" kind_workspace_runtime_image)"
                  [[ "$workspace" == codewire-workspace:verified-fixture ]]
                  grep -q '^workspace-reuse ' "$CALLS" ||
                    fail "$mode skipped source workspace reuse"
                done
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

                docker() {
                  record "docker $*"
                  case "$*" in
                    *dev.codewire.build.profile*) printf 'ci\n' ;;
                    *dev.codewire.promotable*) printf 'false\n' ;;
                    *) return 92 ;;
                  esac
                }
                kubectl() { record "kubectl $*"; cat >/dev/null || true; }
                kubectl_apply() { record "kubectl-apply $*"; }
                for mode in build-ci prebuilt-ci; do
                  : >"$CALLS"
                  CODEWIRE_KIND_PRODUCT_IMAGE_MODE="$mode" start_kind_credential_fixture
                  grep -q '^docker image inspect ' "$CALLS" ||
                    fail "$mode skipped credential image proof"
                  grep -q '^kubectl .*deployment/codewire-credential-service' "$CALLS" ||
                    fail "$mode skipped synthetic credential fixture"
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
                done
                : >"$CALLS"
                CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release dashboard_browser_e2e
                grep -Fxq 'browser-credential-fixture 0' "$CALLS"
                ! grep -q '^dashboard-kubectl ' "$CALLS"

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
