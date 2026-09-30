#!/usr/bin/env python3
"""Synthetic fixture custody/topology tests; no cluster, login or SSH server."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("checkout_fixture", ROOT / "scripts/runtime/dev/hosted-checkout-fixture.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
REAL_KUBE = FIXTURE.Kube
USER, ORGANIZATION = "1" * 32, "2" * 32
KEY = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(32)).decode()
IMAGE = "ghcr.io/codewiresh/workspace@sha256:" + "3" * 64
READY = KEY + "\n" + "4" * 40 + "\n" + FIXTURE.CONTENT + "\n"
CERTIFICATE = b"synthetic-public-certificate"


class FakeKube:
    def __init__(self):
        self.objects, self.calls = {}, []
        self.ready = READY
        self.failure = None
        self.counter = "1\n"
        self.cluster = {"server": FIXTURE.DEV_SERVER, "tls-server-name": FIXTURE.DEV_TLS,
                        "certificate-authority-data": base64.b64encode(CERTIFICATE).decode()}

    def wait_ready(self, name):
        return self.run(["wait", "pod/" + name, "--for=condition=Ready", "--timeout=240s"], as_json=False)

    def run(self, args, payload=None, as_json=True):
        self.calls.append((list(args), copy.deepcopy(payload)))
        if args[0] == "config":
            assert args == ["config", "view", "--minify", "--raw", "-o", "jsonpath={.clusters[0].cluster}"]
            return copy.deepcopy(self.cluster)
        if args[0] == "create":
            if self.failure == "create":
                raise FIXTURE.Failure("private mock provider error")
            value = copy.deepcopy(payload)
            value["metadata"]["uid"] = str(uuid.UUID(int=len(self.objects) + 1))
            if value["kind"] == "Service":
                value["spec"]["clusterIP"] = "10.43.1.2"
            if value["kind"] == "Pod":
                value["status"] = {"phase": "Running", "podIP": "10.42.1.2", "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"name": "target", "ready": True, "image": IMAGE,
                        "imageID": "ghcr.io/codewiresh/workspace@sha256:" + "7" * 64, "state": {"running": {}}}]}
            self.objects[(FIXTURE.RESOURCES[value["kind"]][1], value["metadata"]["name"])] = value
            return value
        if args[0] == "wait":
            if self.failure == "wait":
                raise FIXTURE.Failure("private mock provider error")
            return ""
        if args[0] == "exec":
            self.assert_exec(args)
            if args[-1] == "drain":
                pod = self.objects[("pods", args[1])]
                pod["status"]["containerStatuses"][0]["state"] = {"terminated": {"exitCode": 0}}
                return "hosted-checkout-target-drain-requested\n"
            if self.failure == "exec":
                raise FIXTURE.Failure("private mock provider error")
            return self.ready if args[-1] == "ready" else self.counter
        if args[0] == "logs":
            assert args[2:] == ["-c", "target", "--tail=1"]
            return "hosted-checkout-target-drained\n"
        if args[0] == "get" and args[1] == "endpoints":
            pod = next(value for value in self.objects.values() if value["kind"] == "Pod")
            ref = {"kind": "Pod", "name": pod["metadata"]["name"], "namespace": pod["metadata"]["namespace"], "uid": pod["metadata"]["uid"]}
            if self.failure == "endpoint":
                ref["uid"] = str(uuid.UUID(int=999))
            return {"metadata": {"name": args[2], "namespace": pod["metadata"]["namespace"]},
                    "subsets": [{"addresses": [{"ip": "10.42.1.2", "targetRef": ref}], "ports": [{"name": "ssh", "port": 22222, "protocol": "TCP"}]}]}
        if args[0] == "get":
            value = self.objects.get((args[1], args[2]))
            if value is None:
                if "--ignore-not-found" in args:
                    return ""
                raise FIXTURE.Failure("not found")
            return copy.deepcopy(value) if as_json else json.dumps(value)
        if args[0] == "delete":
            assert args[1:3] == ["--raw", args[2]] and args[-2:] == ["-f", "-"]
            assert payload["kind"] == "DeleteOptions"
            plural, name = args[2].split("/")[-2:]
            value = self.objects[(plural, name)]
            assert payload["preconditions"] == {"uid": value["metadata"]["uid"]}
            del self.objects[(plural, name)]
            return {"kind": "Status", "status": "Success"}
        raise AssertionError("unexpected mock command")

    @staticmethod
    def assert_exec(args):
        assert args[2:] in (["-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "ready"],
                            ["-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "counter"],
                            ["-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "drain"])


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-hosted-checkout-tests-")
        self.parent = Path(self.temporary.name)
        self.identity = self.parent / "identity.json"
        self.identity.write_text(json.dumps({"version": 1, "status": "enrolled", "email": "hello@codewire.sh", "userId": USER, "organizationId": ORGANIZATION}))
        self.key = self.parent / "selected.pub"
        self.key.write_text(KEY + "\n")
        self.args = argparse.Namespace(state_dir=self.parent / "fixture", context=FIXTURE.DEV_CONTEXT, namespace=FIXTURE.DEV_NAMESPACE,
            organization_id=ORGANIZATION, principal_user_id=USER, principal_email="hello@codewire.sh", image=IMAGE, public_key_file=self.key)
        self.kube = FakeKube()
        self.admission_patch = patch.object(FIXTURE, "IDENTITY", self.identity)
        self.kube_patch = patch.object(FIXTURE, "Kube", return_value=self.kube)
        self.ca_patch = patch.object(FIXTURE, "DEV_CA_SHA256", hashlib.sha256(CERTIFICATE).hexdigest())
        self.admission_patch.start()
        self.kube_patch.start()
        self.ca_patch.start()

    def tearDown(self):
        self.kube_patch.stop()
        self.ca_patch.stop()
        self.admission_patch.stop()
        self.temporary.cleanup()

    def start(self):
        FIXTURE.start(self.args)
        return FIXTURE.load_state(self.args.state_dir)

    def cli(self, mode):
        with patch("sys.argv", ["fixture", mode, "--state-dir", str(self.args.state_dir)]):
            return FIXTURE.main()

    def test_full_lifecycle_public_receipts_and_uid_deletion(self):
        state = self.start()
        ready = json.loads((self.args.state_dir / "ready.json").read_text())
        self.assertEqual(ready, {"version": 1, "url": "ssh://codewire@10.43.1.2:22222/repository.git", "revision": "4" * 40,
            "known_hosts": ["[10.43.1.2]:22222 " + KEY], "content_path": "proof.txt", "content": FIXTURE.CONTENT})
        self.assertEqual(self.cli("inspect"), 0)
        self.assertEqual(json.loads((self.args.state_dir / "counter.json").read_text()), {"version": 1, "authenticated": 1})
        self.assertEqual(self.cli("stop"), 0)
        self.assertEqual(self.kube.objects, {})
        self.assertEqual(json.loads((self.args.state_dir / "finish.json").read_text()), {"version": 1, "deleted": True})
        deletions = [args for args, _ in self.kube.calls if args[0] == "delete"]
        self.assertTrue(deletions[0][2].endswith(state["name"] + "-source"))
        self.assertEqual(self.cli("stop"), 0)  # Already-absent exact objects.

    def test_cold_pull_wait_bound_and_ordinary_command_bound(self):
        kube = REAL_KUBE(FIXTURE.DEV_CONTEXT, FIXTURE.DEV_NAMESPACE, self.parent)
        process = Mock(pid=123, returncode=0)

        def cold_pull(timeout):
            # Observed cold pulls of 95s and 150s both exceeded the old 90s wait.
            if timeout < 150:
                raise subprocess.TimeoutExpired("synthetic-kubectl", timeout)

        with self.assertRaises(subprocess.TimeoutExpired):
            cold_pull(90)
        process.wait.side_effect = cold_pull
        with patch.object(FIXTURE.subprocess, "Popen", return_value=process) as launch:
            self.assertEqual(kube.wait_ready("synthetic-pod"), "")
        process.wait.assert_called_once_with(timeout=245)
        self.assertEqual(launch.call_args.args[0], ["kubectl", "--context", FIXTURE.DEV_CONTEXT,
            "--namespace", FIXTURE.DEV_NAMESPACE, "--request-timeout=20s", "wait",
            "pod/synthetic-pod", "--for=condition=Ready", "--timeout=240s"])
        process.wait.reset_mock(side_effect=True)
        with patch.object(FIXTURE.subprocess, "Popen", return_value=process):
            self.assertEqual(kube.run(["get", "pods"], as_json=False), "")
        process.wait.assert_called_once_with(timeout=25)

    def test_wait_timeout_kills_process_group_and_reaps_with_fixed_error(self):
        kube = REAL_KUBE(FIXTURE.DEV_CONTEXT, FIXTURE.DEV_NAMESPACE, self.parent)
        process = Mock(pid=123, returncode=-9)
        process.wait.side_effect = [subprocess.TimeoutExpired("private-provider-canary", 245), None]
        with patch.object(FIXTURE.subprocess, "Popen", return_value=process), patch.object(FIXTURE.os, "killpg") as kill:
            with self.assertRaisesRegex(FIXTURE.Failure, "^fixture Kubernetes command failed$"):
                kube.wait_ready("synthetic-pod")
        kill.assert_called_once_with(123, FIXTURE.signal.SIGKILL)
        self.assertEqual(process.wait.call_args_list, [unittest.mock.call(timeout=245), unittest.mock.call()])

    def test_route_is_only_enrolled_org_workspace_to_nonce_port(self):
        state = self.start()
        created = [payload for args, payload in self.kube.calls if args[0] == "create"]
        self.assertEqual(len(created), 5)
        source, target = created[1:3]
        selector = {"codewire.sh/type": "workspace", "codewire.sh/org-id": ORGANIZATION}
        nonce = {FIXTURE.LABEL: state["nonce"]}
        self.assertEqual(source["spec"], {"podSelector": {"matchLabels": selector}, "policyTypes": ["Egress"],
            "egress": [{"to": [{"podSelector": {"matchLabels": nonce}}], "ports": [{"protocol": "TCP", "port": 22222}]}]})
        self.assertEqual(target["spec"], {"podSelector": {"matchLabels": nonce}, "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": selector}}], "ports": [{"protocol": "TCP", "port": 22222}]}], "egress": []})
        self.assertTrue(all(value["metadata"]["namespace"] == self.args.namespace for value in created))
        self.assertFalse(any(args[0] in {"apply", "patch", "replace"} for args, _ in self.kube.calls))

    def test_pod_and_configmap_are_public_only_hardened_and_bounded(self):
        self.start()
        values = list(self.kube.objects.values())
        pod = next(value for value in values if value["kind"] == "Pod")["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertEqual(pod["activeDeadlineSeconds"], 1800)
        self.assertEqual(pod["securityContext"]["runAsUser"], 1000)
        self.assertFalse(pod.get("hostNetwork", False))
        self.assertTrue(all(not set(volume) & {"secret", "hostPath", "persistentVolumeClaim"} for volume in pod["volumes"]))
        self.assertEqual(pod["volumes"][1]["emptyDir"], {"medium": "Memory", "sizeLimit": "64Mi"})
        container = pod["containers"][0]
        self.assertEqual(container["image"], IMAGE)
        self.assertEqual(container["securityContext"], {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}})
        self.assertNotIn("env", container)
        config = next(value for value in values if value["kind"] == "ConfigMap")
        self.assertTrue(config["immutable"])
        self.assertEqual(set(config["data"]), {"client.pub", "target.sh"})
        self.assertEqual(config["data"]["client.pub"], KEY + "\n")
        self.assertNotIn("PRIVATE KEY", json.dumps(values))

    def test_unenrolled_and_owner_inputs_rejected_before_kubernetes(self):
        for field, value in (("status", "not-enrolled"), ("userId", None), ("organizationId", "0" * 32), ("email", "noel@codewire.sh")):
            with self.subTest(field=field):
                document = {"version": 1, "status": "enrolled", "email": "hello@codewire.sh", "userId": USER, "organizationId": ORGANIZATION}
                document[field] = value
                self.identity.write_text(json.dumps(document))
                with self.assertRaises(FIXTURE.Failure):
                    FIXTURE.start(self.args)
        self.assertFalse(any(args[0] == "create" for args, _ in self.kube.calls))
        self.assertFalse(self.args.state_dir.exists())

    def test_exact_principal_tuple_and_closed_admission(self):
        for attribute, value in (("principal_user_id", "5" * 32), ("organization_id", "6" * 32), ("principal_email", "noel@codewire.sh")):
            with self.subTest(attribute=attribute):
                args = copy.copy(self.args)
                setattr(args, attribute, value)
                with self.assertRaises(FIXTURE.Failure):
                    FIXTURE.start(args)
        document = json.loads(self.identity.read_text())
        document["extra"] = True
        self.identity.write_text(json.dumps(document))
        with self.assertRaises(FIXTURE.Failure):
            FIXTURE.start(self.args)
        self.assertFalse(any(args[0] == "create" for args, _ in self.kube.calls))

    def test_invalid_image_namespace_key_and_state_collision(self):
        for attribute, value in (("image", "workspace"), ("image", "evil.invalid/workspace@sha256:" + "3" * 64),
                                 ("namespace", "prod"), ("namespace", "../dev"), ("context", "--evil")):
            args = copy.copy(self.args)
            setattr(args, attribute, value)
            with self.subTest(attribute=attribute, value=value), self.assertRaises(FIXTURE.Failure):
                FIXTURE.start(args)
        self.key.write_text(KEY + "\n" + KEY)
        with self.assertRaises(FIXTURE.Failure):
            FIXTURE.start(self.args)
        self.key.write_text(KEY + "\n")
        self.args.state_dir.mkdir(mode=0o700)
        with self.assertRaises(FIXTURE.Failure):
            FIXTURE.start(self.args)
        self.assertFalse(any(args[0] == "create" for args, _ in self.kube.calls))

    def test_bad_ready_or_endpoint_cleans_all_known_objects(self):
        for failure in ("wait", "endpoint", "exec"):
            with self.subTest(failure=failure):
                self.kube.failure = failure
                self.args.state_dir = self.parent / failure
                with self.assertRaisesRegex(FIXTURE.Failure, "owned objects cleaned"):
                    FIXTURE.start(self.args)
                self.assertEqual(self.kube.objects, {})
                self.assertFalse((self.args.state_dir / "ready.json").exists())
        self.kube.failure = None
        self.kube.ready = READY + "untrusted-extra\n"
        self.args.state_dir = self.parent / "extra"
        with self.assertRaisesRegex(FIXTURE.Failure, "owned objects cleaned"):
            FIXTURE.start(self.args)
        self.assertEqual(self.kube.objects, {})

    def test_failure_receipt_has_only_closed_stage_and_code_before_cleanup(self):
        for failure, stage, code in (("create", "create", "operation-failed"),
                                     ("wait", "readiness", "operation-failed"),
                                     ("endpoint", "observe", "endpoint-identity"),
                                     ("exec", "observe", "operation-failed")):
            with self.subTest(failure=failure):
                self.kube.failure = failure
                self.args.state_dir = self.parent / ("receipt-" + failure)
                original_stop = FIXTURE.stop

                def inspect_then_stop(kube, state, directory):
                    self.assertEqual(json.loads((directory / "failure.json").read_text()),
                                     {"version": 1, "stage": stage, "code": code})
                    return original_stop(kube, state, directory)

                with patch.object(FIXTURE, "stop", side_effect=inspect_then_stop):
                    with self.assertRaises(FIXTURE.Failure):
                        FIXTURE.start(self.args)
                self.assertFalse((self.args.state_dir / "ready.json").exists())
                self.assertNotIn("private mock provider error", (self.args.state_dir / "failure.json").read_text())
                self.assertEqual(self.kube.objects, {})

    def test_observation_failure_allowlist_and_hostile_default(self):
        for index, (message, code) in enumerate([
            *FIXTURE.OBSERVATION_FAILURE_CODES.items(),
            ("private-provider-key-status-event-canary", "operation-failed"),
        ]):
            with self.subTest(code=code, index=index):
                self.args.state_dir = self.parent / ("observe-" + str(index))
                with patch.object(FIXTURE, "observe", side_effect=FIXTURE.Failure(message)):
                    with self.assertRaisesRegex(FIXTURE.Failure, "owned objects cleaned"):
                        FIXTURE.start(self.args)
                receipt = (self.args.state_dir / "failure.json").read_text()
                self.assertEqual(json.loads(receipt), {"version": 1, "stage": "observe", "code": code})
                self.assertNotIn(message, receipt)
                self.assertFalse((self.args.state_dir / "ready.json").exists())
                self.assertEqual(json.loads((self.args.state_dir / "finish.json").read_text()),
                                 {"version": 1, "deleted": True})
                self.assertEqual(self.kube.objects, {})

    def test_failure_receipt_write_error_still_cleans_owned_objects(self):
        self.kube.failure = "wait"
        original_write = FIXTURE.write_json

        def reject_failure_receipt(path, value):
            if path.name == "failure.json":
                raise OSError("private-filesystem-canary")
            return original_write(path, value)

        with patch.object(FIXTURE, "write_json", side_effect=reject_failure_receipt):
            with self.assertRaises(OSError):
                FIXTURE.start(self.args)
        self.assertEqual(self.kube.objects, {})
        self.assertFalse((self.args.state_dir / "ready.json").exists())
        self.assertTrue((self.args.state_dir / "finish.json").exists())

    def test_ambiguous_create_never_adopts_or_deletes_unknown_uid(self):
        self.kube.failure = "create"
        with self.assertRaisesRegex(FIXTURE.Failure, "cleanup is incomplete"):
            FIXTURE.start(self.args)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.kube.calls))
        self.assertFalse((self.args.state_dir / "finish.json").exists())

    def test_replacement_uid_refuses_delete_but_cleans_independent_objects(self):
        state = self.start()
        pod = self.kube.objects[("pods", state["name"])]
        pod["metadata"]["uid"] = str(uuid.UUID(int=999))
        with self.assertRaisesRegex(FIXTURE.Failure, "cleanup incomplete"):
            FIXTURE.stop(self.kube, state, self.args.state_dir)
        self.assertEqual(list(self.kube.objects), [("pods", state["name"])])
        self.assertFalse((self.args.state_dir / "finish.json").exists())

    def test_inspect_rejects_changed_trust_and_nonstatic_counter(self):
        self.start()
        self.kube.ready = READY.replace("4" * 40, "5" * 40)
        with patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(self.cli("inspect"), 1)
        self.assertNotIn("private mock", errors.getvalue())
        self.kube.ready = READY
        self.kube.counter = "private mock provider error\n"
        with patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(self.cli("inspect"), 1)
        self.assertNotIn("private mock", errors.getvalue())
        self.assertFalse((self.args.state_dir / "counter.json").exists())

    def test_cleanup_does_not_require_still_enrolled_identity(self):
        self.start()
        self.identity.unlink()
        self.assertEqual(self.cli("stop"), 0)
        self.assertEqual(self.kube.objects, {})

    def test_fixed_target_command_and_sshd_restrictions(self):
        program = FIXTURE.TARGET.read_text()
        self.assertIn('"${SSH_ORIGINAL_COMMAND:-}" == "git-upload-pack \'/repository.git\'"', program)
        self.assertNotIn("eval ", program)
        self.assertIn('upload-pack --strict "$STATE/repository.git"', program)
        for setting in ("PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin no", "StrictModes yes",
                        "AllowAgentForwarding no", "AllowTcpForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no",
                        "PermitUserEnvironment no", "PermitTTY no", "X11Forwarding no", "AuthorizedKeysFile none"):
            self.assertIn(setting, program)
        self.assertNotIn("Subsystem ", program)
        self.assertIn("AuthorizedKeysCommand /usr/bin/cat /state/checkout/authorized_keys", program)
        self.assertIn("--kill-after=2 20", program)
        self.assertIn("--kill-after=5 1800", program)
        subprocess.run(["bash", "-n", str(FIXTURE.TARGET)], check=True)

    def test_actual_request_guard_rejects_shell_paths_and_extra_options(self):
        program = FIXTURE.TARGET.read_text()
        guard = program[program.index("valid_request() {"):program.index("\n}", program.index("valid_request() {")) + 2] + "\nvalid_request"
        for command, expected in (("git-upload-pack '/repository.git'", 0), ("", 1), ("git-upload-pack '/other.git'", 1),
                                  ("git-upload-pack /repository.git", 1), ("git-upload-pack '/repository.git'; touch should-not-exist", 1),
                                  ("$(touch should-not-exist)", 1), ("git-receive-pack '/repository.git'", 1),
                                  ("git-upload-pack '--help'", 1), ("internal-sftp", 1)):
            with self.subTest(command=command):
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", guard], cwd=self.parent,
                    env={"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": command}, check=False)
                self.assertEqual(result.returncode, expected)
                self.assertFalse((self.parent / "should-not-exist").exists())

    def test_dev_cluster_server_tls_proxy_insecure_and_ca_rejections(self):
        for field, value in (("server", "https://prod.invalid:6443"), ("tls-server-name", "prod.invalid"),
                             ("proxy-url", "http://proxy.invalid"), ("insecure-skip-tls-verify", True),
                             ("certificate-authority-data", base64.b64encode(b"wrong-public-root").decode())):
            with self.subTest(field=field):
                original = copy.deepcopy(self.kube.cluster)
                self.kube.cluster[field] = value
                with self.assertRaises(FIXTURE.Failure):
                    FIXTURE.start(self.args)
                self.kube.cluster = original
        self.assertFalse(any(args[0] == "create" for args, _ in self.kube.calls))

    def test_real_kubectl_projects_only_public_selected_cluster(self):
        # Local synthetic kubeconfig only: no network or owner config/user reads.
        config = self.parent / "synthetic-kubeconfig.json"
        config.write_text(json.dumps({"apiVersion": "v1", "kind": "Config", "current-context": FIXTURE.DEV_CONTEXT,
            "clusters": [{"name": "synthetic", "cluster": self.kube.cluster}],
            "contexts": [{"name": FIXTURE.DEV_CONTEXT, "context": {"cluster": "synthetic", "user": "synthetic"}}],
            "users": [{"name": "synthetic", "user": {"token": "synthetic-user-token-must-not-be-projected",
                "client-key": str(self.parent / "does-not-exist-user.key"),
                "client-certificate": str(self.parent / "does-not-exist-user.crt")}}]}))
        self.kube_patch.stop()
        with patch.dict(os.environ, {"KUBECONFIG": str(config)}):
            FIXTURE.preflight(self.args, self.parent)
        self.kube_patch.start()

    def test_malformed_object_does_not_abort_independent_owned_cleanup(self):
        state = self.start()
        original = self.kube.run
        def malformed(args, payload=None, as_json=True):
            if args[:3] == ["get", "configmaps", state["name"]]:
                return "[]" if not as_json else []
            return original(args, payload, as_json)
        with patch.object(self.kube, "run", side_effect=malformed):
            with self.assertRaisesRegex(FIXTURE.Failure, "cleanup incomplete"):
                FIXTURE.stop(self.kube, state, self.args.state_dir)
        self.assertEqual(list(self.kube.objects), [("configmaps", state["name"])])
        self.assertFalse((self.args.state_dir / "finish.json").exists())

    def test_drain_failure_still_deletes_known_objects_without_success_receipt(self):
        state = self.start()
        original = self.kube.run
        def no_drain(args, payload=None, as_json=True):
            if args[0] == "exec" and args[-1] == "drain":
                raise FIXTURE.Failure("private mock drain error")
            return original(args, payload, as_json)
        with patch.object(self.kube, "run", side_effect=no_drain):
            with self.assertRaisesRegex(FIXTURE.Failure, "cleanup incomplete"):
                FIXTURE.stop(self.kube, state, self.args.state_dir)
        self.assertEqual(self.kube.objects, {})
        self.assertFalse((self.args.state_dir / "finish.json").exists())

    def test_runtime_image_status_is_required_but_index_can_resolve_to_child(self):
        state = self.start()  # ImageID child digest differs from immutable index pin.
        pod = self.kube.objects[("pods", state["name"])]
        pod["status"]["containerStatuses"][0]["imageID"] = ""
        with self.assertRaises(FIXTURE.Failure):
            FIXTURE.observe(self.kube, state)

    def test_runtime_guard_subtypes_preserve_rejection_and_redact_values(self):
        cases = [
            ("containerStatuses", [], "runtime-container-shape"),
            ("name", "private-name-canary", "runtime-container-identity"),
            ("ready", False, "runtime-container-identity"),
            ("image", "ghcr.io/codewiresh/workspace:private-tag-canary", "runtime-image-name-approved-repository-tag"),
            ("image", "registry.example.invalid/codewire/workspace@sha256:" + "a" * 64,
             "runtime-image-name-approved-repository-digest"),
            ("image", "sha256:" + "B" * 64, "runtime-image-name-unrecognized"),
            ("image", "private-image-key-event-canary", "runtime-image-name-unrecognized"),
            ("image", None, "runtime-image-name-unrecognized"),
            ("imageID", "private-imageid-canary", "runtime-image-id-unrecognized"),
            ("imageID", None, "runtime-image-id-unrecognized"),
        ]
        original_observe = FIXTURE.observe
        for index, (field, value, code) in enumerate(cases):
            with self.subTest(field=field, code=code):
                self.args.state_dir = self.parent / ("runtime-" + str(index))

                def mutated_observe(kube, state):
                    result = kube.objects[("pods", state["name"])]
                    prior = copy.deepcopy(result["status"])
                    try:
                        if field == "containerStatuses":
                            result["status"][field] = value
                        else:
                            result["status"]["containerStatuses"][0][field] = value
                        return original_observe(kube, state)
                    finally:
                        result["status"] = prior

                with patch.object(FIXTURE, "observe", side_effect=mutated_observe):
                    with self.assertRaises(FIXTURE.Failure):
                        FIXTURE.start(self.args)
                receipt = (self.args.state_dir / "failure.json").read_text()
                self.assertEqual(json.loads(receipt), {"version": 1, "stage": "observe", "code": code})
                if isinstance(value, str):
                    self.assertNotIn(value, receipt)
                self.assertNotIn("canary", receipt)
                self.assertFalse((self.args.state_dir / "ready.json").exists())
                self.assertEqual(self.kube.objects, {})

    def test_runtime_repository_evidence_combinations(self):
        state = self.start()
        container = self.kube.objects[("pods", state["name"])]["status"]["containerStatuses"][0]
        digest = "sha256:" + "7" * 64
        selected_id = "ghcr.io/codewiresh/workspace@" + digest
        wrong_id = "registry.example.invalid/codewire/workspace@" + digest
        cases = [
            (IMAGE, selected_id, True),
            (IMAGE, "docker-pullable://" + selected_id, True),
            (IMAGE, digest, True),
            (IMAGE, "containerd://" + digest, True),
            (digest, selected_id, True),
            (digest, "docker-pullable://" + selected_id, True),
            (IMAGE, wrong_id, False),
            (IMAGE, "docker-pullable://" + wrong_id, False),
            (digest, wrong_id, False),
            (digest, "docker-pullable://" + wrong_id, False),
            (digest, digest, False),
            (digest, "containerd://" + digest, False),
            (digest, "private-imageid-canary", False),
            (digest, "ghcr.io/codewiresh/workspace:private-id-tag-canary", False),
            ("ghcr.io/codewiresh/workspace:private-tag-canary", selected_id, False),
            ("sha256:" + "G" * 64, selected_id, False),
            (digest, "evil.invalid/workspace@" + digest, False),
        ]
        for image, image_id, accepted in cases:
            with self.subTest(image=image, accepted=accepted):
                container["image"], container["imageID"] = image, image_id
                if accepted:
                    self.assertEqual(FIXTURE.observe(self.kube, state)["content"], FIXTURE.CONTENT)
                else:
                    with self.assertRaises(FIXTURE.Failure) as caught:
                        FIXTURE.observe(self.kube, state)
                    self.assertIn(str(caught.exception), FIXTURE.OBSERVATION_FAILURE_CODES)
                    self.assertNotIn(image_id, str(caught.exception))

    def test_digest_only_name_requires_repository_id_in_failure_receipt(self):
        original_observe = FIXTURE.observe
        for index, (image_id, code) in enumerate([
            ("sha256:" + "7" * 64, "runtime-image-id-digest-only"),
            ("registry.example.invalid/codewire/workspace@sha256:" + "7" * 64,
             "runtime-image-id-approved-repository-digest"),
            ("private-imageid-canary", "runtime-image-id-unrecognized"),
        ]):
            self.args.state_dir = self.parent / ("digest-receipt-" + str(index))

            def mutated_observe(kube, state):
                status = kube.objects[("pods", state["name"])]["status"]
                prior = copy.deepcopy(status["containerStatuses"])
                try:
                    status["containerStatuses"][0].update(image="sha256:" + "6" * 64, imageID=image_id)
                    return original_observe(kube, state)
                finally:
                    status["containerStatuses"] = prior

            with patch.object(FIXTURE, "observe", side_effect=mutated_observe):
                with self.assertRaises(FIXTURE.Failure):
                    FIXTURE.start(self.args)
            receipt = (self.args.state_dir / "failure.json").read_text()
            self.assertEqual(json.loads(receipt), {"version": 1, "stage": "observe", "code": code})
            self.assertNotIn(image_id, receipt)
            self.assertFalse((self.args.state_dir / "ready.json").exists())
            self.assertEqual(self.kube.objects, {})


if __name__ == "__main__":
    unittest.main()
