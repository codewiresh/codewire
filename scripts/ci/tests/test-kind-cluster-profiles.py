#!/usr/bin/env python3
"""Synthetic owned-profile regressions; no Docker or Kind mutation is needed."""

from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "scripts/dev/kind/cluster-profile.py"
SPEC = importlib.util.spec_from_file_location("kind_cluster_profile", SOURCE)
assert SPEC is not None and SPEC.loader is not None
profile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profile
SPEC.loader.exec_module(profile)


class FakeDocker:
    def __init__(self, identity: str = "synthetic-daemon"):
        self.daemon = identity
        self.selected_nodes: dict[str, list] = {}
        self.images = {name: f"sha256:{index:064x}"
                       for index, name in enumerate(profile.IMAGE_NAMES, 1)}
        self.image_reads = 0
        self.unmanaged = []

    def identity(self):
        return self.daemon

    def nodes(self, cluster):
        return self.selected_nodes.get(cluster, [])

    def image_ids(self):
        self.image_reads += 1
        return self.images

    def cluster_names(self):
        return sorted(set(self.unmanaged) | {name for name, nodes in self.selected_nodes.items() if nodes})


def allocate_child(root: str, cluster: str, results) -> None:
    try:
        value = profile.Profiles(Path(root), FakeDocker()).ensure(cluster)
        results.put((cluster, value, None))
    except Exception as error:
        results.put((cluster, None, repr(error)))


@contextmanager
def bind_port(port: int):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        yield listener
    finally:
        listener.close()


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="kind-profile-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "profiles"
        self.docker = FakeDocker()
        self.profiles = profile.Profiles(self.root, self.docker)
        self.environ = patch.dict(os.environ, {}, clear=False)
        self.environ.start()
        self.addCleanup(self.environ.stop)
        for name in (*profile.ENV_CONFLICT_KEYS, "CLUSTER", "KIND_PROFILE_LOCK_FD", "KIND_BUILD_PUBLICATION_LOCK_FD",
                     "KIND_PROFILE_LOCK_TIMEOUT_SECONDS"):
            os.environ.pop(name, None)

    def path(self, cluster="alpha"):
        return self.profiles.path(cluster)

    def save_unvalidated(self, value, cluster="alpha"):
        profile.write_json(self.path(cluster) / "profile.json", value)

    def bind_node(self, value, identifier=None):
        cluster = value["cluster_name"]
        node = profile.Node(identifier or "a" * 64, f"{cluster}-control-plane", cluster,
                            "control-plane", "2026-09-30T12:00:00Z")
        self.docker.selected_nodes[cluster] = [node]
        return self.profiles.record_node(cluster, value["ownership_nonce"], node.id)

    def seal(self, value, *, head="1" * 40, tree="2" * 40):
        directory = self.path(value["cluster_name"]) / "artifacts" / f"{head}-{tree}"
        directory.mkdir(mode=0o700)
        (directory / "smokes").mkdir(mode=0o700)
        files = {}
        for name, data, mode in (("images.tar", b"synthetic image archive", 0o400),
                                 ("smokes/fixture-smoke", b"#!/bin/sh\nexit 0\n", 0o500)):
            member = directory / name
            member.write_bytes(data)
            member.chmod(mode)
            files[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                           "bytes": len(data), "mode": mode}
        manifest = {"schema": profile.ARTIFACT_SCHEMA,
                    "cluster_name": value["cluster_name"], "docker_id": value["docker_id"],
                    "ownership_nonce": value["ownership_nonce"],
                    "source_head": head, "source_tree": tree,
                    "product_images": copy.deepcopy(self.docker.images), "files": files}
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest))
        path.chmod(0o400)
        return path, manifest

    def admit(self, value):
        path, manifest = self.seal(value)
        admitted = self.profiles.record_artifacts(value["cluster_name"], value["ownership_nonce"], path)
        return admitted, path, manifest

    def test_seven_real_loopback_leases_are_saved_and_stable(self):
        first = self.profiles.ensure("alpha")
        second = profile.Profiles(self.root, self.docker).ensure("alpha")
        self.assertEqual(first, second)
        self.assertEqual(set(first["ports"]), set(profile.PORT_NAMES))
        self.assertEqual(len(set(first["ports"].values())), 7)
        self.assertTrue(all(1024 <= value <= 65535 for value in first["ports"].values()))
        other = self.profiles.ensure("beta")
        self.assertFalse(set(first["ports"].values()) & set(other["ports"].values()))
        self.assertNotEqual(first["ownership_nonce"], other["ownership_nonce"])
        self.assertEqual(stat.S_IMODE((self.path() / "profile.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)

    def test_concurrent_allocations_publish_unique_leases_and_same_name_once(self):
        context = multiprocessing.get_context("fork")
        results = context.Queue()
        children = [context.Process(target=allocate_child, args=(str(self.root), cluster, results))
                    for cluster in ("alpha", "beta", "alpha", "gamma", "delta")]
        for child in children:
            child.start()
        values = [results.get(timeout=15) for _ in children]
        for child in children:
            child.join(timeout=15)
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
                self.fail("synthetic allocation child did not terminate")
            self.assertEqual(child.exitcode, 0)
        results.close()
        results.join_thread()
        saved = {}
        leased = set()
        for cluster, value, error in values:
            self.assertIsNone(error, error)
            if cluster in saved:
                self.assertEqual(value, saved[cluster])
            else:
                self.assertFalse(leased & set(value["ports"].values()))
                leased.update(value["ports"].values())
                saved[cluster] = value
        self.assertEqual(len(leased), 28)

    def test_occupied_saved_port_refuses_without_reallocation_or_rewrite(self):
        value = self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        for key in profile.PORT_NAMES:
            with self.subTest(port=key), bind_port(value["ports"][key]):
                with self.assertRaises(profile.ProfileError):
                    self.profiles.ensure("alpha")
                self.assertEqual((self.path() / "profile.json").read_bytes(), before)
        self.assertEqual(self.profiles.ensure("alpha"), value)

    def test_invalid_names_origins_and_conflicting_saved_origins_fail(self):
        for name in ("", "../alpha", "Upper", "alpha_1", "-alpha", "alpha-", "a" * 50, "a\x00b"):
            with self.subTest(name=name), self.assertRaises(profile.ProfileError):
                self.profiles.ensure(name)
        self.assertFalse(self.root.exists())
        for value in ("https://user:password@example.com", "http://localhost/path", "http://localhost?x",
                      "http://localhost#x", "http://localhost\n", "http://local\x00host", "http://localhost ",
                      "http://localhost\\example.com", "file:///tmp", "http://localhost:65536"):
            with self.subTest(origin=value), self.assertRaises(profile.ProfileError):
                self.profiles.ensure("alpha", public=value)
        value = self.profiles.ensure("alpha", public="https://review.example.com:4174",
                                     browser="https://review.example.com:8090")
        self.assertEqual(self.profiles.ensure("alpha"), value)
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha", public="http://localhost")
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("beta", public="http://one.example", browser="http://two.example")
        self.assertFalse(self.path("beta").exists())

    def test_invalid_saved_keys_ports_identity_and_duplicate_json_are_rejected(self):
        original = self.profiles.ensure("alpha")
        alterations = []
        value = copy.deepcopy(original)
        value["unexpected"] = True
        alterations.append(value)
        for wrong in (True, 1023, 65536, "8090"):
            value = copy.deepcopy(original)
            value["ports"]["http"] = wrong
            alterations.append(value)
        value = copy.deepcopy(original)
        value["ports"]["tls"] = value["ports"]["http"]
        alterations.append(value)
        value = copy.deepcopy(original)
        value["ports"].pop("watch")
        alterations.append(value)
        for key, wrong in (("docker_id", "another-daemon"), ("cluster_name", "beta"),
                           ("ownership_nonce", "not-a-nonce"), ("node", {})):
            value = copy.deepcopy(original)
            value[key] = wrong
            alterations.append(value)
        for value in alterations:
            with self.subTest(value=value):
                self.save_unvalidated(value)
                with self.assertRaises(profile.ProfileError):
                    self.profiles.env("alpha")
        self.save_unvalidated(original)
        for data in (b'{"schema":1,"schema":2}', b"[]", b" " * (profile.JSON_BOUND + 1)):
            with self.subTest(json=data[:40]), self.assertRaises(profile.ProfileError):
                profile.decode_json(data)

    def test_symlink_hardlink_mode_and_foreign_ownership_are_rejected(self):
        self.profiles.ensure("alpha")
        path = self.path() / "profile.json"
        data = path.read_bytes()
        other = self.path() / "other.json"
        other.write_bytes(data)
        other.chmod(0o600)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaises(OSError):
            self.profiles.env("alpha")
        path.unlink()
        os.link(other, path)
        with self.assertRaises(profile.ProfileError):
            self.profiles.env("alpha")
        path.unlink()
        other.unlink()
        path.write_bytes(data)
        path.chmod(0o644)
        with self.assertRaises(profile.ProfileError):
            self.profiles.env("alpha")
        path.chmod(0o600)
        with patch.object(profile.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(profile.ProfileError):
                self.profiles.env("alpha")
        link = Path(self.scratch.name) / "profile-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            profile.Profiles(link, self.docker).env("alpha")

    def test_bounded_nofollow_json_read(self):
        self.profiles.ensure("alpha")
        path = self.path() / "profile.json"
        path.write_bytes(b"x" * (profile.JSON_BOUND + 1))
        with self.assertRaises(profile.ProfileError):
            profile.read_json(path)
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(profile.ProfileError):
            profile.read_json(path)

    def test_mutable_run_directory_symlink_mode_and_ownership_fail_before_writes(self):
        value = self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        run = self.path() / "run"
        outside = Path(self.scratch.name) / "unrelated-run"
        outside.mkdir(mode=0o700)
        sentinel = outside / "preserved"
        sentinel.write_bytes(b"unrelated bytes")
        run.rmdir()
        run.symlink_to(outside, target_is_directory=True)
        for operation in (lambda: self.profiles.env("alpha"), lambda: self.profiles.ensure("alpha"),
                          lambda: self.profiles.save(value)):
            with self.assertRaisesRegex(profile.ProfileError, "profile run directory"):
                operation()
            self.assertEqual((self.path() / "profile.json").read_bytes(), before)
            self.assertEqual(sentinel.read_bytes(), b"unrelated bytes")
        run.unlink()
        run.mkdir(mode=0o755)
        with self.assertRaisesRegex(profile.ProfileError, "profile run directory"):
            self.profiles.env("alpha")
        run.chmod(0o700)
        inode = run.stat().st_ino
        real_fstat = os.fstat
        def foreign_directory(descriptor):
            info = real_fstat(descriptor)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info
        with patch.object(profile.os, "fstat", side_effect=foreign_directory):
            with self.assertRaisesRegex(profile.ProfileError, "profile run directory"):
                self.profiles.env("alpha")
        self.assertEqual(self.profiles.ensure("alpha"), value)

    def test_existing_kubeconfig_metadata_refuses_links_mode_and_foreign_uid(self):
        self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        kubeconfig = self.path() / "kubeconfig"
        outside = Path(self.scratch.name) / "unrelated-config"
        outside.write_bytes(b"synthetic unrelated configuration")
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink", "fifo", "directory", "shared-mode"):
            if kind == "symlink":
                kubeconfig.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, kubeconfig)
            elif kind == "fifo":
                os.mkfifo(kubeconfig, 0o600)
            elif kind == "directory":
                kubeconfig.mkdir(mode=0o700)
            else:
                kubeconfig.write_bytes(b"synthetic configuration")
                kubeconfig.chmod(0o644)
            for operation in (lambda: self.profiles.env("alpha"), lambda: self.profiles.ensure("alpha")):
                with self.subTest(kind=kind), self.assertRaisesRegex(profile.ProfileError, "existing profile kubeconfig"):
                    operation()
                self.assertEqual((self.path() / "profile.json").read_bytes(), before)
                self.assertEqual(outside.read_bytes(), b"synthetic unrelated configuration")
            if kind == "directory":
                kubeconfig.rmdir()
            else:
                kubeconfig.unlink()
        kubeconfig.write_bytes(b"synthetic owned configuration")
        kubeconfig.chmod(0o600)
        real_stat = os.stat
        def foreign_config(path, *arguments, **keywords):
            info = real_stat(path, *arguments, **keywords)
            if path == "kubeconfig":
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info
        with patch.object(profile.os, "stat", side_effect=foreign_config):
            with self.assertRaisesRegex(profile.ProfileError, "existing profile kubeconfig"):
                self.profiles.env("alpha")
        self.profiles.env("alpha")

    def test_kubeconfig_validation_never_opens_or_reads_its_values(self):
        self.profiles.ensure("alpha")
        kubeconfig = self.path() / "kubeconfig"
        kubeconfig.write_bytes(b"synthetic private client material must not be read")
        kubeconfig.chmod(0o600)
        real_open = os.open
        def reject_kubeconfig_open(path, *arguments, **keywords):
            if path == "kubeconfig" or os.fspath(path) == str(kubeconfig):
                self.fail("metadata validation opened kubeconfig data")
            return real_open(path, *arguments, **keywords)
        with patch.object(profile.os, "open", side_effect=reject_kubeconfig_open):
            fields = self.profiles.env("alpha")
            self.profiles.ensure("alpha")
        self.assertEqual(fields["KUBECONFIG"], str(kubeconfig))

    def test_daemon_mismatch_and_change_refuse_existing_profile(self):
        self.profiles.ensure("alpha")
        other = profile.Profiles(self.root, FakeDocker("different-daemon"))
        with self.assertRaises((profile.ProfileError, FileNotFoundError)):
            other.env("alpha")
        value = self.profiles.load("alpha")
        value["docker_id"] = "different-daemon"
        self.save_unvalidated(value)
        with self.assertRaises(profile.ProfileError):
            self.profiles.env("alpha")
        self.docker.daemon = "changed-after-selection"
        with self.assertRaises(profile.ProfileError):
            self.profiles.build_lock_path()

    def test_distinct_daemon_namespaces_still_exclude_saved_host_port_leases(self):
        first = self.profiles.ensure("alpha")
        other = profile.Profiles(self.root, FakeDocker("different-daemon"))
        second = other.ensure("alpha")
        self.assertNotEqual(self.path(), other.path("alpha"))
        self.assertFalse(set(first["ports"].values()) & set(second["ports"].values()))
        self.assertEqual(self.profiles.load("alpha"), first)
        self.assertEqual(other.load("alpha"), second)

    def test_inherited_selector_and_endpoint_conflicts_precede_persistent_admission(self):
        for key, wrong in (("CLUSTER", "beta"), ("KIND_CLUSTER_NAME", "beta"),
                           ("KUBE_CONTEXT", "kind-beta"), ("KIND_INGRESS_URL", "http://foreign:8090"),
                           ("KUBECONFIG", "/foreign/kubeconfig")):
            with self.subTest(key=key), patch.dict(os.environ, {key: wrong}):
                with self.assertRaises(profile.ProfileError):
                    self.profiles.ensure("alpha")
            self.assertFalse(self.path().exists())
        value = self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        fields = self.profiles.environment(value)
        for key in profile.ENV_CONFLICT_KEYS:
            with self.subTest(key=key), patch.dict(os.environ, {key: "conflicting-value"}):
                with self.assertRaises(profile.ProfileError):
                    self.profiles.ensure("alpha")
                self.assertEqual((self.path() / "profile.json").read_bytes(), before)
        with patch.dict(os.environ, {key: fields[key] for key in profile.ENV_CONFLICT_KEYS}):
            self.assertEqual(self.profiles.ensure("alpha"), value)
        self.bind_node(value)
        self.docker.selected_nodes["alpha"] = []
        self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        before = (self.path() / "profile.json").read_bytes()
        with patch.dict(os.environ, {"KIND_TEMPORAL_ADDRESS": "http://127.0.0.1:7233"}):
            with self.assertRaises(profile.ProfileError):
                self.profiles.ensure("alpha")
        self.assertEqual((self.path() / "profile.json").read_bytes(), before)

    def test_preexisting_unowned_node_is_never_adopted(self):
        node = profile.Node("a" * 64, "alpha-control-plane", "alpha", "control-plane", "fixture")
        self.docker.selected_nodes["alpha"] = [node]
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        self.assertFalse(self.path().exists())

    def test_node_nonce_and_exact_container_identity_gate_lifecycle(self):
        value = self.profiles.ensure("alpha")
        node = profile.Node("a" * 64, "alpha-control-plane", "alpha", "control-plane", "fixture")
        self.docker.selected_nodes["alpha"] = [node]
        with self.assertRaises(profile.ProfileError):
            self.profiles.record_node("alpha", "0" * 32, node.id)
        for wrong in (profile.Node(node.id, "other-control-plane", "alpha", "control-plane", "fixture"),
                      profile.Node(node.id, node.name, "beta", "control-plane", "fixture"),
                      profile.Node(node.id, node.name, "alpha", "worker", "fixture"),
                      profile.Node(node.id, node.name, "alpha", "control-plane", "fixture", False)):
            self.docker.selected_nodes["alpha"] = [wrong]
            with self.subTest(node=wrong), self.assertRaises(profile.ProfileError):
                self.profiles.record_node("alpha", value["ownership_nonce"], node.id)
        self.docker.selected_nodes["alpha"] = [node]
        bound = self.profiles.record_node("alpha", value["ownership_nonce"], node.id)
        self.assertEqual(self.profiles.verify_node("alpha"), bound)
        self.assertEqual(self.profiles.ensure("alpha"), bound)
        with self.assertRaises(profile.ProfileError):
            self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        replacement = profile.Node("b" * 64, node.name, node.cluster, node.role, "later")
        self.docker.selected_nodes["alpha"] = [replacement]
        for operation in (lambda: self.profiles.ensure("alpha"),
                          lambda: self.profiles.verify_node("alpha"),
                          lambda: self.profiles.record_node("alpha", value["ownership_nonce"], replacement.id),
                          lambda: self.profiles.mark_deleted("alpha", value["ownership_nonce"])):
            with self.assertRaises(profile.ProfileError):
                operation()
        self.assertEqual(self.profiles.load("alpha"), bound)
        self.docker.selected_nodes["alpha"] = []
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        self.assertEqual(self.profiles.load("alpha"), bound)

    def test_recorded_delete_recreates_same_leases_nonce_and_sealed_base(self):
        value, manifest, _ = self.admit(self.profiles.ensure("alpha"))
        bound = self.bind_node(value)
        self.docker.selected_nodes["alpha"] = []
        deleted = self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        with self.assertRaises(profile.ProfileError):
            self.profiles.env("alpha")
        before = (self.path() / "profile.json").read_bytes()
        with bind_port(value["ports"]["http"]):
            with self.assertRaises(profile.ProfileError):
                self.profiles.ensure("alpha")
        self.assertEqual((self.path() / "profile.json").read_bytes(), before)
        self.docker.selected_nodes["alpha"] = [profile.Node("c" * 64, "alpha-control-plane", "alpha",
                                                            "control-plane", "replacement")]
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        self.docker.selected_nodes["alpha"] = []
        recreated = self.profiles.ensure("alpha")
        expected = {**deleted, "lifecycle": "allocated", "node": None}
        self.assertEqual(recreated, expected)
        self.assertEqual(recreated["artifacts"], bound["artifacts"])
        self.assertEqual(self.profiles.manifest_path(recreated), manifest)
        self.bind_node(recreated, "d" * 64)
        self.assertEqual(self.profiles.verify_node("alpha")["node"]["id"], "d" * 64)

    def test_recreation_refuses_changed_admitted_artifacts_without_state_effect(self):
        value, manifest, _ = self.admit(self.profiles.ensure("alpha"))
        self.bind_node(value)
        self.docker.selected_nodes["alpha"] = []
        self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        before = (self.path() / "profile.json").read_bytes()
        manifest.chmod(0o600)
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        manifest.chmod(0o400)
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        self.assertEqual((self.path() / "profile.json").read_bytes(), before)

    def test_deleted_profile_keeps_leases_and_recreation_rejects_saved_overlap(self):
        value = self.profiles.ensure("alpha")
        self.bind_node(value)
        self.docker.selected_nodes["alpha"] = []
        self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        other = self.profiles.ensure("beta")
        self.assertFalse(set(other["ports"].values()) & set(value["ports"].values()))
        other["ports"]["http"] = value["ports"]["http"]
        self.save_unvalidated(other, "beta")
        before = (self.path() / "profile.json").read_bytes()
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        self.assertEqual((self.path() / "profile.json").read_bytes(), before)

    def test_inherited_operation_and_publication_locks_are_reused_and_bound(self):
        value = self.profiles.ensure("alpha")
        other = self.profiles.ensure("beta")
        operation = self.path() / "operation.lock"
        publication = self.profiles.build_lock_path()
        with profile.owned_file(operation, writable=True) as operation_fd:
            with profile.owned_file(publication, writable=True) as publication_fd:
                fcntl.flock(operation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(publication_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.dict(os.environ, {"KIND_PROFILE_LOCK_FD": str(operation_fd),
                                             "KIND_BUILD_PUBLICATION_LOCK_FD": str(publication_fd)}):
                    path, _ = self.seal(value)
                    self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
                    self.profiles.verify_artifacts("alpha")
                    with self.assertRaises(profile.ProfileError):
                        self.profiles.env("beta")
                    with self.assertRaises(profile.ProfileError):
                        self.profiles.record_node("beta", other["ownership_nonce"], "b" * 64)
                with patch.dict(os.environ, {"KIND_PROFILE_LOCK_FD": "-1"}):
                    with self.assertRaises(profile.ProfileError):
                        self.profiles.env("alpha")

    def test_standalone_lock_contention_and_invalid_timeouts_terminate(self):
        self.profiles.ensure("alpha")
        operation = self.path() / "operation.lock"
        with profile.owned_file(operation, writable=True) as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.dict(os.environ, {"KIND_PROFILE_LOCK_TIMEOUT_SECONDS": "1"}):
                with patch.object(profile.time, "monotonic", side_effect=[0, 2]):
                    with self.assertRaisesRegex(profile.ProfileError, "timed out"):
                        with self.profiles.operation("alpha"):
                            self.fail("competing descriptor acquired an owned lock")
        for wrong in ("0", "-1", "1.5", "86401", "unbounded"):
            with self.subTest(timeout=wrong), patch.dict(os.environ, {"KIND_PROFILE_LOCK_TIMEOUT_SECONDS": wrong}):
                with self.assertRaises(profile.ProfileError):
                    self.profiles.build_lock_path()

    def test_operation_waiter_refuses_replaced_lock_inode(self):
        self.profiles.ensure("alpha")
        operation = self.path() / "operation.lock"
        before = (self.path() / "profile.json").read_bytes()
        def replace_while_waiting(descriptor):
            operation.unlink()
            operation.write_bytes(b"")
            operation.chmod(0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch.object(profile, "acquire_lock", side_effect=replace_while_waiting):
            with self.assertRaisesRegex(profile.ProfileError, "replaced while waiting"):
                with self.profiles.operation("alpha"):
                    self.fail("old inode admitted a new profile operation")
        self.assertEqual((self.path() / "profile.json").read_bytes(), before)

    def test_list_reports_saved_lifecycle_endpoints_source_and_unmanaged_names(self):
        self.docker.unmanaged = ["legacy-review"]
        self.assertEqual(self.profiles.list_profiles(), {"docker_id": self.docker.daemon,
                                                       "saved_profiles": [], "unmanaged_clusters": ["legacy-review"]})
        self.assertFalse(self.root.exists())
        allocated = self.profiles.ensure("alpha")
        admitted, _, _ = self.admit(self.profiles.ensure("beta"))
        self.bind_node(admitted)
        other = profile.Profiles(self.root, FakeDocker("other-daemon"))
        other.ensure("other-only")
        result = self.profiles.list_profiles()
        self.assertEqual(result["unmanaged_clusters"], ["legacy-review"])
        rows = {row["cluster_name"]: row for row in result["saved_profiles"]}
        self.assertEqual(set(rows), {"alpha", "beta"})
        self.assertEqual(rows["alpha"]["lifecycle"], "allocated")
        self.assertEqual(rows["alpha"]["runtime_state"], "absent")
        self.assertEqual(rows["alpha"]["context"], "kind-alpha")
        self.assertEqual(rows["alpha"]["endpoints"]["http"], f"http://127.0.0.1:{allocated['ports']['http']}")
        self.assertEqual(set(rows["alpha"]["endpoints"]), set(profile.PORT_NAMES))
        self.assertEqual(rows["beta"]["runtime_state"], "running")
        self.assertEqual(rows["beta"]["source_head"], "1" * 40)
        self.assertEqual(rows["beta"]["source_tree"], "2" * 40)
        self.docker.selected_nodes["beta"] = []
        rows = {row["cluster_name"]: row for row in self.profiles.list_profiles()["saved_profiles"]}
        self.assertEqual(rows["beta"]["runtime_state"], "attention")
        self.assertIn("missing", rows["beta"]["reason"])
        self.profiles.mark_deleted("beta", admitted["ownership_nonce"])
        rows = {row["cluster_name"]: row for row in self.profiles.list_profiles()["saved_profiles"]}
        self.assertEqual(rows["beta"]["lifecycle"], "deleted")

    def test_unmanaged_name_metadata_is_bounded_and_safe_to_display(self):
        docker = profile.Docker()
        with patch.object(docker, "run", return_value="legacy-review\nalpha\nalpha"):
            self.assertEqual(docker.cluster_names(), ["alpha", "legacy-review"])
        for value in ("unsafe\x1b[31mname", "a" * 64, "../other", "alpha\n" * 257):
            with self.subTest(names=value[:20]), patch.object(docker, "run", return_value=value):
                with self.assertRaises(profile.ProfileError):
                    docker.cluster_names()

    def test_named_replacement_without_kind_labels_still_fences_owned_operations(self):
        docker = profile.Docker()
        identifier = "a" * 64
        inspection = {"id": identifier, "name": "/alpha-control-plane", "cluster": None,
                      "role": None, "created": "2026-09-30T12:00:00Z", "running": True}
        calls = []
        def metadata(*arguments):
            calls.append(arguments)
            if arguments[0] == "ps":
                return identifier if arguments[-1] == "name=^/alpha-control-plane$" else ""
            return json.dumps(inspection)
        with patch.object(docker, "run", side_effect=metadata):
            nodes = docker.nodes("alpha")
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].id, identifier)
        self.assertIsNone(nodes[0].cluster)
        self.assertEqual(sum(arguments[0] == "inspect" for arguments in calls), 1)
        value = self.profiles.ensure("alpha")
        self.docker.selected_nodes["alpha"] = nodes
        with self.assertRaises(profile.ProfileError):
            self.profiles.ensure("alpha")
        with self.assertRaises(profile.ProfileError):
            self.profiles.purge("alpha", value["ownership_nonce"])

    def test_purge_removes_only_nonce_owned_private_profile_and_preserves_neighbors(self):
        value, _, _ = self.admit(self.profiles.ensure("alpha"))
        other = self.profiles.ensure("beta")
        neighbor = (self.path("beta") / "profile.json").read_bytes()
        run_log = self.path() / "run/owned.log"
        run_log.write_text("owned synthetic runtime output")
        run_log.chmod(0o644)
        result = self.profiles.purge("alpha", value["ownership_nonce"])
        self.assertEqual(result, {"cluster_name": "alpha", "purged": True})
        self.assertFalse(self.path().exists())
        self.assertEqual((self.path("beta") / "profile.json").read_bytes(), neighbor)
        self.assertEqual(self.profiles.ensure("beta"), other)
        self.assertTrue((self.root / "publication.lock").is_file())
        self.assertTrue((self.root / "registry.lock").is_file())
        recreated = self.profiles.ensure("alpha")
        self.assertNotEqual(recreated["ownership_nonce"], value["ownership_nonce"])
        self.assertIsNone(recreated["artifacts"])

    def test_purge_wrong_nonce_bound_node_or_occupied_port_has_no_effect(self):
        value = self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        with self.assertRaises(profile.ProfileError):
            self.profiles.purge("alpha", "0" * 32)
        for key in profile.PORT_NAMES:
            with self.subTest(port=key), bind_port(value["ports"][key]):
                with self.assertRaises(profile.ProfileError):
                    self.profiles.purge("alpha", value["ownership_nonce"])
            self.assertEqual((self.path() / "profile.json").read_bytes(), before)
        bound = self.bind_node(value)
        with self.assertRaises(profile.ProfileError):
            self.profiles.purge("alpha", value["ownership_nonce"])
        self.docker.selected_nodes["alpha"] = []
        with self.assertRaises(profile.ProfileError):
            self.profiles.purge("alpha", value["ownership_nonce"])
        self.assertEqual(self.profiles.load("alpha"), bound)
        self.profiles.mark_deleted("alpha", value["ownership_nonce"])
        self.docker.selected_nodes["alpha"] = [profile.Node("b" * 64, "alpha-control-plane", "alpha",
                                                            "control-plane", "replacement")]
        with self.assertRaises(profile.ProfileError):
            self.profiles.purge("alpha", value["ownership_nonce"])
        self.docker.selected_nodes["alpha"] = []
        self.profiles.purge("alpha", value["ownership_nonce"])
        self.assertFalse(self.path().exists())

    def test_purge_preflight_refuses_links_special_and_shared_writable_members(self):
        value = self.profiles.ensure("alpha")
        before = (self.path() / "profile.json").read_bytes()
        outside = Path(self.scratch.name) / "unrelated"
        outside.write_bytes(b"preserve unrelated bytes")
        retained = self.path() / "run/retained.log"
        retained.write_bytes(b"retained bytes")
        retained.chmod(0o600)
        member = self.path() / "run/invalid"
        for kind in ("symlink", "hardlink", "fifo", "shared-mode"):
            if kind == "symlink":
                member.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, member)
            elif kind == "fifo":
                os.mkfifo(member, 0o600)
            else:
                member.write_bytes(b"shared writable bytes")
                member.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaises(profile.ProfileError):
                self.profiles.purge("alpha", value["ownership_nonce"])
            self.assertEqual((self.path() / "profile.json").read_bytes(), before)
            self.assertEqual(retained.read_bytes(), b"retained bytes")
            self.assertEqual(outside.read_bytes(), b"preserve unrelated bytes")
            member.unlink()

    def test_cli_list_and_safe_collision_message_identify_recovery_action(self):
        value = self.profiles.ensure("alpha")
        self.docker.unmanaged = ["legacy-review"]
        for format in ("table", "json"):
            output = io.StringIO()
            with patch.object(profile, "Docker", return_value=self.docker), redirect_stdout(output):
                with patch.object(sys, "argv", [str(SOURCE), "--root", str(self.root), "list", "--format", format]):
                    self.assertEqual(profile.main(), 0)
            self.assertIn("alpha", output.getvalue())
            self.assertIn("legacy-review", output.getvalue())
            if format == "json":
                self.assertEqual(json.loads(output.getvalue())["saved_profiles"][0]["cluster_name"], "alpha")
        error = io.StringIO()
        with bind_port(value["ports"]["http"]):
            with patch.object(profile, "Docker", return_value=self.docker), redirect_stderr(error):
                with patch.object(sys, "argv", [str(SOURCE), "--root", str(self.root), "ensure", "--cluster", "alpha"]):
                    self.assertEqual(profile.main(), 2)
        self.assertIn(f"http loopback port {value['ports']['http']}", error.getvalue())
        self.assertIn("free that port or select another profile", error.getvalue())

    def test_artifact_admission_owns_source_qualified_files_and_producer_image_ids(self):
        value = self.profiles.ensure("alpha")
        path, manifest = self.seal(value)
        original = path.read_bytes()
        for key, wrong in (("schema", "other-schema"), ("cluster_name", "beta"),
                           ("docker_id", "other-daemon"), ("ownership_nonce", "0" * 32),
                           ("source_head", "3" * 40)):
            altered = copy.deepcopy(manifest)
            altered[key] = wrong
            path.chmod(0o600)
            path.write_text(json.dumps(altered))
            path.chmod(0o400)
            with self.subTest(key=key), self.assertRaises(profile.ProfileError):
                self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
            self.assertIsNone(self.profiles.load("alpha")["artifacts"])
        path.chmod(0o600)
        path.write_bytes(original)
        path.chmod(0o400)
        self.docker.images["mesh"] = "sha256:" + "f" * 64
        with self.assertRaises(profile.ProfileError):
            self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
        self.docker.images = manifest["product_images"]
        admitted = self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
        self.assertEqual(admitted["artifacts"]["manifest_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.profiles.verify_artifacts("alpha"), admitted)

    def test_runtime_artifact_verification_hashes_all_bytes_without_mutable_tags(self):
        value, manifest, _ = self.admit(self.profiles.ensure("alpha"))
        reads = self.docker.image_reads
        self.docker.images = {name: "sha256:" + "f" * 64 for name in profile.IMAGE_NAMES}
        self.assertEqual(self.profiles.verify_artifacts("alpha"), value)
        self.assertEqual(self.docker.image_reads, reads)
        self.assertEqual(self.profiles.env("alpha")["KIND_PROFILE_IMAGE_MANIFEST"], str(manifest))
        executable = manifest.parent / "smokes/fixture-smoke"
        original = executable.read_bytes()
        executable.chmod(0o700)
        executable.write_bytes(b"X" * len(original))
        executable.chmod(0o500)
        with self.assertRaises(profile.ProfileError):
            self.profiles.verify_artifacts("alpha")
        self.assertEqual(self.docker.image_reads, reads)

    def test_artifact_member_paths_links_and_modes_are_fail_closed(self):
        value = self.profiles.ensure("alpha")
        path, manifest = self.seal(value)
        contract = manifest["files"]["images.tar"]
        for name in ("../images.tar", "/images.tar", "smokes/../images.tar", "smokes//fixture-smoke", "manifest.json"):
            altered = copy.deepcopy(manifest)
            altered["files"] = {name: contract}
            path.chmod(0o600)
            path.write_text(json.dumps(altered))
            path.chmod(0o400)
            with self.subTest(path=name), self.assertRaises(profile.ProfileError):
                self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
        path.chmod(0o600)
        path.write_text(json.dumps(manifest))
        path.chmod(0o400)
        member = path.parent / "images.tar"
        data = member.read_bytes()
        member.chmod(0o600)
        with self.assertRaises(profile.ProfileError):
            self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
        member.unlink()
        member.symlink_to(path.parent / "smokes/fixture-smoke")
        with self.assertRaises(OSError):
            self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)
        member.unlink()
        member.write_bytes(data)
        member.chmod(0o400)
        os.link(member, path.parent / "hardlink")
        with self.assertRaises(profile.ProfileError):
            self.profiles.record_artifacts("alpha", value["ownership_nonce"], path)

    def test_env_derives_exact_localhost_tls_and_profile_paths(self):
        value = self.profiles.ensure("alpha")
        fields = self.profiles.env("alpha")
        ports = value["ports"]
        expected = {"KIND_INGRESS_URL": f"http://127.0.0.1:{ports['http']}",
                    "KIND_INGRESS_TLS_URL": f"https://localhost:{ports['tls']}",
                    "KIND_ORCHESTRATION_URL": f"http://127.0.0.1:{ports['orchestration']}",
                    "KIND_COORDINATOR_DIRECT_URL": f"http://127.0.0.1:{ports['coordinator']}",
                    "KIND_TEMPORAL_ADDRESS": f"http://127.0.0.1:{ports['temporal']}",
                    "KIND_DATABASE_URL": f"postgres://codewire:codewire@127.0.0.1:{ports['postgres']}/codewire",
                    "KIND_WATCH_ADDR": f"127.0.0.1:{ports['watch']}",
                    "KUBE_CONTEXT": "kind-alpha", "KUBECONFIG": str(self.path() / "kubeconfig"),
                    "RUN_DIR": str(self.path() / "run"),
                    "KIND_PROFILE_ARTIFACT_ROOT": str(self.path() / "artifacts")}
        for key, value in expected.items():
            self.assertEqual(fields[key], value)
        self.assertEqual(len(fields), 39)
        self.assertTrue(all(re.fullmatch(r"[A-Z][A-Z0-9_]+", key) for key in fields))
        self.assertTrue(all(isinstance(value, str) and "\0" not in value for value in fields.values()))

    def test_renderer_changes_only_six_host_mappings_in_one_pass(self):
        value = self.profiles.ensure("alpha")
        source = ROOT / "tests/e2e/kind/kind-config.yaml"
        rendered = self.profiles.render_config("alpha", source)
        text = rendered.read_text()
        actual = [int(port) for port in re.findall(r"(?m)^\s*hostPort: ([0-9]+)\s*$", text)]
        self.assertEqual(set(actual), {value["ports"][key] for key in profile.DEFAULT_PORTS})
        self.assertEqual(text.count('listenAddress: "127.0.0.1"'), 6)
        normalized = re.sub(r'(?m)^[ \t]*listenAddress: "127\.0\.0\.1"\n', "", text)
        normalized = re.sub(r"(?m)^(\s*hostPort: )[0-9]+(\s*)$", r"\1PORT\2", normalized)
        original = re.sub(r"(?m)^(\s*hostPort: )[0-9]+(\s*)$", r"\1PORT\2", source.read_text())
        self.assertEqual(normalized, original)
        self.assertEqual(stat.S_IMODE(rendered.stat().st_mode), 0o600)
        value["ports"]["http"], value["ports"]["tls"] = 10443, 8090
        self.profiles.save(value)
        # Explicitly probe both ports; a busy workstation should not require
        # binding legacy ports merely to prove the one-pass rendering rule.
        with patch.object(self.profiles, "free_ports") as free:
            free.return_value.__enter__.return_value = value["ports"]
            text = self.profiles.render_config("alpha", source).read_text()
        actual = [int(port) for port in re.findall(r"(?m)^\s*hostPort: ([0-9]+)\s*$", text)]
        original = [int(port) for port in re.findall(r"(?m)^\s*hostPort: ([0-9]+)\s*$", source.read_text())]
        replacements = {port: value["ports"][key] for key, port in profile.DEFAULT_PORTS.items()}
        self.assertEqual(actual, [replacements[port] for port in original])

    def test_renderer_refuses_unexpected_listen_addresses_before_output_change(self):
        self.profiles.ensure("alpha")
        source = ROOT / "tests/e2e/kind/kind-config.yaml"
        rendered = self.profiles.render_config("alpha", source)
        before = rendered.read_bytes()
        fixture = Path(self.scratch.name) / "kind-template.yaml"
        for address in ("0.0.0.0", "127.0.0.1", "::"):
            fixture.write_text(source.read_text().replace("hostPort: 8090", f"hostPort: 8090\n    listenAddress: \"{address}\""))
            with self.subTest(address=address), self.assertRaises(profile.ProfileError):
                self.profiles.render_config("alpha", fixture)
            self.assertEqual(rendered.read_bytes(), before)

    def test_legacy_publication_lock_matches_named_profiles_without_allocation(self):
        path = self.profiles.build_lock_path()
        self.assertEqual(path, self.root / "publication.lock")
        self.assertEqual(set(entry.name for entry in self.root.iterdir()), {"registry.lock", "publication.lock"})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.profiles.ensure("alpha")
        self.assertEqual(self.profiles.env("alpha")["KIND_BUILD_PUBLICATION_LOCK_FILE"], str(path))
        output = io.StringIO()
        with patch.object(profile, "Docker", return_value=self.docker), redirect_stdout(output):
            with patch.object(sys, "argv", [str(SOURCE), "--root", str(self.root), "build-lock-path"]):
                self.assertEqual(profile.main(), 0)
        self.assertEqual(output.getvalue(), f"{path}\n")

    def test_cli_nul_fields_are_fixed_and_errors_do_not_reflect_untrusted_state(self):
        self.profiles.ensure("alpha")
        output = io.BytesIO()
        text_output = io.TextIOWrapper(output)
        with patch.object(profile, "Docker", return_value=self.docker), redirect_stdout(text_output):
            with patch.object(sys, "argv", [str(SOURCE), "--root", str(self.root), "env", "--cluster", "alpha",
                                            "--format", "nul"]):
                self.assertEqual(profile.main(), 0)
        fields = output.getvalue().split(b"\0")
        self.assertEqual(fields.pop(), b"")
        self.assertEqual(dict(zip(fields[::2], fields[1::2])),
                         {key.encode(): value.encode() for key, value in self.profiles.env("alpha").items()})
        value = self.profiles.load("alpha")
        value["ownership_nonce"] = "UNTRUSTED_VALUE_MUST_NOT_ESCAPE"
        self.save_unvalidated(value)
        error = io.StringIO()
        with patch.object(profile, "Docker", return_value=self.docker), redirect_stderr(error):
            with patch.object(sys, "argv", [str(SOURCE), "--root", str(self.root), "env", "--cluster", "alpha"]):
                self.assertEqual(profile.main(), 2)
        self.assertNotIn("UNTRUSTED_VALUE", error.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
