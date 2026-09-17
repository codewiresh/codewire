#!/usr/bin/env python3
"""Nonce-owned public-only hosted initial-checkout fixture.

The temporary additive route covers workspace Pods in the enrolled E2E org,
not just one environment. No production policy or bootstrap is edited. Fresh
OAuth/principal observation and live-effect authority belong to the wrapper.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

IDENTITY = Path(__file__).resolve().parent / "testdata/acceptance-identity.json"
TARGET = Path(__file__).resolve().with_name("hosted-checkout-target.sh")
CONTENT = "initial-private-checkout-synthetic-v1"
LABEL = "codewire.sh/acceptance-checkout-nonce"
MAX_OUTPUT = 1024 * 1024
READINESS_SECONDS = 240
READINESS_PROCESS_SECONDS = READINESS_SECONDS + 5
# Closed observation discriminators: never persist exception text or provider data.
OBSERVATION_FAILURE_CODES = {
    "fixture lifetime expired": "lifetime-expired",
    "fixture object identity changed": "object-identity",
    "fixture object UID changed": "object-identity",
    "invalid fixture Pod shape": "pod-shape",
    "fixture is not ready": "pod-not-ready",
    "fixture image changed": "pod-image",
    "invalid fixture container status": "runtime-container-shape",
    "fixture runtime container changed": "runtime-container-identity",
    "fixture runtime imageID changed": "runtime-image-id",
    "fixture runtime image name changed (approved-repository-tag)": "runtime-image-name-approved-repository-tag",
    "fixture runtime image name changed (approved-repository-digest)": "runtime-image-name-approved-repository-digest",
    "fixture runtime image name changed (digest-only)": "runtime-image-name-digest-only",
    "fixture runtime image name changed (unrecognized)": "runtime-image-name-unrecognized",
    "invalid fixture Service shape": "service-shape",
    "fixture service changed": "service-shape",
    "invalid fixture service address": "service-address",
    "invalid fixture endpoint shape": "endpoint-shape",
    "fixture endpoint identity changed": "endpoint-identity",
    "invalid fixture ready metadata": "ready-metadata",
    "invalid public key": "ready-metadata",
}
IMAGE = re.compile(r"(?:ghcr\.io/codewiresh/workspace|nexus\.example\.invalid/oci-approved/codewire/workspace)@sha256:[0-9a-f]{64}")
# Public route/trust binding from owning Infra clusters/kubernetes-access.json
# main a7cb24de1ed865e44cc728530d4f47f64c33202c, dev-cluster. No alternatives.
DEV_CONTEXT = "dev-cluster"
DEV_NAMESPACE = "dev-sandboxes"
DEV_SERVER = "https://100.64.0.152:6443"
DEV_TLS = "api.dev-cluster.codewire.sh"
DEV_CA_SHA256 = "c649ace4c99caaf7d8e653c0858e3da2f0de7714d823edfd70acdc91d816c692"
RESOURCES = {"ConfigMap": ("v1", "configmaps"), "Pod": ("v1", "pods"),
             "Service": ("v1", "services"), "NetworkPolicy": ("networking.k8s.io/v1", "networkpolicies")}


class Failure(Exception):
    """Only fixed diagnostics are allowed to escape this module."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "invalid identity")
    require(uuid.UUID(value).int != 0, "invalid identity")
    return value


def public_key(value):
    require(isinstance(value, str) and len(value) <= 256 and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", value), "invalid public key")
    try:
        blob = base64.b64decode(value.split(" ")[1], validate=True)
        expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
        require(len(blob) == len(expected) + 32 and blob.startswith(expected), "invalid public key")
    except (ValueError, TypeError):
        raise Failure("invalid public key") from None
    return value


def admission(user, email, organization):
    try:
        value = json.loads(IDENTITY.read_text())
    except (OSError, ValueError):
        raise Failure("acceptance identity is not enrolled") from None
    require(isinstance(value, dict) and set(value) == {"version", "status", "email", "userId", "organizationId"}
            and type(value["version"]) is int and value["version"] == 1 and value["status"] == "enrolled"
            and value["email"] == "hello@codewire.sh", "acceptance identity is not enrolled")
    require(all(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{32}", value[key])
                for key in ("userId", "organizationId")), "invalid enrolled identity")
    identifier(value["userId"])
    identifier(value["organizationId"])
    require(identifier(user) == value["userId"] and identifier(organization) == value["organizationId"]
            and email == value["email"], "principal is not the enrolled E2E identity")


def private_directory(path):
    require(path.is_absolute() and path.resolve() == path and path.is_dir() and not path.is_symlink(), "invalid private state directory")
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "invalid private state directory")


def write_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
        temporary = Path(output.name)
    temporary.replace(path)


class Kube:
    def __init__(self, context, namespace, directory):
        self.context, self.namespace, self.directory = context, namespace, directory

    def run(self, arguments, payload=None, as_json=True):
        return self._run(arguments, payload, as_json, 25)

    def wait_ready(self, name):
        return self._run(["wait", "pod/" + name, "--for=condition=Ready",
                          f"--timeout={READINESS_SECONDS}s"], None, False, READINESS_PROCESS_SECONDS)

    def _run(self, arguments, payload, as_json, timeout_seconds):
        command = ["kubectl", "--context", self.context, "--namespace", self.namespace,
                   "--request-timeout=20s", *arguments]
        # Own process group; errors/output never become public diagnostics.
        with tempfile.TemporaryFile(dir=self.directory) as output:
            def cap_output():
                resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))

            process = subprocess.Popen(command, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.DEVNULL, start_new_session=True, preexec_fn=cap_output)
            try:
                if payload is not None:
                    process.stdin.write(json.dumps(payload).encode())
                    process.stdin.close()
                process.wait(timeout=timeout_seconds)
            except (subprocess.TimeoutExpired, BrokenPipeError):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise Failure("fixture Kubernetes command failed") from None
            require(process.returncode == 0, "fixture Kubernetes command failed")
            require(output.tell() <= MAX_OUTPUT, "fixture Kubernetes output exceeded bound")
            output.seek(0)
            raw = output.read(MAX_OUTPUT + 1)
        if not as_json:
            return raw.decode("utf-8")
        try:
            value = json.loads(raw)
            require(isinstance(value, dict), "invalid fixture Kubernetes response")
            return value
        except (ValueError, UnicodeError):
            raise Failure("invalid fixture Kubernetes response") from None


def preflight(args, directory):
    admission(args.principal_user_id, args.principal_email, args.organization_id)
    require(args.namespace == DEV_NAMESPACE, "invalid fixture namespace")
    require(args.context == DEV_CONTEXT and IMAGE.fullmatch(args.image), "invalid fixture context or image")
    cluster_trust(Kube(args.context, args.namespace, directory))


def cluster_trust(kube):
    # Project this selected PUBLIC cluster only. Never emit users, token/key
    # fields or the entire raw kubeconfig. Require the inline public CA: do not
    # use --flatten, which also opens selected-user private key/cert paths.
    cluster = kube.run([
        "config", "view", "--minify", "--raw", "-o", "jsonpath={.clusters[0].cluster}"])
    require(isinstance(cluster, dict) and cluster.get("server") == DEV_SERVER and cluster.get("tls-server-name") == DEV_TLS
            and cluster.get("insecure-skip-tls-verify", False) is False and not cluster.get("proxy-url")
            and not cluster.get("certificate-authority"), "fixture Dev cluster trust changed")
    try:
        certificate = base64.b64decode(cluster["certificate-authority-data"], validate=True)
    except (KeyError, ValueError, TypeError):
        raise Failure("fixture Dev cluster trust changed") from None
    require(hashlib.sha256(certificate).hexdigest() == DEV_CA_SHA256, "fixture Dev cluster trust changed")


def manifests(state, key):
    namespace, nonce, organization, name = (state[k] for k in ("namespace", "nonce", "organization", "name"))
    labels = {LABEL: nonce}
    source = {"codewire.sh/type": "workspace", "codewire.sh/org-id": organization}

    def obj(kind, suffix, body):
        return {"apiVersion": RESOURCES[kind][0], "kind": kind,
                "metadata": {"name": name + suffix, "namespace": namespace, "labels": labels}, **body}

    return [
        obj("ConfigMap", "", {"immutable": True, "data": {"client.pub": key + "\n", "target.sh": TARGET.read_text()}}),
        obj("NetworkPolicy", "-source", {"spec": {"podSelector": {"matchLabels": source}, "policyTypes": ["Egress"],
            "egress": [{"to": [{"podSelector": {"matchLabels": labels}}], "ports": [{"protocol": "TCP", "port": 22222}]}]}}),
        obj("NetworkPolicy", "-target", {"spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": source}}], "ports": [{"protocol": "TCP", "port": 22222}]}], "egress": []}}),
        obj("Service", "", {"spec": {"type": "ClusterIP", "selector": labels, "ports": [{"name": "ssh", "port": 22222, "targetPort": 22222, "protocol": "TCP"}]}}),
        obj("Pod", "", {"spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 1800,
            "terminationGracePeriodSeconds": 10, "enableServiceLinks": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
            "volumes": [{"name": "fixture", "configMap": {"name": name, "defaultMode": 0o444}},
                        {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
            "containers": [{"name": "target", "image": state["image"], "imagePullPolicy": "IfNotPresent",
                "command": ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "serve"],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}, {"name": "state", "mountPath": "/state"}],
                "readinessProbe": {"exec": {"command": ["/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "ready"]}, "periodSeconds": 2, "timeoutSeconds": 2, "failureThreshold": 5}}]}}),
    ]


def check_object(value, state, resource):
    require(isinstance(value, dict), "fixture object identity changed")
    metadata = value.get("metadata", {})
    require(isinstance(metadata, dict) and isinstance(metadata.get("labels"), dict), "fixture object identity changed")
    require(value.get("kind") == resource["kind"] and value.get("apiVersion") == RESOURCES[resource["kind"]][0]
            and metadata.get("name") == resource["name"] and metadata.get("namespace") == state["namespace"]
            and metadata.get("labels", {}).get(LABEL) == state["nonce"]
            and metadata.get("deletionTimestamp") is None, "fixture object identity changed")
    uid = identifier(metadata.get("uid"))
    require(resource.get("uid") is None or uid == resource["uid"], "fixture object UID changed")
    return uid


def get_owned(kube, state, kind):
    resource = next(item for item in state["resources"] if item["kind"] == kind)
    value = kube.run(["get", RESOURCES[kind][1], resource["name"], "-o", "json"])
    check_object(value, state, resource)
    return value


def runtime_image_format(value):
    if isinstance(value, str):
        if IMAGE.fullmatch(value):
            return "approved-repository-digest"
        if re.fullmatch(IMAGE.pattern.split("@sha256:", 1)[0] + r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", value):
            return "approved-repository-tag"
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            return "digest-only"
    return "unrecognized"


def observe(kube, state):
    require(time.time() < state["deadline"], "fixture lifetime expired")
    pod = get_owned(kube, state, "Pod")
    status, spec = pod.get("status"), pod.get("spec")
    require(isinstance(status, dict) and isinstance(spec, dict) and isinstance(status.get("conditions"), list)
            and all(isinstance(item, dict) for item in status["conditions"])
            and isinstance(spec.get("containers"), list) and len(spec["containers"]) == 1
            and isinstance(spec["containers"][0], dict), "invalid fixture Pod shape")
    require(status.get("phase") == "Running" and
            any(item.get("type") == "Ready" and item.get("status") == "True" for item in status["conditions"]), "fixture is not ready")
    require(pod["spec"]["containers"][0]["image"] == state["image"] and
            pod["spec"]["containers"][0]["name"] == "target", "fixture image changed")
    statuses = status.get("containerStatuses")
    require(isinstance(statuses, list) and len(statuses) == 1 and isinstance(statuses[0], dict), "invalid fixture container status")
    container = statuses[0]
    # Runtime imageID can name the selected OCI index's child manifest, not the
    # index itself. The immutable Pod spec is the pin; require the observed
    # runtime repository/image and a real content-addressed imageID as well.
    require(container.get("name") == "target" and container.get("ready") is True,
            "fixture runtime container changed")
    require(isinstance(container.get("image"), str) and IMAGE.fullmatch(container["image"])
            and container["image"].split("@", 1)[0] == state["image"].split("@", 1)[0],
            "fixture runtime image name changed (" + runtime_image_format(container.get("image")) + ")")
    require(isinstance(container.get("imageID"), str)
            and re.fullmatch(r"(?:docker-pullable://)?(?:[a-zA-Z0-9./_-]+@)?sha256:[0-9a-f]{64}|containerd://sha256:[0-9a-f]{64}", container["imageID"]), "fixture runtime imageID changed")
    service = get_owned(kube, state, "Service")
    require(isinstance(service.get("spec"), dict), "invalid fixture Service shape")
    require(service["spec"]["type"] == "ClusterIP" and service["spec"]["selector"] == {LABEL: state["nonce"]}
            and service["spec"]["ports"] == [{"name": "ssh", "port": 22222, "targetPort": 22222, "protocol": "TCP"}], "fixture service changed")
    try:
        address = ipaddress.ip_address(service["spec"]["clusterIP"])
    except ValueError:
        raise Failure("invalid fixture service address") from None
    require(address.version == 4 and not address.is_loopback and not address.is_unspecified, "invalid fixture service address")
    endpoints = kube.run(["get", "endpoints", state["name"], "-o", "json"])
    require(isinstance(endpoints, dict) and isinstance(endpoints.get("metadata"), dict)
            and isinstance(endpoints.get("subsets"), list) and
            all(isinstance(item, dict) and isinstance(item.get("addresses"), list)
                and all(isinstance(address, dict) and isinstance(address.get("targetRef"), dict) for address in item["addresses"])
                for item in endpoints["subsets"]), "invalid fixture endpoint shape")
    addresses = [item for subset in endpoints.get("subsets", []) for item in subset.get("addresses", [])]
    require(endpoints.get("metadata", {}).get("name") == state["name"] and endpoints["metadata"].get("namespace") == state["namespace"]
            and len(addresses) == 1 and addresses[0].get("targetRef", {}).get("uid") == pod["metadata"]["uid"]
            and addresses[0]["targetRef"].get("name") == state["name"] and addresses[0]["targetRef"].get("kind") == "Pod"
            and addresses[0]["targetRef"].get("namespace") == state["namespace"]
            and addresses[0].get("ip") == pod.get("status", {}).get("podIP")
            and all(subset.get("ports") == [{"name": "ssh", "port": 22222, "protocol": "TCP"}] and not subset.get("notReadyAddresses") for subset in endpoints.get("subsets", [])), "fixture endpoint identity changed")
    raw = kube.run(["exec", state["name"], "-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "ready"], as_json=False)
    require(len(raw) <= 512, "invalid fixture ready metadata")
    lines = raw.splitlines()
    require(len(lines) == 3 and lines[2] == CONTENT and re.fullmatch(r"[0-9a-f]{40}", lines[1]), "invalid fixture ready metadata")
    key = public_key(lines[0])
    # Reobserve the stored Pod UID after exec; replacement must not publish trust.
    get_owned(kube, state, "Pod")
    return {"version": 1, "url": f"ssh://codewire@{address}:22222/repository.git", "revision": lines[1],
            "known_hosts": [f"[{address}]:22222 {key}"], "content_path": "proof.txt", "content": CONTENT}


def load_state(directory):
    private_directory(directory)
    path = directory / "state.json"
    require(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_size <= 16384, "invalid fixture state")
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and set(value) == {"version", "context", "namespace", "nonce", "name", "organization", "user", "email", "image", "deadline", "resources"}
            and type(value["version"]) is int and value["version"] == 1 and re.fullmatch(r"[0-9a-f]{32}", value["nonce"])
            and value["name"] == "cw-checkout-" + value["nonce"] and value["namespace"] == DEV_NAMESPACE
            and IMAGE.fullmatch(value["image"]) and value["context"] == DEV_CONTEXT, "invalid fixture state")
    identifier(value["organization"])
    identifier(value["user"])
    require(all(re.fullmatch(r"[0-9a-f]{32}", value[key]) for key in ("organization", "user")), "invalid fixture state")
    require(value["email"] == "hello@codewire.sh" and isinstance(value["deadline"], (int, float)), "invalid fixture state")
    allowed = [("ConfigMap", ""), ("NetworkPolicy", "-source"), ("NetworkPolicy", "-target"), ("Service", ""), ("Pod", "")]
    require(isinstance(value["resources"], list) and len(value["resources"]) <= 5, "invalid fixture state")
    for resource, (kind, suffix) in zip(value["resources"], allowed):
        require(set(resource) == {"kind", "name", "uid"} and resource["kind"] == kind and resource["name"] == value["name"] + suffix, "invalid fixture state")
        if resource["uid"] is not None:
            identifier(resource["uid"])
    return value


def stop(kube, state, directory):
    failed = False
    # Remove source grant first. Continue independent exact-owned cleanup failures.
    ordered = sorted(state["resources"], key=lambda item: 0 if item["name"].endswith("-source") else
                     {"Pod": 1, "Service": 2, "NetworkPolicy": 3, "ConfigMap": 4}[item["kind"]])
    for resource in ordered:
        if resource["uid"] is None:
            failed = True  # Ambiguous create: never adopt/delete by labels alone.
            continue
        try:
            kind = resource["kind"]
            current = kube.run(["get", RESOURCES[kind][1], resource["name"], "--ignore-not-found", "-o", "json"], as_json=False)
            if not current.strip():
                continue
            check_object(json.loads(current), state, resource)
            if kind == "Pod":
                drained = False
                try:
                    prior = json.loads(current).get("status", {}).get("containerStatuses", [])
                    already_terminated = any(item.get("name") == "target" and item.get("state", {}).get("terminated") is not None for item in prior)
                    if not already_terminated:
                        raw = kube.run(["exec", resource["name"], "-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "drain"], as_json=False)
                        require(raw == "hosted-checkout-target-drain-requested\n", "fixture drain request failed")
                    deadline = time.monotonic() + 20
                    while True:
                        pod = get_owned(kube, state, "Pod")
                        statuses = pod.get("status", {}).get("containerStatuses", [])
                        terminated = [item.get("state", {}).get("terminated") for item in statuses if item.get("name") == "target"]
                        if len(terminated) == 1 and terminated[0] is not None:
                            require(terminated[0].get("exitCode") == 0, "fixture target drain failed")
                            break
                        require(time.monotonic() < deadline, "fixture target drain timed out")
                        time.sleep(0.2)
                    marker = kube.run(["logs", resource["name"], "-c", "target", "--tail=1"], as_json=False)
                    require(marker == "hosted-checkout-target-drained\n", "fixture target drain failed")
                    get_owned(kube, state, "Pod")
                    drained = True
                except (Failure, ValueError, OSError, KeyError, TypeError, AttributeError):
                    failed = True
                # Still delete exact owned resources on a failed drain, but
                # never emit a success finish receipt from object absence alone.
                if not drained:
                    failed = True
            api, plural = RESOURCES[kind]
            prefix = "/api/v1" if api == "v1" else "/apis/" + api
            kube.run(["delete", "--raw", f"{prefix}/namespaces/{state['namespace']}/{plural}/{resource['name']}", "-f", "-"],
                     {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": resource["uid"]}, "gracePeriodSeconds": 10})
            deadline = time.monotonic() + 30
            while True:
                remaining = kube.run(["get", plural, resource["name"], "--ignore-not-found", "-o", "json"], as_json=False)
                if not remaining.strip():
                    break
                require(json.loads(remaining).get("metadata", {}).get("uid") == resource["uid"], "fixture object UID changed")
                require(time.monotonic() < deadline, "fixture cleanup timed out")
                time.sleep(0.2)
        except (Failure, ValueError, OSError, KeyError, TypeError, AttributeError):
            failed = True
    require(not failed, "fixture cleanup incomplete; preserve state for diagnosis")
    write_json(directory / "finish.json", {"version": 1, "deleted": True})


def start(args):
    parent = args.state_dir.parent
    private_directory(parent)
    preflight(args, parent)
    require(not args.state_dir.exists() and not args.state_dir.is_symlink(), "fixture state directory already exists")
    require(args.public_key_file.is_absolute() and args.public_key_file.resolve() == args.public_key_file
            and args.public_key_file.is_file() and not args.public_key_file.is_symlink() and args.public_key_file.stat().st_size <= 256, "invalid public key file")
    key = public_key(args.public_key_file.read_text().removesuffix("\n"))
    args.state_dir.mkdir(mode=0o700)
    nonce = uuid.uuid4().hex
    state = {"version": 1, "context": args.context, "namespace": args.namespace, "nonce": nonce, "name": "cw-checkout-" + nonce,
             "organization": args.organization_id, "user": args.principal_user_id, "email": args.principal_email, "image": args.image,
             "deadline": time.time() + 1800, "resources": []}
    write_json(args.state_dir / "state.json", state)
    kube = Kube(args.context, args.namespace, args.state_dir)
    stage = "create"
    try:
        for manifest in manifests(state, key):
            resource = {"kind": manifest["kind"], "name": manifest["metadata"]["name"], "uid": None}
            state["resources"].append(resource)
            write_json(args.state_dir / "state.json", state)  # Intent survives a lost reply.
            created = kube.run(["create", "-f", "-", "-o", "json"], manifest)
            resource["uid"] = check_object(created, state, resource)
            write_json(args.state_dir / "state.json", state)
        stage = "readiness"
        kube.wait_ready(state["name"])
        stage = "observe"
        ready = observe(kube, state)
        write_json(args.state_dir / "ready.json", ready)
    except (Failure, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        code = (OBSERVATION_FAILURE_CODES.get(str(error), "operation-failed")
                if stage == "observe" and isinstance(error, Failure) else "operation-failed")
        try:
            write_json(args.state_dir / "failure.json", {"version": 1, "stage": stage, "code": code})
        finally:
            # Receipt I/O failure must not skip independently owned cleanup.
            try:
                stop(kube, state, args.state_dir)
            except Failure:
                raise Failure("fixture startup failed and cleanup is incomplete; preserve state") from None
        raise Failure("fixture startup failed; owned objects cleaned") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    create = sub.add_parser("start")
    before = sub.add_parser("preflight")
    for command in (create, before):
        for name in ("context", "namespace", "organization-id", "principal-user-id", "principal-email", "image"):
            command.add_argument("--" + name, required=True)
    create.add_argument("--state-dir", type=Path, required=True)
    create.add_argument("--public-key-file", type=Path, required=True)
    for name in ("inspect", "stop"):
        sub.add_parser(name).add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.mode == "preflight":
            runtime = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
            private_directory(runtime)
            with tempfile.TemporaryDirectory(prefix="cw-checkout-preflight-", dir=runtime) as temporary:
                preflight(args, Path(temporary))
        elif args.mode == "start":
            start(args)
        else:
            state = load_state(args.state_dir)
            kube = Kube(state["context"], state["namespace"], args.state_dir)
            cluster_trust(kube)
            if args.mode == "stop":
                stop(kube, state, args.state_dir)
            else:
                ready = observe(kube, state)
                require(ready == json.loads((args.state_dir / "ready.json").read_text()), "fixture trust changed")
                count = kube.run(["exec", state["name"], "-c", "target", "--", "/bin/bash", "--noprofile", "--norc", "/fixture/target.sh", "counter"], as_json=False)
                require(re.fullmatch(r"[0-9]{1,9}\n", count), "invalid fixture counter")
                get_owned(kube, state, "Pod")
                write_json(args.state_dir / "counter.json", {"version": 1, "authenticated": int(count)})
    except (Failure, OSError, ValueError, KeyError, TypeError, AttributeError):
        # Do not print exception/provider data or private configuration.
        print("hosted-checkout-fixture: failed; preserve owned state if cleanup is incomplete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
