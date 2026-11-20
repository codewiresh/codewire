"""cw-egress's manifests keep the shape its node-local stream and updates rely on.

A sandbox dials the one codewire-egress ClusterIP and must reach the cw-egress
on its own node or nothing, so the Service routes locally and the stream stays
plaintext on that basis (codewire#4000).

A new cw-egress version starts beside the old one on each node, and the old
Pod drains while it terminates (codewire#4000, item 5). That needs three things
of the DaemonSet: a surge rollout that never stops the old Pod before the new
one is Ready; nothing held once per node, since two Pods run there during a
rollout; and a grace period longer than the drain, so cw-egress cuts the last
streams itself and flushes their records before the kubelet kills it.
"""

from __future__ import annotations

import ipaddress

from .kubernetes import documents, exactly_one
from .shared import *

KUSTOMIZATION = "deployments/k8s/egress/kustomization.yaml"
DAEMONSET = "deployments/k8s/egress/daemonset.yaml"
SERVICE = "deployments/k8s/egress/service.yaml"
NETWORK_POLICY = "deployments/k8s/egress/network-policy.yaml"
IMAGE_PLACEHOLDER = "git.example.com/codewire/egress"
ORCHESTRATION_PORT = "8088"
# Ranges cw-egress's own Pod may never reach directly (design, "The Pod's
# network policy"); the broker it runs refuses them for sandboxes as well.
PRIVATE_V4 = (
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
)
# NAT64, Teredo and 6to4 addresses reach IPv4, private ranges and metadata
# included (cw-security on #5344). IPv4-mapped addresses are not here: a
# socket that dials one sends IPv4, which PRIVATE_V4 already holds, and
# Kubernetes refuses one in an ipBlock (ipblock_failures).
PRIVATE_V6 = (
    "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16",
    "fc00::/7", "fe80::/10", "ff00::/8",
)
# Every NetworkPolicy deploy applies from here; each ipBlock must pass the
# API server's own validation (ipblock_failures).
NETWORK_POLICY_ROOT = "deployments/k8s"
NAME = "codewire-egress"
DRAIN_SETTING = "CODEWIRE_EGRESS_DRAIN_SECONDS"
# What cw-egress needs after the deadline to flush records and exit.
EXIT_MARGIN_SECONDS = 30
STREAM_PORT = "8089"
PER_NODE_FIELDS = ("hostNetwork", "hostPID", "hostIPC")
# cw-egress runs unprivileged (#4000): its image names no user, so the Pod
# names one, and its projected token (0440) is readable through the Pod's
# group.
UNPRIVILEGED = (
    ("runAsNonRoot", "true"), ("runAsUser", "65532"), ("runAsGroup", "65532"),
    ("fsGroup", "65532"), ("fsGroupChangePolicy", "OnRootMismatch"),
)
# The ports cw-egress serves. It has no probe endpoint yet, so every probe
# and declared port is the stream port.
SERVED_PORTS = (STREAM_PORT, "stream")
PROBES = ("readinessProbe", "livenessProbe", "startupProbe")
PER_NODE_KEYS = ("hostPort", "hostPath")


def without_comments(document: str) -> str:
    return "\n".join(line for line in document.split("\n") if not line.lstrip().startswith("#"))


def values(document: str, key: str) -> list[str]:
    return re.findall(rf"^\s*(?:- )?{re.escape(key)}:\s*[\"']?([^\"'\s]+)[\"']?\s*$", document, re.MULTILINE)


def only(document: str, key: str, label: str, failures: list[str]) -> str | None:
    found = values(document, key)
    if len(found) != 1:
        failures.append(f"{label}: expected exactly one {key}, found {len(found)}")
        return None
    return found[0]


def nested(document: str, key: str) -> str:
    """The lines indented under the first `key:` line."""
    lines = document.split("\n")
    for index, line in enumerate(lines):
        if line.strip() == f"{key}:":
            indent = len(line) - len(line.lstrip())
            body: list[str] = []
            for following in lines[index + 1 :]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body.append(following)
            return "\n".join(body)
    return ""


def env_values(document: str, name: str) -> list[str]:
    return re.findall(
        rf"^\s*- name:\s*{re.escape(name)}\s*\n\s*value:\s*[\"']?([^\"'\s]+)[\"']?\s*$",
        document,
        re.MULTILINE,
    )


def daemonset_failures(document: str, label: str = DAEMONSET) -> list[str]:
    document = without_comments(document)
    failures: list[str] = []
    for field in PER_NODE_FIELDS:
        if "true" in values(document, field):
            failures.append(f"{label}: {field} is one per node; two cw-egress Pods share a node during a rollout")
    for key in PER_NODE_KEYS:
        if re.search(rf"^\s*(?:- )?{key}:", document, re.MULTILINE):
            failures.append(f"{label}: {key} is one per node; two cw-egress Pods share a node during a rollout")
    strategy = nested(document, "updateStrategy")
    if only(strategy, "type", f"{label} updateStrategy", failures) not in (None, "RollingUpdate"):
        failures.append(f"{label}: updateStrategy.type must be RollingUpdate")
    if only(strategy, "maxSurge", f"{label} updateStrategy", failures) not in (None, "1"):
        failures.append(f"{label}: maxSurge must be 1, so the new Pod starts beside the old one")
    if only(strategy, "maxUnavailable", f"{label} updateStrategy", failures) not in (None, "0"):
        failures.append(f"{label}: maxUnavailable must be 0, so the old Pod stops only once the new one is Ready")
    for key, wanted in UNPRIVILEGED:
        if values(document, key) != [wanted]:
            failures.append(
                f"{label}: {key} must be {wanted}, so cw-egress runs unprivileged and reads its token "
                "through the Pod's group"
            )
    if values(document, "containerPort") != [STREAM_PORT]:
        failures.append(f"{label}: cw-egress serves only the stream port {STREAM_PORT}; declare no other")
    if not values(nested(document, "readinessProbe"), "port"):
        failures.append(f"{label}: a readiness probe on the stream port lets a surge rollout wait for the new Pod")
    for probe in PROBES:
        unserved = [port for port in values(nested(document, probe), "port") if port not in SERVED_PORTS]
        if unserved:
            failures.append(f"{label}: {probe} targets {unserved}, which cw-egress doesn't serve")
    grace = only(document, "terminationGracePeriodSeconds", label, failures)
    drains = env_values(document, DRAIN_SETTING)
    if len(drains) != 1:
        failures.append(f"{label}: expected exactly one {DRAIN_SETTING}, found {len(drains)}")
    elif not drains[0].isdigit() or int(drains[0]) == 0:
        failures.append(f"{label}: {DRAIN_SETTING} must be a positive number of seconds, not {drains[0]!r}")
    elif grace is not None and grace != str(int(drains[0]) + EXIT_MARGIN_SECONDS):
        failures.append(
            f"{label}: terminationGracePeriodSeconds is {grace}; it must be {DRAIN_SETTING} "
            f"({drains[0]}) plus {EXIT_MARGIN_SECONDS}"
        )
    return failures


def wiring_failures(document: str, label: str = DAEMONSET) -> list[str]:
    """The image, DNS and orchestration address the design fixes."""
    document = without_comments(document)
    failures: list[str] = []
    if values(document, "image") != [IMAGE_PLACEHOLDER]:
        failures.append(f"{label}: the image must be exactly {IMAGE_PLACEHOLDER}, which the component pins by digest")
    if values(document, "automountServiceAccountToken") != ["false"]:
        failures.append(f"{label}: cw-egress reads no Kubernetes object, so no service account token is mounted")
    if values(document, "dnsPolicy") != ["None"]:
        failures.append(f"{label}: dnsPolicy must be None, so cw-egress reaches no server that answers cluster names")
    urls = env_values(document, "CODEWIRE_EGRESS_ORCHESTRATION_URL")
    addrs = env_values(document, "CODEWIRE_EGRESS_ORCHESTRATION_ADDR")
    if len(urls) != 1 or not re.fullmatch(rf"https://[a-z0-9.-]+:{ORCHESTRATION_PORT}", urls[0]):
        failures.append(f"{label}: CODEWIRE_EGRESS_ORCHESTRATION_URL must be one https origin on port {ORCHESTRATION_PORT}")
    if addrs != [f"$(CODEWIRE_ORCHESTRATION_SERVICE_HOST):{ORCHESTRATION_PORT}"]:
        failures.append(
            f"{label}: CODEWIRE_EGRESS_ORCHESTRATION_ADDR must be the service address on port {ORCHESTRATION_PORT}, "
            "the URL's port"
        )
    return failures


def network_policy_failures(document: str, label: str = NETWORK_POLICY) -> list[str]:
    document = without_comments(document)
    failures: list[str] = []
    for policy_type in ("Ingress", "Egress"):
        if not re.search(rf"^\s*- {policy_type}\s*$", document, re.MULTILINE):
            failures.append(f"{label}: policyTypes must include {policy_type}")
    ingress = nested(document, "ingress")
    if values(ingress, "codewire.sh/resource-type") != ["sandbox"] or values(ingress, "codewire.sh/egress") != ["broker"]:
        failures.append(f"{label}: only a broker-mode Pod in a sandbox namespace may open the stream")
    if values(ingress, "port") != [STREAM_PORT]:
        failures.append(f"{label}: ingress must open only the stream port {STREAM_PORT}")
    egress = nested(document, "egress")
    for cidr in ("0.0.0.0/0", "::/0"):
        if cidr not in values(egress, "cidr"):
            failures.append(f"{label}: egress must name {cidr} with its private ranges excepted")
    excepted = re.findall(r"^\s*- ([0-9a-f:.]+/[0-9]+)\s*$", egress, re.MULTILINE)
    for cidr in PRIVATE_V4 + PRIVATE_V6:
        if cidr not in excepted:
            failures.append(f"{label}: egress must except {cidr}")
    failures.extend(ipblock_failures(document, label))
    return failures


def ipblock_failures(document: str, label: str) -> list[str]:
    """Each ipBlock as the API server validates it: a CIDR in canonical
    form, never IPv4-mapped IPv6, and each except a strict subset of its
    cidr in the same family. Dev refused the first delivery of cw-egress on
    the mapped range (codewire#4000), which no offline schema catches."""
    failures: list[str] = []
    blocks = re.findall(
        r"^(\s*)(?:- )?ipBlock:\s*\n((?:\1\s+.*\n?)*)", without_comments(document), re.MULTILINE
    )
    for _, block in blocks:
        cidr_values = re.findall(r"^\s*cidr:\s*['\"]?([^'\"\s]+)", block, re.MULTILINE)
        excepts = re.findall(r"^\s*- ['\"]?([0-9A-Fa-f:.]+/[0-9]+)['\"]?\s*$", block, re.MULTILINE)
        if len(cidr_values) != 1:
            failures.append(f"{label}: an ipBlock must have exactly one cidr")
            continue
        parsed: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        for value in cidr_values + excepts:
            try:
                network = ipaddress.ip_network(value)
            except ValueError:
                failures.append(f"{label}: {value} is not a CIDR in canonical form")
                continue
            if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped is not None:
                failures.append(f"{label}: {value} is IPv4-mapped IPv6, which Kubernetes refuses in an ipBlock")
                continue
            parsed[value] = network
        outer = parsed.get(cidr_values[0])
        if outer is None:
            continue
        for value in excepts:
            inner = parsed.get(value)
            if inner is None:
                continue
            if inner.version != outer.version or not inner.subnet_of(outer) or inner == outer:
                failures.append(f"{label}: except {value} must be a strict subset of cidr {cidr_values[0]}")
    return failures


def component_failures(document: str, label: str = KUSTOMIZATION) -> list[str]:
    document = without_comments(document)
    failures: list[str] = []
    if values(document, "kind") != ["Component"]:
        failures.append(f"{label}: cw-egress is a Component an overlay opts into, never part of base")
    for resource in ("serviceaccount.yaml", "daemonset.yaml", "service.yaml", "network-policy.yaml"):
        if resource not in re.findall(r"^\s*- (\S+)\s*$", nested(document, "resources"), re.MULTILINE):
            failures.append(f"{label}: the component must include {resource}")
    return failures


def service_failures(document: str, label: str = SERVICE) -> list[str]:
    document = without_comments(document)
    failures: list[str] = []
    if only(document, "internalTrafficPolicy", label, failures) not in (None, "Local"):
        failures.append(f"{label}: internalTrafficPolicy must be Local, so a sandbox never reaches another node's cw-egress")
    if only(document, "port", label, failures) not in (None, STREAM_PORT):
        failures.append(f"{label}: the stream port must be {STREAM_PORT}")
    if only(document, "protocol", label, failures) not in (None, "TCP"):
        failures.append(f"{label}: the stream port must be TCP")
    return failures


GOOD_DAEMONSET = """apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: codewire-egress
spec:
  updateStrategy:
    # maxSurge: 3 in a comment is not a setting
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      terminationGracePeriodSeconds: 1830
      securityContext:
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
      containers:
        - name: egress
          ports:
            - containerPort: 8089
              name: stream
          env:
            - name: CODEWIRE_EGRESS_DRAIN_SECONDS
              value: "1800"
          readinessProbe:
            tcpSocket:
              port: stream
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            seccompProfile:
              type: RuntimeDefault
"""
GOOD_SERVICE = """apiVersion: v1
kind: Service
metadata:
  name: codewire-egress
spec:
  type: ClusterIP
  internalTrafficPolicy: Local
  ports:
    - port: 8089
      targetPort: 8089
      protocol: TCP
"""

GOOD_WIRING = """spec:
  template:
    spec:
      automountServiceAccountToken: false
      dnsPolicy: None
      containers:
        - name: egress
          image: git.example.com/codewire/egress
          env:
            - name: CODEWIRE_EGRESS_ORCHESTRATION_URL
              value: https://codewire-orchestration.prod.svc.cluster.local:8088
            - name: CODEWIRE_EGRESS_ORCHESTRATION_ADDR
              value: $(CODEWIRE_ORCHESTRATION_SERVICE_HOST):8088
"""
GOOD_POLICY = """spec:
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              codewire.sh/resource-type: sandbox
          podSelector:
            matchLabels:
              codewire.sh/egress: broker
      ports:
        - protocol: TCP
          port: 8089
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 100.64.0.0/10
              - 127.0.0.0/8
              - 169.254.0.0/16
              - 172.16.0.0/12
              - 192.0.0.0/24
              - 192.168.0.0/16
              - 198.18.0.0/15
              - 224.0.0.0/4
              - 240.0.0.0/4
        - ipBlock:
            cidr: ::/0
            except:
              - ::1/128
              - 64:ff9b::/96
              - 64:ff9b:1::/48
              - 2001::/32
              - 2002::/16
              - fc00::/7
              - fe80::/10
              - ff00::/8
"""
GOOD_COMPONENT = """apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component
resources:
  - serviceaccount.yaml
  - daemonset.yaml
  - service.yaml
  - network-policy.yaml
"""


# Orchestration takes the egress, binding and DERP Services' addresses for
# broker-mode Sandboxes from the Service links Kubernetes gives its Pod (#4000).
ORCHESTRATION_DEPLOYMENTS = (
    "deployments/k8s/orchestration/deployment.yaml",
    "deployments/helm/codewire/templates/orchestration.yaml",
)


def service_link_failures(text: str, where: str) -> list[str]:
    """Orchestration's Pod keeps the Service links broker-mode rendering reads."""
    if re.search(r"^\s*enableServiceLinks:\s*false\b", text, re.MULTILINE):
        return [f"{where}: orchestration must keep enableServiceLinks on; broker-mode Sandboxes take three Services' addresses from it"]
    return []


def self_test() -> list[str]:
    failures: list[str] = []
    if service_link_failures("spec:\n  enableServiceLinks: true\n", "fixture"):
        failures.append("egress manifests self-test: kept Service links were refused")
    if not service_link_failures("spec:\n      enableServiceLinks: false\n", "fixture"):
        failures.append("egress manifests self-test: orchestration without Service links passed")
    if daemonset_failures(GOOD_DAEMONSET, "fixture"):
        failures.append("egress manifests self-test: the good DaemonSet was refused")
    if service_failures(GOOD_SERVICE, "fixture"):
        failures.append("egress manifests self-test: the good Service was refused")
    refused_daemonsets = {
        "no surge": ("      maxSurge: 1\n", ""),
        "a surge of two": ("maxSurge: 1", "maxSurge: 2"),
        "a surge as a share": ("maxSurge: 1", 'maxSurge: "25%"'),
        "an unavailable Pod": ("maxUnavailable: 0", "maxUnavailable: 1"),
        "OnDelete": ("type: RollingUpdate", "type: OnDelete"),
        "a grace period equal to the drain": ("terminationGracePeriodSeconds: 1830", "terminationGracePeriodSeconds: 1800"),
        "a grace period shorter than the drain": ("terminationGracePeriodSeconds: 1830", "terminationGracePeriodSeconds: 15"),
        "no grace period": ("      terminationGracePeriodSeconds: 1830\n", ""),
        "no drain setting": ('            - name: CODEWIRE_EGRESS_DRAIN_SECONDS\n              value: "1800"\n', ""),
        "a drain of zero": ('value: "1800"', 'value: "0"'),
        "a drain that is not a number": ('value: "1800"', 'value: "30m"'),
        "the host network": ("    spec:\n", "    spec:\n      hostNetwork: true\n"),
        "a host port": ("          env:\n", "          ports:\n            - containerPort: 8089\n              hostPort: 8089\n          env:\n"),
        "a host path": ("      containers:\n", "      volumes:\n        - name: lock\n          hostPath:\n            path: /run/cw-egress\n      containers:\n"),
        "no user": ("            runAsUser: 65532\n", ""),
        "the root user": ("runAsUser: 65532", "runAsUser: 0"),
        "no group": ("            runAsGroup: 65532\n", ""),
        "the root group": ("runAsGroup: 65532", "runAsGroup: 0"),
        "root allowed": ("runAsNonRoot: true", "runAsNonRoot: false"),
        "no fsGroup": ("        fsGroup: 65532\n", ""),
        "an fsGroup the token isn't shared with": ("fsGroup: 65532", "fsGroup: 1000"),
        "a recursive relabel on every start": ("fsGroupChangePolicy: OnRootMismatch", "fsGroupChangePolicy: Always"),
        "an unserved port": ("              name: stream\n", "              name: stream\n            - containerPort: 8098\n              name: http\n"),
        "no readiness probe": ("          readinessProbe:\n            tcpSocket:\n              port: stream\n", ""),
        "a readiness probe on an unserved port": ("tcpSocket:\n              port: stream", "httpGet:\n              path: /readyz\n              port: 8098"),
        "a liveness probe on an unserved port": ("          securityContext:\n            runAsNonRoot", "          livenessProbe:\n            httpGet:\n              path: /healthz\n              port: http\n          securityContext:\n            runAsNonRoot"),
    }
    for name, (old, new) in refused_daemonsets.items():
        if GOOD_DAEMONSET.count(old) != 1:
            failures.append(f"egress manifests self-test: the fixture for {name} does not apply")
        elif not daemonset_failures(GOOD_DAEMONSET.replace(old, new), "fixture"):
            failures.append(f"egress manifests self-test: {name} was admitted")
    refused_services = {
        "cluster-wide routing": ("internalTrafficPolicy: Local", "internalTrafficPolicy: Cluster"),
        "no traffic policy": ("  internalTrafficPolicy: Local\n", ""),
        "another port": ("- port: 8089", "- port: 8090"),
        "UDP": ("protocol: TCP", "protocol: UDP"),
    }
    for name, (old, new) in refused_services.items():
        if GOOD_SERVICE.count(old) != 1:
            failures.append(f"egress manifests self-test: the fixture for {name} does not apply")
        elif not service_failures(GOOD_SERVICE.replace(old, new), "fixture"):
            failures.append(f"egress manifests self-test: {name} was admitted")
    checks = (
        (wiring_failures, GOOD_WIRING, {
            "a tagged image": ("codewire/egress\n", "codewire/egress:latest\n"),
            "another image": ("codewire/egress\n", "codewire/services\n"),
            "a mounted token": ("automountServiceAccountToken: false", "automountServiceAccountToken: true"),
            "cluster DNS": ("dnsPolicy: None", "dnsPolicy: ClusterFirst"),
            "an address on another port": ("SERVICE_HOST):8088", "SERVICE_HOST):8087"),
            "a URL on another port": ("cluster.local:8088", "cluster.local:443"),
            "a named address": ("$(CODEWIRE_ORCHESTRATION_SERVICE_HOST):8088", "codewire-orchestration:8088"),
        }),
        (network_policy_failures, GOOD_POLICY, {
            "no egress policy type": ("    - Egress\n", ""),
            "any Pod in a sandbox namespace": ("          podSelector:\n            matchLabels:\n              codewire.sh/egress: broker\n", ""),
            "another ingress port": ("port: 8089", "port: 8098"),
            "a private range opened": ("              - 10.0.0.0/8\n", ""),
            "CGNAT opened": ("              - 100.64.0.0/10\n", ""),
            "IPv6 local opened": ("              - fc00::/7\n", ""),
            "NAT64 opened": ("              - 64:ff9b::/96\n", ""),
            "an IPv4-mapped except": ("              - ::1/128\n", "              - ::1/128\n              - ::ffff:0:0/96\n"),
            "an IPv4-mapped cidr": ("cidr: ::/0", "cidr: ::ffff:0:0/96"),
            "an except outside its cidr": ("              - 10.0.0.0/8\n", "              - 10.0.0.0/8\n              - fc00::/7\n"),
            "a non-canonical CIDR": ("              - 10.0.0.0/8\n", "              - 10.0.0.1/8\n"),
            "6to4 opened": ("              - 2002::/16\n", ""),
            "Teredo opened": ("              - 2001::/32\n", ""),
            "IPv6 multicast opened": ("              - ff00::/8\n", ""),
        }),
        (component_failures, GOOD_COMPONENT, {
            "a plain kustomization": ("kind: Component", "kind: Kustomization"),
            "no network policy": ("  - network-policy.yaml\n", ""),
        }),
    )
    for check, good, refused in checks:
        if check(good, "fixture"):
            failures.append(f"egress manifests self-test: the good fixture for {check.__name__} was refused")
        for name, (old, new) in refused.items():
            if good.count(old) != 1:
                failures.append(f"egress manifests self-test: the fixture for {name} does not apply")
            elif not check(good.replace(old, new), "fixture"):
                failures.append(f"egress manifests self-test: {name} was admitted")
    return failures


def check_egress_manifests(args: argparse.Namespace) -> int:
    if args.self_test:
        if report("egress manifests", self_test()):
            return 1
        print("egress manifests: OK (self-test)")
        return 0
    failures: list[str] = []
    daemonset = exactly_one(documents(read_text(DAEMONSET)), "DaemonSet", NAME, DAEMONSET, failures)
    service = exactly_one(documents(read_text(SERVICE)), "Service", NAME, SERVICE, failures)
    policy = exactly_one(documents(read_text(NETWORK_POLICY)), "NetworkPolicy", NAME, NETWORK_POLICY, failures)
    failures.extend(component_failures(read_text(KUSTOMIZATION)))
    for deployment in ORCHESTRATION_DEPLOYMENTS:
        failures.extend(service_link_failures(read_text(deployment), deployment))
    # The pin, once set, is one digest-only images entry: overlays name the
    # registry and never set a digest or tag (egress-image-pin.py).
    pin = subprocess.run(
        [sys.executable, str(ROOT / "scripts/ci/images/egress-image-pin.py"), "check"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if pin.returncode != 0:
        failures.append(f"{KUSTOMIZATION}: {pin.stderr.strip()}")
    if daemonset is not None:
        failures.extend(daemonset_failures(daemonset))
        failures.extend(wiring_failures(daemonset))
    if service is not None:
        failures.extend(service_failures(service))
    if policy is not None:
        failures.extend(network_policy_failures(policy))
    # Every other NetworkPolicy deploy applies holds the same ipBlock rules.
    for path in sorted((ROOT / NETWORK_POLICY_ROOT).rglob("*.yaml")):
        relative = str(path.relative_to(ROOT))
        if relative == NETWORK_POLICY:
            continue
        for document in documents(path.read_text(encoding="utf-8")):
            if re.search(r"^kind: NetworkPolicy\s*$", document, re.MULTILINE):
                failures.extend(ipblock_failures(document, relative))
    if report("egress manifests", failures):
        return 1
    print("egress manifests: OK")
    return 0
