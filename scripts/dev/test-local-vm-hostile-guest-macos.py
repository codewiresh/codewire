#!/usr/bin/env python3
"""Hostile-guest network battery in a real macOS local VM (#2615, #1906, #1911).

Run on an Apple silicon Mac against a built cw and a runtime directory from
`make macos-local-runtime` (or scripts/dev/macos-local-runtime.py --pack):

  scripts/dev/test-local-vm-hostile-guest-macos.py --cw /abs/cw --runtime /abs/runtime-dir [--docker]

It creates a local VM as test-cli-local-vm-macos.py does (private root, own
HOME, throwaway keychain), installs python3 in the guest and runs
hostile-guest-probe.py as the workload's root. Each probe tries one way past
the network boundary:
- raw and ping-socket ICMP, UDP to public resolvers and NTP;
- TCP to public addresses on ports the baseline denies;
- TCP to every protected range, the Mac's own addresses, its default
  gateway and the network's public address (#2614);
- IPv6 and IPv4-mapped destinations, and DNS answers naming private,
  loopback or metadata addresses;
- adding an interface, address or route;
- AF_VSOCK to host ports, to the guest's own daemon and network agent, and
  binding their ports;
- TLS and DNS while another connection's dial hangs, which must not stop
  them (#2638);
- bursts toward the network worker: malformed DNS questions to the guest
  resolver address, 300 parallel connects and, where a raw socket exists,
  crafted fragments, spoofed sources, IP options and odd TCP flags. The
  allowed controls must still work after each burst.

Controls (DNS, TCP and HTTPS to allowed destinations) must succeed, or the
run is invalid. With --docker it repeats the probes from a container inside a
Docker-enabled VM (docker:28-dind). Docker gives a container CAP_NET_RAW and
its own eth0, so there a raw socket may open, but nothing sent on it may get
an answer, and the container's traffic must still leave only through cw0.

Each case's outcome is judged here: `pass`; `bypass`, which fails the run;
`review`, a reachable path that may still authenticate, which is reported and
fails the run until its finding is recorded in ACCEPTED_REVIEWS; `broken`,
the network path no longer serving after a burst, which fails the run;
`degraded`, the VM's own DNS answering again only after a delay, which is
reported; or `info`, recorded only. Needs network egress for the image pulls and the controls.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


journey_module = load("local_vm_journey", "test-cli-local-vm-macos.py")
cli_host = journey_module.cli_host

PROBE = Path(__file__).with_name("hostile-guest-probe.py")
DOCKER_NAME = "hostile-docker"
DOCKER_IMAGE = "docker.io/library/docker:28-dind"
PROBE_CONTAINER_IMAGE = "docker.io/library/python:3.13-alpine"
NOT_CONNECTED = {"timeout", "refused", "ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL",
                 "EAFNOSUPPORT", "ECONNRESET", "EPERM", "EACCES"}
# Reachable paths reviewed and recorded as safe, with where the finding lives.
ACCEPTED_REVIEWS = {}


# Docker gives containers CAP_NET_RAW and their own network namespace; their
# traffic still leaves through the VM's cw0, which the other probes prove.
EXPECTED_INTERFACES = {"workload": "cw0 lo", "docker": "eth0 lo"}


def judge(case, outcome, detail, where="workload"):
    """(verdict, reason) for one probe result."""
    if case.startswith("control-"):
        kind = case.rsplit("-", 1)[-1]
        if case.startswith("control-after-") and kind == "dns":
            if outcome != "resolved":
                return "broken", f"DNS did not answer within {detail} s of the burst"
            return ("pass", "") if float(detail) < 1 else \
                ("degraded", f"DNS answered again after {detail} s (this VM only)")
        ok = (outcome == "resolved" if kind == "dns" or case.startswith("control-dns-") else
              outcome == "connected" if kind == "tcp" or case.startswith("control-tcp-") else
              outcome == "answered" if kind == "http" or case.startswith("control-http-") else
              outcome == "handshake" if case.startswith("control-tls-") else
              outcome == "status" and detail == "200")
        if ok:
            return "pass", "allowed traffic works"
        if case.startswith("control-after-"):
            return "broken", "the network path stopped serving after the burst"
        return "invalid", "an allowed control failed"
    if case.startswith("concurrency-"):
        ok = outcome in {"handshake", "resolved"}
        return ("pass", "") if ok else ("broken", "a pending dial stopped other traffic (#2638)")
    if case.startswith("info-") or case == "done" or case.endswith("-burst"):
        return "info", ""
    if case == "raw-icmp-socket":
        if outcome in {"EPERM", "EACCES"}:
            return "pass", ""
        if where == "docker":
            return "info", "Docker grants containers CAP_NET_RAW; what it sends is judged next"
        return "bypass", "raw socket created"
    if case.startswith("raw-icmp-echo"):
        return ("bypass", "raw ICMP answered") if outcome == "reply" else ("pass", "")
    if case.startswith("ping-socket"):
        return ("bypass", "ICMP echo answered") if outcome == "reply" else ("pass", "")
    if case.startswith("udp-"):
        return ("bypass", "UDP answered") if outcome == "reply" else ("pass", "")
    if case.startswith(("tcp-", "tcp6-")):
        if outcome == "unknown":
            return "invalid", detail
        return ("pass", "") if outcome in NOT_CONNECTED else ("bypass", f"TCP {outcome}")
    if case.startswith("dns-"):
        return ("pass", "") if outcome == "unresolved" else ("bypass", f"resolved to a protected address: {detail}")
    if case == "interfaces":
        expected = EXPECTED_INTERFACES[where]
        return ("pass", "") if outcome == expected else ("bypass", f"unexpected interfaces: {outcome}")
    if case.startswith("ip-"):
        return ("bypass", "network configuration changed") if outcome == "ok" else ("pass", "")
    if case == "vsock-socket":
        return "info", ""
    if case.startswith(("vsock-host-", "vsock-local-")):
        if outcome != "connected":
            return "pass", ""
        if case in ACCEPTED_REVIEWS:
            return "pass", f"reviewed: {ACCEPTED_REVIEWS[case]}"
        return "review", f"reachable from the workload ({detail})"
    if case.startswith("vsock-bind-"):
        return ("pass", "") if outcome in {"EADDRINUSE", "EACCES", "EPERM"} else \
            ("bypass", f"the workload can take the port: {outcome}")
    return "review", "unknown case"


def mac_addresses():
    """The Mac's own IPv4 addresses and its default gateway."""
    addresses = set()
    listed = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, check=True).stdout
    for line in listed.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "inet" and not fields[1].startswith("127."):
            addresses.add(fields[1])
    route = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True).stdout
    for line in route.splitlines():
        key, _, value = line.strip().partition(": ")
        if key == "gateway" and value.count(".") == 3:
            addresses.add(value)
    return sorted(addresses)


class HostileGuestBattery(journey_module.LocalVmJourney):
    def __init__(self, cw, runtime, docker):
        super().__init__(cw, runtime)
        self.docker = docker
        self.docker_created = False
        shutil.copy(PROBE, self.project / PROBE.name)

    def results(self, output, where):
        rows = []
        for line in output.splitlines():
            if line.startswith("{"):
                row = json.loads(line)
                verdict, reason = judge(row["case"], row["outcome"], row["detail"], where)
                rows.append({**row, "where": where, "verdict": verdict, "reason": reason})
        assert any(row["case"] == "done" for row in rows), f"the {where} probe did not finish:\n{output}"
        return rows

    def probe_arguments(self):
        return [argument for address in mac_addresses() for argument in ("--host-address", address)]

    def run(self):
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "journey", str(self.keychain)], check=True)
        subprocess.run(["/usr/bin/security", "set-keychain-settings", str(self.keychain)], check=True)
        self.call("setup", "--local", "--from", self.runtime, timeout=600)
        self.created = True
        self.call("env", "--local", "create", "--name", journey_module.NAME, "--image", journey_module.IMAGE,
                  "--no-docker", "--yes", timeout=900)
        self.environment_id = self.info()["id"]
        # apk's mirror is ordinary allowed HTTPS; a lookup can still fail once.
        self.guest("for n in 1 2 3; do apk add --quiet --no-cache python3 iproute2 && exit 0; sleep 3; done; exit 1",
                   timeout=300)
        arguments = " ".join(self.probe_arguments())
        output = self.guest(f"python3 /workspace/project/{PROBE.name} {arguments}", timeout=600).stdout
        rows = self.results(output, "workload")
        if self.docker:
            rows += self.docker_rows(arguments)
        return rows

    def docker_rows(self, arguments):
        self.docker_created = True
        self.call("env", "--local", "create", "--name", DOCKER_NAME, "--image", DOCKER_IMAGE,
                  "--docker-disk", "1Gi", "--yes", timeout=1200)
        # dockerd need not see the workload's paths, so the probe goes in on stdin.
        command = (f"docker run --rm -i {PROBE_CONTAINER_IMAGE} "
                   f"sh -c 'apk add --quiet --no-cache iproute2 >/dev/null 2>&1; python3 - {arguments}' "
                   f"< /workspace/project/{PROBE.name}")
        output = self.call("run", DOCKER_NAME, "--no-tty", "--", "sh", "-c", command, timeout=900).stdout
        return self.results(output, "docker")

    def remove_environment(self):
        if self.docker_created:
            self.call("env", "--local", "rm", DOCKER_NAME, "--yes", ok=False, timeout=600)
        super().remove_environment()


def report(rows):
    width = max(len(row["case"]) for row in rows)
    for row in rows:
        if row["verdict"] != "info" or row["case"] != "done":
            note = row["reason"] or (row["detail"] if row["verdict"] == "info" else "")
            print(f"{row['where']:8} {row['case']:{width}}  {row['verdict']:7} {row['outcome']}"
                  f"{'  ' + note if note else ''}")
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print("hostile-guest: " + " ".join(f"{verdict}={count}" for verdict, count in sorted(counts.items())))
    return counts


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise SystemExit("test-local-vm-hostile-guest-macos.py needs an Apple silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    parser.add_argument("--docker", action="store_true", help="repeat the probes from a container in a Docker VM")
    args = parser.parse_args()
    cli_host.arm_owned_session()
    battery = HostileGuestBattery(args.cw, args.runtime, args.docker)
    try:
        rows = battery.run()
    finally:
        battery.cleanup()
    counts = report(rows)
    if counts.get("invalid"):
        raise SystemExit("hostile-guest: INVALID, an allowed control failed")
    if counts.get("bypass") or counts.get("review") or counts.get("broken"):
        raise SystemExit("hostile-guest: FAIL")
    print("hostile-guest: all checks PASS")


if __name__ == "__main__":
    main()
