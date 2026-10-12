#!/usr/bin/env python3
"""Hostile-guest network battery against an existing environment (#2615, #1906, #1911).

Runs hostile-guest-probe.py as the workload's root in an environment the
caller already owns, and judges each outcome. It is the portable half of the
battery: test-local-vm-hostile-guest-macos.py creates a macOS local VM and
uses it, and on Linux it runs against a native local VM from the checked-in
native topology:

  scripts/dev/test-local-vm-hostile-guest.py --cw /abs/cw --environment NAME [--local-host] [--docker]

--local-host adds this machine's own addresses and its default gateway to the
protected destinations; pass it only when the environment runs on this
machine. --docker repeats the probes from a container through the
environment's own Docker. The probe is staged in the guest's /tmp, and
python3 is installed with apk or apt-get when missing (ordinary allowed
HTTPS). Nothing is created or removed outside the guest's /tmp.

Each case's outcome is judged: `pass`; `bypass`, which fails the run;
`review`, a reachable path that may still authenticate, which is reported and
fails the run until its finding is recorded in ACCEPTED_REVIEWS; `broken`,
the network path no longer serving after a burst, which fails the run;
`degraded`, the VM's own DNS answering again only after a delay, which is
reported; or `info`, recorded only. Allowed controls must succeed first, or
the run is invalid.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

PROBE = Path(__file__).with_name("hostile-guest-probe.py")
GUEST_PROBE = "/tmp/hostile-guest-probe.py"
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


def results(output, where):
    """The judged rows of one probe run; the probe must have finished."""
    rows = []
    for line in output.splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            verdict, reason = judge(row["case"], row["outcome"], row["detail"], where)
            rows.append({**row, "where": where, "verdict": verdict, "reason": reason})
    assert any(row["case"] == "done" for row in rows), f"the {where} probe did not finish:\n{output}"
    return rows


def host_addresses():
    """This machine's own IPv4 addresses and its default gateway."""
    addresses = set()
    if sys.platform == "darwin":
        listed = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, check=True).stdout
        for line in listed.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "inet":
                addresses.add(fields[1])
        route = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True).stdout
        for line in route.splitlines():
            key, _, value = line.strip().partition(": ")
            if key == "gateway" and value.count(".") == 3:
                addresses.add(value)
    else:
        listed = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=True).stdout
        for line in listed.splitlines():
            fields = line.split()
            if "inet" in fields:
                addresses.add(fields[fields.index("inet") + 1].split("/")[0])
        route = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout
        for line in route.splitlines():
            fields = line.split()
            if "via" in fields:
                addresses.add(fields[fields.index("via") + 1])
    return sorted(address for address in addresses if not address.startswith("127."))


class GuestRunner:
    """Stages and runs the probe in one environment through `call(*cw_args, timeout=)`."""

    def __init__(self, call, environment):
        self.call = call
        self.environment = environment

    def sh(self, command, timeout):
        return self.call("run", self.environment, "--no-tty", "--", "sh", "-c", command, timeout=timeout)

    def stage(self):
        encoded = base64.b64encode(PROBE.read_bytes()).decode()
        # apk's or apt's mirror is ordinary allowed HTTPS; a lookup can still fail once.
        self.sh("command -v python3 >/dev/null && command -v ip >/dev/null && exit 0; "
                "for n in 1 2 3; do "
                "if command -v apk >/dev/null; then apk add --quiet --no-cache python3 iproute2 && exit 0; "
                "else apt-get update -qq && apt-get install -y -qq python3 iproute2 >/dev/null && exit 0; fi; "
                "sleep 3; done; exit 1", timeout=600)
        self.sh(f"printf %s {encoded} | base64 -d > {GUEST_PROBE}", timeout=60)

    def workload(self, arguments):
        command = f"python3 {GUEST_PROBE} {shlex.join(arguments)}"
        return results(self.sh(command, timeout=900).stdout, "workload")

    def docker(self, arguments):
        # The container gets the probe on stdin, so dockerd need not see the guest's paths.
        command = (f"docker run --rm -i {PROBE_CONTAINER_IMAGE} sh -c "
                   f"{shlex.quote('apk add --quiet --no-cache iproute2 >/dev/null 2>&1; python3 - ' + shlex.join(arguments))}"
                   f" < {GUEST_PROBE}")
        return results(self.sh(command, timeout=900).stdout, "docker")


def report(rows):
    width = max(len(row["case"]) for row in rows)
    for row in rows:
        if row["case"] != "done":
            note = row["reason"] or (row["detail"] if row["verdict"] == "info" else "")
            print(f"{row['where']:8} {row['case']:{width}}  {row['verdict']:7} {row['outcome']}"
                  f"{'  ' + note if note else ''}")
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print("hostile-guest: " + " ".join(f"{verdict}={count}" for verdict, count in sorted(counts.items())))
    return counts


def finish(rows):
    counts = report(rows)
    if counts.get("invalid"):
        raise SystemExit("hostile-guest: INVALID, an allowed control failed")
    if counts.get("bypass") or counts.get("review") or counts.get("broken"):
        raise SystemExit("hostile-guest: FAIL")
    print("hostile-guest: all checks PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--environment", required=True, help="an existing environment the caller owns")
    parser.add_argument("--local-host", action="store_true",
                        help="add this machine's addresses and gateway; only for an environment on this machine")
    parser.add_argument("--host-address", action="append", default=[], help="another protected address to probe")
    parser.add_argument("--docker", action="store_true", help="repeat the probes from a container in its Docker")
    args = parser.parse_args()
    cw = str(Path(args.cw).resolve())

    def call(*cw_args, timeout):
        result = subprocess.run([cw, *cw_args], stdin=subprocess.DEVNULL, text=True, capture_output=True,
                                timeout=timeout)
        if result.returncode != 0:
            raise AssertionError(f"cw {cw_args[:4]}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    addresses = sorted(set(args.host_address) | (set(host_addresses()) if args.local_host else set()))
    arguments = [argument for address in addresses for argument in ("--host-address", address)]
    guest = GuestRunner(call, args.environment)
    guest.stage()
    rows = guest.workload(arguments)
    if args.docker:
        rows += guest.docker(arguments)
    finish(rows)


if __name__ == "__main__":
    main()
