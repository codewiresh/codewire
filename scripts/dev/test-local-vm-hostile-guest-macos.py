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
- a name whose DNS answers alternate between a public and a private address,
  whose private answer must never reach the guest;
- TLS and DNS while another connection's dial hangs, which must not stop
  them (#2638);
- bursts toward the network worker: malformed DNS questions to the guest
  resolver address, 300 parallel connects and, where a raw socket exists,
  crafted fragments, spoofed sources, IP options and odd TCP flags. The
  allowed controls must still work after each burst.

Controls (DNS, TCP and HTTPS to allowed destinations) must succeed, or the
run is invalid. With --docker it repeats the probes from a container inside a
Docker-enabled VM (docker:28-dind), and checks from the Mac that a port a
guest container publishes with -p is reachable only inside its VM, and that
a host port taken by one environment is refused to another until released.
Docker gives a container CAP_NET_RAW and its own eth0, so there a raw socket
may open, but nothing sent on it may get an answer, and the container's
traffic must still leave only through cw0.

Staging, the probes and their judgement are test-local-vm-hostile-guest.py's,
which also runs the same battery against an existing Linux local VM or other
environment. Needs network egress for the image pulls and the controls.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


journey_module = load("local_vm_journey", "test-cli-local-vm-macos.py")
battery = load("hostile_guest", "test-local-vm-hostile-guest.py")
cli_host = journey_module.cli_host

DOCKER_NAME = "hostile-docker"
DOCKER_IMAGE = "docker.io/library/docker:28-dind"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tcp_outcome(address, port):
    try:
        with socket.create_connection((address, port), timeout=3):
            return "connected"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as error:
        return type(error).__name__


class HostileGuestBattery(journey_module.LocalVmJourney):
    def __init__(self, cw, runtime, docker):
        super().__init__(cw, runtime)
        self.docker = docker
        self.docker_created = False

    def run(self):
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "journey", str(self.keychain)], check=True)
        subprocess.run(["/usr/bin/security", "set-keychain-settings", str(self.keychain)], check=True)
        self.call("setup", "--local", "--from", self.runtime, timeout=600)
        self.created = True
        self.call("--local", "create", "--name", journey_module.NAME, "--image", journey_module.IMAGE,
                  "--no-docker", "--yes", timeout=900)
        self.environment_id = self.info()["id"]
        arguments = [argument for address in battery.host_addresses() for argument in ("--host-address", address)]
        guest = battery.GuestRunner(self.call, journey_module.NAME)
        guest.stage()
        rows = guest.workload(arguments)
        if self.docker:
            self.docker_created = True
            self.call("--local", "create", "--name", DOCKER_NAME, "--image", DOCKER_IMAGE,
                      "--docker-disk", "1Gi", "--yes", timeout=1200)
            docker = battery.GuestRunner(self.call, DOCKER_NAME)
            docker.stage()
            rows += docker.docker(arguments)
            rows += self.host_side()
        return rows

    def host_side(self):
        """A guest Docker -p port stays inside its VM, and a host port has one owner."""
        rows = []

        def row(case, outcome, detail=""):
            verdict, reason = battery.judge(case, outcome, detail, "host")
            rows.append({"case": case, "outcome": outcome, "detail": detail, "where": "host",
                         "verdict": verdict, "reason": reason})

        def docker_vm(command, timeout=300):
            return self.call("run", DOCKER_NAME, "--no-tty", "--", "sh", "-c", command, ok=False, timeout=timeout)

        published = free_port()
        docker_vm(f"docker run -d --rm --name hostile-publish -p {published}:80 "
                  f"{battery.PROBE_CONTAINER_IMAGE} python3 -m http.server 80 >/dev/null")
        inside = docker_vm(f"for n in $(seq 1 20); do wget -q -T 2 -O /dev/null http://127.0.0.1:{published}/ "
                           f"&& echo answered && exit 0; sleep 1; done; echo silent").stdout.split()
        row("control-docker-publish-inside", inside[-1] if inside else "silent")
        for address in ["127.0.0.1", *battery.host_addresses(gateway=False)]:
            row(f"host-docker-publish-{address}-{published}", tcp_outcome(address, published))
        docker_vm("docker rm -f hostile-publish >/dev/null 2>&1 || true", timeout=120)

        port = str(free_port())
        self.call("ports", journey_module.NAME, "--local", "--publish", "3000", "--host-port", port, timeout=120)
        second = self.call("ports", DOCKER_NAME, "--local", "--publish", "3000", "--host-port", port,
                           ok=False, timeout=120)
        row("port-owner-second-refused", "refused" if second.returncode != 0 else "accepted",
            (second.stderr or second.stdout).strip()[:160])
        self.call("ports", journey_module.NAME, "--local", "--unpublish", "3000", "--host-port", port,
                  timeout=120)
        handover = self.call("ports", DOCKER_NAME, "--local", "--publish", "3000", "--host-port", port,
                             ok=False, timeout=120)
        row("port-owner-handover", "published" if handover.returncode == 0 else "failed",
            (handover.stderr or handover.stdout).strip()[:160])
        if handover.returncode == 0:
            self.call("ports", DOCKER_NAME, "--local", "--unpublish", "3000", "--host-port", port,
                      ok=False, timeout=120)
        return rows

    def remove_environment(self):
        if self.docker_created:
            self.call("--local", "rm", DOCKER_NAME, "--yes", ok=False, timeout=600)
        super().remove_environment()


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise SystemExit("test-local-vm-hostile-guest-macos.py needs an Apple silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    parser.add_argument("--docker", action="store_true", help="repeat the probes from a container in a Docker VM")
    args = parser.parse_args()
    cli_host.arm_owned_session()
    run = HostileGuestBattery(args.cw, args.runtime, args.docker)
    try:
        rows = run.run()
    finally:
        run.cleanup()
    battery.finish(rows)


if __name__ == "__main__":
    main()
