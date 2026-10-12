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

Staging, the probes and their judgement are test-local-vm-hostile-guest.py's,
which also runs the same battery against an existing Linux local VM or other
environment. Needs network egress for the image pulls and the controls.
"""
import argparse
import importlib.util
import os
from pathlib import Path
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
        self.call("env", "--local", "create", "--name", journey_module.NAME, "--image", journey_module.IMAGE,
                  "--no-docker", "--yes", timeout=900)
        self.environment_id = self.info()["id"]
        arguments = [argument for address in battery.host_addresses() for argument in ("--host-address", address)]
        guest = battery.GuestRunner(self.call, journey_module.NAME)
        guest.stage()
        rows = guest.workload(arguments)
        if self.docker:
            self.docker_created = True
            self.call("env", "--local", "create", "--name", DOCKER_NAME, "--image", DOCKER_IMAGE,
                      "--docker-disk", "1Gi", "--yes", timeout=1200)
            docker = battery.GuestRunner(self.call, DOCKER_NAME)
            docker.stage()
            rows += docker.docker(arguments)
        return rows

    def remove_environment(self):
        if self.docker_created:
            self.call("env", "--local", "rm", DOCKER_NAME, "--yes", ok=False, timeout=600)
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
