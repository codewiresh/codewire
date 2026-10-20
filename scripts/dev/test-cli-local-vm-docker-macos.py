#!/usr/bin/env python3
"""Observed private guest Docker journey on a macOS local VM (#1913, Program #2064).

Run on an Apple silicon Mac against a built cw and a runtime directory packed
for it, plus a second runtime directory packed from another source revision
(for the runtime-generation step):

  scripts/dev/test-cli-local-vm-docker-macos.py --cw /abs/cw \\
      --runtime /abs/runtime-a --next-runtime /abs/runtime-b

It proves #1913's acceptance list on Apple silicon, with stock arm64 images:
- the Docker data disk is a dedicated `docker.raw` of the requested size,
  apart from the workspace's state disk;
- build, run, Compose, a public pull through egress, a refused private pull,
  guest-visible `docker login`, and `docker -p` publishing only inside the VM;
- an amd64-only image fails clearly (no emulation);
- filling the Docker disk's bytes or inodes fails with ENOSPC inside Docker
  only, container logs stay bounded, and the disk keeps its size;
- images, volumes and the guest's Docker login persist across restart, a
  runtime install while stopped, VMM death, runner death and a dockerd crash
  (each repaired with `cw --local daemon repair`);
- removing the environment removes its Docker disk and ends the VM.

It uses the same private root, HOME, throwaway keychain and owned-family
cleanup as test-cli-local-vm-macos.py.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


local_vm = load("local_vm", "test-cli-local-vm-macos.py")

IMAGE = "docker.io/library/docker:28-dind"
DOCKER_DISK_BYTES = 1024 * 1024 * 1024
PRIVATE_IMAGE = "ghcr.io/codewiresh/private-native-docker-smoke:1913"
LOG_LIMIT_BYTES = 32 * 1024 * 1024
GUEST_PORT = 18080

SETUP = r'''
set -eu
test -S /var/run/docker.sock
test "$(docker info --format '{{.DockerRootDir}}|{{.Driver}}|{{.Architecture}}')" = '/var/lib/docker|overlay2|aarch64'
docker compose version >/dev/null
docker pull -q --platform linux/arm64 alpine:3.22 >/dev/null
context=$(mktemp -d)
printf 'FROM alpine:3.22\nRUN echo docker-run-ok > /built\nCMD ["cat", "/built"]\n' > "$context/Dockerfile"
docker build -q -t codewire-macos-smoke:1913 "$context" >/dev/null
test "$(docker run --rm codewire-macos-smoke:1913)" = docker-run-ok
printf 'services:\n  fixture:\n    image: codewire-macos-smoke:1913\n' > "$context/compose.yaml"
test "$(docker compose -p codewire-macos-smoke -f "$context/compose.yaml" run --rm fixture)" = docker-run-ok
docker volume create codewire-macos-smoke-volume >/dev/null
docker run --rm -v codewire-macos-smoke-volume:/data alpine:3.22 sh -c 'echo generation-one > /data/marker'
mkdir -p "$HOME/.docker" && chmod 0700 "$HOME/.docker"
printf '{"auths":{"registry.invalid":{"auth":"%s"}}}\n' "$(printf synthetic:not-a-secret | base64)" > "$HOME/.docker/config.json"
echo docker-build-run-compose-ok
'''

PERSISTENCE = r'''
set -eu
test "$(docker info --format '{{.DockerRootDir}}|{{.Driver}}')" = '/var/lib/docker|overlay2'
docker image inspect codewire-macos-smoke:1913 >/dev/null
test "$(docker run --rm codewire-macos-smoke:1913)" = docker-run-ok
test "$(docker run --rm -v codewire-macos-smoke-volume:/data alpine:3.22 cat /data/marker)" = generation-one
grep -q registry.invalid "$HOME/.docker/config.json"
echo docker-persistence-ok
'''

EXHAUSTION = r'''
set -u
docker volume create codewire-macos-bytes >/dev/null
bytes=$(docker run --rm --log-driver=none -v codewire-macos-bytes:/data alpine:3.22 \
  sh -c 'dd if=/dev/zero of=/data/fill bs=1M 2>&1; echo "dd exit $?"')
docker volume rm codewire-macos-bytes >/dev/null
echo "$bytes" | grep -q 'No space left on device' && echo "$bytes" | grep -qv 'dd exit 0' && echo docker-byte-enospc-ok
docker volume create codewire-macos-inodes >/dev/null
inodes=$(docker run --rm --log-driver=none -v codewire-macos-inodes:/data alpine:3.22 \
  sh -c 'mkdir /data/d && cd /data/d && seq 1 2000000 | xargs touch 2>&1 | tail -1')
docker volume rm codewire-macos-inodes >/dev/null
echo "$inodes" | grep -q 'No space left on device' && echo docker-inode-enospc-ok
docker run --name codewire-macos-log alpine:3.22 \
  sh -c 'yes 0123456789012345678901234567890123456789012345678901234567890123 | head -c 41943040' >/dev/null
log_bytes=$(docker logs codewire-macos-log 2>&1 | wc -c)
docker rm codewire-macos-log >/dev/null
echo "log bytes $log_bytes"
[ "$log_bytes" -gt 0 ] && [ "$log_bytes" -le LIMIT ] && echo docker-log-bound-ok
docker info >/dev/null && echo docker-after-exhaustion-ok
echo workspace-still-writable > /workspace/project/after-exhaustion.txt
'''.replace("LIMIT", str(LOG_LIMIT_BYTES))


class DockerJourney(local_vm.LocalVmJourney):
    def __init__(self, cw, runtime, next_runtime):
        super().__init__(cw, runtime)
        self.next_runtime = str(Path(next_runtime).resolve())

    def sh(self, script, timeout=600, ok=True):
        return self.call("run", local_vm.NAME, "--no-tty", "--", "sh", "-c", script, ok=ok, timeout=timeout)

    def docker_disk(self):
        disks = list((self.home / ".codewire/native-v1/engine/vms" / self.environment_id).rglob("docker.raw"))
        assert len(disks) == 1, disks
        return disks[0]

    def require(self, output, *markers):
        for marker in markers:
            assert marker in output.splitlines(), f"missing {marker}:\n{output}"

    def wait_state(self, wanted, timeout=60):
        return self.until(self.info, lambda value: value["state"] == wanted, timeout,
                          f"the environment turning {wanted}")

    def repair(self, what, error_code=None):
        """After a crash: the environment is in error with a code saying what
        failed (exactly `error_code` when given); repair restores it and
        everything Docker held persists."""
        info = self.wait_state("error", 60)
        print(f"local-vm-docker: {what} -> error {info.get('error_code')}", flush=True)
        assert info.get("error_code"), f"{what} left error without an error_code: {info}"
        assert error_code is None or info["error_code"] == error_code, info
        self.call("--local", "daemon", "repair", local_vm.NAME, "--output", "json", timeout=600)
        self.wait_state("running", 120)
        self.require(self.sh(PERSISTENCE).stdout, "docker-persistence-ok")
        self.check(f"{what}: repaired and Docker state persists")

    def run(self):
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "journey", str(self.keychain)], check=True)
        subprocess.run(["/usr/bin/security", "set-keychain-settings", str(self.keychain)], check=True)
        self.call("setup", "--local", "--from", self.runtime, timeout=600)
        self.created = True
        self.call("--local", "create", "--name", local_vm.NAME, "--image", IMAGE,
                  "--docker-disk", "1Gi", "--yes", timeout=900)
        info = self.info()
        self.environment_id = info["id"]
        assert info["state"] == "running", info

        disk = self.docker_disk()
        assert disk.is_file() and not disk.is_symlink(), disk
        assert disk.stat().st_size == DOCKER_DISK_BYTES, disk.stat().st_size
        others = [path for path in disk.parent.iterdir() if path != disk]
        assert others and all(path.stat().st_ino != disk.stat().st_ino for path in others), others
        print(f"local-vm-docker: disks {sorted(path.name for path in disk.parent.iterdir())}")
        self.check("dedicated 1 GiB docker.raw, apart from the other disks")

        self.require(self.sh(SETUP).stdout, "docker-build-run-compose-ok")
        self.check("build, run, Compose and a public pull through egress")

        private = self.sh(f"docker pull {PRIVATE_IMAGE} 2>&1; echo \"pull exit $?\"", ok=False).stdout
        assert "pull exit 0" not in private, private
        self.check("a private pull without a login is refused")
        assert not (self.project / ".docker").exists(), "guest Docker login reached the host project"
        self.check("guest docker login stays in the guest")

        self.sh(f"docker run -d --name codewire-macos-port -p {GUEST_PORT}:8080 alpine:3.22 "
                "sh -c 'while :; do echo docker-port-local | nc -l -p 8080; done' >/dev/null")
        inside = self.until(lambda: self.sh(f"nc 127.0.0.1 {GUEST_PORT} </dev/null", ok=False).stdout,
                            lambda out: "docker-port-local" in out, 30, "the container port answering in the VM")
        assert "docker-port-local" in inside
        host = subprocess.run(["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", str(GUEST_PORT)])
        assert host.returncode != 0, "docker -p published a port on the host"
        self.sh("docker rm -f codewire-macos-port >/dev/null")
        self.check("docker -p publishes only inside the VM")

        amd64 = self.sh("docker run --rm --platform linux/amd64 busybox:1.37 true 2>&1; echo \"run exit $?\"",
                        ok=False).stdout
        assert "run exit 0" not in amd64 and "exec format error" in amd64, amd64
        self.check("an amd64-only image fails clearly")

        exhausted = self.sh(EXHAUSTION, timeout=900).stdout
        print(f"local-vm-docker: {next(line for line in exhausted.splitlines() if line.startswith('log bytes'))}")
        self.require(exhausted, "docker-byte-enospc-ok", "docker-inode-enospc-ok", "docker-log-bound-ok",
                     "docker-after-exhaustion-ok")
        assert (self.project / "after-exhaustion.txt").read_text().strip() == "workspace-still-writable"
        assert self.docker_disk().stat().st_size == DOCKER_DISK_BYTES
        self.check("byte and inode exhaustion stay inside docker.raw, logs stay bounded")

        self.call("--local", "restart", local_vm.NAME, timeout=600)
        self.wait_state("running", 120)
        self.require(self.sh(PERSISTENCE).stdout, "docker-persistence-ok")
        self.check("restart keeps images, volumes and the guest login")

        before = json.loads(self.call("--local", "runtime", "info", local_vm.NAME, "--output", "json",
                                      timeout=300).stdout)
        self.call("--local", "stop", local_vm.NAME, timeout=300)
        self.call("setup", "--local", "--from", self.next_runtime, "--replace", timeout=600)
        self.call("--local", "start", local_vm.NAME, timeout=600)
        after = json.loads(self.call("--local", "runtime", "info", local_vm.NAME, "--output", "json",
                                     timeout=300).stdout)
        def runtime(view):
            return (view.get("selection") or {}).get("catalog", {}).get("active_sha256", "")[:12]
        print(f"local-vm-docker: VM generation {before.get('generation')} -> {after.get('generation')}, "
              f"active runtime catalog {runtime(before)} -> {runtime(after)}")
        self.require(self.sh(PERSISTENCE).stdout, "docker-persistence-ok")
        self.check("installing another runtime while stopped keeps Docker state")

        helper = self.helper_pid()
        os.kill(helper, signal.SIGKILL)
        self.repair("VMM death")

        runner = self.role_pid("__native-runner")
        assert runner, "no runner process for the environment"
        os.kill(runner, signal.SIGKILL)
        self.repair("runner death", "runner_exit")

        self.sh("docker run --rm --privileged --pid=host alpine:3.22 sh -c 'kill -9 $(pidof dockerd)'",
                ok=False, timeout=120)
        self.repair("dockerd crash")

        disk = self.docker_disk()
        self.remove_environment()
        self.created = False
        assert not disk.exists(), "env rm left the Docker disk"
        self.check("env rm removes docker.raw")

    def helper_pid(self):
        listed = subprocess.run(["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
                                capture_output=True, text=True, check=True).stdout
        for line in listed.splitlines():
            pid, _, command = line.strip().partition(" ")
            if " vm --config " in command and self.environment_id in command:
                return int(pid)
        raise AssertionError("no VZ helper process for the environment")


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise SystemExit("test-cli-local-vm-docker-macos.py needs an Apple silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    parser.add_argument("--next-runtime", required=True,
                        help="a second runtime directory, packed from another source revision")
    args = parser.parse_args()
    local_vm.cli_host.arm_owned_session()
    journey = DockerJourney(args.cw, args.runtime, args.next_runtime)
    try:
        journey.run()
    finally:
        journey.cleanup()
    print("local-vm-docker: all checks PASS")


if __name__ == "__main__":
    main()
