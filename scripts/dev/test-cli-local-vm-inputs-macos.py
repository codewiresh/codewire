#!/usr/bin/env python3
"""Observed macOS local VM workspace inputs (#1910, Program #2064).

Run on an Apple silicon Mac against a built cw and a runtime directory from
`make macos-local-runtime` (or scripts/dev/macos-local-runtime.py --pack):

  scripts/dev/test-cli-local-vm-inputs-macos.py --cw /abs/cw --runtime /abs/runtime-dir

It creates a local VM from a project file declaring the inputs the Linux
native smoke proves (scripts/ci/verify/smoke-native-local-environment.sh):
two repositories at pinned commits (Forgejo and GitHub), a copy mount, a
direct read-only and a direct read-write share (each holding a symlink to a
directory outside it), and repository, direct-share and user skills. It then
proves, on this Mac:
- each repository is checked out at its pinned commit;
- the copy mount holds its content at creation; later host changes and guest
  writes stay on their own side;
- the read-only share is live: a host change appears, a guest write is
  refused and the host is unchanged;
- the read-write share is live both ways;
- neither share's symlink reaches the directory outside it;
- the skill snapshot (3 skills, generation 1) keeps its content when the host
  sources change; `cw refresh-skills --local` makes generation 2 with the
  new content, read-only in the guest, and leaves the host sources unchanged;
- after stop and start, host changes made while stopped are live in both
  shares;
- `--path-mode copy` (no network, no Docker) copies the source at creation,
  hidden files, an executable, a symlink and a hard link (as separate files)
  included, with no `.git`; neither side's later changes reach the other, and
  removing the environment leaves the source as it was.

The VM, its private root, HOME and throwaway keychain are those of
test-cli-local-vm-macos.py. Needs network egress for the image pull, the
repositories and the guest's git. GITHUB_SERVER_URL names the Forgejo instance
whose public supply-chain scanner repository it clones.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
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

NAME = journey_module.NAME
IMAGE = journey_module.IMAGE
COPY_NAME = "copy-proof"
# The Linux native smoke's pinned repositories and commits. The Forgejo one is
# the public supply-chain scanner repository on the forge GITHUB_SERVER_URL names.
GITEA_COMMIT = "bcbae548ab2f4f0e407068aa8717cec341084d7a"
GITHUB = ("https://github.com/noeljackson/method.git", "93f68ba4abc9f6e222481265b9b759e71d332575")


def gitea_source():
    server = os.environ.get("GITHUB_SERVER_URL", "").rstrip("/")
    if not server:
        raise SystemExit("GITHUB_SERVER_URL: set to the Forgejo base URL")
    return f"{server}/supplychain.git"


class InputsJourney(journey_module.LocalVmJourney):
    def __init__(self, cw, runtime, gitea):
        super().__init__(cw, runtime)
        self.gitea = (gitea, GITEA_COMMIT)
        root = self.root
        self.workspace = root / "w"
        self.copy_source = root / "m"
        self.direct_ro = root / "direct-ro"
        self.direct_rw = root / "direct-rw"
        self.outside = root / "direct-outside"
        self.repository_skill = self.copy_source / ".agents/skills/repo-smoke"
        self.direct_skill = self.direct_ro / ".agents/skills/direct-smoke"
        self.user_skill = self.home / ".codewire/skills/user-smoke"
        self.copy_workspace = root / "copy-source"
        self.copy_created = False

    def fixtures(self):
        for directory in (self.workspace, self.copy_source, self.direct_ro, self.direct_rw, self.outside,
                          self.repository_skill / "scripts", self.direct_skill, self.user_skill):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # cw refuses a group- or world-accessible ~/.codewire; mkdir(parents=True)
        # gives the intermediate directories the default mode.
        for directory in (self.home / ".codewire", self.home / ".codewire/skills"):
            directory.chmod(0o700)
        (self.copy_source / "data.txt").write_text("copy mount before creation\n")
        (self.repository_skill / "SKILL.md").write_text("repository skill generation one\n")
        verify = self.repository_skill / "scripts/verify.sh"
        verify.write_text('#!/bin/sh\nprintf "skill-executable-ok\\n"\n')
        verify.chmod(0o755)
        (self.user_skill / "SKILL.md").write_text("user skill generation one\n")
        (self.direct_ro / "data.txt").write_text("direct read-only before creation\n")
        (self.direct_rw / "data.txt").write_text("direct read-write before creation\n")
        (self.outside / "data.txt").write_text("direct outside must remain isolated\n")
        for share in (self.direct_ro, self.direct_rw):
            (share / "outside.txt").symlink_to(self.outside / "data.txt")
        (self.direct_skill / "SKILL.md").write_text("direct skill generation one\n")
        (self.workspace / "README.md").write_text("workspace inputs journey\n")
        (self.workspace / "codewire.yaml").write_text(f"""version: 1
image: {IMAGE}
repositories:
  - source: {self.gitea[0]}
    revision: {self.gitea[1]}
    destination: /workspace/gitea
  - source: {GITHUB[0]}
    revision: {GITHUB[1]}
    destination: /workspace/github
mounts:
  - source: ../m
    destination: /workspace/fixtures
    mode: copy
  - source: ../direct-ro
    destination: /workspace/direct-ro
    mode: direct
    read_only: true
  - source: ../direct-rw
    destination: /workspace/direct-rw
    mode: direct
    read_only: false
skills:
  - source: repository
    path: fixtures/.agents/skills/repo-smoke
    agents: [codex, claude-code]
  - source: repository
    path: direct-ro/.agents/skills/direct-smoke
    agents: [codex]
  - source: user
    name: user-smoke
    agents: [codex]
""")

    def login_shell(self, command, ok=True, timeout=120):
        return self.call("run", "--in", NAME, "--no-tty", "--", "sh", "-lc", command, ok=ok, timeout=timeout)

    def run(self):
        self.fixtures()
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "journey", str(self.keychain)], check=True)
        subprocess.run(["/usr/bin/security", "set-keychain-settings", str(self.keychain)], check=True)
        self.call("setup", "--local", "--from", self.runtime, timeout=600)

        self.created = True
        created = self.call("--local", "create", "--name", NAME, "--path", str(self.workspace),
                            "--no-docker", "--yes", "--output", "json", timeout=900)
        for warning in ("direct mounts let guest root inspect every file",
                        "Read-write grants let guest root modify or delete that host content"):
            assert warning in created.stderr, f"creation did not warn: {warning!r}\n{created.stderr}"
        info = self.info()
        self.environment_id = info["id"]
        assert info["state"] == "running", info
        assert info.get("workspace_inputs") == 5, info
        assert info.get("skill_count") == 3 and info.get("skill_snapshot_generation") == 1, info
        initial_snapshot = info.get("skill_snapshot", "")
        assert re.fullmatch(r"[0-9a-f]{64}", initial_snapshot), info
        self.check("create from the project file (5 inputs, 3 skills, direct-share warnings)")

        # The guest's own git reads the checkouts; apk's mirror is allowed HTTPS.
        self.guest("for n in 1 2 3; do apk add --quiet --no-cache git && exit 0; sleep 3; done; exit 1", timeout=300)
        heads = self.guest("git -c safe.directory='*' -C /workspace/gitea rev-parse HEAD; "
                           "git -c safe.directory='*' -C /workspace/github rev-parse HEAD").stdout.split()
        assert heads == [self.gitea[1], GITHUB[1]], heads
        self.check("repositories at their pinned commits")

        # Host changes after creation: live in the shares, not in the copy or the skills.
        (self.copy_source / "data.txt").write_text("copy mount host changed after creation\n")
        (self.copy_source / "host-only.txt").write_text("copy mount host-only content\n")
        (self.direct_ro / "data.txt").write_text("direct read-only host changed after creation\n")
        (self.direct_rw / "host-later.txt").write_text("direct read-write host change\n")
        (self.repository_skill / "SKILL.md").write_text("repository skill generation two\n")
        (self.direct_skill / "SKILL.md").write_text("direct skill generation two\n")
        (self.user_skill / "SKILL.md").write_text("user skill generation two\n")

        self.guest(
            "set -eu; grep -qx 'copy mount before creation' /workspace/fixtures/data.txt; "
            "test ! -e /workspace/fixtures/host-only.txt; "
            "printf 'guest-copy-mount-write\\n' > /workspace/fixtures/guest-only.txt")
        assert not (self.copy_source / "guest-only.txt").exists(), "a copy-mount guest write reached the host"
        self.check("copy mount keeps its creation content on each side")

        self.guest(
            "set -eu; grep -qx 'direct read-only host changed after creation' /workspace/direct-ro/data.txt; "
            "if printf forbidden > /workspace/direct-ro/guest-write.txt 2>/dev/null; then exit 82; fi; "
            "test ! -e /workspace/direct-ro/guest-write.txt; "
            "grep -qx 'direct read-write host change' /workspace/direct-rw/host-later.txt; "
            "printf 'direct guest write\\n' > /workspace/direct-rw/guest-write.txt; "
            "if cat /workspace/direct-ro/outside.txt >/dev/null 2>&1; then exit 81; fi; "
            "if cat /workspace/direct-rw/outside.txt >/dev/null 2>&1; then exit 83; fi")
        assert (self.direct_rw / "guest-write.txt").read_text() == "direct guest write\n", \
            "a read-write guest change did not reach the host"
        assert not (self.direct_ro / "guest-write.txt").exists(), "the read-only share changed its host source"
        assert (self.outside / "data.txt").read_text() == "direct outside must remain isolated\n"
        self.check("direct shares: read-only live and refused, read-write live both ways, symlinks contained")

        self.login_shell(
            'set -eu; grep -qx "repository skill generation one" "$CODEX_HOME/skills/repo-smoke/SKILL.md"; '
            'grep -qx "repository skill generation one" "$HOME/.claude/skills/repo-smoke/SKILL.md"; '
            'grep -qx "direct skill generation one" "$CODEX_HOME/skills/direct-smoke/SKILL.md"; '
            'grep -qx "user skill generation one" "$CODEX_HOME/skills/user-smoke/SKILL.md"; '
            'test "$("$CODEX_HOME/skills/repo-smoke/scripts/verify.sh")" = skill-executable-ok')
        self.check("skill snapshot keeps generation one after host changes")

        refreshed = json.loads(self.call("refresh-skills", "--local", NAME, "--output", "json",
                                         timeout=600).stdout)
        assert refreshed.get("skill_count") == 3 and refreshed.get("skill_snapshot_generation") == 2, refreshed
        assert refreshed.get("skill_snapshot") not in ("", None, initial_snapshot), refreshed
        self.login_shell(
            'set -eu; grep -qx "repository skill generation two" "$CODEX_HOME/skills/repo-smoke/SKILL.md"; '
            'grep -qx "repository skill generation two" "$HOME/.claude/skills/repo-smoke/SKILL.md"; '
            'grep -qx "direct skill generation two" "$CODEX_HOME/skills/direct-smoke/SKILL.md"; '
            'grep -qx "user skill generation two" "$CODEX_HOME/skills/user-smoke/SKILL.md"; '
            'if printf forbidden > "$CODEX_HOME/skills/user-smoke/SKILL.md" 2>/dev/null; then exit 84; fi')
        assert ((self.repository_skill / "SKILL.md").read_text(), (self.direct_skill / "SKILL.md").read_text(),
                (self.user_skill / "SKILL.md").read_text()) == (
            "repository skill generation two\n", "direct skill generation two\n", "user skill generation two\n"), \
            "skill refresh changed a host skill source"
        self.check("refresh-skills makes generation two, read-only, host sources unchanged")

        self.call("--local", "stop", NAME, timeout=300)
        (self.direct_ro / "restart.txt").write_text("direct read-only offline host change\n")
        (self.direct_rw / "restart.txt").write_text("direct read-write offline host change\n")
        self.call("--local", "start", NAME, timeout=600)
        self.guest(
            "set -eu; grep -qx 'direct read-only offline host change' /workspace/direct-ro/restart.txt; "
            "grep -qx 'direct read-write offline host change' /workspace/direct-rw/restart.txt; "
            "grep -qx 'direct guest write' /workspace/direct-rw/guest-write.txt; "
            "grep -qx 'guest-copy-mount-write' /workspace/fixtures/guest-only.txt; "
            "printf 'direct restarted guest write\\n' > /workspace/direct-rw/restarted.txt")
        assert (self.direct_rw / "restarted.txt").read_text() == "direct restarted guest write\n"
        self.check("after stop and start both shares are live and guest state persists")
        self.copy_mode()

    def copy_mode(self):
        source = self.copy_workspace
        source.mkdir(mode=0o700)
        (source / "data.txt").write_text("copy source before creation\n")
        (source / ".hidden").write_text("hidden copy content\n")
        tool = source / "tool.sh"
        tool.write_text('#!/bin/sh\nprintf "copy-executable-ok\\n"\n')
        tool.chmod(0o755)
        os.link(source / "data.txt", source / "hardlink.txt")
        (source / "link.txt").symlink_to("data.txt")
        self.copy_created = True
        self.call("--local", "create", "--name", COPY_NAME, "--image", IMAGE, "--path", str(source),
                  "--path-mode", "copy", "--no-network", "--no-docker", "--yes", timeout=900)
        info = json.loads(self.call("--local", "info", COPY_NAME, "--output", "json").stdout)
        assert info["state"] == "running" and info.get("workspace_inputs") == 1, info
        assert info.get("working_directory") == "/workspace", info
        (source / "data.txt").write_text("host changed after copy creation\n")
        (source / "host-only.txt").write_text("host-only after copy\n")
        result = self.call(
            "run", "--in", COPY_NAME, "--no-tty", "--", "sh", "-c",
            "set -eu; cd /workspace; test ! -e .git; test ! -e host-only.txt; "
            "grep -qx 'copy source before creation' data.txt; grep -qx 'hidden copy content' .hidden; "
            "test \"$(readlink link.txt)\" = data.txt; test \"$(stat -c %h data.txt)\" = 1; "
            "test \"$(stat -c %h hardlink.txt)\" = 1; ./tool.sh; printf 'guest\\n' > guest-only.txt")
        assert "copy-executable-ok" in result.stdout, result.stdout
        assert (source / "data.txt").read_text() == "host changed after copy creation\n"
        assert not (source / "guest-only.txt").exists(), "a copy-mode guest write reached the host"
        self.call("--local", "rm", COPY_NAME, "--yes", timeout=300)
        self.copy_created = False
        assert (source / "data.txt").read_text() == "host changed after copy creation\n", \
            "removing the copy-mode environment changed its source"
        self.check("--path-mode copy is detached from its source both ways")

    def remove_environment(self):
        if self.copy_created:
            self.call("--local", "rm", COPY_NAME, "--yes", ok=False, timeout=300)
        super().remove_environment()


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise SystemExit("test-cli-local-vm-inputs-macos.py needs an Apple silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cw", required=True)
    parser.add_argument("--runtime", required=True, help="a runtime directory packed for this cw")
    args = parser.parse_args()
    gitea = gitea_source()
    cli_host.arm_owned_session()
    journey = InputsJourney(args.cw, args.runtime, gitea)
    try:
        journey.run()
    finally:
        journey.cleanup()
    print("local-vm-inputs: all checks PASS")


if __name__ == "__main__":
    main()
