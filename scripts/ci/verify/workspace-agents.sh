#!/usr/bin/env bash
# The workspace agents check: install the workspace image's agent lockfile and
# start each agent, as images/workspace/Dockerfile does, without building the
# image (owner, 2026-10-24: a lockfile-only change "totally doesn't have to
# wait the whole time").
#
# It installs images/workspace/agents with npm ci and no lifecycle scripts,
# then runs only the postinstall scripts the manifest's allowScripts admits
# (the image's --strict-allow-scripts admits exactly those), and starts each
# agent the pin tool names (AGENT_PACKAGES): every one must print the version
# the manifest pins. It also runs the support-images contract, which reads
# the same two files.
#
# It then runs the pinned Claude Code against a fake provider with the login
# file Codewire writes (claude-login-compat.py). The agent runs with no
# network but loopback: in a user and network namespace of its own where one
# can be made, and otherwise, in a CI job that may not make one, in a
# container with no network that the job's Docker daemon starts from the
# job's own image. Where neither can be had the check fails: it never runs the
# agent with a network instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly AGENTS="$ROOT/images/workspace/agents"

die() {
  echo "workspace-agents: $*" >&2
  exit 1
}

command -v npm >/dev/null || die 'npm is required'
command -v node >/dev/null || die 'node is required'
command -v openssl >/dev/null || die 'openssl is required'

# How the login check gets its loopback-only network, decided before the
# install so a job that cannot have one fails at once.
job_image=''
if unshare -rn true 2>/dev/null; then
  LOOPBACK_ONLY=namespace
elif job_image="$(docker inspect --format '{{.Image}}' "${HOSTNAME:-}" 2>/dev/null)" &&
  [[ "$job_image" == sha256:* ]]; then
  # The job runs in a container of the daemon it can reach, named by its
  # host name; that container's image is already on the daemon.
  LOOPBACK_ONLY=container
else
  die 'cannot run the agent with no network but loopback: no user and network namespace (unshare -rn), and no Docker daemon that runs this job from an image of its own'
fi
readonly LOOPBACK_ONLY

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/workspace-agents.XXXXXX")"
login_container=''
cleanup() {
  [[ -z "$login_container" ]] || docker rm -f "$login_container" >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT
cp "$AGENTS/package.json" "$AGENTS/package-lock.json" "$work/"

(
  cd "$work"
  env -u NPM_CONFIG_PREFIX npm_config_cache="$work/.npm-cache" \
    npm ci --ignore-scripts --no-audit --no-fund
)

# The admitted lifecycle scripts, each pinned to the version it names, and the
# agents with their pinned versions, one per line: "script NAME DIR" or
# "agent BIN VERSION".
plan="$(python3 -I - "$work" "$ROOT/scripts/ci/images/workspace-image-pin.py" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

work, pin_tool = Path(sys.argv[1]), sys.argv[2]
spec = importlib.util.spec_from_file_location("workspace_image_pin_tool", pin_tool)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
manifest = json.loads((work / "package.json").read_text())
dependencies = manifest["dependencies"]
for key, allowed in sorted(manifest.get("allowScripts", {}).items()):
    if allowed is not True:
        continue
    name, _, version = key.rpartition("@")
    if not name or not version:
        sys.exit(f"allowScripts entry {key!r} does not name an exact version")
    installed = json.loads((work / "node_modules" / name / "package.json").read_text())["version"]
    if installed != version:
        sys.exit(f"allowScripts admits {key} but {name} {installed} is installed")
    print("script", name, work / "node_modules" / name)
for agent, package in sorted(tool.AGENT_PACKAGES.items()):
    if package not in dependencies:
        sys.exit(f"the manifest does not pin {package} for {agent}")
    print("agent", agent, dependencies[package])
PY
)" || die 'the agent manifest and its lockfile disagree'

while read -r kind first second; do
  case "$kind" in
    script)
      # npm runs a package's postinstall from that package's directory.
      (cd "$second" && env -u NPM_CONFIG_PREFIX npm run --if-present postinstall >/dev/null) ||
        die "the admitted postinstall of $first failed"
      ;;
    agent)
      output="$(timeout 60 "$work/node_modules/.bin/$first" --version </dev/null 2>&1)" ||
        die "$first did not start: $(head -n 1 <<<"$output")"
      [[ "$output" == *"$second"* ]] || die "$first started as '$(head -n 1 <<<"$output")', not $second"
      echo "workspace-agents: $first $second starts"
      ;;
  esac
done <<<"$plan"

# The agents' login file formats are recorded against exact versions (#3999):
# a moved pin means the recorded formats must be checked against the new agent.
python3 -I - "$AGENTS/package.json" "$ROOT/crates/codewire-daemon/fixtures/agent-formats/manifest.json" <<'PY' ||
import json
import sys

pins = json.load(open(sys.argv[1]))["dependencies"]
recorded = json.load(open(sys.argv[2]))
moved = [f"{package} {pins.get(package)} (recorded: {version})" for package, version in sorted(recorded.items()) if pins.get(package) != version]
if moved:
    sys.exit("login file formats are recorded for other versions: " + "; ".join(moved))
PY
  die 'check each moved agent still reads its recorded login file, then record its version in crates/codewire-daemon/fixtures/agent-formats/manifest.json'

"$ROOT/scripts/ci/tests/test-support-images-workflow.sh"

# The pinned Claude Code, given the recorded login file, refreshes and sends
# its placeholder as Codewire expects (#3999).
readonly COMPAT="$ROOT/scripts/ci/verify/claude-login-compat.py"
readonly LOGIN="$ROOT/crates/codewire-daemon/fixtures/agent-formats/claude-code.credentials.json"
readonly MOVED='the pinned Claude Code no longer does with its login file what Codewire expects: see crates/codewire-daemon/fixtures/agent-formats/README.md'
mkdir "$work/claude-login"
case "$LOOPBACK_ONLY" in
  namespace)
    unshare -rn python3 -I "$COMPAT" --agent "$work/node_modules/.bin/claude" \
      --login "$LOGIN" --work "$work/claude-login" || die "$MOVED"
    ;;
  container)
    # Files are copied in: a bind mount would name a path on the daemon's
    # host, not in this job. The script refuses to start the agent unless
    # loopback is the container's only interface.
    cp "$COMPAT" "$work/claude-login/claude-login-compat.py"
    cp "$LOGIN" "$work/claude-login/login.json"
    mkdir "$work/claude-login/work" "$work/claude-login/agents"
    login_container="$(docker create --network none --pids-limit 2048 --entrypoint python3 "$job_image" \
      -I /claude-login/claude-login-compat.py --agent /claude-login/agents/node_modules/.bin/claude \
      --login /claude-login/login.json --work /claude-login/work)" ||
      die 'the container for the Claude Code login check could not be made'
    if ! docker cp -q "$work/claude-login" "$login_container":/claude-login ||
      ! docker cp -q "$work/node_modules" "$login_container":/claude-login/agents/; then
      die 'the agent could not be copied into the container for the Claude Code login check'
    fi
    status=0
    timeout 180 docker start -a "$login_container" || status=$?
    [[ "$status" -ne 124 ]] || die 'the Claude Code login check did not finish within 180 s'
    [[ "$status" -eq 0 ]] || die "$MOVED"
    ;;
esac
echo "workspace-agents: the lockfile installs, every agent starts at its pinned version, and Claude Code reads its login file (loopback only by $LOOPBACK_ONLY)"
