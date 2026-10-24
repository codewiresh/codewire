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
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly AGENTS="$ROOT/images/workspace/agents"

die() {
  echo "workspace-agents: $*" >&2
  exit 1
}

command -v npm >/dev/null || die 'npm is required'
command -v node >/dev/null || die 'node is required'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/workspace-agents.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
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

"$ROOT/scripts/ci/tests/test-support-images-workflow.sh"
echo 'workspace-agents: the lockfile installs and every agent starts at its pinned version'
