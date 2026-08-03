#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly GO_LOCAL="$ROOT/libs/sdk-go/local.go"
readonly TS_LOCAL="$ROOT/libs/sdk-ts/src/local.ts"
readonly PY_LOCAL="$ROOT/libs/sdk-python/codewire/local.py"

fail() {
  printf '[test-sdk-local-cli-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

count_output_flags() {
  local count=0 file
  for file in "$@"; do
    while IFS= read -r _; do
      count=$((count + 1))
    done < <(grep -oF -- '"--output"' "$file" || true)
  done
  printf '%s\n' "$count"
}

for file in "$GO_LOCAL" "$TS_LOCAL" "$PY_LOCAL"; do
  [[ -f "$file" ]] || fail "missing SDK local adapter: $file"
  if grep -Fq -- '--json' "$file"; then
    fail "SDK local adapter still uses removed --json spelling: $file"
  fi
  if grep -Eq '(^|[^[:alnum:]_])cw local|["'"'"']local["'"'"'][[:space:]]*,' "$file"; then
    fail "SDK local adapter still invokes removed cw local grammar: $file"
  fi
done

[[ ! -e "$ROOT/libs/sdk-go/local_files.go" ]] ||
  fail 'Go SDK still exposes the removed cw local files subprocess adapter'

for retired_path in \
  apps/cli/contrib \
  apps/cli/demo \
  apps/cli/docker-compose.yml \
  apps/cli/docs/mcp.md \
  crates/codewire-cli/src/access_cache.rs \
  crates/codewire-cli/src/local_client.rs \
  crates/codewire-cli/src/local_node.rs \
  crates/codewire-cli/src/local_session.rs \
  crates/codewire-cli/src/mcp.rs \
  crates/codewire-cli/src/node_tailnet.rs \
  crates/codewire-cli/src/peer_server.rs \
  crates/codewire-cli/src/platform_run.rs \
  crates/codewire-cli/src/protocol.rs \
  crates/codewire-cli/src/remote_session.rs \
  docs/homepage/index.html; do
  [[ ! -e "$ROOT/$retired_path" ]] ||
    fail "retired host-session surface still exists: $retired_path"
done

legacy_doc_hits="$(
  rg -n \
    --glob '!*evidence*' \
    --glob '!archive/**' \
    'cw local|cw exec|cw node|cw run --local|cw run --node|node:session' \
    "$ROOT/README.md" \
    "$ROOT/CONTRIBUTING.md" \
    "$ROOT/crates/codewire-dashboard-web" \
    "$ROOT/apps/docs/zola/content" \
    "$ROOT/docs/dev" \
    "$ROOT/docs/runbooks" || true
)"
[[ -z "$legacy_doc_hits" ]] || {
  printf '%s\n' "$legacy_doc_hits" >&2
  fail 'canonical source or documentation still presents retired CLI grammar'
}

[[ "$(count_output_flags "$GO_LOCAL")" == 6 ]] ||
  fail 'Go local adapter does not request JSON for all six lifecycle operations'
[[ "$(count_output_flags "$TS_LOCAL")" == 6 ]] ||
  fail 'TypeScript local adapter does not request JSON for all six lifecycle operations'
[[ "$(count_output_flags "$PY_LOCAL")" == 6 ]] ||
  fail 'Python local adapter does not request JSON for all six lifecycle operations'

grep -qF 'args := []string{"run", "--no-tty", name}' \
  "$GO_LOCAL" || fail 'Go exec adapter does not use the environment session run contract'
grep -qF 'const args = ["run", "--no-tty", name]' \
  "$TS_LOCAL" || fail 'TypeScript exec adapter does not use the environment session run contract'
grep -qF 'args = ["run", "--no-tty", name]' \
  "$PY_LOCAL" || fail 'Python exec adapter does not use the environment session run contract'

grep -qF '[]string{"env", "--local", "create"' \
  "$GO_LOCAL" || fail 'Go lifecycle adapter does not use cw env --local'
grep -qF '"env",' "$TS_LOCAL" ||
  fail 'TypeScript lifecycle adapter does not use cw env --local'
grep -qF '"env",' "$PY_LOCAL" ||
  fail 'Python lifecycle adapter does not use cw env --local'

grep -qF 'opts.Wait && !strings.EqualFold(inst.Status, "running")' \
  "$GO_LOCAL" || fail 'Go create adapter discards an already-running response'
grep -qF 'opts.wait && instance.status.toLowerCase() !== "running"' \
  "$TS_LOCAL" || fail 'TypeScript create adapter discards an already-running response'
grep -qF 'wait and instance.status.lower() != "running"' \
  "$PY_LOCAL" || fail 'Python create adapter discards an already-running response'

echo 'SDK local CLI output contract: OK'
