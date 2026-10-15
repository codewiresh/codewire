#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-retired-local-sdk-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

for retired_path in \
  libs/sdk-go/local.go \
  libs/sdk-go/local_files.go \
  libs/sdk-python/codewire/local.py \
  libs/sdk-ts/src/local.ts \
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
    fail "retired local or host-session surface still exists: $retired_path"
done

example_hits="$(
  if [[ -d "$ROOT/libs/sdk-examples/run-claude" ]]; then
    find "$ROOT/libs/sdk-examples/run-claude" -type f -print
  fi
)"
[[ -z "$example_hits" ]] || {
  printf '%s\n' "$example_hits" >&2
  fail 'retired local SDK parity example remains tracked'
}

legacy_sdk_hits="$(
  rg -n -i \
    'client\.local|cw\.Local|LocalService|LocalCreateOptions|LocalLimaInfo|LocalSpec|LocalError|LocalInstance|LocalInstanceData|LocalPort|LocalMount|LocalExecRequest|LocalExecResult|Docker-backed local|Docker and Lima backends|local Docker or Lima|sdk-run-claude|run-claude' \
    "$ROOT/README.md" \
    "$ROOT/UPGRADE.md" \
    "$ROOT/Makefile" \
    "$ROOT/libs/sdk-go" \
    "$ROOT/libs/sdk-python" \
    "$ROOT/libs/sdk-ts" \
    "$ROOT/apps/docs/zola/content" \
    "$ROOT/docs/dev" \
    "$ROOT/docs/design/story.html" \
    --glob '!**/__pycache__/**' \
    --glob '!**/.venv/**' || true
)"
[[ -z "$legacy_sdk_hits" ]] || {
  printf '%s\n' "$legacy_sdk_hits" >&2
  fail 'active source or documentation still exposes the retired local SDK contract'
}

legacy_doc_hits="$(
  rg -n \
    --glob '!*evidence*' \
    --glob '!archive/**' \
    'cw local|cw exec|cw node|cw run --local|cw run --node|node:session' \
    "$ROOT/README.md" \
    "$ROOT/CONTRIBUTING.md" \
    "$ROOT/crates/codewire-dashboard-web" \
    "$ROOT/apps/docs/zola/content" \
    "$ROOT/docs/dev" || true
)"
[[ -z "$legacy_doc_hits" ]] || {
  printf '%s\n' "$legacy_doc_hits" >&2
  fail 'canonical source or documentation still presents retired CLI grammar'
}

echo 'Retired local SDK and CLI contract: OK'
