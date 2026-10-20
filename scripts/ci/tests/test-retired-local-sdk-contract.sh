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
    --glob '!**/__pycache__/**' \
    --glob '!**/.venv/**' || true
)"
[[ -z "$legacy_sdk_hits" ]] || {
  printf '%s\n' "$legacy_sdk_hits" >&2
  fail 'active source or documentation still exposes the retired local SDK contract'
}

# Retired CLI spellings: the local-SDK era commands, the `cw env` namespace,
# `cw config-ssh`, and the CLI updater's former `cw update` routes (now
# `cw upgrade`). `cw update ENV` changes an environment and stays valid, as
# does a placement flag on either side of a command (`cw --local ls`).
readonly RETIRED_CLI_GRAMMAR='cw local\b|cw exec\b|cw node\b|cw run --node|node:session|cw (--(local|cloud) )?env\b|cw config-ssh\b|cw update( (status|rollback)\b| --(version|channel|from|sha256|restart-vms|to|expect-generation|store)\b|`|$)'

# Print every retired spelling in the given paths.
retired_grammar_hits() {
  rg -n \
    --glob '!*evidence*' \
    --glob '!archive/**' \
    "$RETIRED_CLI_GRAMMAR" \
    "$@" || true
}

# The guard itself: retired spellings fail, their replacements pass.
# shellcheck disable=SC2016 # the fixtures are literal Markdown with backticks
self_test() {
  local fixture
  fixture="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand the fixture path now
  trap "rm -rf '$fixture'" RETURN
  local retired
  for retired in \
    'cw env list' \
    'cw env --local stop app' \
    'cw --cloud env create' \
    'run `cw config-ssh` again' \
    'cw update' \
    'cw update status' \
    'cw update rollback --to v0.3.390' \
    'cw update --version v0.3.391' \
    'cw update --restart-vms' \
    'see `cw update`' \
    'cw exec ls' \
    'cw run --node build'; do
    printf '```sh\n%s\n```\n' "$retired" >"$fixture/retired.md"
    [[ -n "$(retired_grammar_hits "$fixture")" ]] ||
      fail "self-test: retired spelling passed the guard: $retired"
  done
  rm -f "$fixture/retired.md"
  local current
  for current in \
    'cw ls' \
    'cw --local ls' \
    'cw stop app --cloud' \
    'cw stop app --session coding' \
    'cw setup ssh' \
    'cw update app --profile local:work' \
    'cw update --in app --clear-secrets' \
    'cw upgrade' \
    'cw upgrade rollback --to v0.3.390' \
    'cw upgrade --vms' \
    'cw run app -- cargo test' \
    'environment variables such as cw environment names'; do
    printf '```sh\n%s\n```\n' "$current" >"$fixture/current.md"
    [[ -z "$(retired_grammar_hits "$fixture")" ]] ||
      fail "self-test: current spelling failed the guard: $current"
  done
}

self_test

legacy_doc_hits="$(
  retired_grammar_hits \
    "$ROOT/README.md" \
    "$ROOT/CONTRIBUTING.md" \
    "$ROOT/crates/codewire-dashboard-web" \
    "$ROOT/packages/codewire-design/reference" \
    "$ROOT/apps/cli" \
    "$ROOT/apps/docs/zola/content" \
    "$ROOT/docs"
)"
[[ -z "$legacy_doc_hits" ]] || {
  printf '%s\n' "$legacy_doc_hits" >&2
  fail 'canonical source or documentation still presents retired CLI grammar'
}

echo 'Retired local SDK and CLI contract: OK'
