#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/claude-e2e.yaml"
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-infisical-ci-secret.sh"
readonly EXPORTER="$ROOT/scripts/ci/setup/export-infisical-secrets.sh"
readonly GO_EXAMPLE_MOD="$ROOT/libs/sdk-examples/run-claude/go/go.mod"
readonly GO_EXAMPLE_SUM="$ROOT/libs/sdk-examples/run-claude/go/go.sum"
readonly WORKSPACE_REF='ghcr.io/codewiresh/workspace@sha256:93623453cf2046fbca5f77a8f24d606e9dde9e5d9514e84d4b110a19f9661145'

fail() {
  printf '[test-claude-e2e-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'Claude E2E workflow is missing'
grep -qF "CW_EXAMPLE_IMAGE: $WORKSPACE_REF" "$WORKFLOW" ||
  fail 'Claude E2E does not use the reviewed Gitea-built workspace digest'
if grep -Eq 'ghcr\.io/codewiresh/workspace:(latest|main)' "$WORKFLOW"; then
  fail 'Claude E2E still uses a moving workspace tag'
fi
grep -qF 'INFISICAL_WORKSPACE_SLUG: codewire' "$WORKFLOW" ||
  fail 'Claude E2E does not select the Codewire Infisical project'
grep -qF 'INFISICAL_SECRET_PATH: /' "$WORKFLOW" ||
  fail 'Claude E2E does not select the Codewire project root'
# shellcheck disable=SC2016
grep -qF "INFISICAL_ENVIRONMENT: \${{ startsWith(github.ref, 'refs/tags/v') && 'prod' || 'dev' }}" \
  "$WORKFLOW" || fail 'Claude E2E does not map tags to prod and branches to dev'
grep -qF 'scripts/ci/setup/export-infisical-secrets.sh ANTHROPIC_API_KEY' \
  "$WORKFLOW" || fail 'Claude E2E bypasses the established Codewire exporter'
if grep -Fq 'secrets.ANTHROPIC_API_KEY' "$WORKFLOW"; then
  fail 'Claude E2E still consumes a duplicated Gitea secret'
fi
if grep -Fq 'fetch-infisical-ci-secret.sh ANTHROPIC_API_KEY' "$WORKFLOW"; then
  fail 'Claude E2E incorrectly routes its product key through shared CI secrets'
fi
grep -qF 'run: GOWORK=off make sdk-run-claude' "$WORKFLOW" ||
  fail 'Claude E2E parity run inherits the parent go.work'
grep -qF 'replace github.com/codewiresh/codewire/libs/gen-go => ../../../gen-go' \
  "$GO_EXAMPLE_MOD" || fail 'standalone Go example cannot resolve local generated Connect clients'
[[ -s "$GO_EXAMPLE_SUM" ]] || fail 'standalone Go example is missing its checksum closure'
grep -qF 'protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip' \
  "$WORKFLOW" || fail 'Claude E2E does not install the reviewed protoc release'
grep -qF '6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7  /tmp/protoc.zip' \
  "$WORKFLOW" || fail 'Claude E2E does not verify the protoc archive checksum'
grep -qF 'uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff' \
  "$WORKFLOW" || fail 'Claude E2E does not use the reviewed Go setup action'
grep -qF "go-version: '1.26.4'" "$WORKFLOW" ||
  fail 'Claude E2E does not install the repository Go toolchain'
grep -qF 'libs/sdk-ts/package-lock.json' "$WORKFLOW" ||
  fail 'Claude E2E cache does not include the TypeScript SDK lockfile'
grep -qF 'libs/sdk-examples/run-claude/typescript/package-lock.json' "$WORKFLOW" ||
  fail 'Claude E2E cache does not include the TypeScript example lockfile'
grep -qF 'npm --prefix libs/sdk-ts ci --ignore-scripts' "$WORKFLOW" ||
  fail 'Claude E2E does not install the locked TypeScript SDK dependencies'
grep -qF 'npm --prefix libs/sdk-ts run build' "$WORKFLOW" ||
  fail 'Claude E2E does not build the local TypeScript SDK package'
grep -qF 'npm --prefix libs/sdk-examples/run-claude/typescript ci --ignore-scripts' \
  "$WORKFLOW" || fail 'Claude E2E does not install the locked TypeScript example dependencies'

checkout_line="$(grep -n 'uses: actions/checkout@' "$WORKFLOW" | cut -d: -f1)"
export_line="$(grep -n 'export-infisical-secrets.sh ANTHROPIC_API_KEY' "$WORKFLOW" | cut -d: -f1)"
protoc_line="$(grep -n 'name: Install protoc (pinned)' "$WORKFLOW" | cut -d: -f1)"
go_line="$(grep -n 'name: Set up Go' "$WORKFLOW" | cut -d: -f1)"
build_line="$(grep -n 'name: Build cw binary' "$WORKFLOW" | cut -d: -f1)"
ts_build_line="$(grep -n 'name: Build TypeScript SDK' "$WORKFLOW" | cut -d: -f1)"
ts_example_line="$(grep -n 'name: Install TypeScript example deps' "$WORKFLOW" | cut -d: -f1)"
parity_line="$(grep -n 'name: Run claude through all three SDKs' "$WORKFLOW" | cut -d: -f1)"
[[ "$checkout_line" -lt "$export_line" ]] ||
  fail 'Claude E2E attempts secret retrieval before checking out the wrapper'
[[ "$protoc_line" -lt "$build_line" ]] ||
  fail 'Claude E2E builds cw before installing protoc'
[[ "$go_line" -lt "$parity_line" ]] ||
  fail 'Claude E2E runs the Go SDK before installing Go'
[[ "$ts_build_line" -lt "$ts_example_line" ]] ||
  fail 'Claude E2E installs the TypeScript example before building its local SDK'
[[ "$ts_example_line" -lt "$parity_line" ]] ||
  fail 'Claude E2E runs the TypeScript example before installing its dependencies'
grep -qF "instances_json='[]'" "$WORKFLOW" ||
  fail 'Claude E2E cleanup does not tolerate an absent local daemon'

# shellcheck disable=SC2016
grep -qF 'INFISICAL_WORKSPACE_SLUG="${INFISICAL_WORKSPACE_SLUG:-codewire}"' \
  "$EXPORTER" || fail 'established exporter no longer defaults to Codewire'
if grep -Fq 'ANTHROPIC_API_KEY' "$FETCHER"; then
  fail 'shared container credential wrapper accepts the Codewire product key'
fi

echo 'Claude E2E workflow contract: OK'
