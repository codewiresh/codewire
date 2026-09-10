#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

fail=0

active_paths=(
  ".gitea/**"
  "apps/**/Dockerfile"
  "apps/**/Dockerfile.*"
  "apps/dashboard/playwright.config.ts"
  "deployments/**/*.yaml"
  "deployments/**/*.yml"
  "Dockerfile"
  "Dockerfile.*"
  "Makefile"
  "package.json"
  "packages/**/*.json"
  "scripts/**"
  ":(exclude)scripts/checks/security/audit-js-supply-chain.sh"
)

web_runtime_paths=(
  "apps/docs/zola/**"
  "crates/codewire-dashboard-web/src/**"
  "crates/codewire-dashboard-web/templates/**"
  "docs/homepage/**"
  "packages/codewire-design/**"
)

runtime_template_paths=(
  "apps/docs/zola/templates/**"
  "crates/codewire-dashboard-web/templates/**"
  "docs/homepage/*.html"
)

is_ignored_line() {
  local line="$1"
  case "$line" in
    *":#"*|*" skipped "*|*"skip "*)
      return 0
      ;;
  esac
  return 1
}

report_matches() {
  local label="$1"
  local pattern="$2"
  shift 2
  local -a search_paths
  if [[ "$#" -eq 0 ]]; then
    search_paths=("${active_paths[@]}")
  else
    search_paths=("$@")
  fi
  local out
  if out="$(git grep -nE "$pattern" -- "${search_paths[@]}" 2>/dev/null)"; then
    echo "supply-chain audit: $label" >&2
    echo "$out" >&2
    fail=1
  fi
}

dynamic_runner_matches="$(git grep -nE \
  '(^|[^[:alnum:]_-])(npx|bunx)([^[:alnum:]_-]|$)' \
  -- "${active_paths[@]}" 2>/dev/null || true)"
# This exact line is an absence inventory used to prove the final distroless
# image contains no package runner. Keep the exception line-scoped so an
# executable npx/bunx reference anywhere in the verifier still fails closed.
readonly runner_inventory_exception='^scripts/ci/verify/dashboard-image\.sh:[0-9]+:  usr/bin/dpkg usr/bin/node usr/bin/npm usr/bin/npx usr/bin/rustc usr/bin/sh$'
if ! grep -Eq "$runner_inventory_exception" <<< \
    'scripts/ci/verify/dashboard-image.sh:85:  usr/bin/dpkg usr/bin/node usr/bin/npm usr/bin/npx usr/bin/rustc usr/bin/sh' \
  || grep -Eq "$runner_inventory_exception" <<< \
    'scripts/ci/verify/dashboard-image.sh:85:  npx --yes unreviewed-package'; then
  echo "supply-chain audit: dynamic-runner inventory exception self-test failed" >&2
  exit 1
fi
dynamic_runner_matches="$(grep -Ev \
  "$runner_inventory_exception" \
  <<<"$dynamic_runner_matches" || true)"
if [[ -n "$dynamic_runner_matches" ]]; then
  echo "supply-chain audit: dynamic package runners are not allowed in active paths" >&2
  echo "$dynamic_runner_matches" >&2
  fail=1
fi

report_matches "runtime web assets must not load package CDNs" \
  'https://(unpkg\.com|cdn\.jsdelivr\.net|esm\.sh|skypack\.dev)' \
  "${web_runtime_paths[@]}"

report_matches "Playwright browser downloads must use the checksum-verifying installer" \
  'playwright[[:space:]]+install[[:space:]]+(chromium|firefox|webkit)([[:space:]]|$)'

pinned_chromium_installer="scripts/ci/install-pinned-playwright-chromium.sh"
if ! grep -Fq "readonly chromium_version='145.0.7632.6'" "$pinned_chromium_installer" \
  || ! grep -Fq "readonly chromium_sha256='b5e3195041af345a668d110f5daf5581961fa3608626ea588c97dd0fe81c4e38'" "$pinned_chromium_installer" \
  || ! grep -Fq 'https://storage.googleapis.com/chrome-for-testing-public/' "$pinned_chromium_installer" \
  || ! grep -Fq 'sha256sum --check --status' "$pinned_chromium_installer"; then
  echo "supply-chain audit: pinned Playwright Chromium provenance guard is incomplete" >&2
  fail=1
fi

vendor_manifest=".supplychain/vendor-artifacts.json"
if ! jq -e '
  .schema_version == 1 and
  (.npm | type == "array" and length > 0) and
  all(.npm[];
    ((keys_unsorted - ["package", "version", "member", "path", "integrity", "size", "sha384"]) | length == 0) and
    (.package | type == "string" and length > 0) and
    (.version | type == "string" and length > 0) and
    (.member | type == "string" and length > 0) and
    (.path | type == "string" and length > 0) and
    (.integrity | startswith("sha512-")) and
    (.size | type == "number" and . > 0) and
    (.sha384 | startswith("sha384-")))
' "$vendor_manifest" >/dev/null; then
  echo "supply-chain audit: invalid $vendor_manifest" >&2
  fail=1
fi

while IFS=$'\t' read -r package version member path expected_size expected_sha384; do
  if [[ ! -f "$path" ]]; then
    echo "supply-chain audit: missing vendored member $path ($package@$version:$member)" >&2
    fail=1
    continue
  fi
  actual_size="$(wc -c < "$path" | tr -d '[:space:]')"
  actual_sha384="sha384-$(openssl dgst -sha384 -binary "$path" | openssl base64 -A)"
  if [[ "$actual_size" != "$expected_size" ]]; then
    echo "supply-chain audit: size mismatch for $path" >&2
    fail=1
  fi
  if [[ "$actual_sha384" != "$expected_sha384" ]]; then
    echo "supply-chain audit: SHA-384 mismatch for $path" >&2
    fail=1
  fi
done < <(jq -r '.npm[] | [.package, .version, .member, .path, (.size | tostring), .sha384] | @tsv' "$vendor_manifest")

while IFS= read -r asset; do
  if ! jq -e --arg path "$asset" 'any(.npm[]; .path == $path)' "$vendor_manifest" >/dev/null; then
    echo "supply-chain audit: undeclared vendored browser asset $asset" >&2
    fail=1
  fi
done < <(find crates/codewire-dashboard-web/assets -type f -print | sort)

while IFS=$'\t' read -r path expected_sha384; do
  case "$path" in
    *.js|*.css)
      ;;
    *)
      continue
      ;;
  esac
  reference="/assets/codewire/${path##*/}"
  sources=("crates/codewire-dashboard-web/templates" "docs/homepage/demo.html")
  matches="$(rg --no-heading -n -F "$reference" "${sources[@]}" || true)"
  if [[ -z "$matches" ]]; then
    echo "supply-chain audit: vendored browser asset is not referenced: $path" >&2
    fail=1
  else
    while IFS= read -r match; do
      if [[ "$match" != *"integrity=\"$expected_sha384\""* ]]; then
        echo "supply-chain audit: missing or incorrect SRI for $reference: $match" >&2
        fail=1
      fi
    done <<<"$matches"
  fi
done < <(jq -r '.npm[] | [.path, .sha384] | @tsv' "$vendor_manifest")

# Match an attribute token, not the suffix of a BuildKit option or data attribute.
# Keep the same scan paths and exercise the exact pattern used by the audit.
readonly inline_style_attribute='(^|[[:space:]])style[[:space:]]*='
for style_attribute in 'style="color:red"' '<p style = "color:red">' $'<p\tstyle="color:red">'; do
  if ! grep -Eq "$inline_style_attribute" <<<"$style_attribute"; then
    echo "supply-chain audit: inline-style positive self-test failed" >&2
    exit 1
  fi
done
for style_identifier in 'use_path_style=true' '<p data-style="compact">' 'lifestyle=compact'; do
  if grep -Eq "$inline_style_attribute" <<<"$style_identifier"; then
    echo "supply-chain audit: inline-style negative self-test failed" >&2
    exit 1
  fi
done

report_matches "runtime templates must not use inline style attributes" \
  "$inline_style_attribute" \
  "${runtime_template_paths[@]}"

report_matches "runtime templates must not use inline DOM event handlers" \
  '[[:space:]]on[a-z]+[[:space:]]*=' \
  "${runtime_template_paths[@]}"

while IFS= read -r line; do
  if [[ "$line" != *"src="* ]]; then
    echo "supply-chain audit: runtime templates must not use inline script blocks: $line" >&2
    fail=1
  fi
done < <(git grep -nE '<script([[:space:]>])' -- \
  crates/codewire-dashboard-web/templates 2>/dev/null || true)

while IFS= read -r line; do
  if is_ignored_line "$line"; then
    continue
  fi
  if [[ "$line" != *"--ignore-scripts"* ]]; then
    echo "supply-chain audit: bun install must use --ignore-scripts: $line" >&2
    fail=1
  fi
done < <(git grep -nE 'bun install([^#]|$)' -- "${active_paths[@]}" 2>/dev/null || true)

while IFS= read -r line; do
  if is_ignored_line "$line"; then
    continue
  fi
  if [[ "$line" != *"--ignore-scripts"* ]]; then
    echo "supply-chain audit: npm ci must use --ignore-scripts: $line" >&2
    fail=1
  fi
done < <(git grep -nE 'npm ci([^#]|$)' -- "${active_paths[@]}" 2>/dev/null || true)

htmx_asset="crates/codewire-dashboard-web/assets/htmx-2.0.10.min.js"
expected_htmx_sri="$(jq -er --arg path "$htmx_asset" '.npm[] | select(.path == $path) | .sha384' "$vendor_manifest")"
if [[ -z "$expected_htmx_sri" ]]; then
  echo "supply-chain audit: HTMX is missing from $vendor_manifest" >&2
  fail=1
fi

mapfile -t htmx_templates < <(git grep -lF 'src="/assets/codewire/htmx-2.0.10.min.js"' -- \
  crates/codewire-dashboard-web/templates 2>/dev/null || true)
if [[ "${#htmx_templates[@]}" -eq 0 ]]; then
  echo "supply-chain audit: no tracked full-page HTMX templates were found" >&2
  fail=1
fi
for template in "${htmx_templates[@]}"; do
  if ! grep -Fq "integrity=\"${expected_htmx_sri}\"" "$template"; then
    echo "supply-chain audit: $template must use the pinned HTMX SRI" >&2
    fail=1
  fi
  if ! grep -Fq '"allowEval":false,"allowScriptTags":false' "$template"; then
    echo "supply-chain audit: $template must disable HTMX eval and response scripts" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "supply-chain audit: OK"
