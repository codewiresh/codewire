#!/usr/bin/env bash
# Hermetic contract for `dev-loop.sh runtime-images`: every row resolves from
# its product constant to a public source of the same digest, loads by digest
# into every Kind node under the reference the product renders, is idempotent,
# and fails closed. Fake kind, kubectl and docker stand in for the cluster.
set -euo pipefail
unset CLUSTER KIND_PROFILE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-runtime-images.XXXXXX")"
trap 'rm -rf -- "$FIXTURE"' EXIT
BIN="$FIXTURE/bin"
TREE="$FIXTURE/tree"
STATE="$FIXTURE/state"
CALLS="$FIXTURE/docker-calls"
SCRIPT="$TREE/scripts/dev/kind/dev-loop.sh"
WORKSPACE_CONSTANTS="$TREE/crates/codewire-workspace-image/src/pin.rs"
DIND_CONSTANTS="$TREE/crates/codewire-orchestration/src/sandbox/template/mod.rs"

readonly WS_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly DIND_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
readonly WS_DIGEST_UPPER=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
readonly OTHER_DIGEST=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
readonly WS_REF="registry.example.invalid/codewire/workspace@${WS_DIGEST}"
readonly WS_SOURCE="ghcr.io/codewiresh/workspace@${WS_DIGEST}"
readonly DIND_REF="docker.io/library/docker:29.7.1-dind@${DIND_DIGEST}"
readonly DIND_SOURCE="docker.io/library/docker@${DIND_DIGEST}"

fail() {
  printf '[test-kind-runtime-images] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$BIN" "$STATE" "$(dirname "$SCRIPT")" "$(dirname "$WORKSPACE_CONSTANTS")" \
  "$(dirname "$DIND_CONSTANTS")"
cp "$ROOT/scripts/dev/kind/dev-loop.sh" "$SCRIPT"
cp "$ROOT/scripts/dev/kind/profile.sh" "$TREE/scripts/dev/kind/profile.sh"

write_constants() {
  printf 'pub const HARBOR_IMAGE: &str = "%s";\n' "$1" >"$WORKSPACE_CONSTANTS"
  printf 'pub const DEFAULT_DIND_IMAGE: &str = "%s";\n' "$2" >"$DIND_CONSTANTS"
}

cat >"$BIN/kind" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'get clusters') printf '%s\n' "${FAKE_CLUSTERS-codewire-e2e-ci}" ;;
  'get nodes --name codewire-e2e-ci') printf '%s\n' $FAKE_NODES ;;
  *) exit 64 ;;
esac
EOF

cat >"$BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *' get deployment codewire-credential-service' ]] || exit 64
EOF

# Each node's image store is one "<name> <digest>" line per record. A pull
# records the reference under the digest it names unless FAKE_PULL_DIGEST
# models a registry that serves other content.
cat >"$BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_CALLS"
[ "$1" = exec ] || exit 64
store="$FAKE_STATE/$2.images"
touch "$store"
shift 2
case "$*" in
  'ctr -n k8s.io images ls')
    printf 'REF TYPE DIGEST SIZE PLATFORMS LABELS\n'
    while read -r name digest; do
      printf '%s application/vnd.oci.image.index.v1+json %s 1.0 MiB linux/amd64 -\n' \
        "$name" "$digest"
    done <"$store"
    ;;
  'crictl pull '*)
    [ "${FAKE_PULL_FAIL:-0}" != 1 ] || exit 1
    ref="$3"
    grep -q "^${ref} " "$store" \
      || printf '%s %s\n' "$ref" "${FAKE_PULL_DIGEST:-${ref##*@}}" >>"$store"
    ;;
  'ctr -n k8s.io images tag '*)
    source="$6" target="$7"
    ! grep -q "^${target} " "$store" || exit 1
    digest="$(awk -v ref="$source" '$1 == ref { print $2 }' "$store")"
    [ -n "$digest" ] || exit 1
    printf '%s %s\n' "$target" "$digest" >>"$store"
    ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$BIN/kind" "$BIN/kubectl" "$BIN/docker"

reset_nodes() {
  rm -f "$STATE"/*.images
  : >"$CALLS"
}

run_loader() {
  env PATH="$BIN:$PATH" KIND_CLUSTER_NAME=codewire-e2e-ci \
    FAKE_NODES='kind-control-plane kind-worker' FAKE_STATE="$STATE" FAKE_CALLS="$CALLS" \
    "$SCRIPT" runtime-images "$@"
}

expect_failure() {
  local label="$1" message="$2"
  shift 2
  if "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "${label} unexpectedly succeeded"
  fi
  grep -Fq -- "$message" "$FIXTURE/${label}.out" \
    || fail "${label} did not report: ${message} ($(cat "$FIXTURE/${label}.out"))"
}

node_digest() {
  awk -v ref="$2" '$1 == ref { print $2 }' "$STATE/$1.images" 2>/dev/null
}

call_count() {
  grep -Fxc -- "$1" "$CALLS" || true
}

# The real product constants resolve, and each source pins the same digest.
real_workspace="$(sed -n 's/^pub const HARBOR_IMAGE: &str = "\(.*\)";$/\1/p' \
  "$ROOT/crates/codewire-workspace-image/src/pin.rs")"
real_dind="$(sed -n 's/^pub const DEFAULT_DIND_IMAGE: &str = "\(.*\)";$/\1/p' \
  "$ROOT/crates/codewire-orchestration/src/sandbox/template/mod.rs")"
expected="workspace ${real_workspace} <- ghcr.io/codewiresh/workspace@${real_workspace##*@}
dind ${real_dind} <- docker.io/library/docker@${real_dind##*@}"
actual="$(env PATH="$BIN:$PATH" "$ROOT/scripts/dev/kind/dev-loop.sh" runtime-images --dry-run)" \
  || fail "the product constants do not resolve; update RUNTIME_IMAGES with them"
[ "$actual" = "$expected" ] || fail "unexpected product plan:
${actual}"

# A dry run reads only the constants: no cluster, node or registry.
write_constants "$WS_REF" "$DIND_REF"
reset_nodes
[ "$(run_loader --dry-run)" = "workspace ${WS_REF} <- ${WS_SOURCE}
dind ${DIND_REF} <- ${DIND_SOURCE}" ] || fail "dry run printed an unexpected plan"
[ ! -s "$CALLS" ] || fail "dry run touched a node"

# A load needs the retained cluster; it never touches another.
reset_nodes
FAKE_CLUSTERS=codewire-ux-2099 expect_failure absent_cluster \
  'cluster codewire-e2e-ci does not exist' run_loader
[ ! -s "$CALLS" ] || fail "a load without the cluster touched a node"

# Fresh nodes pull each source by digest; only the workspace needs a second
# name, because containerd already records the DinD reference by its digest.
run_loader >/dev/null 2>&1 || fail "fresh load failed"
for node in kind-control-plane kind-worker; do
  [ "$(node_digest "$node" "$WS_REF")" = "$WS_DIGEST" ] || fail "$node lacks $WS_REF"
  [ "$(node_digest "$node" "$DIND_SOURCE")" = "$DIND_DIGEST" ] || fail "$node lacks $DIND_SOURCE"
  [ "$(call_count "exec $node crictl pull $WS_SOURCE")" = 1 ] || fail "$node workspace pull count"
  [ "$(call_count "exec $node crictl pull $DIND_SOURCE")" = 1 ] || fail "$node DinD pull count"
  [ "$(call_count "exec $node ctr -n k8s.io images tag $WS_SOURCE $WS_REF")" = 1 ] \
    || fail "$node workspace was not named as the product renders it"
done
! grep -Eq 'crictl pull .*:29\.7\.1-dind|images tag .*docker' "$CALLS" \
  || fail "DinD was pulled by tag or renamed"
[ "$(grep -c ' crictl pull ' "$CALLS")" = 4 ] || fail "fresh load pulled more than needed"

# A second run finds every image at its digest and changes nothing.
: >"$CALLS"
run_loader >/dev/null 2>&1 || fail "idempotent rerun failed"
! grep -Eq ' crictl pull | images tag ' "$CALLS" || fail "rerun pulled or renamed an image"

# A node that already holds DinD loads only the workspace.
reset_nodes
printf '%s %s\n' "$DIND_SOURCE" "$DIND_DIGEST" >"$STATE/kind-worker.images"
run_loader >/dev/null 2>&1 || fail "partial load failed"
[ "$(call_count "exec kind-worker crictl pull $DIND_SOURCE")" = 0 ] || fail "present DinD was pulled"
[ "$(call_count "exec kind-worker crictl pull $WS_SOURCE")" = 1 ] || fail "missing workspace was not pulled"

# A record naming the product reference for other content fails closed.
reset_nodes
printf '%s %s\n' "$WS_REF" "$OTHER_DIGEST" >"$STATE/kind-control-plane.images"
expect_failure mismatched_record "names ${WS_REF} for ${OTHER_DIGEST}" run_loader
! grep -q ' crictl pull ' "$CALLS" || fail "a mismatched record was overwritten"

# A source that resolves to other content is never named as the product image.
reset_nodes
FAKE_PULL_DIGEST="$OTHER_DIGEST" expect_failure pulled_other_digest \
  "pulled ${WS_SOURCE} as ${OTHER_DIGEST}" run_loader
! grep -q ' images tag ' "$CALLS" || fail "other content was renamed"

reset_nodes
FAKE_PULL_FAIL=1 expect_failure pull_failure "ghcr.io/codewiresh/workspace does not serve" run_loader

# Malformed constants fail before any node is touched.
malformed_case() {
  local label="$1" message="$2"
  reset_nodes
  write_constants "$3" "$4"
  expect_failure "$label" "$message" run_loader
  [ ! -s "$CALLS" ] || fail "${label} touched a node"
}
malformed_case dind_tag_only 'DEFAULT_DIND_IMAGE is not a reference the dind row accepts' \
  "$WS_REF" 'docker.io/library/docker:29.7.1-dind'
malformed_case dind_other_repository 'DEFAULT_DIND_IMAGE is not a reference the dind row accepts' \
  "$WS_REF" "docker.io/library/docker:dind@${DIND_DIGEST}"
malformed_case workspace_other_registry 'HARBOR_IMAGE is not a reference the workspace row accepts' \
  "ghcr.io/codewiresh/workspace@${WS_DIGEST}" "$DIND_REF"
malformed_case workspace_uppercase_digest 'HARBOR_IMAGE is not a reference the workspace row accepts' \
  "registry.example.invalid/codewire/workspace@sha256:${WS_DIGEST_UPPER}" "$DIND_REF"

reset_nodes
write_constants "$WS_REF" "$DIND_REF"
printf 'pub const DEFAULT_DIND_IMAGE: &str = "%s";\n' "$DIND_REF" >>"$DIND_CONSTANTS"
expect_failure repeated_constant 'must define DEFAULT_DIND_IMAGE once' run_loader
: >"$DIND_CONSTANTS"
expect_failure missing_constant 'must define DEFAULT_DIND_IMAGE once' run_loader --dry-run
[ ! -s "$CALLS" ] || fail "an unresolved table touched a node"

# A row whose source would not pin the reference's own digest is rejected.
write_constants "$WS_REF" "$DIND_REF"
cp "$SCRIPT" "$FIXTURE/dev-loop.sh"
sed -i "s#ghcr.io/codewiresh/\\\\1@\\\\2#ghcr.io/codewiresh/\\\\1@${OTHER_DIGEST}#" "$SCRIPT"
! cmp -s "$SCRIPT" "$FIXTURE/dev-loop.sh" || fail "could not rewrite the workspace row"
expect_failure other_digest_source 'does not pin HARBOR_IMAGE' run_loader --dry-run
cp "$FIXTURE/dev-loop.sh" "$SCRIPT"
sed -i 's#ghcr.io/codewiresh/\\1@\\2#ghcr.io/codewiresh/\\1:latest#' "$SCRIPT"
! cmp -s "$SCRIPT" "$FIXTURE/dev-loop.sh" || fail "could not rewrite the workspace row"
expect_failure tagged_source 'does not pin HARBOR_IMAGE' run_loader --dry-run

printf '[test-kind-runtime-images] table, digest identity, idempotence and fail-closed loads passed\n'
