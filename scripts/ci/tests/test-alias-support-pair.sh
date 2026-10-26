#!/usr/bin/env bash
# Execute scripts/ci/images/alias-support-pair.sh against a recording registry:
# it tags exactly the planned indexes, only when Harbor's own tags of the
# source pair name them, never moves latest, and proves the aliases resolve to
# the same digests in Harbor and anonymously in GHCR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly ALIAS="$ROOT/scripts/ci/images/alias-support-pair.sh"
readonly REGISTRY=harbor.example.invalid
readonly SOURCE=1111111111111111111111111111111111111111
readonly FROM=2222222222222222222222222222222222222222
BASE_DIGEST="sha256:$(printf 'a%.0s' {1..64})"
WORKSPACE_DIGEST="sha256:$(printf 'b%.0s' {1..64})"
readonly BASE_DIGEST WORKSPACE_DIGEST

fail() {
  printf '[test-alias-support-pair] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"

# The registry: one file per tag, named after the reference, holding its digest.
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$(basename "$DOCKER_CONFIG")" "$*" >>"$STUB_LOG"
case "$1" in
  login)
    [[ "$2" == "$CODEWIRE_IMAGE_REGISTRY" && "$(basename "$DOCKER_CONFIG")" == harbor-config ]]
    cat >/dev/null ;;
  buildx)
    reference="${*: -1}"
    case "$reference" in
      "$CODEWIRE_IMAGE_REGISTRY"/*) [[ "$(basename "$DOCKER_CONFIG")" == harbor-config ]] ;;
      ghcr.io/*) [[ "$(basename "$DOCKER_CONFIG")" == public-config ]] ;;
      *) exit 2 ;;
    esac
    file="$REGISTRY_STATE/${reference//[\/:]/_}"
    [[ -f "$file" ]] || { echo "$reference: not found" >&2; exit 1; }
    printf '{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s"}\n' "$(<"$file")" ;;
  *) exit 2 ;;
esac
STUB
cat >"$work/bin/publish" <<'STUB'
#!/usr/bin/env bash
# publish DIGEST_REF REPOSITORY TAG: copy the exact digest to the tag.
set -euo pipefail
printf '%s %s\n' "$(basename "$0")" "$*" >>"$STUB_LOG"
[[ $# -eq 3 ]]
[[ "$(basename "$0")" != "${FAIL_PUBLISHER:-}" ]] || exit 1
[[ "$(basename "$0")" != "${STALE_PUBLISHER:-}" ]] || exit 0
reference="$2:$3"
printf '%s\n' "${1##*@}" >"$REGISTRY_STATE/${reference//[\/:]/_}"
STUB
chmod +x "$work/bin/docker" "$work/bin/publish"
ln -s publish "$work/bin/harbor-publisher"
ln -s publish "$work/bin/ghcr-publisher"
cat >"$work/bin/fetcher" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == --pull && $# -eq 3 ]] || exit 1
printf 'pull-robot\n' >"$2"
printf 'synthetic-password\n' >"$3"
STUB
cat >"$work/bin/release-check" <<'STUB'
#!/usr/bin/env bash
printf 'release-check %s\n' "$*" >>"$STUB_LOG"
STUB
chmod +x "$work/bin/fetcher" "$work/bin/release-check"

# seed NAME: a fresh registry holding the FROM pair in both registries.
seed() {
  state="$work/$1.registry"
  log="$work/$1.log"
  mkdir -p "$state"
  : >"$log"
  local prefix image digest
  for prefix in "$REGISTRY/codewire" ghcr.io/codewiresh; do
    for image in base workspace; do
      digest="$BASE_DIGEST"
      [[ "$image" == base ]] || digest="$WORKSPACE_DIGEST"
      printf '%s\n' "$digest" >"$state/${prefix//[\/:]/_}_${image}_$FROM"
      printf '%s\n' "$digest" >"$state/${prefix//[\/:]/_}_${image}_latest"
    done
  done
}
# run NAME [ENV...] -- ARGS... prints ok or failed
run() {
  local name="$1"
  shift
  local -a extra=()
  while [[ "$1" != -- ]]; do extra+=("$1"); shift; done
  shift
  if env CODEWIRE_IMAGE_REGISTRY="$REGISTRY" DOCKER_BIN="$work/bin/docker" \
      OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/bin/fetcher" \
      SUPPORT_ALIAS_HARBOR_PUBLISHER="$work/bin/harbor-publisher" \
      SUPPORT_ALIAS_GHCR_PUBLISHER="$work/bin/ghcr-publisher" \
      SUPPORT_ALIAS_RELEASE_CHECK="$work/bin/release-check" \
      REGISTRY_STATE="$work/$name.registry" STUB_LOG="$work/$name.log" RUNNER_TEMP="$work" \
      "${extra[@]}" "$ALIAS" "$@" >"$work/$name.out" 2>&1; then
    echo ok
  else
    echo failed
  fi
}
digest_of() { cat "$work/$1.registry/${2//[\/:]/_}" 2>/dev/null || echo missing; }

seed success
[[ "$(run success -- "$SOURCE" "$FROM" "$BASE_DIGEST" "$WORKSPACE_DIGEST")" == ok ]] ||
  { cat "$work/success.out" >&2; fail 'a valid alias failed'; }
for prefix in "$REGISTRY/codewire" ghcr.io/codewiresh; do
  [[ "$(digest_of success "$prefix/base:$SOURCE")" == "$BASE_DIGEST" ]] ||
    fail "the base alias in $prefix does not name the planned index"
  [[ "$(digest_of success "$prefix/workspace:$SOURCE")" == "$WORKSPACE_DIGEST" ]] ||
    fail "the workspace alias in $prefix does not name the planned index"
done
grep -Fxq "harbor-publisher $REGISTRY/codewire/base@$BASE_DIGEST $REGISTRY/codewire/base $SOURCE" "$work/success.log" ||
  fail 'the base was not tagged in Harbor by its exact digest'
grep -Fxq "ghcr-publisher $REGISTRY/codewire/workspace@$WORKSPACE_DIGEST ghcr.io/codewiresh/workspace $SOURCE" "$work/success.log" ||
  fail 'the workspace was not mirrored to GHCR by its exact digest'
if grep -E 'publisher .*latest' "$work/success.log"; then
  fail 'the alias moved latest'
fi
[[ "$(grep -c 'publisher ' "$work/success.log")" -eq 4 ]] || fail 'the alias published more than the two tags in two registries'
grep -Fxq "support pair alias: base:$SOURCE is $BASE_DIGEST, the pair published for $FROM" "$work/success.out" ||
  fail 'the alias does not log the pair it came from'
[[ "$(tail -n 1 "$work/success.log")" == "release-check $SOURCE" ]] ||
  fail 'the alias does not end with the release support-pair check'
grep -q 'synthetic-password' "$work/success.out" "$work/success.log" && fail 'the pull credential leaked'
if grep -E '^public-config login' "$work/success.log"; then
  fail 'GHCR was read with a credential'
fi

# Harbor's own source tags must name exactly the planned indexes.
seed moved
printf '%s\n' "sha256:$(printf 'c%.0s' {1..64})" >"$work/moved.registry/${REGISTRY}_codewire_workspace_$FROM"
[[ "$(run moved -- "$SOURCE" "$FROM" "$BASE_DIGEST" "$WORKSPACE_DIGEST")" == failed ]] ||
  fail 'an alias of a pair Harbor does not hold was accepted'
grep -q 'publisher ' "$work/moved.log" && fail 'a refused alias published a tag'
grep -Fq 'refusing the alias' "$work/moved.out" || fail 'the refused alias was refused for another reason'

seed missing
rm -f "$work/missing.registry/${REGISTRY}_codewire_base_$FROM"
[[ "$(run missing -- "$SOURCE" "$FROM" "$BASE_DIGEST" "$WORKSPACE_DIGEST")" == failed ]] ||
  fail 'an alias of an unpublished pair was accepted'
grep -q 'publisher ' "$work/missing.log" && fail 'an alias of an unpublished pair published a tag'

# A tag that does not resolve to the planned digest afterwards fails the job.
seed stale
[[ "$(run stale STALE_PUBLISHER=ghcr-publisher -- "$SOURCE" "$FROM" "$BASE_DIGEST" "$WORKSPACE_DIGEST")" == failed ]] ||
  fail 'an alias GHCR does not serve was accepted'
grep -q 'release-check' "$work/stale.log" && fail 'the release check ran after a failed alias'
seed refused
[[ "$(run refused FAIL_PUBLISHER=harbor-publisher -- "$SOURCE" "$FROM" "$BASE_DIGEST" "$WORKSPACE_DIGEST")" == failed ]] ||
  fail 'a failed Harbor publication was accepted'

seed args
for args in \
  "$SOURCE $SOURCE $BASE_DIGEST $WORKSPACE_DIGEST" \
  "${SOURCE:0:12} $FROM $BASE_DIGEST $WORKSPACE_DIGEST" \
  "$SOURCE $FROM sha256:short $WORKSPACE_DIGEST" \
  "$SOURCE $FROM $BASE_DIGEST $BASE_DIGEST" \
  "$SOURCE $FROM $BASE_DIGEST"; do
  # shellcheck disable=SC2086 # Split the case into its arguments.
  [[ "$(run args -- $args)" == failed ]] || fail "malformed arguments were accepted: $args"
done
grep -q 'publisher ' "$work/args.log" && fail 'malformed arguments published a tag'

echo 'test-alias-support-pair: PASS'
