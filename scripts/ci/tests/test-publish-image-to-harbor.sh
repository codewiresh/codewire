#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly PUBLISH="$ROOT/scripts/ci/images/publish-image-to-harbor.sh"

fail() {
  printf '[test-publish-image-to-harbor] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/publish-image-to-harbor.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/present"

digest="sha256:$(printf 'a%.0s' {1..64})"
other_digest="sha256:$(printf 'b%.0s' {1..64})"
source_sha="$(printf 'c%.0s' {1..40})"
harbor="registry.example.invalid/codewire"

cat >"$work/bin/harbor-fetcher" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_FETCH_LOG:?}"
if [[ "$1" == --pull ]]; then
  printf 'robot$codewire+pull' >"$2"
  printf 'synthetic-harbor-pull-password' >"$3"
else
  printf 'robot$codewire+publisher' >"$1"
  printf 'synthetic-harbor-publisher-password' >"$2"
fi
SH
cat >"$work/bin/copy-helper" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${HARBOR_PUBLISH_USERNAME:?}" == 'robot$codewire+publisher' ]]
[[ "$(<"${HARBOR_PUBLISH_PASSWORD_FILE:?}")" == synthetic-harbor-publisher-password ]]
printf '%s\n' "$*" >>"${FAKE_COPY_LOG:?}"
[[ "${FAKE_COPY_FAILURE:-0}" != 1 ]]
SH
cat >"$work/bin/skopeo-runner" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_SKOPEO_LOG:?}"
case "$1" in
  --check) echo SKOPEO_RUNTIME_READY ;;
  login)
    [[ "${SKOPEO_AUTH_VOLUME:?}" == fake-volume ]]
    credential="$(cat)"
    [[ "$credential" == synthetic-harbor-pull-password \
      || "$credential" == synthetic-harbor-publisher-password ]]
    [[ "${!#}" == registry.example.invalid ]]
    ;;
  inspect)
    [[ "${SKOPEO_AUTH_VOLUME:?}" == fake-volume ]]
    ref="${!#}"
    ref="${ref#docker://}"
    ref_digest="${ref##*@}"
    if [[ -n "${FAKE_ABSENT:-}" && "$ref" == *"$FAKE_ABSENT"* \
        && ! -e "${FAKE_PRESENT_DIR:?}/${ref_digest}" ]]; then
      echo 'manifest unknown' >&2
      exit 1
    fi
    printf '%s\n' "${FAKE_PULL_DIGEST:-$ref_digest}"
    ;;
  copy)
    destination="${!#}"
    source="${*: -2:1}"
    [[ "$*" == *--src-no-creds* && "$source" == docker://ghcr.io/codewiresh/* ]]
    [[ "$destination" == docker://registry.example.invalid/codewire/*:keep-sha256-* ]]
    touch "${FAKE_PRESENT_DIR:?}/${source##*@}"
    ;;
  *) exit 64 ;;
esac
SH
cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'volume create') printf 'fake-volume\n' ;;
  'volume rm fake-volume') printf 'removed\n' >>"${FAKE_DOCKER_LOG:?}" ;;
  *) exit 1 ;;
esac
SH
chmod +x "$work/bin/"*

export OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/bin/harbor-fetcher"
export HARBOR_COPY_HELPER="$work/bin/copy-helper"
export SKOPEO_RUNNER="$work/bin/skopeo-runner"
export DOCKER_BIN="$work/bin/docker"
export FAKE_FETCH_LOG="$work/fetch.log"
export FAKE_COPY_LOG="$work/copy.log"
export FAKE_SKOPEO_LOG="$work/skopeo.log"
export FAKE_DOCKER_LOG="$work/docker.log"
export FAKE_PRESENT_DIR="$work/present"

reset_logs() { : >"$FAKE_FETCH_LOG"; : >"$FAKE_COPY_LOG"; : >"$FAKE_SKOPEO_LOG"; : >"$FAKE_DOCKER_LOG"; }

bundle="$work/bundle.json"
python3 "$ROOT/scripts/ci/images/image-bundle.py" create --source-sha "$source_sha" --output "$bundle" \
  --candidate dashboard "$source_sha" "$harbor/dashboard@$digest" \
  --candidate derp "$source_sha" "$harbor/derp@$digest" \
  --candidate daemon "$source_sha" "$harbor/daemon@$digest" \
  --candidate services "$source_sha" "$harbor/services@$digest" \
  --candidate mesh "$source_sha" "$harbor/mesh@$digest"

reset_logs
export GITHUB_OUTPUT="$work/output"
: >"$GITHUB_OUTPUT"
"$PUBLISH" --runtime-bundle "$bundle" >"$work/runtime.out" 2>&1 ||
  { cat "$work/runtime.out" >&2; fail 'runtime bundle publication failed'; }
[[ "$(wc -l <"$FAKE_COPY_LOG")" -eq 5 ]] || fail 'runtime bundle did not confirm five source tags'
for family in dashboard derp daemon services mesh; do
  grep -qxF "$harbor/$family@$digest $harbor/$family $source_sha" "$FAKE_COPY_LOG" ||
    fail "runtime publication for $family is not the exact source-tagged Harbor image"
  grep -qxF "${family}_harbor_ref=$harbor/$family@$digest" "$GITHUB_OUTPUT" ||
    fail "runtime Harbor ref output for $family is absent"
done
[[ "$(grep -c '^inspect ' "$FAKE_SKOPEO_LOG")" -eq 5 ]] ||
  fail 'the pull-only identity did not verify all five digests'
grep -qxF -- '--pull' <(cut -d' ' -f1 "$FAKE_FETCH_LOG") ||
  fail 'the Harbor pull-only credential was not fetched'
if grep -q '^copy ' "$FAKE_SKOPEO_LOG"; then
  fail 'runtime publication imported an image instead of confirming Harbor tags'
fi
grep -qxF removed "$FAKE_DOCKER_LOG" || fail 'the pull auth volume was not removed'
if grep -rqF synthetic- "$FAKE_COPY_LOG" "$FAKE_SKOPEO_LOG" "$work/runtime.out"; then
  fail 'a registry credential reached command arguments or output'
fi

reset_logs
"$PUBLISH" --support-pair "$harbor/base@$digest" "$harbor/workspace@$digest" "$source_sha" \
  >"$work/support.out" 2>&1 || { cat "$work/support.out" >&2; fail 'support pair publication failed'; }
grep -qxF "$harbor/base@$digest $harbor/base $source_sha latest" "$FAKE_COPY_LOG" ||
  fail 'support base did not receive its source tag and latest alias'
grep -qxF "$harbor/workspace@$digest $harbor/workspace $source_sha latest" "$FAKE_COPY_LOG" ||
  fail 'support workspace did not receive its source tag and latest alias'

reset_logs
"$PUBLISH" --keep "$harbor/workspace@$digest" "$harbor/daemon@$digest" >"$work/keep.out" 2>&1 ||
  { cat "$work/keep.out" >&2; fail 'keep publication failed'; }
grep -qxF "$harbor/workspace@$digest $harbor/workspace keep-${digest/:/-}" "$FAKE_COPY_LOG" ||
  fail 'keep publication did not use the exact-digest keep tag'
[[ "$(grep -c '^inspect ' "$FAKE_SKOPEO_LOG")" -eq 2 ]] || fail 'keep publication did not verify both digests'

# Compiled-in defaults already in Harbor are only kept; the public mirror is
# never contacted.
mapfile -t pinned < <(
  grep -ohE 'registry\.example\.invalid/codewire/(workspace|daemon)@sha256:[0-9a-f]{64}' \
    "$ROOT/crates/codewire-server-core/src/runtime_images.rs" | sort -u
)
[[ "${#pinned[@]}" -ge 2 ]] || fail 'source does not pin Harbor workspace and daemon defaults'
reset_logs
"$PUBLISH" --pinned-defaults >"$work/pinned.out" 2>&1 ||
  { cat "$work/pinned.out" >&2; fail 'pinned defaults publication failed'; }
if grep -q '^copy ' "$FAKE_SKOPEO_LOG"; then
  fail 'a pinned default already in Harbor was imported again'
fi
for ref in "${pinned[@]}"; do
  pinned_digest="${ref##*@}"
  grep -qxF "$ref ${ref%@*} keep-${pinned_digest/:/-}" "$FAKE_COPY_LOG" ||
    fail "pinned default was not kept in Harbor: $ref"
done

# A default Harbor lacks is imported once, by exact digest, from the public
# mirror without credentials, then kept and verified.
reset_logs
workspace_default="$(printf '%s\n' "${pinned[@]}" | grep '/workspace@')"
FAKE_ABSENT="${workspace_default##*@}" "$PUBLISH" --pinned-defaults >"$work/import.out" 2>&1 ||
  { cat "$work/import.out" >&2; fail 'pinned default import failed'; }
[[ "$(grep -c '^copy ' "$FAKE_SKOPEO_LOG")" -eq 1 ]] ||
  fail 'a missing pinned default was not imported exactly once'
grep -qF "docker://ghcr.io/codewiresh/workspace@${workspace_default##*@}" "$FAKE_SKOPEO_LOG" ||
  fail 'the pinned default import did not use the exact public digest'
grep -qF 'Imported pinned default into Harbor' "$work/import.out" ||
  fail 'the pinned default import was not reported'
reset_logs
FAKE_ABSENT="${workspace_default##*@}" "$PUBLISH" --pinned-defaults >"$work/import-again.out" 2>&1 ||
  fail 'repeated pinned default publication failed'
if grep -q '^copy ' "$FAKE_SKOPEO_LOG"; then
  fail 'an imported pinned default was imported again'
fi

reset_logs
"$PUBLISH" "$harbor/confidential-probe@$digest" "$harbor/confidential-probe" "$source_sha" \
  >"$work/single.out" 2>&1 || { cat "$work/single.out" >&2; fail 'single publication failed'; }
if "$PUBLISH" "$harbor/daemon@$digest" "$harbor/services" "$source_sha" \
    >"$work/mismatch.out" 2>&1; then
  fail 'a Harbor repository for another family was accepted'
fi
if "$PUBLISH" --keep "ghcr.io/codewiresh/workspace@$digest" >"$work/bad-keep.out" 2>&1; then
  fail 'a non-Harbor keep source was accepted'
fi
if "$PUBLISH" "ghcr.io/codewiresh/daemon@$digest" \
    "$harbor/daemon" "$source_sha" >"$work/foreign-source.out" 2>&1; then
  fail 'a non-Harbor source reference was accepted'
fi

reset_logs
if FAKE_PULL_DIGEST="$other_digest" "$PUBLISH" --runtime-bundle "$bundle" >"$work/pull.out" 2>&1; then
  fail 'a digest the pull-only identity reads differently was accepted'
fi
grep -qF 'Harbor pull identity does not read the canonical digest' "$work/pull.out" ||
  fail 'pull identity mismatch was not attributable'

reset_logs
if FAKE_COPY_FAILURE=1 "$PUBLISH" --runtime-bundle "$bundle" >"$work/copy-failure.out" 2>&1; then
  fail 'a failed Harbor tag confirmation was accepted'
fi
if grep -q '^inspect ' "$FAKE_SKOPEO_LOG"; then
  fail 'verification continued after a failed Harbor tag confirmation'
fi

echo '[test-publish-image-to-harbor] Harbor publication contract passed'
