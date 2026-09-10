#!/usr/bin/env bash
# Failure fixtures never invoke Docker or contact a registry.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
mkdir -p "$ROOT/.tmp"
scratch="$(mktemp -d "$ROOT/.tmp/codewire-ssh-image-verifier.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin" "$scratch/config"
cat >"$scratch/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" != fixture-probe ]] || exit 0
touch "$SSH_FIXTURE_STATE/docker-invoked"
image="sha256:$(printf '%064d' 1)"
id="$(printf '%064d' 2)"
case "$1" in
  image) printf '%s\n' "$image" ;;
  create)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --label) printf '%s' "${2#*=}" >"$SSH_FIXTURE_STATE/owner"; shift ;;
      esac
      shift
    done
    touch "$SSH_FIXTURE_STATE/created"
    [[ "$SSH_FIXTURE_MODE" != response-loss ]] || exit 1
    printf '%s\n' "$id"
    ;;
  container)
    if [[ -f "$SSH_FIXTURE_STATE/created" ]]; then printf '%s\n' "$id"; fi
    ;;
  inspect)
    if [[ "$3" == '{{.State.ExitCode}}' ]]; then
      printf '0\n'
    else
      owner="$(<"$SSH_FIXTURE_STATE/owner")"
      [[ "$SSH_FIXTURE_MODE" != wrong-owner ]] || owner=another-owner
      printf '%s %s %s\n' "$id" "$image" "$owner"
    fi
    ;;
  start) exit 0 ;;
  rm)
    touch "$SSH_FIXTURE_STATE/removal-attempted"
    [[ "$SSH_FIXTURE_MODE" != cleanup-failure ]] || exit 1
    rm "$SSH_FIXTURE_STATE/created"
    ;;
  *) exit 2 ;;
esac
SH
chmod 755 "$scratch/bin/docker"
# Fail before any PATH lookup could fall through to a real Docker CLI when the
# fixture directory is unexpectedly mounted noexec.
"$scratch/bin/docker" fixture-probe

for mode in response-loss cleanup-failure wrong-owner success; do
  state="$scratch/$mode"
  mkdir "$state"
  status=0
  PATH="$scratch/bin:$PATH" DOCKER_CONFIG="$scratch/config" \
    SSH_FIXTURE_MODE="$mode" SSH_FIXTURE_STATE="$state" \
    "$ROOT/scripts/ci/verify/verify-service-ssh-image.sh" synthetic-image \
    >"$state/output" 2>&1 || status=$?
  [[ -e "$state/docker-invoked" ]] || {
    echo 'SSH verifier fixture did not execute its isolated Docker stub' >&2
    exit 1
  }
  if [[ "$mode" == success ]]; then
    [[ "$status" -eq 0 && ! -e "$state/created" ]]
    grep -Fq 'services SSH packaged tools/helper passed:' "$state/output"
  else
    [[ "$status" -ne 0 ]]
    if grep -Fq 'services SSH packaged tools/helper passed:' "$state/output"; then
      echo 'failed cleanup emitted acceptance' >&2
      exit 1
    fi
    case "$mode" in
      response-loss) [[ ! -e "$state/created" && -e "$state/removal-attempted" ]] ;;
      cleanup-failure) [[ -e "$state/created" && -e "$state/removal-attempted" ]] ;;
      wrong-owner) [[ -e "$state/created" && ! -e "$state/removal-attempted" ]] ;;
    esac
  fi
done
printf 'services SSH image verifier: 4 failure/success fixtures passed\n'
