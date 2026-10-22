#!/usr/bin/env bash
# Exercise run-workspace-contract-on-image.sh against a fake Docker client, a
# fake pull-credential fetcher and a contract that would leave a marker if it
# ever ran on the host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# CI names these in Actions variables and the job context; the scripts
# require them.
export CODEWIRE_IMAGE_REGISTRY=registry.example.invalid
readonly RUNNER="$ROOT/scripts/ci/images/run-workspace-contract-on-image.sh"

fail() {
  printf '[test-run-workspace-contract-on-image] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$RUNNER"
[[ -x "$RUNNER" ]] || fail 'the contract runner is not executable'

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/run-workspace-contract-on-image.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin" "$work/runner" "$work/state"

readonly DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly REF="registry.example.invalid/codewire/workspace@$DIGEST"
readonly GHCR_REF="ghcr.io/codewiresh/workspace@$DIGEST"
readonly REVISION=0123456789abcdef0123456789abcdef01234567
readonly IMAGE_ID=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

# Executed on the host, this contract would leave the marker.
contract="$work/workspace-agent-contract.sh"
printf '#!/usr/bin/env bash\ntouch %q\nexit 0\n' "$work/host-executed" >"$contract"

cat >"$work/fetcher" <<'FETCH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_STATE/fetch.log"
[[ "${FAKE_FETCH:-ok}" == ok ]] || exit 1
[[ "$1" == --pull && "$#" -eq 3 ]] || exit 64
printf 'robot$codewire+pull\n' >"$2"
printf 'synthetic-pull-password\n' >"$3"
FETCH

cat >"$work/bin/sleep" <<'SLEEP'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_STATE/sleep.log"
SLEEP

# Each call is logged as one line: the config it saw, whether the login
# configuration still existed, then the quoted arguments.
cat >"$work/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
state="$FAKE_STATE"
login_config="$(cat "$state/login-config" 2>/dev/null || true)"
config_present=no
[[ -z "$login_config" || ! -e "$login_config" ]] || config_present=yes
{
  printf 'config=%s present=%s |' "${DOCKER_CONFIG:-}" "$config_present"
  printf ' %q' "$@"
  printf '\n'
} >>"$state/docker.log"
case "$1" in
  login)
    [[ "${FAKE_LOGIN:-ok}" == ok ]] || { echo 'unauthorized' >&2; exit 1; }
    [[ "$(cat)" == synthetic-pull-password ]] || exit 65
    printf '%s\n' "$DOCKER_CONFIG" >"$state/login-config"
    printf '{"auths":{"registry.example.invalid":{}}}\n' >"$DOCKER_CONFIG/config.json"
    ;;
  pull)
    printf '%s\n' "$DOCKER_CONFIG" >"$state/pull-config"
    if [[ "${FAKE_PULL:-ok}" != ok ]]; then echo 'toomanyrequests' >&2; exit 1; fi
    : >"$state/pulled"
    ;;
  image)
    case "$2" in
      inspect)
        [[ -e "$state/pulled" || "${FAKE_PRESENT:-no}" == yes ]] || { echo 'No such image' >&2; exit 1; }
        jq -n --arg id "$FAKE_IMAGE_ID" --arg digest "${FAKE_REPO_DIGEST:-${*: -1}}" \
          --arg os "${FAKE_OS:-linux}" --arg arch "${FAKE_ARCH:-amd64}" --arg revision "${FAKE_LABEL-$FAKE_REVISION}" \
          '[{Id: $id, RepoDigests: ["registry.example.invalid/other@sha256:\("b" * 64)", $digest], Os: $os,
             Architecture: $arch, Config: {Labels: (if $revision == "" then {} else
             {"org.opencontainers.image.revision": $revision} end)}}]'
        ;;
      rm) ;;
      *) exit 64 ;;
    esac
    ;;
  run)
    count="$(( $(cat "$state/runs" 2>/dev/null || echo 0) + 1 ))"
    printf '%s\n' "$count" >"$state/runs"
    cat >"$state/stdin.$count"
    case "${FAKE_RUN_FAIL:-}:$*" in
      full:*' -eu -s') exit 3 ;;
      mounted-home:*' --mounted-home-agents') exit 4 ;;
    esac
    ;;
  rm) ;;
  *) exit 64 ;;
esac
DOCKER
chmod 0755 "$work/fetcher" "$work/bin/sleep" "$work/bin/docker"

# run_case [ENV=VALUE ...] -- RUNNER_ARGS... prints ok or "failed STATUS".
run_case() {
  local -a settings=()
  while [[ "$1" != -- ]]; do settings+=("$1"); shift; done
  shift
  rm -rf -- "${work:?}/state" "$work/output"
  mkdir -p "$work/state"
  : >"$work/state/docker.log"; : >"$work/state/fetch.log"; : >"$work/output"
  if env -u GITHUB_ACTIONS -u FORGEJO_ACTIONS -u GITEA_ACTIONS -u OPENBAO_HARBOR_CREDENTIAL_FETCHER \
      PATH="$work/bin:$PATH" FAKE_STATE="$work/state" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REVISION="$REVISION" \
      OPENBAO_HARBOR_CREDENTIAL_FETCHER="$work/fetcher" RUNNER_TEMP="$work/runner" GITHUB_OUTPUT="$work/output" \
      "${settings[@]}" "$RUNNER" "$@" >"$work/out" 2>&1; then
    echo ok
  else
    echo "failed $?"
  fi
}
docker_calls() { cut -d'|' -f2- "$work/state/docker.log"; }
runs() { grep -E '^config=.* \| run ' "$work/state/docker.log" || true; }
no_trace() {
  [[ ! -s "$work/output" && ! -e "$work/host-executed" \
    && -z "$(find "$work/runner" -mindepth 1 -print -quit)" ]]
}

# The exact Harbor image: pulled with the pull robot, the robot gone before
# any image code runs, both modes run, and only then the digest is reported.
[[ "$(run_case -- "$REF" "$REVISION" "$contract")" == ok ]] || { cat "$work/out" >&2; fail 'a passing contract failed'; }
[[ "$(cat "$work/state/fetch.log")" == "--pull $work/runner/codewire-workspace-contract."*"/harbor-username $work/runner/codewire-workspace-contract."*"/harbor-password" ]] ||
  fail 'the runner did not read exactly the pull-only Harbor robot into its private directory'
login_config="$(cat "$work/state/login-config")"
[[ "$login_config" == "$work/runner/codewire-workspace-contract."*/docker-config ]] ||
  fail 'the pull robot was not kept in a private Docker configuration'
[[ "$(cat "$work/state/pull-config")" == "$login_config" ]] ||
  fail 'the image was not pulled with the private Docker configuration'
expected_calls="$(printf '%s\n' \
  " image inspect $REF" \
  " login registry.example.invalid --username robot\\\$codewire+pull --password-stdin" \
  " pull --quiet $REF" \
  " image inspect $REF" \
  " run --rm --interactive --pull=never --pids-limit=2048 --name codewire-workspace-contract-PID-full --user 1000:1000 --entrypoint bash $IMAGE_ID -eu -s" \
  " run --rm --interactive --pull=never --pids-limit=2048 --name codewire-workspace-contract-PID-mounted-home --user 1000:1000 --tmpfs /home/codewire:rw\\,exec\\,uid=1000\\,gid=1000\\,mode=0700\\,size=256m --entrypoint bash $IMAGE_ID -eu -s -- --mounted-home-agents" \
  " rm --force codewire-workspace-contract-PID-full" \
  " rm --force codewire-workspace-contract-PID-mounted-home" \
  " image rm $REF")"
actual_calls="$(docker_calls | sed -E 's/codewire-workspace-contract-[0-9]+-/codewire-workspace-contract-PID-/')"
[[ "$actual_calls" == "$expected_calls" ]] || {
  diff <(printf '%s\n' "$expected_calls") <(printf '%s\n' "$actual_calls") >&2 || true
  fail 'the runner did not pull, check and run both contract modes exactly'
}
[[ "$(grep -c ' present=no | run ' "$work/state/docker.log")" -eq 2 \
  && "$(runs | grep -c ' present=yes ')" -eq 0 ]] ||
  fail 'the pull robot'"'"'s Docker configuration still existed when image code ran'
# Only the Docker options before the image are judged; the contract's own
# arguments follow it.
while read -r -a words; do
  for word in "${words[@]}"; do
    [[ "$word" != "$IMAGE_ID" ]] || break
    case "$word" in
      -v|-v*|--volume|--volume=*|--volumes-from*|--mount|--mount=*|-e|-e*|--env|--env=*|--env-file*|\
      --privileged*|--network*|--net|--net=*|--cap-add*|--device*|--security-opt*|--ipc*|--pid|--pid=*|\
      --userns*|-w|-w*|--workdir*|--group-add*)
        fail "a contract container received $word" ;;
    esac
  done
done < <(runs | cut -d'|' -f2-)
cmp -s "$contract" "$work/state/stdin.1" && cmp -s "$contract" "$work/state/stdin.2" ||
  fail 'the contract was not streamed into both containers on stdin'
[[ ! -e "$work/host-executed" ]] || fail 'the contract ran on the host'
[[ "$(cat "$work/output")" == "workspace_digest=$DIGEST" ]] ||
  fail 'a passing contract did not report exactly the image digest'
[[ -z "$(find "$work/runner" -mindepth 1 -print -quit)" ]] ||
  fail 'the runner left its private directory or credential behind'

# Without GITHUB_OUTPUT the digest is printed instead.
[[ "$(run_case GITHUB_OUTPUT= -- "$REF" "$REVISION" "$contract")" == ok ]] &&
  grep -qxF "workspace_digest=$DIGEST" "$work/out" || fail 'the digest is not printed without GITHUB_OUTPUT'

# Only one exact Harbor workspace digest is accepted, before any credential
# or Docker call.
for bad_ref in 'registry.example.invalid/codewire/workspace:main' "registry.example.invalid/codewire/workspace:$REVISION" \
    "registry.example.invalid/codewire/workspace:main@$DIGEST" "$GHCR_REF" "docker.io/codewiresh/workspace@$DIGEST" \
    "registry.example.invalid/codewire/base@$DIGEST" "registry.example.invalid/codewire/workspace@sha256:abc" \
    "registry.example.invalid/codewire/workspace@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" " $REF" "$REF " \
    "registry.example.invalid.evil.example/codewire/workspace@$DIGEST"; do
  [[ "$(run_case -- "$bad_ref" "$REVISION" "$contract")" == 'failed 1' ]] ||
    fail "the runner accepted the reference: $bad_ref"
  [[ ! -s "$work/state/docker.log" && ! -s "$work/state/fetch.log" ]] && no_trace ||
    fail "a refused reference reached Docker or the credential: $bad_ref"
done
for bad_revision in '' main "${REVISION:0:12}" "${REVISION^^}"; do
  [[ "$(run_case -- "$REF" "$bad_revision" "$contract")" == 'failed 1' && ! -s "$work/state/docker.log" ]] ||
    fail "the runner accepted the expected revision: '$bad_revision'"
done
ln -s "$contract" "$work/contract-link"
for bad_contract in "$work/contract-link" "$work/missing.sh" "$work"; do
  [[ "$(run_case -- "$REF" "$REVISION" "$bad_contract")" == 'failed 1' && ! -s "$work/state/docker.log" ]] ||
    fail "the runner accepted the contract path: $bad_contract"
done
for bad_args in '' "$REF $REVISION" "$REF $REVISION $contract extra" "--source harbor $REF $REVISION $contract" \
    "--source $REF $REVISION $contract"; do
  read -r -a args <<<"$bad_args"
  [[ "$(run_case -- "${args[@]}")" == 'failed 2' && ! -s "$work/state/docker.log" ]] ||
    fail "the runner accepted the arguments: $bad_args"
done

# The image must be exactly the pulled reference, linux/amd64, at the revision.
for mismatch in "FAKE_REPO_DIGEST=registry.example.invalid/codewire/workspace@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|recorded as exactly" \
    'FAKE_ARCH=arm64|not linux/amd64' 'FAKE_OS=windows|not linux/amd64' \
    'FAKE_LABEL=fedcba9876543210fedcba9876543210fedcba98|revision label' 'FAKE_LABEL=|revision label' \
    'FAKE_IMAGE_ID=sha256:short|no exact local image ID'; do
  [[ "$(run_case "${mismatch%%|*}" -- "$REF" "$REVISION" "$contract")" == 'failed 1' ]] ||
    fail "the runner accepted an image with ${mismatch%%|*}"
  grep -qF "${mismatch#*|}" "$work/out" || { cat "$work/out" >&2; fail "unexplained refusal: ${mismatch%%|*}"; }
  [[ -z "$(runs)" ]] && no_trace || fail "an image with ${mismatch%%|*} ran or reported a digest"
done

# A failing contract mode fails the runner and reports nothing.
for mode in full mounted-home; do
  [[ "$(run_case FAKE_RUN_FAIL="$mode" -- "$REF" "$REVISION" "$contract")" == 'failed 1' ]] ||
    fail "a failing $mode contract passed"
  grep -qF "the $mode workspace contract failed" "$work/out" || fail "the failing $mode contract is not named"
  no_trace || fail "a failing $mode contract reported a digest or left state behind"
done
[[ "$(runs | wc -l)" -eq 2 ]] || fail 'the mounted-home contract did not follow the full contract'

# Credential and registry failures fail closed, without running image code and
# without leaving the robot behind.
[[ "$(run_case FAKE_FETCH=fail -- "$REF" "$REVISION" "$contract")" == 'failed 1' && ! -s "$work/state/login-config" ]] &&
  [[ -z "$(runs)" ]] && no_trace || fail 'an unreadable pull credential did not fail closed'
[[ "$(run_case FAKE_LOGIN=fail -- "$REF" "$REVISION" "$contract")" == 'failed 1' && -z "$(runs)" ]] && no_trace ||
  fail 'a refused pull robot did not fail closed'
[[ "$(run_case FAKE_PULL=fail -- "$REF" "$REVISION" "$contract")" == 'failed 1' && -z "$(runs)" ]] && no_trace ||
  fail 'an unpullable image did not fail closed'
[[ "$(grep -c ' | pull ' "$work/state/docker.log")" -eq 3 && "$(cat "$work/state/sleep.log")" == $'10\n20' ]] ||
  fail 'the pull is not attempted three times with a backoff'
[[ ! -e "$(cat "$work/state/login-config")" ]] || fail 'a failed pull left the pull robot behind'

# An image the run did not bring stays in place.
[[ "$(run_case FAKE_PRESENT=yes -- "$REF" "$REVISION" "$contract")" == ok ]] ||
  fail 'a contract on an already present image failed'
if grep -qF ' | image rm ' "$work/state/docker.log"; then
  fail 'the runner removed an image it did not pull'
fi

# The local-only GHCR source pulls the same digest anonymously and checks it
# under that reference; CI refuses it.
[[ "$(run_case -- --source ghcr "$REF" "$REVISION" "$contract")" == ok ]] || { cat "$work/out" >&2; fail 'a local GHCR run failed'; }
[[ ! -s "$work/state/fetch.log" && ! -e "$work/state/login-config" ]] ||
  fail 'a local GHCR run read a credential'
pull_config="$(cat "$work/state/pull-config")"
[[ "$pull_config" == "$work/runner/codewire-workspace-contract."*/docker-config && ! -e "$pull_config" ]] ||
  fail 'a local GHCR run did not pull with an empty private Docker configuration'
grep -qF " | pull --quiet $GHCR_REF" "$work/state/docker.log" && [[ "$(runs | wc -l)" -eq 2 ]] ||
  fail 'a local GHCR run did not pull the same digest from the mirror and run both modes'
[[ "$(cat "$work/output")" == "workspace_digest=$DIGEST" ]] || fail 'a local GHCR run did not report the digest'
[[ "$(run_case FAKE_REPO_DIGEST="$REF" -- --source ghcr "$REF" "$REVISION" "$contract")" == 'failed 1' && -z "$(runs)" ]] ||
  fail 'a local GHCR run accepted an image not recorded under the mirror reference'
for ci in GITHUB_ACTIONS=true FORGEJO_ACTIONS=true GITEA_ACTIONS=true; do
  [[ "$(run_case "$ci" -- --source ghcr "$REF" "$REVISION" "$contract")" == 'failed 1' && ! -s "$work/state/docker.log" ]] ||
    fail "the GHCR source was accepted under $ci"
done
[[ "$(run_case -- --source ghcr "$GHCR_REF" "$REVISION" "$contract")" == 'failed 1' && ! -s "$work/state/docker.log" ]] ||
  fail 'the GHCR source accepted a non-Harbor reference'

echo 'workspace contract runner: OK'
