#!/usr/bin/env bash
# run-family.sh JOB [--placement main|pr] [options] [COMMIT]
#
# Run one ci.yaml job (policy, tooling, ...) on this machine as CI runs it:
# the job's own steps, in the CI runner image, with CI's environment, at
# COMMIT (default HEAD). CI's own call does not change; this reads what CI
# reads, so a CI-only failure shows up here first.
#
# Where each part comes from (ci-job-plan.py has the detail):
# - the steps, the workflow and job env, runs-on and the timeout: ci.yaml at
#   COMMIT;
# - the Actions variables: `fj actions variables list` (never secrets);
# - the runner the placement reaches (main: a push to main; pr: a pull
#   request), its envs (CODEWIRE_CI_CPU_SHARE), container options, image
#   digest and memory limit: infra's forgejo-runners config at --infra-ref;
# - the selection: the selector at COMMIT (on pr, the base's selector), as
#   the selection step runs it, unless --selection names one;
# - what steps write to GITHUB_ENV (bound-cargo-jobs.sh): the steps
#   themselves, run in order.
#
# Options:
#   --placement main|pr   which runner and event (default pr)
#   --selection SEL       use this selection instead of computing it
#   --base SHA            pr: the base (default merge-base with origin/main);
#                         main: the verified main commit to select from
#                         (default none: the selector selects everything, as
#                         main does when its base is unverified)
#   --infra DIR           the infra checkout (default: CODEWIRE_INFRA_DIR, or
#                         infra beside this repository's canonical checkout)
#   --infra-ref REF       infra revision to read (default origin/main)
#   --no-fetch            do not fetch origin in either repository first
#   --explain             print the runner and job environment; run nothing
#   --cargo-cache VOLUME  keep the job's Cargo home (/root/.cargo) in the named
#                         Docker volume across runs, so Cargo's registry and Git
#                         sources are fetched once, not every run
#   --timeout-scale N     run with N times the job's timeout-minutes (1 to 99),
#                         for a machine slower or busier than CI's runner
#
# Known differences from a CI job, by design: no job token (steps that need
# GITHUB_TOKEN or a secret cannot pass here), empty caches where the runner
# binds a host cache (and, with --cargo-cache, a warm Cargo home where CI's is
# empty), this machine's CPUs and network, and no Docker socket.
#
# Prints each step as `[run-family] step STEP: passed|failed in Ns`, then the job's wall
# time; exits with 1 when a step failed, 2 on a usage or planning error.
set -euo pipefail

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$TOOL_DIR" rev-parse --show-toplevel)"
readonly TOOL_DIR REPO
readonly RUNNER_FILES=(dispatcher.py metal-inventory.json ephemeral-ci.yaml warm-vms.yaml)
readonly NOFILE=1048576 # Forgejo Runner's job containers; Docker's default 1024 fails Policy.

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2
  exit 2
}
die() {
  printf 'run-family: %s\n' "$*" >&2
  exit 2
}

job='' placement=pr selection='' base='' commit=HEAD explain=false fetch=true
infra="${CODEWIRE_INFRA_DIR:-}" infra_ref=origin/main cargo_cache='' timeout_scale=1
while [ $# -gt 0 ]; do
  case "$1" in
    --placement) placement="${2:?}"; shift 2 ;;
    --cargo-cache) cargo_cache="${2:?}"; shift 2 ;;
    --timeout-scale) timeout_scale="${2:?}"; shift 2 ;;
    --selection) selection="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    --infra) infra="${2:?}"; shift 2 ;;
    --infra-ref) infra_ref="${2:?}"; shift 2 ;;
    --no-fetch) fetch=false; shift ;;
    --explain) explain=true; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option $1" ;;
    *) if [ -z "$job" ]; then job="$1"; else commit="$1"; fi; shift ;;
  esac
done
[ -n "$job" ] || usage
case "$placement" in main|pr) ;; *) die "--placement is main or pr" ;; esac
for tool in docker fj git python3; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

common_dir="$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)"
if [ -z "$infra" ]; then
  infra="$(dirname "$common_dir")/../infra"
fi
[ -d "$infra" ] || die "no infra checkout at $infra; pass --infra or set CODEWIRE_INFRA_DIR"

if $fetch; then
  git -C "$REPO" fetch -q origin
  git -C "$infra" fetch -q origin
fi
commit="$(git -C "$REPO" rev-parse --verify "$commit^{commit}")"
infra_commit="$(git -C "$infra" rev-parse --verify "$infra_ref^{commit}")"
branch="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
if [ "$placement" = pr ] && [ -z "$base" ]; then
  base="$(git -C "$REPO" merge-base origin/main "$commit")"
fi
[ -z "$base" ] || base="$(git -C "$REPO" rev-parse --verify "$base^{commit}")"

work="$(mktemp -d "${TMPDIR:-/tmp}/run-family.XXXXXX")"
plan="$work/plan"
mkdir -p "$work/infra/forgejo-runners" "$plan"
volume=''
container=''
cleanup() {
  [ -z "$container" ] || docker rm -f "$container" >/dev/null 2>&1 || true
  [ -z "$volume" ] || docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

git -C "$REPO" show "$commit:.gitea/workflows/ci.yaml" >"$work/ci.yaml"
# The one cluster that runs the Forgejo runners; this tree does not name it.
mapfile -t runner_dirs < <(git -C "$infra" ls-tree -d --name-only "$infra_commit" clusters/ |
  while IFS= read -r cluster; do
    git -C "$infra" cat-file -e "$infra_commit:$cluster/infrastructure/forgejo-runners" 2>/dev/null &&
      printf '%s/infrastructure/forgejo-runners\n' "$cluster"
  done)
[ "${#runner_dirs[@]}" -eq 1 ] || {
  printf '[run-family] ERROR: the infrastructure commit has %d forgejo-runners directories; expected one\n' "${#runner_dirs[@]}" >&2
  exit 2
}
for file in "${RUNNER_FILES[@]}"; do
  git -C "$infra" show "$infra_commit:${runner_dirs[0]}/$file" >"$work/infra/forgejo-runners/$file"
done
# Every warm VM's manifest, by the name warm-vms.yaml gives it: the machines are
# named by page (infra#2151), so this tree names none of them.
mapfile -t warm_files < <(python3 -I -c 'import sys, yaml
listing = yaml.safe_load(open(sys.argv[1])) or {}
print("\n".join(sorted({vm["file"] for vm in (listing.get("vms") or {}).values()})))' \
  "$work/infra/forgejo-runners/warm-vms.yaml")
[ "${#warm_files[@]}" -gt 0 ] || die "infra's warm-vms.yaml lists no warm VM"
for file in "${warm_files[@]}"; do
  [[ "$file" =~ ^[a-z0-9-]+\.yaml$ ]] || die "unexpected warm VM file name: $file"
  git -C "$infra" show "$infra_commit:${runner_dirs[0]}/$file" >"$work/infra/forgejo-runners/$file"
done
# Variables only. `fj actions variables list` cannot print a secret.
(cd "$REPO" && fj actions variables list -R origin) </dev/null >"$work/variables"

plan_args=(--workflow "$work/ci.yaml" --job "$job" --placement "$placement"
  --variables "$work/variables" --infra "$work/infra" --commit "$commit" --base "$base" --branch "$branch")
runner="$(python3 -I -B "$TOOL_DIR/ci-job-plan.py" runner "${plan_args[@]}" \
  --cargo-cache "$cargo_cache" --timeout-scale "$timeout_scale")" || exit 2
field() { python3 -I -c 'import json,sys; v=json.loads(sys.argv[1])[sys.argv[2]]; print("\n".join(v) if isinstance(v, list) else v)' "$runner" "$1"; }
image="$(field image)"
label="$(field label)"
memory="$(field memory)"
timeout_minutes="$(field timeout_minutes)"
mapfile -t options < <(field docker_options)
mapfile -t notes < <(field notes)

printf 'run-family: %s at %s, placement %s\n' "$job" "$commit" "$placement"
printf '  runner:  %s (%s, infra %s)\n' "$label" "$(field source)" "${infra_commit:0:12}"
printf '  image:   %s\n' "$image"
printf '  options: --ulimit nofile=%s %s%s\n' "$NOFILE" "${options[*]}" "${memory:+ --memory $memory}"
for note in "${notes[@]}"; do [ -z "$note" ] || printf '  note:    %s\n' "$note"; done

docker_memory=()
if [ -n "$memory" ]; then
  case "$memory" in
    *Mi) docker_memory=(--memory "${memory%Mi}m") ;;
    *Gi) docker_memory=(--memory "${memory%Gi}g") ;;
    *) die "unexpected memory limit $memory" ;;
  esac
fi

printf '%s\n' "$commit" >"$plan/commit"
printf '%s\n' "$base" >"$plan/base"
printf '%s\n' "$placement" >"$plan/placement"
: >"$plan/dispatch"
field origin_url >"$plan/origin-url"

# run_phase PHASE SECONDS: one container on the runner image. A timed-out
# docker client leaves its container running; cleanup removes it by name.
run_phase() {
  local phase="$1" seconds="$2"
  container="run-family-$$-$phase"
  timeout --kill-after=30 "$seconds" docker run --rm --name "$container" --ulimit "nofile=$NOFILE:$NOFILE" \
    "${options[@]}" "${docker_memory[@]}" \
    -v "$volume:/workspace" \
    -v "$common_dir:/run/run-family/source.git:ro" \
    -v "$TOOL_DIR:/run/run-family/tool:ro" \
    -v "$plan:/run/run-family/plan" \
    -w /workspace --entrypoint bash \
    "$image" /run/run-family/tool/run-job-steps.sh "$phase" </dev/null
}

if ! $explain; then
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
  volume="run-family-$$"
  docker volume create "$volume" >/dev/null
  if [ -n "$cargo_cache" ]; then
    # The planner mounts the cache at /root/.cargo: only a root image keeps its
    # Cargo home there.
    user="$(docker image inspect --format '{{.Config.User}}' "$image")"
    case "$user" in ''|root|0|0:0) ;; *) die "--cargo-cache needs an image that runs as root; $image runs as $user" ;; esac
    docker volume create "$cargo_cache" >/dev/null
  fi
fi

[ -z "$selection" ] || printf '%s\n' "$selection" >"$plan/selection"
if $explain && [ -z "$selection" ]; then
  printf '(computed by the selector at run time)\n' >"$plan/selection"
  : >"$plan/dispatch"
elif ! $explain; then
  run_phase select 600 >"$work/select.log" 2>&1 || { cat "$work/select.log" >&2; die "the selector failed"; }
fi
selection="$(cat "$plan/selection")"
printf '  selection: %s\n' "$selection"

python3 -I -B "$TOOL_DIR/ci-job-plan.py" job "${plan_args[@]}" --selection "$selection" \
  --dispatch "$plan/dispatch" --out "$plan" || exit 2
if [ "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected"])' "$plan/job.json")" != True ]; then
  printf '  note:    CI would not start this job for this selection (its if is false); running its steps anyway\n'
fi

if $explain; then
  printf '\nJob environment before its steps (later: GITHUB_ENV writes, then each step env):\n'
  sed 's/^export /  /' "$plan/job.env"
  printf '\nSteps (number, runs while green, runs after a failure, name):\n'
  sed 's/^/  /' "$plan/steps.tsv"
  exit 0
fi

start=$SECONDS
rc=0
run_phase steps "$((timeout_minutes * 60))" || rc=$?
elapsed=$((SECONDS - start))
printf 'run-family: %s %s at %s on %s in %ss\n' "$job" "$([ "$rc" -eq 0 ] && echo passed || echo failed)" \
  "${commit:0:12}" "$placement" "$elapsed"
[ "$rc" -eq 0 ] || exit 1
