# shellcheck shell=bash
# The trusted BuildKit builder (infra docs/runbooks/ci-buildkit-trusted.md,
# infra#1534): one persistent builder in the system cluster with its own
# layer cache, which builds what Codewire ships. Only protected jobs reach it,
# over mutual TLS, with the client certificate that only the three publisher
# roles and the two release builds (#3119) read from OpenBao. When it cannot be
# reached the build fails: it never
# falls back to building in the job on its own. The owner's explicit recovery,
# CODEWIRE_IN_JOB_BUILD=1, is the one way to build in the job instead.
#
# Callers set ROOT and source this file.

readonly TRUSTED_BUILDKIT_HOST='ams3-1-trusted-builder-large-0.forgejo-ci-builder.svc.cluster.local'
readonly TRUSTED_BUILDKIT_ENDPOINT="tcp://$TRUSTED_BUILDKIT_HOST:1234"
# Cargo jobs per build step. The builder's guest is 16 GiB and runs two build
# steps at once (infra's ci-buildkit/builder.yaml: max-parallelism 2,
# infra#1534), sized for two Linux release compiles of 8 jobs each (8.47 GiB
# together). At 14 jobs a step, buildkitd's cgroup sat at 93-94.5% of 16 GiB
# with 10,837 socket-memory throttles, and the Dockerfile frontend's gRPC
# dropped under two concurrent steps (Dev deliveries 45596, 45607, 46581;
# infra#1534, 2026-11-13). More jobs need more guest memory, not this value.
readonly TRUSTED_BUILDKIT_CARGO_BUILD_JOBS=8
# The static CW producer sizes its own Cargo jobs from the machine it runs on
# (finalize-cw-runtime-source.py, 3 GiB per job), and the job that verifies its
# receipt recomputes that exact command. On a remote builder those machines
# differ, so the job pins the count both sides use: the same 8 as every other
# build step, since it runs beside one. Fewer jobs also hold each optimized
# Codewire crate to fewer codegen units, so the cw compile is slower (579 s at
# 7, support-images run 22393); a faster one needs a bigger guest.
readonly TRUSTED_BUILDKIT_CW_PRODUCER_JOBS=8
# deploy-dev.yaml and support-images.yaml pass no artifacts between jobs, and
# a failed half cancels its run, so the recovery reruns the whole run.
readonly TRUSTED_BUILDKIT_RECOVERY='after checking the builder (infra docs/runbooks/ci-buildkit-trusted.md), the owner may build this commit in the job: set the repository variable CODEWIRE_IN_JOB_BUILD_SHA to this commit and rerun all jobs of this run, or dispatch deploy-prod.yaml with in_job_build'

# Succeeds when the owner asked this run to build in the job.
trusted_buildkit_in_job() {
  case "${CODEWIRE_IN_JOB_BUILD:-0}" in
    0) return 1 ;;
    1)
      printf '::warning::building in the job instead of on the trusted BuildKit builder: the owner-invoked recovery path\n' >&2
      return 0
      ;;
    *)
      printf 'CODEWIRE_IN_JOB_BUILD must be exactly 0 or 1\n' >&2
      exit 2
      ;;
  esac
}

# trusted_buildkit_attach NAME DOCKER_CONFIG TLS_DIR
# Read the client tuple into the empty private directory TLS_DIR, create the
# remote Buildx builder NAME in DOCKER_CONFIG, and prove it answers as a
# running linux/amd64 builder. Removing NAME later only forgets it locally.
trusted_buildkit_attach() {
  local name="$1" docker_config="$2" tls="$3" inspect
  "${TRUSTED_BUILDKIT_CLIENT_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-trusted-buildkit-client.sh}" "$tls" >&2 || {
    printf '::error::the trusted BuildKit client certificate could not be read; protected builds do not fall back to building in the job (%s)\n' \
      "$TRUSTED_BUILDKIT_RECOVERY" >&2
    return 1
  }
  DOCKER_CONFIG="$docker_config" docker buildx create --name "$name" \
    --driver remote --platform linux/amd64 \
    --driver-opt "cacert=$tls/ca.crt,cert=$tls/client.crt,key=$tls/client.key,servername=$TRUSTED_BUILDKIT_HOST" \
    "$TRUSTED_BUILDKIT_ENDPOINT" >/dev/null || return 1
  if ! inspect="$(DOCKER_CONFIG="$docker_config" timeout 60 \
      docker buildx inspect "$name" --bootstrap 2>&1)" \
      || ! grep -Eq '^Status: +running$' <<<"$inspect" \
      || ! grep -Eq '^Platforms: .*linux/amd64' <<<"$inspect"; then
    printf '::error::the trusted BuildKit builder %s did not answer as a running linux/amd64 builder; protected builds do not fall back to building in the job (%s)\n' \
      "$TRUSTED_BUILDKIT_ENDPOINT" "$TRUSTED_BUILDKIT_RECOVERY" >&2
    return 1
  fi
  # Every build on it bounds Cargo's jobs; the CW producer and its verifier
  # share one explicit count.
  export CODEWIRE_CARGO_BUILD_JOBS="$TRUSTED_BUILDKIT_CARGO_BUILD_JOBS"
  export CODEWIRE_CARGO_JOBS="$TRUSTED_BUILDKIT_CW_PRODUCER_JOBS"
  printf 'Attached the trusted BuildKit builder %s (Cargo jobs %s)\n' \
    "$TRUSTED_BUILDKIT_ENDPOINT" "$TRUSTED_BUILDKIT_CARGO_BUILD_JOBS" >&2
}
