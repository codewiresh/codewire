#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SMOKE_DIR="$ROOT/deployments/k8s/runtime-profiles/confidential-smoke"
KUSTOMIZATION="$SMOKE_DIR/kustomization.confidential-snp.yaml"
RUNTIME_CONTRACT="$ROOT/deployments/k8s/runtime-profiles/policy/genpolicy-runtime-contract.json"
ANNOTATION='io.katacontainers.config.hypervisor.cc_init_data'
EXPECTED_KATA_COMMIT='b81c0f2db867caddbe98e660e0ccccc9c420b6f8'
POD_NAME_SUFFIX='[bcdfghjklmnpqrstvwxz2456789]+'

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/generate-confidential-probe-initdata.sh update KATA_SOURCE GENERATION
  scripts/runtime/confidential/generate-confidential-probe-initdata.sh verify KATA_SOURCE

Generates the two static confidential probe policies with genpolicy from the
exact accepted Kata downstream source. `update` takes one generation such as
v73 and writes all three probe Job names plus both generated cc_init_data
annotations. `verify` regenerates and compares without changing the source
manifests.

KATA_GENPOLICY_BIN may select an exact-head genpolicy executable. Otherwise
the script checks the usual host debug and release output paths.
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

mode="${1:-}"
kata_root="${2:-}"
generation="${3:-}"
[[ "$mode" == update || "$mode" == verify ]] || {
  usage >&2
  exit 2
}
if [[ "$mode" == update ]]; then
  [[ "$generation" =~ ^v[1-9][0-9]*$ ]] || \
    die 'update requires one generation matching v[1-9][0-9]*'
else
  [[ -z "$generation" ]] || die 'verify does not accept a generation argument'
fi
[[ -z "${4:-}" ]] || die 'too many arguments'
[[ -n "$kata_root" && -e "$kata_root/.git" ]] || die 'KATA_SOURCE must be a Kata git worktree'

for command in base64 git gzip install jq rg sed sort timeout yq; do
  require_cmd "$command"
done

kata_head="$(git -C "$kata_root" rev-parse HEAD)"
[[ "$kata_head" == "$EXPECTED_KATA_COMMIT" ]] || \
  die "Kata source is $kata_head, expected $EXPECTED_KATA_COMMIT"
git -C "$kata_root" diff --quiet --ignore-submodules -- || die 'Kata source has tracked unstaged changes'
git -C "$kata_root" diff --cached --quiet --ignore-submodules -- || die 'Kata source has tracked staged changes'

rules="$kata_root/src/tools/genpolicy/rules.rego"
base_settings="$kata_root/src/tools/genpolicy/genpolicy-settings.json"
[[ -f "$rules" && -f "$base_settings" ]] || die 'Kata source is missing genpolicy rules or settings'
[[ -f "$RUNTIME_CONTRACT" ]] || die 'Codewire genpolicy runtime contract is missing'

[[ "$(jq -er '.schemaVersion' "$RUNTIME_CONTRACT")" == 2 ]] || \
  die 'Codewire genpolicy runtime contract has an unsupported schema'
oci_version="$(jq -er '.ociVersion' "$RUNTIME_CONTRACT")"
settings_drop_in_name="$(jq -er '.kataSettingsDropIn' "$RUNTIME_CONTRACT")"
privileged_caps_provider="$(jq -er '.privilegedCapabilities.provider' "$RUNTIME_CONTRACT")"
privileged_caps_source_commit="$(jq -er '.privilegedCapabilities.sourceCommit' "$RUNTIME_CONTRACT")"
dropped_privileged_caps="$(jq -cer '
  .privilegedCapabilities.drop |
  if type == "array" and length > 0 and length == (unique | length) and
     all(.[]; test("^CAP_[A-Z0-9_]+$"))
  then sort
  else error("invalid privileged capability drop set")
  end
' "$RUNTIME_CONTRACT")"
[[ "$oci_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Codewire OCI version is malformed'
[[ "$settings_drop_in_name" =~ ^[A-Za-z0-9._-]+\.json$ ]] || \
  die 'Codewire Kata settings drop-in name is malformed'
[[ "$privileged_caps_provider" == talos ]] || \
  die 'Codewire privileged capability provider must be Talos'
[[ "$privileged_caps_source_commit" =~ ^[0-9a-f]{40}$ ]] || \
  die 'Codewire Talos capability source commit is malformed'
settings_drop_in="$kata_root/src/tools/genpolicy/drop-in-examples/$settings_drop_in_name"
[[ -f "$settings_drop_in" ]] || die "Kata source is missing settings drop-in $settings_drop_in_name"
[[ "$(jq -er '
  [.[] | select(
    .op == "replace" and
    .path == "/kata_config/oci_version"
  ) | .value] | if length == 1 then .[0] else error("invalid OCI drop-in") end
' "$settings_drop_in")" == "$oci_version" ]] || \
  die 'Kata settings drop-in does not match the Codewire OCI contract'

base_privileged_caps="$(jq -cer '
  .common.privileged_caps |
  if type == "array" and length > 0 and length == (unique | length) and
     all(.[]; test("^CAP_[A-Z0-9_]+$"))
  then .
  else error("invalid Kata privileged capability set")
  end
' "$base_settings")"
unknown_dropped_caps="$(
  jq -cn \
    --argjson base "$base_privileged_caps" \
    --argjson dropped "$dropped_privileged_caps" \
    '$dropped - $base'
)"
[[ "$unknown_dropped_caps" == '[]' ]] || \
  die "Codewire drops capabilities absent from Kata settings: $unknown_dropped_caps"
privileged_caps="$(
  jq -cn \
    --argjson base "$base_privileged_caps" \
    --argjson dropped "$dropped_privileged_caps" \
    '$base - $dropped'
)"
[[ "$(jq -nr --argjson caps "$privileged_caps" '$caps | length')" -gt 0 ]] || \
  die 'Codewire Talos privileged capability set is empty'

genpolicy_bin="${KATA_GENPOLICY_BIN:-}"
if [[ -z "$genpolicy_bin" ]]; then
  for candidate in \
    "$kata_root/target/x86_64-unknown-linux-gnu/debug/genpolicy" \
    "$kata_root/target/x86_64-unknown-linux-gnu/release/genpolicy" \
    "$kata_root/target/debug/genpolicy" \
    "$kata_root/target/release/genpolicy"; do
    if [[ -x "$candidate" ]]; then
      genpolicy_bin="$candidate"
      break
    fi
  done
fi
[[ -n "$genpolicy_bin" && -x "$genpolicy_bin" ]] || \
  die 'exact-head genpolicy binary not found; build it from KATA_SOURCE first'

version_output="$($genpolicy_bin -p "$rules" -j "$base_settings" -v)"
embedded_commit="${version_output##*commit: }"
[[ "$embedded_commit" == "$kata_head" ]] || \
  die "genpolicy reports $embedded_commit, but Kata source is $kata_head; regenerate src/version.rs and rebuild"

probe_digest="$(yq -er '.images[] | select(.name == "ghcr.io/codewiresh/confidential-probe") | .digest' "$KUSTOMIZATION")"
probe_repository="$(yq -er '.images[] | select(.name == "ghcr.io/codewiresh/confidential-probe") | .newName' "$KUSTOMIZATION")"
[[ "$probe_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'confidential probe digest is not immutable'
probe_image="$probe_repository@$probe_digest"

commodity_manifest="$SMOKE_DIR/commodity-smoke-job.yaml"
runtime_manifest="$SMOKE_DIR/confidential-smoke-job.yaml"
attestation_manifest="$SMOKE_DIR/confidential-attestation-job.yaml"
current_commodity_job_name="$(yq -er '.metadata.name' "$commodity_manifest")"
current_runtime_job_name="$(yq -er '.metadata.name' "$runtime_manifest")"
current_attestation_job_name="$(yq -er '.metadata.name' "$attestation_manifest")"
[[ "$current_commodity_job_name" =~ ^codewire-commodity-runtime-smoke-(v[1-9][0-9]*)$ ]] || \
  die 'commodity probe Job name has an invalid generation'
current_generation="${BASH_REMATCH[1]}"
[[ "$current_runtime_job_name" == "codewire-confidential-runtime-smoke-$current_generation" ]] || \
  die 'confidential runtime probe generation does not match the commodity probe'
[[ "$current_attestation_job_name" == "codewire-confidential-snp-attestation-$current_generation" ]] || \
  die 'confidential attestation probe generation does not match the commodity probe'
if [[ "$mode" == verify ]]; then
  generation="$current_generation"
  commodity_job_name="$current_commodity_job_name"
  runtime_job_name="$current_runtime_job_name"
  attestation_job_name="$current_attestation_job_name"
else
  expected_generation="v$((10#${current_generation#v} + 1))"
  [[ "$generation" == "$expected_generation" ]] || \
    die "update generation must be the exact successor $expected_generation"
  commodity_job_name="codewire-commodity-runtime-smoke-$generation"
  runtime_job_name="codewire-confidential-runtime-smoke-$generation"
  attestation_job_name="codewire-confidential-snp-attestation-$generation"
fi

umask 077
mkdir -p "$ROOT/.tmp"
workdir="$(mktemp -d "$ROOT/.tmp/confidential-probe-genpolicy.XXXXXX")"
chmod 0700 "$workdir"
mkdir -p "$workdir/docker-config"
settings="$workdir/genpolicy-settings"
mkdir -p "$settings/genpolicy-settings.d"
install -m 0600 "$base_settings" "$settings/genpolicy-settings.json"
install -m 0600 "$settings_drop_in" "$settings/genpolicy-settings.d/$settings_drop_in_name"
jq -n \
  --argjson capabilities "$privileged_caps" \
  '[{"op":"replace","path":"/common/privileged_caps","value":$capabilities}]' \
  >"$settings/genpolicy-settings.d/30-talos-privileged-capabilities.json"
# The static probes are observed through the Kubernetes CRI log path after
# completion. Kata services that path with ReadStreamRequest, independently of
# the container's successful CreateContainer/WaitProcess lifecycle. Permit
# stdout reads for these disposable one-container probe VMs while retaining the
# base policy's deny defaults for stdin writes and closes.
jq -n \
  '[{"op":"replace","path":"/request_defaults/ReadStreamRequest","value":true}]' \
  >"$settings/genpolicy-settings.d/40-probe-read-stream.json"
# Both inputs are public and digest-pinned. Do not let the generator consult
# ambient registry credentials merely because the workstation has a global
# Docker credential helper configured.
printf '{}\n' >"$workdir/docker-config/config.json"
cleanup() {
  rm -rf -- "$workdir"
}
trap cleanup EXIT

generate_one() {
  local source_manifest="$1"
  local container_name="$2"
  local unsupported_run_as_non_root="$3"
  local job_name="$4"
  local encoded_output="$5"
  local input decoded policy
  local encoded current expected_sandbox_name policy_oci_versions policy_privileged_caps
  local policy_request_defaults policy_sandbox_names

  input="$workdir/$(basename "$source_manifest")"
  decoded="$input.initdata.toml"
  policy="$input.policy.rego"

  [[ "$(yq -er '.spec.template.spec.automountServiceAccountToken' "$source_manifest")" == false ]] || \
    die "$(basename "$source_manifest") must disable service-account token mounting"
  if [[ "$unsupported_run_as_non_root" == true ]]; then
    [[ "$(yq -er '.spec.template.spec.containers[0].securityContext.runAsNonRoot' "$source_manifest")" == true ]] || \
      die "$(basename "$source_manifest") must keep runAsNonRoot=true"
  fi

  cp "$source_manifest" "$input"
  JOB_NAME="$job_name" yq -i \
    'del(.spec.template.spec.automountServiceAccountToken) |
     del(.spec.template.spec.containers[0].securityContext.runAsNonRoot) |
     del(.spec.template.metadata.annotations."io.katacontainers.config.hypervisor.cc_init_data") |
     .metadata.name = strenv(JOB_NAME) |
     .spec.template.spec.containers[0].image = strenv(PROBE_IMAGE)' \
    "$input"

  DOCKER_CONFIG="$workdir/docker-config" PROBE_IMAGE="$probe_image" \
    timeout --kill-after=10s 120s \
    "$genpolicy_bin" \
      -y "$input" \
      -p "$rules" \
      -j "$settings" \
      --runtime-class-names confidential

  encoded="$(yq -er ".spec.template.metadata.annotations.\"$ANNOTATION\"" "$input")"
  [[ "${#encoded}" -le 65536 ]] || die "$(basename "$source_manifest") Init-Data exceeds 64 KiB encoded"
  printf '%s' "$encoded" | base64 -d | gzip -dc >"$decoded"
  [[ "$(yq -p=toml -oy -r '.version' "$decoded")" == '0.1.0' ]] || die 'generated Init-Data has wrong version'
  [[ "$(yq -p=toml -oy -r '.algorithm' "$decoded")" == sha256 ]] || die 'generated Init-Data has wrong algorithm'
  yq -p=toml -oy -er '.data."policy.rego"' "$decoded" >"$policy"
  rg -Fx 'package agent_policy' "$policy" >/dev/null || die 'generated Init-Data lacks Agent policy'
  rg -F "$probe_digest" "$policy" >/dev/null || die 'generated Agent policy lacks the exact probe digest'
  rg -F "\"$container_name\"" "$policy" >/dev/null || die 'generated Agent policy lacks the expected container'
  expected_sandbox_name="^${job_name}(-[0-9]+)?-${POD_NAME_SUFFIX}$"
  policy_sandbox_names="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -er '.. | objects | .["io.kubernetes.cri.sandbox-name"]? // empty' |
      sort -u
  )"
  [[ "$policy_sandbox_names" == "$expected_sandbox_name" ]] || \
    die "generated Agent policy sandbox name is $policy_sandbox_names, expected $expected_sandbox_name"
  rg -Fx 'default ReadStreamRequest := false' "$policy" >/dev/null || \
    die 'generated Agent policy lost its fail-closed ReadStream default'
  policy_oci_versions="$(
    rg -o '\"Version\": \"[^\"]+\"' "$policy" |
      sed -E 's/^\"Version\": \"([^\"]+)\"$/\1/' |
      sort -u
  )"
  [[ "$policy_oci_versions" == "$oci_version" ]] || \
    die "generated Agent policy OCI version is $policy_oci_versions, expected $oci_version"
  policy_privileged_caps="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -ce '.common.privileged_caps'
  )"
  [[ "$(jq -cn --argjson caps "$policy_privileged_caps" '$caps | sort')" == \
      "$(jq -cn --argjson caps "$privileged_caps" '$caps | sort')" ]] || \
    die 'generated Agent policy privileged capabilities do not match the Talos runtime contract'
  policy_request_defaults="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -ce '.request_defaults | {ReadStreamRequest, WriteStreamRequest, CloseStdinRequest}'
  )"
  [[ "$policy_request_defaults" == \
      '{"ReadStreamRequest":true,"WriteStreamRequest":false,"CloseStdinRequest":false}' ]] || \
    die 'generated Agent policy does not expose read-only CRI stream observability'

  if [[ "$mode" == verify ]]; then
    current="$(yq -er ".spec.template.metadata.annotations.\"$ANNOTATION\"" "$source_manifest")"
    [[ "$current" == "$encoded" ]] || die "$(basename "$source_manifest") Init-Data is stale"
    printf '%s: exact-head Init-Data verified\n' "$(basename "$source_manifest")"
  fi
  printf -v "$encoded_output" '%s' "$encoded"
}

export PROBE_IMAGE="$probe_image"
runtime_initdata=''
attestation_initdata=''
generate_one "$runtime_manifest" smoke true "$runtime_job_name" runtime_initdata
generate_one "$attestation_manifest" attest false "$attestation_job_name" attestation_initdata
if [[ "$mode" == update ]]; then
  JOB_NAME="$commodity_job_name" yq -i '.metadata.name = strenv(JOB_NAME)' "$commodity_manifest"
  JOB_NAME="$runtime_job_name" CC_INIT_DATA="$runtime_initdata" yq -i \
    ".metadata.name = strenv(JOB_NAME) |
     .spec.template.metadata.annotations.\"$ANNOTATION\" = strenv(CC_INIT_DATA)" \
    "$runtime_manifest"
  JOB_NAME="$attestation_job_name" CC_INIT_DATA="$attestation_initdata" yq -i \
    ".metadata.name = strenv(JOB_NAME) |
     .spec.template.metadata.annotations.\"$ANNOTATION\" = strenv(CC_INIT_DATA)" \
    "$attestation_manifest"
  printf 'probe generation %s: all Job names and Init-Data updated\n' "$generation"
fi
printf 'Kata genpolicy source: %s\n' "$kata_head"
printf 'Containerd OCI contract: %s\n' "$oci_version"
printf 'Talos capability source: %s\n' "$privileged_caps_source_commit"
printf 'Talos-dropped privileged capabilities: %s\n' \
  "$(jq -r 'join(",")' <<<"$dropped_privileged_caps")"
