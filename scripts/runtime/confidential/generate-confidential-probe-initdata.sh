#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SMOKE_DIR="$ROOT/deployments/k8s/runtime-profiles/confidential-smoke"
KUSTOMIZATION="$SMOKE_DIR/kustomization.confidential-snp.yaml"
RUNTIME_CONTRACT="$ROOT/deployments/k8s/runtime-profiles/policy/genpolicy-runtime-contract.json"
ANNOTATION='io.katacontainers.config.hypervisor.cc_init_data'
EXPECTED_KATA_COMMIT='c3774d4a0b57bf16c550d6f698024f07589ee07b'

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/generate-confidential-probe-initdata.sh update KATA_SOURCE
  scripts/runtime/confidential/generate-confidential-probe-initdata.sh verify KATA_SOURCE

Generates the two static confidential probe policies with genpolicy from the
exact accepted Kata downstream source. `update` writes only the generated
cc_init_data annotations; `verify` regenerates and compares without changing
the source manifests.

KATA_GENPOLICY_BIN may select an exact-head genpolicy executable. Otherwise
the script checks the usual host debug and release output paths.
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

mode="${1:-}"
kata_root="${2:-}"
[[ "$mode" == update || "$mode" == verify ]] || {
  usage >&2
  exit 2
}
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

[[ "$(jq -er '.schemaVersion' "$RUNTIME_CONTRACT")" == 1 ]] || \
  die 'Codewire genpolicy runtime contract has an unsupported schema'
oci_version="$(jq -er '.ociVersion' "$RUNTIME_CONTRACT")"
settings_drop_in_name="$(jq -er '.kataSettingsDropIn' "$RUNTIME_CONTRACT")"
[[ "$oci_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Codewire OCI version is malformed'
[[ "$settings_drop_in_name" =~ ^[A-Za-z0-9._-]+\.json$ ]] || \
  die 'Codewire Kata settings drop-in name is malformed'
settings_drop_in="$kata_root/src/tools/genpolicy/drop-in-examples/$settings_drop_in_name"
[[ -f "$settings_drop_in" ]] || die "Kata source is missing settings drop-in $settings_drop_in_name"
[[ "$(jq -er '
  [.[] | select(
    .op == "replace" and
    .path == "/kata_config/oci_version"
  ) | .value] | if length == 1 then .[0] else error("invalid OCI drop-in") end
' "$settings_drop_in")" == "$oci_version" ]] || \
  die 'Kata settings drop-in does not match the Codewire OCI contract'

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

umask 077
mkdir -p "$ROOT/.tmp"
workdir="$(mktemp -d "$ROOT/.tmp/confidential-probe-genpolicy.XXXXXX")"
chmod 0700 "$workdir"
mkdir -p "$workdir/docker-config"
settings="$workdir/genpolicy-settings"
mkdir -p "$settings/genpolicy-settings.d"
install -m 0600 "$base_settings" "$settings/genpolicy-settings.json"
install -m 0600 "$settings_drop_in" "$settings/genpolicy-settings.d/$settings_drop_in_name"
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
  local input decoded policy
  local encoded current policy_oci_versions

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
  yq -i \
    'del(.spec.template.spec.automountServiceAccountToken) |
     del(.spec.template.spec.containers[0].securityContext.runAsNonRoot) |
     del(.spec.template.metadata.annotations."io.katacontainers.config.hypervisor.cc_init_data") |
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
  policy_oci_versions="$(
    rg -o '\"Version\": \"[^\"]+\"' "$policy" |
      sed -E 's/^\"Version\": \"([^\"]+)\"$/\1/' |
      sort -u
  )"
  [[ "$policy_oci_versions" == "$oci_version" ]] || \
    die "generated Agent policy OCI version is $policy_oci_versions, expected $oci_version"

  if [[ "$mode" == update ]]; then
    CC_INIT_DATA="$encoded" yq -i \
      ".spec.template.metadata.annotations.\"$ANNOTATION\" = strenv(CC_INIT_DATA)" \
      "$source_manifest"
  else
    current="$(yq -er ".spec.template.metadata.annotations.\"$ANNOTATION\"" "$source_manifest")"
    [[ "$current" == "$encoded" ]] || die "$(basename "$source_manifest") Init-Data is stale"
  fi

  printf '%s: exact-head Init-Data %s\n' "$(basename "$source_manifest")" "$mode"
}

export PROBE_IMAGE="$probe_image"
generate_one "$SMOKE_DIR/confidential-smoke-job.yaml" smoke true
generate_one "$SMOKE_DIR/confidential-attestation-job.yaml" attest false
printf 'Kata genpolicy source: %s\n' "$kata_head"
printf 'Containerd OCI contract: %s\n' "$oci_version"
