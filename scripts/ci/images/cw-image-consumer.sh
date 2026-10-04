#!/usr/bin/env bash
# Common bridge for existing image/cache owners. The Python owner holds the
# original producer and verified named context throughout each actual solve.

cw_image_check() {
  local profile="$1" source_dir="$2" work="$3"
  shift 3
  local source_sha
  local -a image_options=()
  [[ -z "${cw_image_context_dir:-}" ]] || image_options+=(--image-source-dir "$cw_image_context_dir")
  source_sha="$(git -C "$source_dir" rev-parse HEAD)" || return
  python3 -B "$ROOT/scripts/ci/images/cw-image-consumer.py" check \
    --source-dir "$source_dir" --source-sha "$source_sha" --profile "$profile" \
    --output "$work/check" --docker-bin "${docker_bin:-docker}" "${image_options[@]}" -- "$@"
}

cw_image_prepare() {
  local profile="$1" source_dir="$2" work="$3"
  local source_sha status=0 producer_work result_file
  local -a producer_options=()
  source_sha="$(git -C "$source_dir" rev-parse HEAD)" || return
  if [[ -n "${cw_image_reference:-}" ]]; then
    [[ "$cw_image_profile" == "$profile" && "$cw_image_source_dir" == "$source_dir" ]] || {
      echo 'CW producer reuse requires the same selected source and profile' >&2
      return 2
    }
    return 0
  fi
  if [[ -n "${cw_image_builder:-${builder:-${buildx_builder:-}}}" ]]; then
    producer_options+=(--builder "${cw_image_builder:-${builder:-$buildx_builder}}")
  fi
  if [[ -n "${CODEWIRE_VERSION:-}" ]]; then
    producer_options+=(--version "$CODEWIRE_VERSION")
  fi
  producer_options+=("${cw_image_producer_cache_args[@]:-}")
  # An unset cache array must add no empty argv element.
  if [[ "${#producer_options[@]}" -gt 0 && "${producer_options[-1]}" == '' ]]; then
    unset 'producer_options[-1]'
  fi
  result_file="$work/cw-producer-result.json"
  if [[ ! -e "$result_file" && ! -L "$result_file" ]]; then
    # A diagnosed retry keeps its failed producer and gets a fresh task. Only
    # a successful result becomes the retained reference for this owner work.
    producer_work="$(mktemp -d "$work/cw-producer.XXXXXX")" || return
    python3 -B "$ROOT/scripts/ci/images/cw-image-consumer.py" produce \
      --source-dir "$source_dir" --source-sha "$source_sha" --profile "$profile" \
      --output "$producer_work/build" --docker-bin "${docker_bin:-docker}" \
      --sccache-mode "${sccache_mode:-${CODEWIRE_SCCACHE_MODE:-local}}" \
      "${producer_options[@]}" >"$producer_work/result.json" || status=$?
    [[ "$status" == 0 ]] || return "$status"
    python3 -B - "$ROOT" "$producer_work/result.json" "$result_file" <<'PY' || return
from contextlib import closing
import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('cw_bridge', pathlib.Path(sys.argv[1])/'scripts/ci/images/cw-image-consumer.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with closing(module.asset.HeldFile(pathlib.Path(sys.argv[2]), module.release.MAX_JSON)) as held:
    value=module.release.parse_canonical(held.data)
    module.asset.require(value['status']=='producer-admitted', 'producer result is not admitted')
    with closing(module.asset.Parent(pathlib.Path(sys.argv[3]).parent)) as parent:
        held.revalidate(content=True)
        module.asset.write_new(parent.fd, pathlib.Path(sys.argv[3]).name, held.data, 0o400)
PY
    cw_image_compilation=new
  else
    cw_image_compilation=reused
  fi
  local reference
  reference="$(python3 -B - "$ROOT" "$result_file" "$profile" <<'PY'
from contextlib import closing
import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('cw_bridge', pathlib.Path(sys.argv[1])/'scripts/ci/images/cw-image-consumer.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with closing(module.asset.HeldFile(pathlib.Path(sys.argv[2]), module.release.MAX_JSON)) as held:
    value=module.release.parse_canonical(held.data)
    module.asset.require(value['status']=='producer-admitted' and value['profile']==sys.argv[3], 'producer selection differs')
    pin=value['receipt']; module.asset.path_arg(pin['path'])
    module.asset.require(module.release.is_hex(pin['sha256'],64), 'producer reference refused')
    held.revalidate(content=True)
    print(pin['path']); print(pin['sha256'])
PY
)" || return
  cw_image_reference="${reference%$'\n'*}"
  cw_image_reference_sha="${reference##*$'\n'}"
  cw_image_profile="$profile"
  cw_image_source_dir="$source_dir"
}

cw_image_run() {
  local profile="$1" source_dir="$2" work="$3"
  shift 3
  local admission source_sha output
  local -a producer_options=()
  admission="$(cw_image_check "$profile" "$source_dir" "$work" "$@")" || return
  cw_image_builder="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["builder"] or "")' <<<"$admission")" || return
  if [[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["needs_cw_asset"])' <<<"$admission")" == True ]]; then
    cw_image_prepare "$profile" "$source_dir" "$work" || return
    producer_options+=(--producer-receipt "$cw_image_reference" --producer-sha256 "$cw_image_reference_sha")
  fi
  if [[ -n "${CODEWIRE_VERSION:-}" ]]; then
    producer_options+=(--version "$CODEWIRE_VERSION")
  fi
  [[ -z "${cw_image_context_dir:-}" ]] || producer_options+=(--image-source-dir "$cw_image_context_dir")
  source_sha="$(git -C "$source_dir" rev-parse HEAD)" || return
  # Separate solves share the immutable producer but get fresh contexts and
  # receipts. A failed attempt is retained and never overwritten by a retry.
  output="$(mktemp -d "$work/.cw-consumer-parent.XXXXXX")" || return
  python3 -B "$ROOT/scripts/ci/images/cw-image-consumer.py" consume \
    --source-dir "$source_dir" --source-sha "$source_sha" --profile "$profile" \
    --output "$output/solve" --docker-bin "${docker_bin:-docker}" \
    "${producer_options[@]}" -- "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  readonly ROOT
  [[ $# -ge 5 ]] || { echo 'usage: cw-image-consumer.sh PROFILE SOURCE WORK [PRODUCER_CACHE_ARG ...] -- DOCKER_COMMAND ...' >&2; exit 2; }
  profile="$1" source_dir="$2" work="$3"
  shift 3
  cw_image_producer_cache_args=()
  while [[ $# -gt 0 && "$1" != -- ]]; do
    case "$1" in
      --image-source-dir)
        [[ $# -ge 2 && -n "$2" && -z "${cw_image_context_dir:-}" ]] || exit 2
        cw_image_context_dir="$2"; shift 2 ;;
      --cache-from|--cache-to)
        [[ $# -ge 2 && -n "$2" ]] || exit 2
        cw_image_producer_cache_args+=("$1" "$2"); shift 2 ;;
      --no-cache) cw_image_producer_cache_args+=("$1"); shift ;;
      *) echo 'CW producer cache option refused' >&2; exit 2 ;;
    esac
  done
  [[ $# -gt 1 && "$1" == -- ]] || exit 2
  shift
  docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
  cw_image_run "$profile" "$source_dir" "$work" "$@"
fi
