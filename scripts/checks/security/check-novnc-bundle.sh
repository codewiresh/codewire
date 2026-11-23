#!/usr/bin/env bash
# The dashboard's noVNC bundle is upstream's code and nothing else
# (docs/dev/SANDBOX-DESKTOP.md, "The dashboard viewer"; #3223).
#
# It rebuilds the bundle from the vendored upstream files with the pinned
# esbuild, inside the pinned image with no network, and fails unless the
# result is byte-equal to the committed bundle, whose size and SHA-384 the
# vendor manifest records. It also fails if the bundle stops being one
# self-contained module: any import or export, eval, new Function, a Worker
# or a blob: URL. Every pin is in .supplychain/vendor-bundles.json.
#
#   check-novnc-bundle.sh              check the committed bundle
#   check-novnc-bundle.sh --write      rebuild it in place (after a version bump)
#   check-novnc-bundle.sh --self-test  prove a one-byte change and a forbidden
#                                      construct each fail the check
set -euo pipefail

readonly manifest=".supplychain/vendor-bundles.json"
# Every file this check makes, removed when it exits.
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

die() {
  echo "noVNC bundle: $*" >&2
  exit 1
}

field() {
  jq -er ".bundles[0].$1" "$manifest"
}

sha384_of() {
  echo "sha384-$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"
}

# The vendored inputs are exactly the manifest's, byte for byte.
check_inputs() {
  local root listed present member path size sha384
  root="$(field inputs_root)"
  [[ -d "$root" ]] || die "missing input directory $root"
  listed="$(jq -r '.bundles[0].inputs[].member' "$manifest" | sort)"
  present="$(cd "$root" && find . -type f | sed 's#^\./##' | sort)"
  [[ "$listed" == "$present" ]] ||
    die "the files under $root are not exactly the manifest's inputs"
  while IFS=$'\t' read -r member size sha384; do
    path="$root/$member"
    [[ "$(wc -c <"$path" | tr -d '[:space:]')" == "$size" ]] || die "size mismatch for $path"
    [[ "$(sha384_of "$path")" == "$sha384" ]] || die "SHA-384 mismatch for $path"
  done < <(jq -r '.bundles[0].inputs[] | [.member, (.size | tostring), .sha384] | @tsv' "$manifest")
  path="$(field entry.path)"
  [[ "$(sha384_of "$path")" == "$(field entry.sha384)" ]] || die "SHA-384 mismatch for $path"
}

# Where bun's isolated install puts the pinned esbuild's binary.
esbuild_binary() {
  echo "node_modules/.bun/@esbuild+linux-x64@$(field esbuild.version)/node_modules/@esbuild/linux-x64/bin/esbuild"
}

# The esbuild that installs from the lockfile is the pinned one.
check_esbuild() {
  local esbuild_binary
  esbuild_binary="$(esbuild_binary)"
  [[ -x "$esbuild_binary" ]] || die "no $esbuild_binary; run bun install --frozen-lockfile --ignore-scripts"
  [[ "$(sha256sum "$esbuild_binary" | cut -d' ' -f1)" == "$(field esbuild.binary_sha256)" ]] ||
    die "$esbuild_binary is not the pinned esbuild $(field esbuild.version)"
}

# Build the bundle into OUT inside the pinned image, with no network. The
# inputs and esbuild go in as a tar on standard input and the bundle comes back
# on standard output, so nothing is mounted: in CI the Docker daemon does not
# share the job container's filesystem.
build() {
  local out="$1" image entry inputs_parent esbuild_binary
  local -a options
  esbuild_binary="$(esbuild_binary)"
  mapfile -t options < <(jq -er '.bundles[0].options[]' "$manifest")
  image="$(field image)"
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || die "the builder image is not pinned by digest"
  entry="$(field entry.path)"
  inputs_parent="$(dirname "$entry")"
  # The script and its arguments expand inside the container.
  # shellcheck disable=SC2016
  # Each -C is absolute: tar resolves a relative one against the previous.
  tar -cf - -C "$PWD/$inputs_parent" . -C "$PWD/$(dirname "$esbuild_binary")" esbuild |
    docker run -i --rm --network none --read-only --user "$(id -u):$(id -g)" \
      --tmpfs /work:rw,exec,mode=1777,size=64m -w /work "$image" \
      sh -c 'mkdir src && cd src && tar -xf - && ./esbuild "$@" --log-level=warning' sh \
      "$(basename "$entry")" "${options[@]}" >"$out"
}

# One module that loads nothing else and runs no generated code.
check_self_contained() {
  local bundle="$1"
  local found
  # Collected first: with pipefail, a match count cut short by head would
  # read as no match.
  found="$(grep -nE '^[[:space:]]*(import|export)\b|\bimport[[:space:]]*\(|\bimport\.meta\b|(^|[^[:alnum:]_$])eval[[:space:]]*\(|\bFunction[[:space:]]*\(|Worker\b|blob:' "$bundle" || true)"
  if [[ -n "$found" ]]; then
    printf '%s\n' "$found" | head -5 >&2
    die "$bundle is not one self-contained module"
  fi
}

check_bundle() {
  local bundle="$1" rebuilt="$2"
  [[ "$(wc -c <"$bundle" | tr -d '[:space:]')" == "$(field size)" ]] || die "size mismatch for $bundle"
  [[ "$(sha384_of "$bundle")" == "$(field sha384)" ]] || die "SHA-384 mismatch for $bundle"
  cmp -s "$bundle" "$rebuilt" || die "$bundle is not what the pinned build makes of the vendored inputs"
  check_self_contained "$bundle"
}

self_test() {
  local rebuilt changed
  rebuilt="$scratch/rebuilt.js"
  build "$rebuilt"
  ( check_bundle "$(field path)" "$rebuilt" ) || die "self-test: the committed bundle does not pass"
  changed="$scratch/changed.js"
  cp "$rebuilt" "$changed"
  printf 'x' | dd of="$changed" bs=1 seek=100 conv=notrunc status=none
  if ( cmp -s "$changed" "$rebuilt" ); then die "self-test: the one-byte change made no change"; fi
  if ( check_bundle "$changed" "$rebuilt" ) 2>/dev/null; then die "self-test: a one-byte change passed"; fi
  for construct in 'import("x")' 'import x from "y";' 'export const x = 1;' 'eval("1")' \
    'x = window.eval("1")' 'new Function("1")' 'Function("1")()' 'new Worker("x")' \
    'new SharedWorker("x")' '"blob:x"' 'import.meta.url'; do
    printf '%s\n' "$construct" >>"$changed"
    if ( check_self_contained "$changed" ) 2>/dev/null; then
      die "self-test: $construct passed the self-contained check"
    fi
    cp "$rebuilt" "$changed"
  done
  echo "noVNC bundle: self-test passed"
}

main() {
  [[ -f "$manifest" ]] || die "run from the repository root"
  check_inputs
  check_esbuild
  case "${1:-}" in
    --self-test)
      self_test
      ;;
    --write)
      build "$(field path)"
      echo "size $(wc -c <"$(field path)" | tr -d '[:space:]') $(sha384_of "$(field path)")"
      ;;
    "")
      build "$scratch/rebuilt.js"
      check_bundle "$(field path)" "$scratch/rebuilt.js"
      echo "noVNC bundle: OK ($(field version), $(jq '.bundles[0].inputs | length' "$manifest") inputs, rebuilt byte-equal)"
      ;;
    *)
      die "usage: $0 [--write|--self-test]"
      ;;
  esac
}

main "$@"
