#!/usr/bin/env bash
set -euo pipefail

targets=("${@}")
if [ "${#targets[@]}" -eq 0 ]; then
  targets=(x86_64-apple-darwin aarch64-apple-darwin)
fi

for target in "${targets[@]}"; do
  case "$target" in
    *-apple-darwin)
      ;;
    *)
      echo "check-cw-darwin-sdkless: expected a Darwin target, got $target" >&2
      exit 1
      ;;
  esac

  dependency_tree="$(
    cargo tree \
      --locked \
      -p codewire-cli-bin \
      --target "$target" \
      --prefix none \
      --format '{p}'
  )"
  if printf '%s\n' "$dependency_tree" | grep -q '^core-foundation-sys v'; then
    echo "check-cw-darwin-sdkless: $target still links core-foundation-sys" >&2
    exit 1
  fi
done

echo "check-cw-darwin-sdkless: Darwin CLI graphs require no CoreFoundation SDK framework"
