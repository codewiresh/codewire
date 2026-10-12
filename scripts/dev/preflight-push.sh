#!/usr/bin/env bash
# The fast pre-push check: only what the changed files need, in minutes on a
# warm worktree. Merge qualification (preflight.sh --for-merge) runs the
# selected families; Kind and everything else run in post-merge CI.
#
#   scripts/dev/preflight-push.sh <changed-paths-file> <base-commit> <ran-output>
#
# Each executed check is appended to <ran-output>, one name per line.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 3 ] || {
  echo 'usage: scripts/dev/preflight-push.sh <changed-paths-file> <base-commit> <ran-output>' >&2
  exit 2
}
CHANGED="$1"
BASE="$2"
RAN="$3"
cd "$ROOT"
: >"$RAN"

log() { printf '[push-check] %s\n' "$*"; }
ran() { printf '%s\n' "$1" >>"$RAN"; }
step() {
  local name="$1" started=$SECONDS status=0
  shift
  log "${name}: start"
  "$@" || status=$?
  if [ "$status" -ne 0 ]; then
    printf 'preflight: push check %s FAILED (exit %s)\n' "$name" "$status" >&2
    exit 1
  fi
  log "${name}: passed in $((SECONDS - started))s"
  ran "$name"
}

declare -A crate_dirs=()
rust_workspace=false
detached_desktop=false
shell_files=()
python_files=()
proto_changed=false
dashboard_changed=false

while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in
    crates/*/*)
      dir="${path#crates/}"
      dir="crates/${dir%%/*}"
      if [ "$dir" = crates/codewire-desktop ]; then
        detached_desktop=true
      elif [ -f "$dir/Cargo.toml" ] && grep -Fq "\"$dir\"" Cargo.toml; then
        crate_dirs["$dir"]=1
      elif [ -f "$dir/Cargo.toml" ] || [[ "$path" == *.rs ]]; then
        # A crate outside the workspace member list: compile the workspace.
        rust_workspace=true
      fi
      ;;
    Cargo.toml | Cargo.lock | rust-toolchain.toml | .cargo/*)
      rust_workspace=true
      ;;
    *.rs)
      rust_workspace=true
      ;;
  esac
  case "$path" in
    proto/*) proto_changed=true ;;
    apps/dashboard/* | packages/*) dashboard_changed=true ;;
  esac
  # Deleted files need no lint; the merge qualification checks the rest.
  [ -f "$path" ] || continue
  case "$path" in
    *.sh | .githooks/*) shell_files+=("$path") ;;
    *.py) python_files+=("$path") ;;
  esac
done <"$CHANGED"

rust_needed=false
if [ "${#crate_dirs[@]}" -gt 0 ] || [ "$rust_workspace" = true ] || [ "$detached_desktop" = true ]; then
  rust_needed=true
fi

environment_args=()
[ "$rust_needed" = false ] || environment_args+=(--rust)
[ "$dashboard_changed" = false ] || environment_args+=(--node-modules)
step environment "$ROOT/scripts/dev/preflight-environment.sh" "${environment_args[@]}"

if [ "$rust_needed" = true ]; then
  CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh "$ROOT")"
  export CARGO_TARGET_DIR
  # The same best-effort shared compiler cache as the merge families.
  # shellcheck source=scripts/ci/verify/local-rust-cache.sh
  source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
  select_local_rust_cache "$ROOT" || true
fi

packages=()
lib_packages=()
bin_packages=()
for dir in $(printf '%s\n' "${!crate_dirs[@]}" | LC_ALL=C sort); do
  package="$(sed -nE 's/^name = "([^"]+)"/\1/p' "$dir/Cargo.toml" | head -n 1)"
  [ -n "$package" ] || { echo "push-check: cannot read the package name of $dir" >&2; exit 1; }
  packages+=(-p "$package")
  if [ -f "$dir/src/lib.rs" ] || grep -q '^\[lib\]' "$dir/Cargo.toml"; then
    lib_packages+=(-p "$package")
  elif [ -f "$dir/src/main.rs" ] || [ -d "$dir/src/bin" ] || grep -q '^\[\[bin\]\]' "$dir/Cargo.toml"; then
    bin_packages+=(-p "$package")
  fi
done

if [ "${#packages[@]}" -gt 0 ] || [ "$rust_workspace" = true ]; then
  step rust-fmt cargo fmt --all --check
fi
if [ "$rust_workspace" = true ]; then
  step rust-clippy-workspace cargo clippy --locked --workspace --all-targets -- -D warnings
elif [ "${#packages[@]}" -gt 0 ]; then
  step rust-clippy cargo clippy --locked "${packages[@]}" --all-targets -- -D warnings
fi
if [ "${#lib_packages[@]}" -gt 0 ]; then
  step rust-unit-tests-lib cargo test --locked "${lib_packages[@]}" --lib
fi
if [ "${#bin_packages[@]}" -gt 0 ]; then
  step rust-unit-tests-bin cargo test --locked "${bin_packages[@]}" --bins
fi
if [ "$detached_desktop" = true ]; then
  desktop_manifest=crates/codewire-desktop/Cargo.toml
  step desktop-fmt cargo fmt --manifest-path "$desktop_manifest" --check
  step desktop-check cargo check --locked --manifest-path "$desktop_manifest"
fi

shellcheck_changed() {
  local report status=0 findings expected
  if ! command -v shellcheck >/dev/null || ! command -v jq >/dev/null; then
    echo 'push-check: shellcheck and jq are required on PATH' >&2
    return 1
  fi
  # Match the repository policy: warnings fail unless the reviewed baseline
  # owns them. The full ShellCheck domain runs in merge qualification.
  # shellcheck source=scripts/ci/verify/shellcheck-baseline.sh
  source "$ROOT/scripts/ci/verify/shellcheck-baseline.sh"
  # The policy check analyzes each script together with every script it
  # sources (check-shell-scripts.sh), so a variable a sourced file reads is
  # used. Follow the sources here too; findings stay those of the changed files.
  # Status 1 means findings; anything else above 0 is a ShellCheck failure.
  report="$(shellcheck --external-sources --severity=warning --format=json1 "${shell_files[@]}")" || status=$?
  if [ "$status" -gt 1 ]; then
    echo "push-check: shellcheck failed with status $status" >&2
    return 1
  fi
  findings="$(
    jq -r --args '
        [.comments[] | select(.file as $file | $ARGS.positional | index($file))]
        | group_by([.file, .code])[]
        | "\(.[0].file)\tSC\(.[0].code)\t\(length)"' "${shell_files[@]}" <<<"$report" \
      | LC_ALL=C sort
  )"
  expected="$(
    printf '%s\n' "$SHELLCHECK_BASELINE_TSV" \
      | awk -F '\t' 'NR == FNR { keep[$0] = 1; next }
          /^#/ || NF != 4 { next }
          ($1 in keep) { print $1 "\t" $2 "\t" $3 }' \
        <(printf '%s\n' "${shell_files[@]}") - \
      | LC_ALL=C sort
  )"
  if [ "$findings" != "$expected" ]; then
    shellcheck --external-sources --severity=warning "${shell_files[@]}" || true
    printf 'push-check: ShellCheck findings differ from the reviewed baseline\n' >&2
    return 1
  fi
}
if [ "${#shell_files[@]}" -gt 0 ]; then
  step shellcheck shellcheck_changed
fi

python_syntax() {
  python3 -I -c '
import ast, sys
for name in sys.argv[1:]:
    with open(name, encoding="utf-8") as handle:
        ast.parse(handle.read(), name)
' "${python_files[@]}"
}
if [ "${#python_files[@]}" -gt 0 ]; then
  step python-syntax python_syntax
fi

ensure_buf() {
  local version go_bin
  version="$(sed -nE 's|^[[:space:]]*go install github.com/bufbuild/buf/cmd/buf@(v[0-9.]+)$|\1|p' \
    scripts/ci/verify/run-product-verification.sh | head -n 1)"
  [ -n "$version" ] || { echo 'push-check: cannot read the pinned buf version' >&2; return 1; }
  go_bin="$(go env GOPATH)/bin"
  if [ "$("$go_bin/buf" --version 2>/dev/null || true)" != "${version#v}" ]; then
    go install "github.com/bufbuild/buf/cmd/buf@${version}"
  fi
  export PATH="$go_bin:$PATH"
}
proto_lint() { (cd proto && buf lint); }
proto_breaking() {
  BUF="$(command -v buf)" python3 scripts/checks/proto_breaking.py --base-sha "$BASE"
}
if [ "$proto_changed" = true ]; then
  step proto-buf ensure_buf
  step proto-lint proto_lint
  step proto-breaking proto_breaking
fi

dashboard_typecheck() {
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts
  bun run --cwd apps/dashboard typecheck
}
if [ "$dashboard_changed" = true ]; then
  step dashboard-typecheck dashboard_typecheck
fi

log "passed: $(paste -sd, "$RAN")"
