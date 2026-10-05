#!/usr/bin/env bash
# Select the compiler cache for the protected Dev runtime-image build.
#
# The shared protected R2 cache is best effort. When this exact canonical-main
# deploy job obtains its protected credential, the build uses the dedicated
# protected bucket and prefix. Any failure to obtain it (OpenBao document not
# yet created, policy not yet reconciled, OpenBao or Forgejo OIDC outage, or a
# malformed value) selects the job-local cache instead: the compiler cache must
# never fail or block delivery. The fallback is the more conservative mode, so
# failing open here cannot widen any trust boundary.
#
# The selected mode is written as the `mode` step output (exactly `r2` or
# `local`). The credential, when present, stays in the private file named by
# the caller below RUNNER_TEMP; the workflow removes it after the build.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: select-protected-rust-cache.sh AWS_CREDENTIALS_FILE' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly credentials_file="$1"
readonly fetcher="$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh"

: "${GITHUB_OUTPUT:?Forgejo step output file is required}"
: "${RUNNER_TEMP:?Forgejo runner temporary directory is required}"

case "$credentials_file" in
  "$RUNNER_TEMP"/*) ;;
  *)
    echo 'protected compiler-cache credential must remain below RUNNER_TEMP' >&2
    exit 2
    ;;
esac
[[ ! -e "$credentials_file" && ! -L "$credentials_file" ]] || {
  echo 'protected compiler-cache credential output must be a new nonsymlink path' >&2
  exit 2
}

remove_credential() {
  if [[ -f "$credentials_file" && ! -L "$credentials_file" ]]; then
    shred -u -- "$credentials_file" 2>/dev/null || rm -f -- "$credentials_file"
  else
    rm -f -- "$credentials_file"
  fi
}

credential_ready() {
  [[ -f "$credentials_file" && ! -L "$credentials_file" && -s "$credentials_file" ]] &&
    [[ "$(stat -c '%a' -- "$credentials_file")" == 600 ]]
}

if "$fetcher" "$credentials_file" && credential_ready; then
  printf 'mode=r2\n' >>"$GITHUB_OUTPUT"
  printf 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=protected\n'
else
  remove_credential
  echo '::warning::Protected R2 compiler cache is unavailable; building with the job-local cache'
  printf 'mode=local\n' >>"$GITHUB_OUTPUT"
  printf 'CODEWIRE_CI_CACHE state=cache-unavailable fallback=local trust=protected\n'
fi
