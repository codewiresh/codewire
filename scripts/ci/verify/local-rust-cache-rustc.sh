#!/usr/bin/env bash
# RUSTC_WRAPPER selected by local-rust-cache.sh.
#
# sccache hashes every CARGO_* variable in a compiler's environment, and the
# repository runners export a per-worktree CARGO_TARGET_DIR, so a crate built
# in one worktree would never hit in the next. rustc and the workspace's proc
# macros do not read it; remove it before the cache key is computed.
#
# A compile that has to restart the shared server passes its environment to
# that server, so give it the cache's own temporary directory rather than a
# caller's scratch directory that is deleted after its task.
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR
if [[ -x "${CODEWIRE_LOCAL_SCCACHE_BIN:-}" && -n "${CODEWIRE_LOCAL_SCCACHE_TMPDIR:-}" ]]; then
  export TMPDIR="$CODEWIRE_LOCAL_SCCACHE_TMPDIR"
  restarts="${CODEWIRE_LOCAL_SCCACHE_RESTARTS:-}"
  [[ -n "$restarts" ]] || exec "$CODEWIRE_LOCAL_SCCACHE_BIN" "$@"
  before=''
  { read -r before <"$restarts"; } 2>/dev/null
  "$CODEWIRE_LOCAL_SCCACHE_BIN" "$@" && exit 0
  status=$?
  after=''
  { read -r after <"$restarts"; } 2>/dev/null
  # The hung server this compile waited on was stopped (#2753). sccache 0.17
  # compiles locally only when its server had already started the compile; a
  # request still waiting for the server's first answer fails. Compile it here.
  [[ "$after" == "$before" ]] || exec "$@"
  exit "$status"
fi
# The cache is best effort: without its selection, compile uncached.
exec "$@"
