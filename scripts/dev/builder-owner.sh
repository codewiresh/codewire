#!/usr/bin/env bash
# Sourced. Records who made a local Docker builder, so `codewire-cpu status`
# can name the owner of each idle buildx and Kind node container and each
# session removes only its own (docs/dev/AGENT-WORKFLOW.md, "Workstation CPU
# limits"). Docker's buildx docker-container driver and Kind set no label a
# creator chooses, so the record is a file beside them:
#
#   ~/.cache/codewire-builders/NAME   one key=value per line
#     kind      buildx or kind
#     worktree  the checkout that made it
#     task      that checkout's directory name
#     owner     the first line of the session's OWNER file, when TMPDIR sits
#               under a ~/.cache/cwt-<task> directory that holds one
#     created   when, in UTC
#
# NAME is a buildx builder's name or a Kind cluster's name. Recording never
# fails its caller, and CI guests record nothing: they are wiped after a job.

builder_owner_record() {
  local builder="$1" name="$2" dir worktree owner='' up
  [ -z "${GITHUB_ACTIONS:-}" ] && [ -z "${CI:-}" ] || return 0
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || return 0
  dir="${HOME:-}/.cache/codewire-builders"
  [ -n "${HOME:-}" ] && mkdir -p "$dir" 2>/dev/null || return 0
  worktree="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
  up="${TMPDIR:-}"
  while [ -n "$up" ] && [ "$up" != / ]; do
    case "${up##*/}" in
      cwt-*)
        [ -f "$up/OWNER" ] && IFS= read -r owner <"$up/OWNER" 2>/dev/null
        break
        ;;
    esac
    up="${up%/*}"
  done
  {
    printf 'kind=%s\n' "$builder"
    printf 'worktree=%s\n' "$worktree"
    printf 'task=%s\n' "${worktree##*/}"
    printf 'owner=%s\n' "$(printf '%s' "$owner" | tr -cd '[:print:]' | cut -c1-120)"
    printf 'created=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$dir/$name.tmp.$$" 2>/dev/null && mv -f "$dir/$name.tmp.$$" "$dir/$name" 2>/dev/null
  rm -f "$dir/$name.tmp.$$" 2>/dev/null
  return 0
}
