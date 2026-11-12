#!/bin/sh
# herdr runs this for every Codewire action and pane (see herdr-plugin.toml):
#   codewire.sh open ENTRYPOINT [KEY=VALUE]...  opens that plugin pane
#   codewire.sh pane ENTRYPOINT                 is the program the pane runs
# A pane for one environment gets CW_ENV and CW_PLACEMENT (local, cloud or
# host); without CW_ENV it uses the environment `cw use` selected.
set -eu

herdr="${HERDR_BIN_PATH:-herdr}"
plugin="${HERDR_PLUGIN_ID:-codewire}"

die() { printf 'codewire: %s\n' "$*" >&2; exit 1; }

# herdr's server may not have the login shell's PATH.
cw="$(command -v cw 2>/dev/null || true)"
for candidate in "$HOME/.local/bin/cw" /usr/local/bin/cw /opt/homebrew/bin/cw; do
  [ -z "$cw" ] && [ -x "$candidate" ] && cw="$candidate"
done

need_cw() {
  [ -n "$cw" ] || die "cw is not installed; see https://codewire.sh/docs/install/"
}

# Leaves a failed command's output on screen until Enter.
finish() { # status
  if [ "$1" -ne 0 ]; then
    printf '\n[exited with status %d; press Enter to close]' "$1"
    IFS= read -r _ || true
  fi
  exit "$1"
}

placement_flag() {
  case "${CW_PLACEMENT:-}" in
    local | cloud) printf -- '--%s' "$CW_PLACEMENT" ;;
    "" | host) ;;
    *) die "unknown placement: $CW_PLACEMENT" ;;
  esac
}

open_pane() { # entrypoint [KEY=VALUE]...
  entrypoint="$1"
  shift
  for pair in "$@"; do
    set -- "$@" --env "$pair"
    shift
  done
  set -- plugin pane open --plugin "$plugin" --entrypoint "$entrypoint" --focus "$@"
  case "$entrypoint" in
    environments) ;;
    doctor) [ -z "${HERDR_PANE_ID:-}" ] || set -- "$@" --target-pane "$HERDR_PANE_ID" --direction right ;;
    *) [ -z "${HERDR_WORKSPACE_ID:-}" ] || set -- "$@" --workspace "$HERDR_WORKSPACE_ID" ;;
  esac
  status=0
  "$herdr" "$@" >/dev/null || status=$?
  finish "$status"
}

# Lists environments and opens a shell or agent tab in the one chosen.
choose_environment() {
  command -v jq >/dev/null || die "listing environments needs jq"
  status=0
  inventory="$("$cw" ls --output json)" || status=$?
  # cw ls exits non-zero when a location could not be listed, and still
  # prints every environment it could list.
  rows="$(printf '%s' "$inventory" | jq -r '.[] | [.placement, .name, .state] | @tsv')" ||
    die "cw ls printed no environment list"
  [ "$status" -eq 0 ] || printf 'Some environments could not be listed; run cw ls to see why.\n\n'
  if [ -z "$rows" ]; then
    printf 'No environments yet. Codewire: new environment creates one.\n'
    finish 1
  fi
  printf '%s\n' "$rows" | awk -F '\t' '{ printf "%3d  %-6s %-32s %s\n", NR, $1, $2, $3 }'
  printf '\nNumber, then s for a shell or a for Claude Code (for example 1s); Enter cancels: '
  IFS= read -r answer || exit 0
  [ -n "$answer" ] || exit 0
  number="${answer%?}"
  case "$number" in "" | *[!0-9]*) die "not a choice: $answer" ;; esac
  case "$answer" in *s | *a) ;; *) die "not a choice: $answer" ;; esac
  row="$(printf '%s\n' "$rows" | sed -n "${number}p")"
  [ -n "$row" ] || die "no environment $number"
  placement="$(printf '%s' "$row" | cut -f1)"
  name="$(printf '%s' "$row" | cut -f2)"
  case "$answer" in
    *s) open_pane shell "CW_ENV=$name" "CW_PLACEMENT=$placement" ;;
    *a) open_pane agent "CW_ENV=$name" "CW_PLACEMENT=$placement" HERDR_AGENT=claude ;;
  esac
}

run_pane() { # entrypoint
  need_cw
  flag="$(placement_flag)"
  status=0
  # shellcheck disable=SC2086 # $flag is empty or one word.
  case "$1" in
    environments) choose_environment ;;
    shell) "$cw" $flag shell ${CW_ENV:+"$CW_ENV"} || status=$? ;;
    agent) "$cw" $flag run claude ${CW_ENV:+--in "$CW_ENV"} || status=$? ;;
    new)
      "$cw" create || finish $?
      open_pane environments
      ;;
    doctor)
      "$cw" doctor || status=$?
      printf '\n[press Enter to close]'
      IFS= read -r _ || true
      ;;
    *) die "unknown pane: $1" ;;
  esac
  finish "$status"
}

case "${1:-}" in
  open)
    [ $# -ge 2 ] || die "usage: codewire.sh open ENTRYPOINT [KEY=VALUE]..."
    shift
    [ "$1" != agent ] || set -- "$@" HERDR_AGENT=claude
    open_pane "$@"
    ;;
  pane)
    [ $# -eq 2 ] || die "usage: codewire.sh pane ENTRYPOINT"
    run_pane "$2"
    ;;
  *) die "usage: codewire.sh open|pane ENTRYPOINT" ;;
esac
