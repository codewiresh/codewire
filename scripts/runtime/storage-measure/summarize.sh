#!/usr/bin/env bash
# Prints summary JSON for one storage-measure evidence directory. The harness
# runs it on exit; run it again to re-summarize kept evidence. It reads only
# local files.
# shellcheck disable=SC2016 # jq programs are single-quoted on purpose.
set -euo pipefail

SM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
  printf '[storage-measure summarize] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" != -* ]] || {
  printf 'usage: summarize.sh EVIDENCE_DIR\n' >&2
  exit 2
}
dir="$1"
[[ -s "$dir/meta.json" ]] || die "$dir/meta.json is missing; not a storage-measure evidence directory"

# A JSON document, or null when the file is absent or empty.
document() {
  if [[ -s "$1" ]]; then cat "$1"; else printf 'null\n'; fi
}

# NDJSON as one array; unreadable lines (an interrupted write) are dropped.
lines() {
  if [[ -s "$1" ]]; then jq -R 'fromjson? // empty' "$1" | jq -s .; else printf '[]\n'; fi
}

attach_runs() {
  local runs=()
  shopt -s nullglob
  runs=("$dir"/attach/run-*.json)
  shopt -u nullglob
  if ((${#runs[@]} > 0)); then jq -s . "${runs[@]}"; else printf '[]\n'; fi
}

jq -n -L "$SM_DIR" \
  --slurpfile meta <(document "$dir/meta.json") \
  --slurpfile attach <(attach_runs) \
  --slurpfile bench <(document "$dir/bench.json") \
  --slurpfile fio <(document "$dir/fio.json") \
  --slurpfile workload <(document "$dir/workload.json") \
  --slurpfile snapshot <(document "$dir/snapshot.json") \
  --slurpfile remote <(document "$dir/remote.json") \
  --slurpfile metrics <(lines "$dir/metrics.ndjson") \
  --slurpfile phases <(lines "$dir/phases.ndjson") \
  --slurpfile cleanup <(document "$dir/cleanup.json") \
  'include "measure";
   {meta: $meta[0], attach: $attach[0], bench: $bench[0], fio: $fio[0],
    workload: $workload[0], snapshot: $snapshot[0], remote: $remote[0],
    metrics: $metrics[0], phases: $phases[0], cleanup: $cleanup[0]}
   | summarize'
