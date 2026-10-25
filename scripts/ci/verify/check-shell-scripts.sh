#!/usr/bin/env bash
# Fail on every unreviewed warning from the exact repository ShellCheck.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/ci/verify/shellcheck-baseline.sh
source "$ROOT/scripts/ci/verify/shellcheck-baseline.sh"

normalize_baseline() {
  awk '
    /^[[:space:]]*#/ || NF == 0 { next }
    NF != 4 { invalid = 1; next }
    $2 !~ /^SC[0-9]+$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[a-z0-9-]+$/ {
      invalid = 1
      next
    }
    { print $1 "\t" $2 "\t" $3 }
    END { if (invalid) exit 1 }
  ' | LC_ALL=C sort
}

group_findings() {
  jq -r '
    .comments
    | group_by([.file, .code])[]
    | "\(.[0].file)\tSC\(.[0].code)\t\(length)"
  ' | LC_ALL=C sort
}

compare_findings() {
  local expected="$1"
  local actual="$2"

  if [[ "$expected" == "$actual" ]]; then
    return 0
  fi
  diff -u \
    <(printf '%s\n' "$expected") \
    <(printf '%s\n' "$actual") >&2 || true
  return 1
}

self_test() {
  local expected actual

  expected="$(printf '%s\n' \
    '# path code count reason' \
    'fixture/a.sh SC2034 2 intentional-fixture' \
    | normalize_baseline)"
  actual="$(printf '%s\n' '{"comments":[{"file":"fixture/a.sh","code":2034},{"file":"fixture/a.sh","code":2034}]}' | group_findings)"
  compare_findings "$expected" "$actual" || {
    printf 'ShellCheck baseline self-test rejected an exact match\n' >&2
    return 1
  }
  if compare_findings "$expected" "fixture/a.sh"$'\t'"SC2034"$'\t'"3" 2>/dev/null; then
    printf 'ShellCheck baseline self-test accepted a changed count\n' >&2
    return 1
  fi
  printf 'ShellCheck warning-ratchet self-test: OK\n'
}

# Print "shard<TAB>weight<TAB>path" for each tracked script path read from stdin
# (one per line), placing the scripts on at most $1 shards.
#
# Without --external-sources, ShellCheck follows a sourced file only when that
# file is named on the same command line, so the single full-list process
# followed every tracked script that another script sources. A shard keeps that
# result only when it holds each member's whole source closure. Scripts joined
# by any source edge therefore share one shard, and every script is analyzed
# exactly once. ShellCheck 0.11.0 follows the name in a `# shellcheck source=`
# directive, a literal source word, or a word that is one expansion followed by
# a literal "/name", which it reads as "./name". Edges cover all three: each
# directive, and each .sh path in a `source` or `.` command line, with and
# without its leading directories, resolved from the repository root and from
# the script's directory. Extra edges only join more scripts into a shard, so
# they cannot change a finding. A script's weight is its bytes plus the weight of
# each file it sources, counted at every source site because ShellCheck reads a
# sourced file again at each one. Components go heaviest first onto the
# lightest shard, and each shard lists its lighter scripts first so its
# heaviest analysis starts last.
plan_shards() {
  local shards="$1"

  awk -v root="$ROOT" -v quote="'" '
    function normalize(path,    count, parts, kept, depth, position, result) {
      count = split(path, parts, "/")
      depth = 0
      for (position = 1; position <= count; position++) {
        if (parts[position] == "" || parts[position] == ".") continue
        if (parts[position] == ".." && depth > 0 && kept[depth] != "..") {
          depth--
          continue
        }
        kept[++depth] = parts[position]
      }
      result = ""
      for (position = 1; position <= depth; position++) {
        result = result (position > 1 ? "/" : "") kept[position]
      }
      return result
    }
    function add_edge(script, target) {
      if (!(target in tracked) || target == script) return
      edge[script, ++edges[script]] = target
    }
    function add_source(script, directory, value,    from_root, from_directory) {
      if (value == "" || value == "/dev/null" || value ~ /[$`]/) return
      if (substr(value, 1, 10) == "SCRIPTDIR/") {
        add_edge(script, normalize(directory "/" substr(value, 11)))
        return
      }
      if (substr(value, 1, 1) == "/") {
        if (substr(value, 1, length(root) + 1) == root "/") {
          add_edge(script, normalize(substr(value, length(root) + 2)))
        }
        add_edge(script, normalize(substr(value, 2)))
        return
      }
      from_root = normalize(value)
      from_directory = normalize(directory "/" value)
      add_edge(script, from_root)
      if (from_directory != from_root) add_edge(script, from_directory)
    }
    # ShellCheck follows a literal name and also "$dir/name", which it reads
    # as "./name". Take every .sh path run in the command, with and without
    # each of its leading directories.
    function add_paths(script, directory, text,    path, position) {
      gsub(/"/, "", text)
      gsub(quote, "", text)
      while (match(text, /[^[:space:]$`(){};&|<>]*\.sh/)) {
        path = substr(text, RSTART, RLENGTH)
        text = substr(text, RSTART + RLENGTH)
        add_source(script, directory, path)
        while ((position = index(path, "/")) > 0) {
          path = substr(path, position)
          add_source(script, directory, path)
          path = substr(path, 2)
        }
      }
    }
    function scan(script,    directory, physical, line, rest, value) {
      directory = script
      if (!sub(/\/[^\/]*$/, "", directory)) directory = "."
      bytes[script] = 0
      line = ""
      while ((getline physical < script) > 0) {
        bytes[script] += length(physical) + 1
        if (sub(/\\$/, "", physical)) {
          line = line physical " "
          continue
        }
        line = line physical
        if (match(line, /#[[:space:]]*shellcheck[[:space:]]/)) {
          rest = substr(line, RSTART + RLENGTH)
          while (match(rest, /(^|[[:space:]])source=[^[:space:]]+/)) {
            value = substr(rest, RSTART, RLENGTH)
            rest = substr(rest, RSTART + RLENGTH)
            sub(/^[[:space:]]*source=/, "", value)
            gsub(/"/, "", value)
            gsub(quote, "", value)
            add_source(script, directory, value)
          }
        }
        if (match(line, /(^|[;&|({[:space:]])(source|\.)[[:space:]]/)) {
          add_paths(script, directory, substr(line, RSTART + RLENGTH))
        }
        line = ""
      }
      close(script)
    }
    function find(script) {
      while (parent[script] != script) {
        parent[script] = parent[parent[script]]
        script = parent[script]
      }
      return script
    }
    function weight(script,    total, position) {
      if (script in memo) return memo[script]
      if (script in visiting) return 0
      visiting[script] = 1
      total = bytes[script]
      for (position = 1; position <= edges[script]; position++) {
        total += weight(edge[script, position])
      }
      delete visiting[script]
      if (total > 1e15) total = 1e15
      memo[script] = total
      return total
    }
    { order[++count] = $0; tracked[$0] = 1; parent[$0] = $0 }
    END {
      for (script_index = 1; script_index <= count; script_index++) {
        scan(order[script_index])
      }
      for (script_index = 1; script_index <= count; script_index++) {
        script = order[script_index]
        for (position = 1; position <= edges[script]; position++) {
          left = find(script)
          right = find(edge[script, position])
          if (left != right) parent[right] = left
        }
      }
      for (script_index = 1; script_index <= count; script_index++) {
        component = find(order[script_index])
        if (!(component in first)) first[component] = script_index
        component_weight[component] += weight(order[script_index])
      }
      for (script_index = 1; script_index <= count; script_index++) {
        script = order[script_index]
        component = find(script)
        printf "%.0f\t%d\t%.0f\t%s\n", component_weight[component], \
          first[component], weight(script), script
      }
    }
  ' | LC_ALL=C sort -t "$(printf '\t')" -k1,1nr -k2,2n -k3,3n -k4,4 \
    | awk -v shards="$shards" '
      BEGIN { FS = OFS = "\t" }
      $2 != component {
        component = $2
        target = 1
        for (shard = 2; shard <= shards; shard++) {
          if (load[shard] < load[target]) target = shard
        }
        load[target] += $1
      }
      { print target, $3, $4 }
    '
}

# check_files PATH...: ShellCheck exactly these scripts, each together with the
# scripts it sources (--external-sources), so a variable a sourced file reads is
# used. Findings stay those of the named files, and must equal the reviewed
# baseline's entries for them. The fast push check and a pull request use this.
check_files() {
  local report status=0 findings expected tool
  for tool in shellcheck jq; do
    command -v "$tool" >/dev/null || {
      printf 'check-shell-scripts: %s is required on PATH\n' "$tool" >&2
      return 1
    }
  done
  # Status 1 means findings; anything else above 0 is a ShellCheck failure.
  report="$(shellcheck --external-sources --severity=warning --format=json1 "$@")" || status=$?
  if [ "$status" -gt 1 ]; then
    printf 'check-shell-scripts: shellcheck failed with status %s\n' "$status" >&2
    return 1
  fi
  findings="$(
    jq -r --args '
        [.comments[] | select(.file as $file | $ARGS.positional | index($file))]
        | group_by([.file, .code])[]
        | "\(.[0].file)\tSC\(.[0].code)\t\(length)"' "$@" <<<"$report" \
      | LC_ALL=C sort
  )"
  expected="$(
    printf '%s\n' "$SHELLCHECK_BASELINE_TSV" \
      | awk -F '\t' 'NR == FNR { keep[$0] = 1; next }
          /^#/ || NF != 4 { next }
          ($1 in keep) { print $1 "\t" $2 "\t" $3 }' \
        <(printf '%s\n' "$@") - \
      | LC_ALL=C sort
  )"
  if [ "$findings" != "$expected" ]; then
    shellcheck --external-sources --severity=warning "$@" || true
    printf 'check-shell-scripts: ShellCheck findings differ from the reviewed baseline\n' >&2
    return 1
  fi
}

usage() {
  printf 'usage: check-shell-scripts.sh [--self-test | --files PATH... | --changed-since COMMIT]\n' >&2
  exit 2
}

case "${1:-}" in
  --self-test)
    [[ $# -eq 1 ]] || usage
    self_test
    exit 0
    ;;
  --files)
    shift
    [[ $# -gt 0 ]] || usage
    cd "$ROOT"
    check_files "$@"
    printf 'ShellCheck of %s named script(s): OK\n' "$#"
    exit 0
    ;;
  --changed-since)
    # A pull request checks only the scripts it changes, and a push to main
    # those changed since the main commit main CI last verified (#3119 A7,
    # M1). A base this checkout lacks checks every script.
    [[ $# -eq 2 && "$2" =~ ^[0-9a-f]{40}$ ]] || usage
    cd "$ROOT"
    if git cat-file -e "$2^{commit}" 2>/dev/null && base="$(git merge-base "$2" HEAD)"; then
      changed=()
      while IFS= read -r -d '' script; do
        [[ -f "$script" ]] && changed+=("$script")
      done < <(git diff -z --name-only --diff-filter=d "$base" HEAD -- '*.sh')
      if [[ "${#changed[@]}" -eq 0 ]]; then
        printf 'ShellCheck: no script changed since %s\n' "$base"
        exit 0
      fi
      check_files "${changed[@]}"
      printf 'ShellCheck of %s script(s) changed since %s: OK\n' "${#changed[@]}" "$base"
      exit 0
    fi
    printf 'ShellCheck: %s is not in this checkout; checking every script\n' "$2"
    ;;
  '') ;;
  *) usage ;;
esac


cd "$ROOT"
# ShellCheck reads a sourced file again at every source site, so a script that
# repeats a large closure dominates the analysis: one script can need most of
# a heavy worker's memory and minutes of CPU by itself. Shards follow source
# closures (see plan_shards) and run concurrently. Every shard starts at once
# under the same deadline, so SHELLCHECK_TIMEOUT_SECONDS bounds each shard and
# the whole analysis. SHELLCHECK_SHARDS=1 is the single-process analysis.
shellcheck_timeout_seconds="${SHELLCHECK_TIMEOUT_SECONDS:-600}"
if [[ ! "$shellcheck_timeout_seconds" =~ ^[0-9]+$ ]] \
    || (( 10#$shellcheck_timeout_seconds < 1 )) \
    || (( 10#$shellcheck_timeout_seconds > 900 )); then
  printf 'SHELLCHECK_TIMEOUT_SECONDS must be an integer from 1 through 900\n' >&2
  exit 2
fi
shellcheck_timeout_seconds=$((10#$shellcheck_timeout_seconds))
shellcheck_shards="${SHELLCHECK_SHARDS:-4}"
if [[ ! "$shellcheck_shards" =~ ^[0-9]+$ ]] \
    || (( 10#$shellcheck_shards < 1 )) \
    || (( 10#$shellcheck_shards > 16 )); then
  printf 'SHELLCHECK_SHARDS must be an integer from 1 through 16\n' >&2
  exit 2
fi
shellcheck_shards=$((10#$shellcheck_shards))
shellcheck_bin="$(scripts/ci/setup/setup-shellcheck.sh)"
mapfile -d '' shell_files < <(
  git ls-files -z -- '*.sh'
)
[[ "${#shell_files[@]}" -gt 0 ]] || {
  printf 'ShellCheck policy found no tracked shell scripts\n' >&2
  exit 1
}
for shell_file in "${shell_files[@]}"; do
  [[ "$shell_file" != *$'\n'* && "$shell_file" != *$'\t'* ]] || {
    printf 'ShellCheck policy cannot shard a script path containing a tab or newline: %q\n' \
      "$shell_file" >&2
    exit 1
  }
done

shellcheck_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-shellcheck.XXXXXX")"
shard_pids=()
stop_shards() {
  local pid
  for pid in "${shard_pids[@]}"; do
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  done
}
trap 'stop_shards; rm -rf -- "$shellcheck_work"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

printf '%s\n' "${shell_files[@]}" | plan_shards "$shellcheck_shards" \
  >"$shellcheck_work/plan.tsv"
# Each tracked script must be analyzed exactly once: a missing script would
# pass unchecked, and a repeated one would double its reviewed findings.
if [[ "$(cut -f3 "$shellcheck_work/plan.tsv" | LC_ALL=C sort)" \
    != "$(printf '%s\n' "${shell_files[@]}" | LC_ALL=C sort)" ]]; then
  printf 'ShellCheck shard plan does not cover each tracked script exactly once\n' >&2
  exit 1
fi
shard_ids=()
shard_sizes=()
shard_heaviest=()
while IFS=$'\t' read -r shard_id shard_size shard_top; do
  shard_ids+=("$shard_id")
  shard_sizes+=("$shard_size")
  shard_heaviest+=("$shard_top")
done < <(awk -F '\t' '
  {
    if (!($1 in size)) order[++count] = $1
    size[$1]++
    if (!($1 in top) || $2 > weight[$1]) { weight[$1] = $2; top[$1] = $3 }
  }
  END { for (i = 1; i <= count; i++) printf "%s\t%s\t%s\n", order[i], size[order[i]], top[order[i]] }
' "$shellcheck_work/plan.tsv" | LC_ALL=C sort -n)
shard_count="${#shard_ids[@]}"

shard_label() {
  printf '%s/%s (scripts=%s heaviest=%s)' "$(($1 + 1))" "$shard_count" \
    "${shard_sizes[$1]}" "${shard_heaviest[$1]}"
}

run_shard() {
  local shard="$1" started_at=$SECONDS status elapsed
  shift
  set +e
  timeout --foreground --signal=TERM --kill-after=5s \
    "${shellcheck_timeout_seconds}s" \
    "$shellcheck_bin" --severity=warning --format=json1 "$@" \
    >"$shellcheck_work/shard-$shard.json"
  status=$?
  set -e
  elapsed=$((SECONDS - started_at))
  printf '%s\t%s\n' "$status" "$elapsed" >"$shellcheck_work/shard-$shard.status"
  printf 'ShellCheck shard %s/%s: finish (status=%s elapsed_seconds=%s)\n' \
    "$((shard + 1))" "$shard_count" "$status" "$elapsed"
}

printf 'ShellCheck analysis: start (scripts=%s shards=%s timeout_seconds=%s)\n' \
  "${#shell_files[@]}" "$shard_count" "$shellcheck_timeout_seconds"
for ((shard = 0; shard < shard_count; shard++)); do
  printf 'ShellCheck shard %s: start\n' "$(shard_label "$shard")"
done
shellcheck_started_at=$SECONDS
for ((shard = 0; shard < shard_count; shard++)); do
  mapfile -t shard_files < <(
    awk -F '\t' -v shard="${shard_ids[shard]}" '$1 == shard { print $3 }' \
      "$shellcheck_work/plan.tsv"
  )
  run_shard "$shard" "${shard_files[@]}" &
  shard_pids+=("$!")
done
for pid in "${shard_pids[@]}"; do
  wait "$pid" || true
done
shard_pids=()
shellcheck_elapsed_seconds=$((SECONDS - shellcheck_started_at))

# Any shard that did not finish with a complete report fails the analysis;
# the findings of the other shards never pass on their own.
shellcheck_status=0
shard_failures=()
shard_reports=()
for ((shard = 0; shard < shard_count; shard++)); do
  shard_status=''
  shard_elapsed=''
  if [[ -s "$shellcheck_work/shard-$shard.status" ]]; then
    IFS=$'\t' read -r shard_status shard_elapsed \
      <"$shellcheck_work/shard-$shard.status"
  fi
  failure=''
  failure_status=1
  case "$shard_status" in
    0|1)
      if jq -e '.comments | type == "array"' \
          "$shellcheck_work/shard-$shard.json" >/dev/null 2>&1; then
        shard_reports+=("$shellcheck_work/shard-$shard.json")
        if [[ "$shard_status" -eq 1 && "$shellcheck_status" -eq 0 ]]; then
          shellcheck_status=1
        fi
      else
        failure="ShellCheck shard $(shard_label "$shard") wrote no valid json1 report"
      fi
      ;;
    124)
      failure="ShellCheck shard $(shard_label "$shard") timed out after ${shellcheck_timeout_seconds} seconds"
      failure_status=124
      ;;
    137)
      failure_status=137
      if (( shard_elapsed >= shellcheck_timeout_seconds )); then
        failure="ShellCheck shard $(shard_label "$shard") timed out after ${shellcheck_timeout_seconds} seconds"
      else
        failure="ShellCheck shard $(shard_label "$shard") was killed after ${shard_elapsed} seconds, before its deadline (out of memory?)"
      fi
      ;;
    '')
      failure="ShellCheck shard $(shard_label "$shard") reported no status"
      ;;
    *)
      failure="ShellCheck shard $(shard_label "$shard") failed with status ${shard_status}"
      failure_status="$shard_status"
      ;;
  esac
  if [[ -n "$failure" ]]; then
    if [[ "${#shard_failures[@]}" -eq 0 ]]; then
      shellcheck_status="$failure_status"
    fi
    shard_failures+=("$failure")
  fi
done
printf 'ShellCheck analysis: finish (status=%s elapsed_seconds=%s)\n' \
  "$shellcheck_status" "$shellcheck_elapsed_seconds"
if [[ "${#shard_failures[@]}" -gt 0 ]]; then
  printf '%s\n' "${shard_failures[@]}" >&2
  exit "$shellcheck_status"
fi

findings_json="$(jq -s '{comments: (map(.comments) | add // [])}' \
  "${shard_reports[@]}")"
expected_findings="$(printf '%s\n' "$SHELLCHECK_BASELINE_TSV" | normalize_baseline)"
actual_findings="$(printf '%s\n' "$findings_json" | group_findings)"
compare_findings "$expected_findings" "$actual_findings" || {
  printf 'ShellCheck warning set differs from the reviewed baseline\n' >&2
  exit 1
}
printf 'ShellCheck warning ratchet: OK (%s scripts, %s shards, %s reviewed groups)\n' \
  "${#shell_files[@]}" "$shard_count" \
  "$(printf '%s\n' "$SHELLCHECK_BASELINE_TSV" \
    | awk '/^[^#[:space:]]/ { count++ } END { print count + 0 }')"
