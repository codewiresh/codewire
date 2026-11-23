#!/usr/bin/env bash
# Queue a pull request for the merge queue (infra tools/merge-queue, infra#2599),
# with merge-pr.sh's checks: a public-safe commit title and a merge Cargo
# accepts. The queue squashes it once its head is green and approved, as
# "TITLE (#N)" with "Reviewed-on: #N", the message merge-pr.sh writes.
# It also builds the pull request's code, merged with main, as the caller:
# its build scripts and proc macros run here. Queue only what you would build.
set -euo pipefail

if [[ $# == 1 && ( "$1" == --help || "$1" == -h ) ]]; then
  printf 'usage: scripts/dev/queue-pr.sh PR_NUMBER "COMMIT TITLE"\n'
  exit 0
fi
if [[ $# != 2 || ! "$1" =~ ^[1-9][0-9]*$ || -z "$2" || "$2" == *$'\n'* || "$2" == *$'\r'* || "$2" == *'Reviewed-on:'* ]]; then
  printf 'usage: scripts/dev/queue-pr.sh PR_NUMBER "COMMIT TITLE"\n' >&2
  exit 2
fi
# Main's copy of this script and of the helpers it runs does the queueing,
# whatever the caller's branch carries: a branch cut before a check landed
# would otherwise queue without it (#5664's compile check was skipped by every
# PR worktree older than it). The copy runs with the caller's checkout as its
# repository, for its git objects and its warm target.
here="$(cd "$(dirname "$0")/../.." && pwd -P)"
if [[ -z "${QUEUE_PR_CALLER-}" ]]; then
  git -C "$here" fetch -q --no-write-fetch-head origin "+refs/heads/main:refs/queue-pr/$$/self"
  copy="$(mktemp -d "${TMPDIR:-/tmp}/queue-pr.XXXXXX")"
  if ! git -C "$here" archive "refs/queue-pr/$$/self" \
      scripts/dev/queue-pr.sh scripts/dev/queue_pr_packages.py scripts/checks | tar -x -C "$copy"; then
    rm -rf -- "$copy"
    git -C "$here" update-ref -d "refs/queue-pr/$$/self"
    printf "queue-pr.sh: could not read main's copy of queue-pr.sh\n" >&2
    exit 1
  fi
  git -C "$here" update-ref -d "refs/queue-pr/$$/self"
  QUEUE_PR_CALLER="$here" QUEUE_PR_COPY="$copy" exec bash "$copy/scripts/dev/queue-pr.sh" "$@"
fi
copy_root=''
if [[ -n "${QUEUE_PR_COPY-}" ]]; then
  # The copy's path comes in through the environment, and it is removed on
  # exit: it must be this very run's copy, a queue-pr.* directory directly
  # under the temporary directory, or nothing is removed and nothing queued.
  # Paths are compared with symlinks resolved, and only the resolved path is
  # removed, so a link can't make the check and the removal see different
  # directories.
  copy_root="$(cd "$QUEUE_PR_COPY" 2>/dev/null && pwd -P)" || copy_root=''
  tmp_root="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" || tmp_root=''
  if [[ -z "$copy_root" || "$copy_root" != "$here" || "${copy_root%/*}" != "$tmp_root" ||
    "${copy_root##*/}" != queue-pr.* ]]; then
    printf "queue-pr.sh: QUEUE_PR_COPY is not this run's copy of main's queue-pr.sh; nothing was queued\n" >&2
    exit 1
  fi
  trap 'rm -rf -- "$copy_root"' EXIT
fi
pr="$1" title="$2"
# The title becomes a commit on main and on the public mirror, and it cannot be
# changed afterwards. A placeholder is refused: #4834's pull request was
# created with the title "x", and main carries "x (#4834)". Among main's last
# 3,000 subjects the rule refuses only that one; the shortest real title is
# "style: rustfmt", 14 characters and two words.
subject="${title% (#"$pr")}"
read -ra words <<<"$subject"
if [[ ${#subject} -lt 10 || ${#words[@]} -lt 2 ]]; then
  printf 'queue-pr.sh: "%s" is not a commit title: it needs at least 10 characters and two words\n' "$subject" >&2
  exit 2
fi
[[ "$title" == *" (#$pr)" ]] || title="$title (#$pr)"

# A pull request's CI checks its own head, so two valid Cargo lockfiles can
# still merge textually into one Cargo refuses (b34cf2bb: a bare "base64" once
# main locked two). Check every lockfile of the merge itself before merging.
root="$QUEUE_PR_CALLER"
# Every session shares the canonical checkout, so FETCH_HEAD and
# refs/remotes/origin/main move under a concurrent fetch: the pull request's
# head and main go into refs of this run's own, removed on exit.
refs="refs/queue-pr/$$"
cleanup() {
  git -C "$root" update-ref -d "$refs/head" 2>/dev/null || true
  git -C "$root" update-ref -d "$refs/main" 2>/dev/null || true
  [[ -z "$copy_root" ]] || rm -rf -- "$copy_root"
}
trap cleanup EXIT
git -C "$root" fetch -q --no-write-fetch-head origin "+refs/pull/$pr/head:$refs/head" "+refs/heads/main:$refs/main"
head="$(git -C "$root" rev-parse --verify "$refs/head^{commit}")"
base="$(git -C "$root" rev-parse --verify "$refs/main^{commit}")"
if ! tree="$(git -C "$root" merge-tree --write-tree "$base" "$head")"; then
  printf 'queue-pr.sh: #%s does not merge cleanly with main\n' "$pr" >&2
  exit 1
fi
while IFS= read -r lock; do
  if ! git -C "$root" show "$tree:$lock" |
      python3 "$here/scripts/checks/repo_checks.py" cargo-lock-integrity --lock - --label "merged $lock"; then
    printf 'queue-pr.sh: #%s would leave main with a %s Cargo refuses; merge main into it and update the lock\n' \
      "$pr" "$lock" >&2
    exit 1
  fi
done < <(git -C "$root" ls-tree -r --name-only "$tree" | grep -E '(^|/)([A-Za-z0-9_-]+\.)?Cargo\.lock$')

# A closing keyword closes its issue when the pull request merges, whatever
# follows it: "Closes #5949 once observed on Dev" closed #5949 the moment #5970
# landed. A condition after it is refused before any build slot is spent.
if ! body="$(fj pr -R origin view "$pr" body)"; then
  printf 'queue-pr.sh: could not read #%s description; nothing was queued\n' "$pr" >&2
  exit 1
fi
if conditional="$(grep -inP '(?<![\w-])(close[sd]?|fix(es|ed)?|resolve[sd]?):?\s+([\w.-]+/[\w.-]+)?#[0-9]+[,(]?\s*\(?(once|after|when|until)\b' <<<"$body")"; then
  printf '%s\n' "$conditional" >&2
  printf 'queue-pr.sh: #%s closes an issue on merge, not once a condition holds; write "For #N" there instead and close the issue yourself\n' \
    "$pr" >&2
  exit 1
fi

# The merge must also compile. A pull request's CI builds its own head, and a
# change that landed since can break it on main's tree: #5512 met main's new
# `pinned` field in BrokerUpstreamRequest, which cost an 85-minute bisection
# (2026-11-20). So check the Rust packages it touches, every target and
# feature as CI's compile-all-targets does, on the merge itself, in the build
# slot, with the calling worktree's own warm target. Direct dependents too cost
# a broad PR about ten minutes of slot, so they wait for a day of numbers
# (cw-orchestrator). A pull request that touches no Rust package is not checked.
merge="$(git -C "$root" commit-tree "$tree" -p "$base" -p "$head" -m "queue-pr.sh: #$pr merged with main")"
mapfile -t changed < <(git -C "$root" diff --name-only --no-renames "$base...$head")
rust=0
for path in "${changed[@]}"; do [[ "$path" =~ (\.rs|Cargo\.toml|Cargo\.lock)$ ]] && rust=1; done
packages=()
if [[ $rust == 1 ]]; then
# One copy of the merge per calling worktree, kept between runs and moved to
# each new merge by a checkout, which rewrites only the files that differ: the
# rest keep their times, so cargo reuses its work on them. A clone sharing this
# worktree's objects, not a worktree: nothing is added to the shared checkout.
cache="${XDG_CACHE_HOME:-$HOME/.cache}/codewire-queue-pr"
mkdir -p "$cache"
key="$(printf '%s' "$root" | sha256sum | cut -c1-16)"
check_dir="$cache/$key"
if command -v flock >/dev/null; then
  exec 9>"$cache/$key.lock"
  if ! flock -n 9; then
    printf 'queue-pr.sh: waiting for another queue-pr.sh check from this worktree\n' >&2
    flock 9
  fi
fi
[[ -d "$check_dir/.git" ]] || git clone -q --shared --no-checkout "$root" "$check_dir"
git -C "$check_dir" checkout -q -f --detach "$merge"
git -C "$check_dir" clean -q -fdx
# Unreadable metadata stops here rather than checking nothing.
if ! metadata="$(cd "$check_dir" && cargo metadata --locked --no-deps --format-version 1)"; then
  printf 'queue-pr.sh: cargo metadata failed on #%s merged with main\n' "$pr" >&2
  exit 1
fi
# A mapper that fails refuses too, rather than reading as "no package".
if ! mapped="$(python3 "$here/scripts/dev/queue_pr_packages.py" "${changed[@]}" <<<"$metadata")"; then
  printf 'queue-pr.sh: could not map #%s changed files to packages\n' "$pr" >&2
  exit 1
fi
mapfile -t packages < <(grep -v '^$' <<<"$mapped" || true)
fi
# A change only to the workspace's own Cargo.toml or Cargo.lock (a dependency
# bump) belongs to no package, so it is not checked: checking the whole
# workspace for it costs more build slot than one PR should (cw-orchestrator).
# The batch's CI is what checks it; say so rather than pass it silently.
if [[ $rust == 1 && ${#packages[@]} -eq 0 ]]; then
  printf 'queue-pr.sh: #%s changes Rust only in workspace-level files; not compile-checked here, the batch CI checks it\n' "$pr" >&2
fi
if [[ ${#packages[@]} -gt 0 ]]; then
  check=(cargo check --locked --all-targets --all-features)
  # A build script that hangs, or a fetch the firewall drops, must not hold a
  # build slot without end.
  command -v timeout >/dev/null && check=(timeout "${QUEUE_PR_CHECK_TIMEOUT:-1800}" "${check[@]}")
  for package in "${packages[@]}"; do check+=(-p "$package"); done
  command -v codewire-cpu >/dev/null && check=(codewire-cpu build -- "${check[@]}")
  printf 'queue-pr.sh: compile-checking #%s merged with main: %s\n' "$pr" "${packages[*]}" >&2
  started="$(date +%s)"
  status=0
  (cd "$check_dir" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}" "${check[@]}" \
    >"$cache/$key.log" 2>&1) || status=$?
  if [[ $status == 124 ]]; then
    # timeout's own status: the check ran out of time, which says nothing of the code.
    printf 'queue-pr.sh: the compile check of #%s timed out after %ss; nothing was queued, run it again\n' \
      "$pr" "${QUEUE_PR_CHECK_TIMEOUT:-1800}" >&2
    exit 1
  elif [[ $status == 75 ]] && grep -q '^codewire-cpu: ' "$cache/$key.log"; then
    # codewire-cpu's own refusal, for want of disk space: the check never ran.
    reason="$(grep '^codewire-cpu: ' "$cache/$key.log" | grep -v ' waited ' | tail -1 || true)"
    printf 'queue-pr.sh: #%s not checked: build slot refused (%s); nothing was queued, run it again once that clears\n' \
      "$pr" "${reason#codewire-cpu: }" >&2
    exit 1
  elif [[ $status != 0 ]]; then
    grep -E '^(error|warning: unused)|^ *--> ' "$cache/$key.log" | head -40 >&2 || tail -40 "$cache/$key.log" >&2
    printf 'queue-pr.sh: #%s does not compile merged with main; merge main into it and fix it\n' "$pr" >&2
    exit 1
  fi
  # Seconds in all, seconds waiting for a build slot, and the packages: kept to
  # measure what the check costs (cw-orchestrator, 2026-11-20).
  # codewire-cpu reports its wait as it grows: the last report is the whole wait.
  # No line at all when a slot was free at once, or without codewire-cpu.
  waited="$(grep -o 'waited [0-9]*s' "$cache/$key.log" | tail -1 | tr -dc '0-9' || true)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$pr" "$(( $(date +%s) - started ))" "${waited:-0}" "${packages[*]}" \
    >>"$cache/times.tsv"
fi

fj pr -R origin edit "$pr" title "$subject" >/dev/null
fj pr -R origin edit "$pr" labels -a merge-queue >/dev/null
# fj can print nothing and change nothing: the label is read back.
# Exactly merge-queue: merge-queue-solo alone queues nothing.
if ! fj pr -R origin view "$pr" labels 2>/dev/null | tr -s ', \t' '\n' | grep -qxF merge-queue; then
  printf 'queue-pr.sh: #%s does not carry the merge-queue label after adding it; run this again\n' "$pr" >&2
  exit 1
fi
printf 'queue-pr.sh: #%s is queued as "%s (#%s)"; the merge queue lands it once Required verification is green and codewire-review-bot approved its head\n' \
  "$pr" "$subject" "$pr"
