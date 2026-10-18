#!/usr/bin/env bash
# Refuse to mirror commits that carry a secret or text that must stay private.
#
# usage: check-mirror-content.sh REMOTE_HEAD [HEAD]
#
# REMOTE_HEAD is the commit the mirror's main points at. Everything after it up
# to HEAD (default: HEAD) is scanned: gitleaks over the range with the
# repository policy, and public-content-patterns.txt over added diff lines and
# commit messages. A finding names the commit and the pattern number, never the
# matched text. The owner clears a finding by fixing it, or through a reviewed
# change to .gitleaks.toml or .gitleaks-baseline.json. An unknown or
# non-ancestor REMOTE_HEAD fails closed: the first push to an empty mirror is
# made by hand after the history filter's own verification.
set -euo pipefail

fail() {
  printf '[check-mirror-content] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -ge 1 && $# -le 2 ]] || {
  printf 'usage: check-mirror-content.sh REMOTE_HEAD [HEAD]\n' >&2
  exit 2
}
readonly base="$1"
readonly head="${2:-HEAD}"

root="$(git rev-parse --show-toplevel)"
readonly root
readonly patterns="$root/scripts/ci/release/public-content-patterns.txt"
[[ -f "$patterns" ]] || fail 'the public-content pattern file is missing'

[[ "$base" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'the mirror head is unknown; make the first push by hand after the history filter verification'
git -C "$root" cat-file -e "${base}^{commit}" 2>/dev/null ||
  fail 'the mirror head is not in this checkout; fetch full history or push by hand'
git -C "$root" merge-base --is-ancestor "$base" "$head" ||
  fail 'the mirror head is not an ancestor of the commit being mirrored'
readonly range="$base..$head"

if [[ -z "$(git -C "$root" rev-list -n 1 "$range")" ]]; then
  printf '[check-mirror-content] no new commits to mirror\n'
  exit 0
fi

status=0
number=0
while IFS= read -r pattern; do
  [[ -n "$pattern" && "$pattern" != '#'* ]] || continue
  number=$((number + 1))
  # The pattern travels in the environment: awk -v would process its escapes.
  added="$(git -C "$root" log --no-color -p -U0 --format='@@commit %h' "$range" |
    PATTERN="$pattern" awk 'BEGIN{p=ENVIRON["PATTERN"]} /^@@commit /{c=$2; next} /^\+\+\+ /{next} /^\+/{ if (substr($0, 2) ~ p) print c }' |
    sort -u | tr '\n' ' ')"
  messages="$(git -C "$root" log --no-color --format='@@commit %h%n%B' "$range" |
    PATTERN="$pattern" awk 'BEGIN{p=ENVIRON["PATTERN"]} /^@@commit /{c=$2; next} { if ($0 ~ p) print c }' |
    sort -u | tr '\n' ' ')"
  if [[ -n "$added" ]]; then
    printf '[check-mirror-content] pattern %s found in added lines of: %s\n' "$number" "$added" >&2
    status=1
  fi
  if [[ -n "$messages" ]]; then
    printf '[check-mirror-content] pattern %s found in the messages of: %s\n' "$number" "$messages" >&2
    status=1
  fi
done <"$patterns"

command -v gitleaks >/dev/null || fail 'gitleaks is required to mirror'
gitleaks_args=(git --no-banner --redact --exit-code 23
  --config "$root/.gitleaks.toml" --log-opts="$range")
if [[ -f "$root/.gitleaks-baseline.json" ]]; then
  gitleaks_args+=(--baseline-path "$root/.gitleaks-baseline.json")
fi
gitleaks_status=0
gitleaks "${gitleaks_args[@]}" "$root" >/dev/null 2>&1 || gitleaks_status=$?
if [[ "$gitleaks_status" -ne 0 ]]; then
  printf '[check-mirror-content] gitleaks reported a finding in %s (exit %s); inspect it locally with: gitleaks git --redact --log-opts=%s\n' \
    "$range" "$gitleaks_status" "$range" >&2
  status=1
fi

[[ "$status" -eq 0 ]] || fail "the commits in $range must not be mirrored"
printf '[check-mirror-content] %s commits in %s are clean\n' \
  "$(git -C "$root" rev-list --count "$range")" "$range"
