#!/usr/bin/env bash
# Refuse commits that carry a secret or text that must stay private.
#
# usage: check-mirror-content.sh [--patterns FILE] [--no-gitleaks] REMOTE_HEAD [HEAD]
#        check-mirror-content.sh --pull-request [--patterns FILE] [--no-gitleaks]
#                                [--message-file FILE] BASE HEAD
#        check-mirror-content.sh --tree [--patterns FILE] [HEAD]
#
# REMOTE_HEAD is the commit the mirror's main points at. Everything after it up
# to HEAD (default: HEAD) is scanned: gitleaks over the range with the
# repository policy, and two pattern lists over added diff lines and commit
# messages: the generic, tracked public-content-patterns.txt, and the private
# names that must stay out of the tracked tree, which arrive as newline-separated
# extended regular expressions in MIRROR_PRIVATE_CONTENT_PATTERNS (the mirror
# workflow passes the Forgejo Actions variable of the same name). A finding
# names the commit and the pattern number, never the matched text or the
# pattern. The owner clears a finding by fixing it, or through a reviewed change
# to .gitleaks.toml or .gitleaks-baseline.json. An unknown or non-ancestor
# REMOTE_HEAD fails closed: the first push to an empty mirror is made by hand
# after the history filter's own verification.
#
# --pull-request runs the same scan before merge, so nothing waits for the
# mirror to find it. It scans the commits after the merge base of BASE and HEAD,
# so a branch behind main is not blamed for main's own changes, and the
# --message-file text (the pull request's title and body, which the squash
# commit's message comes from). Its caller passes --patterns from the protected
# base; a candidate's own pattern file is never trusted to scan itself.
#
# --tree scans every tracked text file at HEAD, naming the file and line, never
# the text. The shared policy core runs it with the tracked patterns, so a
# committed home directory or similar fails before any push.
#
# A pattern line may be followed by an "except: REGEX" line. Matches of the
# exception are blanked from the text before the pattern is tested, so a rule
# keeps its reviewed allow-list beside it.
#
# Without private patterns the range scans fail closed. Only a local test run
# outside CI may scan with the tracked patterns alone, by setting
# MIRROR_CONTENT_LOCAL_TEST=1; CI refuses that flag. The tree scan uses the
# private patterns only when they are set.
set -euo pipefail

fail() {
  printf '[check-mirror-content] ERROR: %s\n' "$*" >&2
  exit 1
}
usage() {
  printf 'usage: check-mirror-content.sh [--pull-request|--tree] [--patterns FILE] [--no-gitleaks] [--message-file FILE] BASE [HEAD]\n' >&2
  exit 2
}

mode=mirror patterns='' gitleaks=1 message_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pull-request) mode=pull-request ;;
    --tree) mode=tree ;;
    --patterns) [[ $# -ge 2 ]] || usage; patterns="$2"; shift ;;
    --no-gitleaks) gitleaks=0 ;;
    --message-file) [[ $# -ge 2 ]] || usage; message_file="$2"; shift ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
  shift
done
case "$mode" in
  mirror) [[ $# -ge 1 && $# -le 2 ]] || usage ;;
  pull-request) [[ $# -eq 2 ]] || usage ;;
  tree) [[ $# -le 1 ]] || usage ;;
esac
[[ -z "$message_file" || "$mode" == pull-request ]] || usage

root="$(git rev-parse --show-toplevel)"
readonly root mode gitleaks message_file
[[ -n "$patterns" ]] || patterns="$root/scripts/ci/release/public-content-patterns.txt"
readonly patterns
[[ -f "$patterns" && ! -L "$patterns" ]] || fail 'the public-content pattern file is missing'

# Keep only pattern lines: blank lines and comments carry no pattern, and a
# carriage return from a web form would silently stop a pattern matching.
pattern_lines() { tr -d '\r' | grep -Ev '^[[:space:]]*(#|$)' || true; }

# load_patterns NAME LABEL: read pattern lines from stdin into the parallel
# arrays NAME_patterns and NAME_excepts. An "except: REGEX" line belongs to the
# pattern line before it.
load_patterns() {
  local -n loaded_patterns="$1_patterns" loaded_excepts="$1_excepts"
  local line
  while IFS= read -r line; do
    if [[ "$line" == 'except: '* ]]; then
      [[ ${#loaded_patterns[@]} -gt 0 && -z "${loaded_excepts[-1]}" ]] ||
        fail "the $2 have an except line without its own pattern"
      loaded_excepts[-1]="${line#except: }"
    else
      loaded_patterns+=("$line")
      loaded_excepts+=('')
    fi
  done < <(pattern_lines)
}

tracked_patterns=() tracked_excepts=() private_patterns=() private_excepts=()
load_patterns tracked 'tracked patterns' <"$patterns"
load_patterns private 'private patterns' < <(printf '%s\n' "${MIRROR_PRIVATE_CONTENT_PATTERNS:-}")
if [[ ${#private_patterns[@]} -eq 0 && "$mode" != tree ]]; then
  if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    fail 'MIRROR_PRIVATE_CONTENT_PATTERNS is empty; set the Forgejo Actions variable before mirroring'
  fi
  [[ "${MIRROR_CONTENT_LOCAL_TEST:-}" == 1 ]] ||
    fail 'MIRROR_PRIVATE_CONTENT_PATTERNS is empty; set it, or MIRROR_CONTENT_LOCAL_TEST=1 for a local test run'
  printf '[check-mirror-content] local test run: scanning with the tracked patterns only\n' >&2
fi

# The match, shared by every scan: blank the exception's matches, then test.
# Blanking with a space keeps text on either side of an allowed match apart.
# Patterns travel in the environment: awk -v would process their escapes.
readonly MATCH='BEGIN { p = ENVIRON["PATTERN"]; x = ENVIRON["EXCEPT"] }
function hit(text) { if (x != "") gsub(x, " ", text); return text ~ p }'

status=0

# valid LABEL PATTERN EXCEPT: fail by label, never by text, when either is not
# an extended regular expression. awk's diagnostics would quote them.
valid() {
  PATTERN="$2" EXCEPT="$3" awk "$MATCH"' BEGIN { hit("") }' 2>/dev/null </dev/null ||
    fail "$1 is not a valid extended regular expression"
}

# scan_range LABEL PATTERN EXCEPT: report the commits in the range whose added
# lines or messages match.
scan_range() {
  local label="$1" added messages text
  added="$(git -C "$root" log --no-color -p -U0 --format='@@commit %h' "$range" |
    PATTERN="$2" EXCEPT="$3" awk "$MATCH"'
      /^@@commit /{c=$2; next} /^\+\+\+ /{next} /^\+/{ if (hit(substr($0, 2))) print c }' 2>/dev/null |
    sort -u | tr '\n' ' ')"
  messages="$(git -C "$root" log --no-color --format='@@commit %h%n%B' "$range" |
    PATTERN="$2" EXCEPT="$3" awk "$MATCH"' /^@@commit /{c=$2; next} { if (hit($0)) print c }' 2>/dev/null |
    sort -u | tr '\n' ' ')"
  if [[ -n "$added" ]]; then
    printf '[check-mirror-content] %s found in added lines of: %s\n' "$label" "$added" >&2
    status=1
  fi
  if [[ -n "$messages" ]]; then
    printf '[check-mirror-content] %s found in the messages of: %s\n' "$label" "$messages" >&2
    status=1
  fi
  if [[ -n "$message_file" ]]; then
    text="$(PATTERN="$2" EXCEPT="$3" awk "$MATCH"' { if (hit($0)) { print "hit"; exit } }' \
      "$message_file" 2>/dev/null)"
    if [[ -n "$text" ]]; then
      printf '[check-mirror-content] %s found in the pull request title or body\n' "$label" >&2
      status=1
    fi
  fi
}

# scan_tree LABEL PATTERN EXCEPT: report the tracked text files and lines that
# match, at most twenty, by path and line number only.
scan_tree() {
  local label="$1" found
  found="$(git -C "$root" grep -I --name-only -z -e '' "$head" -- . |
    sed -z "s|^$head:||" |
    (cd "$root" && PATTERN="$2" EXCEPT="$3" xargs -0 -r awk "$MATCH"' { if (hit($0)) print FILENAME ":" FNR }' \
      2>/dev/null) | head -n 20 | tr '\n' ' ')"
  if [[ -n "$found" ]]; then
    printf '[check-mirror-content] %s found at: %s\n' "$label" "$found" >&2
    status=1
  fi
}

case "$mode" in
  mirror)
    readonly base="$1" head="${2:-HEAD}"
    [[ "$base" =~ ^[0-9a-f]{40}$ ]] ||
      fail 'the mirror head is unknown; make the first push by hand after the history filter verification'
    git -C "$root" cat-file -e "${base}^{commit}" 2>/dev/null ||
      fail 'the mirror head is not in this checkout; fetch full history or push by hand'
    git -C "$root" merge-base --is-ancestor "$base" "$head" ||
      fail 'the mirror head is not an ancestor of the commit being mirrored'
    range="$base..$head"
    ;;
  pull-request)
    readonly head="$2"
    [[ "$1" =~ ^[0-9a-f]{40}$ && "$head" =~ ^[0-9a-f]{40}$ ]] ||
      fail 'a pull request scan takes full base and head commits'
    for commit in "$1" "$head"; do
      git -C "$root" cat-file -e "${commit}^{commit}" 2>/dev/null ||
        fail 'a pull request commit is not in this checkout; fetch its full history'
    done
    merge_base="$(git -C "$root" merge-base "$1" "$head")" ||
      fail 'the pull request has no merge base with its base branch'
    range="$merge_base..$head"
    if [[ -n "$message_file" ]]; then
      [[ -f "$message_file" && ! -L "$message_file" ]] || fail 'the pull request text is not a regular file'
    fi
    ;;
  tree)
    readonly head="${1:-HEAD}"
    git -C "$root" cat-file -e "${head}^{commit}" 2>/dev/null || fail 'the tree scan commit is not in this checkout'
    [[ "$head" == HEAD || -z "$(git -C "$root" status --porcelain --untracked-files=no)" ]] ||
      fail 'a tree scan of another commit needs a clean checkout'
    ;;
esac
readonly range="${range:-}"

if [[ "$mode" == mirror && -z "$(git -C "$root" rev-list -n 1 "$range")" ]]; then
  printf '[check-mirror-content] no new commits to mirror\n'
  exit 0
fi

scan() {
  if [[ "$mode" == tree ]]; then scan_tree "$@"; else scan_range "$@"; fi
}
for index in "${!tracked_patterns[@]}"; do
  valid "pattern $((index + 1))" "${tracked_patterns[index]}" "${tracked_excepts[index]}"
  scan "pattern $((index + 1))" "${tracked_patterns[index]}" "${tracked_excepts[index]}"
done
for index in "${!private_patterns[@]}"; do
  valid "private pattern $((index + 1))" "${private_patterns[index]}" "${private_excepts[index]}"
  scan "private pattern $((index + 1))" "${private_patterns[index]}" "${private_excepts[index]}"
done

if [[ "$mode" == tree ]]; then
  [[ "$status" -eq 0 ]] || fail 'committed text carries what the public-content patterns refuse'
  printf '[check-mirror-content] tracked text at %s is clean\n' "$head"
  exit 0
fi

if [[ "$gitleaks" == 1 ]]; then
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
fi

if [[ "$mode" == pull-request ]]; then
  [[ "$status" -eq 0 ]] || fail 'this pull request carries text that must not reach main or the public mirror'
else
  [[ "$status" -eq 0 ]] || fail "the commits in $range must not be mirrored"
fi
printf '[check-mirror-content] %s commits in %s are clean\n' \
  "$(git -C "$root" rev-list --count "$range")" "$range"
