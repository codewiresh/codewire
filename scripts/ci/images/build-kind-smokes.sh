#!/usr/bin/env bash
# Build the host programs the Kind smoke suites run, one cargo build per group
# of the smoke inventory (scripts/ci/verify/kind/smokes.txt), and record the
# no-run test artifact of its test targets (the billing fixture).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly MANIFEST="$ROOT/scripts/ci/verify/kind/smokes.txt"

if [[ $# -ne 1 || -z "$1" ]]; then
  printf 'usage: %s BILLING_TEST_ARTIFACT_JSONL\n' "$0" >&2
  exit 2
fi

billing_artifact_jsonl="$1"
# The cargo commands, one line per group in the inventory's order. A group is
# one crate and one feature set; a test target writes its artifact record.
commands="$(awk '
  function fail(message) { printf "%s:%d: %s\n", FILENAME, FNR, message > "/dev/stderr"; failed = 1; exit 2 }
  /^[[:space:]]*(#|$)/ { next }
  NF != 5 { fail("want GROUP CRATE FEATURES KIND NAME") }
  {
    for (i = 1; i <= 5; i++) if ($i !~ /^[a-z0-9][a-z0-9_,-]*$/ && !(i == 3 && $i == "-")) fail("invalid field " $i)
    if ($4 != "bin" && $4 != "example" && $4 != "test") fail("unknown kind " $4)
    if (!($1 in crate)) { order[++groups] = $1; crate[$1] = $2; features[$1] = $3; kind[$1] = $4 }
    if (crate[$1] != $2 || features[$1] != $3) fail("group " $1 " mixes crates or feature sets")
    if ((kind[$1] == "test") != ($4 == "test")) fail("group " $1 " mixes a test target with programs")
    args[$1] = args[$1] " --" $4 " " $5
  }
  END {
    if (failed) exit 2
    for (i = 1; i <= groups; i++) {
      g = order[i]
      feature = features[g] == "-" ? "" : " --features " features[g]
      if (kind[g] == "test")
        printf "cargo test --locked --profile ci -p %s%s%s --no-run --message-format=json %s\"$1\"\n", crate[g], args[g], feature, (tests++ ? ">>" : ">")
      else
        printf "cargo build --locked --profile ci -p %s%s%s\n", crate[g], args[g], feature
    }
  }
' "$MANIFEST")"
started_at="$(date +%s)"
(
  cd "$ROOT"
  "$ROOT/scripts/ci/verify/run-host-rust-build.sh" bash -ceu "$commands" -- "$billing_artifact_jsonl"
)
printf 'CODEWIRE_CI_PHASE name=kind-smoke-binary-build seconds=%s\n' \
  "$(( $(date +%s) - started_at ))"
