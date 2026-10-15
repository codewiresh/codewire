#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/images/base/apt-get-with-retry"
readonly PRODUCTION_SECRET=/run/secrets/codewire-apt-mirror
readonly CI_MIRROR=http://apt-snapshot-cache.forgejo-runner-control.svc.cluster.local:8080
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "${TMPDIR:-$ROOT/.tmp}/apt-get-with-retry.XXXXXX")"
readonly TEST_TMP
trap 'rm -rf "$TEST_TMP"' EXIT

fail() {
  printf '[test-apt-get-with-retry] ERROR: %s\n' "$*" >&2
  exit 1
}

# The helper binds the BuildKit secret path. A fixture copy differs from the
# production bytes only in that one declaration, so mirror cases can supply the
# secret without root while canonical cases still execute the real helper.
readonly MIRROR_SECRET="$TEST_TMP/secret/codewire-apt-mirror"
readonly MIRROR_HELPER="$TEST_TMP/apt-get-with-retry-mirror-fixture"
mkdir "$TEST_TMP/secret"
[[ "$(grep -cxF "readonly mirror_secret=$PRODUCTION_SECRET" "$HELPER")" == 1 ]] \
  || fail 'helper does not bind the BuildKit secret path exactly once'
sed "s|^readonly mirror_secret=$PRODUCTION_SECRET\$|readonly mirror_secret=$MIRROR_SECRET|" "$HELPER" >"$MIRROR_HELPER"
chmod 0755 "$MIRROR_HELPER"
[[ "$(diff "$HELPER" "$MIRROR_HELPER" | grep -c '^[<>]' || true)" == 2 ]] \
  || fail 'mirror fixture helper differs from production beyond the secret path'

mkdir -p "$TEST_TMP/bin"
ln -s /usr/bin/bash "$TEST_TMP/bin/bash"
ln -s /usr/bin/mktemp "$TEST_TMP/bin/mktemp"
ln -s /usr/bin/rm "$TEST_TMP/bin/rm"
cat >"$TEST_TMP/bin/apt-get" <<'SH'
#!/usr/bin/bash
set -euo pipefail
count="$(<"$FAKE_APT_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" >"$FAKE_APT_STATE"
printf '%s\0' "$@" >"$FAKE_APT_ARGV.$count"
rendered='' update=false
for arg in "$@"; do
  case "$arg" in
    Dir::Etc::SourceParts=*) rendered="${arg#*=}" ;;
    update) update=true ;;
  esac
done
if [[ -n "$rendered" ]]; then
  # Snapshot exactly what APT would read during this transaction.
  [[ -d "$rendered" ]] || exit 94
  /usr/bin/cp -R -- "$rendered" "$FAKE_APT_ARGV.$count.rendered"
fi
IFS=, read -r -a results <<<"$FAKE_APT_RESULTS"
result="${results[$((count - 1))]:-unexpected}"
case "$result" in
  partial)
    # Model APT's native transient-index behavior: warning/0 by default,
    # error/100 with the last effective update error-mode set to any.
    error_mode=persistent
    for arg in "$@"; do
      case "$arg" in APT::Update::Error-Mode=*) error_mode="${arg#*=}" ;; esac
    done
    printf 'Some index files failed to download\n' >&2
    [[ "$error_mode" != any ]] || exit 100
    exit 0 ;;
  hang)
    child_pid=''
    terminate() {
      if [[ -n "$child_pid" ]]; then
        kill -TERM "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
      fi
      printf 'TERM\n' >"$FAKE_APT_ARGV.$count.terminated"
      exit 143
    }
    trap terminate TERM
    /usr/bin/sleep 10 &
    child_pid=$!
    printf '%s\n' "$$" >"$FAKE_APT_ARGV.$count.apt-pid"
    printf '%s\n' "$child_pid" >"$FAKE_APT_ARGV.$count.child-pid"
    wait "$child_pid"
    exit 96 ;;
  ''|*[!0-9]*) exit 97 ;;
  *)
    if [[ "$result" == 0 && "$update" == true ]]; then
      # A successful update replaces every list. Lists fetched through the
      # mirror carry its host in their names, like APT's URItoFileName.
      /usr/bin/rm -f -- "$FAKE_LISTS"/*
      if [[ -n "$rendered" ]]; then
        : >"$FAKE_LISTS/${FAKE_MIRROR_LIST_HOST}_ubuntu_20260803T000000Z_dists_noble_InRelease"
      else
        : >"$FAKE_LISTS/snapshot.ubuntu.com_ubuntu_20260803T000000Z_dists_noble_InRelease"
      fi
    fi
    exit "$result" ;;
esac
SH
chmod 0755 "$TEST_TMP/bin/apt-get"

cat >"$TEST_TMP/bin/apt-config" <<'SH'
#!/usr/bin/bash
set -euo pipefail
printf 'called\n' >>"$FAKE_APT_CONFIG_LOG"
[[ "$*" == 'shell source_list Dir::Etc::sourcelist/f source_parts Dir::Etc::sourceparts/d list_dir Dir::State::lists/d' ]] || exit 95
printf "source_list='%s'\nsource_parts='%s/'\nlist_dir='%s/'\n" \
  "$FAKE_ETC/sources.list" "$FAKE_ETC/sources.list.d" "$FAKE_LISTS"
SH
chmod 0755 "$TEST_TMP/bin/apt-config"

cat >"$TEST_TMP/bin/sleep" <<'SH'
#!/usr/bin/bash
set -euo pipefail
[[ $# == 1 && "$1" =~ ^(30|60|120|240|300)$ ]] || exit 98
printf '%s\n' "$1" >>"$FAKE_SLEEP_LOG"
SH
chmod 0755 "$TEST_TMP/bin/sleep"

cat >"$TEST_TMP/bin/timeout" <<'SH'
#!/usr/bin/bash
set -euo pipefail
[[ $# -ge 4 && "$1" == --signal=TERM && "$2" == --kill-after=3s \
  && "$3" == 300s && "$4" == apt-get ]] || exit 99
count="$(<"$FAKE_TIMEOUT_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" >"$FAKE_TIMEOUT_STATE"
printf '%s\0' "$@" >"$FAKE_TIMEOUT_ARGV.$count"
shift 3
# Validate the production bound above, then shorten only the fixture deadline.
# The real GNU timeout still delivers TERM and owns its ordinary process group.
exec /usr/bin/timeout --signal=TERM --kill-after=3s 1s "$@"
SH
chmod 0755 "$TEST_TMP/bin/timeout"

cat >"$TEST_TMP/update-and-install" <<'SH'
#!/usr/bin/bash
set -euo pipefail
"$APT_HELPER_UNDER_TEST" "$@" && "$APT_HELPER_UNDER_TEST" install -y package-one
SH

# Configured APT sources: the real image snapshot definitions plus lines that
# must survive byte-for-byte (comments, other hosts, plain HTTP, and a host
# that merely begins with a snapshot hostname).
readonly SNAPSHOT_ETC="$TEST_TMP/etc-snapshot"
readonly PLAIN_ETC="$TEST_TMP/etc-plain"
mkdir -p "$SNAPSHOT_ETC/sources.list.d" "$PLAIN_ETC/sources.list.d"
cat >"$SNAPSHOT_ETC/sources.list" <<'EOF'
# deb https://snapshot.ubuntu.com/ubuntu/20260803T000000Z/ noble main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/20251208T000000Z/ bookworm main
deb https://deb.example.invalid/debian bookworm main
EOF
cp "$ROOT/images/base/ubuntu.sources" "$SNAPSHOT_ETC/sources.list.d/ubuntu.sources"
cp "$ROOT/images/workspace/debian.sources" "$SNAPSHOT_ETC/sources.list.d/debian.sources"
cat >"$SNAPSHOT_ETC/sources.list.d/extra.list" <<'EOF'
deb http://snapshot.ubuntu.com/ubuntu/20260803T000000Z/ noble main
deb https://snapshot.ubuntu.com.example.invalid/ubuntu noble main
deb https://snapshot.debian.org/file/0123456789abcdef0123456789abcdef01234567/ ./
EOF
printf 'deb https://snapshot.ubuntu.com/ubuntu/20260803T000000Z/ noble main\n' \
  >"$SNAPSHOT_ETC/sources.list.d/retired.list.disabled"
printf 'https://snapshot.debian.org/\n' >"$SNAPSHOT_ETC/sources.list.d/notes.txt"
printf 'deb https://deb.example.invalid/debian bookworm main\n' >"$PLAIN_ETC/sources.list.d/plain.list"
cat >"$PLAIN_ETC/sources.list.d/plain.sources" <<'EOF'
Types: deb
URIs: http://snapshot.debian.org/archive/debian/20251208T000000Z/
Suites: bookworm
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

tree_digest() {
  (cd "$1" && find . -print0 | LC_ALL=C sort -z | xargs -0 -r stat -c '%n %s %a' && find . -type f -print0 \
    | LC_ALL=C sort -z | xargs -0 -r sha256sum)
}
SNAPSHOT_ETC_DIGEST="$(tree_digest "$SNAPSHOT_ETC")"
PLAIN_ETC_DIGEST="$(tree_digest "$PLAIN_ETC")"
readonly SNAPSHOT_ETC_DIGEST PLAIN_ETC_DIGEST

# An independent sed oracle for the rendered copy APT must read.
expected_rendered() {
  local mirror="$1" destination="$2" name
  local rewrite="/^[[:space:]]*#/!{s#https://snapshot\\.ubuntu\\.com/#$mirror/#g;s#https://snapshot\\.debian\\.org/#$mirror/#g;}"
  mkdir "$destination"
  sed -e "$rewrite" "$SNAPSHOT_ETC/sources.list" >"$destination/0-sources.list"
  for name in debian.sources extra.list ubuntu.sources; do
    sed -e "$rewrite" "$SNAPSHOT_ETC/sources.list.d/$name" >"$destination/1-$name"
  done
  # Spot-check the oracle itself against the cache's 1:1 path contract.
  grep -qxF "URIs: $mirror/ubuntu/20260803T000000Z/" "$destination/1-ubuntu.sources"
  grep -qxF "URIs: $mirror/archive/debian/20251208T000000Z/" "$destination/1-debian.sources"
  grep -qxF "URIs: $mirror/archive/debian-security/20251208T000000Z/" "$destination/1-debian.sources"
  grep -qxF "deb $mirror/file/0123456789abcdef0123456789abcdef01234567/ ./" "$destination/1-extra.list"
  grep -qxF 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' "$destination/1-ubuntu.sources"
  [[ "$(grep -c '^Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg$' "$destination/1-debian.sources")" == 2 ]]
  grep -qxF '# deb https://snapshot.ubuntu.com/ubuntu/20260803T000000Z/ noble main' "$destination/0-sources.list"
  grep -qxF 'deb https://snapshot.ubuntu.com.example.invalid/ubuntu noble main' "$destination/1-extra.list"
  grep -qxF 'deb http://snapshot.ubuntu.com/ubuntu/20260803T000000Z/ noble main' "$destination/1-extra.list"
}

normalized_argv() {
  local file="$1" case_dir="$2" entry
  local -a entries
  mapfile -d '' -t entries <"$file"
  for entry in "${entries[@]}"; do
    if [[ "$entry" == Dir::Etc::SourceParts=* ]]; then
      [[ "${entry#*=}" =~ ^"$case_dir"/tmp/codewire-apt-sources\.[A-Za-z0-9]{6}$ ]] || return 1
      entry='Dir::Etc::SourceParts=@RENDERED@'
    fi
    printf '%s\0' "$entry"
  done
}

readonly -a MIRROR_SOURCE_ARGS=(-o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=@RENDERED@)
helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' install -y package-one)
fallback_update_args=(update)
cases=0 mirror_cases=0 timed_out_transactions=0 bounded_acquisitions=0 total_apt_calls=0

# Per-case mirror environment; reset after every case.
reset_mirror_case() {
  secret=absent initial_lists=none sources_fixture=snapshot expected_config_calls=0
  expect_output=() forbid_output=()
}
reset_mirror_case

run_case() {
  local name="$1" results="$2" expected_status="$3" kinds="$4" expected_waits="$5"
  local mode="${6:-single}" expected_calls expected_timeouts=0 timeout_index=0
  local case_dir="$TEST_TMP/$name" status attempt kind pid pid_file state helper="$HELPER"
  local mirror='' fake_etc="$SNAPSHOT_ETC" etc_digest="$SNAPSHOT_ETC_DIGEST" text
  local -a expected_results expected_kinds invocation expected_args install_args
  IFS=, read -r -a expected_results <<<"$results"
  IFS=, read -r -a expected_kinds <<<"$kinds"
  expected_calls="${#expected_kinds[@]}"
  [[ "${#expected_results[@]}" == "$expected_calls" ]] || fail "$name has inconsistent fixture calls"
  for kind in "${expected_kinds[@]}"; do
    [[ "$kind" == apply || "$kind" == mirror-apply ]] || expected_timeouts=$((expected_timeouts + 1))
  done
  mkdir "$case_dir" "$case_dir/tmp" "$case_dir/lists"
  printf '0\n' >"$case_dir/apt.state"
  printf '0\n' >"$case_dir/timeout.state"
  : >"$case_dir/sleep.log"
  : >"$case_dir/apt-config.log"
  rm -f "$MIRROR_SECRET"
  if [[ "$secret" != absent ]]; then
    helper="$MIRROR_HELPER"
    printf '%s' "${secret#value:}" >"$MIRROR_SECRET"
    mirror="${secret#value:}"
    mirror="${mirror%$'\n'}"
  fi
  [[ "$sources_fixture" == snapshot ]] || { fake_etc="$PLAIN_ETC"; etc_digest="$PLAIN_ETC_DIGEST"; }
  case "$initial_lists" in
    none) ;;
    mirror) : >"$case_dir/lists/${mirror#http://}_ubuntu_20260803T000000Z_dists_noble_InRelease" ;;
    canonical) : >"$case_dir/lists/snapshot.ubuntu.com_ubuntu_20260803T000000Z_dists_noble_InRelease" ;;
    *) fail "$name has unknown initial lists $initial_lists" ;;
  esac
  invocation=("$helper")
  if [[ "$mode" == chain ]]; then
    invocation=(/usr/bin/bash "$TEST_TMP/update-and-install")
  fi
  set +e
  # A closed PATH cannot fall through to real apt-get if any fake is missing.
  PATH="$TEST_TMP/bin" TMPDIR="$case_dir/tmp" \
    FAKE_APT_STATE="$case_dir/apt.state" FAKE_APT_ARGV="$case_dir/apt.argv" FAKE_APT_RESULTS="$results" \
    FAKE_TIMEOUT_STATE="$case_dir/timeout.state" FAKE_TIMEOUT_ARGV="$case_dir/timeout.argv" \
    FAKE_SLEEP_LOG="$case_dir/sleep.log" FAKE_APT_CONFIG_LOG="$case_dir/apt-config.log" \
    FAKE_ETC="$fake_etc" FAKE_LISTS="$case_dir/lists" FAKE_MIRROR_LIST_HOST="${mirror#http://}" \
    APT_HELPER_UNDER_TEST="$helper" \
    "${invocation[@]}" "${helper_args[@]}" >"$case_dir/output.log" 2>&1
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] || fail "$name returned $status, expected $expected_status"
  [[ "$(<"$case_dir/apt.state")" == "$expected_calls" ]] || fail "$name changed the APT invocation count"
  [[ "$(<"$case_dir/timeout.state")" == "$expected_timeouts" ]] || fail "$name changed bounded acquisition count"
  [[ "$(wc -l <"$case_dir/sleep.log")" == "$expected_waits" ]] || fail "$name changed the inter-attempt waits"
  [[ "$(head -n "$expected_waits" <<<"30
60
120
240
300" | tr '\n' ' ')" == "$(tr '\n' ' ' <"$case_dir/sleep.log")" ]] || fail "$name changed the exponential backoff sequence"
  [[ "$(grep -c '^APT acquisition failed; retrying the exact command ' "$case_dir/output.log" || true)" == "$expected_waits" ]] \
    || fail "$name changed the retry reports"
  [[ "$(wc -l <"$case_dir/apt-config.log")" == "$expected_config_calls" ]] \
    || fail "$name changed when APT source configuration is read"
  # The rendered copy never outlives the helper, and the configured sources
  # are never modified.
  [[ -z "$(find "$case_dir/tmp" -mindepth 1 -print -quit)" ]] || fail "$name left rendered mirror sources behind"
  [[ "$(tree_digest "$fake_etc")" == "$etc_digest" ]] || fail "$name modified the configured APT sources"
  for text in "${expect_output[@]}"; do
    grep -qF -- "$text" "$case_dir/output.log" || fail "$name did not report: $text"
  done
  for text in "${forbid_output[@]}"; do
    ! grep -qF -- "$text" "$case_dir/output.log" || fail "$name unexpectedly reported: $text"
  done
  for ((attempt = 1; attempt <= expected_calls; attempt++)); do
    kind="${expected_kinds[$((attempt - 1))]}"
    install_args=("${helper_args[@]}")
    [[ "$mode" != chain ]] || install_args=(install -y package-one)
    case "$kind" in
      update) expected_args=("${helper_args[@]}" -o Acquire::Retries=5) ;;
      mirror-update) expected_args=("${helper_args[@]}" "${MIRROR_SOURCE_ARGS[@]}" -o Acquire::Retries=5) ;;
      fallback-update) expected_args=("${fallback_update_args[@]}" -o Acquire::Retries=5) ;;
      download) expected_args=("${install_args[@]}" --download-only -o Acquire::Retries=5) ;;
      mirror-download) expected_args=("${install_args[@]}" --download-only "${MIRROR_SOURCE_ARGS[@]}" -o Acquire::Retries=5) ;;
      apply) expected_args=("${install_args[@]}" --no-download) ;;
      mirror-apply) expected_args=("${install_args[@]}" --no-download "${MIRROR_SOURCE_ARGS[@]}") ;;
      *) fail "$name has unknown expected invocation kind $kind" ;;
    esac
    expected_args+=(-o APT::Update::Error-Mode=any)
    printf '%s\0' "${expected_args[@]}" >"$TEST_TMP/expected-apt-argv"
    normalized_argv "$case_dir/apt.argv.$attempt" "$case_dir" >"$TEST_TMP/actual-apt-argv" \
      || fail "$name passed rendered sources outside its private temporary directory"
    cmp "$TEST_TMP/expected-apt-argv" "$TEST_TMP/actual-apt-argv" || fail "$name changed APT argument boundaries"
    if [[ "$kind" == mirror-* ]]; then
      [[ -d "$case_dir/expected-rendered" ]] || expected_rendered "$mirror" "$case_dir/expected-rendered" \
        || fail "$name rendered-source oracle failed"
      diff -r "$case_dir/expected-rendered" "$case_dir/apt.argv.$attempt.rendered" \
        || fail "$name rendered sources other than the two rewritten snapshot prefixes"
    else
      [[ ! -e "$case_dir/apt.argv.$attempt.rendered" ]] || fail "$name read rendered sources in canonical mode"
    fi
    if [[ "$kind" != apply && "$kind" != mirror-apply ]]; then
      timeout_index=$((timeout_index + 1))
      printf '%s\0' --signal=TERM --kill-after=3s 300s apt-get "${expected_args[@]}" >"$TEST_TMP/expected-timeout-argv"
      normalized_argv "$case_dir/timeout.argv.$timeout_index" "$case_dir" >"$TEST_TMP/actual-timeout-argv" \
        || fail "$name bounded rendered sources outside its private temporary directory"
      cmp "$TEST_TMP/expected-timeout-argv" "$TEST_TMP/actual-timeout-argv" \
        || fail "$name changed the 300s/TERM/3s acquisition deadline"
    fi
    if [[ "${expected_results[$((attempt - 1))]}" == hang ]]; then
      [[ "$kind" != apply ]] || fail "$name attempted to retry a mutating package apply"
      grep -Fxq TERM "$case_dir/apt.argv.$attempt.terminated" || fail "$name did not terminate the timed-out fake APT"
      for pid_file in "$case_dir/apt.argv.$attempt.apt-pid" "$case_dir/apt.argv.$attempt.child-pid"; do
        pid="$(<"$pid_file")"
        state="$(ps -o stat= -p "$pid" || true)"
        # A Z-state process has exited and cannot continue an APT transaction.
        # In CI containers, PID 1 may defer reaping an already terminated
        # process after timeout control completes, so only a live process is
        # a cleanup failure here.
        state="${state//[[:space:]]/}"
        [[ -z "$state" || "$state" == Z* ]] || fail "$name left its TERM-responsive fixture process $pid ($state)"
      done
      timed_out_transactions=$((timed_out_transactions + 1))
    fi
  done
  cases=$((cases + 1))
  [[ "$secret" == absent ]] || mirror_cases=$((mirror_cases + 1))
  total_apt_calls=$((total_apt_calls + expected_calls))
  bounded_acquisitions=$((bounded_acquisitions + expected_timeouts))
  reset_mirror_case
}

# Canonical mode: no secret leaves the production helper's transactions
# byte-for-byte unchanged and never reads the source configuration.
helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' update)
run_case partial-update-recovery partial,0,0,0 0 update,update,download,apply 1 chain
run_case partial-update-exhaustion partial,partial,partial,partial,partial,partial 100 update,update,update,update,update,update 5 chain
helper_args+=(-o APT::Update::Error-Mode=persistent)
run_case caller-cannot-weaken-update partial,0,0,0 0 update,update,download,apply 1 chain

helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' install -y package-one)
run_case immediate-success 0,0 0 download,apply 0
run_case ordinary-recovery 42,43,0,0 0 download,download,download,apply 2
run_case ordinary-exhaustion 41,42,43,44,45,46 46 download,download,download,download,download,download 5
run_case timeout-recovery hang,0,0 0 download,download,apply 1
run_case timeout-exhaustion hang,hang,hang,hang,hang,hang 124 download,download,download,download,download,download 5
run_case apply-failure-is-not-retried 0,67 67 download,apply 0

# Mirror mode: only the two snapshot prefixes are rewritten in a private copy.
readonly MIRROR_BANNER='using APT snapshot mirror'
readonly MIRROR_FALLBACK='APT snapshot mirror failed 2 attempts; using canonical sources for the remaining attempts'
readonly MALFORMED='ignoring a malformed APT snapshot mirror secret'
helper_args=(update)
secret="value:$CI_MIRROR" expected_config_calls=2 expect_output=("$MIRROR_BANNER $CI_MIRROR")
forbid_output=("$MIRROR_FALLBACK")
run_case mirror-update-and-install 0,0,0 0 mirror-update,mirror-download,mirror-apply 0 chain
secret="value:http://127.0.0.1:18089"$'\n' expected_config_calls=1 expect_output=("$MIRROR_BANNER http://127.0.0.1:18089")
run_case mirror-local-ip-update 0 0 mirror-update 0
secret='value:http://cache' expected_config_calls=1 expect_output=("$MIRROR_BANNER http://cache for")
run_case mirror-default-port-update 0 0 mirror-update 0
secret="value:$CI_MIRROR" expected_config_calls=1 expect_output=("$MIRROR_FALLBACK")
run_case mirror-update-falls-back 100,100,0 0 mirror-update,mirror-update,update 2
secret="value:$CI_MIRROR" expected_config_calls=1 expect_output=("$MIRROR_FALLBACK")
run_case mirror-update-exhaustion 100,100,100,100,100,100 100 mirror-update,mirror-update,update,update,update,update 5

helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' install -y package-one)
fallback_update_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' update)
secret="value:$CI_MIRROR" initial_lists=mirror expected_config_calls=1 expect_output=("$MIRROR_BANNER")
run_case mirror-install 0,0 0 mirror-download,mirror-apply 0
secret="value:$CI_MIRROR" initial_lists=mirror expected_config_calls=1 expect_output=("$MIRROR_FALLBACK")
run_case mirror-install-falls-back-with-update 100,100,0,0,0 0 mirror-download,mirror-download,fallback-update,download,apply 2
secret="value:$CI_MIRROR" initial_lists=mirror expected_config_calls=1 expect_output=("$MIRROR_FALLBACK")
run_case mirror-fallback-update-retries 100,100,100,0,0,0 0 mirror-download,mirror-download,fallback-update,fallback-update,download,apply 3
secret="value:$CI_MIRROR" initial_lists=mirror expected_config_calls=1
run_case mirror-download-exhaustion 100,100,100,100,100,100 100 mirror-download,mirror-download,fallback-update,fallback-update,fallback-update,fallback-update 5
secret="value:$CI_MIRROR" initial_lists=mirror expected_config_calls=1
run_case mirror-apply-failure 0,67 67 mirror-download,mirror-apply 0
secret="value:$CI_MIRROR" initial_lists=canonical expected_config_calls=1
expect_output=('package lists were not fetched through the APT snapshot mirror') forbid_output=("$MIRROR_BANNER")
run_case mirror-skips-canonical-lists 0,0 0 download,apply 0
secret="value:$CI_MIRROR" sources_fixture=plain initial_lists=mirror expected_config_calls=1
expect_output=('no snapshot source is configured') forbid_output=("$MIRROR_BANNER")
run_case mirror-without-snapshot-sources 0,0 0 download,apply 0
secret='value:' forbid_output=("$MALFORMED" "$MIRROR_BANNER")
run_case empty-secret-is-canonical 0,0 0 download,apply 0

malformed_index=0
for malformed in 'https://cache:8080' 'http://cache/' "$CI_MIRROR/ubuntu" 'http://Cache' 'http://-cache' \
    'http://cache-' 'http://user@cache' 'http://cache:0' 'http://cache:08080' 'http://cache:65536' \
    'http://cache:123456' 'http://[::1]:8080' 'http://cache;touch${IFS}pwned' 'http://cache:8080 ' \
    $'http://cache:8080\nhttp://other' 'cache:8080' 'ftp://cache' 'http://'; do
  malformed_index=$((malformed_index + 1))
  secret="value:$malformed" initial_lists=canonical expect_output=("$MALFORMED") forbid_output=("$MIRROR_BANNER")
  run_case "malformed-mirror-$malformed_index" 0,0 0 download,apply 0
done
[[ ! -e "$TEST_TMP/pwned" && ! -e "$ROOT/pwned" ]] || fail 'a malformed mirror value executed a command'

# This proves ordinary TERM-responsive children, not arbitrary detached process
# cleanup. The enclosing BuildKit namespace owns the broader lifecycle.
printf '[test-apt-get-with-retry] %s cases (%s mirror), %s APT calls, %s bounded acquisitions, %s real timeouts: safe acquisition/apply and snapshot mirror contract passed\n' \
  "$cases" "$mirror_cases" "$total_apt_calls" "$bounded_acquisitions" "$timed_out_transactions"
