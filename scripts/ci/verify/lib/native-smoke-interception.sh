# shellcheck shell=bash
# The interception smoke's checks of a boot (#3999, #4912), for
# smoke-native-local-environment.sh. Sourced, never run: it uses the smoke's
# STATE_ROOT, ENVIRONMENT_ID, NAME, INTERCEPT_DECISIONS_SEEN, LAST_STDOUT,
# run_cw, die and front_door_children.

require_boot_intercepts() {
  # The current boot intercepts and its front door is paired. The
  # supervisor's log spans boots, so this boot's decision is one more than
  # were there before; the runner's log starts again at each boot, so a
  # pairing in it is this boot's.
  local label="$1" decisions decision paired=0 front_doors
  jq -e '.intercept == true' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json" >/dev/null ||
    die "$label: the VM's recorded state does not say it intercepts"
  decisions="$(grep -Ec ' event=egress_intercept( |$)' "$STATE_ROOT/logs/supervisor.log" || true)"
  [[ "$decisions" -gt "$INTERCEPT_DECISIONS_SEEN" ]] ||
    die "$label: the supervisor logged no interception decision for this boot"
  INTERCEPT_DECISIONS_SEEN="$decisions"
  decision="$(grep -E ' event=egress_intercept( |$)' "$STATE_ROOT/logs/supervisor.log" | tail -n 1)"
  [[ "$decision" == *' switch=on'* && "$decision" != *' skipped='* ]] ||
    die "$label: the supervisor did not turn interception on for this boot: ${decision:-no decision logged}"
  # Up to a minute, for a loaded host; a boot that paired does not wait.
  for _attempt in {1..300}; do
    paired="$(grep -Ec ' event=front_door_pairing( .*)? outcome=paired( |$)' \
      "$STATE_ROOT/logs/runner-$ENVIRONMENT_ID.log" || true)"
    [[ "$paired" -ge 1 ]] && break
    sleep 0.2
  done
  [[ "$paired" -ge 1 ]] || die "$label: the runner recorded no front-door pairing"
  front_doors="$(front_door_children | wc -l)"
  [[ "$front_doors" -eq 1 ]] || die "$label: the runner has $front_doors front-door processes"
  require_info_interception "$label" intercepted 'placeholders only: agents never hold your tokens'
}

require_info_interception() {
  # cw info says what the running boot's agents hold (#4912): its JSON
  # carries the state, and its text the note on the line under the
  # Credentials row, or nothing under it when the note is empty.
  local label="$1" state="$2" note="$3" under
  run_cw info --local "$NAME" --output json
  jq -e --arg state "$state" '.state == "running" and .interception.state == $state' \
    "$LAST_STDOUT" >/dev/null ||
    die "$label: cw info does not say a running boot $state: $(jq -c '{state, interception}' "$LAST_STDOUT")"
  run_cw info --local "$NAME"
  under="$(grep -A1 '^Credentials:' "$LAST_STDOUT" | sed -n 2p)"
  if [[ -n "$note" ]]; then
    [[ "$under" == "             $note" ]] || die "$label: cw info does not say, under Credentials: $note"
  elif [[ "$under" == '             '* ]]; then
    die "$label: cw info has a note under Credentials: $under"
  fi
}

require_refusal_logged() {
  # cw --local policy log (#5058) shows the refusal just sent: a row for the
  # route's bound host, api.anthropic.com, port 443, with REASON from SOURCE,
  # and nothing of the request: not the placeholder, the key or the path. A
  # credential row names no policy. The front door reports at most once a
  # second, so the log is read for up to 5 s.
  local label="$1" source="$2" reason="$3" placeholder="$4" row
  # shellcheck disable=SC2016 # jq variables.
  row='.refusals[] | select(.destination == "api.anthropic.com" and .port == 443 and
    .protocol == "tcp" and .reason == $reason and .source == $source and .count >= 1)'
  for _attempt in {1..25}; do
    run_cw --local policy log "$NAME" --output json
    jq -e --arg source "$source" --arg reason "$reason" "[$row] | length == 1" \
      "$LAST_STDOUT" >/dev/null && break
    sleep 0.2
  done
  jq -e --arg source "$source" --arg reason "$reason" "[$row] | length == 1" "$LAST_STDOUT" >/dev/null ||
    die "$label: the refusal log has no $reason row from $source for api.anthropic.com: $(head -c 600 "$LAST_STDOUT")"
  [[ "$source" != credentials ]] ||
    jq -e --arg source "$source" --arg reason "$reason" "[$row | .policy == null] == [true]" \
      "$LAST_STDOUT" >/dev/null ||
    die "$label: the refusal log's credential row names a policy"
  jq -e '.rejected == 0' "$LAST_STDOUT" >/dev/null ||
    die "$label: the runner rejected reports from the front door: $(jq -c '.rejected' "$LAST_STDOUT")"
  ! grep -Fq -e "$placeholder" -e "$ANTHROPIC_CREDENTIAL_CANARY" -e count_tokens "$LAST_STDOUT" ||
    die "$label: the refusal log holds the placeholder, the key or the request's path"
}
