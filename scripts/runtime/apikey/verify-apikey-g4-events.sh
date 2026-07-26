#!/usr/bin/env bash
set -euo pipefail

readonly PRIMARY_FINGERPRINT="40d8b5abc54058a49b91a0c4c64aeaf6"
readonly SECONDARY_FINGERPRINT="253db3f72f82d2d63293548fef910309"

RELEASE_TAG=""
STARTED_AT=""
COMPLETED_AT=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/apikey/verify-apikey-g4-events.sh \
    --release-tag vX.Y.Z \
    --started-at YYYY-MM-DDTHH:MM:SSZ \
    --completed-at YYYY-MM-DDTHH:MM:SSZ < orchestration.ndjson

Verifies the bounded production ApiKeyService event window for G4. Input must
be raw JSON log lines from the production orchestration container. The fixed
query accepts only the exact released CLI User-Agent and the two checked-in
production evidence fingerprints, requires at least 50 events and both
principals, and rejects internal, unavailable, or unknown Connect codes.
USAGE
}

die() {
  printf '[apikey-g4-verify] ERROR: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --release-tag)
      [[ $# -ge 2 ]] || die "--release-tag requires vX.Y.Z"
      RELEASE_TAG="$2"
      shift 2
      ;;
    --started-at)
      [[ $# -ge 2 ]] || die "--started-at requires a UTC timestamp"
      STARTED_AT="$2"
      shift 2
      ;;
    --completed-at)
      [[ $# -ge 2 ]] || die "--completed-at requires a UTC timestamp"
      COMPLETED_AT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  die "--release-tag must be an exact stable semver tag"
for timestamp in "$STARTED_AT" "$COMPLETED_AT"; do
  [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    die "evidence timestamps must use second-precision UTC"
done
[[ "$STARTED_AT" < "$COMPLETED_AT" || "$STARTED_AT" == "$COMPLETED_AT" ]] || \
  die "evidence completion precedes its start"

command -v jq >/dev/null 2>&1 || die "missing required command: jq"

if ! jq -cs \
  --arg start "$STARTED_AT" \
  --arg completed_at "$COMPLETED_AT" \
  --arg ua "codewire-cli/$RELEASE_TAG" \
  --arg primary "$PRIMARY_FINGERPRINT" \
  --arg secondary "$SECONDARY_FINGERPRINT" '
  def second_precision:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
    then sub("\\.[0-9]+Z$"; "Z")
    else error("invalid event timestamp")
    end;
  [ .[]
    | if .target == "connect_rpc" and (.fields | type) == "object"
      then .fields + {timestamp: .timestamp, target: .target}
      else .
      end
    | select(.target == "connect_rpc")
    | select(.service == "codewire.v1.ApiKeyService")
    | . as $event
    | ($event.timestamp | second_precision) as $timestamp
    | select($timestamp >= $start and $timestamp <= $completed_at)
    | select(.user_agent == $ua and .synthetic == true)
  ] as $events
  | ($events | map(.principal_fingerprint) | unique) as $fingerprints
  | ($events | map(select((.code | type) != "string" or (.code | length) == 0))) as $malformed
  | ($events | map(select(.code == "internal" or .code == "unavailable" or .code == "unknown"))) as $severe
  | if ($events | length) < 50 then error("fewer than 50 matching ApiKeyService events")
    elif $fingerprints != ([$primary, $secondary] | sort) then error("principal fingerprint set is not the exact evidence pair")
    elif ($malformed | length) != 0 then error("event code is missing or malformed")
    elif ($severe | length) != 0 then error("severe Connect error present in evidence window")
    else {
      api_key_rpc_events: ($events | length),
      release_user_agent: $ua,
      principal_counts: ($events | group_by(.principal_fingerprint) | map({
        fingerprint: .[0].principal_fingerprint,
        count: length
      })),
      code_counts: ($events | group_by(.code) | map({code: .[0].code, count: length}))
    }
    end
'; then
  die "production event window did not satisfy G4"
fi
