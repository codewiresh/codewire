#!/usr/bin/env bash
# Dev billing round trip (#3263 item 3): a real Stripe test-mode charge, and
# Stripe's own webhook delivery of it, observed through the product.
#
# As the billing-rehearsal identity, whose organization is on the Regular
# rate card and holds a saved Stripe test card, it adds EUR 5 of credit once.
# Billing charges the saved card through Stripe and credits the balance at
# once. The proof that Stripe then reached billing is the `invoice_paid`
# billing event for that charge: only billing's handler of Stripe's
# `invoice.paid` delivery writes it.
#
# Usage, from a codewire checkout:
#   scripts/runtime/dev/with-dev-smoke-auth.sh \
#     --openbao-path apps/codewire/dev/ci-billing-rehearsal -- \
#     scripts/runtime/dev/smoke-dev-billing-roundtrip.sh
#
# Inputs: CODEWIRE_DEV_SMOKE_API_KEY (the rehearsal identity's key; never
# printed), CODEWIRE_SERVER_URL (default https://codewire-dev.sh), and
# BILLING_ROUNDTRIP_WAIT_SECONDS (default 180). It prints figures and IDs
# only. Nothing real is charged: Dev's Stripe account is in test mode, and
# the script refuses any server but Dev's.
set -euo pipefail

readonly DEV_SERVER_URL="https://codewire-dev.sh"
readonly AMOUNT_CENTS=500
readonly NANO_EUR_PER_CENT=10000000

die() {
  printf 'billing-roundtrip: %s\n' "$*" >&2
  exit 1
}

server="${CODEWIRE_SERVER_URL:-$DEV_SERVER_URL}"
[[ "$server" == "$DEV_SERVER_URL" ]] || die "Dev only: CODEWIRE_SERVER_URL must be $DEV_SERVER_URL"
[[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] || die 'CODEWIRE_DEV_SMOKE_API_KEY is required'
wait_seconds="${BILLING_ROUNDTRIP_WAIT_SECONDS:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ && "$wait_seconds" -ge 30 && "$wait_seconds" -le 900 ]] ||
  die 'BILLING_ROUNDTRIP_WAIT_SECONDS must be 30 to 900'
command -v jq >/dev/null || die 'jq is required'

# One Connect JSON call; the response body on stdout. The key goes to curl on
# a header read from stdin, never on its command line.
call() {
  local method="$1" body="$2" response status
  response="$(printf 'Authorization: Bearer %s\n' "$CODEWIRE_DEV_SMOKE_API_KEY" |
    curl -sS --max-time 30 -X POST -H @- -H 'Content-Type: application/json' \
      --data "$body" -w '\n%{http_code}' "$server/$method")" || die "$method: request failed"
  status="${response##*$'\n'}"
  response="${response%$'\n'*}"
  [[ "$status" == 200 ]] || die "$method: HTTP $status $(jq -c '{code, message}' <<<"$response" 2>/dev/null || true)"
  printf '%s' "$response"
}

log() { printf '%s billing-roundtrip: %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

orgs="$(call codewire.v1.OrganizationService/ListOrganizations '{}')"
[[ "$(jq '.organizations | length' <<<"$orgs")" == 1 ]] ||
  die 'the identity must belong to exactly one organization'
org_id="$(jq -r '.organizations[0].organization.id' <<<"$orgs")"
billing_page="$server/$(jq -r '.organizations[0].organization.slug' <<<"$orgs")/billing/"
org_body="$(jq -nc --arg org "$org_id" '{orgId: $org}')"

overview="$(call codewire.console.v1.BillingService/GetBillingOverview "$org_body")"
[[ "$(jq -r '.unmetered // false' <<<"$overview")" == false ]] ||
  die 'the organization is on Unlimited, which is never charged'
[[ "$(jq -r '.hasPaymentMethod // false' <<<"$overview")" == true ]] ||
  die 'the organization has no saved card'
# Only Stripe's succeeding test card proves a payment. A declining test card
# left by an earlier walk (0341, 0002 and the like) must not read as a
# billing failure.
card="$(jq -c '.defaultCard | {brand, last4}' <<<"$overview")"
[[ "$card" == '{"brand":"visa","last4":"4242"}' ]] ||
  die "the saved default card is $card, not Stripe's succeeding test card visa 4242; add 4242 4242 4242 4242 on the organization's Billing page (Add payment method) and rerun"
before="$(jq -r '.creditBalanceNanoEur // "0"' <<<"$overview")"
seen="$(call codewire.console.v1.BillingService/ListBillingEvents "$org_body" |
  jq -c '[.events[]? | select(.eventType == "invoice_paid") | .id]')"
log "organization $org_id, balance before ${before} nano-EUR"

request_id="roundtrip-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
started="$(date +%s)"
added="$(call codewire.console.v1.BillingService/AddCredit \
  "$(jq -nc --arg org "$org_id" --arg request "$request_id" --argjson cents "$AMOUNT_CENTS" \
    --arg page "$billing_page" \
    '{orgId: $org, amountCents: $cents, requestId: $request, successUrl: $page, cancelUrl: $page}')")"
outcome="$(jq -r '.outcome // ""' <<<"$added")"
[[ "$outcome" == ADD_CREDIT_OUTCOME_PAID ]] ||
  die "AddCredit answered $outcome $(jq -c '{refusal, declineCode}' <<<"$added") with card $card"
log "AddCredit $request_id: paid"

after="$(call codewire.console.v1.BillingService/GetBillingOverview "$org_body" |
  jq -r '.creditBalanceNanoEur // "0"')"
delta=$((after - before))
expected=$((AMOUNT_CENTS * NANO_EUR_PER_CENT))
# Usage drawn meanwhile can only lower it; a tenth of the amount bounds that.
((delta <= expected && delta >= expected - expected / 10)) ||
  die "balance moved by $delta nano-EUR, not $expected"
log "balance after ${after} nano-EUR (+${delta})"

# Stripe's own delivery of invoice.paid writes one new invoice_paid event for
# this amount.
deadline=$((started + wait_seconds))
while :; do
  event="$(call codewire.console.v1.BillingService/ListBillingEvents "$org_body" |
    jq -c --argjson seen "$seen" --argjson cents "$AMOUNT_CENTS" '
      [.events[]? | select(.eventType == "invoice_paid" and .amountCents == $cents
        and ((.id as $id | $seen | index($id)) | not))] | first // empty')"
  if [[ -n "$event" ]]; then
    log "Stripe delivered invoice.paid for $(jq -r '.stripeItemId // "?"' <<<"$event") after $(($(date +%s) - started))s"
    printf 'billing-roundtrip: PASS charged EUR %d.%02d, credited, and delivered by Stripe\n' \
      $((AMOUNT_CENTS / 100)) $((AMOUNT_CENTS % 100))
    exit 0
  fi
  (($(date +%s) < deadline)) || die "no invoice_paid delivery within ${wait_seconds}s"
  sleep 5
done
