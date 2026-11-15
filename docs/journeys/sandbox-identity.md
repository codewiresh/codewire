# Sandbox identity

A hosted sandbox proves which organization's sandbox it is to a verifier that
organization trusts: a Kubernetes cluster, an OpenBao or Vault server, or a
cloud's workload-identity federation. Codewire publishes one OIDC issuer per
organization, `{issuer base}/orgs/<org id>`, and a sandbox asks for a short-lived
token (10 minutes, one audience) that the verifier checks through OIDC
discovery. The work is #4661; the configuration is in
[CONFIGURATION.md](../CONFIGURATION.md#sandbox-identity). The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-14. The issuer's code (#4662) is in review and off by default.
No environment serves an issuer yet, and nothing mints a token.

| ID | Slice | Dev | Production |
| --- | --- | --- | --- |
| `identity-groups` | #4664 | not yet built | not yet built |
| `identity-per-org-issuer` | #4664 | not yet built | not yet built |
| `identity-audiences` | #4663 | not yet built | not yet built |
| `identity-groups-stay-put` | #4663 | not yet built | not yet built |
| `identity-changes-apply` | #4663, #4664 | not yet built | not yet built |
| `identity-limits` | #4664 | not yet built | not yet built |
| `identity-discovery` | #4662 | not yet observed | not yet observed |
| `identity-custody` | #4662 | not yet observed | not yet observed |
| `identity-own-openbao` | #4666 | not yet built | not yet built |
| `identity-rotation` | #4662 | not yet observed | not yet observed |
| `identity-audit` | #4663, #4664 | not yet built | not yet built |

## Before the walk

- The issuer serves only where `CODEWIRE_IDENTITY_ENABLED=true` and its
  signing key exists. On Dev neither is set up yet (#4662).
- `ISSUER_BASE` below is the environment's `CODEWIRE_IDENTITY_ISSUER_BASE`.
  `ORG` is the ID of an organization the walker belongs to, as `cw org
  current` prints it under `ID:`.
- Steps that need tokens wait for minting (#4664). Their commands are written
  when it lands.

## 7. `identity-discovery`: each organization's issuer, and nothing else

- **Entry points:** the issuer host through the TLS-terminating edge, as any
  verifier fetches it.
- **States to exercise:**
  - an existing organization;
  - an unknown one;
  - a deleted one;
  - an upper-case spelling of a real ID;
  - forged forwarding headers;
  - every other path, method and query string.
- **Driving it:**
  1. `curl -sS -D- "$ISSUER_BASE/orgs/$ORG/.well-known/openid-configuration"`
     answers 200 with `Cache-Control: public, max-age=300`, and `issuer` is
     exactly `$ISSUER_BASE/orgs/$ORG`.
  2. Repeat it with `-H 'X-Forwarded-Host: attacker.example' -H
     'Forwarded: host=attacker.example'`. The body is byte-identical.
  3. `curl -sS "$ISSUER_BASE/orgs/$ORG/jwks.json"` lists only keys with
     `kty: EC`, `crv: P-256`, `alg: ES256`, `use: sig` and a `kid`, and is
     never empty.
  4. Each of these answers 404 with `Cache-Control: no-store` and no
     `Location`, and no body contains the requested ID:
     - an unknown org ID, and `$ORG` in upper case;
     - `$ISSUER_BASE/orgs/$ORG/jwks.json/`;
     - `$ISSUER_BASE/.well-known/openid-configuration`;
     - a `POST` to the JWKS path.
  5. `curl -sS -D- "$ISSUER_BASE/orgs/$ORG/jwks.json?x=1"` answers 404
     `no-store`. The edge's cache key includes the query string, so the
     request reaches the listener, which refuses any query string.
  6. Send 30 requests in one second for an unknown org ID from one client.
     Some get 429. A request from a second client address in the same second,
     such as from inside a Dev sandbox, still gets its normal answer: each
     client has its own budget.
     The gateway's access log names the route for each request: a document
     fetch is served by `codewire-identity-documents`, and anything else by
     `codewire-identity`.
  7. Create a throwaway organization with `cw org create`, fetch its
     discovery document (200), delete it with `cw org delete`, and fetch it
     again once the deletion finishes, after the five-minute cache: 404
     `no-store`.
- **Proof:** the `issuer` string compared byte for byte, and the status and
  `Cache-Control` of each refusal.
- **Covered by tests, not walkable through the edge:**
  - a forged `Host` header, because the edge routes on it;
  - an organization caught mid-deletion;
  - an unreadable key set.
  The listener's own tests and the database test cover them.
- **Gotchas:**
  - The edge may cache a success for five minutes. Compare a refusal only on
    a path no one has fetched successfully.
  - Tokens never carrying `jku` or `x5u` waits for minting (#4664).
- **Observed:** not yet observed.

## 8. `identity-custody`: the signing key never leaves OpenBao

- **Entry points:** OpenBao, as the signer role and as the rotator role.
- **States to exercise:**
  - an export or backup call;
  - a sign call with the rotator role;
  - the rotator setting `exportable`;
  - a policy without the deny rules;
  - a key whose pinned configuration has drifted.
- **Driving it:** no command yet. Walking it needs an infrastructure helper
  that waits for the owner's approval of the plan (#4662):
  - It logs in as each role from a token of that role's own service account.
  - It makes each refused call and reports the status.
  - It runs the policy check against a fixture policy that lacks the deny
    rules.
  - It names where each alert lands.
- **Proof:**
  - each call above is refused with 403;
  - the policy check fails the fixture;
  - each refused call raises its alert;
  - `codewire-orchestration identity rotate` fails, and changes nothing, on a
    drifted key.
- **Gotchas:** walk drift only with a setting that can be undone, such as
  `auto_rotate_period`, and set it back at once. Never set `exportable` or
  `allow_plaintext_backup` on a real key: neither can be turned off again.
- **Observed:** not yet observed.

## 10. `identity-rotation`: rotating the key fails no request

- **Entry points:**
  - the daily rotation job, `codewire-orchestration identity rotate`;
  - a rotation by hand under the rotator role.
- **States to exercise:**
  - a new version during its first 24 hours, when it is published but not
    signing;
  - the next 24 hours, when it signs and the old version is still published;
  - the old version's removal;
  - a job that hasn't run for days.
- **Driving it:** no command yet. The walk needs:
  - the rotation job's name, and how to start a run at once;
  - a rotation by hand under the rotator role, since the job alone rotates
    only at 30 days.

  Then, over three days:
  1. Rotate by hand, then fetch the JWKS: the new `kid` is listed beside the
     old one at once.
  2. Run the job daily. Its one-line summary names the version that signs:
     the old one for the first 24 hours, then the new one.
  3. 48 hours after the rotation, the job raises the minimums, and the old
     `kid` leaves the JWKS within the edge's five minutes.
- **Proof:**
  - the job's summary lines, and the JWKS `kid`s at each stage, against the
    rules in [CONFIGURATION.md](../CONFIGURATION.md#sandbox-identity);
  - that no verifier request fails across the switch, which needs minting
    (#4664).
- **Observed:** not yet observed.

## The other steps

Design steps 1–6, 9 and 11 (groups, per-org issuers at a verifier,
audiences, groups staying put, changes taking effect, limits, Codewire's own
OpenBao, and audit) need groups, audiences and minting. They are written
here as their slices land: #4663, #4664 and #4666.
