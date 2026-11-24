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

Updated 2026-11-24. Dev serves the issuer at `https://identity.codewire-dev.sh`,
from its own signing key in OpenBao (#4662), and runs groups, audiences and
minting (#4663, #4664). Minting on Dev waits for its key version 2, made by an
emergency rotation rehearsal on 2026-11-23, to reach 24 hours. Production
serves nothing yet (#4667), and no release has these. The contract is
[dev/SANDBOX-IDENTITY.md](../dev/SANDBOX-IDENTITY.md).

| ID | Slice | Dev | Production |
| --- | --- | --- | --- |
| `identity-groups` | #4664 | not yet observed | not yet observed |
| `identity-per-org-issuer` | #4664 | not yet observed | not yet observed |
| `identity-audiences` | #4663 | partly observed (2026-11-24) | not yet observed |
| `identity-groups-stay-put` | #4663 | not yet observed | not yet observed |
| `identity-changes-apply` | #4663, #4664 | partly observed (2026-11-24) | not yet observed |
| `identity-limits` | #4664 | partly observed (2026-11-24) | not yet observed |
| `identity-discovery` | #4662 | observed (2026-11-23) | not yet observed |
| `identity-custody` | #4662 | observed; a drifted key by test (2026-11-23) | not yet observed |
| `identity-own-openbao` | #4666 | the route's refusals observed (2026-11-24); the login not yet | not yet built |
| `identity-rotation` | #4662 | not yet observed | not yet observed |
| `identity-audit` | #4663, #4664 | partly observed (2026-11-24) | not yet observed |
| `identity-files` | #4664 | not yet built | not yet built |

## Before the walk

- The issuer serves only where `CODEWIRE_IDENTITY_ENABLED=true` and its
  signing key exists. On Dev neither is set up yet (#4662).
- `ISSUER_BASE` below is the environment's `CODEWIRE_IDENTITY_ISSUER_BASE`.
  `ORG` is the ID of an organization the walker belongs to, as `cw org
  current` prints it under `ID:`.
- Steps 1 to 6 and 11 need a scratch Kind cluster whose API server trusts
  `$ISSUER_BASE/orgs/$ORG` through structured authentication, with
  `claimMappings.groups` from `groups` and the audience `https://k8s.walk.example`
  registered for `ORG` (`cw identity audience add https://k8s.walk.example`).
  `KIND` below is that cluster's API URL, reachable from the Sandbox.
- Run the steps from inside a cloud Sandbox (`cw ssh NAME`) unless a step
  says otherwise. An admin of `ORG` sets groups; `MEMBER` is a member who is
  not an admin.
- A new signing key signs nothing for 24 hours. On a fresh environment, create
  the key a day ahead.

## 1. `identity-groups`: a group reaches what it was granted, and nothing else

- **Entry points:** `cw identity groups set`, `cw identity token`, and the
  scratch cluster's RBAC.
- **States to exercise:** a Sandbox in `data-readers`, and one in no group.
- **Driving it:**
  1. As the admin: `cw identity groups set A data-readers`, and nothing on `B`.
     The command names who can run code in `A` and so use the group.
  2. On the scratch cluster, bind `get pods` in namespace `data` to the group
     `$ORG:data-readers`.
  3. In `A`: `kubectl --server "$KIND" --token "$(cw identity token --resource
     https://k8s.walk.example)" get pods -n data` lists the Pods.
  4. In `B`, the same command is Forbidden. `B`'s token carries only
     `$ORG:all`.
- **Proof:** the decoded `groups` claim of each token, and each command's
  result.
- **Observed:** not yet observed.

## 2. `identity-per-org-issuer`: another organization's token is refused

- **Entry points:** a second organization `ORG2` with the same audience
  registered and a group of the same name.
- **Driving it:**
  1. In `ORG2`, register `https://k8s.walk.example` and put a Sandbox in
     `data-readers`.
  2. Its token is refused at authentication (401): its `iss` is
     `$ISSUER_BASE/orgs/$ORG2`, which the cluster doesn't trust.
  3. Remove the cluster's `org_id` claim rule and repeat: still 401.
- **Proof:** the two `iss` values, and the 401.
- **Observed:** not yet observed.

## 3. `identity-audiences`: only canonical, registered audiences

- **Driving it:**
  1. `cw identity token --resource https://unregistered.example` exits non-zero
     with `invalid_target`.
  2. `cw identity audience add` refuses each of
     `https://api.$DOMAIN`, `https://x.$DOMAIN/`,
     `https://kubernetes.default.svc`, `https://10.0.0.1`,
     `http://k8s.walk.example` and `https://k8s.walk.example/?a=1`, naming the
     rule each breaks.
  3. `cw identity token --resource HTTPS://K8S.WALK.EXAMPLE:443` succeeds, and
     its `aud` is `https://k8s.walk.example`.
- **Proof:** each refusal's text, and the decoded `aud`.
- **Observed:** partly, on Dev on 2026-11-24 (#4664). Driving 1 exits 1 with
  `invalid_target`. Driving 2 refuses all six, naming the rule: "can't be
  codewire-dev.sh or a host under it" for both deployment hosts, "the
  in-cluster Kubernetes API", "an IP address", "uses https" and "has no
  query". Driving 3 waits for the key to sign.

## 4. `identity-groups-stay-put`: groups don't spread

- **Driving it:**
  1. `MEMBER` forks `A`; the fork has no groups, and step 1's command is
     Forbidden from it. The admin's fork of `A` keeps `data-readers`.
  2. Granting `operator` on `A` as `MEMBER` is refused; as the admin it works.
  3. Moving `A` to another organization clears its groups. Hosted Sandboxes
     can't move between organizations yet, so this waits until that's built.
  4. Presets have no groups field in the protocol, the API or `cw`, so there
     is nothing to refuse until presets can carry groups.
- **Proof:** `cw identity groups` on each Sandbox, and each refusal.
- **Observed:** not yet observed.

## 5. `identity-changes-apply`: a change takes effect within 10 minutes

- **Driving it:**
  1. The admin removes `A`'s group. The next `cw identity token` carries only
     `$ORG:all`, and step 1's command is Forbidden once the old token expires,
     within 10 minutes.
  2. `cw identity stop A`: the next token request in `A` fails with
     `identity_stopped`, even within a cached token's half-life.
     `cw identity resume A` restores it.
  3. Stop `A`; once it is stopped, orchestration issues no token for it.
  4. On Dev, set `CODEWIRE_IDENTITY_MINTING=off`: every Sandbox's request fails
     with `identity_unavailable`. Set it back.
- **Proof:** each refusal, with its time against the last token's `exp`.
- **Observed:** partly, on Dev on 2026-11-24 (#4664). After
  `cw identity stop A`, a token request in `A` exits 1 with
  `identity_stopped`, before any key check, and `cw identity resume A`
  restores it. The cached-token part, and driving 1, 3 and 4, wait for the
  key to sign.

## 6. `identity-limits`: a flood stays in its own Sandbox

- **Driving it:**
  1. In `A`, call the RPC directly in a loop faster than 30 a minute: past the
     burst of 10, calls get `resource_exhausted`.
  2. Meanwhile, `B`'s binding stays healthy, and its own token requests succeed.
  3. With several Sandboxes in one organization, the organization's total stays
     under its limit.
- **Proof:** the counts of granted and refused calls, and `B`'s health.
- **Observed:** partly, on Dev on 2026-11-24 (#4664). 30 concurrent requests
  in `A`: 13 passed the limit and 17 got `resource_exhausted`. During a
  40-request flood in `A` (28 refused), all 8 of `B`'s requests passed the
  limit. Driving 3 isn't practical to drive from one walker.

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
  6. Send 150 requests at once for an unknown org ID from one client. Some
     get 429: the documents route allows 30 a second per client on each of
     the gateway's two proxies, so 30 in a second is not enough to see it. A
     canonical document fetched right after still answers, from the edge's
     cache. A request from a second client address in the same second,
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
- **Observed:** partly, on Dev on 2026-11-22 from a workstation, with an
  existing organization (#4662):
  - 1: 200, `Cache-Control: public, max-age=300`, with `issuer` and
    `jwks_uri` byte-exact;
  - 2: the forged headers left the body byte-identical;
  - 3: one key, `sandbox-identity-1`, with `kty: EC`, `crv: P-256`,
    `alg: ES256`, `use: sig` and a `kid`;
  - 4 and 5: an unknown ID, the ID in upper case, a trailing slash, the bare
    `.well-known`, a `POST` and `?x=1` were each 404 `no-store`, with no
    `Location` and no ID in the body;
  - 6: 150 parallel requests drew 102 answers of 429, and a canonical
    document right after answered 200.

  The rest on 2026-11-23:
  - 6, second client: a Dev Sandbox of the smoke organization asked for an
    unknown organization's document five times a second while this
    workstation sent 150 at once. The workstation drew 67 answers of 429.
    All 60 of the Sandbox's requests answered 404, two of them inside the
    flood's second.
  - 7: as a signed-in test account, because an API key can't create an
    organization. The throwaway organization's document answered 200, with
    `public, max-age=300` and the exact `issuer`. After `cw org delete`
    finished and five minutes passed, it answered 404 `no-store`, with no
    `Location` and no ID in the body.

## 8. `identity-custody`: the signing key never leaves OpenBao

- **Entry points:** OpenBao, as the signer role and as the rotator role.
- **States to exercise:**
  - an export or backup call;
  - a sign call with the rotator role;
  - the rotator setting `exportable`;
  - a policy without the deny rules;
  - a key whose pinned configuration has drifted.
- **Driving it:** the infrastructure repository's custody walk helper, run
  under the owner's approval (#4662), in a window announced first because
  its alerts page:
  - One Job per role, each running as that role's own service account, logs
    in from a Pod-bound token that never leaves the cluster.
  - Each Job makes its role's refused calls and reports their status.
  - Each role reads the key's config before and after its calls.
  - The policy check runs against a fixture policy that lacks the deny
    rules.
  - It names each alert and where it lands.

  A drifted key is never made on Dev. The orchestration test
  `identity::rotate::openbao_tests`, ignored by default, runs the rotation
  job's own code against a throwaway OpenBao dev server on loopback instead:
  it logs in under the rotator's production policy and drifts each pinned
  setting on a fresh key.
- **Proof:**
  - each call above is refused with 403;
  - the policy check fails the fixture;
  - each refused call raises its alert;
  - `codewire-orchestration identity rotate` fails, and changes nothing, on a
    drifted key.
- **Gotchas:** never drift a real key. `exportable` and
  `allow_plaintext_backup` can't be turned off again, and the test drifts
  only throwaway keys.
- **Observed:** partly, on Dev on 2026-11-22 (#4662). No helper exists yet, so
  OpenBao's own engine is the evidence, not live refused calls:
  - the key's custody pins read back exact (`exportable=false`,
    `plaintext_backup=false`, `deletion_allowed=false`);
  - the capability audit found no violations and no unreviewed holder of
    either role's policy across 119 policies;
  - the deny-rule read-back found the block on all 117 other policies.

  Then, live, on Dev on 2026-11-23 at 16:15Z with the custody walk:
  - The signer's export, backup, rotate and config write, and the rotator's
    sign, export, backup and two config writes, each answered 403
    `permission denied`: 4 of 4 and 5 of 5.
  - Both roles read the key's config before and after, and all four reads
    were identical, with the custody pins exact.
  - The policy check failed the fixture without the deny rules and passed
    the control.
  - All 13 expected alert series fired at 16:15:55Z:
    `SandboxIdentityKeyExfiltrationAttempt` and
    `SandboxIdentityKeyConfigDenied` (critical), and
    `SandboxIdentityKeyUnexpectedCaller` (warning). Three pages reached the
    on-call channel within 30 seconds, matched to the alerts by time.

  Then, by test, on 2026-11-23 (#4662), against an OpenBao 2.5.4 dev server:
  - With every pin intact, the job raised both minimums to 3 and rotated
    to version 4 under the rotator's policy.
  - With `auto_rotate_period`, `exportable`, `allow_plaintext_backup` or
    `deletion_allowed` drifted, each on its own key, the job failed with
    its drift error, and each key read back identical before and after.

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

## 11. `identity-audit`: every change and mint is on the record

- **Driving it:** after steps 1 to 5, read the `audit_logs` rows with the
  organization's ID, and `identity_mints` for `A`.
- **Proof:**
  - one `identity.groups.changed`, `identity.audience.registered`,
    `identity.stopped` and `identity.resumed` row per action, with actor and
    before and after;
  - one `identity_mints` row per signature, not per cache hit, with `jti` and
    `kid`, and no column holding a token.
- **Observed:** partly, on Dev on 2026-11-24 (#4664). `audit_logs` held exactly
  one row per action, each with its actor: `identity.audience.registered`,
  `identity.groups.changed` (before `[]`, after `["data-readers"]`),
  `identity.stopped` and `identity.resumed`. The six refused registrations
  wrote none. `identity_mints` has no column holding a token, and no row yet,
  because nothing has been signed.

## 12. `identity-files`: a projected token stays current, in memory, and nowhere else

- **Entry points:** `cw identity audience add URI --file k8s`, the file
  `/codewire/run/identity/k8s.jwt` in a Sandbox made after the change, and the
  scratch cluster from step 1.
- **Driving it:**
  0. Before any file is written: on Dev, `kubectl apply --dry-run=server` of
     a warm-pool template whose `codewire-run` volume is `{}` is refused by
     the warm-pool template policy, whose Flux Kustomization reads Ready.
  1. Register `https://k8s.walk.example` with `--file k8s`. In a new Sandbox:
     `stat -c '%a' /codewire/run/identity /codewire/run/identity/k8s.jwt`
     prints `700` and `600`, and `stat -f -c %T /codewire/run/identity`
     prints `tmpfs`.
  2. `kubectl --server "$KIND" --token "$(cat /codewire/run/identity/k8s.jwt)"
     get pods -n data` lists the Pods, as step 1's command does.
  3. The file's modification time moves at about half the token's lifetime.
  4. `cw identity stop A`: the file is gone at the next renewal, at half life;
     `cw identity resume A` brings it back within a minute.
  5. Remove the audience: the file is gone within one access refresh.
  6. `cw cp A:/codewire/run/identity/k8s.jwt .`, an sftp read and the
     dashboard's files view are refused, and so is a `/workspace` link into
     `/codewire/run`.
  7. A ninth file audience in the organization is refused with
     `identity_file_limit`.
- **Proof:** the `stat` lines, the refusals, the file's times against the
  token's `iat` and `exp`, and the daemon log naming the audience and file,
  never the token.
- **Observed:** not yet built.

## The other steps

Step 9, Codewire's own OpenBao trusting the Dev issuer, is written with #4666.
Its proxy is a route on the in-cluster `codewire-sandbox` gateway, so it runs
only from broker-mode Sandboxes.
