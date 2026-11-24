# Host-bound application secrets

An application secret bound to hosts reaches the environment as a
placeholder, and the front door swaps in its value only on a request to
those hosts (#4003). The rules are in
[`docs/dev/SECRETS-AND-CREDENTIALS.md`](../dev/SECRETS-AND-CREDENTIALS.md),
"Host-bound application secrets". This journey was written before the code,
and the flags in it are the ones that section proposes; the exact output
comes with the CLI and dashboard designs. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-24. Written first; every step is not yet observed.

| ID | Linux local VM | macOS local VM | Dev | Production |
| --- | --- | --- | --- | --- |
| `secret-plain` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-bound` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-echo-redacted` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-hint` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-reentry` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-host-change` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-host-conflict` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-preset` | not yet observed | not yet observed | not yet observed | not yet observed |
| `secret-dashboard` | n/a | n/a | not yet observed | not yet observed |

## Before the walk

- **The fixture.** An HTTPS endpoint on Dev, at a public name with a
  publicly trusted certificate, checked into the infrastructure repository
  (`codewire-walk-echo`, Dev only). Every reply carries a request ID and
  SHA-256 digests of the headers, query and body it received, never a value,
  so a walk compares them with its canary's digests; `/echo` also returns
  the headers as received, and `/requests` lists the last requests'
  digests. Cookies are never echoed or recorded. Below,
  `FIXTURE` is its host name and `OTHER` a second host the walk controls
  that the binding doesn't name.
- **A canary value.** A synthetic, canary-marked value, never a real key,
  made in the walk's scratch directory and passed on stdin. The walk greps
  for it; it is never printed.
- **Accounts.** On Dev, two walk accounts in one organization: A, an admin,
  and M, a member. A scratch `cw` home for each (`HOME` and `CW_CONFIG_DIR`
  under the walk's scratch directory). Remove every secret, project and
  environment the walk makes by exact name afterwards.
- **Where.** A Linux local VM, a macOS local VM, and a hosted Sandbox on Dev.
  Fake credentials and the echo demonstrations run only inside a Codewire
  VM or Sandbox, never on the walker's computer.
- **A network policy** that allows `FIXTURE` and `OTHER` on 443.
- **What to record:** `cw version`, the source Dev was running, and the
  fixture's request IDs.

## `secret-plain`: a secret with no hosts behaves as today

- **Entry points:** `cw secrets set`, `cw create --secrets`, the dashboard's
  secrets page.
- **States to exercise:** a plain project secret, a plain personal secret.
- **Driving it:**
  1. `cw secrets --cloud --project=walk set PLAIN_TOKEN < canary` and
     `cw create --secrets walk walk-plain`.
  2. Inside: `printenv PLAIN_TOKEN | sha256sum`, and a request to
     `https://FIXTURE/` with it in `Authorization`.
- **Proof:** the hash inside equals the canary's hash, and the fixture
  recorded the canary as sent. No front door binds `FIXTURE`: the
  fixture's own certificate is seen inside (`openssl s_client` prints its
  issuer, not the environment's CA).
- **Gotchas:** compare hashes, never print the value.
- **Observed:** not yet observed.

## `secret-bound`: the environment sees a placeholder, and only the bound host gets the value

- **Entry points:** `cw secrets set --host`, `cw create --secrets`.
- **States to exercise:** a project secret on a hosted Sandbox; a local
  personal secret and a platform project secret on each local VM; the
  `header` presentation with the default and with `--header X-Api-Key
  --scheme none`; `basic` for Git over HTTPS to `FIXTURE`.
- **Driving it:**
  1. `cw secrets --cloud --project=walk set FANCY_TOKEN --host FIXTURE --prefix ft_ < canary`.
  2. `cw create --secrets walk walk-bound`, then inside:
     `printenv FANCY_TOKEN`.
  3. `curl -H "Authorization: Bearer $FANCY_TOKEN" https://FIXTURE/` and the
     same to `https://OTHER/`.
- **Proof:**
  - inside, `FANCY_TOKEN` is `ft_cwp1_` and 43 characters, and the canary
    is nowhere in the environment: not in `/proc/*/environ`, the
    environment's files or its logs (the `no-token-at-rest` scan of
    [network-and-egress.md](network-and-egress.md), with the canary added);
  - the fixture's record for the request ID shows `Bearer` and the canary;
  - `OTHER` recorded the placeholder, never the canary;
  - a second environment from the same source has a different placeholder.
  - `cw secrets --cloud --project=walk list` shows `FIXTURE` beside
    `FANCY_TOKEN`, and `plain` beside `PLAIN_TOKEN`;
  - binding a host the deployment serves itself, such as its registry, is
    refused with `bound_host_reserved`.
- **Gotchas:** `OTHER` must be a host the walk reads, so its record proves
  what was sent. A request to `OTHER` isn't intercepted, so Codewire logs
  nothing for it.
- **Observed:** not yet observed.

## `secret-echo-redacted`: an echo of the header comes back redacted

- **Driving it:** inside `walk-bound`,
  `curl -H "Authorization: Bearer $FANCY_TOKEN" https://FIXTURE/echo`.
- **Proof:** the reply holds no canary, in its raw, JSON-escaped, percent or
  base64 forms, and the fixture's record shows the canary was sent.
- **Observed:** not yet observed.

## `secret-hint`: a placeholder outside its binding is refused, with the command that fixes it

- **Driving it:** inside `walk-bound`, send the placeholder to `FIXTURE` in
  `X-Api-Key`, then in the query string (`?key=$FANCY_TOKEN`), then in a JSON
  body.
- **Proof:**
  - each is answered 403 with `Codewire-Refusal: placeholder_outside_binding`,
    and the fixture recorded none of them;
  - the header case's `Fix:` line is the exact `cw secrets --cloud
    --project=walk set FANCY_TOKEN --host FIXTURE --header X-Api-Key
    --scheme none`, and
    says it asks for the value again;
  - the query and body cases say Codewire can't protect a value sent
    there and that a plain secret is readable by every process in the
    environment, and never advise making it plain;
  - `cw policy log` shows the same refusals and hints, with no value;
  - the binding is unchanged afterwards (`cw secrets … list`).
- **Observed:** not yet observed.

## `secret-reentry`: a shared secret's binding can't be redirected without its value

- **States to exercise:** A (admin) on the project secret; M (member).
- **Driving it:**
  1. As A, with no value on stdin:
     `cw secrets --cloud --project=walk set FANCY_TOKEN --host OTHER`, then
     `--header X-Other`, then `--plain`, then replacing `FIXTURE` with
     `OTHER` in one request, then a `--preset` whose header differs.
  2. As A, `--remove-host` of one of two hosts, and `--prefix sk_`, with no
     value.
  3. As M, any binding change.
  4. As A, rename the bound `FANCY_TOKEN`.
- **Proof:** the rename in step 4 is refused with `secret_bound_rename`,
  naming the set-then-delete step, and the key is unchanged; each change in
  step 1 is refused with `secret_value_required`,
  naming the change, and `list` shows the binding unchanged; step 2
  succeeds without a value; step 3 is refused as setting the secret is
  today.
- **Observed:** not yet observed.

## `secret-host-change`: removing a host applies at once; adding one applies at the next start

- **Driving it:**
  1. Bind `FANCY_TOKEN` to `FIXTURE` and `OTHER` (with the value), create
     `walk-hosts`, and send to both.
  2. Remove `OTHER` (`--remove-host OTHER`) while it runs, and send again.
  3. Add `OTHER` back (with the value); send again; then restart
     `walk-hosts` and send again.
- **Proof:** in step 2 the next request to `OTHER` is refused
  `secret_not_bound_to_host`, with no restart, while `FIXTURE` still gets
  the canary. In step 3 `OTHER` stays refused until the restart and gets
  the canary after it. The placeholder is the same throughout.
- **Observed:** not yet observed.

## `secret-host-conflict`: two values never name one host

- **Driving it:** bind a second secret to `FIXTURE`, then
  `cw create --secrets walk walk-conflict`; then select both through a
  source change on a running environment.
- **Proof:** the create is refused with `bound_host_conflict`, naming
  `FIXTURE` and both keys, and nothing is created; the source change is
  refused the same way and the running environment is unchanged.
- **Observed:** not yet observed.

## `secret-preset`: a preset fills in the right fields

- **Driving it:** `cw secrets … set KEY --preset NAME < canary` for each row
  of the preset table, then `list --output json`.
- **Proof:** the binding's hosts, header, scheme and prefix equal the
  table's row; a flag given beside `--preset` overrides its field.
- **Gotchas:** a preset names a vendor's real host, so its swap is walked
  only against `FIXTURE`; the real host is checked by `list` alone.
- **Observed:** not yet observed.

## `secret-dashboard`: the delivery column and the Protect action

- **Entry points:** the dashboard's secrets page, desktop and 390 px.
- **States to exercise:** no secrets; plain and bound secrets; Protect on a
  plain secret, asking for the value; a refused binding (a wildcard, an IP
  address, a refused header, a provider's host); the API failing.
- **Proof:** the delivery column says plain or the bound hosts for each
  key; Protect binds only after the value is entered and the change shows
  in `cw secrets … list`; each refusal names its field; a failed request
  says so and changes nothing.
- **Gotchas:** the screens wait for the owner's "land it".
- **Observed:** not yet observed.
