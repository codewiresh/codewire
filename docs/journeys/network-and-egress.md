# Network and egress

This walk proves what an environment may reach on the Internet, what a user
sees when a destination is refused, and that an agent in an environment works
with its stock settings while its credential stays outside. It belongs to
Program #3997 and its issues #3999 (local VMs), #4000 (hosted Sandboxes),
#2537 (local network policies) and #4015 (refusals an agent can act on).
`SPEC.md` "Networking and egress" defines the feature. The format is in
[README.md](README.md).

**This file describes the target, and every step reads "not yet observed".**
The owner's rule of 2026-11-15 (#3013) is that the spec and the journey are
written first and code follows; a review refuses code this file does not
describe. What ships today is in `docs/dev/SECRETS-AND-CREDENTIALS.md` and in
the user docs (`apps/docs/zola/content/networking/egress.md`).

**Agents use the real provider hosts.** Retiring the base-URL routes for
agents (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and Codex's managed provider)
is required, not optional (owner, 2026-11-15, #3997). An agent's plan display,
`/usage` and account features depend on the agent talking to its provider's
own host with its own login. A TLS front door outside the environment makes
that possible while the environment holds only a placeholder. No step here is
met by a base-URL route.

## Where the walk stands

Updated 2026-11-15. A hosted Sandbox is recorded on Dev and on Production
separately.

| ID | Issue | Linux local VM | macOS local VM | Dev | Production |
| --- | --- | --- | --- | --- | --- |
| `policy-select` | #2537 | not yet observed | not yet observed | n/a | n/a |
| `policy-project-file` | #2537, #4835 | no command yet | no command yet | no command yet | no command yet |
| `policy-hosted` | #4000, #4211 | n/a | n/a | no command yet | no command yet |
| `policy-protected` | #2537, #4000 | not yet observed | not yet observed | no command yet | no command yet |
| `refusal-log` | #3999, #4000 | no command yet | no command yet | no command yet | no command yet |
| `refusal-in-environment` | #4015 | no command yet | no command yet | no command yet | no command yet |
| `learn-mode` | #4015 | after launch | after launch | after launch | after launch |
| `agent-vm-interception` | #3999 (#4809, #4884, #4812, #4887) | no command yet | no command yet | n/a | n/a |
| `agent-claude` | #3999, #4001 | no command yet | no command yet | no command yet | no command yet |
| `agent-codex` | #3999, #4001 | no command yet | no command yet | no command yet | no command yet |
| `agent-own-key` | #3999, #4001 | no command yet | no command yet | no command yet | no command yet |
| `agent-fail-closed` | #3999, #4001 | no command yet | no command yet | no command yet | no command yet |
| `agent-switch-off` | #3999 | no command yet | no command yet | n/a | n/a |
| `agent-hosted` | #4001 | n/a | n/a | no command yet | no command yet |
| `hosted-enforcement` | #4000 | n/a | n/a | no command yet | no command yet |

#2537's status comment of 2026-10-24 records an earlier host walk of
`policy-select` (select at create and update, and a live edit across two VMs).
It names no source commit, so it is not carried here as an observation; walk
it again and record it in this file.

## Before the walk

- Record `cw version` with every observation. A local VM runs the runtime of
  the `cw` that started it: run `cw setup --local`, and stop and start an
  existing VM after an upgrade.
- A Linux local VM needs an x86_64 KVM host. A macOS local VM needs an Apple
  Silicon Mac. Record which.
- Give `cw` a throwaway `HOME` for everything except the agent steps, so the
  walk never touches the walker's own sign-in or policies.
- The agent steps need a real provider login. That is the owner's own Claude
  or ChatGPT sign-in, connected by the owner. Prepare everything else first
  and ask once for that step. Never print, copy or record a token; the proofs
  below read shapes and labels, not values.
- Use names that mark the walk (`egress-walk`, `egress-walk-policy`) and
  remove them at the end.

## `policy-select`: choose what a local VM may reach

Issue: #2537. Code: `crates/codewire-egress-policy`,
`crates/codewire-egress-broker`. User docs:
`apps/docs/zola/content/networking/egress.md`.

- **Entry points:** `cw --local policy create | list | allow | rm | check |
  delete`; `cw create --local --policy REF`; `cw update ENV --policy REF`;
  `cw info ENV`.
- **States to exercise:**
  - the built-ins `open` (the default) and `locked`;
  - a policy made from `locked` that allows two names, one a wildcard;
  - a VM created with `--policy`, and a running VM moved with `cw update`;
  - an edit to a policy two running VMs select: an allow, then a removal;
  - deleting a policy a VM still selects.
- **Driving it:**

  ```sh
  cw --local policy list
  cw --local policy create egress-walk-policy --allow 'example.com,*.example.org'
  cw --local policy check egress-walk-policy example.com:443
  cw --local policy check egress-walk-policy example.net:443
  cw create --local --name egress-walk --policy egress-walk-policy -y
  cw --local info egress-walk
  cw --local exec --in egress-walk -- curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/
  cw --local exec --in egress-walk -- curl -sS -m 10 https://example.net/
  cw --local policy allow egress-walk-policy example.net
  cw --local exec --in egress-walk -- curl -sS -o /dev/null -w '%{http_code}\n' https://example.net/
  cw --local policy rm egress-walk-policy example.net
  cw --local update egress-walk --policy locked
  cw --local policy delete egress-walk-policy
  ```

- **Proof:**
  - `check` prints `Allowed` for the first name and
    `Refused: … (name not allowed)` for the second;
  - `cw info` names the policy and its revision;
  - the first `curl` prints `200`; the second fails within a second, not
    after its 10 s limit;
  - after `allow`, the same `curl` prints `200` with no restart, and
    `cw policy allow` names the VMs that now enforce the edit;
  - after `rm`, an open connection to the removed name ends, and one to the
    still-allowed name stays open;
  - after `update --policy locked`, every outbound connection is refused;
  - `delete` is refused while a VM selects the policy, and succeeds after.
- **Gotchas:**
  - A policy allows names. The broker dials only an address it resolved for
    an allowed name, so a raw IP address is refused unless a rule covers it.
  - `open` allows TCP 22, 80 and 443 only. A refusal on another port is the
    port rule, not the name.
- **Observed:** not yet observed.

## `policy-project-file`: `codewire.yaml` names a policy

Issue: #2537 step C, pull request #4835.

- **Entry points:** `network: { policy: REF }` in `codewire.yaml`, read by
  `cw create --local`.
- **States to exercise:**
  - the file names a policy and no flag is given;
  - the file names one policy and `--policy` names another;
  - the file tries to define a rule (an `allow` key);
  - the file names a policy that does not exist;
  - the same file given to `cw create --cloud`.
- **Driving it:** no command yet; the key lands with #4835. Then: create a VM
  from a directory whose `codewire.yaml` names `egress-walk-policy`, and read
  `cw info`.
- **Proof:**
  - with no flag, the create's review and its result both show the file's
    policy and that it came from `codewire.yaml`, and `cw info` shows it;
  - with a flag, both show the flag's policy and that it came from
    `--policy`;
  - a rule key is refused before anything is created, naming the key;
  - a cloud create refuses the file's policy by name, as local-only, until
    the cloud command of `policy-hosted` exists. It is never silently
    ignored.
- **Gotchas:** the file is read at create. Editing it later does not change a
  running VM; `cw update ENV --policy REF` does.
- **Observed:** not yet observed.

## `policy-hosted`: an organization's policies for hosted Sandboxes

Issue: #4000. The store and its API merged with #4211, behind a switch.

- **Entry points:** `cw policy --cloud` and `--policy` on `cw create --cloud`
  and `cw update`. No command yet; #4000 adds them. The dashboard has no page
  for this yet.
- **States to exercise:**
  - an organization policy created, edited and selected at create;
  - a running Sandbox moved to another policy;
  - a member of another organization trying to read or select it;
  - deleting a policy a Sandbox selects;
  - the default when nothing is selected (any TCP port through the broker,
    plus DNS; other UDP off unless the environment opts in).
- **Driving it:** no command yet (#4000).
- **Proof:**
  - a destination the policy allows answers, and one it does not fails at
    once;
  - an edit reaches a running Sandbox with no restart and ends the
    connections the new revision refuses;
  - the status of `hosted-enforcement` shows the revision the Sandbox
    enforces;
  - another organization's member can neither read nor select the
    policy.
- **Gotchas:** a hosted policy is stored on the platform, a local one on the
  host. The same name in both is two policies.
- **Observed:** not yet observed.

## `policy-protected`: addresses no policy can allow

Issues: #2537, #4000.

- **Entry points:** every policy, on every placement.
- **States to exercise:** a loopback address, a private address, a
  link-local and metadata address, the host's own address (local), another
  Sandbox's address and the cluster's service addresses (hosted), each tried
  under `open` and under a policy that names it.
- **Driving it:** on a local VM:

  ```sh
  cw --local policy check open 192.168.1.10:443
  cw --local exec --in egress-walk -- curl -sS -m 10 http://169.254.169.254/
  ```

  Hosted: no command yet (#4000, with the static floor of its journey).
- **Proof:** `check` prints `Refused: … (protected address)`; the `curl`
  fails at once; naming a protected address in a policy does not make it
  reachable.
- **Gotchas:** a name that resolves only to protected addresses is refused as
  a name. Do not read that as a DNS outage.
- **Observed:** not yet observed.

## `refusal-log`: the owner sees what was refused, and why

Issues: #3999 (local), #4000 (hosted).

- **Entry points:** `cw policy log ENV` on the host; `cw policy --cloud log`
  for a hosted Sandbox; one line in `cw info ENV`. No command yet for any of
  them.
- **States to exercise:**
  - an environment that refused nothing (an empty log reads as empty);
  - one refusal of each kind: a name not allowed, a port not allowed, a
    protected address, an expired name lease;
  - the same destination refused many times (one line, a count);
  - a one-step allow from a log line.
- **Driving it:** no command yet (#3999, #4000).
- **Proof:**
  - each refusal shows the name, the address where there is one, the port,
    the policy and revision, the reason, the first and last time and a
    count;
  - no payload, header or credential appears;
  - after the one-step allow, the same request succeeds and the log shows no
    new refusal for it.
- **Gotchas:** a refused connection and an unreachable one look the same
  from inside the environment. Only the log tells them apart.
- **Observed:** not yet observed.

## `refusal-in-environment`: an agent finds out why a connection failed

Issue: #4015.

- **Entry points:** a command inside the environment that lists this
  environment's recent refusals (command to be named in #4015), and a managed
  note in the agents' instruction files telling them to run it after a
  connection error.
- **States to exercise:**
  - no refusals (an empty list reads as empty);
  - a refused name, then the list;
  - a refusal of a protected address;
  - an agent trying to change the policy or the list from inside;
  - a restored VM checkpoint.
- **Driving it:** no command yet (#4015).
- **Proof:**
  - after a refused connection, Claude Code finds the cause with the
    command, as its note tells it to;
  - a protected refusal reads as an ordinary "not allowed", so the list
    never reveals which names or addresses are protected;
  - nothing inside the environment can change the policy or the list;
  - after a restore, the list holds only the restored environment's own
    refusals.
- **Gotchas:** the owner's `cw policy log` shows the full reason. The two
  views differ on purpose.
- **Observed:** not yet observed.

## `learn-mode`: record what an environment reaches, then lock it

Issue: #4015. **After launch.** Nothing here gates the launch walk.

- **Entry points:** a learn switch for an environment and `cw policy lock
  ENV` (#4015). No command yet.
- **States to exercise, when it is built:** a VM that learned during a
  package install; the proposed policy with known registries ticked and
  unknown hosts unticked; locking it.
- **Driving it:** no command yet (#4015).
- **Proof:** locking applies the proposed policy, and a host that was not
  ticked is refused afterwards.
- **Gotchas:** a compromised dependency's host appears in the proposal like
  any other. The proposal is a list to read, not a recommendation.
- **Observed:** not yet observed.

## `agent-vm-interception`: a local VM boots with interception on

Issue: #3999. Its pieces: the per-host switch, the certificate authority and
the placeholders in the VM's seed (#4809), the front door process and its
pairing (#4884), placeholder delivery (#4812, #4887). The local Claude
sign-in it uses is #4798, whose walk is the credentials journey that pull
request adds.

- **Entry points:** the per-host switch for local VMs (no command yet,
  #4809), then `cw create --local` or `cw start` as usual. Nothing inside the
  VM turns interception on.
- **States to exercise:**
  - the switch on, with a Claude credential selected: an API key, and the
    owner's Claude sign-in;
  - the switch on with no agent credential selected;
  - an image that sets its own `NODE_EXTRA_CA_CERTS`;
  - an image with no system certificate bundle;
  - the credential profile changed, then a stop and start;
  - a VM checkpoint restored in place, and one restored after the switch
    changed;
  - a local VM whose credentials come from the platform rather than the
    local store;
  - the front door unable to start, and the credential broker never
    connecting to it.
- **Driving it:** no command yet (#3999). With the switch on and the VM
  started:

  ```sh
  cw --local exec --in egress-walk -- sh -c 'printenv NODE_EXTRA_CA_CERTS'
  cw --local exec --in egress-walk -- sh -c 'env | grep -c -E "^(ANTHROPIC|OPENAI)_BASE_URL=" || true'
  cw --local exec --in egress-walk -- sh -c 'env | grep -E "^(SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|GIT_SSL_CAINFO)=" || true'
  ```

- **Proof:**
  - the switch is read once at each boot; the boot's recorded state and the
    supervisor's log both say whether interception was on;
  - **the guest trusts the boot's certificate authority, from the seed**
    (#4809, #4884). With the switch on, the boot's seed carries the
    authority's certificate, the guest publishes it as a read-only file, and
    `NODE_EXTRA_CA_CERTS` names that file. Nothing else is set: no
    `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` or
    `GIT_SSL_CAINFO`. The authority belongs to this boot alone, and its key
    exists only in the front door process's memory, never on a disk and
    never in the VM;
  - an image's own `NODE_EXTRA_CA_CERTS` is kept, and the boot log says
    Codewire set none. No other certificate variable is set, and the image's
    system bundle is not written or mounted over;
  - the VM holds a placeholder for each selected Claude credential (it
    begins `cwp1_`) in place of the token, and no base-URL variable. With an
    API key or a subscription token selected, the placeholder is the value
    of the one variable the agent reads; with a sign-in, it is the access
    token of Claude Code's login file;
  - the front door is running and connected to the credential broker before
    the VM reports started. If it cannot start, or the broker does not
    connect within the limit, the start fails with the reason; it never
    reports started with requests left hanging;
  - a VM whose credentials come from the platform refuses to start with the
    switch on, and says why, until that route carries interception;
  - **a restore with interception on at both ends is allowed, and the
    restored boot trusts its own new authority** (#4809, #4884). The trust
    files are replaced from the restored boot's seed before the workload
    thaws. The placeholders are unchanged, because they derive from the
    environment and its credential binding, not from a boot (#4812). An
    agent started after the restore works. An agent process that was already
    running at the checkpoint loaded the earlier authority when it started,
    so its next request to an intercepted host fails with a TLS error until
    that process is restarted;
  - a restore after the switch changed, on to off or off to on, is refused
    and says that a stop and start applies the switch (#4809);
  - after the profile changes and the VM is stopped and started, the VM
    holds the new credential's placeholder and the old one no longer works.
- **Gotchas:**
  - The placeholder is tied to the environment and to its credential
    profile's revision, not to a boot. A fork is another environment: it
    gets other placeholders, and its running agents must restart.
  - With the switch on and no agent credential selected, nothing is
    intercepted and the VM is as with the switch off.
  - Known limit, tracked on #3999: a restore gives the VM a new certificate
    authority, and a running process cannot reload the one it trusts. Agents
    that were running at the checkpoint must be restarted after a restore
    before they reach an intercepted host again.
  - macOS: until the front door has its sandbox profile there, a boot with
    the switch on is refused, and says so.
- **Observed:** not yet observed.

## `agent-claude`: Claude Code with stock settings and no token inside

Issues: #3999 (local VMs), #4001 (hosted Sandboxes). The local Claude sign-in
is #4798.

- **Entry points:** the owner's Claude sign-in, connected with
  `cw credentials --local connect claude` for local VMs (#4798) or
  `cw credentials --cloud connect claude` for hosted Sandboxes, and selected
  in the environment's credential profile. Then `claude` inside the
  environment.
- **States to exercise:**
  - a model call (`claude -p`);
  - the header's plan label, `/status` and `/usage`;
  - a long session across a token refresh;
  - the credential revoked while the agent runs;
  - a stopped and started environment, and a restored VM checkpoint, with
    an agent started after the restore and one that was running at the
    checkpoint (see `agent-vm-interception` for the known limit);
  - a Sandbox or VM that another person can open a terminal in.
- **Driving it:** no command yet for turning interception on (#3999 for a
  local VM; #4001 for a hosted Sandbox). With it on:

  ```sh
  cw --local exec --in egress-walk -- sh -c 'env | grep -c -E "^(ANTHROPIC|OPENAI)_BASE_URL=" || true'
  cw --local exec --in egress-walk -- claude -p 'Reply with the single word ok.'
  ```

  Then, in a shell in the environment, start `claude` and run `/status` and
  `/usage`.
- **Proof:**
  - the first command prints `0`: neither `ANTHROPIC_BASE_URL` nor
    `OPENAI_BASE_URL` is set. With a sign-in, no Anthropic credential
    variable is set either, and `ANTHROPIC_API_KEY` is never set by
    Codewire;
  - the model call answers;
  - the header shows the plan's name (for example "Claude Max"), never
    "Claude API";
  - `/status` shows the owner's account and organization, and `/usage` shows
    the plan's usage;
  - the access token in Claude Code's login file is a Codewire placeholder
    (it begins `cwp1_`), and the real token appears nowhere in the
    environment: not on its disk, not in a VM checkpoint, a hosted volume or
    a snapshot, and not in the daemon's or the egress processes' logs;
  - the session keeps working past the real token's expiry;
  - after `cw credentials revoke`, the next model call fails and none
    succeeds after it.
- **Gotchas:**
  - A header that reads "Claude API", or a `/usage` that is unavailable,
    means the agent is not on this path. Do not record the model call alone
    as this step.
  - The placeholder is not a secret, and it belongs to one environment.
    Copied into another environment it is forwarded untouched and the
    provider rejects it.
  - The proof of "nowhere" needs a search of the disk, the checkpoint and
    the logs for the real token, done by its holder without printing it. No
    command yet; the tool is owned by #3999, whose done-when requires that
    no real token is found there.
- **Observed:** not yet observed.

## `agent-codex`: Codex with stock settings and no token inside

Issues: #3999, #4001.

- **Entry points:** the owner's ChatGPT sign-in, connected with
  `cw credentials connect codex`, selected in the profile. Then `codex`
  inside the environment.
- **States to exercise:** a model call; the plan and account display; an
  account whose model traffic is routed to another origin; a token refresh; a
  revoked credential.
- **Driving it:** no command yet (#3999, #4001).
- **Proof:**
  - `OPENAI_BASE_URL` is not set, and Codex's configuration names no managed
    provider;
  - a model call answers, and Codex shows the owner's plan and account;
  - Codex's login file holds placeholders in place of its tokens, with the
    account's non-secret fields, and the real tokens appear nowhere in the
    environment.
- **Gotchas:** Codex takes the origin for model traffic from its
  account-routing reply. A routed origin that the front door does not cover
  fails closed, and the refusal log names it.
- **Observed:** not yet observed.

## `agent-own-key`: a process with its own key is left alone

Issues: #3999, #4001.

- **Entry points:** any program in the environment that calls an intercepted
  host with a key of the user's own.
- **States to exercise:** a request carrying the user's own API key; one
  carrying no credential; one carrying the placeholder together with another
  credential header.
- **Driving it:** no command yet (#3999, #4001).
- **Proof:**
  - the user's own key reaches the provider unchanged, and the assigned
    credential is not used for that request;
  - a request with no credential is forwarded as sent and gets the
    provider's own 401;
  - the placeholder beside another credential header is refused by Codewire
    before it reaches the provider, with an error that says to send one
    credential.
- **Gotchas:** only a request carrying this environment's placeholder is
  swapped. The reply to any other request is passed back as the provider
  sent it.
- **Observed:** not yet observed.

## `agent-fail-closed`: losing the front door never opens a direct path

Issues: #3999, #4001.

- **Entry points:** none for a user. An operator ends the environment's front
  door process, or the credential broker.
- **States to exercise:** the front door killed while an agent runs; the
  credential broker killed; either one missing when the environment starts.
- **Driving it:** no command yet (#3999, #4001).
- **Proof:**
  - after either ends, a request to an intercepted host fails at once, and
    no connection leaves for that host from the egress broker;
  - other destinations keep following the network policy;
  - an environment whose front door cannot start does not start with
    interception half on: it reports the failure, and a stop and start
    restores it.
- **Gotchas:** a request that hangs is a failure of this step, even though
  nothing leaked.
- **Observed:** not yet observed.

## `agent-switch-off`: with interception off, a local VM behaves as today

Issue: #3999.

- **Entry points:** the per-host switch for local VMs, off by default, which
  the change that makes interception the default removes. No command yet
  (#3999).
- **States to exercise:** the switch absent; the switch holding something
  other than its one accepted value; a VM checkpoint taken with it off and
  restored with it on, and the reverse.
- **Driving it:** no command yet (#3999).
- **Proof:**
  - with the switch absent or unrecognised, a VM boots and its agents use
    today's routes, exactly as `docs/dev/SECRETS-AND-CREDENTIALS.md`
    describes; an unrecognised value is logged once;
  - **with the switch off the guest has no certificate authority** (#4809,
    #4884): the seed carries none, the guest publishes no certificate file,
    and Codewire sets no `NODE_EXTRA_CA_CERTS`;
  - a restore across a change of the switch is refused, and says that a stop
    and start applies it.
- **Gotchas:** hosted Sandboxes have no such switch; their rollout is a
  deployment setting (#4000, #4001).
- **Observed:** not yet observed.

## `agent-hosted`: a hosted Sandbox's front door serves that Sandbox alone

Issue: #4001. This step adds what only the hosted placement has to prove;
`agent-claude`, `agent-codex`, `agent-own-key` and `agent-fail-closed` are
walked on a hosted Sandbox as well.

- **Entry points:** none for a user. Interception is a deployment setting
  for hosted Sandboxes (#4001).
- **States to exercise:**
  - two Sandboxes of different users on one node, each with a Claude
    credential;
  - one Sandbox's front door session opened with another Sandbox's token;
  - a Claude turn with interception on, and the same turn on today's relay
    path;
  - `cw-egress`'s logs and configuration after a session.
- **Driving it:** no command yet (#4001).
- **Proof:**
  - a front door session for one Sandbox is refused another Sandbox's
    token, and no request of one Sandbox is ever served with the other's
    credential;
  - a Claude turn's time to its first token and its streaming rate through
    hosted interception are recorded beside the same turn on today's relay
    path, on the same Dev node;
  - the real token appears nowhere in `cw-egress`'s logs or configuration,
    beside the check inside the Sandbox that `agent-claude` makes.
- **Gotchas:** the search for the real token is done by its holder, without
  printing it; the tool is owned by #3999.
- **Observed:** not yet observed.

## `hosted-enforcement`: a hosted Sandbox proves its egress is enforced

Issue: #4000.

- **Entry points:** the environment's network policy status, in `cw info`
  and the API; no user action starts the checks.
- **States to exercise:**
  - a stopped Sandbox, and one whose placement has no egress broker;
  - a running Sandbox on its selected revision;
  - a running Sandbox just moved to a new revision;
  - a Sandbox whose lockdown is not applied when it starts;
  - a Sandbox claimed from the warm pool;
  - a new `cw-egress` version rolled out while a Sandbox holds open
    connections.
- **Driving it:** no command yet (#4000).
- **Proof:**
  - the status reads `NOT_ENFORCED` for the first state, `ENFORCED` with the
    enforced revision for the second, `ENFORCING` until the new revision
    takes over for the third;
  - at every start the Sandbox tries one direct connection and one lookup
    at the cluster's DNS, around its egress path. Both must fail. If either
    succeeds the Sandbox does not become ready, its status reads
    `FAILED_CLOSED`, and an operator alert fires;
  - a claimed warm Sandbox enforces the claimer's policy before the user can
    run anything in it; a claim that cannot confirm that within its limit
    fails, and never hands over an unrestricted Sandbox;
  - a `cw-egress` rollout in the middle of a session resets each open
    connection at most once, and the Sandbox's egress works on the new
    version afterwards (#4000, item 5).
- **Gotchas:**
  - `NOT_ENFORCED` on a running Sandbox is a finding, not a default.
  - A status whose latest report is older than 15 minutes (three of
    cw-egress's 5-minute refreshes) reads `NOT_ENFORCED`; do not trust a
    cached `ENFORCED`.
- **Observed:** not yet observed.
