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

Updated 2026-11-23. A hosted Sandbox is recorded on Dev and on Production
separately.

| ID | Issue | Linux local VM | macOS local VM | Dev | Production |
| --- | --- | --- | --- | --- | --- |
| `policy-select` | #2537 | observed 2026-11-16, source 40a2877e7 | not yet observed | n/a | n/a |
| `policy-project-file` | #2537, #4835 | no command yet | no command yet | no command yet | no command yet |
| `policy-hosted` | #4000, #4211 | n/a | n/a | partly observed 2026-11-23, Dev source 42306388f8 (steps 1 to 5 and 8, and the enforcement half; step 6 not walked) | not yet observed |
| `policy-dashboard` | #5114, #5116, #5117 | n/a | n/a | not yet observed | not yet observed |
| `policy-protected` | #2537, #4000 | observed 2026-11-16, source 40a2877e7 | not yet observed | no command yet | no command yet |
| `locked-refuses-managed-github` | #4926 | not yet observed | not yet observed | n/a | n/a |
| `egress-late-answer` | #4948 | not yet observed | not yet observed | n/a | n/a |
| `refusal-log` | #5058, #4000, #3997 | observed 2026-11-21, a build of 385cf721d9, c403fcf960 after a rebase onto main (the egress broker's rows; an intercepted host's rows, slice 2, not yet built; the UDP rows not yet observed) | not yet observed | no command yet (#4000) | no command yet (#4000) |
| `refusal-in-environment` | #4015 | no command yet | no command yet | no command yet | no command yet |
| `refusal-readable` | #5057, #5058 | no command yet | no command yet | n/a | n/a |
| `learn-mode` | #4015 | after launch | after launch | after launch | after launch |
| `agent-vm-interception` | #3999 (#4809, #4884, #4812, #4887) | partly observed 2026-11-18, source 582326b40 (an API key; the smoke) | no command yet | n/a | n/a |
| `agent-vm-platform-profile` | #4909 | not yet observed | no command yet | n/a | n/a |
| `agent-claude` | #3999, #4001 | no command yet | partly observed 2026-11-19, v0.4.24 | no command yet | no command yet |
| `agent-codex` | #3999, #4001 | no command yet | partly observed 2026-11-19, source 8f3a2d502 | no command yet | no command yet |
| `agent-codex-websocket` | #3999 | no command yet | no command yet | n/a | n/a |
| `agent-claude-websocket` | #3999 | no command yet | no command yet | n/a | n/a |
| `agent-github` | #3999 | no command yet | partly observed 2026-11-19, v0.4.24 (read only) | n/a | n/a |
| `no-token-at-rest` | #3999 (#4897), #4001, #6194 | no command yet | no command yet | no command yet | no command yet |
| `agent-own-key` | #3999, #4001 | partly observed 2026-11-21, main e62d4d033 (`locked`: another key and no key refused, the placeholder served; an unselected provider's host refused under every policy, #5555) | no command yet | no command yet | no command yet |
| `agent-fail-closed` | #3999, #4001 | partly observed 2026-11-19, source 911a51f01 (the ended front door shown) and 2026-11-18, source 582326b40 (the smoke) | no command yet | no command yet | no command yet |
| `agent-switch-off` | #3999 | no command yet | no command yet | n/a | n/a |
| `agent-hosted` | #4001 | n/a | n/a | no command yet | no command yet |
| `hosted-enforcement` | #4000 | n/a | n/a | partly observed 2026-11-23, Dev source 42306388f8 (`cw info` on a running Sandbox's selected and changed revision, and on `locked`) | not yet observed |

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
- Record the agent's own version with every agent observation. An
  environment runs the agents' newest release, not the image's version
  (#4946): on first real use the image's `claude` installs Claude Code's own
  self-updating build in the home, and `PATH` prefers it from then on. The
  image's version (`images/workspace/agents/package.json`) is where an
  environment starts, and the fallback when that install cannot run. Until
  that first use, `claude --version` answers from the image's copy; after
  it, from the build that runs. `cw doctor` does not show either yet (#4946).
- Run `cw create --local` from an empty directory made for the walk. A
  create takes the directory it runs in as the VM's workspace and shares it
  live, read and write, so a walk started in a checkout hands that checkout
  to the VM.
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
  - In the VM a refused name fails as a lookup (`curl: (6) Could not resolve
    host`), and a refused address or port as a connection (`curl: (7) Failed
    to connect`), each within milliseconds. Neither is a DNS or network
    outage.
  - A wildcard does not cover its own apex: `*.example.org` allows
    `www.example.org` and refuses `example.org`.
  - `locked` still lets a selected model credential reach its own provider
    (#5215); `agent-own-key` walks it.
- **Observed:** Linux local VM (x86_64, KVM), 2026-11-16, `cw` 0.1.0 built
  from 40a2877e7 with the runtime built from the same commit, in a throwaway
  `HOME`:
  - `policy list` shows `open` and `locked`; `policy create` from
    `example.com,*.example.org` reports revision 1; `policy check` allows
    `example.com:443` and `www.example.org:443`, and refuses
    `example.net:443` and `example.org:443` with `(name not allowed)`, and
    `example.com:8443` under `open` with `(port not allowed)`;
  - a VM created with `--policy`: `cw info` shows `egress-walk-policy · rev
    1`; `curl` to `example.com` printed `200`; to `example.net` it failed in
    2 ms with a failed lookup;
  - `policy allow … example.net` reported revision 2 and `Enforced now in:
    egress-walk`, and the same `curl` printed `200` with no restart (the
    VM's generation stayed 1);
  - with a second VM on the policy and a TLS connection held open to
    `example.net` and to `example.com` in each: `policy rm … example.net`
    reported `Enforced now in: egress-walk, egress-walk-2`, and in both VMs
    the connection to `example.net` had ended and the one to `example.com`
    still answered `200`; allowing the name again was enforced in both;
  - `cw update … --policy locked` on the running VM: `cw info` shows
    `locked`, and `example.com`, `example.net` and the address `1.1.1.1`
    were each refused within 3 ms while the other VM still reached
    `example.com`; `--policy open` served both names again with no restart;
  - failure states: `cw update … --policy` and `cw create --local --policy`
    with a name that does not exist are refused (`no local network policy is
    named …`), the update leaving the VM on its policy and the create
    stopping at "Preparing sources" with nothing created; `policy delete` is
    refused while a VM selects the policy, naming that VM, and succeeds once
    none does.

## `policy-project-file`: `codewire.yaml` names a policy

Issue: #2537 step C, pull request #4835.

- **Entry points:** `network: { policy: REF }` in `codewire.yaml`, read by
  `cw create --local`.
- **States to exercise:**
  - the file names a policy and no flag is given;
  - the file names one policy and `--policy` names another;
  - the file tries to define a rule (an `allow` key);
  - the file names a policy that does not exist;
  - the same file given to `cw --cloud create`.
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

- **Entry points:** `cw --cloud policy create | list | allow | rm | check |
  delete`, and `--policy` on `cw --cloud create` and `cw update`. `cw info`
  shows the Sandbox's policy and revision. The dashboard has no page for
  this yet.
- **States to exercise:**
  - an organization policy created, edited and selected at create;
  - a running Sandbox moved to another policy;
  - a member of another organization trying to read or select it;
  - deleting a policy a Sandbox selects;
  - a deployment with the store switched off;
  - a Sandbox on `locked`, reached by its owner;
  - the default when nothing is selected, `hosted-default` (any TCP port
    through the broker, plus DNS; other UDP off unless the environment opts
    in).
- **Driving it,** as a member of an organization whose deployment has the
  store switched on (Kind's overlay does; Dev once
  `CODEWIRE_PLATFORM_NETWORK_POLICIES_ENABLED` is set):
  1. `cw --cloud policy create walk-docs --allow docs.rs:443` makes revision
     1 from `locked`, the default base. `cw --cloud policy ls` lists it with
     its revision and rules; with `--output json` each policy also has its
     digest and its reference, `platform:id:…`. Until `hosted-enforcement`
     reports, each of these commands' text ends with one stderr line saying
     hosted sandboxes don't enforce network policies yet (create, allow and
     rm start it with "Stored."), and `check`'s JSON says `"enforced":
     false`.
  2. `cw --cloud create --policy walk-docs --name policy-walk` selects it at
     create. `cw info policy-walk` shows `NetworkPolicy: walk-docs · rev 1 ·
     not enforced yet`, and the create prints one notice on stderr, never in
     `--output json`. A create without `--policy` prints none. If the server
     doesn't record the selection, the create says so instead.
  3. `cw --cloud policy allow walk-docs crates.io:443` makes revision 2.
     `cw --cloud policy check walk-docs crates.io` says it is allowed, and
     by which rule. `cw info policy-walk` shows revision 2 desired.
  4. `cw update policy-walk --policy locked` moves the running Sandbox to a
     built-in policy.
  5. `cw --cloud policy delete walk-docs` while a Sandbox selects it is
     refused, naming the Sandbox. After step 4 it deletes.
  6. As a member of another organization: `cw --cloud policy ls` does not
     list it, and `cw --cloud create --policy walk-docs` is refused as not
     found.
  7. A server with the store switched off answers each command in the
     user's terms, not with an RPC error.
  8. `cw --local policy ls` never shows `walk-docs`: the same name in both
     stores is two policies.
- **Proof:**
  - steps 1 to 8 as written, with `--output json` where a step names it;
  - a destination the policy allows answers, and one it does not fails at
    once. This half is `hosted-enforcement`'s, once `cw-egress` enforces;
  - an edit reaches a running Sandbox with no restart and ends the
    connections the new revision refuses;
  - the status of `hosted-enforcement` shows the revision the Sandbox
    enforces;
  - another organization's member can neither read nor select the
    policy;
  - a Sandbox on `locked` stays reachable: its terminal, SSH and its page in
    the dashboard keep working. Every connection the workload opens is
    refused, except to the platform's own services: what the platform's
    public gateway serves, and the relay (see `hosted-enforcement`).
- **Gotchas:** a hosted policy is stored on the platform, a local one on the
  host. The same name in both is two policies.
- **Observed:**
  - on a local Kind cluster, 2026-11-16 (#4000): steps 1 to 8 as written,
    with the "not enforced" line on every command that's meant to show it;
  - on Dev, 2026-11-23, Dev source 42306388f8, as the Dev smoke identity,
    with hosted egress and the store on (#4000 comment 135597, with every
    command and its output). The Sandbox `policy-walk` and the
    policy `walk-docs` were removed by name afterwards.
    - **Step 1:** `walk-docs` rev 1 allows `docs.rs:443`. The JSON carries
      its digest and its reference, `platform:id:…`.
    - **Step 2:** `cw info` read `NetworkPolicy: walk-docs · rev 1 ·
      enforces rev 1` and `Egress: enforced`.
    - **Enforcement, from inside the Sandbox:**
      - `https://docs.rs` answered 200;
      - `crates.io` and `example.com` didn't resolve (curl exit 6);
      - `docs.rs` on port 80 was refused at once (curl exit 7).
    - **Step 3:** `allow walk-docs crates.io:443` made rev 2, and
      `check` named the rule. `cw info` read `enforces rev 2` within about
      5 s, with no restart, and `https://crates.io` then answered while
      `example.com` stayed refused.
    - **Step 4:** `--policy locked` read `locked · enforced` within 3 s. The
      terminal kept working, and `docs.rs` and `crates.io` were then
      refused.
    - **Step 5:** deleting `walk-docs` while `policy-walk` selected it was
      refused, naming the Sandbox. After a move to `locked` it deleted.
    - **Step 8:** `cw --local policy ls` never showed `walk-docs`.
  - **Found on Dev:** the client still prints that hosted Sandboxes don't
    enforce network policies yet, on `policy create`, `allow`, `ls` and
    `check` (`"enforced": false, "enforcement": "not_available"`), and on
    create ("is not enforced yet: this environment's outbound connections
    are not restricted"). On Dev that is false; #3997's wording replaces it.
  - **Not walked on Dev:**
    - step 6 needs a member of another organization, and the walk has one
      identity;
    - step 7 needs the store off;
    - an edit ending an open connection the new revision refuses;
    - refusals in `cw policy log`, which wait for #6144.

## `policy-dashboard`: an organization's policies in the dashboard

Issues: #5114 (the Network policies page), #5116 (Network access on a
Sandbox), #5117 (what was refused, with a one-step Allow). `SPEC.md`
"Networking and egress" defines it. The store and its rules are
`policy-hosted`'s; this step proves the dashboard shows and changes the same
policies.

- **Entry points:** Network policies in the organization's navigation;
  Network access on a Sandbox's page; the network policy field on the
  Sandbox create form.
- **States to exercise:**
  - an organization with no policies of its own: the built-ins `open` and
    `locked`, "No policies yet" and Create policy;
  - a policy created from `locked` with two destinations, one a wildcard,
    then a destination added and one removed;
  - a protected range typed as a destination;
  - two browsers editing the same policy, the second saving after the first;
  - the "Used by" number on a policy that 12 Sandboxes select, opened by
    hover, by keyboard focus and by a tap;
  - a member who is not an owner or admin;
  - deleting a policy a Sandbox selects;
  - a deployment with the store switched off;
  - the list failing to load;
  - Network access on a running Sandbox, on a stopped one, and a policy
    changed there (#5116);
  - a refused destination allowed from its row (#5117).
- **Driving it:** on the retained Kind cluster (its overlay switches the store
  on), signed in as an organization owner, then as a member, in two browser
  windows:
  1. Open Network policies. It shows `open` and `locked` as built in,
     "No policies yet", and the notice that hosted Sandboxes don't enforce
     network policies yet.
  2. Create policy `walk-dash` from `locked`, allowing `docs.rs` on 443 and
     `*.crates.io` on the default ports. Add `crates.io` on 443, then remove
     `docs.rs`. Type `10.0.0.0/8` as a destination.
  3. In the second window, add a destination to `walk-dash` and save. Then
     save a different one in the first window, which has not reloaded.
  4. Check `static.crates.io:443` and `pypi.org:443` with Check a
     destination.
  5. Create 12 Sandboxes with `cw --cloud create --policy walk-dash`, then
     hover, focus and tap the number under Used by.
  6. Delete `walk-dash`, then move the Sandboxes to `locked` with
     `cw update NAME --policy locked` and delete it again.
  7. Sign in as a member and open the page.
  8. Turn the store off on the deployment and open the page.
- **Proof:**
  - every revision and rule the page shows matches `cw --cloud policy ls
    --output json` at the same moment;
  - step 2 makes revisions 1 to 3 and refuses the range with "The range
    includes protected addresses", without making a revision;
  - in step 3 the first window's list updated without a reload when the
    second saved, and its own save says another revision was saved first and
    keeps the unsaved destination;
  - step 4 shows Allowed by `*.crates.io` and Refused with "name not
    allowed", as `cw --cloud policy check` does;
  - in step 5 the cell reads `12`, and hover, focus and tap each list 10
    Sandboxes by name, then "and 2 more", and a link to `walk-dash`'s page,
    which lists all 12;
  - step 6 is refused, naming the Sandboxes, and succeeds after the move;
  - a member reads every policy and sees no Create, edit or Delete;
  - with the store off the page says network policies aren't available on
    this deployment, and no RPC error;
  - no page makes a request without a live event or a user action.
- **Gotchas:**
  - The page shows only the organization's store. A policy made with
    `cw --local policy` never appears, even under the same name.
  - Until `hosted-enforcement` reports, every Sandbox reads "Not enforced
    yet". That is the expected state, not a failure of the page.
- **Observed:**
  - on a local Kind profile (`cw-netui`), 2026-11-17, the dashboard built
    from #5114's pull request (NP1), as the seeded owner and member:
    - step 1: the built-ins, "No policies yet", the not-enforced notice and
      the `cw` line under Create;
    - step 2: `10.0.0.0/8:443` refused with "the range includes protected
      addresses", keeping the input; `walk-dash` created at revision 1 and
      revision 2 after allowing `*.crates.io` with the default ports;
    - step 3: a save over a newer revision said revision 3 was saved first
      and kept the typed destination. The other window updating without a
      reload waits for the live event (#4762);
    - step 4: `static.crates.io:443` allowed "when the name answers public
      addresses", and `pypi.org:443` refused "(name not allowed)";
    - step 5: with 12 synthetic hosted environment rows seeded into the
      profile's database in place of real Sandboxes, the cell read `12`;
      hover and keyboard focus at 1280 and a tap at 390 each listed ten names
      and "and 2 more";
    - step 6: delete refused, naming the Sandboxes;
    - step 7: the member saw no Create, Allow, Remove or Delete;
  - not yet observed: step 8 (the Kind overlay switches the store on), Network
    access on a Sandbox (#5116) and refusals (#5117); Dev and Production.

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
  fails at once; a policy cannot name a protected address (`policy create
  --allow` refuses it: `the range includes protected addresses`), and
  allowing a name that answers only protected addresses does not make it
  reachable.
- **Gotchas:** a user's own tailnet ([own-tailnet.md](own-tailnet.md)) reaches
  private addresses inside its tunnel. That is not a way round this step.
  `tailscaled` does send UDP to peers' advertised endpoints, private ones
  included. Each of those sends is refused, as every UDP send but DNS to the
  environment's resolver is, and recorded as `udp_not_carried`, on a local VM
  in `cw --local policy log` (not yet observed). A
  name that resolves only to protected addresses is refused as
  a name. Do not read that as a DNS outage. `policy check` reports such a
  name as `Allowed … when the name answers public addresses`: it judges the
  rule, not what the name resolves to.
- **Observed:** Linux local VM (x86_64, KVM), 2026-11-16, `cw` 0.1.0 built
  from 40a2877e7 with the runtime built from the same commit:
  - `policy check open` refused `192.168.1.10:443`, `127.0.0.1:443` and
    `169.254.169.254:80`, each with `(protected address)`;
  - from the VM under `open`, `169.254.169.254`, `192.168.1.10`, `10.0.0.1`
    and the host's own address (ports 80 and 22) were each refused within 3
    ms;
  - `policy create --allow '169.254.169.254,192.168.1.10'` was refused, so
    no policy named them;
  - a name that answers only loopback (`localtest.me`) failed in the VM as
    a lookup, under `open` and again from a VM whose policy allowed the name.

## `locked-refuses-managed-github`: a policy that does not allow GitHub refuses the managed credential

Issue: #4926. `docs/dev/LINUX-LOCAL-VMS.md`, "Network policies", states the
rule.

- **Entry points:** `git` and `gh` in a local VM whose profile has a GitHub
  connection, with interception off, so requests take the credential route on
  the host. With interception on, the same rule is part of the GitHub step
  of #3999.
- **States to exercise:**
  - `open`;
  - `locked`;
  - a stored policy that allows `github.com` and `api.github.com` on 443;
  - a stored policy that allows `github.com` only;
  - a change from `open` to `locked` and back while the VM runs;
  - a local VM on a platform profile.
- **Driving it:** with `OWNER/PRIVATE` a private repository the connection
  reaches, on the host and then in the VM:

  ```sh
  cw update team --policy locked
  git clone https://github.com/OWNER/PRIVATE.git    # in the VM
  gh api user                                       # in the VM
  cw update team --policy open
  git clone https://github.com/OWNER/PRIVATE.git    # in the VM
  ```

- **Proof:**
  - under `locked`, the clone and `gh api user` fail with a message that
    names the network policy and the two hosts to allow, and the credential
    broker's log shows the refusal and no lease;
  - with rules for both hosts, both work; with a rule for `github.com` only,
    both are refused;
  - after the change to `locked` on a running VM the next request is
    refused, and after the change back the next one works, with no restart;
  - under `open`, nothing differs from before the fix;
  - on a platform profile the results are the same.
- **Gotchas:**
  - Both hosts must be allowed. Git needs only `github.com`, but one answer
    for both keeps `git` and `gh` from disagreeing.
  - Only a rule that names the hosts counts. A rule for an address range
    that happens to hold GitHub's addresses does not, so the credential is
    refused.
  - The refusal is about the managed credential. Under a policy that allows
    GitHub, a user's own token goes through the VM's network as before.
  - Hosted Sandboxes do not apply network policies yet, so this step is local
    only.
- **Observed:** not yet observed.

## `egress-late-answer`: a late answer refuses only its own request

Issues: #4948, #4965.

- **Entry points:** every lookup and connection a local VM makes;
  `cw --local info` and `cw doctor` while the broker is late.
- **States to exercise:**
  - the egress broker paused for longer than the network worker's 8 s
    deadline while a lookup waits, then while a connection waits;
  - the broker resumed, then paused for good.
- **Driving it:** on the host, take the VM's ID from `cw --local info`, find
  its broker's process ID by its exact arguments, and pause and resume it:

  ```sh
  cw --local info egress-walk
  ps -axo pid=,args= | grep -F -- "__native-egress-broker --environment-id ID"
  kill -STOP PID
  cw --local exec --in egress-walk -- sh -c 'time getent hosts example.com'
  kill -CONT PID
  cw --local exec --in egress-walk -- getent hosts example.com
  cw --local exec --in egress-walk -- curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/
  cw --local info egress-walk
  ```

  Then the same with `curl` in place of `getent` while the broker is paused.
- **Proof:**
  - while the broker is paused, each lookup and connection fails after the
    8 s deadline instead of hanging, and nothing is reached;
  - while the broker is paused, after the first refused request, `cw info`
    shows `Egress: unavailable for …`, naming the egress broker as past its
    deadline and `cw --local stop` then `cw --local start` as what restarts
    it. `cw doctor` names the VM the same way;
  - after `kill -CONT`, the next lookup answers, `curl` prints `200`, and
    `cw info` reads `running` with no egress line, with no restart;
  - paused for good, requests keep failing, the VM stays `running`, and the
    time in the egress line grows;
  - the same count feeds the refusal log (#3999).
- **Gotchas:** the guest's resolver retries a failed lookup, so `getent`'s
  total time is a multiple of the deadline.
- **Observed:** not yet observed.

## `refusal-log`: the owner sees what was refused, and why

Issues: #5058 (local), #4000 (hosted). `SPEC.md` "Networking and egress"
defines it; the reasons are those of "Refusals an agent or a person can read"
in `docs/dev/SECRETS-AND-CREDENTIALS.md`.

- **Entry points:** `cw --local policy log ENV`, with `--output json`; one
  line in `cw --local info ENV`. A hosted Sandbox's `cw --cloud policy log`
  is #4000's, with no command yet.
- **States to exercise:**
  - a running VM that refused nothing;
  - one refusal of each egress reason: a name not allowed, a port not
    allowed, an address not allowed, a protected address, a name that
    answers only protected addresses (refused at the lookup), an expired
    lease, a connection to an intercepted host whose front door is gone
    (`intercept_unavailable`), and UDP other than DNS to the environment's
    resolver: a lookup sent to another server and a datagram to a public
    address (`udp_not_carried`, not yet observed);
  - a VM in learn mode (#4015, once it exists), which shows only refusals;
  - a request refused on an intercepted host: no credential selected for
    the provider (the credential broker's), a path the route doesn't serve
    (the front door's own), and a request without the placeholder that the
    policy refuses (`name_not_allowed`);
  - the same destination refused many times, and more destinations than
    the log keeps;
  - a name the workload builds to carry a terminal escape sequence;
  - the one-step allow from the log's next step, under a policy of yours and
    under the built-in `locked`, and none under `open`;
  - a stopped VM, a restarted VM, and a supervisor older than the command.
- **Driving it:** on the host, with a released `cw` or one built from the
  source under test, and a throwaway `HOME`:

  ```sh
  cw --local policy create walk-log --allow example.com:443
  cw create --local --name walk-log --policy walk-log --yes
  cw --local policy log walk-log
  cw exec --in walk-log -- sh -c 'curl -sS -m 5 https://example.org/ ; curl -sS -m 5 http://example.com:8080/ ; curl -sS -m 5 http://169.254.169.254/ ; true'
  cw exec --in walk-log -- sh -c 'for i in 1 2 3 4 5; do curl -sS -m 5 http://example.com:8080/ ; done ; true'
  cw exec --in walk-log -- sh -c 'timeout 10 nslookup example.com 8.8.8.8 ; bash -c "echo stun > /dev/udp/1.1.1.1/3478" ; true'
  cw --local policy log walk-log
  cw --local policy log walk-log --output json
  cw --local info walk-log
  ```

  Then follow the log's `→` line and run the refused request again. For an
  intercepted host's rows, use a VM with interception on, as in
  `agent-claude`, and send a request without the placeholder and one to a
  path the route doesn't serve. Stop and start the VM and read the log again.
  The interception smoke (#5046) asserts an `intercept_unavailable` row and an
  intercepted host's row through `--output json`.
- **Proof:**
  - nothing refused: `Nothing refused since walk-log started.`, exit 0;
  - each refusal is one row, `DESTINATION PROTOCOL PORT REASON POLICY COUNT
    FIRST LAST`: the name, or the address where no name leads to it; a
    refused lookup reads `dns` with `-` for the port; the reason in words,
    the raw reason, so a protected address reads `protected address`; the
    policy it was last refused under as `cw info` names it (`walk-log · rev
    1`), or `-` for a reason on an intercepted host the policy didn't
    decide; relative times;
  - an intercepted host's row names the route's bound host, even when the
    request's `Host` header named another, and a path the route doesn't
    serve is a row with no path in it;
  - five refusals of one destination are one row with a count of 5 (6 with
    the first);
  - UDP other than DNS to the resolver (not yet observed): `nslookup` waits
    out its timeout with no answer, and the log has a `udp` row for
    `8.8.8.8` port 53 and one for `1.1.1.1` port 3478, each `UDP not
    carried`, with no `→` step, since no rule carries UDP. A datagram sent
    again while the broker is still recording the last one to the same
    destination is not counted, as a retransmitted connection attempt isn't;
  - the rows are most recently seen first; at a terminal the table fits its
    width, the policy column giving way first and an address never cut, and
    piped it is whole;
  - the last line is one `→` step for the most recent refusal a rule can
    allow: `→ cw --local policy allow walk-log example.com:8080`, or under
    `locked` `→ cw --local policy create NAME --from locked --allow
    example.com:8080`. A protected or credential reason gets no `→` line,
    and neither does `open`: `create` can't start from it, and a policy
    from `locked` would drop the ports `open` allows;
  - after the allow, the same request is no longer refused, its row's count
    doesn't grow, and the log offers no `→` step for a row refused under an
    older revision of the policy;
  - JSON holds every row with its destination, address (`null` when none),
    port (`null` for `dns`), protocol (`tcp`, `udp` or `dns`),
    the raw reason code, `source` (`network` or `credentials`), the policy's
    name and revision, the first and last time in RFC 3339, and the count;
    beside the rows, `dropped`, the number of rows dropped since the VM
    started, and `rejected`, the number of the front door's reports or
    rows the runner rejected; and nothing on stdout but that;
  - `cw --local info walk-log` shows how many requests were refused since
    it started and when the last was, naming `cw --local policy log
    walk-log` in the same line;
  - no row or JSON value holds a path, a header, a body, a placeholder or a
    credential;
  - a lookup of a name holding an escape sequence (`printf` with `\033`
    inside the name) is refused by the guest's network stack before the
    broker sees it, so it leaves no row and the terminal is unchanged; the
    broker's own check, which keeps such a name as `(a name cw won't
    show)`, is proven by its tests;
  - past 1,000 rows (a loop over 1,100 refused names), the log keeps 1,000
    and says it dropped the least recently seen;
  - a stopped VM: `There's no refusal log while walk-log isn't running`
    with `→ cw --local start walk-log`, exit 1; after a start the log is
    empty;
  - an older supervisor: `your local VMs run on an older cw's supervisor,
    which has no refusal log`, naming `cw upgrade --vms`, as `cw ssh` does
    for its own feature.
- **Gotchas:**
  - a refused connection and an unreachable one look the same from inside
    the environment; only the log tells them apart;
  - the guest's resolver retries a refused lookup, so one `curl` can count
    more than once;
  - the log is in memory and lasts one run of the VM, so read it before a
    stop.
- **Observed:** Linux local VM, 2026-11-21, `cw` and the local runtime built
  from 385cf721d9 (c403fcf960 after a rebase onto main), in the local-smoke isolation (private `HOME` and Secret
  Service), VM and policy `walk-log` (`--allow example.com:443`, from
  `locked`), both removed afterwards:
  - before anything was sent: `Nothing refused since walk-log started.`;
  - after `curl` to `https://example.org/`, `http://example.com:8080/` five
    more times, and `http://169.254.169.254/`: three rows, most recently
    seen first; `example.com tcp 8080 port not allowed walk-log · rev 1`
    with a count of 6, `example.org dns - name not allowed` with 2 (the
    resolver's retry), `169.254.169.254 tcp 80 protected address` with 1;
    `→ cw --local policy allow walk-log example.com:8080`;
  - piped, the table was whole; at 70 and 60 columns only the policy column
    was cut, and the address stayed whole;
  - `--output json`: the three rows with `address` `null` and `port` `null`
    for the `dns` row, the raw reasons, `source` `network`, and `dropped` 0;
  - `cw --local info walk-log`: a `Refused:` line, `9 requests since the
    VM started, the last 1s ago`, naming `cw --local policy log walk-log`;
  - after the allow, the request was no longer refused (it timed out: nothing
    listens on example.com:8080), the row's count stayed 6, and no `→` step
    was offered;
  - stopped: `✗ There's no refusal log while walk-log isn't running` and
    `→ cw --local start walk-log`, exit 1; after a start, empty again.
  - Not walked here: an intercepted host's rows (slice 2), more than
    1,000 rows, an older supervisor, learn mode (#4015), and the interception
    smoke's assertion (#5046).

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

## `refusal-readable`: a refused request says why, in words a person can read

Issues: #5057, #5058. The list is in `docs/dev/SECRETS-AND-CREDENTIALS.md`,
"Refusals an agent or a person can read".

- **Entry points:** an agent's request on an intercepted host, in a local VM
  with interception on, as in `agent-claude` and `agent-codex`.
- **States to exercise:**
  - answered: the credential revoked while the agent runs (`cw credentials
    --local revoke NAME`), its slot emptied (`cw credentials --local
    --profile P unset anthropic`), a credential needing reconnect, the
    placeholder sent beside an API key, a path the route doesn't serve, the
    broker unreachable for a moment;
  - refused at the connection: a host the policy refuses, a port it refuses,
    a protected address.
- **Driving it:** no command yet (#5057). Run `claude -p "hi"` and
  `codex exec 'Reply ok.'` in each state, and `curl -si` the same URLs to see
  the status, headers and body.
- **Proof:**
  - after the revoke, Claude Code shows "Codewire: the Anthropic credential
    this environment uses was revoked." and "Fix: in a local VM, run `cw
    credentials --local list` on the computer that runs it; in a hosted
    Sandbox, run `cw credentials --cloud list` wherever you're signed in to
    Codewire; then connect it again"; `curl` shows 403, `Codewire-Refusal: credential_revoked` and the
    same text. Record what Codex prints for the same refusal;
  - each other answered state reads as its row in the list, with its reason
    in the header;
  - no body names the credential, the profile, an id, an email or an account,
    and a canary sent in the request never comes back;
  - a refused host or port, and a protected address, get no answer from
    Codewire: the agent reports a failed connection, and the reason shows
    only in the guest's refusal list (#4015) and the owner's `cw policy log`
    (#5058), the protected one as plain `address_not_allowed`;
  - `cw policy log` names the same reason as the header for every answered
    refusal.
- **Hosted Sandbox:** the same list holds once #4001's switch is on, with the
  `--cloud` fix lines; not yet observed there either.
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

- **Entry points:** `cw create --local` or `cw start` as usual, for a VM
  with a selected credential: interception is on by default. Nothing inside
  the VM turns it on or off. Until the switch-on lands (#3999), the file
  `egress-intercept` holding `on` turns it on.
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
  - a VM started while a credential authority older than boot secrets is
    still running;
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
  - the switch is read once at each boot; the boot's recorded state, the
    supervisor's log and `cw --local info` all say whether interception was
    on. With it on, `cw --local info` shows `placeholders only: agents never
    hold your tokens` on the line under its `Credentials` row, and so do the
    start and create results; `--output json` carries
    `"interception": {"state": "intercepted"}` (#4912). With the switch set
    to `off`, the line names the file that turned it off, and the JSON says
    `{"state": "off"}`;
  - **the guest trusts the boot's certificate authority, from the seed**
    (#4809, #4884). With the switch on, the boot's seed carries the
    authority's certificate, the guest publishes it as a read-only file, and
    `NODE_EXTRA_CA_CERTS` names that file. Nothing else is set: no
    `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` or
    `GIT_SSL_CAINFO`, and, unless GitHub's hosts are bound (`agent-github`),
    no `SSL_CERT_DIR`. The authority belongs to this boot alone, and its key
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
  - a VM whose credentials come from the platform, on macOS or against an
    authority that does not join the platform's front-door session, starts
    without interception: its recorded state reads interception off, the
    supervisor's log gives the reason (`skipped=platform_credentials`), and
    `cw --local info` shows `no placeholders: they come from the platform`
    under its `Credentials` row, with `{"state": "not_intercepted", "reason":
    "platform_credentials"}` in its JSON. Its
    seed carries no authority and no placeholders, so the guest sets no
    `NODE_EXTRA_CA_CERTS`, and its agents use today's routes. It never boots
    trusting an authority that nothing serves. On Linux against a current
    authority it intercepts through the delegation (#4909,
    `agent-vm-platform-profile`);
  - **only the boot's pairing secret pairs a credential broker with the
    front door** (#3999). The runner mints it for the boot and keeps it in
    memory; the credential authority hands it to each broker, successors
    included, on an inherited descriptor. It is never in the seed, a file, an
    argument, the environment or a log, and the daemon token, which the VM
    knows, is refused;
  - a VM started while a credential authority older than boot secrets runs
    starts without interception, as with the switch off, and the
    supervisor's log gives the reason
    (`skipped=authority_predates_boot_secrets`). `cw --local info` says no
    placeholders because the credential service running is from an earlier
    cw, and to stop the local VMs so cw replaces it, then start this one
    (`"reason": "credential_service_outdated"`). It never reports
    interception on when its broker could not pair;
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
    intercepted and the VM is as with the switch off, except that
    `cw --local info` shows `no placeholders: none are selected` under its
    `Credentials` row (`"reason": "no_credentials"`).
  - With the switch on and only a GitHub sign-in selected, no front door
    runs, since GitHub stays on its own route (#5087). `cw --local info`
    shows `no placeholders: none of its credentials is intercepted yet`
    (`"reason": "nothing_to_intercept"`), never `intercepted` (#5670).
  - Known limit, tracked on #3999: a restore gives the VM a new certificate
    authority, and a running process cannot reload the one it trusts. Agents
    that were running at the checkpoint must be restarted after a restore
    before they reach an intercepted host again.
  - macOS: the front door confines itself with a Seatbelt profile that
    denies everything (no file, no new socket, no process), where Linux
    uses Landlock and seccomp (#4916). The walk is the same on both; a Mac
    boot with the switch on is not yet observed.
- **Observed:** partly. Linux local VM (x86_64, KVM), 2026-11-18, by the
  native local smoke's interception mode
  (`scripts/ci/verify/smoke-native-local-environment.sh
  --managed-credential-broker --egress-interception
  --egress-interception-renewals 2`, synthetic credentials and a synthetic
  provider), host `cw`, credential broker and guest runtime built from
  582326b40, which is `main` at aa729bf8d plus the smoke's own change; the
  run is recorded on #3999. An earlier run, 2026-11-16 at bb379db0e, saw
  the same. With the switch on and an Anthropic API key selected: the boot's
  recorded state
  and the supervisor's log say interception is on, and the runner's log
  records the front door paired; the guest trusts the boot's authority
  through `NODE_EXTRA_CA_CERTS` and holds only its placeholder; a request
  carrying the placeholder is served with the stored key, which comes back
  redacted; the placeholder beside another credential is refused; the key
  is in the memory of none of the runner, the packet worker, the egress
  broker and the front door; and after a stop and start the VM holds the
  same placeholder and is served again. Not yet observed: the owner's
  Claude sign-in, the other states above, and any run on macOS.

  What `cw` shows (#4912), Linux local VM (x86_64, KVM), 2026-11-20, by the
  same smoke with and without `--egress-interception`. The tree was `main`
  at 6557aa7e8 with #5512, the `smoke-credential-claude` step and this
  change on top; the host `cw`, the helpers and the workspace image were
  built from it. Both runs passed whole.
  - With the switch on, at each of the two boots: `cw --local info
    --output json` carried `"interception": {"state": "intercepted"}`, and
    the text had `placeholders only: agents never hold your tokens` under
    its `Credentials` row.
  - With the front door killed: `{"state": "lost"}` and `! agents can't
    reach their providers; restart the VM` under the row, with the VM
    still running.
  - With the switch off: `{"state": "off"}` and nothing under the row.
  - The other three states are proved by unit tests only: credentials from
    the platform, none selected, and an older credential service.

## `agent-vm-platform-profile`: a local VM on a platform profile is intercepted through the delegation

Issue: #4909. The front door's session crosses the owner-local delegation
channel to the platform's broker, by the same mechanism as the hosted relay
(#4001). The rules are in `docs/dev/SECRETS-AND-CREDENTIALS.md`, "Front-door
session through a relay".

- **Entry points:** the per-host switch for local VMs, then `cw create
  --local` or `cw start` for a VM whose credential profile is a platform
  profile. Nothing inside the VM turns interception on.
- **States to exercise:**
  - a Claude sign-in and a Codex login, both from the platform profile;
  - a token forced to expire mid-session;
  - the platform credential revoked, then selected again;
  - a front door from another boot or VM asking for this VM's tokens;
  - the relay replaced by its successor (a new delegation epoch) while an
    agent session runs, with a request in flight and a long streamed
    response;
  - the front door killed while an agent runs;
  - an agent idle for more than two minutes, then a request;
  - the switch off.
- **Driving it:** on a Linux host with a `cw` built from #4909's change,
  signed in to Dev, with the switch on and the VM's credential profile on
  the platform: start the VM, then run a Claude Code prompt, `/usage` and
  the plan, and a Codex task.
- **Proof:**
  - the VM starts with interception on: its recorded state says so, and the
    supervisor's log has no `skipped=platform_credentials`;
  - a Claude Code prompt works, and `/usage` and the plan show; a Codex task
    works, including its account routing;
  - **no real token is found** in the VM's login files (they hold
    placeholders), on its disk, in the local relay's and front door's logs,
    or in the host's credential directories;
  - **the first login is already a placeholder:** the agent's login file,
    read before the front door has joined (before any agent request), holds
    the placeholder, never the sign-in's token;
  - after a forced expiry, the platform refreshes the token, and the agent's
    own refresh gets placeholders back;
  - after a revocation the agent fails; after the credential is selected
    again it recovers;
  - a front door from another boot or VM is refused this VM's tokens, and
    the refusal is shown;
  - **across a relay rotation** the successor pairs before the old relay
    ends: a request in flight on the old relay completes there, a request
    started after the successor paired is served by the successor, and no
    request fails in between. A streamed response long enough to span the
    successor's pairing, but shorter than the old relay's epoch, completes on
    the old relay unbroken;
  - **after an idle spell** of more than two minutes, when the platform has
    ended the joined stream, the next request is served, not failed: the
    relay joins again while it waits;
  - **a WebSocket upgrade** to an intercepted host is refused by the relay:
    the platform's front door serves no WebSockets;
  - **with the front door gone,** a request to an intercepted host is
    refused by the egress broker and counted, and nothing is dialled
    directly;
  - with the switch off, the VM behaves exactly as today: base-URL routes
    through the relay.
- **Gotchas:** the relay's per-id refusals (an unknown or finished id, a
  capability outside the pin) are unit-tested; the walk sees them only as an
  agent's request failing without the session ending.
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
  - the agent's own token refresh never reaches the provider with Codewire's
    values. Its `POST platform.claude.com/v1/oauth/token`, carrying
    Codewire's managed refresh token, is answered by Codewire. Afterwards
    the login file holds the same placeholder access token, a new managed
    refresh token and the sign-in's own scopes, and the broker sent no
    request carrying a Codewire value to the provider (#3999 plan change 7);
  - after `cw credentials revoke`, the next model call fails and none
    succeeds after it;
  - the other person with a terminal in the environment can run a model
    call, and it succeeds on the owner's plan. That person can read the
    placeholder and nothing more: the real token is in no file, variable or
    process they can reach. Both halves are recorded, so the consequence of
    sharing is observed and not only stated
    (`docs/dev/SECRETS-AND-CREDENTIALS.md`).
- **Gotchas:**
  - A header that reads "Claude API", or a `/usage` that is unavailable,
    means the agent is not on this path. Do not record the model call alone
    as this step.
  - With stock settings Claude Code sends the placeholder as a
    Bearer token, at every start, to six paths on `api.anthropic.com`:
    `/v1/messages`, `/api/oauth/profile`, `/api/claude_cli/bootstrap`,
    `/api/claude_code_penguin_mode`, `/api/eval/sdk-<id>` and
    `/api/event_logging/v2/batch`. The swap is by placeholder on any path
    of that host, as today's route already is, so each is served with the
    owner's credential as it would be with a real login. A 401 on one of
    them, followed by a token refresh at every start, means that path was
    not swapped: record it as a failure of this step. Observed against a
    stand-in on 2.1.308, the image's version, and on 2.1.325, the newest
    release on 2026-11-15; between them only a request that carries no
    credential changed (#4946).
  - A release that starts using a host Codewire does not bind sends the
    placeholder to the provider as it is. The user sees the agent's own
    401 and its request to sign in again. The fix is Codewire's, and until
    it ships the user can update or roll back the agent themselves. The
    compatibility test names the new host when it runs against that
    release; its scheduled run against the newest release is to come
    (#4946), read by the CI sweep and looked at within one working day.
  - An `invalid_grant` answer from the token endpoint makes Claude Code
    blank its own tokens (`accessToken` and `refreshToken` become empty,
    `expiresAt` 0) and stop with "OAuth session expired and could not be
    refreshed". A wrong `invalid_grant` therefore signs the user out inside
    the environment until the daemon next writes the login. A 503 leaves the
    file alone and the run continues. Observed on 2.1.308 against a fake
    endpoint, 2026-11-15 (#3999).
  - The placeholder is not a secret, and it belongs to one environment.
    Copied into another environment it is forwarded untouched and the
    provider rejects it.
  - The proof of "nowhere" needs a search of the disk, the checkpoint and
    the logs for the real token, done by its holder without printing it. No
    command yet; the tool is owned by #3999, whose done-when requires that
    no real token is found there.
- **Observed:** partly. A local VM on macOS 27.2.1 (Apple silicon), `cw`
  v0.4.24, interception switched on with `egress-intercept`, the owner's
  Claude sign-in connected with `connect claude` (2026-11-19, #3999):
  - neither base URL was set, and no `ANTHROPIC_*` variable was;
  - the access token in `~/.claude/.credentials.json` began `cwp1_`;
  - `claude -p` answered `ok`;
  - the header read the plan's name ("Claude Ultra"); `/status` showed
    "Claude Ultra account", the owner's organization and the front door's
    CA, and `/usage` showed the plan's weekly usage. Claude Code was 2.1.328,
    updated by itself from the image's 2.1.308.

  Not yet observed: the search for the real token, a session across a token
  refresh, a revocation while the agent runs, a restored checkpoint and a
  second person's terminal.

## `agent-codex`: Codex with stock settings and no token inside

Issues: #3999 (local VMs; changes 8 and 11), #4001 (hosted Sandboxes).

- **Entry points:**
  - the owner's ChatGPT sign-in, connected with `cw credentials --local connect
    codex` for local VMs or `--cloud` for hosted Sandboxes;
  - selected in the environment's credential profile's `codex` slot;
  - then `codex` inside the environment.
- **States to exercise:**
  - a model call (`codex exec`);
  - the TUI's `/status`: account, plan and limits;
  - an account whose `accounts/check` names a routed origin under
    `chatgpt.com`, and one naming an origin outside the list;
  - a token refresh the broker makes, and one Codex starts itself. Until
    change 7 of #3999 captures the provider's token endpoint, the second
    sends the managed marker to the real endpoint and fails; the far-future
    `exp` makes it rare;
  - the credential revoked while Codex runs;
  - a stopped and started environment, and a restored VM checkpoint.
- **Driving it:** with interception on:

  ```sh
  cw --local exec --in egress-walk -- sh -c 'env | grep -c -E "^OPENAI_BASE_URL=" || true; grep -c -E "^\[model_providers" "${CODEX_HOME:-$HOME/.codex}/config.toml" 2>/dev/null || true'
  cw --local exec --in egress-walk -- sh -c 'jq -r "[.auth_mode, (.tokens.access_token|startswith(\"cwp1_\")), .tokens.refresh_token] | @tsv" "${CODEX_HOME:-$HOME/.codex}/auth.json"'
  cw --local exec --in egress-walk -- sh -c 'codex exec --skip-git-repo-check "Reply with the single word ok." </dev/null'
  ```

  Then start `codex` in a shell in the environment and run `/status`.
- **Proof:**
  - the first command prints `0` twice: no `OPENAI_BASE_URL`, and no Codewire
    model provider;
  - the login file reads `chatgpt  true  <the managed marker>`. Its `id_token`
    decodes to only the allow-listed claims: `email`, the account id, plan
    type, user id and FedRAMP flag, the profile email, and `exp` 2099;
  - the model call answers;
  - `/status` shows the owner's account and plan, and limits once they load;
  - a swapped reply from `chatgpt.com` keeps the account id. Codex finds its
    workspace in `accounts/check` by that id, so `/status` and the model
    call working show it was not redacted on this path;
  - with a routed origin under `chatgpt.com`, the model call reaches it through
    the front door, and nothing else is served on that name;
  - with an origin outside the list, the model call fails, the refusal log
    names the host once for the session, and no request carrying the
    placeholder leaves for that host;
  - the real access, refresh and ID tokens appear nowhere in the environment:
    not on its disk, not in a checkpoint, a hosted volume or a snapshot, and
    not in the daemon's or the egress processes' logs;
  - Codex keeps working past the real token's expiry;
  - after `cw credentials revoke`, the next call fails and none succeeds after
    it.
- **Terminal UI:** `cw run codex --in ENV` (Codex's own terminal UI), local
  and cloud. Inside it, `ssh-add -l` lists the profile's key and
  `git ls-remote` of a private repository over SSH answers; Codex's
  `/status` shows its sandbox as full access, and it still asks before
  running a command (#4956). Full access means the agent can sign with the
  profile's SSH key through the agent, for example to push, and reach
  whatever the network policy allows; the key itself never enters the
  environment. With a delivered login, Codewire's `config.toml` holds only
  `sandbox_mode = "danger-full-access"`, so the provider check above still
  prints `0`.
- **Gotchas:**
  - In a local VM Codewire writes Codex's login into its own Codex home,
    not `~/.codex`; a hosted Sandbox uses `~/.codex`. Read the files where
    `CODEX_HOME` points, as the commands above do. A command that reads
    `~/.codex` in a local VM prints nothing and looks like a pass.
  - `CODEX_CA_CERTIFICATE` is set only with the Codex client selected and a CA
    in the seed, and never over an image's own value (logged when skipped). It
    names `/run/codewire-host/ca-certificates.crt`, the image's roots followed
    by the CA. A CA added after boot isn't trusted by Codex until a restart.
    Without it, Codex's model call fails with "workspace routing discovery
    failed" (#5447).
  - Every name under `chatgpt.com` on 443 is intercepted, because the egress
    broker sees only host and port. Other traffic to those names follows the
    network policy: a placeholder on a path the route does not serve is
    refused, and a request without the placeholder passes untouched where a
    rule allows the host. Not yet true: today a path the route does not
    serve is refused whatever it carries (#4898), until the policy rule in
    `agent-own-key` is built.
  - `codex exec` reads more input from stdin while stdin is open, and
    `cw exec` leaves it open: without `</dev/null` it prints "Reading
    additional input from stdin..." and waits.
  - Codex tries a WebSocket for the model call first. Until changes 9 and 10 it
    falls back to HTTPS; a slow first answer is that fallback.
  - The placeholder belongs to one environment: copied elsewhere, it is
    forwarded untouched and rejected.
- **Observed:** partly. A local VM on macOS 27.2.1 (Apple silicon),
  interception on, the owner's ChatGPT sign-in:
  - `main` at 8f3a2d502 with #5455, 2026-11-19 (#5447): the first command
    printed `0` twice, `CODEX_CA_CERTIFICATE` named
    `/run/codewire-host/ca-certificates.crt`, the login file read `chatgpt
    true` and the managed marker, and the ID token held only `email`, `exp`
    (2099), and the account id, plan type and user id. `codex exec`
    (codex-cli 0.160.0) answered `ok` with nothing set by hand, and `/status`
    in `cw run codex` showed the account's plan, weekly limit and credits.
  - `cw` v0.4.24, 2026-11-19 (#3999): failure observed. `codex exec` failed
    with "workspace routing discovery failed": every request to
    `chatgpt.com` failed its TLS handshake, because Codewire did not set
    `CODEX_CA_CERTIFICATE` (#5447).

  Not yet observed: the routed origins, a token refresh, a revocation while
  Codex runs, a stop and start, a restored checkpoint, the search for the
  real tokens, and hosted Sandboxes. Offline evidence of the formats and
  paths is on #3999 (2026-11-15).

## `agent-codex-websocket`: Codex's socket across a refresh and a revocation

Issues: #3999 (changes 9 and 10).

- **Entry points:** none of its own. Codex opens the socket itself, for a
  model call, in a local VM set up as in `agent-codex`.
- **States to exercise:**
  - a socket that stays open across a refresh;
  - a socket closed by revocation;
  - a reconnect after the close;
  - with the switch off, no socket goes through the front door.
- **Driving it:** with the interception switch on, Codex signed in with a
  ChatGPT account, the VM holding only the placeholder login, and the front
  door's credential session opened with `websocket.v1`:
  1. In the VM, run `codex` with a prompt that streams for over a minute. It
     opens `GET chatgpt.com/backend-api/codex/responses` with `Upgrade:
     websocket`.
  2. While it streams, make the broker refresh the sign-in. Driven through
     change 7's token endpoint; no command yet, #3999 change 7.
  3. Start a second long prompt, then revoke the Codex credential on the host.
     Use `cw credentials revoke`.
- **Proof:**
  - (1) The front door's upgrade count rises by one, and the broker logs one
    accepted socket for the `codex` slot.
  - (2) The same socket keeps carrying bytes after the refresh, so the stream
    didn't reconnect. The next new upgrade carries the refreshed token, shown
    by the provider's 101.
  - (3) The socket is reset within 30 s of the revocation, the broker logs the
    re-lease refusal, and Codex's reconnect isn't served with a real token.
  - Throughout, no real token is in the VM.
- **Gotchas:**
  - Codex falls back to HTTPS POST when the upgrade fails. A model call that
    still works isn't proof of the WebSocket; read the upgrade count.
  - The provider may close a socket itself when its token expires, which the
    design lists as not yet known. A close before the refresh step means repeat
    with a shorter prompt.
- **Observed:** not yet observed.

## `agent-claude-websocket`: Claude Code opens no WebSocket to its provider

Issue: #3999.

- **Entry points:** none of its own. This step records whether `claude`, in
  an environment set up as in `agent-claude`, upgrades any connection to its
  provider.
- **States to exercise:** print mode with a refresh that succeeds, an API
  401, a refused refresh and a refresh answered 503; interactive mode; a
  long session; the voice and remote features.
- **Driving it:** no command yet (#3999). A checked-in compatibility test
  that drives Claude Code against a stand-in token endpoint and API is to
  come with #4925. It takes the agent by path, so it runs against the
  image's version and against the newest release, which is the one an
  environment runs (#4946).
- **Proof:**
  - no request carries `Upgrade: websocket` to `api.anthropic.com`,
    `platform.claude.com` or `console.anthropic.com`. Model calls are `POST`
    requests to the messages API, answered as an event stream;
  - once it exists, the compatibility test fails, and names the host and
    path, if a release starts upgrading.
- **Gotchas:** the WebSocket proof of the front door is
  `agent-codex-websocket`. A release of Claude Code that starts upgrading
  needs its path added to the front door's list before it works, and an
  environment takes that release by itself.
- **Observed:** not yet observed. Offline evidence is on #3999
  (2026-11-15): against a stand-in, four `claude -p` runs of Claude Code
  2.1.308, one for each print-mode state, opened no WebSocket; nor did the
  same four of 2.1.325 (#4946).

## `agent-github`: Git and `gh` reach GitHub by its own names, with no token
inside

Issue: #3999. Hosted Sandboxes follow with #4001.

- **Entry points:** `git` and `gh` inside a local VM whose profile has a GitHub
  connection, with agent interception switched on. Hosted sandboxes follow with
  #4001.
- **States to exercise:**
  - an HTTPS remote, and an SSH-form remote on a profile without an SSH key and
    on one with a key;
  - a private clone, and a push larger than 4 MiB;
  - `gh api user` and `gh pr list`;
  - an anonymous clone of a public repository;
  - the user's own token, on a path the routes serve and on one they don't;
  - a placeholder-shaped value on a path the routes don't serve, Git LFS's
    batch request among them;
  - a request body over 4 MiB to `api.github.com`, with the placeholder and
    with the user's own token;
  - a VM whose profile has no GitHub connection;
  - the `locked` network policy, and a policy with an allow rule for the
    two GitHub hosts;
  - the switch off, on the default policy and on `locked`.
- **Driving it:** in the VM, with `OWNER/PRIVATE` a private repository the
  connection can reach:

  ```sh
  git clone https://github.com/OWNER/PRIVATE.git && cd PRIVATE
  git remote -v
  head -c 6000000 /dev/urandom > blob && git add blob && git commit -qm walk && git push
  git clone git@github.com:OWNER/PRIVATE.git ../ssh-form && git -C ../ssh-form remote -v
  gh api user --jq .login
  gh pr list
  env -u GH_TOKEN git -c credential.helper= clone https://github.com/git/git.git ../public --depth 1
  curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token $OWN_TOKEN" https://api.github.com/user
  curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token $OWN_TOKEN" https://api.github.com/rate_limit
  curl -sS -w '\n%{http_code}\n' -H "Authorization: token $GH_TOKEN" https://api.github.com/rate_limit
  git lfs install --local && git lfs track '*.bin' && head -c 100 /dev/urandom > a.bin \
    && git add .gitattributes a.bin && git commit -qm lfs && git push
  ```

  `curl` here needs `--cacert /run/codewire-host/ca-certificates.crt`, the
  bundle Git's `http.https://github.com/.sslCAInfo` names; the walk says so
  where it uses it.
- **Proof:**
  - `git remote -v` prints the HTTPS remote exactly as it was written. For
    the SSH-form clone it prints the SSH form on a profile with a key, and
    `https://github.com/OWNER/PRIVATE.git` on one without; in both,
    `git config remote.origin.url` is the URL as written;
  - the private clone and the 6 MB push succeed, and the pushed commit is on
    GitHub when read from outside the VM;
  - the SSH-form clone works: over HTTPS with the managed credential on a
    profile without a key, over SSH with the profile's key on one with a key;
  - `gh api user` prints the connected account's login;
  - the anonymous clone succeeds, and the credential broker's log shows no
    lease for it;
  - the user's own token gets GitHub's own answer on both paths (200), with no
    lease;
  - the placeholder on `/rate_limit` answers 403 with the refusal's code and no
    lease, and the LFS push fails with the same refusal;
  - a body over 4 MiB to `api.github.com` is answered 413 with the placeholder,
    and is delivered whole with the user's own token;
  - a search of the VM's disk, its processes' environments and its Git
    configuration for the real token finds nothing; they hold only the
    placeholder;
  - in a VM with no GitHub connection the two hosts are not intercepted: the
    certificate `github.com` presents is GitHub's own;
  - on `locked`, or any policy with no rule that allows the two hosts,
    nothing reaches GitHub from the VM: a request without the placeholder is
    refused, and so is the managed credential's own clone, with a message
    that names the network policy. Both are counted as refused
    destinations. The grant cannot limit the credential to the
    environment's own repositories, so it is not served at all there;
  - with an allow rule for the two hosts, the private clone and push work
    with the managed credential, and the user's own token is forwarded;
  - with the switch off, on a policy that allows the two hosts, clone and
    push work through the loopback rewrite, as before;
  - with the switch off on `locked`, the same rule holds: nothing reaches
    GitHub without a rule that allows it, the managed credential included
    (#4926; the step is `locked-refuses-managed-github`).
- **Gotchas:**
  - Git trusts the boot's CA through `http.https://github.com/.sslCAInfo`,
    which names the bundle made at boot from the image's roots plus the CA and
    applies to `https://github.com/` only. `gh` trusts it through
    `SSL_CERT_DIR`: the image's own certificate directory, then a directory
    holding the CA alone. That adds the CA without replacing the store, so a
    root added to the image's store after boot is still trusted. Both are set
    only when the GitHub hosts are bound.
  - An `SSL_CERT_DIR` that the image or project already sets is kept. `gh`
    then fails its TLS check against GitHub until that directory includes
    the CA; the boot log names the variable.
  - In a hosted Sandbox, a Git request without a credential is answered with
    GitHub's own 401 challenge, so Git asks its helper and an anonymous clone
    of a public repository uses the GitHub connection. Locally it reaches
    GitHub as it is, when the policy allows GitHub's hosts.
  - The placeholder works only for Git's fetch and push requests and for the
    API operations the GitHub route grants. Anywhere else on the two hosts it
    is refused, whoever's placeholder it looks like. Git LFS is one such case.
  - On a profile without an SSH key, `git remote -v` and
    `git remote get-url` print an SSH-form or `git://` remote as
    `https://github.com/…`: Git shows a URL after its `insteadOf` rewrite.
    The stored URL does not change. A tool that compares the printed remote
    with one read elsewhere sees a different string for those forms.
  - A VM restored from a checkpoint keeps the bindings of the boot it was
    captured from.
- **Observed:** partly, read only. A local VM on macOS 27.2.1 (Apple
  silicon), `cw` v0.4.24, interception on, the owner's GitHub connection
  (2026-11-19, #3999): `gh auth token` began `codewire`, a placeholder;
  `gh api user` named the owner's account; a private repository cloned over
  HTTPS and `gh pr list` listed its pull requests. The push, the SSH-form
  clone and the other states are not yet observed.

## `no-token-at-rest`: no credential value is left on a disk, in a checkpoint or in a log

Issues: #3999 (local VMs, #4897), #4001 (hosted Sandboxes), #6194 (the
shape scan).

Two scans, each run where the walk's credentials are bound under
interception, with the same findings format: a finding names a shape or a
value, a form, a file and an offset, never the bytes.

- **The canary scan** (`scripts/ci/verify/scan-credential-canaries.py`,
  #4897) looks for synthetic values it is given, in every form a program
  might store them in. It proves the local smoke's own values never land.
- **The shape scan** (`scripts/ci/verify/scan-token-shapes.py`, #6194)
  looks for any value in a real provider's shape, so it needs no
  value and works with a real sign-in. It is run in every interception walk,
  local and hosted, by whoever walks `agent-claude`, `agent-codex`,
  `agent-github` and `agent-own-key` with real credentials.

The shape scan:

- **Shapes:** a closed table in the script, each a provider's fixed prefix
  and the length and alphabet of what follows. It covers every credential
  form a walk binds, refresh tokens included:
  - Anthropic API keys and Claude sign-in access and refresh tokens
    (`sk-ant-` forms);
  - OpenAI keys (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, and the older
    `sk-` form);
  - GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`);
  - Google, GitLab, Slack, AWS access key IDs, Stripe and Hugging Face keys;
  - **signed JWTs**, whose header names an algorithm other than `none`: one
    whose `iss` is in the script's closed list of exact issuer URLs (the
    providers' sign-in servers, such as `https://auth.openai.com` for
    Codex's ChatGPT ID and access tokens; reported as `jwt-openai` or
    `jwt-google` by issuer) is a finding, and so is one whose
    header or payload doesn't decode or has no `iss` ("unreadable JWT").
    A JWT with another issuer is not a credential here; Codewire's own
    workload identity tokens are proved by their own journeys. A JWT whose
    header says `none` is unsigned and not a credential only when its third
    segment is empty or exactly `codewire-placeholder`; any other third
    segment is a finding;
  - **a refresh token of no fixed shape,** such as Codex's ChatGPT refresh
    token: a JSON `"refresh_token"` field, or a TOML, YAML or env-style
    `refresh_token =`, `refresh_token:` or `REFRESH_TOKEN=` line, whose
    value is a token's (20 or more of `A-Za-z0-9._~+/=-`, with a letter and
    a digit) and not a Codewire placeholder refresh token
    (`codewire-managed-no-refresh-token`, alone or with its `-` and nonce),
    is a finding, in every form below. An empty string, `null`, or code
    that names a token (`refresh_token = data.get(...)`) is not.
- **Placeholders pass.** A match whose part after the provider prefix is a
  whole placeholder, `cwp1_` and 43 base64url characters, is counted by
  shape and is not a finding; so is a bare `cwp1_` placeholder. Codex's
  delivered login keeps an unsigned JWT shape (`alg` `none`), which is not
  a finding. Anything else in a provider's shape is a finding. There is no
  other allow-list: a listed direct delivery exception is a finding
  wherever interception is on, because interception replaces it.
- **A baseline for what an image ships.** Software in an image can carry
  values in a provider's shape, such as a public API key inside a package,
  and the raw disk scan finds them.
  - The walk takes the baseline in the same run, before any credential is
    bound: `--write-baseline FILE --image DIGEST` writes the findings under
    a first line naming the image's digest and the scanner's SHA-256 (this
    script and the canary scanner it loads).
  - `--baseline FILE --image DIGEST` refuses, with exit 2, a file for
    another image or scanner, and one listing a control or a shape the walk
    binds (`anthropic`, `openai`, `openai-legacy`, `github`, `github-pat`,
    `refresh-token-field` and `jwt-openai`, cut or whole).
  - It excuses a finding only at the same shape, form, path, offset and
    length, and only in a disk the walk declares holds the image alone
    (`--image-disk PATH`, never a state disk), read raw or through its
    filesystem outside `/home`, `/workspace`, `/root`, `/tmp`, `/var/tmp`
    and `/run`. Never a process, a stream, a decompressed log, a memory
    image or checkpoint, or the host's cw directories.
  - An excused finding is counted as `baseline<TAB>SHAPE<TAB>COUNT`, and the
    walk records the baseline it used.
- **Forms:** raw, UTF-16LE, JSON-escaped (`\u00XX` escapes inside a value),
  and inside base64:
  - a run of 40 or more base64 characters, standard or URL-safe, padding
    optional, and runs broken only by `\r?\n` (MIME-wrapped) joined first;
  - each run decoded at all three byte alignments, in both alphabets, and
    the decoded bytes scanned once more in every form above, not decoded
    again.
- **Compressed files** are read decompressed: gzip, zstd and xz (rotated
  logs), and journald files through `journalctl --file`, whose large
  fields are compressed. A compressed file the scan can't read fails the
  scan (exit 2); none is skipped.
- **Where a value may be split:** a disk is read raw and through its
  filesystem, so a file's bytes are whole in the second. A memory image or
  a raw disk keeps a value in pages or blocks that need not be adjacent, so
  a provider prefix followed by at least 16 of its shape's characters,
  ending at a 4 KiB boundary, is a finding of its own, "cut at a page end",
  in the raw and the UTF-16LE (32 bytes) forms. Every 4 KiB boundary also
  covers 16 KiB and 64 KiB pages. A cut whose part after the prefix starts
  with `cwp1_` is a cut placeholder and is counted.
- **Reading:** the canary scan's walk: links not followed, only allocated
  ranges, a directory it can't list fails the scan, ext4 images read
  through `debugfs -c`, and `--scanned FILE` lists every file read with
  its size.
- **Where what it reads goes.** The debugfs spill and every buffer of a
  streamed log hold real values, so they go in a new 0700 directory on
  tmpfs (`$XDG_RUNTIME_DIR`), never on a persistent disk, removed by exact
  path on every exit, failure included. The scanner sets `RLIMIT_CORE` to
  0, so a crash leaves no core dump.
- **Never a value.** A finding is `SHAPE<TAB>FORM<TAB>PATH<TAB>OFFSET<TAB>LENGTH`.
  No byte of the match is printed, hashed, logged or kept past the check
  that classifies it, the provider prefix included; placeholders are
  counted, never listed. Every error is caught at the boundary and names
  only the path, the offset and the error's class, never bytes or their
  repr, and no traceback reaches the output. Exit 0 means nothing but
  placeholders and controls, 1 a finding or a missing control, and 2 that
  the scan itself failed.
- **Controls:** the walk makes one random value in each shape it binds and
  passes them on stdin (`NAME<TAB>VALUE`, never argv), and plants them where
  the scan must find them: a file in the guest's home, a guest process's
  memory (local), a line the walk writes to a scanned log, and the host's
  cw state directory. A match equal to a control is reported as that
  control, by name. A control that is not found fails the scan, so a clean
  result means each medium was read.
- **In a hosted Sandbox** the walk copies the scanner in, checks its
  SHA-256 before running it, and runs it as root, so every process's
  environment and command line can be read; one that can't fails the scan,
  as an unlistable directory does. The Sandbox is a fresh one for the walk,
  and its controls are random and used once.

- **Entry points:** none for a user. A scan run by whoever walks this file,
  over what a local VM, a hosted Sandbox and the host write.
- **States to exercise:**
  - a local VM's disks, a VM checkpoint, and the supervisor's, the
    runner's and the brokers' logs (the front door's once it writes one,
    #4884), after an agent has run;
  - the host's cw config, data, state and cache directories and the local
    runtime's directory, with the same credentials bound;
  - a hosted Sandbox with interception on, after an agent has run: its
    filesystem, every process's environment and command line, and its
    session logs, scanned inside the Sandbox; and the workspace daemon's
    and the front door's logs on Dev, streamed from the cluster into the
    scan on the walker's host, never written to its disk or printed;
  - for the canary scan, synthetic values planted in the credential store,
    and controls planted where a scan must find them;
  - on macOS, disks and logs only: a Mac VM checkpoint (#4654) is not
    scanned yet.
- **Driving it:** the canary scan runs in the managed native smoke,
  `smoke-native-local-environment.sh --managed-credential-broker` (#4897).
  The shape scan, with the controls on stdin:
  `scan-token-shapes.py [--debugfs DEBUGFS] [--spill-parent DIR]
  [--processes] [--exclude PATH]... [--image DIGEST [--image-disk PATH]...
  [--write-baseline FILE | --baseline FILE]] [--scanned FILE] PATH...`. A log streamed from elsewhere is a PATH such as
  `<(kubectl logs …)`. No walk runs it yet. Searching for a real token
  means reading it, so the scan never shows what it read, and for a real
  sign-in
  `agent-claude` also checks the other side: the login file holds a
  `cwp1_` placeholder.
- **Proof:**
  - each synthetic value is found nowhere: not raw, not split across a block
    or page, not as base64, hex or UTF-16, and not through an ext4 image's
    filesystem;
  - the shape scan finds nothing but placeholders in every place listed,
    and counts at least one placeholder for each credential the walk bound;
  - three controls written into the guest's home are found on its state
    disk, raw and through the filesystem: plain, base64-only, and one cut
    inside a scan window and split across non-adjacent blocks, found only
    through its other window;
  - a control held only in a guest process's memory is found in the
    checkpoint's memory, by both scans;
  - each shape-scan control is found where it was planted;
  - each log was read and is not empty;
  - no run prints a value: the walk's own output is searched for every
    control and comes back clean.
- **Gotchas:**
  - A run needs about 40 GB free: a checkpoint holds all of the guest's
    memory.
  - Until the local placement gives Codex placeholders (#4002), the Codex
    access token is in the guest by the listed exception, and the canary
    scan looks for it only after the VM is deleted. The shape scan reports
    it as a finding wherever interception is on.
- **Observed:** not yet observed.

## `agent-own-key`: a process with its own key is left alone

Issues: #3999, #4001.

- **Entry points:** any program in the environment that calls an intercepted
  host with a key of the user's own.
- **States to exercise:**
  - a request carrying the user's own API key;
  - one carrying no credential;
  - one carrying the placeholder together with another credential header;
  - each of the first two on a policy that allows the host by rule, and on
    `locked` or another policy that does not;
  - the placeholder on a path the route does not serve, on `locked` and on
    a policy that allows the host;
  - **an assigned agent under `locked`** (#5215): `claude -p` with the
    selected credential, and `curl` to the provider's host with another key,
    and to another host;
  - **a hosted Sandbox with interception on** (#5555): the user's own key
    and a request with no credential, under `open` and under `locked`;
  - **a host nothing selected names** (#5215), on a local VM and in a
    hosted Sandbox with interception on, while another provider's
    credential is selected: the user's own key to it under `open` and under
    `locked`;
  - **a selection change** (#5215): on a running environment, select a
    credential for that provider, then unselect it;
  - a policy edit on a running local VM that adds, then removes, a rule
    allowing the provider's host.
- **Driving it:** no command yet (#3999, #4001). For the `locked` state:
  `cw --local update NAME --policy locked`, then in the VM
  `claude -p 'Reply with ok.'`,
  `curl -sS -H "x-api-key: $OTHER_PROVIDER_KEY" https://api.anthropic.com/v1/messages`
  and `curl -sS https://example.com/`.
- **Proof:**
  - where the network policy allows the host, the user's own key reaches
    the provider unchanged, and the assigned credential is not used for
    that request;
  - where the policy allows the host, a request with no credential is
    forwarded as sent and gets the provider's own 401;
  - where the policy does not allow the host, both are refused before
    anything is sent, and the refusal log counts them like any name the
    policy refuses. Only a request carrying this environment's placeholder
    on a path its route serves is served there. Selecting a credential
    never widens a network policy;
  - the placeholder on a path the route does not serve is refused before
    any lease, and counted, on `locked` and on every other policy;
  - the placeholder beside another credential header is refused by Codewire
    before it reaches the provider, with an error that says to send one
    credential;
  - **under `locked`, the assigned agent answers** (#5215): `claude -p`
    with the selected credential prints its answer, and `example.com` is
    refused. `cw --local policy list` says `locked  built-in · nothing,
    except the model providers of credentials you selected`, and `cw info`
    says the same under its network policy line. The `curl` with another
    key, and one with no credential, are refused `name_not_allowed` before
    anything is sent (#5215, #5555);
  - **in a hosted Sandbox with interception on** (#5555), on a host a
    selected credential names, the user's own key and a request with no
    credential are both refused `selected_credential_only` with nothing
    sent, under every policy, and the placeholder is served. Not yet
    observed;
  - **on a host nothing selected names** (#5215), nothing is bound: inside
    the environment the host's certificate is not issued by the front door's
    CA, and its chain verifies against the public roots with that CA left
    out (the guest trusts the CA, so a request that merely succeeds proves
    nothing), and a hosted assignment's interception bindings do not name
    it. The user's own key
    reaches the provider untouched where the network policy allows its host,
    and is refused by the network policy, never `selected_credential_only`,
    where it does not. The selected provider beside it is still served
    through the front door. Not yet observed;
  - **after a selection change** (#5215), the change restarts the local VM
    or replaces the hosted Pod. Once a credential is selected, its hosts
    are proxied and the own key on them is refused as above; once it is
    unselected, they are no longer bound and the own key follows the
    policy again. No host is ever bound while nothing selected names it.
    Not yet observed;
  - after a policy edit, the next request follows the new policy: allowed
    once a rule allows the host, refused once it is removed.
- **Gotchas:**
  - Only a request carrying this environment's placeholder is swapped. The
    reply to any other request is passed back as the provider sent it.
  - Locally, a request without a Codewire value on a proxied host follows
    the network policy instead of being refused, because it leaves from the
    user's own machine under their own policy. Hosted, it would leave from
    the platform's side, past the Sandbox's policy, so it is refused (#5555).
  - A deny rule on an intercepted host refuses everything to it, the
    placeholder's own requests included. A policy that merely does not
    list the host still serves the placeholder's requests.
- **Observed:** partly, on a Linux local VM, 2026-11-21, `cw` built from
  main e62d4d033, with interception on, a private keyring and one synthetic
  Anthropic API key selected; recorded on #5215. Under `locked`: the
  placeholder's request reached Anthropic, which answered its own 401 for
  the synthetic key; `curl` to `api.anthropic.com` with another key and
  with no credential got 403 `Codewire-Refusal: name_not_allowed` in 16 and
  13 ms, saying the network policy doesn't allow api.anthropic.com;
  `example.com` did not resolve; a request to
  `chatgpt.com/backend-api/wham/accounts/check` with another bearer got
  403 `name_not_allowed` in 19 ms. Under a policy allowing
  `api.anthropic.com:443` all three Anthropic requests were forwarded and
  got Anthropic's own 401. Not as the proof reads: under a policy allowing
  `chatgpt.com:443` and `*.chatgpt.com:443`, and under `open`, the
  `chatgpt.com` request with another bearer got 403 `denied` with nothing
  sent, since an environment with no Codex credential dials no ChatGPT host.
  That is a gap against this proof, which fails closed, until #5215's
  choice of when a provider's host is bound (#5555 comment 125437). The routed `*.chatgpt.com` branch is proven
  by unit tests only and needs a real ChatGPT sign-in to walk. Not yet
  observed: `claude -p` under `locked`,
  the placeholder on a path the route does not serve, the placeholder
  beside another header, a policy edit on a running VM, and the hosted
  state, which waits for #4001's switch.

## `agent-fail-closed`: losing the front door never opens a direct path

Issues: #3999, #4001.

- **Entry points:** none for a user. An operator ends the environment's front
  door process, or the credential broker.
- **States to exercise:** the front door killed while an agent runs; the
  credential broker killed; the credential broker's routine renewal, every
  600 seconds; either one missing when the environment starts.
- **Driving it:** no command yet (#3999, #4001).
- **Proof:**
  - after the front door ends, or while no credential broker is paired with
    it, a request to an intercepted host fails at once, and no connection
    leaves for that host from the egress broker;
  - other destinations keep following the network policy;
  - **a credential broker replaced by its successor keeps interception**
    (#3999, #4884): the successor pairs again with the same front door, a
    request in flight on the predecessor is answered, and later requests are
    served with the same placeholder and the same authority. A broker the
    authority restarts after a crash pairs the same way. Only the runner's
    end, or the front door's exit, ends interception for the boot, and the
    runner's log records the front door's exit; a stop and start restores
    it;
  - a credential broker that finds no front door to pair with refuses to
    deliver a login rather than hand the VM the real one;
  - an environment whose front door cannot start does not start with
    interception half on: it reports the failure, and a stop and start
    restores it;
  - **a start that fails because the front door stopped says so** (#3999,
    #4916). When the front door ends, or refuses the sockets it was sent,
    before the VM reports started, the start's error reads "The
    environment's interception front door stopped while it started
    (STAGE)" and says to start the environment again; the environment's
    error code is `front_door_STAGE`, and the start fails as soon as the
    front door has stopped. It is not reported as the guest shutting down,
    which only follows from it. `received_dead` is the stage
    for a socket that reached the front door already at end of file: on
    macOS a socket can die in flight under load. The runner's log has the
    same stage on its `front_door_pairing` line, and for a later credential
    broker's socket the front door does not take, `outcome=front_door_dropped`
    with the stage, after which the next broker pairs;
  - **a front door that ended is shown** (#5216, the `lost` state of
    #4912). Once it has ended without a stop being asked for,
    `cw --local info NAME` shows, under its `Credentials` row,
    `! agents can't reach their providers; restart the VM`,
    then `→ cw --local restart NAME` (`->` where `cw` draws ASCII, such
    as under `TERM=dumb`), and `--output json` carries
    `"interception": {"state": "lost"}`. `cw doctor` names the VM with the
    same step. A front door the runner stops, for a stop or a restart, is
    not shown.
- **Gotchas:**
  - a request that hangs is a failure of this step, even though nothing
    leaked;
  - SIGTERM ends the front door at once: it has no handler, and nothing it
    inherits blocks or ignores the signal
    (`sigterm_ends_a_serving_front_door_at_once`). The 20 s the 2026-11-17
    walk saw after a SIGTERM was not reproduced (#5216).
- **Observed:** partly, in the same run as `agent-vm-interception` (Linux
  local VM, 2026-11-18, source 582326b40, recorded on #3999). With the
  front door killed, a
  request to the intercepted host ended at once with a closed connection
  while the VM kept running, and a stop and start restored it. The request
  was served after each of two routine renewals of the credential broker,
  each successor recorded as paired with the same front door. Not yet
  observed: that no connection leaves the egress broker for that host (the
  run shows the guest's request ended at once, not the broker's refusal
  record, #5058); other destinations still following the policy; the
  credential broker killed; either one missing when the environment
  starts.

  Also observed, on a macOS local VM (v0.4.24, 2026-11-19, #5216): SIGTERM
  to the front door by its PID ended it within 2 s, and the VM stayed
  running. `curl` to the intercepted host then failed in 50 ms (exit 7,
  connection refused), but `claude -p` printed nothing until a 120 s cap
  ended it: Claude Code retries a refused connection silently. The
  connection fails at once; the agent does not, which is why the ended
  front door must show in `cw --local info` and `cw doctor`.

  The ended front door shown (#5216), on a Linux local VM (x86_64, KVM),
  2026-11-19: host `cw` built from main 911a51f01, with the guest runtime
  of main 8f3a2d502 (no guest change between the two), a synthetic
  Anthropic API key and the switch on. Before, `cw --local info` had no
  such line and `cw doctor` said `local VM egress ok`. SIGTERM to the
  front door by its PID ended it within 0.1 s (`event=front_door_exited
  signal=15`) and the VM kept running. Then `cw --local info lp-walk`
  showed `Credentials: ! agents can't reach their providers; restart the
  VM` and the restart line, `--output json` carried `"interception":
  {"state": "lost"}`, and `cw doctor`'s `local VM egress` check warned
  "agents can't reach their providers in lp-walk", naming
  `cw --local restart NAME`. `curl` from the VM to the intercepted host
  failed in 26 ms (exit 7). `cw --local restart lp-walk` took 15 s, after
  which neither line showed and a new front door was paired. Under
  `TERM=dumb` that build's restart line drew `→` where the rest of `cw`
  drew `->`; the line now takes `cw`'s own glyphs.

## `agent-switch-off`: with interception switched off, a local VM behaves as before it

Issue: #3999.

- **Entry points:** the file `egress-intercept` in the local VM state root
  holding `off`: the rollback, kept for one release and removed with D3
  (#4002). No command.
- **States to exercise:** the switch set to `off`; the switch absent, or
  holding anything else (both on); a VM checkpoint taken with it off and
  restored with it on, and the reverse.
- **Driving it:** write `off` to the file, then stop and start the VM.
- **Proof:**
  - with the switch set to `off`, a VM boots and its agents use the
    loopback routes, exactly as `docs/dev/SECRETS-AND-CREDENTIALS.md`
    describes, and `cw --local info` names the file;
  - with the switch absent, `on`, or anything else, the boot intercepts,
    and anything but `on` or `off` is logged once;
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
walked on a hosted Sandbox as well. The spec is "Hosted interception" in
[SECRETS-AND-CREDENTIALS.md](../dev/SECRETS-AND-CREDENTIALS.md).

**Done when** (owner, 2026-11-19, #4001): every connected agent credential
goes through the proxy in a cloud Sandbox on Dev, with the switch on, and no
real token is inside the Sandbox. Each row below is walked on Dev:

| Credential | Walked by | Proof inside the Sandbox |
| --- | --- | --- |
| Claude sign-in | a `claude -p` turn, then `/usage` and the plan display | the turn answers, `/usage` and the plan show; the login file's tokens are `sk-ant-oat01-cwp1_…` placeholders |
| Claude subscription token | a `claude -p` turn, under `cw run` and under `cw exec` | `CLAUDE_CODE_OAUTH_TOKEN` is an `sk-ant-oat01-cwp1_…` placeholder in both (#6179) |
| Anthropic API key | a `claude -p` turn | `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY` is a placeholder in its placement's prefix |
| Codex sign-in | a `codex exec` task, with account routing | `~/.codex/auth.json` holds placeholders in Codex's JWT shape |
| OpenAI API key | a `codex exec` task on the key | as in a local VM, the key's variable holds Codewire's fixed managed value and its base URL is the loopback route |
| GitHub | `git clone` and `git push` over HTTPS, and `gh api user` | `git credential fill` and `gh auth token` give a placeholder or nothing; until GitHub's hosts are intercepted (#4001, after #5463), Git and `gh` use today's loopback route, which holds no token in the Sandbox either |

For each, the Sandbox's volume, environment, login files and process
arguments hold no real token, and the hosted sign-in exception is not used
(#4002). Not yet observed.

- **Entry points:** none for a user. Interception is a deployment setting
  for hosted Sandboxes (#4001).
- **States to exercise:**
  - each credential in the table above, one Sandbox per credential form or
    one Sandbox selecting them all;
  - the switch off: the same Sandbox behaves exactly as today;
  - the switch on with a placeholder key the credential service cannot
    read;
  - the switch on with an epoch's Open that carries no placeholders (a
    credential service that predates them);
  - an epoch renewed while an agent runs, and a rebind to another Anthropic
    credential while one runs;
  - two Sandboxes of different users on one node, each with a Claude
    credential;
  - one Sandbox's front door session opened with another Sandbox's token;
  - a Claude turn with interception on, and the same turn on today's relay
    path;
  - the same Claude credential under `cw run`, under `cw exec`, in a
    `cw shell` and over SSH (#6179);
  - `cw-egress`'s logs and configuration after a session;
  - a `cw-egress` rollout, and a `cw-egress` restart, under a running
    Sandbox that has made intercepted calls;
  - a Sandbox claimed from the warm pool;
  - the Sandbox's trust before any agent runs: a new intercepted Sandbox,
    one not intercepted, an image that sets its own
    `NODE_EXTRA_CA_CERTS`, and an image with no system bundle (#6072);
  - the credential service unreachable for longer than a certificate's
    life;
  - a Sandbox's leaves (`SECRETS-AND-CREDENTIALS.md`, "Hosted interception
    leaves"): before its bind, after it, across a `cw-egress` restart and a
    move to another node, and with the credential service stopped;
  - a front-door session ended by `cw-egress`'s token expiry, and reopened;
  - orchestration refusing the session: hosted interception off there, or the
    Pod denied;
  - bindings no front door can serve: an exact name on a port other than
    443, and a suffix;
  - a credential added to a running Sandbox, changing its bound hosts;
  - a Sandbox destroyed after its first intercepted call.
- **Driving it:** no command yet (#4001).
- **Proof:**
  - before the owner walks (#4001's switch-on gate): in a Sandbox whose
    profile selects a credential that is not the owner's (a synthetic one on
    Kind, or Dev's test identity, #6074), the front door has its leaves and
    one agent request to an intercepted host is answered through it, under
    the Sandbox's CA. A CA installed and named is not enough: the leaves come
    from orchestration through the Pod's relay epoch, and without them every
    intercepted handshake is dropped;
  - each row of the table above holds;
  - `cw run`, `cw exec`, `cw shell` and SSH each name the same Anthropic
    placeholder, and a `claude -p` turn answers from each; before #6179,
    `cw exec` named none and Claude Code said it was not logged in (#4001,
    not yet observed);
  - a Sandbox's front door delivers no real Claude or Codex login: an epoch
    that serves the front door delivers placeholder logins or none;
  - with the switch off, the Sandbox's logins, variables and requests are
    exactly today's;
  - with an unreadable placeholder key the epoch's admission is refused, so
    no Open reaches the Sandbox and its agents fail with a refusal;
  - with the switch on and no placeholders in the epoch's Open, the Sandbox
    projects no agent credential and its agents fail with a refusal, never
    through the loopback routes; the daemon's logs hold no placeholder;
  - a renewed epoch keeps the agent's placeholder and its turns go on; after
    a rebind to another credential a new agent gets the new placeholder,
    and one started before it is answered 403 `selected_credential_only`,
    from at most 60 seconds after the rebind until it restarts;
  - a front door session for one Sandbox is refused another Sandbox's
    token, and no request of one Sandbox is ever served with the other's
    credential;
  - a Claude turn's time to its first token and its streaming rate through
    hosted interception are recorded beside the same turn on today's relay
    path, on the same Dev node;
  - the real token appears nowhere in `cw-egress`'s logs or configuration,
    beside the check inside the Sandbox that `agent-claude` makes;
  - an intercepted connection opened after a `cw-egress` rollout, and
    after a `cw-egress` restart, is served under the same CA the Sandbox
    installed at its start. The Sandbox installs nothing new, and a
    process that was already running keeps working;
  - a Sandbox claimed from the warm pool serves an intercepted host under
    the CA it installed before it was claimed;
  - a new intercepted Sandbox has its CA at
    `/codewire/run/egress-trust/ca.pem` before anything runs, with the
    same digest as the certificate its binding stores. A session, `cw exec`
    and SSH all name it as `NODE_EXTRA_CA_CERTS`, and the bundle beside it
    as `CODEX_CA_CERTIFICATE` while Codex is selected. Node reaches an
    intercepted host with no extra flags, and that host's issuer is the
    Sandbox's CA. A Sandbox that is not intercepted has a comment there and
    names nothing. An image's own `NODE_EXTRA_CA_CERTS` is kept (#6072);
  - no CA key is on a node: `cw-egress` holds only certificates for the
    hosts the Sandbox's credentials bind, each valid for at most an hour;
  - with the credential service unreachable past a certificate's life,
    an intercepted host fails closed, its refusals are recorded as
    `intercept_unavailable`, and the Sandbox's status shows it.
    Its other egress is unaffected, and interception returns by itself
    when the service does;
  - an unbound Sandbox's front door has its CA but no leaf; once bound, its
    leaves name exactly its binding's hosts and end within an hour;
  - the CA certificate's digest inside the Sandbox is the same before and
    after a move to another node;
  - a canary leaf key is found in no log of `cw-egress`, orchestration or
    the credential service;
  - a front-door session that ends at `cw-egress`'s token expiry is
    reopened within seconds, and the next intercepted request is served;
  - while orchestration refuses the session, every intercepted request fails
    closed and the Sandbox's other egress works; once it accepts, they are
    served again without a restart;
  - an exact name the front door can't serve is refused on its bound port
    as `intercept_unavailable` and never dialled, while other egress works;
    a suffix binding leaves the Sandbox with no egress through `cw-egress`;
  - after a change to the bound hosts, the new set is intercepted and a
    host no longer bound is ordinary egress again;
  - once a Sandbox is destroyed, its environment's placeholder key row is
    gone, and every other environment's key is unchanged.
- **Gotchas:**
  - The search for the real token is done by its holder, without
    printing it; the tool is owned by #3999.
  - A host bound as a suffix is served for names one label under it. A
    deeper name fails its handshake on a hosted Sandbox, where a local VM
    serves it. No real routed origin has been observed yet; the first
    `agent-codex` run records its depth (#4947).
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
  - a Sandbox whose egress process on its node dies, or whose node's
    `cw-egress` restarts;
  - the control plane unavailable while a Sandbox runs;
  - a user connecting to a Sandbox whose egress goes through the broker;
  - a workload on `locked` calling the platform's own API;
  - a Sandbox whose configuration lacks one of the daemon's in-cluster
    addresses, or has one that is not an IP address and port;
  - a deployment whose DERP relay's certificate comes from its own
    authority, with that authority's bundle mounted into the Sandbox; a
    Sandbox with no bundle mounted, in which a file has been put at the
    bundle's path;
  - a Sandbox whose egress routing is changed after it starts: one of its
    rules removed, the default route moved off the egress path, or IPv6
    turned back on by a privileged container;
  - a Sandbox started on a VM runtime whose containers have no TUN device
    of their own, and one where a symbolic link or another device was left
    at the TUN device's path before its egress setup ran;
  - a new `cw-egress` version rolled out while one Sandbox has nothing
    open, a second is in the middle of a long download, and a third has an
    open terminal or SSH session;
  - a Sandbox created, and one started, while that rollout is under way;
  - a new `cw-egress` version that never becomes ready;
  - a Sandbox whose daemon speaks a version of the egress stream that its
    node's `cw-egress` does not accept, as when a release reaches the
    daemon before `cw-egress`;
  - an environment made while hosted egress was off, left running when the
    switch went on, then repaired, then stopped and started; a second one
    whose running Pod is deleted, so the controller rebuilds it;
  - with the switch on, a confidential environment created, one created
    from a snapshot, and a stopped one started and then removed; the same
    with the switch off.
- **Driving it:** no command yet (#4000).
- **Proof:**
  - the status reads `NOT_ENFORCED` for the first state, `ENFORCED` with the
    enforced revision for the second, `ENFORCING` until the new revision
    takes over for the third;
  - at every start the Sandbox tries one direct connection and one lookup
    at the cluster's DNS, around its egress path. Both must fail. If either
    succeeds the Sandbox does not become ready, its status reads
    `FAILED_CLOSED`, and an operator alert fires. A check that gives no
    result in its time, or a Sandbox whose stream drops before the result,
    reads `FAILED_CLOSED` the same way;
  - each self-check also reads the Sandbox's egress routing back. A missing
    rule, a default route that does not go into the egress path, or IPv6
    turned on fails it with the reason `routing`, and the Sandbox reads
    `FAILED_CLOSED` as for a probe that connected;
  - IPv6 is off in the Sandbox from its start. Turned back on by a
    privileged container, its packets are still dropped on the host side,
    and the next self-check fails with `routing`;
  - a broker-mode Sandbox on a VM runtime starts although its containers
    come with no `/dev/net/tun`: its egress setup makes the device itself,
    in a memory-backed volume only that setup and the workspace container
    mount, owned by the workspace user alone, and the daemon attaches to
    the TUN through it (not yet observed);
  - a symbolic link or a device other than the TUN left at that path is
    removed and replaced, never followed or opened, and a device that still
    isn't the TUN when opened fails the Sandbox's start (not yet observed);
  - on a test cluster with the Sandbox's lockdown left out, the same
    self-check reports that its direct connection got through and the
    Sandbox reads `FAILED_CLOSED`. Without this nothing shows the check
    can fail;
  - a Sandbox whose lockdown is not applied when it starts reads
    `FAILED_CLOSED` with `failure_code` `lockdown_not_applied`, in the API
    and in `cw info`: at once when it is bound at admission, and once the
    bind grace has passed for a claimed warm member. Orchestration's log line
    and counter name the exact refusal, `policy_missing` when the policy is
    absent. It still reads so after its stream has ended. Applying the
    lockdown and starting the Sandbox again clears it (#5068; not yet
    observed);
  - an environment made before hosted egress, with the switch on: while it
    runs, nothing stops or restarts it for its egress, and its repair fails
    with the reason that it must be stopped and started. Its start then
    moves it to hosted egress: its Sandbox's pod template becomes what a
    create renders for it, in one change made while it has no Pod, and its
    workspace keeps its files. The new Pod passes the self-check and the
    lockdown check, reaches an allowed host through `cw-egress`, and is
    refused a host its policy doesn't allow. A Pod the controller rebuilt
    from a Sandbox not yet moved is refused its bind, so its daemon never
    serves (not yet observed);
  - an environment in broker mode while the switch is turned off and on
    again, with the broker settings kept: it keeps its egress the whole
    time. Its own `NetworkPolicy` reads the same before, during and after.
    A restart while the switch is off comes back broker-mode, passes the
    self-check and reaches an allowed host through `cw-egress`. Turning the
    switch back on refuses nothing. A new create while the switch is off is
    direct. With the broker settings removed instead, the broker
    environment is refused with a named reason and is never given direct
    egress (not yet observed);
  - an environment in broker mode running across an orchestration release
    that changes what its policy renders (the gateway, the UDP relay, the
    server namespace or the key broker): it keeps its egress, its first
    admission after the rollout is accepted with no `policy_differs`, and
    its `NetworkPolicy` reads as the new release renders it (not yet
    observed);
  - with the switch on, a confidential create, a confidential create from a
    snapshot, and a stopped confidential environment's start each fail at
    once with "Confidential sandboxes are unavailable on this deployment
    while its network change completes." No environment is recorded for
    the creates, and no Sandbox or Pod is made or changed for any of them;
    the stopped one's removal works. With the switch off the create and
    the start go on as before, and the create from a snapshot is refused
    with its own reason (not yet observed);
  - a claimed warm Sandbox enforces the claimer's policy before the user can
    run anything in it; a claim that cannot confirm that within its limit
    fails, and never hands over an unrestricted Sandbox;
  - while its egress path is down the Sandbox reaches nothing, by any
    route; when the path is back it reconnects by itself and its status
    reads `ENFORCED` again;
  - a running Sandbox keeps its egress on its last policy through a
    control-plane outage; one started or reconnecting during the outage has
    no egress until it ends;
  - the Sandbox Pod's own egress policy names only peers inside the
    cluster, each by selector and port: the egress process on its node, the
    binding, the UDP relay, the key broker for a confidential Sandbox, the
    platform's public gateway and the DERP relay. It has no address range
    and no rule for port 53, and the policy's test fails on any peer or port
    outside that list;
  - the daemon reaches the control plane, the tailnet coordinator, Mesh
    (when the Sandbox has a Mesh URL) and the DERP relay with cluster DNS
    closed, at the addresses in its configuration: the Sandbox connects,
    and its terminal and SSH work. The control plane is reached through the
    gateway's own listener, never behind it, and none of these goes through
    the egress broker;
  - with one of those addresses missing, or not an IP address and port, the
    daemon refuses to start and names the variable. It never resolves the
    URL's host instead;
  - where the relay's certificate chains to the deployment's own authority,
    the platform mounts that authority's bundle read-only into the Sandbox
    and the daemon reaches the relay. Dev and Production mount none, and
    the relay verifies against the public roots alone;
  - the daemon reads the bundle only from a read-only mount of its own. A
    file at the bundle's path in a Sandbox with nothing mounted there is not
    read, whoever owns it: the daemon's log says it ignored the path, the
    daemon starts, and a relay that needs the bundle is refused as
    unverified. A bundle on the platform's mount that is malformed,
    writable, wrongly owned or reached through a link out of the mount
    stops the daemon's start (#5523; not yet observed);
  - a user's connection to the Sandbox uses a direct path the client
    starts, through the Sandbox's VIP, or the UDP relay. The Sandbox never
    starts one: its own direct probes are dropped by the lockdown;
  - in a `cw-egress` rollout (#4000, item 5) the Sandbox with nothing open
    moves to the new version at once, and a connection it opens seconds
    later succeeds: nothing of its own is reset;
  - the long download carries on through the old version. Thirty minutes
    after the old version was told to stop, the download is reset once, and
    the Sandbox's egress works on the new version afterwards. No connection
    is reset twice;
  - the old `cw-egress` Pod exits as soon as its last Sandbox has moved, and
    no later than 30 s after the deadline; it does not sit terminating for
    the whole 30 minutes when nothing is left on it;
  - the open terminal or SSH session carries on through its Sandbox's move
    without a drop: it rides the daemon's path to the platform, which does
    not pass through `cw-egress`;
  - the Sandbox created and the one started during the rollout run on the
    new version from their first connection;
  - a version that never becomes ready moves no Sandbox, and no Sandbox
    loses its egress;
  - a daemon whose stream version `cw-egress` does not accept gets no
    egress stream. `cw-egress` answers with the versions it accepts and
    nothing else, before it reads the Sandbox's token, and the daemon's log
    names both ranges.
    Only an update cures it, so the daemon tries again after 30 s and then
    every 60 s, never every few seconds. A daemon that was already serving
    shows the refusal in its health as `egress_version_unsupported`, with
    both ranges, for as long as it lasts; one that has not yet passed its
    first self-check serves nothing, so its log is where it reads. Once
    `cw-egress` accepts the daemon's version, the next try connects and the
    health line clears (not yet observed);
  - through every move the status reads `ENFORCED`, never `NOT_ENFORCED` or
    `FAILED_CLOSED`, the refusal log keeps its counts, and `cw-egress`'s
    log names the Sandboxes that moved idle and those cut at the deadline,
    with a count of each.
- **Gotchas:**
  - `NOT_ENFORCED` on a running Sandbox is a finding, not a default.
  - A workload can use every path the daemon has. On `locked` it still
    reaches what the platform's public gateway serves (the API, sign-in,
    the dashboard, previews) and the relay. `locked` means the platform's
    own services and nothing else; a walk that records "nothing can leave"
    is wrong.
  - A status whose latest report is older than 15 minutes (three of
    cw-egress's 5-minute refreshes) reads `NOT_ENFORCED`; do not trust a
    cached `ENFORCED`.
  - Connections to the platform's in-cluster address (the daemon's, and a
    workload's that uses the same address) do not pass through `cw-egress`:
    they do not count as open, and a move does not reset them. A Sandbox
    whose only connections are those is idle and moves at once. A
    connection to the platform's public name is an ordinary destination: the
    policy judges it, and it counts as open.
  - A Sandbox between versions has no egress through `cw-egress` for a
    few seconds; its path to the platform's own services is unaffected. A
    new connection made then is delayed, not refused; record the gap.
  - The deadline takes 30 minutes to reach. A walk that shortens it says so,
    and does not count as an observation of the deadline.
- **Observed:**
  - on Dev, 2026-11-23, Dev source 42306388f8, through `policy-hosted`'s
    walk, as the Dev smoke identity (#4000 comment 135597):
    - **The command is `cw info ENV`.** It showed `NetworkPolicy: NAME ·
      rev N · enforces rev N` and `Egress: enforced` for a running Sandbox
      on its selected revision. It showed `enforces rev 2` about 5 s after
      an edit, and `locked · enforced` about 3 s after a move.
    - **The Sandbox saw:** allowed hosts answered, a name the policy
      doesn't allow got no answer, and a disallowed port was refused at
      once.
    - **What doesn't show the decisions yet:** cw-egress logs no admission
      or refusal lines at info level, and `cw policy log` shows no hosted
      refusals until #6144.
    - **Every other state above:** not yet observed.
