---
title: Egress policies
description: Decide what an environment may reach on the Internet; the built-in open and locked policies, your own policies, and what egress does not protect.
updated: 2026-11-21
weight: 3
---

What an environment may reach on the Internet is its egress.

**A local VM** has no network device. Its TCP and DNS go to a confined
network worker on your machine, and an egress broker dials out on the VM's
behalf under the VM's network policy. Two policies are built in:

```sh
cw --local policy list
```

```text
open    built-in · every public destination on TCP 22, 80 and 443
locked  built-in · nothing, except the model providers of credentials you selected
```

`open` is the default. Whatever the policy, loopback, private, link-local and
metadata addresses, your machine's own addresses and the public address it is
seen from are always refused. `cw policy check` explains a decision:

```sh
cw --local policy check open example.com:8080
cw --local policy check open 192.168.1.10:443
```

```text
Refused: example.com:8080 by open (port not allowed)
Refused: 192.168.1.10:443 by open (protected address)
```

Make your own policy from `locked` and allow named destinations; every change
is a new revision:

```sh
cw --local policy create web-only --allow 'github.com,*.githubusercontent.com,pypi.org,files.pythonhosted.org'
cw --local policy check web-only api.github.com
```

```text
Created network policy web-only · rev 1
  Allows: files.pythonhosted.org (22, 80, 443), github.com (22, 80, 443), pypi.org (22, 80, 443), *.githubusercontent.com (22, 80, 443)
Refused: api.github.com:443 by web-only rev 1 (name not allowed)
```

Choose it when you create the VM with `cw create --local --policy web-only`,
or name it in the project's `codewire.yaml` as `network: {policy: web-only}`.
An explicit `--policy` wins over the file. The file only names a policy, so a
cloned repository cannot widen its own egress; a hosted create refuses a file
that names one until hosted sandboxes can select a policy.
`cw policy allow` and `cw policy rm` change a policy, and `cw policy delete`
removes one no environment selects. If the worker or the broker stops, the
environment fails closed (`error`) until you stop and start it.

A network policy also decides whether Codewire's own GitHub connection is
used. In a VM whose profile has one, `git` and `gh` use it only when the
policy allows both `github.com` and `api.github.com`. `open` does. Under
`locked`, or a policy that leaves either host out, they fail with a message
that names the network policy. To use the connection under your own policy,
allow both hosts:

```sh
cw --local policy allow web-only api.github.com
```

`locked` lets nothing in the environment reach the network by itself. A
model credential you selected for it still reaches its own provider, and only
that: Codewire sends those requests from outside the environment, with the
selected credential, on the paths its route serves. The GitHub connection is
not such a credential: it follows the policy, as above. To stop a provider as
well, revoke its credential with `cw credentials --local revoke NAME`, which
stops it at once everywhere that credential is used, not only in this VM.

Your own key is a different request. A program in the VM that calls a
provider's host with a key of its own, or with none, gets no help from the
selected credential and follows the policy like any other destination.
Codewire steps in only on the hosts of the credentials you selected: a
provider you selected no credential for is reached directly, like any other
host. Under
`open` it reaches the provider untouched. Under `locked`, or a policy with no
rule for that host, it is refused before anything is sent; a rule for the
host lets it through:

```sh
cw --local policy allow web-only api.anthropic.com
```

Codex sometimes sends its requests to a workspace host under `chatgpt.com`.
For your own key to reach those, the rule must be `*.chatgpt.com`: a rule
for one workspace host on its own isn't enough yet.

Right after you update `cw`, VMs that were already running are still served
by the earlier version's background services. Until you have stopped your
local VMs once, a VM that was already running keeps using the GitHub
connection as before the update, and a VM you start under a policy that does
not allow GitHub gets none of its profile's credentials and says so.

**A hosted sandbox** may reach the public Internet; private, loopback,
link-local and carrier-grade NAT ranges are excluded. Your organization can
keep network policies on the platform, with the same rules and words as on
your computer, on a deployment that has them switched on:

```sh
cw --cloud policy create web-only --allow github.com
cw --cloud create --policy web-only
cw --cloud policy ls
```

They are stored, not enforced yet: a hosted sandbox can still reach anything
public whatever it selects, and each command says so. `cw info` shows a
sandbox's policy and whether it's enforced. A sandbox that selects nothing has
`hosted-default`. `cw --local policy` and `cw --cloud policy` are two stores:
the same name in both is two policies, and `cw policy` with neither uses this
computer's.

Egress is not credential mediation: an environment that can reach a
provider's API on port 443 can try it directly. Codewire keeps provider keys
out of the environment, which is a different guarantee; see
[Secrets and credentials](@/secrets/_index.md).

Docker inside an environment is a daemon inside its VM; see
[Docker inside](@/environments/docker.md).
