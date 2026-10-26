---
title: Egress policies
description: Decide what an environment may reach on the Internet; the built-in open and locked policies, your own policies, and what egress does not protect.
updated: 2026-10-26
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
locked  built-in · nothing
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

Choose it when you create the VM with `cw create --local --policy web-only`.
`cw policy allow` and `cw policy rm` change a policy, and `cw policy delete`
removes one no environment selects. If the worker or the broker stops, the
environment fails closed (`error`) until you stop and start it.

**A hosted sandbox** may reach the public Internet; private, loopback,
link-local and carrier-grade NAT ranges are excluded. There is no
per-environment egress rule on the hosted platform yet.

Egress is not credential mediation: an environment that can reach a
provider's API on port 443 can try it directly. Codewire keeps provider keys
out of the environment, which is a different guarantee; see
[Secrets and credentials](@/secrets/_index.md).

Docker inside an environment is a daemon inside its VM; see
[Docker inside](@/environments/docker.md).
