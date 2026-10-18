---
title: Ports and previews
description: Publish an application port as an HTTPS preview URL on the platform, or on 127.0.0.1 for a local VM.
weight: 6
---

## Hosted sandbox: preview URLs

A preview forwards HTTPS requests to one port inside the sandbox. There is no
external port number to choose; the URL is

```text
https://{label}-{sandbox-id-prefix}-{organization-slug}.{preview domain}
```

```sh
cw env port add 3000 --label web --access org_members -e my-app
cw env port list -e my-app
cw env port rm web -e my-app
```

| Flag | Meaning |
| --- | --- |
| `--label` | 2 to 22 lowercase letters, digits or hyphens; distinct per sandbox; required on the platform |
| `--access` | `creator` (default), `org_members` or `public` |
| `-e, --env` | the environment; defaults to the one selected with `cw use` |

Port 2222 is reserved for the environment's SSH server. The dashboard's
**Ports** dialog on the Sandbox page offers the same fields and shows the
exact URL with **Open** and **Copy**.

A `creator` or `org_members` preview asks a signed-out browser to sign in,
then returns it to the page. The application never sees Codewire's cookies or
headers, and a Codewire credential sent to the preview is stripped before the
request reaches the application; the application's own cookies and `Basic`
authentication pass through.

A preset or `codewire.yaml` can declare previews so that every environment
created from it gets them:

```yaml
ports:
  - port: 3000
    label: web
    access: org_members
```

Previews are not isolation. Removing them disables this mechanism only.

## Local VM: host ports

A local VM is reachable only through ports you publish on your machine's
loopback address:

```sh
cw env port add 3000 --host-port 3000 -e my-app    # http://127.0.0.1:3000
cw env port list -e my-app
cw env port rm 3000 -e my-app                      # by host port
```

`--host-port` defaults to the guest port; `--label` and `--access` are
refused here. A stopped VM records the change and publishes the port at its
next start. In `codewire.yaml`, a `host_port`/`guest_port` pair declares a
local port:

```yaml
ports:
  - host_port: 3000
    guest_port: 3000
```
