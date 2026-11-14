---
title: Ports and preview URLs
description: Publish an application port as an HTTPS preview URL on the platform, or on 127.0.0.1 and an HTTPS hostname for a local VM.
updated: 2026-11-14
weight: 5
aliases: ["/guides/previews", "/concepts/preview-environments"]
---

A server inside an environment is reachable from outside only through a port
you publish. A hosted sandbox publishes it as an HTTPS preview URL, which is
how reviewers, teammates or customers see a branch running without cloning it,
and how you open a dev server from your phone. A local VM has no public
address, so it publishes on `127.0.0.1` of your machine instead.

## Hosted sandbox: preview URLs

A preview forwards HTTPS requests to one port inside the sandbox. There is no
external port number to choose; the URL is

```text
https://{label}-{sandbox-id-prefix}-{organization-slug}.{preview domain}
```

```sh
cw ports my-app --publish 3000 --label web --access org_members
cw ports my-app
cw ports my-app --unpublish 3000
```

From a real run, with a server on port 3000 in the sandbox:

```sh
cw ports pr-42 --publish 3000 --label web --access public
cw ports pr-42
cw ports pr-42 --unpublish 3000
```

```text
  * Port 3000 registered as web
  URL: https://web-28b97-{organization-slug}.{preview domain}
  Access: public
PORT	LABEL	ACCESS	PREVIEW URL
3000	web	public	https://web-28b97-{organization-slug}.{preview domain}
  * Port 3000 (web) removed
```

| Flag | Meaning |
| --- | --- |
| `--label` | 2 to 22 lowercase letters, digits or hyphens; distinct per sandbox; default `port-PORT` |
| `--access` | `creator` (default), `org_members` or `public` |
| `ENV` or `--in ENV` | the environment; defaults to the one selected with `cw use` |

Publishing needs a running sandbox; a stopped one is refused with the
`cw start ENV` repair. `--unpublish` names the guest port, with `--label` to
choose when one port has several previews.

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

A preview is not a public TCP port, and previews are not isolation: removing
them disables this mechanism only.

## Local VM: host ports

A local VM is reachable only through ports you publish on your machine's
loopback address:

```sh
cw ports my-app --publish 3000 --host-port 3000     # http://127.0.0.1:3000
cw ports my-app
cw ports my-app --unpublish 3000                    # by guest port
```

`--host-port` defaults to the guest port; `--label` and `--access` are
refused here. Publishing needs a running VM; a stopped one is refused with
the `cw start ENV` repair, while listing and unpublishing work either way.
When a guest port is published on several host ports, `--unpublish` takes
`--host-port` to choose one. In `codewire.yaml`, a `host_port`/`guest_port`
pair declares a local port:

```yaml
ports:
  - host_port: 3000
    guest_port: 3000
```

Publishing joins your machine's loopback to the VM's. A connection to
`127.0.0.1:3000` on your machine reaches port 3000 on the VM's own loopback,
made as the workspace user, so a server in the VM that listens on `127.0.0.1`
answers, and so does one on `0.0.0.0`. The host port listens on `127.0.0.1`
only: nothing on your network can reach it, and nothing in the VM is
reachable from your machine unless you publish that exact port. When nothing
in the VM listens on the port yet, `cw ports --publish` says so; connections
are closed until a server starts. The workspace's own SSH and credential
ports can't be reached this way.

## Local VM: HTTPS hostnames

A labelled port of a local VM is also served at an HTTPS hostname of its own
while the VM runs:

```yaml
ports:
  - port: 3000
    label: web
```

```text
https://{label}-{environment}.cw.localhost
```

`cw create` prints each URL, and `cw ports ENV` lists them beside the host
ports. Browsers send every `.localhost` name to your own machine without
DNS, and keep cookies per hostname. So two environments running copies of one
app, at `web-shop-a.cw.localhost` and `web-shop-b.cw.localhost`, keep their
own sign-ins, which two host ports on `localhost` can't. Requests reach the
port on the VM's own loopback, as host ports do. They keep their `Host`
header and gain `X-Forwarded-Proto: https` and `X-Forwarded-Host`.
WebSockets work. A stopped VM's hostnames refuse connections.

A hostname is one DNS label. The label and the environment's name together
may use lowercase letters, digits and inner hyphens, 63 characters in all.
A port whose label and name don't fit, such as a label `Web UI` or a name
with `_`, works as before but gets no HTTPS URL, and `cw ports` says why.
`cw create` refuses a labelled port whose hostname another environment
already has, and names it. Ports without a label are unaffected.

The certificates come from a certificate authority of your own. Codewire
makes it the first time, keeps it in its local state readable only by you,
and it can sign only names under `cw.localhost`. `cw local-https status`
prints where its certificate is. Browsers don't trust it yet, so they warn.
Command-line tools trust it when told to: `curl --cacert PATH`, or
`SSL_CERT_FILE=PATH` for most OpenSSL-based tools, and
`NODE_EXTRA_CA_CERTS=PATH` for Node.js.

On Linux only root may listen on port 443 until you allow it once:

```sh
sudo cw local-https setup
```

It lets any program on your machine, not only root, listen on ports 443 and
up, and changes nothing else; it prints how to undo it. If another program
already listens on 443, `cw` names it and asks whether to serve on port 8443
instead, where URLs end in `:8443`. `cw local-https port 8443|443|off`
changes the choice later. Any program on your machine can open these URLs,
as with host ports.

Cookies are kept per hostname, except a cookie an app sets with
`Domain=cw.localhost`, which every local environment's hostnames share, as
any parent domain would. Leave `Domain` unset to keep a cookie to one
environment.

## Related

- [Preview environments](@/use-cases/preview-environments.md): a sandbox per
  pull request, from start to finish.
- [Networking](@/networking/_index.md): how environments reach each other and
  the internet.
