---
title: Security model
description: What isolates an environment, where secrets and credentials live, and what each placement does not protect.
weight: 2
---

This page describes the boundaries Codewire enforces and the ones it does not.
Read it before you give an agent access to something that matters.

## A VM per environment

Containers share the host kernel, so one kernel exploit reaches every
environment on the node. Codewire runs each environment in its own
hardware-virtualized VM with its own kernel.

- **Hosted sandbox**: one VM per environment on the platform. The default
  runtime profile is Kata Containers with Cloud Hypervisor. A `confidential`
  profile (AMD SEV-SNP) exists for eligible hosts; it is not available on every
  plan.
- **Local VM**: Cloud Hypervisor on KVM on Linux, Virtualization.framework on
  an Apple Silicon Mac. The host tools `cw` runs are confined with Landlock on
  Linux and run under Seatbelt on macOS.
- **Trusted host session**: no containment. Sessions run as your own user with
  your files, your tools and your network. Codewire only owns process cleanup.

Docker inside a hosted sandbox or a local VM is a daemon inside that VM. The
host's container runtime is never mounted or proxied into an environment.

## The in-environment daemon

Every environment runs the Codewire daemon, which is the `cw` binary itself.
It serves terminal and agent sessions, files, an SSH server with SFTP and SCP
on port 2222, and the environment's tailnet peer. There is no per-environment
gateway or sidecar.

In a hosted sandbox the daemon starts, binds to the platform with its
workspace token, receives its access grant, then serves SSH and joins the
tailnet. The platform records the daemon's SSH host key, and
`cw setup ssh` configures OpenSSH to ask the platform for it, so there is no
trust-on-first-use.

## Reaching an environment

`cw` builds a WireGuard tunnel to the daemon and tries direct UDP, then the
shared UDP relay, then DERP (TCP), and finally a WebSocket proxy through the
platform. The relays carry encrypted packets only. The browser terminal goes
through the platform to the daemon.

Preview URLs forward HTTPS requests to one application port. A private preview
requires the viewer's Codewire sign-in; Codewire cookies and headers never
reach the application, and the proxy strips the credential it authenticated
with. See [Networking and previews](@/concepts/networking.md).

## Application secrets and provider credentials

These are two different things with two different boundaries. See
[Secrets and credentials](@/concepts/secrets-and-credentials.md).

**Application secrets** (for example `DATABASE_URL`) are delivered to the
environment's processes as an environment projection under their original
names. Every process in the environment, and its root user, can read them.
Codewire does not promise secrecy from the workload itself.

**Provider credentials** (Codex and OpenAI, Anthropic, GitHub, SSH keys) stay
outside the environment. A credential profile selects identities; the
environment receives endpoints, placeholders and a bounded capability, and a
broker performs the typed operation: an HTTP proxy that injects the real key
and redacts it from responses, a Git and `gh` route, or an SSH signer that
returns only signatures.

- Hosted: the broker is an isolated platform service. The daemon's credential
  bridge carries only typed requests and ciphertext.
- Local VM: the broker runs on your host. Material is stored in the Secret
  Service on Linux or the Keychain on macOS and never enters the VM.
- Trusted host: there is no broker. Agents use your own installed clients and
  their own logins.

**Direct delivery exceptions.** Two things are written into an environment as
the agents' own login files, because those tools only enable plan features
such as `/usage` with their own login: the environment creator's personal
Codex (ChatGPT) sign-in access token and their personal Claude sign-in access
token. Each is delivered only to a hosted sandbox or to the creator's own local
VM, only while the creator's profile selects it, and with a placeholder refresh
token. A delivered token is a bearer token for your account: every process in
the environment, and anyone with terminal access to it, can read it, and it
stays valid at the provider until it expires (about 8 hours for Claude).
Refresh tokens, API keys, Claude setup tokens, GitHub and SSH material and
organization-owned credentials are never delivered.

A change to a credential applies to the next request. Removing a credential
from a profile, or revoking it, stops its use in running environments.

## Repository access

The Codewire GitHub App requests Contents (read and write), Pull requests
(read and write) and Metadata (read). An environment that uses your GitHub
connection, and the agents in it, can read, push to and open pull requests in
every repository the installation covers. Install the App with **Only select
repositories** to keep that reach small; your GitHub token never enters the
environment.

## Accounts

- Two-factor authentication is TOTP. Codewire offers it at every sign-in until
  it is enabled; once enabled it cannot be turned off, only replaced.
- Five failed passwords or codes lock the account for 15 minutes.
- Browser sessions last 8 hours and are listed in Settings → Account, where
  you can sign out any of them.
- API keys carry the `cw_` prefix and are stored hashed.

## What you still own

- The code an agent writes, the dependencies it installs and the services it
  reaches from inside the environment.
- Who you invite to an organization and which environments you share.
- The repositories the GitHub App installation covers.
- On a trusted host, everything: the session is your user.

To report a vulnerability, follow `SECURITY.md` in the Codewire source
repository.
