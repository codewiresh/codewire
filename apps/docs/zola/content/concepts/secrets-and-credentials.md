---
title: Secrets and credentials
description: Application secrets reach your processes; provider credentials never enter the environment. Profiles select which ones an environment uses.
weight: 4
---

Codewire keeps two things apart on purpose.

| | Application secrets | Provider credentials |
| --- | --- | --- |
| Examples | `DATABASE_URL`, `SENTRY_DSN`, a signing key your app reads | a Codex sign-in, an OpenAI or Anthropic API key, a Claude subscription token, your GitHub connection, an SSH key |
| Who uses it | your application and tools, by name | Codex, Claude Code, Git, `gh`, `ssh` |
| Where the value goes | into the environment's processes | nowhere near the environment; a broker uses it on the environment's behalf |
| Selected by | `--secrets`, `--user-secrets`, `--org-secrets`, or `secrets:` in `codewire.yaml` | `--profile`, or `credentials.profile` in `codewire.yaml` |

Storing either does nothing by itself. An environment with no selected sources
has no application secrets; one with no profile has no provider access.
Codewire never infers the category from a key's name or value.

## Application secrets

A secret is a named value stored write-only: after you set it, lists show only
the key and its timestamps. Three scopes exist on the platform, one locally:

| Scope | Where | Selected with |
| --- | --- | --- |
| Organization | organization **Secrets** page, `cw secrets --cloud --organization` | `--org-secrets` |
| Personal | **Settings → Secrets**, `cw secrets --cloud --user` or `--local --user` | `--user-secrets platform` or `local` |
| Project | a named collection owned by the organization, `cw secrets --cloud --project NAME` | `--secrets NAME` |

When a process launches, Codewire assembles the selected values into an
**environment projection** for that launch and hands them to the process
under their original names: setup, install and startup commands, shells,
`cw run` commands and managed agents alike. If a key is set in several
selected sources, the environment's own configuration wins, then personal,
then project, then organization. Those processes and the environment's root
can read the values; Codewire does not promise secrecy from the workload
itself. A changed value reaches the next launch; running processes keep what
they were given.

Keys match `[A-Za-z_][A-Za-z0-9_]*`. Values are UTF-8 up to 64 KiB.

## Provider credentials

A credential is a named identity for an external provider. Its private
material stays in a protected store, on the platform or on your machine
(the Secret Service on Linux, the Keychain on macOS), and reaches an
environment only as a typed capability:

| Provider | Credential kinds | What the environment gets |
| --- | --- | --- |
| Codex and OpenAI | Codex (ChatGPT) sign-in, OpenAI API key | a local HTTP route; the broker adds the real key and redacts it from responses |
| Anthropic | API key, Claude subscription token, Claude sign-in | the same kind of route (`ANTHROPIC_BASE_URL` plus a placeholder token) |
| GitHub | your one GitHub App connection | Git over HTTPS and `gh` through a route that adds the token |
| SSH | a generated Ed25519 key or an imported OpenSSH key | an agent socket; the host or platform signs, and only signatures cross |

Two exceptions exist so that the agents' plan features work: your own Codex
sign-in and your own Claude sign-in access tokens are written as those
clients' login files in a hosted sandbox or your own local VM. Everything in
that environment can read them. See the [security model](@/security.md).

Sign-ins are personal: an organization can hold API keys and SSH keys, never a
Codex, Claude or GitHub login.

## Credential profiles

A profile is a named selection of identities, one per slot:

| Slot | Accepts |
| --- | --- |
| `codex` | a Codex sign-in or an OpenAI API key |
| `openai` | an OpenAI API key |
| `anthropic` | an Anthropic API key, a Claude subscription token or a Claude sign-in |
| `ssh` | an SSH key |

Your GitHub connection is part of every profile automatically. A profile holds
identities only: no secret mappings, no exposure rules. Editing a profile
creates a new revision; an environment keeps the revision it selected until
you run `cw update ENV --profile NAME` again.

```sh
cw credentials --cloud --profile work set codex work-codex
cw credentials --cloud --profile work set anthropic work-claude
cw create --name app --image workspace --profile platform:work
```

Managed Codex takes the `codex` slot, or the `openai` slot without one; Claude
Code takes the `anthropic` slot.

## Local and platform origin

Secrets and credentials live either in your local store (`--local`) or on the
platform (`--cloud`). References name the origin: `local:work`,
`platform:work`, or a bare name when it is unique. A local VM may select local
or platform sources; a hosted sandbox selects platform ones only. Codewire
never copies material between stores.

- [Provider credentials](@/guides/credentials.md): add, connect and build a
  profile.
- [Application secrets](@/guides/application-secrets.md): store and select
  values.
- [CLI: secrets and credentials](@/cli/secrets-and-credentials.md).
