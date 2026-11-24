---
title: Secrets and credentials
description: Application secrets reach your processes; provider credentials never enter the environment. Profiles select which ones an environment uses.
weight: 50
sort_by: weight
aliases: ["/concepts/secrets-and-credentials"]
---

Codewire keeps two kinds of sensitive value, and they go to different places.

| You have | It is | Where it goes |
| --- | --- | --- |
| a value your application reads, such as `DATABASE_URL` | an [application secret](@/secrets/application-secrets.md) | into the environment's processes, as an environment variable |
| a key or sign-in a tool uses to reach a provider: a model API key, your GitHub connection, an SSH key | a [provider credential](@/secrets/credentials.md) | nowhere near the environment: Codewire uses it on the environment's behalf |
| infrastructure of yours that code in a cloud Sandbox must reach, such as a Kubernetes cluster | a [Sandbox identity token](@/secrets/sandbox-identity.md), not yet released | minted inside the Sandbox for 10 minutes at most; your system trusts your organization's issuer |

Storing either does nothing by itself. An environment gets only the secrets and
the credential profile you select for it.

## Try it

```sh
cw secrets --cloud --user set GREETING                  # type the value; it is never shown again
cw credentials --cloud generate ssh --name my-key       # prints the public key for your Git host
cw credentials --cloud --profile me set ssh my-key      # your first profile becomes your default
cw create --name app --image workspace --user-secrets platform   # your secrets; your default profile
cw exec --in app -- sh -c 'echo "$GREETING"'
```

The last command prints the value you typed. Inside `app`, `git` and `ssh` sign
with `my-key` through a socket, and the private key stays with Codewire. The
[Quickstart](@/quickstart.md) runs the same steps with their output.

## Application secrets

A secret is a named value stored write-only: after you set it, lists show only
its key and timestamps. Pick a scope when you store it, and select the scope
when you create the environment:

| Scope | Store with | Select with |
| --- | --- | --- |
| Organization | `cw secrets --cloud --organization set KEY` (owners and admins) | `--org-secrets` |
| Personal | `cw secrets --cloud --user set KEY`, or `--local --user` on your machine | `--user-secrets platform` or `local` |
| Project, a named collection | `cw secrets --cloud --project NAME set KEY` | `--secrets NAME` |

Every process the environment starts gets the selected values under their own
names: setup commands, shells, `cw run` and `cw exec` commands and managed
agents. Those processes and the environment's root can read them. See
[Application secrets](@/secrets/application-secrets.md).

## Provider credentials

A credential is a named identity for a provider. Its private material stays in a
protected store, on the platform or on your machine (the Secret Service on
Linux, the Keychain on macOS). The environment gets a way to use it, never the
material:

| Provider | What the environment gets |
| --- | --- |
| Codex and OpenAI, Anthropic | a local HTTP route; Codewire adds the real key to each request and redacts it from responses |
| GitHub | Git over HTTPS and `gh` through a route that adds the token |
| SSH | an agent socket; Codewire signs, and only signatures cross |

Your own Codex and Claude sign-ins are the exception: so that plan features
work, their access tokens are written into the environment as those clients'
login files. See the [security model](@/reference/security.md).

An environment selects credentials through a **credential profile**: a named
set of one identity per provider. Your first cloud profile is your default, and
a cloud `cw create` that names no profile uses it. See
[Credentials](@/secrets/credentials.md).

## On the platform or on your machine

Every `cw secrets` and `cw credentials` command names its store: `--cloud` for
the platform, `--local` for the protected store on your machine. A hosted
sandbox selects platform sources only; a local VM may select either. Codewire
never copies values between the two.

- [Credentials](@/secrets/credentials.md): add, connect and build a profile.
- [Application secrets](@/secrets/application-secrets.md): store and select
  values.
- [CLI: secrets and credentials](@/reference/cli/secrets-and-credentials.md).

## FAQ

**What does an agent see?** The environment's files, the application secrets
you selected (by name), and a local route to the providers in its credential
profile. Never the provider credentials themselves, apart from the sign-in
tokens the [security model](@/reference/security.md) names.
