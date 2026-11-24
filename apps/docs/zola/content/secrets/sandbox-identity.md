---
title: Sandbox identity tokens
description: A cloud Sandbox gets a short-lived OIDC token that proves which organization's Sandbox it is, for a verifier your organization registered, with no long-lived secret inside it.
updated: 2026-11-24
weight: 3
---

**Not in a release yet.** Sandbox identity is being tested on Codewire's
development deployment. The `cw identity` commands and the issuer described
here come with a later release; until then, nothing on this page works on
codewire.sh.

A cloud Sandbox can ask for a token that says "I am Sandbox X of organization
Y, in these groups". A system you run, such as a Kubernetes cluster, an
OpenBao server or a cloud provider's workload identity federation, checks the
token against your organization's public keys and grants access. The Sandbox
holds no password, API key or certificate for that system, and each token
expires within 10 minutes.

Use it when code in a Sandbox needs to reach infrastructure you control. For
model providers and Git hosts, use [credentials](@/secrets/credentials.md);
for values your application reads, use
[application secrets](@/secrets/application-secrets.md).

## How it works

1. An owner or admin of the organization registers the verifier as an
   **audience**: an `https` URI that the verifier expects tokens to name.
2. An admin gives a Sandbox **identity groups**, such as `data-readers`.
3. Inside the Sandbox, `cw identity token --resource URI` prints a token for
   that audience.
4. The verifier trusts your organization's **issuer**, checks the audience,
   and decides what the token's subject or groups may do.

## Register an audience

```sh
cw identity audience add https://k8s.example.com
cw identity audience add https://bao.example.com:8200/v1/auth/jwt --groups readers --lifetime 5m
cw identity audience list
cw identity audience remove https://k8s.example.com
```

- An audience is an absolute `https` URI with no user name, query or fragment.
  Codewire stores it in a canonical form: lowercase scheme and host, no
  `:443`, and the path exactly as written. A token request must name the same
  canonical audience.
- It can't be an IP address, a local or private-network name, the in-cluster
  Kubernetes API, or a domain the Codewire deployment itself serves.
- `--groups` limits which of a Sandbox's groups go into this audience's tokens.
  Without it, every group does.
- `--lifetime` is 1 to 10 minutes, 10 by default.
- `--claim created_by` and `--claim environment_name` add those claims to this
  audience's tokens. They are off by default.
- Each audience is registered once per organization. Two organizations may
  register the same URI: their tokens name different issuers.

`--file NAME` is accepted, but Sandboxes don't receive the file yet. See
[In the Sandbox](#in-the-sandbox).

## Give a Sandbox groups

```sh
cw identity groups set app data-readers   # replaces app's groups
cw identity groups app                    # lists them
cw identity groups set app --clear        # removes them all
```

- Only an owner or admin of the organization sets groups. Nothing in a create
  request, `codewire.yaml` or the Sandbox can.
- A group name is 1 to 63 lowercase letters, digits and hyphens, and `all` is
  reserved. A Sandbox has at most 32.
- **Everyone who can run code in the Sandbox can use its groups:** its creator,
  members granted operator or owner, the organization's owners and admins, and
  every process in it. `cw identity groups set` lists who that is. Granting
  operator or owner on a Sandbox that has groups needs an admin.
- A fork made by someone who isn't an admin starts with no groups.
- A change applies to the next token. Tokens already issued keep their old
  groups until they expire, within 10 minutes.

## Stop and resume

```sh
cw identity stop app      # this Sandbox gets no new token
cw identity stop --org    # no Sandbox in the organization does
cw identity resume app
```

Stopping refuses new tokens straight away. Inside the Sandbox, a token it
already holds may still be handed out until half its lifetime, and every token
issued before the stop stays valid until it expires, within 10 minutes. This is
not revocation.

## Get a token in the Sandbox

```sh
cw identity token --resource https://k8s.example.com
kubectl --token "$(cw identity token --resource https://k8s.example.com)" get pods
```

The token goes to standard output with no newline. It needs no sign-in: the
Sandbox proves itself. A refusal goes to standard error with its name, and
`cw` exits non-zero:

| Name | Meaning |
| --- | --- |
| `invalid_target` | The resource isn't an audience your organization registered. |
| `identity_stopped` | Minting is stopped for this Sandbox or its organization, or the organization or the Sandbox's creator is suspended. |
| `resource_exhausted` | Too many requests: a Sandbox may ask 30 times a minute, with bursts of 10. |
| `not_running` | The Sandbox isn't running. |
| `identity_unavailable` | Identity tokens are unavailable right now. |
| `key_not_yet_published` | The signing key is too new: a new key signs nothing for its first 24 hours. |

Outside a cloud Sandbox, `cw identity token` says so and exits 2. Local VMs
and hosts don't have identity tokens.

## In the Sandbox

The Sandbox's daemon serves tokens on a local socket,
`/codewire/run/identity.sock`, which `cw identity token` uses. It keeps one
token per audience until half its lifetime, then asks for a new one. Logs
name the audience, never the token.

Every process in the Sandbox runs as the same user, so any of them can ask for
a token. The groups you give a Sandbox are the boundary, not the process.

**Not built yet:** for an audience registered with `--file NAME`, the daemon is
to keep a current token in `/codewire/run/identity/NAME.jwt`, renewed at half
its lifetime, on a memory-only file system kept out of snapshots, checkpoints
and file copies. Today the registration stores the name, but no file appears
in the Sandbox.

## The issuer

Each organization has its own issuer:

```text
{issuer base}/orgs/{org id}
```

`cw org current` prints your organization's ID. The issuer base is the
deployment's; codewire.sh's will be listed here when the feature is released.
Two URLs hang off the issuer:

- **OIDC discovery:** `{issuer}/.well-known/openid-configuration`
- **Public keys (JWKS):** `{issuer}/jwks.json`

Both may be cached for five minutes. A deleted organization's issuer stops
answering. Keys are ES256 (P-256), named `sandbox-identity-{version}`, and a
new key version is published 24 hours before it signs anything, so a verifier
that refreshes the JWKS at least once a day never meets an unknown key.

## The token's claims

A token is a compact JWS signed with ES256. Decoded, it looks like this:

```json
{
  "alg": "ES256",
  "kid": "sandbox-identity-7",
  "typ": "JWT"
}
{
  "iss": "https://identity.example.com/orgs/4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40",
  "sub": "spiffe://sandboxes.example.com/org/4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40/sandbox/821a645e-730d-4d5d-8403-4a2ce3a5e6c9",
  "aud": "https://k8s.example.com",
  "iat": 1794600000,
  "nbf": 1794600000,
  "exp": 1794600600,
  "jti": "Rk0xMjM0NTY3ODkwYWJjZA",
  "groups": [
    "4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40:all",
    "4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40:data-readers"
  ],
  "codewire.sh": {
    "org_id": "4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40",
    "sandbox_id": "821a645e-730d-4d5d-8403-4a2ce3a5e6c9"
  }
}
```

| Claim | What it holds |
| --- | --- |
| `iss` | The Sandbox's own organization's issuer. |
| `sub` | The Sandbox's SPIFFE ID: `spiffe://sandboxes.{deployment domain}/org/{org id}/sandbox/{sandbox id}`. |
| `aud` | One string: the registered audience, in its canonical form. |
| `iat`, `nbf` | When it was issued. `nbf` equals `iat`. |
| `exp` | When it expires: the audience's lifetime after `iat`, never more than 10 minutes. |
| `jti` | A random identifier, unique to this token. |
| `groups` | `{org id}:all`, then `{org id}:{group}` for each of the Sandbox's groups this audience may see, sorted. |
| `codewire.sh` | One object holding Codewire's own claims, below. |
| `codewire.sh` → `org_id`, `sandbox_id` | The organization and the Sandbox, always. |
| `codewire.sh` → `created_by` | The creator's user ID, never an email address or a name. Only for audiences registered with `--claim created_by`. |
| `codewire.sh` → `environment_name` | The Sandbox's name. Only for audiences registered with `--claim environment_name`. |

Codewire's claims are members of one claim named `codewire.sh`, not claims
named `codewire.sh.org_id`. A verifier's rule reads them as
`claims["codewire.sh"].org_id`.

The header never names a key location (`jku`, `x5u`, `jwk` or `x5c`). There is
no email, name, `nonce`, `azp` or `amr`: this is a workload identity, not a
person's sign-in.

## Trust it from your system

Whatever the verifier, it needs the same three things:

1. **Issuer:** exactly `{issuer base}/orgs/{your org id}`, with keys from its
   discovery document. Trusting one organization's issuer never admits another
   organization's tokens.
2. **Audience:** exactly the URI you registered, in its canonical form.
3. **A condition on who:** `sub` for one Sandbox, or a value in `groups`, such
   as `{org id}:data-readers`, for every Sandbox an admin put in that group.
   Prefer groups: a Sandbox's ID changes when it is made again, and a group
   doesn't.

A Kubernetes cluster's structured authentication configuration, for example:

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://identity.example.com/orgs/4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40
      audiences: [https://k8s.example.com]
    claimMappings:
      username: { claim: sub, prefix: "" }
      groups: { claim: groups, prefix: "" }
```

Then bind roles to a group, such as
`4f1c2b7e9a0d4c6f8e3b5a7d9c1e2f40:data-readers`. An OpenBao JWT auth mount
takes the issuer as its discovery URL and bound issuer, the audience as the
role's bound audience, and the group as a bound claim. A cloud provider's
workload identity federation takes the issuer as an OIDC provider, the
audience as its allowed audience, and `sub` or `groups` in the role's
condition.
