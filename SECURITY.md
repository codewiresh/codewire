# Security Policy

## Supported Versions

Codewire is pre-1.0 and ships continuously off the `main` branch. Only the
latest released tag and the current `main` are supported for security fixes.

| Version          | Supported          |
| ---------------- | ------------------ |
| `main`           | :white_check_mark: |
| Latest `v0.3.x`  | :white_check_mark: |
| Older `v0.3.x`   | :x:                |

## Reporting a Vulnerability

If you find a security issue in codewire, please report it privately. Do not
open a public GitHub issue.

Email: **n@noeljackson.com**

Include:

- A description of the issue and which component it affects (control plane API,
  workspace daemon, dashboard, CLI, local VM runtime, etc.).
- Steps to reproduce, or a proof-of-concept if you have one.
- The version or commit SHA you tested against.
- Any suggested remediation, if you have a recommendation.

We will acknowledge your report within three business days and aim to provide a
status update within one week. Coordinated disclosure timelines will be agreed
on a per-issue basis.

## Scope

In scope:

- The Rust control-plane services in `crates/`, including billing,
  orchestration, IdP/auth, credential service, coordinator, Mesh, the
  workspace daemon, DERP, the local VM runtime, and the `cw` CLI.
- The retained Go SDK/generated-client modules, Tailscale-client
  interoperability suite, and Tailscale wire-format golden.
- The dashboard (`apps/dashboard`) and other client apps in this repository.
- The published SDKs and generated clients in `libs/` and `packages/`.
- The Kubernetes manifests in `deployments/k8s/`.

Out of scope:

- Self-hosted infrastructure operated by individual users (your own k8s
  cluster, your own database, your own Stripe account, etc.) — those are your
  responsibility.
- Third-party dependencies — report those upstream and let us know if a
  workaround is needed on our side.
- Theoretical issues without a reproducer.

## What we will and will not do

We will:

- Acknowledge and investigate every legitimate report.
- Credit reporters who want public credit, on a best-effort basis once the
  issue is fixed and disclosed.
- Coordinate disclosure timing where appropriate.

We will not:

- Pay bug bounties at this stage of the project.
- Take action against good-faith security research that follows this policy.
