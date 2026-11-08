---
title: Errors
description: The error codes the Codewire platform returns, what each one means, and what to do next.
updated: 2026-11-08
weight: 10
---

When the platform refuses a request, `cw` prints the platform's message and
exits with status 1. The output below is from a real run on a Codewire
platform:

```sh
cw create --name err-demo --preset no-such-preset
cw info no-such-sandbox
```

```text
create environment: preset not found: no-such-preset
platform environment "no-such-sandbox" not found
```

Behind each message the platform's API returns a stable code, listed below
with what to do. Code that calls the API should branch on the code, never on
the message text, which can change.

## Sign-in and permission

| Code | Means | What to do |
| --- | --- | --- |
| `session_expired` | Your saved sign-in has expired | `cw login` |
| `forbidden` | Only organization owners and admins may do this | Ask an owner or admin |
| `access_denied` | Only the environment's creator, or someone it is shared with, may do this | Ask the creator to share it; see [Members and sharing](@/organizations/members.md) |
| `insufficient_scope` | The sign-in lacks the API scope | `cw login` again |
| `api_key_scope_violation` | An API key cannot do account-level or global operations | Use your own sign-in for this |

## Not found

| Code | Means | What to do |
| --- | --- | --- |
| `env_not_found` | No environment with that name or ID in this organization | `cw ls` |
| `org_not_found` | No such organization, or you are not a member | `cw org list` |
| `preset_not_found` | No such preset in the organization | `cw preset list` |
| `secret_project_not_found` | No such secret project | `cw secrets list` |

## State

| Code | Means | What to do |
| --- | --- | --- |
| `invalid_state` | The environment is in a state that does not allow this, for example resizing while it starts | `cw info ENV`, then retry when it is `running` or `stopped` |
| `environment_protected` | The environment is protected from deletion | `cw unprotect ENV` first |
| `preset_in_use` | An environment created from the preset still exists | Remove those environments first |
| `storage_shrink_forbidden` | A disk can only grow | Choose a size at least as large as the current one |
| `missing_input` | A create named neither a repository, an image nor a preset | Add `--repo`, `--image` or `--preset` |

## Limits

| Code | Means | What to do |
| --- | --- | --- |
| `quota_exceeded` | The organization already has as many active sandboxes as its plan allows | Stop or remove one (`cw stop`, `cw rm`), or upgrade the plan |
| `resource_limit_exceeded` | The new sandbox's CPU or memory would take the organization past its total | Stop a sandbox or make one smaller |
| `disk_limit_exceeded` | A hosted sandbox's disk is at most 200 GiB, at create and when it grows | Choose 200 GiB or less |
| `confidential_disk_limit_exceeded` | A confidential sandbox's disk is at most 50 GiB | Choose 50 GiB or less |
| `rate_limited` | More than 10 creates, or 10 starts, in a minute | Wait a moment and retry |

Stopped sandboxes do not count toward either limit. See
[Resources and limits](@/environments/resources.md) for the numbers.

## Organizations being changed

| Code | Means | What to do |
| --- | --- | --- |
| `organization_write_blocked` | The organization is being deleted | Wait for the deletion to finish, or retry the failed deletion |
| `organization_mutation_lease_conflict`, `organization_mutation_barrier_not_drained`, `organization_deletion_stale_generation` | Another change to the organization is still in flight | Wait, reload, and retry |

## Related

- [Troubleshooting hosted sandboxes](@/reference/troubleshooting-hosted.md)
- [Troubleshooting](@/reference/troubleshooting.md) for local VMs
