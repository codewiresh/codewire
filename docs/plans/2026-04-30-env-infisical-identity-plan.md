# Codewire Env -> Infisical Identity Plan

## 1. State of play

### Confirmed findings from the CLI repo

- The brief references `hetzner_backend.go`, but there is no such file in the current `cli` repo. In this tree, hosted environment behavior is represented by platform API requests, not by a local Hetzner backend implementation.
- The launch/API types already model all three secret selectors:
  - `internal/platform/launch.go:25-33` defines `EnvVars`, `SecretProject`, `IncludeOrgSecrets`, and `IncludeUserSecrets` on `PrepareLaunchRequest`.
  - `internal/platform/types.go:328-350` carries the same fields on `CreateEnvironmentRequest`.
  - `internal/platform/types.go:362-381` carries them into preset definitions.
- `cw env create` and preset authoring already send those fields to the hosted platform API:
  - `cmd/cw/preset_authoring.go:244-265` sends them to `PrepareLaunch`.
  - `cmd/cw/preset_authoring.go:357-403` builds the final `CreateEnvironmentRequest`.
  - `internal/platform/environments.go:37-42` posts that request to `/api/v1/organizations/:org/environments`.
- Local config/spec parsing also preserves the selectors:
  - `internal/config/codewire_yaml.go:14-31` exposes `secrets`, `env`, `include_org_secrets`, `include_user_secrets`.
  - `internal/config/codewire_yaml.go:254-300` defines `secrets.org`, `secrets.user`, `secrets.project`.
  - `cmd/cw/local_cmd.go:141-156` mirrors them in the SDK-facing local JSON spec.
  - `cmd/cw/local_cmd.go:978-999` persists them into `LocalInstance`.
  - `internal/config/local_instances.go:17-36` stores them on disk in `local_instances.toml`.

### Where they would be injected

- Hosted environments:
  - The CLI only forwards selectors to the platform API. Injection is not implemented in this repo; it must happen server-side after `CreateEnvironmentRequest` reaches the Codewire platform.
  - From the CLI code alone, I can confirm forwarding, not actual hosted runtime materialization.
- Local backends:
  - Docker consumes explicit env vars from `instance.Env`: `cmd/cw/local_cmd.go:1451-1479`.
  - Incus consumes only a hard-coded host credential subset plus no `instance.Env` loop at all: `cmd/cw/local_cmd.go:1352-1371`.
  - Lima consumes only a hard-coded host credential subset: `cmd/cw/lima_backend.go:694-705`.
  - Firecracker has no visible env injection path in this repo.

### Correction to the brief

- The Lima gap is real, but "wire Lima to consume what is already specced" is not sufficient by itself.
- The larger gap is that the CLI has no client-side read path for Codewire secret values:
  - `cmd/cw/secrets.go` supports create/list/set/delete/rename for secret projects, org secrets, and user secrets.
  - `internal/platform/secrets.go:35-159` exposes list/set/delete/rename methods only.
  - There is no `GetSecret`, `GetProjectSecret`, `GetUserSecret`, or `cw secrets get` command in the current CLI.
- Result: local backends cannot automatically inject Codewire secret values today, because they can persist selectors but cannot resolve them into `KEY=VALUE` pairs.

### Which backends consume what today

- Hosted platform environments:
  - `EnvVars`, `SecretProject`, `IncludeOrgSecrets`, `IncludeUserSecrets` are forwarded to the API.
  - Actual consumption is outside this repo.
- Local Docker:
  - Consumes explicit `env` from `codewire.yaml` / `--env`.
  - Does not consume project/org/user secret selectors.
- Local Incus:
  - Forwards `GH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`.
  - Does not consume explicit `instance.Env`.
  - Does not consume project/org/user secret selectors.
- Local Lima:
  - Forwards `GH_TOKEN`, `SSH_AUTH_SOCK`, `ANTHROPIC_API_KEY`.
  - Does not consume explicit `instance.Env`.
  - Does not consume project/org/user secret selectors.
- Local Firecracker:
  - No env or secret selector handling found in this repo.

### How `cw secrets` works today

- Secret projects:
  - `cmd/cw/secrets.go:34-168` and `:176-265` manage project creation, listing, set, delete, rename.
  - Backing API methods live at `internal/platform/secrets.go:77-125`.
- User secrets:
  - `cmd/cw/secrets.go:273-406`.
  - Backing API methods live at `internal/platform/secrets.go:134-159`.
- Org secrets:
  - `cmd/cw/secrets.go:410-542`.
  - Backing API methods live at `internal/platform/secrets.go:35-64`.
- Important limitation:
  - Every list endpoint returns metadata only (`SecretMetadata` has key/timestamps only; `internal/platform/secrets.go:5-13`).
  - There is no current mechanism in this repo for a running local backend to retrieve raw secret values.

### Conclusion

The right fix is two-part:

1. Add a secret-resolution path for local runtimes.
2. Then wire every local backend, including Lima, to consume the resolved env map.

Without step 1, wiring Lima only fixes explicit `env`, not Codewire secret projects/org/user secrets.

## 2. Infisical machine identity model

Primary docs:

- Universal Auth: <https://infisical.com/docs/documentation/platform/identities/universal-auth>
- Machine identities overview: <https://infisical.com/docs/documentation/platform/identities/overview>
- CLI `login`: <https://infisical.com/docs/cli/commands/login>
- CLI `run`: <https://infisical.com/docs/cli/commands/run>
- Project config file: <https://infisical.com/docs/cli/project-config>
- CLI quickstart: <https://infisical.com/docs/cli/usage>

### Model

- Universal Auth is a machine identity auth method based on `clientId` + `clientSecret`.
- The client exchanges those credentials at `/api/v1/auth/universal-auth/login` for a short-lived bearer token.
- The default access-token TTL is 7200 seconds, per the Universal Auth docs.
- The default client-secret TTL is `0`, which means no expiry, unless you set one.
- Universal Auth can also issue periodic tokens:
  - If `Access Token Period` is configured, the token can be renewed repeatedly for that period.
  - When the period is set, normal TTL and Max TTL are ignored.

### CLI shape

- Obtain a token:

```bash
INFISICAL_API_URL=https://<your-host>/api \
infisical login \
  --method=universal-auth \
  --client-id="$INFISICAL_CLIENT_ID" \
  --client-secret="$INFISICAL_CLIENT_SECRET" \
  --plain --silent
```

- Use the token with `infisical run`:

```bash
INFISICAL_TOKEN="$(...login command above...)" \
infisical run --projectId="$INFISICAL_PROJECT_ID" --env=dev -- ./script.sh
```

- Important CLI detail:
  - `infisical run` requires `--projectId` when authenticating as a machine identity unless the repo already has a `.infisical.json` / project config file that points at a workspace.

### Recommended identity scope

Infisical's own guidance is permission-set based, not machine-count based. One identity per machine is the wrong default.

Recommended scope:

- One identity per Codewire runtime trust boundary and permission set.
- Concretely:
  - `codewire-local-envs` for local Docker/Lima/Incus sessions.
  - `codewire-hosted-envs` for hosted Codewire workspaces.
  - Split again only when project/path permissions differ.

Trade-offs:

- One per environment:
  - Best blast-radius isolation.
  - Worst operational complexity; too much minting, revocation, and secret distribution.
- One per host:
  - Better than per-environment, but still couples auth to machine lifecycle instead of permissions.
- One per user:
  - Wrong abstraction for shared/ephemeral envs; mixes human identity with machine access.
- One per permission set:
  - Matches Infisical's model.
  - Minimizes identity count while keeping least privilege workable.

## 3. Where the identity lives

There are two separate questions: the bootstrap secret at rest, and the runtime delivery mechanism.

### Local backends: Docker, Lima, Incus

Recommended at-rest location:

- Store the Universal Auth bootstrap values in Codewire-managed secrets, not in a local keychain file:
  - `INFISICAL_API_URL`
  - `INFISICAL_CLIENT_ID`
  - `INFISICAL_CLIENT_SECRET`
  - optionally `INFISICAL_PROJECT_ID` for repos that do not commit `.infisical.json`
- Use Codewire org/project secrets as the primary sink once local secret resolution exists.

Why not local keychain or `~/.config/codewire/identity.json`:

- A fresh `cw run --on codewire` session should work on any machine where the user already has Codewire access.
- Local-only storage breaks the IaC requirement and creates a second secret lifecycle outside Terraform.
- A CLI-managed file would reintroduce secret-zero locally and complicate rotation.

Runtime delivery:

- Inject as env vars into the local runtime at create/start time.
- Do not 9p-mount a credentials file for local backends.
- Reason:
  - Local backends already have env-delivery patterns.
  - Env injection avoids leaving long-lived credential files on host-mounted storage.
  - It is the smallest compatible change with existing backend creation code.

### Hosted Codewire environments

Recommended at-rest location depends on actual runtime substrate:

- If hosted workspaces are Kubernetes workloads:
  - Prefer native K8s/OIDC auth, not Universal Auth client secrets.
  - The infra repo already follows this pattern for machine identities such as `gitea-runner` and `codewire_server`.
- If hosted workspaces are direct Hetzner VMs or containers without a native workload identity:
  - Use a separate Universal Auth identity for hosted envs.
  - Store the bootstrap credentials in the server-side Codewire secret store used during environment provisioning.

Runtime delivery:

- Preferred:
  - Server-side env injection into the workspace runtime.
- Fallback when the substrate only supports first-boot provisioning:
  - Cloud-init writes a root-owned env file outside the repo checkout, for example `/etc/codewire/infisical.env` with mode `0600`, and the runtime launcher exports it into the user shell.

Do not recommend:

- Storing the client secret inside Infisical as the primary bootstrap path for the same workload. That just relocates secret zero.

## 4. Codify in `~/src/infra`

### Recommendation

Yes: create a new identity-only Terraform component, for example:

- `~/src/infra/components/terraform/infisical-codewire-env-identity/`

Reason:

- The concern is "mint and distribute workload identity," not "deploy the Infisical server."
- Keeping it separate from `components/terraform/codewire-infisical/` avoids coupling identity rotation to Infisical instance deployment.
- The existing repo already has the exact resource pattern needed; the new component can just consume shared Infisical host/org/project inputs.

### Resources to use

These are already in active use in the infra repo:

- `infisical_identity`
- `infisical_identity_universal_auth`
- `infisical_identity_universal_auth_client_secret`
- `infisical_project_identity`
- optionally `infisical_project_role` when built-in `viewer` is too weak

Reference patterns:

- Shared Infisical component:
  - `~/src/infra/components/terraform/infisical/main.tf:153-245`
  - `~/src/infra/components/terraform/infisical/outputs.tf:49-58`
- Dedicated Codewire Infisical component:
  - `~/src/infra/components/terraform/codewire-infisical/main.tf:691-728`
  - `~/src/infra/components/terraform/codewire-infisical/outputs.tf:56-70`
- Hosted K8s identity pattern:
  - `~/src/infra/components/terraform/codewire-infisical/main.tf:605-645`
  - `~/src/infra/components/terraform/gitea-runner/main.tf:120-175`

### What the new component should output

- `local_identity_id`
- `local_client_id` (sensitive)
- `local_client_secret` (sensitive)
- `hosted_identity_id` if hosted envs also use Universal Auth
- `project_ids` map for the granted Infisical workspaces
- `infisical_api_url`

### Where outputs should go

Recommended sinks:

- Local backend bootstrap:
  - Sync into Codewire org/project secrets so the CLI can inject them once local secret resolution exists.
- Hosted workspace bootstrap:
  - Sync into the server-side Codewire provisioning secret store used by the hosted runtime.
- CI-only use cases:
  - Optional mirror into Gitea Actions secrets if image builds or provisioning jobs need them.

I do not recommend "Terraform outputs only" as the user-facing delivery path. Sensitive outputs are useful for bootstrap and debugging, but not as the steady-state consumption mechanism.

### Existing stack evidence

- Shared Infisical defaults live in:
  - `~/src/infra/stacks/orgs/system/_defaults.yaml:9-21`
- The Codewire-specific Infisical component is already wired into the Hetzner/K8s stack:
  - `~/src/infra/stacks/orgs/csrke2/platform.yaml:440-445`

## 5. CLI patch outline

This should stay small, but it is not only a Lima patch.

### Patch A: resolve Codewire secret sources before backend creation

Add a single resolution point in `cw local create`, after `prepareLocalInstance` returns and before `createLocalRuntime` is called:

- File: `cmd/cw/local_cmd.go:206-230`

Recommended flow:

1. Build a `resolvedEnv` map from `instance.Env`.
2. If `instance.Secrets != ""` or either include flag is not explicitly false, call a new platform resolver.
3. Merge secret-derived env into `resolvedEnv`.
4. Reassign `instance.Env = resolvedEnv`.
5. Persist the instance as today.

Recommended precedence:

1. org secrets
2. user secrets
3. project secrets
4. explicit `codewire.yaml` `env`
5. explicit `--env`
6. reserved bootstrap env such as relay vars

That keeps backward compatibility: explicit env still wins.

### Patch B: add a raw secret-resolution API/client path

The current client only exposes metadata and writes.

Add one of:

- Preferred: a server endpoint that resolves all applicable secret sources for a requested spec and returns a merged `map[string]string`.
- Acceptable: explicit raw get/list endpoints for project/org/user secret values, then the CLI merges locally.

I would avoid making the CLI fetch secret values key-by-key when a single "resolve for this spec" endpoint can enforce precedence and auditing server-side.

### Patch C: wire every local backend to consume `instance.Env`

#### Lima

Update `cmd/cw/lima_backend.go:680-705` so the `docker run` args append sorted `instance.Env` entries, not just the hard-coded host credentials.

Sketch:

```go
if len(instance.Env) > 0 {
    keys := make([]string, 0, len(instance.Env))
    for key := range instance.Env {
        keys = append(keys, key)
    }
    sort.Strings(keys)
    for _, key := range keys {
        dockerArgs = append(dockerArgs, "-e", key+"="+instance.Env[key])
    }
}
```

Keep `GH_TOKEN`, `SSH_AUTH_SOCK`, and `ANTHROPIC_API_KEY` forwarding as a separate host-credential block.

#### Docker

- Already consumes `instance.Env` correctly at `cmd/cw/local_cmd.go:1470-1478`.
- No structural change needed.

#### Incus

- Add an `instance.Env` loop similar to Docker, using `incus config set environment.KEY value`.
- Today it only forwards the host credential subset.

#### Firecracker

- Leave out of the first patch if necessary, but call it out explicitly as unsupported rather than silently ignoring selectors.

### What `cw secrets get` should be

There is no current `cw secrets get`.

If added, it should not default to "print one raw value to stdout" because that is a footgun. The useful debug surface is:

```bash
cw secrets get --project <name> --include-org --include-user --json
```

Return shape:

```json
{
  "env": {
    "INFISICAL_API_URL": "...",
    "INFISICAL_CLIENT_ID": "...",
    "INFISICAL_CLIENT_SECRET": "..."
  },
  "sources": {
    "org": true,
    "user": true,
    "project": "codewire-infisical-local"
  }
}
```

That gives operators a way to preview the exact resolved env for a backend spec.

### Backward compatibility

- Existing `--env FOO=bar` stays valid.
- Existing `codewire.yaml` `env:` stays valid.
- Secret-derived values fill gaps only; they do not override explicit env unless the user asks for that in a future option.

## 6. End-to-end UX after plan ships

### Local Codewire session

1. Terraform mints the local Codewire Universal Auth identity.
2. A sync step writes the bootstrap values into Codewire-managed secrets.
3. `cw local create` resolves secret selectors into `instance.Env`.
4. Docker/Lima/Incus inject those env vars into the runtime.
5. The image contains the `infisical` CLI and a tiny login helper that refreshes `INFISICAL_TOKEN` from `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` when needed.

Target UX:

```bash
$ cw run --on codewire
# inside env:
$ infisical run --silent --env=dev -- ./scripts/test-snapshot.sh
```

### How the env knows which Infisical project to use

Authentication and project selection are separate concerns.

Recommended project-selection source of truth:

- Commit a repo-local `.infisical.json` with `workspaceId` and optional default environment/branch mapping.
- Infisical documents that this file is non-sensitive and intended to live at repo root.

Why this is better than a single global `INFISICAL_PROJECT_ID`:

- One Codewire identity may need access to multiple Infisical projects.
- Project choice is repo-specific, not machine-specific.
- `.infisical.json` already matches the Infisical CLI's native workflow.

Fallback:

- For repos that cannot commit `.infisical.json`, inject `INFISICAL_PROJECT_ID` and require `infisical run --projectId="$INFISICAL_PROJECT_ID" ...`.

## 7. Gaps, risks, follow-ups

### Out of scope

- Per-developer human Infisical identities.
- Replacing Codewire's own org/user/project secret store with Infisical.
- Automatic project discovery for repos with no `.infisical.json` and no Codewire metadata.

### Risks

- Universal Auth client-secret leakage from local runtimes.
- Over-broad project grants if one identity is shared across unrelated repos.
- Long-lived local sessions outliving the initial Infisical access-token TTL.
- Silent inconsistency across backends if Docker/Incus/Lima are not fixed together.

### Rotation policy

- Prefer finite-lifetime client secrets for local identities and rotate them by Terraform on a schedule.
- Keep access tokens short-lived.
- If longer-lived sessions are common, add a helper that re-logins on demand instead of exporting a static token once at boot.

### Follow-up issues to file

1. CLI: add a local secret-resolution API/client path for project/org/user secrets.
2. CLI: wire `instance.Env` into Lima and Incus, and explicitly gate/disable secret selectors on Firecracker until supported.
3. Images: install the Infisical CLI in the base/full images and add a lightweight token-refresh helper.
4. Infra: add `infisical-codewire-env-identity` and sync its outputs into the Codewire provisioning secret sink.
5. Repo UX: document `.infisical.json` as the per-repo project selector for Codewire workspaces.

## Recommendations

- Do not treat this as only a Lima bug; the missing raw secret-resolution path is the real blocker.
- Use one Infisical identity per Codewire runtime permission set, not per environment or per user.
- For local backends, inject Universal Auth bootstrap values as env vars; for hosted K8s workloads, prefer native workload identity instead of shipping a client secret.
- Put repo-specific project selection in `.infisical.json`; keep authentication bootstrap in Codewire secret injection.
