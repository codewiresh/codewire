# Shared Preset and Runtime Model

Date: 2026-03-23

## Summary

Codewire should use a single shared `codewire.yaml` file as the user-facing preset definition for both:

- cloud environments managed by Codewire
- local environments launched via Docker or Incus

The file should describe desired workspace intent, not a raw cloud environment create request.

This design keeps a single preset schema while preserving honest lifecycle semantics:

- cloud environments are durable managed objects with `create`, `start`, `stop`, `pause`, and `rm`
- local environments are local runtime instances with their own state and lifecycle

The CLI should not force both models behind one misleading verb like `up`.

## Terminology

### User-facing term: `preset`

The product should standardize on `preset` for all user-facing concepts:

- `codewire.yaml` defines a preset
- `cw preset ...` manages reusable presets
- `cw preset init` authors a preset document
- `cw env create --preset ...` launches a cloud environment from a preset
- `cw local create --preset ...` launches a local environment from a preset

### Internal-only term: `template`

The term `template` should remain only as an internal implementation detail where needed, especially in the agent-sandbox platform layer.

It should not appear in:

- top-level CLI commands
- CLI flags
- user-visible config schema
- user-visible API docs

## Problem

Today the current model is split across two incompatible surfaces:

- `cw env create` consumes `codewire.yaml`, but the current file shape is biased toward cloud environment creation
- `cw env create` cannot yet cleanly turn interactive create inputs into a reusable preset document
- the standalone `sandbox` tool launches local Incus containers with repo mounts and backend-specific behavior

That produces several problems:

- there is no single canonical workspace definition for local and cloud
- the current schema mixes portable workspace intent with cloud-only concepts
- local lifecycle and cloud lifecycle are not represented consistently
- the `sandbox` tool duplicates product surface outside the main CLI
- the existing `template` naming no longer matches product language

## Goals

- Make `codewire.yaml` the canonical user-facing preset file
- Use the same preset file for cloud and local launches
- Let `cw env create` synthesize a preset when users create from flags
- Replace user-facing `template` terminology with `preset`
- Fold local Docker and Incus support into `cw`
- Retire the standalone `sandbox` tool
- Keep lifecycle semantics explicit and correct
- Preserve a migration path from the current CLI and config model

## Non-Goals

- Perfectly identical local and cloud runtime behavior
- A single verb that fully hides the difference between create and start
- Exposing every Docker or Incus tuning knob in the portable preset core
- Eliminating all backend-specific configuration

## Design Principles

### One preset file, multiple runtime adapters

There should be one shared user-facing preset schema. Codewire then resolves that preset onto one of several runtime backends:

- cloud
- docker
- incus

The preset defines what the workspace should look like. The runtime adapter decides how to realize it.

Preset authoring and preset consumption are separate concerns:

- authoring turns repo inspection or direct flags into a preset document
- consumption launches a cloud or local runtime from that preset document

The CLI may combine both flows in one command when explicitly requested, but the conceptual model should stay split.

### Portable core, backend-specific edges

The preset should have a portable core for cross-backend intent:

- source repo/workdir
- image
- install steps
- startup steps
- environment variables
- ports
- resource hints
- agent defaults

Backend-specific fields are allowed, but must live in backend-specific sections.

### Honest lifecycle semantics

Cloud environments and local runtime instances should not be collapsed into one fake universal verb.

In particular:

- `create` means allocate a new object
- `start` means start an existing object
- `stop` means stop an existing object
- `pause` means suspend an existing object when supported
- `rm` means destroy an existing object

This matters because `up` usually conflates create and start, which is not correct for Codewire-managed environment objects.

## Proposed Preset Model

### File name

The canonical project-local preset file remains:

- `codewire.yaml`

This avoids inventing another file name and preserves the current entry point.

### Shape

The file itself is the preset. There should not be a top-level `preset:` field.

Example:

```yaml
apiVersion: codewire.sh/v1alpha1
kind: Preset

name: fullstack-dev
description: Full-stack application development workspace

source:
  repos:
    - url: .
      path: /workspace
  workdir: /workspace

workspace:
  image: ghcr.io/codewiresh/full:latest

  install:
    - pnpm install

  startup:
    - pnpm dev

  env:
    NODE_ENV: development
    API_URL: http://localhost:8080

  ports:
    - port: 3000
      name: web
      protocol: http
    - port: 8080
      name: api
      protocol: http

  resources:
    cpu: 2000m
    memory: 4Gi
    disk: 20Gi

  features:
    nestedContainers: false

agent:
  profile: codex
  installCodewire: true

backends:
  cloud:
    secrets:
      project: my-project
      includeOrg: true
      includeUser: true

  docker:
    mounts:
      - source: ~/.gitconfig
        target: /home/agent/.gitconfig
        readOnly: true

  incus:
    mounts:
      - source: ~/.ssh
        target: /home/agent/.ssh
        readOnly: true
```

### Explicit `v1alpha1` field inventory

The initial structured schema should stay small and opinionated.

Top-level fields:

- `apiVersion`
- `kind`
- `name`
- `description`
- `source`
- `workspace`
- `agent`
- `backends`

`source` fields:

- `repos`
- `workdir`

`source.repos[]` fields:

- `url`
- `branch`
- `path`

`workspace` fields:

- `image`
- `install`
- `startup`
- `env`
- `ports`
- `resources`
- `features`

`workspace.ports[]` fields:

- `port`
- `name`
- `protocol`

`workspace.resources` fields:

- `cpu`
- `memory`
- `disk`

`workspace.features` fields:

- `nestedContainers`

`agent` fields:

- `profile`
- `installCodewire`
- `env`

`backends.cloud` fields:

- `secrets`
- `network`

`backends.cloud.secrets` fields:

- `project`
- `includeOrg`
- `includeUser`

`backends.docker` fields:

- `mounts`
- `env`
- `network`

`backends.incus` fields:

- `mounts`
- `env`
- `extraProfiles`

`backends.<runtime>.mounts[]` fields:

- `source`
- `target`
- `readOnly`

This is intentionally narrower than the full space of runtime capabilities.

### Schema conventions

Conventions for the structured schema:

- use camelCase for structured fields to match current Go and JSON conventions
- use arrays for ordered command sequences such as `install` and `startup`
- keep values declarative rather than shell-specific wherever possible
- treat missing fields as "adapter default" rather than introducing many booleans

The existing legacy top-level schema remains accepted during migration, but new docs and examples should use the structured form.

### Portable core

These fields are intended to be portable across backends:

- `name`
- `description`
- `source`
- `workspace.image`
- `workspace.install`
- `workspace.startup`
- `workspace.env`
- `workspace.ports`
- `workspace.resources`
- `workspace.features`
- `agent`

### Backend-specific sections

Backend-specific sections are allowed for runtime-specific behavior:

- `backends.cloud`
- `backends.docker`
- `backends.incus`

These sections should be optional and narrow in scope.

They should exist for:

- secret binding
- local mount configuration
- local networking quirks
- runtime-specific escape hatches

They should not be the primary way most projects describe their workspace.

### What adapters are expected to normalize

Runtime adapters should absorb backend differences rather than pushing them into preset authorship.

Examples:

- path mapping differences between Docker and Incus
- host user and group handling
- default workspace root setup
- repo mount versus repo clone
- default shell and entrypoint behavior
- port publication mechanics
- whether Codewire is preinstalled or injected

The preset should express desired behavior, while adapters own most of the translation.

## What Does Not Belong in the Portable Core

The following concepts are backend-specific and should not remain as portable top-level fields:

- cloud preset slug or ID
- cloud secret project binding
- relay bootstrap configuration
- Docker-specific network mode
- Docker socket wiring
- Incus named profiles
- host-local backend object names

In particular, the preset schema should not expose a normal field like:

```yaml
backends:
  incus:
    profile: sandbox
```

This is too host-specific and makes repo config depend on local administrative state.

If advanced Incus profile support is ever needed, it should be an escape hatch such as:

- `backends.incus.extraProfiles`

and not the default model.

## Source Semantics

The same preset should work for local and cloud without pretending the mechanics are identical.

The key difference is source materialization:

- local backends usually mount the repo from the host
- cloud backends usually clone repos into the environment

The preset should describe desired source shape, while runtime adapters decide the mechanism.

Default behavior:

- `url: .` means use the current project
- local Docker or Incus adapters mount the repo into the target
- cloud adapters resolve the local repo to a remote clone source when possible

If the source cannot be resolved for a cloud launch, the CLI should fail clearly rather than silently guessing.

### Cloud source resolution rules

For `cw env create`, source resolution should be predictable:

- if `source.repos[].url` is a remote URL, use it directly
- if `source.repos[].url` is `.`, try to detect the git remote for the current repo
- if the current repo has no usable remote, fail with a clear error
- do not silently upload the working tree in v1

This keeps the first version simple and avoids hidden transport behavior.

## CLI Model

### Cloud lifecycle

Cloud environments remain first-class managed objects:

- `cw env create`
- `cw env start`
- `cw env stop`
- `cw env pause`
- `cw env rm`
- `cw env list`
- `cw env info`

These commands should consume the shared preset model where applicable.

Examples:

```bash
cw env create
cw env create --preset fullstack-dev
cw env create --file ./codewire.yaml
```

Recommended semantics:

- `cw env create` creates a new cloud environment object
- `cw env start` starts a stopped or paused environment
- `cw env stop` stops a running environment
- `cw env pause` pauses a running environment when supported
- `cw env rm` destroys the environment object

`cw env create` should support:

- `--preset <name>`
- `--file <path>`
- `--name <name>`
- direct authoring flags such as `--image`, `--install`, `--startup`, and `--env`

When direct authoring flags are used, `cw env create` should synthesize an in-memory preset and create the environment from that resolved preset.

Preset persistence should be explicit:

- `--write-preset` writes the resolved preset to `./codewire.yaml`
- `--save-preset <name>` stores the resolved preset on the server
- no preset file or server preset should be mutated implicitly as a side effect of environment creation

This keeps environment creation and preset management conceptually separate while still making `cw env create` a convenient entry point.

### Preset authoring

Preset authoring should also have a dedicated explicit CLI:

- `cw preset init`

Recommended semantics:

- infer from repo or accept direct flags
- write a canonical `codewire.yaml`
- optionally save to the server
- do not create an environment by default

Examples:

```bash
cw preset init
cw preset init --image full --install "pnpm install" --startup "pnpm dev"
cw preset init --save-preset fullstack-dev
cw env create --image full --write-preset
cw env create --preset fullstack-dev
cw env create --file ./codewire.yaml
```

### Local lifecycle

Local runtime instances should become a first-class CLI surface:

- `cw local create`
- `cw local start`
- `cw local stop`
- `cw local rm`
- `cw local list`
- `cw local info`

Examples:

```bash
cw local create --backend docker
cw local create --backend incus
cw local start
cw local stop
cw local rm
```

`cw local create` reads the shared preset and creates a new local instance.

`cw local start` starts an existing local instance from local state. It should not silently create a new one.

Recommended semantics:

- `cw local create` creates a new local runtime instance and records it in local state
- `cw local start` starts an existing local instance
- `cw local stop` stops an existing local instance
- `cw local rm` deletes the local instance and removes its state
- `cw local list` shows local instances without requiring backend-specific tools directly
- `cw local info` shows resolved preset, backend, runtime object name, and state

`cw local create` should support:

- `--backend docker|incus`
- `--preset <name>`
- `--file <path>`
- `--name <name>`

If no backend is specified, the CLI may later choose a default from config, but v1 should prefer requiring `--backend` for explicitness.

### Target-aware day-2 workflow

After a target exists, the target-aware CLI becomes the main workflow:

- `cw use <target>`
- `cw current`
- `cw run -- ...`
- `cw exec -- ...`
- `cw ssh`

This matches the direction already described in `2026-03-22-target-aware-cli.md`.

### Target naming

The CLI should distinguish target kinds explicitly in stored state, while keeping user input short.

Proposed target kinds:

- `local`
- `env`

Proposed user-facing target forms:

- `local` for the default local node target
- local runtime instance name for `cw local` instances
- environment name, short ID, or full ID for cloud environments

Persisted target references should remain explicit:

- local runtime target: `kind=local`, `ref=<local-instance-id>`
- cloud environment target: `kind=env`, `ref=<environment-id>`

This keeps the target model compatible with the current direction while allowing local runtime instances to become first-class targets.

### Relationship to `cw run`

The design should preserve the existing capability distinction:

- local node targets support full `cw run` session semantics
- cloud environments without a Codewire node support `cw exec` and `cw ssh`
- local Docker or Incus runtime instances may initially support `cw ssh` and `cw exec` before they support native `cw run`

The CLI should surface capability differences honestly rather than pretending every target supports every command.

## Preset Resolution

Commands that create environments should resolve presets in this order:

1. explicit `--file`
2. explicit `--preset`
3. synthesized in-memory preset from direct authoring flags
4. `./codewire.yaml`
5. error

This keeps the project-local preset as the default without blocking reusable named presets.

## Preset Storage

Reusable presets should exist at three scopes:

- project-local preset: `./codewire.yaml`
- user presets: `~/.codewire/presets/<name>.yaml`
- org presets: stored server-side and managed through Codewire

The project-local file is the default source of truth for repo-specific workspace intent.

Authoring commands should make scope explicit:

- `cw preset init` writes a project preset by default
- `cw preset push` uploads a local preset to the server
- `cw env create --save-preset <name>` creates an environment and saves the resolved preset to the server

Environment creation output should show which preset source was used:

- `preset: ./codewire.yaml`
- `preset: local/fullstack-dev`
- `preset: org/fullstack-dev`
- `preset: synthesized (not saved)`

## Local State Storage

Local runtime instances need state separate from presets.

Presets answer:

- what should be created

Local state answers:

- what already exists

Suggested local state storage:

- `~/.codewire/config.toml` for current target and global settings
- `~/.codewire/local-instances.toml` or equivalent store for local runtime instances

Each local instance should store at least:

- instance name
- backend (`docker` or `incus`)
- repo path
- resolved image
- runtime object ID or name
- creation time
- current lifecycle state

Optional but useful additional fields:

- source repo fingerprint or canonical repo root
- resolved workdir
- published ports
- adapter metadata needed for reconnect or exec
- whether Codewire is installed in the instance

This allows `cw local start` to operate on an existing instance rather than reconstructing identity from `codewire.yaml`.

### Repo association

The local state model should associate a repo with a default local instance when possible.

Default lookup order for `cw local start`:

1. explicit local instance name or ID
2. repo-associated local instance for the current directory
3. current selected target if it is a local runtime instance
4. error

This lets `cw local start` feel convenient without smuggling creation behavior into `start`.

## Migration from Current `codewire.yaml`

Current fields map approximately as follows:

- `preset` remains `preset`
- `install` becomes `workspace.install`
- `startup` becomes `workspace.startup`
- `env` becomes `workspace.env`
- `ports` becomes `workspace.ports`
- `cpu` becomes `workspace.resources.cpu`
- `memory` becomes `workspace.resources.memory`
- `disk` becomes `workspace.resources.disk`
- `secrets` becomes `backends.cloud.secrets.project`
- `include_org_secrets` becomes `backends.cloud.secrets.includeOrg`
- `include_user_secrets` becomes `backends.cloud.secrets.includeUser`
- `agent` remains under `agent`

For migration compatibility, the CLI should initially support both:

- legacy top-level fields
- new structured preset schema

The CLI can warn when deprecated legacy structured fields are used during development, but the shipped surface should be `preset`-only.

### Legacy parser behavior

During migration, the parser should:

- accept current flat fields without `apiVersion` and `kind`
- accept new structured fields with `apiVersion: codewire.sh/v1alpha1` and `kind: Preset`
- reject mixed conflicting definitions when both legacy and structured fields are set incompatibly
- prefer explicit structured fields when both are present and equivalent

This keeps migration safe and predictable.

## Command and Naming Migration

### Rename user-facing `template` surface to `preset`

The following user-facing names should be renamed:

- `cw template ...` to `cw preset ...`
- `--template` to `--preset`
- `--template-id` to `--preset-id`

User-facing request and response models should use:

- `preset_id`
- `preset_slug`

Internal platform code may continue to translate presets into sandbox templates or related internal objects.

### Server presets and local presets

Server presets and local `codewire.yaml` presets should be the same user concept and the same schema family.

The difference is storage scope, not meaning:

- project preset: stored in the repo as `codewire.yaml`
- user preset: stored locally under `~/.codewire/presets/`
- org preset: stored on the Codewire server

The server may wrap presets with metadata such as:

- `id`
- `org_id`
- `created_at`
- `updated_at`

But the underlying preset payload should stay aligned with the local preset model.

The CLI should make preset scope visible in output so users can tell whether a launch came from:

- `./codewire.yaml`
- a local named preset
- an org preset stored on the server

## Retiring the Standalone `sandbox` Tool

The standalone `sandbox` tool should be removed once the CLI provides equivalent local lifecycle support.

The replacement should cover:

- create local Incus or Docker instances from `codewire.yaml`
- bind mount the repo into the instance
- support additional local mounts
- enter or exec into the running instance
- stop and delete instances

Not every `sandbox` behavior must be reproduced 1:1 on day one, but the CLI should cover the primary development loop before removal.

### Functional parity target

Before removing `sandbox`, `cw local` should cover at least:

- create a new instance from the current repo
- attach repo mounts
- add extra bind mounts
- exec a shell or command into the instance
- list running and stopped instances
- stop and remove instances by name

Detached arbitrary command execution can be added later if needed, but core lifecycle and shell access should exist first.

## Implementation Phases

### Phase 1: Terminology and schema direction

- rename user-facing CLI surface from `template` to `preset`
- document the new shared preset direction
- align `codewire.yaml`, CLI flags, and server environment APIs on `preset`

### Phase 2: Add structured preset parser

- support new `apiVersion` and `kind`
- support structured `workspace`, `source`, and `backends`
- preserve legacy compatibility

### Phase 2.5: Rename CLI and public types to `preset`

- add `cw preset ...` commands
- add `cw preset init`
- add `--preset` and `--preset-id` flags
- rename public client types and API payload fields to `preset`
- keep `template` only for Coder templates and internal sandbox-template implementation details

### Phase 3: Make preset authoring first-class

- let `cw env create` synthesize a preset from direct flags
- add `--write-preset`
- add `--save-preset`
- make create output show preset source and persistence behavior
- keep preset writes explicit rather than implicit

### Phase 4: Add local lifecycle to `cw`

- introduce `cw local create/start/stop/rm/list/info`
- add local state persistence
- implement Docker backend
- implement Incus backend

Recommended slice order:

- local state store
- Docker create/start/stop/rm/info/list
- local target integration
- Incus backend

### Phase 5: Unify target workflow

- allow `cw use` to target local runtime instances
- make `cw exec` and `cw ssh` work consistently across local and cloud targets
- keep `cw run` capability-aware

### Phase 6: Remove standalone `sandbox`

- migrate users to `cw local ...`
- remove the standalone script and install path

## Open Questions

- Should local runtime instances be repo-scoped by default, or globally named?
- Should `cw local create` default to one instance per repo, or allow multiple named instances by default?
- Should Docker and Incus adapters share one common mount model, or should runtime-specific mount features stay separate?
- How should cloud launches resolve local `url: .` sources when the repo has no usable remote?
- Should org presets be materialized locally on first use, or always fetched from the server?
- Should `cw env create --save-preset` require an explicit slug/name separate from the environment name?
- Should `cw preset init` default to repo inference only when a git remote exists, or also allow purely local repos?

## Default Recommendations

Unless later implementation proves otherwise, the default choices should be:

- one shared `codewire.yaml` per repo
- `cw preset init` as the explicit preset authoring path
- `cw env create` as a preset consumer that can optionally write or save the resolved preset
- one default local instance per repo unless the user explicitly names additional ones
- explicit `cw env ...` and `cw local ...` lifecycle commands rather than `cw up`
- `--backend` required for `cw local create` in v1
- no normal `incus.profile` field in the shared schema
- no implicit working-tree upload for cloud launches in v1
- honest command capability differences across target kinds

## Recommendation

Adopt one shared `codewire.yaml` preset schema, but do not force one shared lifecycle verb.

The clean product model is:

- one preset file
- `preset` everywhere user-facing
- `cw preset init` to author presets
- `cw env ...` for cloud environment lifecycle
- `cw local ...` for local Docker and Incus lifecycle
- `cw use`, `cw exec`, and `cw ssh` as the shared day-2 target workflow

This gives Codewire one coherent configuration model without flattening away the real differences between managed cloud environments and local runtime instances.
