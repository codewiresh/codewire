# CI configuration

The workflows, CI scripts and their tests name no site. Every forge,
registry and storage location comes from configuration. A site that runs
Codewire's CI on its own Forgejo sets the values below once; nothing in the
tree changes.

What a deployment itself configures, such as the registries its runtime
images come from, is in the [configuration reference](../CONFIGURATION.md).

## Forgejo server

- **Action resolution.** Workflows refer to actions by short references such
  as `noel/actions-checkout@<full SHA>`. Forgejo resolves a short reference
  against `[actions] DEFAULT_ACTIONS_URL`. Set it to `self`, so the reference
  resolves on your own instance:

  ```ini
  [actions]
  DEFAULT_ACTIONS_URL = self
  ```

- **Action mirrors.** Mirror each action the workflows use into a public,
  Actions-disabled repository under the `noel` owner on your instance, keeping
  at least the pinned commit: `actions-checkout`, `actions-upload-artifact`,
  `actions-download-artifact`, `setup-bun` and `setup-node`. The exact commits
  are the `uses:` lines in `.gitea/workflows/`.

- **Forge URL.** Forgejo gives every job the base URL its runner reaches it
  by, as `${{ github.server_url }}` and the `GITHUB_SERVER_URL` environment
  variable. Scripts call the API through it. A runner may use an internal
  name, so nothing that is published (image provenance, release checks) takes
  the forge from it: those use `CODEWIRE_SOURCE_URL` below.

## Repository Actions variables

Set these as repository (or organization) Actions variables. The workflows
pass each to their jobs under the same name. They are configuration, not
secrets; credentials come from OpenBao.

| Variable | Value | Used by |
|---|---|---|
| `CODEWIRE_SOURCE_URL` | Canonical public clone URL of this repository, for example `https://forgejo.example.com/codewire/codewire.git` | image provenance (`vcs.source`), which deployment verifies; the release tag's canonical-server check. Never an internal URL |
| `CODEWIRE_IMAGE_REGISTRY` | Image registry host, with no scheme, for example `registry.example.com` | image build, publish, sign and verify scripts; Kind's approved images; Production publication |
| `CODEWIRE_R2_CACHE_ENDPOINT` | `https://` S3 endpoint of the CI compiler and layer cache buckets | sccache and workspace layer cache selection |
| `CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED` | The one CI compiler and layer cache bucket. Main pushes read and write it; pull requests read it with a read-only token | the cache selectors and the protected image builds. With the endpoint set and this unset, they stop |
| `CODEWIRE_R2_RELEASES_ENDPOINT` | `https://` S3 endpoint of the `cw` release bucket | `cw` release publication (`cli-release.yaml`) |
| `CODEWIRE_OPENBAO_ADDR` | OpenBao base URL | every OpenBao credential fetch |
| `CODEWIRE_RELEASE_TAGGER` | Login of the Forgejo account whose registered GPG key signs release tags, exactly as Forgejo spells it | the release tag check in `deploy-prod.yaml` and `cli-release.yaml`: a tag counts only when Forgejo verifies it against a key on this account. Unset, every release is refused |
| `CODEWIRE_FORGEJO_INTERNAL_URL` | Internal Forgejo URL that runners register against, if it differs from the public one | release tag and receipt checks |
| `ARM64_BUILDKIT_HOST` | Host of the native arm64 BuildKit builder | arm64 image builds |
| `CONFIDENTIAL_SNP_NODE` | Dev node that runs confidential (SNP) Sandboxes | confidential smoke |
| `EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE` | Transport zone the Dev tailnet direct-UDP check expects | Dev transport smoke |
| `MIRROR_PRIVATE_CONTENT_PATTERNS` | Newline-separated patterns the public-mirror content scan refuses | `source-approval.yml`, `mirror-github.yaml` |
| `CODEWIRE_WARM_CACHE_EPOCH` | Optional; changing it starts a new warm Rust cache | warm cache selection |
| `CODEWIRE_IN_JOB_BUILD_SHA` | Optional; a commit whose image builds run in the job instead of trusted BuildKit | image build recovery |

A script that needs one of these and does not get it stops with an error that
names the variable. It never falls back to a built-in site.

### Runner labels

Every job's `runs-on` names a repository variable, never a label. Each
variable holds the label of the runner pool for one role. Jobs that differ
between a main push and every other run select the trusted variable on a main
push and the untrusted one otherwise.

| Variable | Role | Jobs |
|---|---|---|
| `CODEWIRE_CI_RUNNER_UNTRUSTED_LIGHT` | Credential-free light work | selection, aggregation, the Dev delivery trigger, source approval, measures |
| `CODEWIRE_CI_RUNNER_UNTRUSTED_HEAVY` | Heavy metal guests (13 GiB), for every run except a main push | `ci.yaml` Database verification, `test-archive-measure.yaml` |
| `CODEWIRE_CI_RUNNER_UNTRUSTED_MEDIUM` | Medium metal guests (6 GiB, Docker, a warm Rust cache, the archive store), for every run except a main push (infra#1534) | `ci.yaml` Policy, Standard, Tooling, the three Rust / transport groups and both service groups, Rust checks |
| `CODEWIRE_CI_RUNNER_UNTRUSTED_BUILD` | The pull request Rust build runner: one metal guest whose build disk keeps the build folder between jobs (infra#1632). It compiles once per run: it runs the build legs listed in `scripts/ci/setup/build-once.sh` and publishes each leg's test archive for the test jobs | `ci.yaml` Build test archives (every run except a main push), `build-runner-measure.yaml` |
| `CODEWIRE_CI_RUNNER_TRUSTED_HEAVY` | Heavy metal guests on a main push | Database verification on a main push |
| `CODEWIRE_CI_RUNNER_TRUSTED_MEDIUM` | Medium metal guests on a main push | the medium groups on a main push |
| `CODEWIRE_CI_RUNNER_TRUSTED_BUILD` | The main Rust build runner: the same as the pull request build runner, for a main push only. It builds in its own build folder (`/ci-cache/main`) and publishes to the main archive store, which only main's guests reach (infra#1632) | `ci.yaml` Build test archives on a main push |
| `CODEWIRE_CI_RUNNER_UNTRUSTED_KIND` | The Kind producers and Edge / Kind, for every run except a main push | `ci.yaml` Kind jobs |
| `CODEWIRE_CI_RUNNER_TRUSTED_KIND` | The same Kind jobs on a main push | `ci.yaml` Kind jobs on a main push |
| `CODEWIRE_CI_RUNNER_TRUSTED_LIGHT` | Protected publication, signing and release jobs, which hold OIDC roles and build on the trusted BuildKit builder | Dev and Production delivery, support images, release, mirror |
| `CODEWIRE_CI_RUNNER_MACOS` | Native macOS builds | the macOS `cw`, the VZ helper and the runtime pack |

A missing variable never selects another runner. The job waits on a label
named `unset-<variable>` that no runner advertises, so the queue shows which
variable to set. A main push never falls through to an untrusted runner.

## Local runs

Scripts read the same names outside CI. A workstation sets these in
`~/.config/codewire/env` (or an untracked `.envrc`; see `.envrc.example`):

```sh
export CODEWIRE_IMAGE_REGISTRY=registry.example.com
export GITHUB_SERVER_URL=https://forgejo.example.com
export CODEWIRE_FORGEJO_FIXTURE_REPOSITORY=example/supplychain
export CODEWIRE_CI_SCCACHE_BUCKET_UNTRUSTED=example-ci-cache-untrusted
```

- `CODEWIRE_CI_SCCACHE_BUCKET_UNTRUSTED` is the disposable cache bucket a
  local workspace build uses in `r2` mode without main or pull-request trust.
  CI never selects it, so it is not an Actions variable.

- `GITHUB_SERVER_URL` is the Forgejo base URL. The CI measures and the local
  VM journeys that clone a Forgejo-hosted source need it.
- `CODEWIRE_FORGEJO_FIXTURE_REPOSITORY` is the `owner/name` of that
  Forgejo-hosted source: a public repository on the same instance that holds
  the pinned commit the journeys check out. Mirror the public supply-chain
  scanner repository, `https://github.com/noeljackson/supplychain`, to get it.
  The Linux native smoke and the macOS local VM inputs journey need it.
- A release tag push needs no token. The pre-push hook checks only local facts:
  the tag is annotated and its signature verifies, it names a commit on the
  push remote's `main`, the workspace pin is current, and the support pair is
  published. Release selection in `deploy-prod` and `cli-release` reverifies
  the tag from main's code with the job's own token before anything is
  published.
- `CODEWIRE_IMAGE_REGISTRY` is needed by the Dev and confidential smokes and
  Kind's sealed CI inputs. A local Kind loop that builds its own images does
  not need it.
- `CODEWIRE_SOURCE_URL` is read only by the protected image builds and the
  release tag check, which run in CI.

## Tests

Tests use the reserved names `git.example.invalid`, `registry.example.invalid`
and other `*.example.invalid` endpoints, so they pass anywhere.
`python3 scripts/checks/repo_checks.py private-host-literals` (policy core)
refuses the live forge and registry host names and literal R2 account
endpoints everywhere except the Dev and Production deployment paths that move
to the deploy repository.
