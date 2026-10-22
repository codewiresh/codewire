# CI configuration

The workflows, CI scripts and their tests name no site. Every forge,
registry and storage location comes from configuration. A site that runs
Codewire's CI on its own Forgejo sets the values below once; nothing in the
tree changes.

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

- **Forge URL.** Forgejo gives every job its own base URL as
  `${{ github.server_url }}` and the `GITHUB_SERVER_URL` environment variable.
  Scripts build API, clone and OIDC URLs from it, so there is nothing to set.

## Repository Actions variables

Set these as repository (or organization) Actions variables. The workflows
pass each to their jobs under the same name. They are configuration, not
secrets; credentials come from OpenBao.

| Variable | Value | Used by |
|---|---|---|
| `CODEWIRE_IMAGE_REGISTRY` | Image registry host, with no scheme, for example `registry.example.com` | image build, publish, sign and verify scripts; Kind's approved images; Production publication |
| `CODEWIRE_R2_CACHE_ENDPOINT` | `https://` S3 endpoint of the CI compiler and layer cache buckets | sccache and workspace layer cache selection |
| `CODEWIRE_R2_RELEASES_ENDPOINT` | `https://` S3 endpoint of the `cw` release bucket | `cw` release publication (`cli-release.yaml`) |
| `CODEWIRE_OPENBAO_ADDR` | OpenBao base URL | every OpenBao credential fetch |
| `CODEWIRE_FORGEJO_INTERNAL_URL` | Internal Forgejo URL that runners register against, if it differs from the public one | release tag and receipt checks |
| `ARM64_BUILDKIT_HOST` | Host of the native arm64 BuildKit builder | arm64 image builds |
| `CONFIDENTIAL_SNP_NODE` | Dev node that runs confidential (SNP) Sandboxes | confidential smoke |
| `EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE` | Transport zone the Dev tailnet direct-UDP check expects | Dev transport smoke |
| `MIRROR_PRIVATE_CONTENT_PATTERNS` | Newline-separated patterns the public-mirror content scan refuses | `source-approval.yml`, `mirror-github.yaml` |
| `CODEWIRE_WARM_CACHE_EPOCH` | Optional; changing it starts a new warm Rust cache | warm cache selection |
| `CODEWIRE_IN_JOB_BUILD_SHA` | Optional; a commit whose image builds run in the job instead of trusted BuildKit | image build recovery |

A script that needs one of these and does not get it stops with an error that
names the variable. It never falls back to a built-in site.

## Local runs

Scripts read the same names outside CI. Put them in `~/.config/codewire/env`
(or an untracked `.envrc`; see `.envrc.example`). Outside CI, set
`GITHUB_SERVER_URL` to the Forgejo base URL for anything that builds Forgejo
URLs: a release tag push's receipt check (without it the push falls back to
full local verification), the CI measures, and the local VM journeys that
clone a Forgejo-hosted source. Kind's sealed CI inputs need
`CODEWIRE_IMAGE_REGISTRY`; a local Kind loop that builds its own images does
not.

## Tests

Tests use the reserved names `git.example.invalid`, `registry.example.invalid`
and other `*.example.invalid` endpoints, so they pass anywhere.
