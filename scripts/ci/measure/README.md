# CI measurement

`forgejo-ci-start-latency` reads Codewire's main-push Actions records from
Forgejo and reports how long each Heavy, protected, sized or Lite job waited
from becoming eligible to its first command. It is read-only: GET requests to
fixed API paths, and it prints no token, response body or log line. The
dispatch-only `CI start latency` workflow
(`.gitea/workflows/ci-start-latency.yaml`) runs its `collect` and `summary`
commands with the job's own token and uploads the rows and summary. It also
prints the rows in a `rows.jsonl` log group, so `fj actions runs logs` can read
them for the placement join without a token for the artifact API.

The collector is vendored from the infrastructure repository (`infra`), which
keeps its tests, its placement join and its runbook:

| | |
|---|---|
| Source path | `tools/forgejo/commands/forgejo-ci-start-latency` |
| Source commit | `63fa55f481d494a0bee8081c3702bd8ce20fa2e2` |
| Source sha256 | `ea24bae8ed934205da6ebcdb923b5a09dc71deb69cf559b05402107488e9ed9f` |
| Vendored sha256 | `2bf6c18846317e670c875be1e0a304f4ae7a3dd668e6ffa75de3d12997856048` |

The copy differs from the source in two lines: `REPOSITORIES` and the `REPO`
path pattern allow only `codewire/codewire`. The source also allows the
infrastructure repository, whose name stays out of this tree; a Codewire job
token cannot read it in any case. Everything else, including the entrypoint
path shim at the top, is byte for byte the source.

`forgejo-ci-start-latency.sha256` records the vendored sha256. The workflow
checks it before collecting, and `scripts/ci/tests/test-select-verification.sh`
checks it in policy. To update the copy, take the new source commit, make the
same two-line change, and update this table and the checksum file together.
