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
| Vendored sha256 | `a3c7d3a771afb995e051fcaa52ed486ad4a452567b02f1582566e707ccea9985` |

The copy differs from the source in two ways. `REPOSITORIES` and the `REPO`
path pattern allow only `codewire/codewire`; the source also allows the
infrastructure repository, whose name stays out of this tree, and a Codewire
job token cannot read it in any case. And the API root comes from
`GITHUB_SERVER_URL`, which Forgejo sets in every job (`api_base`), instead of a
fixed host. Everything else, including the entrypoint path shim at the top, is
byte for byte the source.

`forgejo-ci-start-latency.sha256` records the vendored sha256. The workflow
checks it before collecting, and `scripts/ci/tests/test-select-verification.sh`
checks it in policy. To update the copy, take the new source commit, make the
same changes, and update this table and the checksum file together.

## CI done measures (#3144)

`ci-done-measures` computes the CI Program's "Done when" measures (#3144) over
one window of this repository's retained Actions records. It is not vendored;
its tests are `scripts/ci/tests/test-ci-done-measures.py`. Like the start-latency
collector, it is read-only: GET requests to fixed API paths, and it prints no
token or event payload. The dispatch-only `CI done measures` workflow
(`.gitea/workflows/ci-done-measures.yaml`) runs it with the job's own token
against the job's full checkout. It posts the summary to the step summary and
the log, and uploads the rows and the summary.

For the measurement week, dispatch it with `since=2026-10-31T00:00:00Z` and
`until=2026-11-07T00:00:00Z`. A window may be dispatched earlier to see
progress.

| Measure (#3144) | How it is read | Must hold |
|---|---|---|
| Ordinary PR speed | Per PR head pushed in the window, without `ci-full` on the push: from the push's first run to the last required check finishing (default `ci.yaml:Required verification` and `source-approval.yml:Supply-chain scan`). Only push-started runs count; labeled, unlabeled and closed runs never set a head. Superseded and unfinished heads are counted apart. | p50 ≤ 5 min, p95 ≤ 10 min |
| `ci-full` PR speed | The same, for heads whose push carried `ci-full` | reported, not counted |
| Main CI speed | Each main-push `ci.yaml` run that ran its verification (verified or failed), from creation to stop | p50 ≤ 10 min |
| Merge to Dev | From each push to main to the first passing Dev smoke receipt whose deployed source contains it | p50 ≤ 15 min |
| Main CI first attempt | Of the main-push `ci.yaml` runs that ran their verification, those verified with every job on its first attempt. Skipped, superseded and unverified runs are excluded and counted apart. | ≥ 95% |
| Dev smoke | Deploy-owned smoke results of the Dev deployment smoke receipts created in the window | ≥ 95% |

A main run's category comes from its own verdict: the marker its Required
verification job prints, which `scripts/ci/plan/main-ci-verdict.py` also reads
(#3176).
- **verified:** the marker names exactly this run and commit.
- **superseded:** the run was cancelled, or its Required verification says a
  newer commit's run verifies its change. It dispatched nothing, so it has no
  seconds.
- **failed:** Required verification did not pass.
- **unverified:** the job printed no verdict, or a marker for another run.

Receipts and checks that finish up to 24 hours after the window still settle
what the window started; receipts created after it are not counted as smoke
results. Percentiles are nearest-rank. A measure with no samples reports
`holds: null`, not a pass.
