# Codewire artifact planner

This directory classifies artifact impact for the packaged `cw` CLI, desktop
package, workspace `cw` binary, atomic base/workspace support-image pair, and
the dashboard, gateway, DERP, services, and mesh runtime images.
Verification capabilities are owned only by
`scripts/ci/select/select-verification.sh`; the planner never adds or removes
capability tokens. Runtime artifact facts remain independent of PR verification
selection. Until Dev consumes those facts through its event adapter,
`scripts/ci/select/select-deploy-dev.sh` is a temporary compatibility path.

Pull requests execute `planner.py` and `artifact-graph.json` from the trusted
target-base commit. Proposed policy may be tested but cannot reduce work. A
policy-path change makes every artifact `unclassified` under the trusted
policy. Artifact state is `affected`, `unaffected`, or `unclassified`, and
consumers schedule both `affected` and `unclassified`.

```sh
python3 scripts/ci/plan/planner.py \
  --repository . \
  --target-base gitea/main \
  --head HEAD
```

For canonical-main support publication, the support workflow resolves the
published base/workspace pair, removes registry credentials, and supplies the
untrusted metadata as `--baseline-candidate`. The planner accepts only a
matching immutable pair whose revision is an ancestor of the exact head.
`apply-support-plan.py` preserves pair atomicity: if either artifact is not
proven unaffected, both are selected.

`apply-verification-plan.py` validates the plan and emits only the three
artifact-job facts used by CI. `emit-verification-receipt.py` binds a successful
Required-verification job to its exact base, head, and tree. Post-merge reuse
validates that identity and falls back whenever receipt-control files changed.

Run the focused no-network tests and current-tree Cargo oracle with:

```sh
scripts/ci/plan/test.sh
```

The planner exports Git trees into isolated temporary directories, rejects
unsafe archive paths, symlinks, and candidate Cargo configuration, and invokes
only offline `cargo metadata --locked --no-deps`. It never executes candidate
build scripts or helpers.
