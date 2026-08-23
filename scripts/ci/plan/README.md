# Codewire artifact planner

This directory classifies artifact impact for the packaged `cw` CLI, desktop
package, workspace `cw` binary, atomic base/workspace support-image pair, and
the dashboard, gateway, DERP, services, and mesh runtime images.
Verification capabilities are owned only by
`scripts/ci/select/select-verification.sh`; the planner never adds or removes
capability tokens. Runtime artifact facts remain independent of PR verification
selection and Dev consumes those facts through its event adapter.

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

The workspace image also depends on the complete Dev release selection: the
release tree, all five runtime images, and the confidential-workspace
acceptance contract. Every source selected for Dev therefore publishes an
exact-source workspace image even when the `cw` binary is unchanged. A source
that does not select Dev and does not affect the support pair remains
skippable. File-set and composite inputs are explicit ownership rules, so they
do not make unrelated Rust artifacts unclassified.

`apply-verification-plan.py` validates the plan and emits only the three
artifact-job facts used by CI. `emit-verification-receipt.py` binds a successful
Required-verification job to its exact base, head, and tree. Post-merge reuse
validates that identity and falls back whenever receipt-control files changed.

## Decision regression corpus

`decision-corpus.json` is a versioned, deterministic snapshot of representative
trusted-selector decisions. It records only event/path inputs and the selector
contract they currently produce: classification, capability tokens, and the
required local mode. It deliberately does not select artifact jobs, describe
runtime facts, validate receipts, or authorize a reduction in verification.

Run its standard-library-only check directly with:

```sh
python3 scripts/ci/plan/tests/test_decision_corpus.py
```

The selector contract test runs the same check. A future decision graph may use
the corpus as a shadow-mode regression oracle, but trusted-base policy must
still decide PR work and unknown inputs must continue to fail closed.

Canonical-main Dev deployment uses `--deployed-source-candidate`. The deploy
workflow resolves an untrusted release document through its existing private
credential boundary. The candidate binds that retrieval to the exact workflow
head, then the credential-free planner validates the release identity, source
repository, Git object, and ancestry before emitting a `deployed_source`
baseline. A missing, malformed, stale-head, absent-history, or non-ancestor
candidate makes every artifact `unclassified`.

`apply-deploy-plan.py` owns only the existing atomic runtime policy. It selects
the complete five-image build, publication, and exact-source dispatch when any
runtime image is `affected` or `unclassified`; it skips only when all five are
`unaffected`. The adapter does not inspect source paths, resolve external
state, publish images, or authorize deployment.

Run the focused no-network tests and current-tree Cargo oracle with:

```sh
scripts/ci/plan/test.sh
```

The planner exports Git trees into isolated temporary directories, rejects
unsafe archive paths, symlinks, and candidate Cargo configuration, and invokes
only offline `cargo metadata --locked --no-deps`. It never executes candidate
build scripts or helpers.
