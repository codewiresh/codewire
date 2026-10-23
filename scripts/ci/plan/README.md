# Codewire artifact planner

This directory classifies artifact impact for the packaged `cw` CLI, desktop
package, workspace `cw` binary and content verification, atomic base/workspace
support-image pair, and the dashboard, daemon, DERP, services, and mesh runtime
images.
Verification capabilities are owned only by
`scripts/ci/select/select-verification.sh`; the planner never adds or removes
capability tokens. Runtime artifact facts remain independent of PR verification
selection and Dev consumes those facts through its event adapter.

Pull requests execute `planner.py` and `artifact-graph.json` from the trusted
target-base commit. Proposed policy may be tested but cannot reduce work. A
policy-path change makes every artifact `unclassified` under the trusted
policy. Artifact state is `affected`, `unaffected`, or `unclassified`, and
consumers schedule both `affected` and `unclassified`.

A push to `main` runs `plan-main-push.py` from the previous main commit's
checkout, so it plans with that commit's policy exactly as a pull request
plans with its base's. It plans against the previous main commit only when
main CI's verdict verified that commit (`main-ci-verdict.py`, the predicate
Dev delivery also uses): its own `ci.yaml` push run on `main` printed the
verdict marker in Required verification, after every selected capability
group succeeded or an exact tested-tree receipt was accepted. A superseded run
prints no marker and a failed run proved nothing, so after either, a pending
or missing run, and for a dispatch, a force push, an unavailable Forgejo API
or any planner failure, every artifact stays selected
(`apply-verification-plan.py --unclassified`), as it did for every push before.

A Rust package compiles only from its crates and the files the graph lists.
`scripts/`, `.githooks/` and the other unrelated roots are never its unknown
inputs: a script is an input only of the artifacts that list it, and the
tests fail when a crate embeds a script or an image build driver runs a helper
its images do not list.

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
proven unaffected, both are selected. Support and Dev planning execute the
exact canonical head's reviewed policy, so a policy path in the range never
makes an artifact unclassified there, alone or beside other changes; the
artifact fingerprints decide.

The workspace image also depends on the complete Dev release selection: the
release tree, the Dev acceptance harness, all five runtime images, and the
confidential-workspace acceptance contract. Every source selected for Dev
therefore publishes an exact-source workspace image even when the `cw` binary
is unchanged. A source
that does not select Dev and does not affect the support pair remains
skippable. File-set and composite inputs are explicit ownership rules, so they
do not make unrelated Rust artifacts unclassified.

PR workspace content qualification uses the separate
`workspace_image_verification` artifact. It depends on the base image and the
workspace `cw` binary, and binds workspace image files, the root Docker ignore
file and raw Cargo manifest, and the verifier, local image helpers, agent
contract and their assertions. The read-only root build-context mount is used
by Cargo; the resulting `cw` binary is the only source-built output copied
into the final image. Reachable Rust fingerprints include embedded policy and
private protobuf inputs. Unknown files inside a reachable package remain
unclassified even when a runtime image also owns `crates/**`.

This split does not change capability selection or exact-source publication.
Selected Kind runs the published workspace pin unless the change alters the
image definition (`images/base`, `images/workspace`); then it builds and
verifies its workspace image and consumes the exact local image receipt. CI
builds no other exact-source workspace image (#3119 A12): support-images runs
the workspace contract on the exact image it publishes from main. The receipt
retains its contract, architecture and
immutable image bindings. A local receipt also covers a later tree when this
planner shows `workspace_image_verification` unchanged from the receipt's
commit. Only standalone workspace
verification can be omitted by the narrower artifact fact. An unaffected fact
means the checked-in build and contract inputs are unchanged; floating tool
channels can still resolve differently on the next actual image build.

`apply-verification-plan.py` validates the plan and emits only the three
artifact-job facts used by CI. Its established `workspace_image_state` and
`workspace_image_selected` outputs now describe `workspace_image_verification`;
the support adapter continues to consume `workspace_image`. A missing new
artifact is an error, never an implicit unaffected result. PRs on older trusted
bases continue executing that base's broader planner and adapter. Policy edits
cannot reduce their own PR work and invalidate post-merge tested-tree reuse.
No planner artifact fact adds a local capability gate or creates local proof.

`emit-verification-receipt.py` binds a successful
Required-verification job to its exact base, head, and tree. Post-merge reuse
validates that identity and falls back whenever receipt-control files changed.

## Decision regression corpus

`decision-corpus.json` is a versioned, deterministic snapshot of representative
trusted-selector decisions. It records only event/path inputs and the selector
contract they currently produce: classification, capability tokens, and the
required local mode. It deliberately does not select artifact jobs, describe
runtime facts, validate receipts, or authorize a reduction in verification.
Its crate cases classify against a workspace without crate edges, so they
record path rules alone; the selector fixture suite proves the crate graph.
The edgeless Cargo stub lives under the checkout's `.tmp`, and each case first
proves that the `cargo` on the selector's `PATH` is that stub. A stub that
cannot run fails the check, so the corpus never reads the live crate graph.

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
runtime image, the Dev release tree, or the Dev acceptance harness is `affected`
or `unclassified`; it skips only when all of them are `unaffected`. promote-dev
runs acceptance only from the exact promoted source, so a harness-only change
(`dev_acceptance_affected`) is accepted only by promoting that source. The
adapter does not inspect source paths, resolve external state, publish images,
or authorize deployment.

Run the focused no-network tests and current-tree Cargo oracle with:

```sh
scripts/ci/plan/test.sh
```

The planner exports Git trees into isolated temporary directories, rejects
unsafe archive paths, symlinks, and candidate Cargo configuration, and invokes
only offline `cargo metadata --locked --no-deps`. It never executes candidate
build scripts or helpers.
