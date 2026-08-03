# Codewire CI planner

This directory is the versioned impact-policy kernel for Codewire CI. In its
first migration slice it classifies the packaged `cw` CLI and desktop
artifacts. Image nodes deliberately remain `unclassified`, and the existing
workflow selectors remain authoritative.

For a pull request, the workflow must execute the copy of `planner.py`, the
graph, and schemas from the trusted target-base commit. The proposed-head copy
may be tested, but it must never be allowed to reduce work. A policy-path
change makes every artifact `unclassified` under the old policy.

Run it locally with:

```sh
python3 scripts/ci/plan/planner.py \
  --repository . \
  --target-base gitea/main \
  --head HEAD
```

The output is `codewire.ci-plan/v1`. Artifact state is exactly `affected`,
`unaffected`, or `unclassified`; consumers must schedule `affected` and
`unclassified`. The planner reports impact facts only. It does not authorize
publication or deployment.

Run the focused no-network tests and the current-repository Cargo oracle with:

```sh
scripts/ci/plan/test.sh
```

The planner exports candidate Git trees to isolated temporary directories,
validates archive paths and symlinks, rejects Cargo configuration supplied by
the candidate, and invokes only offline `cargo metadata --locked --no-deps`.
It never executes build scripts or source helpers.
