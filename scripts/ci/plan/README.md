# Codewire CI planner

This directory is the versioned impact-policy kernel for Codewire CI. It
classifies the packaged `cw` CLI, desktop, workspace binary, and atomic support
image inputs. Runtime image nodes remain `unclassified`, and existing workflow
selectors remain authoritative only for unmigrated artifacts.

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

Canonical-main support publication uses the same planner with
`--baseline-candidate`. The support workflow resolves untrusted `base:latest`
and `workspace:latest` registry metadata through its existing credential
boundary, then removes the credential before planning. The planner validates
that both repositories, immutable digests, and revision labels form one
matching Git ancestor and emits `codewire.ci-baseline/v1` in
`published_support_pair` mode. Missing, malformed, mismatched, inaccessible,
or non-ancestor candidates make every artifact `unclassified`.

`apply-support-plan.py` is the support event adapter. It owns only the atomic
pair policy: publish both support images when either planner artifact is
`affected` or `unclassified`; skip only when both are `unaffected`. It does not
inspect source paths or dependency graphs.

`apply-verification-plan.py` is the event adapter. It validates the trusted
plan, removes the legacy desktop-package decision, and adds that decision back
from the canonical artifact fact. Every other legacy selection token remains
authoritative until its artifact migrates, so PRs execute that selector from
the same exact target-base checkout and include it in the policy hash.
`emit-verification-receipt.py`
serializes the successful required-job inputs into one canonical base64 log
record. The post-merge receipt validator attests that record; it never repeats
change-impact classification.

Run the focused no-network tests and the current-repository Cargo oracle with:

```sh
scripts/ci/plan/test.sh
```

The planner exports candidate Git trees to isolated temporary directories,
validates archive paths and symlinks, rejects Cargo configuration supplied by
the candidate, and invokes only offline `cargo metadata --locked --no-deps`.
It never executes build scripts or source helpers.
