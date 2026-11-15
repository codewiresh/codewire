# Fast sandbox starts

This journey proves that a cloud sandbox starts fast, the targets of Program
#2238 under `SPEC.md` "4. Hosted sandboxes": a create from a warm pool reaches
a usable terminal in seconds, almost no Production create misses the pool,
and the first start after a release pulls no image. A create's own behaviour
is in [cloud-sandbox.md](cloud-sandbox.md) `sandbox-create`; this file holds
only its speed. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-15.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `fast-pool-hit` | cw-fast-start | not yet observed | not yet observed |
| `fast-cold-share` | cw-fast-start | not applicable | not yet observed |
| `fast-first-start-after-release` | cw-fast-start | not yet observed | not yet observed |

## Before the walk

- Run creates as the environment's smoke identity:
  `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` on Dev, and
  `scripts/runtime/prod/with-prod-smoke-auth.sh -- COMMAND` on Production,
  which may create, inspect and remove only its own sandboxes.
- Orchestration's metrics are read through the API server's service proxy
  with the infrastructure repository's read-only cluster access, as
  `scripts/runtime/dev/load-dev-sandbox-capacity.sh` reads them.
- Record `cw version` and the source the surface runs. A promotion that has
  not rolled out is not the source you tested.

## `fast-pool-hit`: a create from the pool is usable in seconds

- **Entry points:** `cw --cloud create`; the dashboard's new-environment
  form. Only `cw` is walked here.
- **States to exercise:**
  - a create that takes a ready pool member;
  - a create that finds the pool empty and starts cold, which is correct but
    slow, and must say so in the route metric rather than look like a slow
    hit.
- **Driving it:** twenty creates in a row of the default shape with no
  repository, each timed, in bash, from the create to a `cw exec` that
  answers, then removed:

  ```sh
  TIMEFORMAT='%R s'
  for i in $(seq 1 20); do
    time sh -c "cw --cloud create --name fast-$i --no-file --ttl 30m --no-network && cw --cloud exec --in fast-$i true"
    cw --cloud rm "fast-$i" --yes
  done
  ```

  Read orchestration's `codewire_warm_pool_routes_total` before and after.
- **Proof:**
  - the `route="pool"` count rose by the number of creates that hit the
    pool, and each `cold_*` count that rose names why a create missed;
  - over the creates that hit the pool, the time to a create that exits 0 and
    a `cw exec` that answers is at most 5 s at p50 and 10 s at p95. With 20
    samples, p95 is the second slowest, so run the loop until 20 creates hit
    the pool.
- **Gotchas:**
  - Creates closer together than the pool refills drain it; the later ones
    start cold and are not pool hits. Space them by the refill time, or read
    the route count per create.
  - `codewire_environment_create_milestone_seconds` (bound, access_ready,
    setup_complete; #3567) has buckets too coarse to read a p50 under 5 s
    from; the client time above is the measure until finer buckets exist
    (no command yet; #2238).
- **Observed:** not yet observed.

## `fast-cold-share`: almost no Production create misses the pool

- **Entry points:** every create on Production.
- **States to exercise:** a week that includes a release, when pools are
  replaced.
- **Driving it:** over 7 days, from `codewire_warm_pool_routes_total` on
  Production, divide the increase of the `cold_*` routes by the increase of
  every route. Leave out `cold_source_snapshot` and `cold_tier` from both:
  snapshot creates and confidential creates are never pooled.
- **Proof:** the share is under 5% (owner, 2026-11-14, on #2238).
- **Gotchas:**
  - A counter resets when orchestration restarts; take increases, not raw
    values.
  - `cold_unconfigured` and `cold_shape` mean a create asked for a shape no
    pool holds: pool coverage is the lever, not start time.
- **Observed:** not yet observed.

## `fast-first-start-after-release`: no image pull on the first start

- **Entry points:** the first `cw --cloud create` after a release reaches the
  surface.
- **States to exercise:** a create on each runtime node after the release's
  rollout, before any other create there.
- **Driving it:** after the rollout, run `fast-pool-hit`'s loop once, then
  read the new sandbox Pods' events in the sandbox namespace with
  `kubectl get events`, through that read-only cluster access.
- **Proof:** no `Pulling` event for the workspace or daemon image on any of
  them.
- **Gotchas:**
  - A pool member made before the release still runs the old image; only a
    member made after it proves the pre-pull.
  - Kubernetes keeps events for about an hour; read them within the hour
    after the creates.
- **Observed:** not yet observed.
