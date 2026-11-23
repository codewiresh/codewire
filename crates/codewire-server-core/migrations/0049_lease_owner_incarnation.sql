-- The process that admitted an environment runtime lease, and when it was
-- last alive (#4523). Each orchestration process picks a random incarnation
-- at start, writes a heartbeat for it every few seconds on a connection of its
-- own, and records the incarnation on every runtime lease it admits. An
-- active lease whose owner has written no heartbeat for long enough, and that
-- is itself that old, is one nothing is acting for any more. Every time is the
-- database's own clock. Leases admitted before this carry no owner.
ALTER TABLE public.organization_mutation_leases
    ADD COLUMN owner_incarnation bigint,
    ADD CONSTRAINT organization_mutation_leases_owner_incarnation_check CHECK (
        owner_incarnation IS NULL OR mutation_class = 'environment_runtime_dispatch');

-- The sweep reads only active runtime leases with an owner.
CREATE INDEX organization_mutation_leases_owned_active_idx
    ON public.organization_mutation_leases USING btree (owner_incarnation, admitted_at, id)
    WHERE (state = 'active'::text AND owner_incarnation IS NOT NULL);

-- One row per process that holds runtime leases, written by that process
-- alone. Like the leases' own times, `last_seen` is LOCALTIMESTAMP.
CREATE TABLE public.lease_owner_heartbeats (
    incarnation bigint PRIMARY KEY,
    last_seen timestamp without time zone NOT NULL
);
