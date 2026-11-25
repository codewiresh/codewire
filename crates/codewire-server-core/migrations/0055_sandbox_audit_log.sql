-- The Sandbox audit log (#6189; SPEC.md "Sandbox audit log"): one event for
-- each thing that happened to a hosted Sandbox or through it, kept 90 days.
--
-- sandbox_audit_events holds finished events. Rows are only inserted: a
-- trigger refuses every UPDATE, and only codewire_expire_sandbox_audit and
-- the organization's deletion remove rows. It is partitioned by month on
-- first_at, so expiry drops whole months; the partitions are made ahead by
-- codewire_ensure_sandbox_audit_partitions, which orchestration calls at
-- start and every day. Nothing here makes a dated partition, so the schema
-- this migration leaves is the same whenever it runs.
--
-- sandbox_audit_pending holds what isn't finished: the current hour's folds,
-- whose counts grow, and sessions still open. codewire_flush_sandbox_audit
-- moves a fold once its hour has ended and a session once it has closed, or
-- once the process holding it (lease_owner_heartbeats, #4523) is gone; such a
-- session is closed at that process's last heartbeat. A read covers both
-- tables.
--
-- Only orchestration writes either table, through its audit module; the
-- services run as the database's owner (#5166), so a repository check
-- (sandbox-audit-writers) enforces that instead of a grant. Events carry the
-- actor as it was when recorded: a deleted user's events keep their email
-- and client IP until they expire.
--
-- Compatible: new tables and functions; older code ignores them.
-- Rollback: drop the functions, then both tables.

CREATE TABLE public.sandbox_audit_events (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    environment_id text NOT NULL,
    kind text NOT NULL,
    action text NOT NULL,
    -- What a fold is about (a destination, a credential and host, an actor
    -- and address), or the event itself when it doesn't fold.
    subject text NOT NULL,
    first_at timestamp with time zone NOT NULL,
    -- NULL only while a session is open, which never reaches this table
    -- except when it outlived the process holding it.
    last_at timestamp with time zone,
    count bigint DEFAULT 1 NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    -- A user's email or an API key's name, when recorded.
    actor_label text,
    actor_role text,
    client_ip inet,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT sandbox_audit_events_pkey PRIMARY KEY (first_at, id),
    CONSTRAINT sandbox_audit_events_org_fkey FOREIGN KEY (org_id)
        REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT sandbox_audit_events_kind_check
        CHECK (kind IN ('access', 'lifecycle', 'policy', 'refused', 'credentials')),
    CONSTRAINT sandbox_audit_events_count_check CHECK (count >= 1),
    CONSTRAINT sandbox_audit_events_span_check CHECK (last_at IS NULL OR last_at >= first_at),
    CONSTRAINT sandbox_audit_events_actor_check CHECK (
        (actor_type IN ('user', 'api_key') AND actor_id IS NOT NULL)
        OR (actor_type IN ('platform', 'sandbox') AND actor_id IS NULL
            AND actor_label IS NULL AND actor_role IS NULL)),
    CONSTRAINT sandbox_audit_events_role_check
        CHECK (actor_role IS NULL OR actor_role IN ('owner', 'admin', 'member', 'staff')),
    CONSTRAINT sandbox_audit_events_client_ip_check CHECK (client_ip IS NULL OR kind = 'access'),
    CONSTRAINT sandbox_audit_events_detail_check CHECK (jsonb_typeof(detail) = 'object')
) PARTITION BY RANGE (first_at);

-- The read: one environment, newest first, paged by (first_at, id).
CREATE INDEX sandbox_audit_events_environment_idx
    ON public.sandbox_audit_events (environment_id, first_at DESC, id DESC);
-- The organization's deletion cascades by org_id.
CREATE INDEX sandbox_audit_events_org_idx ON public.sandbox_audit_events (org_id);

CREATE FUNCTION public.codewire_refuse_sandbox_audit_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    RAISE EXCEPTION 'sandbox audit events are never updated'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER sandbox_audit_events_never_updated
    BEFORE UPDATE ON public.sandbox_audit_events
    FOR EACH ROW EXECUTE FUNCTION public.codewire_refuse_sandbox_audit_update();

CREATE TABLE public.sandbox_audit_pending (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    environment_id text NOT NULL,
    kind text NOT NULL,
    action text NOT NULL,
    subject text NOT NULL,
    -- 'fold': the hour's count for one subject; it moves when its hour ends.
    -- 'session': one open session; it moves when it closes.
    pending text NOT NULL,
    -- The fold's subject and hour, or the session's own key: what a writer
    -- adds to or closes.
    pending_key text NOT NULL,
    -- The orchestration process holding an open session.
    holder_incarnation bigint,
    first_at timestamp with time zone NOT NULL,
    last_at timestamp with time zone,
    count bigint DEFAULT 1 NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    actor_label text,
    actor_role text,
    client_ip inet,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT sandbox_audit_pending_pkey PRIMARY KEY (id),
    CONSTRAINT sandbox_audit_pending_key UNIQUE (environment_id, kind, pending_key),
    CONSTRAINT sandbox_audit_pending_org_fkey FOREIGN KEY (org_id)
        REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT sandbox_audit_pending_kind_check
        CHECK (kind IN ('access', 'lifecycle', 'policy', 'refused', 'credentials')),
    CONSTRAINT sandbox_audit_pending_pending_check CHECK (
        (pending = 'fold' AND holder_incarnation IS NULL AND last_at IS NOT NULL)
        OR (pending = 'session' AND kind = 'access' AND holder_incarnation IS NOT NULL)),
    CONSTRAINT sandbox_audit_pending_count_check CHECK (count >= 1),
    CONSTRAINT sandbox_audit_pending_span_check CHECK (last_at IS NULL OR last_at >= first_at),
    CONSTRAINT sandbox_audit_pending_actor_check CHECK (
        (actor_type IN ('user', 'api_key') AND actor_id IS NOT NULL)
        OR (actor_type IN ('platform', 'sandbox') AND actor_id IS NULL
            AND actor_label IS NULL AND actor_role IS NULL)),
    CONSTRAINT sandbox_audit_pending_role_check
        CHECK (actor_role IS NULL OR actor_role IN ('owner', 'admin', 'member', 'staff')),
    CONSTRAINT sandbox_audit_pending_client_ip_check CHECK (client_ip IS NULL OR kind = 'access'),
    CONSTRAINT sandbox_audit_pending_detail_check CHECK (jsonb_typeof(detail) = 'object')
);

CREATE INDEX sandbox_audit_pending_environment_idx
    ON public.sandbox_audit_pending (environment_id, first_at DESC, id DESC);
CREATE INDEX sandbox_audit_pending_org_idx ON public.sandbox_audit_pending (org_id);

-- The month holding `at`, the one before it and the two after it. A
-- partition that exists is left alone.
CREATE FUNCTION public.codewire_ensure_sandbox_audit_partitions(at timestamp with time zone)
    RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    month_start timestamp with time zone;
BEGIN
    FOR step IN -1..2 LOOP
        month_start := date_trunc('month', at, 'UTC') + make_interval(months => step);
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS public.%I PARTITION OF public.sandbox_audit_events '
            'FOR VALUES FROM (%L) TO (%L)',
            'sandbox_audit_events_' || to_char(month_start AT TIME ZONE 'UTC', 'YYYY_MM'),
            month_start,
            month_start + interval '1 month');
    END LOOP;
END;
$$;

-- Moves what is finished from sandbox_audit_pending into
-- sandbox_audit_events, in one statement, and returns how many rows moved:
-- folds whose hour ended before `flush_at`, closed sessions, and open sessions
-- whose holder last wrote a heartbeat more than `grace` before `flush_at`,
-- or none.
CREATE FUNCTION public.codewire_flush_sandbox_audit(flush_at timestamp with time zone, grace interval)
    RETURNS bigint
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    moved bigint;
BEGIN
    -- A row that waited past the months around now still has a partition
    -- to move into, so one old row can't stall every later flush.
    PERFORM public.codewire_ensure_sandbox_audit_partitions(flush_at);
    PERFORM public.codewire_ensure_sandbox_audit_partitions(waiting.month)
       FROM (SELECT DISTINCT date_trunc('month', p.first_at, 'UTC') AS month
               FROM public.sandbox_audit_pending p) waiting;
    WITH finished AS (
        DELETE FROM public.sandbox_audit_pending p
         WHERE (p.pending = 'fold' AND p.first_at < date_trunc('hour', flush_at, 'UTC'))
            OR (p.pending = 'session' AND p.last_at IS NOT NULL)
            OR (p.pending = 'session' AND NOT EXISTS (
                    SELECT 1 FROM public.lease_owner_heartbeats o
                     WHERE o.incarnation = p.holder_incarnation
                       AND o.last_seen::timestamp with time zone >= flush_at - grace))
        RETURNING p.*
    )
    INSERT INTO public.sandbox_audit_events (
        id, org_id, environment_id, kind, action, subject, first_at, last_at, count,
        actor_type, actor_id, actor_label, actor_role, client_ip, detail)
    SELECT f.id, f.org_id, f.environment_id, f.kind, f.action, f.subject, f.first_at,
           CASE
               WHEN f.pending = 'session' AND f.last_at IS NULL THEN
                   (SELECT GREATEST(o.last_seen::timestamp with time zone, f.first_at)
                      FROM public.lease_owner_heartbeats o
                     WHERE o.incarnation = f.holder_incarnation)
               ELSE f.last_at
           END,
           f.count, f.actor_type, f.actor_id, f.actor_label, f.actor_role, f.client_ip, f.detail
      FROM finished f;
    GET DIAGNOSTICS moved = ROW_COUNT;
    RETURN moved;
END;
$$;

-- Removes events that began before `cutoff`: whole months by dropping their
-- partition, the rest of the oldest month row by row. Pending rows that old
-- go too. A cutoff inside the 90 days events are kept is refused, so no call
-- can remove an event its readers are owed.
CREATE FUNCTION public.codewire_expire_sandbox_audit(cutoff timestamp with time zone)
    RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    partition record;
BEGIN
    -- In hours, as the caller's retention is, so no time zone's daylight
    -- saving change makes the two differ.
    IF cutoff > pg_catalog.now() - interval '2160 hours' THEN
        RAISE EXCEPTION 'sandbox audit events are kept 90 days; % is inside that', cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR partition IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class parent ON parent.oid = i.inhparent
          JOIN pg_namespace n ON n.oid = parent.relnamespace
         WHERE n.nspname = 'public'
           AND parent.relname = 'sandbox_audit_events'
           AND c.relname ~ '^sandbox_audit_events_[0-9]{4}_[0-9]{2}$'
           AND to_timestamp(substr(c.relname, 22), 'YYYY_MM')::timestamp AT TIME ZONE 'UTC'
               + interval '1 month' <= cutoff
    LOOP
        EXECUTE format('DROP TABLE public.%I', partition.relname);
    END LOOP;
    DELETE FROM public.sandbox_audit_events WHERE first_at < cutoff;
    DELETE FROM public.sandbox_audit_pending WHERE first_at < cutoff;
END;
$$;
