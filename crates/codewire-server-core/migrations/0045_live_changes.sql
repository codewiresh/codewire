-- Live changes (#4762): the dashboard learns that a Sandbox, its setup or a
-- resize changed from Postgres notices instead of polling for them
-- (private-docs designs/live-updates.md). Orchestration listens and passes
-- each notice on to the signed-in pages that show it.
--
-- A notice names only what changed, as text `<organization id>:<environment
-- id>`, never its state; a page re-fetches what it shows and that read is
-- authorized as usual. A notice is sent at commit and never for a
-- rolled-back transaction, and Postgres folds identical notices within one
-- transaction.
--
-- Triggers, not calls in each writer (owner, 2026-11-14, recorded on
-- #3013): about fifteen code paths write `environments` directly, and a
-- missed one would leave a page that never updates. Each trigger fires only
-- when a column a page shows changes, so the minute's billing counters, the
-- activity clock and generation bumps stay quiet.
--
-- Compatible: the triggers only notify. Older code ignores the notices.
-- Rolling back is forward only (docs/dev/DATABASE-MIGRATIONS.md).

CREATE FUNCTION public.codewire_notify_environment_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    changed public.environments%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        changed := OLD;
    ELSE
        changed := NEW;
    END IF;
    PERFORM pg_catalog.pg_notify('environment_changes', changed.org_id || ':' || changed.id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER environments_live_changes_rows
    AFTER INSERT OR DELETE ON public.environments
    FOR EACH ROW EXECUTE FUNCTION public.codewire_notify_environment_change();

CREATE TRIGGER environments_live_changes
    AFTER UPDATE OF name, state, desired_state, error_reason, recoverable, cpu_millicores, memory_mb,
        disk_gb, ttl_seconds, shutdown_at, deletion_requested_at, deletion_grace_until, protected,
        isolation_tier, started_at, stopped_at, destroyed_at
    ON public.environments
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name
          OR OLD.state IS DISTINCT FROM NEW.state
          OR OLD.desired_state IS DISTINCT FROM NEW.desired_state
          OR OLD.error_reason IS DISTINCT FROM NEW.error_reason
          OR OLD.recoverable IS DISTINCT FROM NEW.recoverable
          OR OLD.cpu_millicores IS DISTINCT FROM NEW.cpu_millicores
          OR OLD.memory_mb IS DISTINCT FROM NEW.memory_mb
          OR OLD.disk_gb IS DISTINCT FROM NEW.disk_gb
          OR OLD.ttl_seconds IS DISTINCT FROM NEW.ttl_seconds
          OR OLD.shutdown_at IS DISTINCT FROM NEW.shutdown_at
          OR OLD.deletion_requested_at IS DISTINCT FROM NEW.deletion_requested_at
          OR OLD.deletion_grace_until IS DISTINCT FROM NEW.deletion_grace_until
          OR OLD.protected IS DISTINCT FROM NEW.protected
          OR OLD.isolation_tier IS DISTINCT FROM NEW.isolation_tier
          OR OLD.started_at IS DISTINCT FROM NEW.started_at
          OR OLD.stopped_at IS DISTINCT FROM NEW.stopped_at
          OR OLD.destroyed_at IS DISTINCT FROM NEW.destroyed_at)
    EXECUTE FUNCTION public.codewire_notify_environment_change();

-- Setup's progress is the Sandbox's backend row; the page shows its phase,
-- whether it finished and its error.
CREATE FUNCTION public.codewire_notify_environment_setup_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    org text;
BEGIN
    SELECT e.org_id INTO org FROM public.environments e WHERE e.id = NEW.environment_id;
    IF org IS NOT NULL THEN
        PERFORM pg_catalog.pg_notify('environment_changes', org || ':' || NEW.environment_id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER sandbox_environment_backend_live_changes
    AFTER UPDATE OF setup_phase, setup_complete, setup_error, setup_owner_status
    ON public.sandbox_environment_backend
    FOR EACH ROW
    WHEN (OLD.setup_phase IS DISTINCT FROM NEW.setup_phase
          OR OLD.setup_complete IS DISTINCT FROM NEW.setup_complete
          OR OLD.setup_error IS DISTINCT FROM NEW.setup_error
          OR OLD.setup_owner_status IS DISTINCT FROM NEW.setup_owner_status)
    EXECUTE FUNCTION public.codewire_notify_environment_setup_change();

-- A resize operation's request and each step of it. The row names its own
-- organization.
CREATE FUNCTION public.codewire_notify_resize_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM pg_catalog.pg_notify('resize_changes', NEW.org_id || ':' || NEW.environment_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER environment_resize_operations_live_changes
    AFTER INSERT OR UPDATE ON public.environment_resize_operations
    FOR EACH ROW EXECUTE FUNCTION public.codewire_notify_resize_change();

REVOKE ALL ON FUNCTION public.codewire_notify_environment_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_notify_environment_setup_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_notify_resize_change() FROM PUBLIC;
