-- The profile a systemd workspace was created on (#5638,
-- docs/dev/SYSTEMD-WORKSPACE.md, "When an environment is a systemd
-- workspace").
--
-- environments.systemd_runtime_profile: `commodity` or `standard`, the
-- runtime profile a systemd workspace's Pod rendered on at its create,
-- written by the create's insert. Every later render and check of the
-- environment reads it, never the deployment's current `standard` disk, so a
-- republished disk never moves a workspace between profiles. NULL for every
-- other environment, and for a systemd workspace created before this column,
-- which orchestration reads as `commodity`.
--
-- The systemd record (this column and environments.systemd_workspace) is
-- written once: a trigger refuses any update that changes either.
--
-- Adding a nullable column rewrites no rows; every existing row is NULL, so
-- the check holds; older code that does not read it keeps working.
ALTER TABLE ONLY public.environments
    ADD COLUMN systemd_runtime_profile text,
    ADD CONSTRAINT environments_systemd_runtime_profile_check CHECK (
        systemd_runtime_profile IS NULL
        OR (systemd_workspace AND systemd_runtime_profile IN ('commodity', 'standard'))
    );

CREATE FUNCTION public.codewire_environment_systemd_record_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF ROW(NEW.systemd_workspace, NEW.systemd_runtime_profile)
       IS DISTINCT FROM
       ROW(OLD.systemd_workspace, OLD.systemd_runtime_profile) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'an environment''s systemd record is written once, at create';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER environment_systemd_record_immutable
    BEFORE UPDATE OF systemd_workspace, systemd_runtime_profile ON public.environments
    FOR EACH ROW EXECUTE FUNCTION public.codewire_environment_systemd_record_immutable();
