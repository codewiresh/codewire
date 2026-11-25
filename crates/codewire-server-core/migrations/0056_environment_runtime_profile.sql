-- One organization moves onto `standard` (#5602,
-- docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md, "Moving an organization").
--
-- organizations.standard_runtime_enabled: the organization's new sandboxes
-- run on `standard` while the deployment makes it available. Off for every
-- organization, existing and new: only a global administrator moves one.
--
-- environments.runtime_profile: the runtime profile the environment was
-- created on, `commodity`, `standard` or `confidential` (or a local Kind
-- deployment's diagnostic `runc` or `none`, or empty on a deployment that
-- names no runtime profile, whose every start is refused), written by the
-- create's insert. Every later render, start and check reads it, never the
-- deployment's current profile or `standard` disk, so neither a change to the
-- organization's flag nor a republished disk moves an environment between
-- profiles. It generalizes 0047's systemd_runtime_profile, which code built
-- with this migration neither reads nor writes. That column stays, so an
-- older orchestration Pod still serving during the rollout keeps working: it
-- reads NULL as `commodity`, and what it writes is copied here on insert. A
-- later migration drops it once every deployment runs this code.
--
-- Its default, `commodity`, is the backfill's value for a plain environment
-- and what a writer that does not name the column records; every render reads
-- the same record, so the record and the Pod never disagree, and the default
-- never puts an environment on `standard`. An insert that leaves the default
-- is completed by the trigger below: on the confidential tier it is recorded
-- `confidential`, and an older Pod's systemd_runtime_profile is copied.
--
-- The backfill gives every existing row a profile. A confidential
-- environment is `confidential`; a systemd workspace keeps the profile 0047
-- recorded, `commodity` where none was; every other environment is
-- `commodity`, which is the profile every deployment renders them on while
-- none runs `standard` as its default (a local Kind deployment renders a
-- `commodity` record on its own diagnostic profile, having no VM runtime). Orchestration refuses to start with a
-- `standard` default while any plain environment's recorded `commodity`
-- disagrees with its live Sandbox.
--
-- The record (systemd_workspace, systemd_runtime_profile and runtime_profile)
-- is written once: the trigger 0047 added now guards all three. A systemd workspace's profile is `commodity` or `standard`, and an
-- environment on the confidential isolation tier is always `confidential`.
ALTER TABLE ONLY public.organizations
    ADD COLUMN standard_runtime_enabled boolean DEFAULT false NOT NULL;

ALTER TABLE ONLY public.environments
    ADD COLUMN runtime_profile text DEFAULT 'commodity' NOT NULL;

UPDATE public.environments
   SET runtime_profile = CASE
       WHEN isolation_tier = 'confidential' THEN 'confidential'
       WHEN systemd_workspace THEN COALESCE(systemd_runtime_profile, 'commodity')
       ELSE 'commodity'
   END
 WHERE isolation_tier = 'confidential' OR systemd_runtime_profile IS NOT NULL;

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_runtime_profile_check CHECK (
        runtime_profile IN ('commodity', 'standard', 'confidential', 'runc', 'none', '')
        AND (isolation_tier <> 'confidential' OR runtime_profile = 'confidential')
        AND (NOT systemd_workspace OR runtime_profile IN ('commodity', 'standard'))
    );

DROP TRIGGER environment_systemd_record_immutable ON public.environments;

CREATE OR REPLACE FUNCTION public.codewire_environment_systemd_record_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF ROW(NEW.systemd_workspace, NEW.systemd_runtime_profile, NEW.runtime_profile)
       IS DISTINCT FROM
       ROW(OLD.systemd_workspace, OLD.systemd_runtime_profile, OLD.runtime_profile) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'an environment''s runtime record is written once, at create';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER environment_systemd_record_immutable
    BEFORE UPDATE OF systemd_workspace, systemd_runtime_profile, runtime_profile
    ON public.environments
    FOR EACH ROW EXECUTE FUNCTION public.codewire_environment_systemd_record_immutable();

CREATE FUNCTION public.codewire_environment_runtime_profile_default() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF NEW.isolation_tier = 'confidential' AND NEW.runtime_profile = 'commodity' THEN
        NEW.runtime_profile := 'confidential';
    ELSIF NEW.systemd_runtime_profile IS NOT NULL AND NEW.runtime_profile = 'commodity' THEN
        NEW.runtime_profile := NEW.systemd_runtime_profile;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER environment_runtime_profile_default
    BEFORE INSERT ON public.environments
    FOR EACH ROW EXECUTE FUNCTION public.codewire_environment_runtime_profile_default();
