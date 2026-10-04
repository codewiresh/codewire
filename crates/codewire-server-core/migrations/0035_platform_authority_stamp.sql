-- Authority stamp (credential plan PR-12b). Every write to a row that runtime
-- credential authority reads advances a generation for that row's own scope,
-- in the writer's transaction. A later reader can compare a tuple of scope
-- generations before and after a decision; nothing reads them yet.
--
-- Scopes: global (TRUNCATE of any stamped table), env (environment id),
-- user (user id), org (organization id), profile (access profile id) and
-- creds (credential owner: 'user:<id>' or 'organization:<id>').
--
-- Each trigger keys only on the written row's own columns: no join and no
-- fan-out. A bump is an upsert with a fresh sequence value, not an append-log
-- row, because sequence order is not commit order. Rows are never deleted, so
-- a generation can never return to a value a reader has already seen; an
-- absent row reads as 0. Every value is unique, and every committed bump
-- replaces the value with a larger one. The sequence starts at the database
-- clock and installation bumps the global scope, so that also holds across
-- the in-place rollback and a later roll-forward.
--
-- An UPDATE that changes no column bumps nothing. On environments, an UPDATE
-- that changes only the billing tracking columns bumps nothing either. That
-- is a deny-list: any other column, including one added later, bumps.
--
-- The trigger function is SECURITY DEFINER with a fixed search path, so no
-- writer role needs a grant on the generation table or sequence. The triggers
-- are named to sort after every other AFTER trigger on their tables, so for
-- each row the generation row is the last lock its triggers take (per row: a
-- multi-row statement holds it while it goes on to later rows). Every writer
-- that keeps the program-wide order (environment row, then its backend and
-- binding rows) has already taken the environment row lock before an env bump.
--
-- Disabling triggers stops bumps. After session_replication_role=replica,
-- ALTER TABLE ... DISABLE TRIGGER, or a data restore, bump the global scope
-- (or restart every credential broker) before relying on a stamp again; see
-- docs/dev/DATABASE-MIGRATIONS.md.
--
-- The change is additive: version-34 binaries never read the new objects, and
-- the in-place rollback drops them without touching any other row.

-- Fail fast rather than queue every writer behind this migration: a lock wait
-- longer than 5 s aborts it, and the next service start retries it.
SET LOCAL lock_timeout = '5s';
-- Take each stamped table's trigger lock up front, one table at a time in the
-- application's lock order (user, organization, membership, environment, its
-- backend and bindings, profile, credentials, project), so a version-34
-- writer that keeps that order cannot deadlock with the triggers below.
LOCK TABLE public.users, public.organizations, public.org_members, public.environments,
    public.sandbox_environment_backend, public.sandbox_workspace_bindings,
    public.platform_environment_access_bindings, public.platform_access_profiles,
    public.platform_access_profile_revisions, public.platform_access_profile_entries,
    public.platform_credentials, public.secret_projects
    IN SHARE ROW EXCLUSIVE MODE;

CREATE SEQUENCE public.platform_authority_generation_seq AS bigint NO CYCLE;
-- Start at the database clock in microseconds, so a sequence created again
-- after the in-place rollback and a roll-forward issues only values above
-- every value the previous one issued.
SELECT pg_catalog.setval(
    'public.platform_authority_generation_seq',
    (pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000000)::bigint);

CREATE TABLE public.platform_authority_generations (
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    generation bigint NOT NULL,
    PRIMARY KEY (scope_kind, scope_id),
    CONSTRAINT platform_authority_generations_scope_check CHECK (
        (scope_kind = 'global' AND scope_id = '')
        OR (scope_kind IN ('env', 'user', 'org', 'profile') AND scope_id <> '')
        OR (scope_kind = 'creds'
            AND ((starts_with(scope_id, 'user:') AND length(scope_id) > 5)
                 OR (starts_with(scope_id, 'organization:') AND length(scope_id) > 13)))
    ),
    CONSTRAINT platform_authority_generations_generation_check CHECK (generation > 0)
);

-- A deleted or truncated generation row would read as 0 again, so a reader
-- could see an old tuple after a change. Rows are retained for good; the
-- in-place rollback drops the whole table instead.
CREATE FUNCTION public.codewire_platform_authority_generation_retained()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'authority generations are never deleted';
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_authority_generation_retained() FROM PUBLIC;

CREATE TRIGGER codewire_platform_authority_generation_retained
BEFORE DELETE ON public.platform_authority_generations
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_generation_retained();

CREATE TRIGGER codewire_platform_authority_generation_retained_truncate
BEFORE TRUNCATE ON public.platform_authority_generations
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_generation_retained();

-- Arguments: the scope kind, then how the row names its scope: 'id',
-- 'environment_id', 'user_id', 'org_id' or 'profile_id' (that column), or
-- 'owner' ('user:<user_id>', else 'organization:<organization_id>'). An
-- UPDATE bumps the old and the new key, each distinct key once, in sorted
-- order. A key column the row does not have fails the write instead of
-- silently skipping the bump. The statement-level TRUNCATE form bumps the
-- global scope.
CREATE FUNCTION public.codewire_platform_authority_row_changed()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    old_key text;
    new_key text;
    first_key text;
    second_key text;
BEGIN
    IF TG_LEVEL = 'STATEMENT' THEN
        IF TG_OP <> 'TRUNCATE' OR TG_NARGS <> 1 OR TG_ARGV[0] <> 'global' THEN
            RAISE EXCEPTION USING
                ERRCODE = '39P01',
                MESSAGE = 'authority stamp statement trigger is misconfigured';
        END IF;
        first_key := '';
    ELSE
        IF TG_NARGS <> 2
           OR TG_ARGV[1] NOT IN ('id', 'environment_id', 'user_id', 'org_id', 'profile_id', 'owner') THEN
            RAISE EXCEPTION USING
                ERRCODE = '39P01',
                MESSAGE = 'authority stamp row trigger is misconfigured';
        END IF;
        IF TG_OP <> 'INSERT' THEN
            CASE TG_ARGV[1]
                WHEN 'id' THEN old_key := OLD.id;
                WHEN 'environment_id' THEN old_key := OLD.environment_id;
                WHEN 'user_id' THEN old_key := OLD.user_id;
                WHEN 'org_id' THEN old_key := OLD.org_id;
                WHEN 'profile_id' THEN old_key := OLD.profile_id;
                WHEN 'owner' THEN
                    old_key := COALESCE('user:' || OLD.user_id, 'organization:' || OLD.organization_id);
            END CASE;
        END IF;
        IF TG_OP <> 'DELETE' THEN
            CASE TG_ARGV[1]
                WHEN 'id' THEN new_key := NEW.id;
                WHEN 'environment_id' THEN new_key := NEW.environment_id;
                WHEN 'user_id' THEN new_key := NEW.user_id;
                WHEN 'org_id' THEN new_key := NEW.org_id;
                WHEN 'profile_id' THEN new_key := NEW.profile_id;
                WHEN 'owner' THEN
                    new_key := COALESCE('user:' || NEW.user_id, 'organization:' || NEW.organization_id);
            END CASE;
        END IF;
        -- LEAST and GREATEST ignore a NULL key.
        first_key := LEAST(old_key, new_key);
        second_key := GREATEST(old_key, new_key);
        IF second_key = first_key THEN
            second_key := NULL;
        END IF;
    END IF;
    IF first_key IS NOT NULL THEN
        INSERT INTO public.platform_authority_generations AS g (scope_kind, scope_id, generation)
        VALUES (TG_ARGV[0], first_key,
                pg_catalog.nextval('public.platform_authority_generation_seq'::pg_catalog.regclass))
        ON CONFLICT (scope_kind, scope_id) DO UPDATE
        SET generation = pg_catalog.nextval('public.platform_authority_generation_seq'::pg_catalog.regclass);
    END IF;
    IF second_key IS NOT NULL THEN
        INSERT INTO public.platform_authority_generations AS g (scope_kind, scope_id, generation)
        VALUES (TG_ARGV[0], second_key,
                pg_catalog.nextval('public.platform_authority_generation_seq'::pg_catalog.regclass))
        ON CONFLICT (scope_kind, scope_id) DO UPDATE
        SET generation = pg_catalog.nextval('public.platform_authority_generation_seq'::pg_catalog.regclass);
    END IF;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_authority_row_changed() FROM PUBLIC;

-- The generations of the requested scopes, in request order, 0 for a scope
-- never bumped, and the database clock when they were read. Malformed input
-- returns no row: unequal or empty arrays, more than 16 scopes, a NULL, or a
-- (kind, id) pair the generation table could never hold (its scope CHECK),
-- such as an unknown kind, an empty id, or a creds id without its owner
-- prefix. A caller that builds a key wrongly is refused instead of reading a
-- generation of 0 that never changes. Only the credential broker is granted
-- EXECUTE, by deployment; this migration creates no role and grants nothing.
CREATE FUNCTION public.codewire_platform_authority_stamp(scope_kinds text[], scope_ids text[])
RETURNS TABLE (generations bigint[], observed_at timestamptz)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT ARRAY(
               SELECT COALESCE(g.generation, 0)
               FROM ROWS FROM (pg_catalog.unnest($1), pg_catalog.unnest($2))
                    WITH ORDINALITY AS s(scope_kind, scope_id, ordinal)
               LEFT JOIN public.platform_authority_generations AS g
                 ON g.scope_kind = s.scope_kind AND g.scope_id = s.scope_id
               ORDER BY s.ordinal),
           pg_catalog.clock_timestamp()
    WHERE pg_catalog.array_ndims($1) = 1 AND pg_catalog.array_ndims($2) = 1
      AND pg_catalog.cardinality($1) = pg_catalog.cardinality($2)
      AND pg_catalog.cardinality($1) BETWEEN 1 AND 16
      -- Every pair satisfies platform_authority_generations_scope_check. A
      -- NULL kind or id makes the condition NULL, which IS NOT TRUE.
      AND NOT EXISTS (
          SELECT 1
          FROM ROWS FROM (pg_catalog.unnest($1), pg_catalog.unnest($2)) AS v(scope_kind, scope_id)
          WHERE ((v.scope_kind = 'global' AND v.scope_id = '')
                 OR (v.scope_kind IN ('env', 'user', 'org', 'profile') AND v.scope_id <> '')
                 OR (v.scope_kind = 'creds'
                     AND ((pg_catalog.starts_with(v.scope_id, 'user:')
                           AND pg_catalog.length(v.scope_id) > 5)
                          OR (pg_catalog.starts_with(v.scope_id, 'organization:')
                              AND pg_catalog.length(v.scope_id) > 13)))) IS NOT TRUE);
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_authority_stamp(text[], text[]) FROM PUBLIC;

-- Three triggers per stamped table, in the application's lock order: INSERT or
-- DELETE, an UPDATE that changed something, and TRUNCATE.
CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('user', 'id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.users
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('user', 'id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.users
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.organizations
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('org', 'id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.organizations
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('org', 'id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.organizations
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.org_members
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('user', 'user_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.org_members
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('user', 'user_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.org_members
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.environments
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.environments
FOR EACH ROW
WHEN ((pg_catalog.to_jsonb(OLD) - '{last_billing_event_at,total_running_seconds}'::text[])
      IS DISTINCT FROM
      (pg_catalog.to_jsonb(NEW) - '{last_billing_event_at,total_running_seconds}'::text[]))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.environments
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.sandbox_environment_backend
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.sandbox_environment_backend
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.sandbox_environment_backend
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.sandbox_workspace_bindings
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.sandbox_workspace_bindings
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.sandbox_workspace_bindings
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.platform_environment_access_bindings
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.platform_environment_access_bindings
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'environment_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.platform_environment_access_bindings
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.platform_access_profiles
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.platform_access_profiles
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.platform_access_profiles
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.platform_access_profile_revisions
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'profile_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.platform_access_profile_revisions
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'profile_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.platform_access_profile_revisions
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.platform_access_profile_entries
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'profile_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.platform_access_profile_entries
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('profile', 'profile_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.platform_access_profile_entries
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.platform_credentials
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('creds', 'owner');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.platform_credentials
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('creds', 'owner');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.platform_credentials
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

CREATE TRIGGER codewire_stamp_authority_row
AFTER INSERT OR DELETE ON public.secret_projects
FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('org', 'org_id');
CREATE TRIGGER codewire_stamp_authority_update
AFTER UPDATE ON public.secret_projects
FOR EACH ROW WHEN (pg_catalog.to_jsonb(OLD) IS DISTINCT FROM pg_catalog.to_jsonb(NEW))
EXECUTE FUNCTION public.codewire_platform_authority_row_changed('org', 'org_id');
CREATE TRIGGER codewire_stamp_authority_truncate
AFTER TRUNCATE ON public.secret_projects
FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global');

-- Every stamp includes the global scope. Bumping it at installation means no
-- tuple read after an in-place rollback and roll-forward can equal one read
-- before it, although writes in between were not stamped.
INSERT INTO public.platform_authority_generations (scope_kind, scope_id, generation)
VALUES ('global', '', pg_catalog.nextval('public.platform_authority_generation_seq'::pg_catalog.regclass));
