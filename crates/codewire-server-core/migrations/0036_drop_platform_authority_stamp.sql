-- Remove the authority stamp (credential plan PR-12b, migration 35). The
-- credential plan no longer reads scope generations, and nothing ever read
-- them, so this drops every object migration 35 created and nothing else.
-- Afterwards the schema is the version-34 schema again; rows in other tables
-- are untouched, and the generations are discarded.
--
-- Every DROP names an object migration 35 created, with no IF EXISTS and no
-- CASCADE. SQLx runs this file and records its ledger row in one transaction,
-- so a failure leaves version 35 exactly as it was, the next service start
-- retries from the same state, and the file never runs against a partly
-- dropped schema. A database that has drifted from migration 35 (a stamp
-- object missing, or something new that depends on one) fails here loudly
-- instead of being half-reconciled in silence.
--
-- Compatibility: version-35 binaries never read the stamp, and their writes
-- need no grant on it, so they keep working once it is gone.

-- Fail fast rather than queue every reader and writer of these tables behind
-- this migration: a lock wait longer than 5 s aborts it, and the next service
-- start retries it.
SET LOCAL lock_timeout = '5s';
-- DROP TRIGGER needs ACCESS EXCLUSIVE on its table. Take it on every stamped
-- table up front, one table at a time in the application's lock order (user,
-- organization, membership, environment, its backend and bindings, profile,
-- credentials, project), instead of upgrading a lock table by table, so a
-- writer that keeps that order cannot deadlock with the drops below. A session
-- that takes these tables in another order can still deadlock with it;
-- PostgreSQL then aborts one side, and if that is this migration, the next
-- service start retries it. The locks are held only for the drops, which
-- change no row.
LOCK TABLE public.users, public.organizations, public.org_members, public.environments,
    public.sandbox_environment_backend, public.sandbox_workspace_bindings,
    public.platform_environment_access_bindings, public.platform_access_profiles,
    public.platform_access_profile_revisions, public.platform_access_profile_entries,
    public.platform_credentials, public.secret_projects
    IN ACCESS EXCLUSIVE MODE;

-- The three stamp triggers on each table, in the same order.
DROP TRIGGER codewire_stamp_authority_row ON public.users;
DROP TRIGGER codewire_stamp_authority_update ON public.users;
DROP TRIGGER codewire_stamp_authority_truncate ON public.users;

DROP TRIGGER codewire_stamp_authority_row ON public.organizations;
DROP TRIGGER codewire_stamp_authority_update ON public.organizations;
DROP TRIGGER codewire_stamp_authority_truncate ON public.organizations;

DROP TRIGGER codewire_stamp_authority_row ON public.org_members;
DROP TRIGGER codewire_stamp_authority_update ON public.org_members;
DROP TRIGGER codewire_stamp_authority_truncate ON public.org_members;

DROP TRIGGER codewire_stamp_authority_row ON public.environments;
DROP TRIGGER codewire_stamp_authority_update ON public.environments;
DROP TRIGGER codewire_stamp_authority_truncate ON public.environments;

DROP TRIGGER codewire_stamp_authority_row ON public.sandbox_environment_backend;
DROP TRIGGER codewire_stamp_authority_update ON public.sandbox_environment_backend;
DROP TRIGGER codewire_stamp_authority_truncate ON public.sandbox_environment_backend;

DROP TRIGGER codewire_stamp_authority_row ON public.sandbox_workspace_bindings;
DROP TRIGGER codewire_stamp_authority_update ON public.sandbox_workspace_bindings;
DROP TRIGGER codewire_stamp_authority_truncate ON public.sandbox_workspace_bindings;

DROP TRIGGER codewire_stamp_authority_row ON public.platform_environment_access_bindings;
DROP TRIGGER codewire_stamp_authority_update ON public.platform_environment_access_bindings;
DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_environment_access_bindings;

DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profiles;
DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profiles;
DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profiles;

DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profile_revisions;
DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profile_revisions;
DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profile_revisions;

DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profile_entries;
DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profile_entries;
DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profile_entries;

DROP TRIGGER codewire_stamp_authority_row ON public.platform_credentials;
DROP TRIGGER codewire_stamp_authority_update ON public.platform_credentials;
DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_credentials;

DROP TRIGGER codewire_stamp_authority_row ON public.secret_projects;
DROP TRIGGER codewire_stamp_authority_update ON public.secret_projects;
DROP TRIGGER codewire_stamp_authority_truncate ON public.secret_projects;

-- The generation table's two retained-row guards, then the table itself.
DROP TRIGGER codewire_platform_authority_generation_retained
    ON public.platform_authority_generations;
DROP TRIGGER codewire_platform_authority_generation_retained_truncate
    ON public.platform_authority_generations;
DROP TABLE public.platform_authority_generations;

-- The reader (dropping it also removes any EXECUTE grant made on it), the
-- trigger function, the guard function, and the sequence.
DROP FUNCTION public.codewire_platform_authority_stamp(text[], text[]);
DROP FUNCTION public.codewire_platform_authority_row_changed();
DROP FUNCTION public.codewire_platform_authority_generation_retained();
DROP SEQUENCE public.platform_authority_generation_seq;
