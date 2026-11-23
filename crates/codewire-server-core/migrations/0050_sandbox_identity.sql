-- Sandbox identity's records (#4663, #4664; docs/dev/SANDBOX-IDENTITY.md):
-- each Sandbox's identity groups, the audiences an organization registered,
-- the kill switches, and the mint log.
--
-- Groups are stored bare; the org ID is prefixed only in a token. Each groups
-- row and each audience row carries a version, so the mint cache misses after
-- a change. A groups row's version is bumped on every change. An audience's
-- comes from a sequence, never a clock, so removing and registering it again
-- never reuses a version, whatever the replicas' clocks say.
--
-- identity_mints has no foreign key to environments: it keeps a deleted
-- Sandbox's mints for its 30 days. It never holds a token, only jti and kid.
--
-- Compatible: new tables only; older code never reads or writes them.
-- Rollback:
--   DROP TABLE public.identity_mints;
--   DROP TABLE public.identity_minting_stops;
--   DROP TABLE public.identity_audiences;
--   DROP SEQUENCE public.identity_audience_versions;
--   DROP TABLE public.environment_identity_groups;

CREATE TABLE public.environment_identity_groups (
    environment_id text NOT NULL,
    groups text[] NOT NULL,
    version bigint NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_identity_groups_pkey PRIMARY KEY (environment_id),
    CONSTRAINT environment_identity_groups_environment_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT environment_identity_groups_count CHECK (cardinality(groups) <= 32),
    CONSTRAINT environment_identity_groups_version CHECK (version > 0)
);

CREATE SEQUENCE public.identity_audience_versions;

CREATE TABLE public.identity_audiences (
    org_id text NOT NULL,
    audience text NOT NULL,
    -- NULL lets the audience see every group; otherwise only these.
    visible_groups text[],
    lifetime_seconds integer DEFAULT 600 NOT NULL,
    claim_created_by boolean DEFAULT false NOT NULL,
    claim_environment_name boolean DEFAULT false NOT NULL,
    file_name text,
    version bigint DEFAULT nextval('public.identity_audience_versions') NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_audiences_pkey PRIMARY KEY (org_id, audience),
    CONSTRAINT identity_audiences_org_fkey
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT identity_audiences_lifetime CHECK (lifetime_seconds BETWEEN 60 AND 600),
    CONSTRAINT identity_audiences_version CHECK (version > 0)
);

CREATE UNIQUE INDEX identity_audiences_file_name_key
    ON public.identity_audiences (org_id, file_name)
    WHERE file_name IS NOT NULL;

-- A row with environment_id NULL stops the whole organization.
CREATE TABLE public.identity_minting_stops (
    org_id text NOT NULL,
    environment_id text,
    stopped_by text NOT NULL,
    stopped_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_minting_stops_org_fkey
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT identity_minting_stops_environment_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX identity_minting_stops_org_key
    ON public.identity_minting_stops (org_id)
    WHERE environment_id IS NULL;

CREATE UNIQUE INDEX identity_minting_stops_environment_key
    ON public.identity_minting_stops (environment_id)
    WHERE environment_id IS NOT NULL;

CREATE TABLE public.identity_mints (
    jti text NOT NULL,
    environment_id text NOT NULL,
    org_id text NOT NULL,
    audience text NOT NULL,
    kid text NOT NULL,
    groups_version bigint NOT NULL,
    audience_version bigint NOT NULL,
    minted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_mints_pkey PRIMARY KEY (jti)
);

CREATE INDEX identity_mints_minted_at_idx ON public.identity_mints (minted_at);
CREATE INDEX identity_mints_environment_idx ON public.identity_mints (environment_id, minted_at);
