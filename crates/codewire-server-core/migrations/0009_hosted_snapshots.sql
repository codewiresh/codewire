-- Hosted disk snapshots (#3046 H1).
--
-- A snapshot is a stopped environment's workspace disk, kept as a
-- VolumeSnapshot in the Sandbox namespace and private to its creator. Every
-- Kubernetes name derives from the row's id. A delete removes the row once its
-- objects are gone, so a row always names objects that may exist.
--
-- The organization key has no cascade: organization deletion removes its
-- snapshots first, and a row it missed fails the deletion instead of leaving a
-- volume nothing can find. The creator and the source environment carry no key:
-- a snapshot outlives its source, and a deleted creator's snapshots are found
-- and removed by orchestration's reconciler.
--
-- Compatible: the table is new, and older code reads nothing from it. Rollback
-- drops the table once no VolumeSnapshot named by a row remains.

CREATE TABLE public.hosted_snapshots (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    created_by text NOT NULL,
    source_environment_id text NOT NULL,
    name text NOT NULL,
    state text DEFAULT 'capturing'::text NOT NULL,
    failure_code text,
    size_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT hosted_snapshots_pkey PRIMARY KEY (id),
    CONSTRAINT hosted_snapshots_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES public.organizations(id),
    CONSTRAINT hosted_snapshots_state_check
        CHECK (state = ANY (ARRAY['capturing'::text, 'ready'::text, 'failed'::text, 'deleting'::text])),
    CONSTRAINT hosted_snapshots_name_check
        CHECK (char_length(name) BETWEEN 1 AND 128),
    CONSTRAINT hosted_snapshots_size_check
        CHECK (size_bytes IS NULL OR size_bytes >= 0),
    CONSTRAINT hosted_snapshots_failure_check
        CHECK ((state = 'failed') = (failure_code IS NOT NULL) OR state = 'deleting')
);

-- A creator's names are unique in an organization; listing reads this index.
CREATE UNIQUE INDEX hosted_snapshots_creator_name_key
    ON public.hosted_snapshots USING btree (org_id, created_by, name);

-- The reconciler's scan for captures and deletes that may have stranded.
CREATE INDEX hosted_snapshots_unsettled_idx
    ON public.hosted_snapshots USING btree (updated_at)
    WHERE state = ANY (ARRAY['capturing'::text, 'deleting'::text]);
