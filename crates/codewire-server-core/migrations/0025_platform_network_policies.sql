-- Platform network policies (#4000, item 1): an organization's named egress
-- policies, which hosted environments select.
--
-- A policy belongs to one organization; its name is unique there and follows
-- the policy library's name rules, never a built-in's (`open`, `locked`,
-- `hosted-default`). Every change appends a revision and moves
-- current_revision; a revision never changes. A revision holds the canonical
-- JSON document and its SHA-256 digest exactly as a local VM's policy store
-- writes them for the same rules, so one set of rules has one digest
-- wherever it is stored. A policy holds no secret.
--
-- An environment that selects nothing has no row and is on `hosted-default`.
-- A row selects either a stored policy, following its current revision as a
-- local selection does, or the built-in `open` or `locked`. The enforced_*
-- columns record what the environment's egress broker last reported
-- enforcing; nothing writes them until cw-egress exists. A selected policy
-- cannot be deleted. Destroying an environment removes its row.
--
-- Deleting the organization deletes its policies and its environments'
-- selections. Deleting the user who made a revision clears created_by, which
-- is the only change a revision accepts.
--
-- Compatible: the tables are new, and older code reads nothing from them.
-- Rollback drops the three tables and the trigger function, which forgets
-- every platform network policy and selection.

CREATE TABLE public.platform_network_policies (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    current_revision integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_network_policies_pkey PRIMARY KEY (id),
    CONSTRAINT platform_network_policies_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT platform_network_policies_org_name_key UNIQUE (org_id, name),
    -- codewire_egress_policy::PolicyName.
    CONSTRAINT platform_network_policies_name_check CHECK (
        name ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'
        AND name <> ALL (ARRAY['open'::text, 'locked'::text, 'hosted-default'::text])
    ),
    CONSTRAINT platform_network_policies_current_revision_check
        CHECK (current_revision BETWEEN 1 AND 10000)
);

CREATE TABLE public.platform_network_policy_revisions (
    policy_id text NOT NULL,
    revision integer NOT NULL,
    document bytea NOT NULL,
    digest bytea NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_network_policy_revisions_pkey PRIMARY KEY (policy_id, revision),
    CONSTRAINT platform_network_policy_revisions_policy_id_fkey
        FOREIGN KEY (policy_id) REFERENCES public.platform_network_policies(id) ON DELETE CASCADE,
    CONSTRAINT platform_network_policy_revisions_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT platform_network_policy_revisions_revision_check
        CHECK (revision BETWEEN 1 AND 10000),
    -- codewire_egress_policy::MAX_POLICY_DOCUMENT_BYTES.
    CONSTRAINT platform_network_policy_revisions_document_check
        CHECK (octet_length(document) BETWEEN 1 AND 262144),
    CONSTRAINT platform_network_policy_revisions_digest_check
        CHECK (octet_length(digest) = 32)
);

CREATE FUNCTION public.codewire_network_policy_revision_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF ROW(NEW.policy_id, NEW.revision, NEW.document, NEW.digest, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.policy_id, OLD.revision, OLD.document, OLD.digest, OLD.created_at)
       OR (NEW.created_by IS NOT NULL AND NEW.created_by IS DISTINCT FROM OLD.created_by) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a network policy revision is immutable';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.codewire_network_policy_revision_immutable() FROM PUBLIC;

CREATE TRIGGER platform_network_policy_revisions_immutable
    BEFORE UPDATE ON public.platform_network_policy_revisions
    FOR EACH ROW EXECUTE FUNCTION public.codewire_network_policy_revision_immutable();

CREATE TABLE public.platform_environment_network_policies (
    environment_id text NOT NULL,
    policy_id text,
    builtin text,
    enforced_revision integer,
    enforced_digest bytea,
    enforced_at timestamp with time zone,
    CONSTRAINT platform_environment_network_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT platform_environment_network_policies_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    -- A selected policy cannot be deleted.
    CONSTRAINT platform_environment_network_policies_policy_id_fkey
        FOREIGN KEY (policy_id) REFERENCES public.platform_network_policies(id) ON DELETE NO ACTION,
    CONSTRAINT platform_environment_network_policies_selection_check
        CHECK ((policy_id IS NULL) <> (builtin IS NULL)),
    CONSTRAINT platform_environment_network_policies_builtin_check
        CHECK (builtin = ANY (ARRAY['open'::text, 'locked'::text])),
    CONSTRAINT platform_environment_network_policies_enforced_check CHECK (
        (enforced_digest IS NULL AND enforced_revision IS NULL AND enforced_at IS NULL)
        OR (enforced_digest IS NOT NULL AND octet_length(enforced_digest) = 32
            AND enforced_at IS NOT NULL
            AND (enforced_revision IS NULL OR enforced_revision BETWEEN 1 AND 10000))
    )
);

-- The delete refusal, and the organization-deletion check.
CREATE INDEX platform_environment_network_policies_policy_id_idx
    ON public.platform_environment_network_policies USING btree (policy_id);
