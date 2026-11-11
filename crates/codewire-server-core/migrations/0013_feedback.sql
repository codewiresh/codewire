-- CLI feedback (#4061).
--
-- `cw feedback` stores one row per message, signed in or anonymous. A signed-in
-- row names its user and, when the sender chose one they belong to, their
-- current organization; an anonymous row names neither. Besides the message the
-- row holds only what the CLI attaches: its version, OS, architecture, local or
-- cloud placement and, when the sender names one, an environment ID.
--
-- client_address_hash is a keyed hash (HMAC-SHA256 under a key derived from
-- the service secret) of the sender's address, never the address. The abuse
-- limits count rows by it, by user and in total over the last hour, so the
-- rows are their own rate-limit record. NULL means the address was unknown;
-- those senders share one anonymous allowance.
--
-- Feedback is the sender's: deleting an account deletes its feedback, while
-- deleting an organization keeps the feedback and forgets the organization.
-- Only platform admins read it.
--
-- Compatible: the table is new, and older code reads nothing from it. Rollback
-- drops the table and its indexes, which discards the feedback.

CREATE TABLE public.feedback (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id text,
    organization_id text,
    message text NOT NULL,
    cli_version text NOT NULL,
    os text NOT NULL,
    arch text NOT NULL,
    placement text,
    environment_id text,
    client_address_hash text,
    CONSTRAINT feedback_pkey PRIMARY KEY (id),
    CONSTRAINT feedback_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT feedback_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL,
    -- At most 10 KB, and not only whitespace.
    CONSTRAINT feedback_message_check
        CHECK (octet_length(message) BETWEEN 1 AND 10240 AND message ~ '[^[:space:]]'),
    CONSTRAINT feedback_cli_version_check CHECK (char_length(cli_version) BETWEEN 1 AND 64),
    CONSTRAINT feedback_os_check CHECK (char_length(os) BETWEEN 1 AND 32),
    CONSTRAINT feedback_arch_check CHECK (char_length(arch) BETWEEN 1 AND 32),
    CONSTRAINT feedback_placement_check
        CHECK (placement = ANY (ARRAY['local'::text, 'cloud'::text])),
    CONSTRAINT feedback_environment_id_check
        CHECK (environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    CONSTRAINT feedback_client_address_hash_check
        CHECK (client_address_hash ~ '^[0-9a-f]{64}$'),
    -- An anonymous row names no organization.
    CONSTRAINT feedback_organization_needs_user_check
        CHECK (organization_id IS NULL OR user_id IS NOT NULL)
);

-- The admin list, newest first.
CREATE INDEX feedback_created_at_idx
    ON public.feedback USING btree (created_at DESC, id DESC);

-- The per-user limit.
CREATE INDEX feedback_user_created_at_idx
    ON public.feedback USING btree (user_id, created_at)
    WHERE (user_id IS NOT NULL);

-- The per-address limit for anonymous senders.
CREATE INDEX feedback_anonymous_address_created_at_idx
    ON public.feedback USING btree (client_address_hash, created_at)
    WHERE (user_id IS NULL);
