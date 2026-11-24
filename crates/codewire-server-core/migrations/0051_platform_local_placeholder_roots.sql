-- Owner-local placeholder roots (#6191): one sealed root per user, under
-- which the credential service derives the placeholder key of each local VM
-- that user runs on a platform profile (#4909; docs/dev/SECRETS-AND-CREDENTIALS.md,
-- "Per-environment placeholders"). Such a VM has no row in environments, so
-- the hosted per-environment keys (platform_placeholder_keys) cannot serve
-- it. Each VM's key is derived from the root and its environment id; neither
-- the key nor a placeholder is ever stored.
--
-- The credential service creates a user's row on that user's first
-- delegation lease that needs a placeholder, with INSERT ... ON CONFLICT DO
-- NOTHING, and from then on only reads it: a root never changes, and there is
-- no rotation path. The envelope is sealed like platform_credential_material:
-- a DEK wrapped by the credential-material KEK, scoped to the user, and
-- AES-GCM ciphertext whose associated data names the user and this purpose,
-- so a row copied to another user does not open. The root goes when the
-- user's row is deleted (the cascade below). Its restricted role is granted
-- SELECT and INSERT only, outside this history (tests/e2e/kind/credential-broker.sql
-- and infra's credential database grants).
--
-- Compatible: the table is new, and older code reads nothing from it.
-- Rollback drops the table, which changes every owner-local placeholder; a
-- stale placeholder matches nothing and fails closed.

CREATE TABLE public.platform_local_placeholder_roots (
    user_id text NOT NULL,
    kek_provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek bytea NOT NULL,
    wrapped_format smallint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_local_placeholder_roots_pkey PRIMARY KEY (user_id),
    CONSTRAINT platform_local_placeholder_roots_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    -- A 32-byte root and AES-GCM's 16-byte tag.
    CONSTRAINT platform_local_placeholder_roots_ciphertext_check CHECK ((octet_length(ciphertext) = 48)),
    CONSTRAINT platform_local_placeholder_roots_format_check CHECK ((format = 1)),
    CONSTRAINT platform_local_placeholder_roots_kek_provider_check CHECK ((kek_provider = 'openbao-transit'::text)),
    CONSTRAINT platform_local_placeholder_roots_key_version_check CHECK (((key_version > 0) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT platform_local_placeholder_roots_nonce_check CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT platform_local_placeholder_roots_wrapped_dek_check CHECK (((octet_length(wrapped_dek) >= 1) AND (octet_length(wrapped_dek) <= 65536))),
    CONSTRAINT platform_local_placeholder_roots_wrapped_format_check CHECK ((wrapped_format = 1))
);

REVOKE ALL ON public.platform_local_placeholder_roots FROM PUBLIC;
