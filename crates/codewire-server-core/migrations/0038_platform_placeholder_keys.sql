-- Hosted placeholder keys (#4001): one sealed key per environment, under
-- which the credential service derives that environment's credential
-- placeholders (docs/dev/SECRETS-AND-CREDENTIALS.md, "Per-environment
-- placeholders"). A placeholder itself is never stored.
--
-- The credential service creates an environment's row on its first lease
-- with placeholders on, with INSERT ... ON CONFLICT DO NOTHING, and from then
-- on only reads it: a key never changes. The envelope is sealed like
-- platform_credential_material: a DEK wrapped by the credential-material KEK
-- and AES-GCM ciphertext whose associated data names the environment, so a
-- row copied to another environment does not open. The key goes when the
-- environment's row is deleted (the cascade below); a destroyed environment
-- keeps it until that row is purged. Its restricted role is granted SELECT and
-- INSERT only, outside this history (tests/e2e/kind/credential-broker.sql and
-- infra's credential database grants).
--
-- Compatible: the table is new, and older code reads nothing from it.
-- Rollback drops the table, which changes every hosted placeholder; a stale
-- placeholder matches nothing and fails closed.

CREATE TABLE public.platform_placeholder_keys (
    environment_id text NOT NULL,
    kek_provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek bytea NOT NULL,
    wrapped_format smallint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_placeholder_keys_pkey PRIMARY KEY (environment_id),
    CONSTRAINT platform_placeholder_keys_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    -- A 32-byte key and AES-GCM's 16-byte tag.
    CONSTRAINT platform_placeholder_keys_ciphertext_check CHECK ((octet_length(ciphertext) = 48)),
    CONSTRAINT platform_placeholder_keys_format_check CHECK ((format = 1)),
    CONSTRAINT platform_placeholder_keys_kek_provider_check CHECK ((kek_provider = 'openbao-transit'::text)),
    CONSTRAINT platform_placeholder_keys_key_version_check CHECK (((key_version > 0) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT platform_placeholder_keys_nonce_check CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT platform_placeholder_keys_wrapped_dek_check CHECK (((octet_length(wrapped_dek) >= 1) AND (octet_length(wrapped_dek) <= 65536))),
    CONSTRAINT platform_placeholder_keys_wrapped_format_check CHECK ((wrapped_format = 1))
);

REVOKE ALL ON public.platform_placeholder_keys FROM PUBLIC;
