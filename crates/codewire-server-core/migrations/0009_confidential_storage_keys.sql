-- Non-secret lifecycle metadata for per-environment confidential workspace keys.
--
-- This migration is deliberately additive. A source rollback can continue to
-- read and destroy environments while the metadata remains available for a
-- later forward recovery; rollback must never drop this table or key-provider
-- references while confidential storage may still exist.
CREATE TABLE public.confidential_storage_keys (
    environment_id text PRIMARY KEY REFERENCES public.environments(id) ON DELETE CASCADE,
    kbs_uri text NOT NULL,
    infisical_path text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    sha256_fingerprint text,
    state text DEFAULT 'provisioning'::text NOT NULL,
    last_redacted_error text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    ready_at timestamp without time zone,
    deleting_at timestamp without time zone,
    deleted_at timestamp without time zone,
    CONSTRAINT confidential_storage_keys_version_check CHECK (version > 0),
    CONSTRAINT confidential_storage_keys_fingerprint_check CHECK (
        sha256_fingerprint IS NULL
        OR sha256_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT confidential_storage_keys_state_check CHECK (
        state IN ('provisioning', 'ready', 'deleting', 'deleted', 'error')
    ),
    CONSTRAINT confidential_storage_keys_uri_check CHECK (
        kbs_uri = 'kbs:///default/codewire-workspace-luks/' || environment_id
    ),
    CONSTRAINT confidential_storage_keys_path_check CHECK (
        infisical_path = '/confidential-storage/' || environment_id
    )
);

CREATE INDEX confidential_storage_keys_state_idx
    ON public.confidential_storage_keys (state, updated_at);
