-- Encrypted tenant-secret storage. This migration is additive: Infisical
-- remains authoritative until the separately controlled import and cutover,
-- and local_secrets remains available for source rollback.

-- One immutable DEK identity per organization or user scope. Project paths
-- intentionally share their owning organization's DEK, while each envelope's
-- AAD still binds the exact project path and secret key.
CREATE TABLE public.tenant_secret_deks (
    dek_id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scope text NOT NULL,
    scope_id text NOT NULL,
    provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek text NOT NULL,
    wrapped_nonce bytea,
    format smallint DEFAULT 1 NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_secret_deks_scope_key UNIQUE (scope, scope_id),
    CONSTRAINT tenant_secret_deks_identity_key UNIQUE (dek_id, scope, scope_id),
    CONSTRAINT tenant_secret_deks_scope_check CHECK (scope IN ('org', 'user')),
    CONSTRAINT tenant_secret_deks_scope_id_check CHECK (
        length(scope_id) BETWEEN 1 AND 255
        AND scope_id ~ '^[A-Za-z0-9_-]+$'
    ),
    CONSTRAINT tenant_secret_deks_provider_check CHECK (
        provider IN ('keyring', 'openbao-transit')
    ),
    CONSTRAINT tenant_secret_deks_key_name_check CHECK (key_name = 'tenant-dek'),
    CONSTRAINT tenant_secret_deks_key_version_check CHECK (
        key_version BETWEEN 1 AND 4294967295
    ),
    CONSTRAINT tenant_secret_deks_format_check CHECK (format = 1),
    CONSTRAINT tenant_secret_deks_revision_check CHECK (revision > 0),
    CONSTRAINT tenant_secret_deks_wrapped_shape_check CHECK (
        (
            provider = 'keyring'
            AND wrapped_nonce IS NOT NULL
            AND octet_length(wrapped_nonce) = 12
            AND length(wrapped_dek) = 64
            AND wrapped_dek ~ '^[A-Za-z0-9+/]+={0,2}$'
            AND octet_length(decode(wrapped_dek, 'base64')) = 48
        ) OR (
            provider = 'openbao-transit'
            AND wrapped_nonce IS NULL
            AND length(wrapped_dek) BETWEEN 12 AND 4096
            AND wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'
            AND split_part(wrapped_dek, ':', 2) = 'v' || key_version::text
        )
    )
);

-- Redundant scope columns make cross-tenant DEK assignment impossible at the
-- foreign-key boundary. The path constraint also binds each stored path to
-- that scope before application-level AES-GCM authentication is attempted.
CREATE TABLE public.tenant_secrets (
    path text NOT NULL,
    key text NOT NULL,
    dek_id text NOT NULL,
    scope text NOT NULL,
    scope_id text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (path, key),
    CONSTRAINT tenant_secrets_dek_scope_fkey
        FOREIGN KEY (dek_id, scope, scope_id)
        REFERENCES public.tenant_secret_deks (dek_id, scope, scope_id),
    CONSTRAINT tenant_secrets_key_check CHECK (
        length(key) BETWEEN 1 AND 255
        AND key ~ '^[A-Za-z0-9_]+$'
    ),
    CONSTRAINT tenant_secrets_payload_check CHECK (
        octet_length(ciphertext) >= 16
        AND octet_length(nonce) = 12
        AND format = 1
    ),
    CONSTRAINT tenant_secrets_path_scope_check CHECK (
        (
            scope = 'org'
            AND (
                path = '/org-secrets/' || scope_id
                OR path ~ (
                    '^/projects/' || scope_id || '/[A-Za-z0-9_-]{1,255}$'
                )
            )
        ) OR (
            scope = 'user'
            AND path = '/users/' || scope_id
        )
    )
);

CREATE INDEX tenant_secrets_dek_id_idx
    ON public.tenant_secrets (dek_id);

-- A singleton canary proves that the configured provider can unwrap data
-- previously persisted by this database. Its DEK always uses the fixed
-- canary/tenant-secret scope under the codewire/tenant-dek-context/v1 domain;
-- only its digest is stored.
CREATE TABLE public.tenant_secret_kek_canary (
    singleton boolean PRIMARY KEY DEFAULT true,
    provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek text NOT NULL,
    wrapped_nonce bytea,
    format smallint DEFAULT 1 NOT NULL,
    expected_authority_id text,
    plaintext_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    CONSTRAINT tenant_secret_kek_canary_singleton_check CHECK (singleton),
    CONSTRAINT tenant_secret_kek_canary_provider_check CHECK (
        provider IN ('keyring', 'openbao-transit')
    ),
    CONSTRAINT tenant_secret_kek_canary_key_name_check CHECK (key_name = 'tenant-dek'),
    CONSTRAINT tenant_secret_kek_canary_key_version_check CHECK (
        key_version BETWEEN 1 AND 4294967295
    ),
    CONSTRAINT tenant_secret_kek_canary_digest_check CHECK (
        octet_length(plaintext_sha256) = 32
    ),
    CONSTRAINT tenant_secret_kek_canary_format_check CHECK (format = 1),
    CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check CHECK (
        (
            provider = 'keyring'
            AND expected_authority_id IS NULL
            AND wrapped_nonce IS NOT NULL
            AND octet_length(wrapped_nonce) = 12
            AND length(wrapped_dek) = 64
            AND wrapped_dek ~ '^[A-Za-z0-9+/]+={0,2}$'
            AND octet_length(decode(wrapped_dek, 'base64')) = 48
        ) OR (
            provider = 'openbao-transit'
            AND expected_authority_id IS NOT NULL
            AND length(expected_authority_id) BETWEEN 1 AND 255
            AND expected_authority_id ~ '^[A-Za-z0-9_.:-]+$'
            AND wrapped_nonce IS NULL
            AND length(wrapped_dek) BETWEEN 12 AND 4096
            AND wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'
            AND split_part(wrapped_dek, ':', 2) = 'v' || key_version::text
        )
    )
);

-- The singleton authority row is the durable cutover fence. Writes are
-- admitted only in infisical or postgres; importing and postgres-readonly are
-- mutation-fenced states used by the forward-only equality/proof sequence.
CREATE TABLE public.tenant_secret_control (
    singleton boolean PRIMARY KEY DEFAULT true,
    state text DEFAULT 'infisical' NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    source_revision text,
    transition_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_secret_control_singleton_check CHECK (singleton),
    CONSTRAINT tenant_secret_control_state_check CHECK (
        state IN ('infisical', 'importing', 'postgres-readonly', 'postgres')
    ),
    CONSTRAINT tenant_secret_control_generation_check CHECK (generation >= 0),
    CONSTRAINT tenant_secret_control_transition_check CHECK (
        state = 'infisical'
        OR (
            source_revision IS NOT NULL
            AND length(source_revision) BETWEEN 1 AND 1024
            AND transition_started_at IS NOT NULL
        )
    ),
    CONSTRAINT tenant_secret_control_verification_check CHECK (
        state <> 'postgres'
        OR verified_at IS NOT NULL
    )
);

INSERT INTO public.tenant_secret_control (singleton) VALUES (true);
