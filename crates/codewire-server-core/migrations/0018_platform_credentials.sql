-- Typed credential metadata is separate from its protected material. These
-- tables create no delivery binding and import no previous credential model.
CREATE TABLE public.platform_credentials (
    id text PRIMARY KEY,
    user_id text REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id text REFERENCES public.organizations(id) ON DELETE CASCADE,
    provider text NOT NULL,
    authentication_kind text NOT NULL,
    display_name text NOT NULL,
    account_hint text,
    status text NOT NULL,
    expires_at_unix bigint,
    revocation_generation bigint NOT NULL,
    material_generation bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT platform_credentials_owner_check CHECK (
        (user_id IS NOT NULL) <> (organization_id IS NOT NULL)
    ),
    CONSTRAINT platform_credentials_authentication_kind_check CHECK (
        authentication_kind IN ('oauth', 'api_key', 'access_token', 'github_app')
    ),
    CONSTRAINT platform_credentials_status_check CHECK (
        status IN ('active', 'expired', 'refresh_failed', 'revoked')
    ),
    CONSTRAINT platform_credentials_display_name_check CHECK (
        octet_length(display_name) BETWEEN 1 AND 256
    ),
    CONSTRAINT platform_credentials_account_hint_check CHECK (
        octet_length(account_hint) BETWEEN 1 AND 256
    ),
    CONSTRAINT platform_credentials_expiry_check CHECK (expires_at_unix >= 0),
    CONSTRAINT platform_credentials_revocation_generation_check CHECK (
        revocation_generation > 0
    ),
    CONSTRAINT platform_credentials_material_generation_check CHECK (
        material_generation > 0
    ),
    CONSTRAINT platform_credentials_id_material_generation_key UNIQUE (id, material_generation)
);

CREATE UNIQUE INDEX platform_credentials_user_display_name_key
    ON public.platform_credentials (user_id, lower(display_name))
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX platform_credentials_organization_display_name_key
    ON public.platform_credentials (organization_id, lower(display_name))
    WHERE organization_id IS NOT NULL;

-- Each credential owns its own envelope. No generic tenant-secret DEK or
-- plaintext/protected reference is stored in metadata. A replacement removes
-- old material before advancing metadata and inserting the matching envelope,
-- all in one transaction; the immediate composite FK rejects mixed generations.
CREATE TABLE public.platform_credential_material (
    credential_id text PRIMARY KEY,
    material_generation bigint NOT NULL CHECK (material_generation > 0),
    kek_provider text NOT NULL CHECK (kek_provider = 'openbao-transit'),
    key_name text NOT NULL,
    key_version bigint NOT NULL CHECK (key_version > 0 AND key_version <= 4294967295),
    wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 65536),
    wrapped_format smallint NOT NULL CHECK (wrapped_format = 1),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    format smallint NOT NULL CHECK (format = 1),
    CONSTRAINT platform_credential_material_generation_fkey
        FOREIGN KEY (credential_id, material_generation)
        REFERENCES public.platform_credentials(id, material_generation) ON DELETE CASCADE
);
