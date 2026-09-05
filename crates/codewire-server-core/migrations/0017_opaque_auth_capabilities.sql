-- Persist only fixed-size digests for bearer capabilities owned by the IdP
-- and organization invitation flow. This is a deliberate pre-launch clean
-- cutover: already-issued ephemeral capabilities are invalidated rather than
-- copied into the current representation. In-flight authorization requests
-- which have not issued a code remain valid.

TRUNCATE TABLE public.verifications;
ALTER TABLE public.verifications
    DROP COLUMN value,
    ADD COLUMN purpose text NOT NULL,
    ADD COLUMN token_hash text NOT NULL,
    ADD CONSTRAINT verifications_purpose_check CHECK (
        purpose IN ('email_verification', 'password_reset')
    ),
    ADD CONSTRAINT verifications_token_hash_format_check CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT verifications_purpose_token_hash_key UNIQUE (purpose, token_hash);

TRUNCATE TABLE public.two_factor_tokens;
DROP INDEX public.idx_two_factor_tokens_token;
ALTER TABLE public.two_factor_tokens
    DROP CONSTRAINT two_factor_tokens_token_key,
    DROP COLUMN token,
    ADD COLUMN token_hash text NOT NULL,
    ADD CONSTRAINT two_factor_tokens_token_hash_format_check CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT two_factor_tokens_token_hash_key UNIQUE (token_hash);

DELETE FROM public.oidc_auth_requests WHERE code IS NOT NULL;
DROP INDEX public.oidc_auth_requests_code_idx;
ALTER TABLE public.oidc_auth_requests
    DROP CONSTRAINT oidc_auth_requests_code_key,
    DROP COLUMN code,
    ADD COLUMN code_hash text,
    ADD CONSTRAINT oidc_auth_requests_code_hash_format_check CHECK (
        code_hash IS NULL OR code_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT oidc_auth_requests_code_hash_key UNIQUE (code_hash);
CREATE INDEX oidc_auth_requests_code_hash_idx
    ON public.oidc_auth_requests (code_hash)
    WHERE code_hash IS NOT NULL;

TRUNCATE TABLE public.oidc_device_authorizations;
DROP INDEX public.oidc_device_authorizations_user_code_idx;
ALTER TABLE public.oidc_device_authorizations
    DROP CONSTRAINT oidc_device_authorizations_pkey,
    DROP CONSTRAINT oidc_device_authorizations_user_code_key,
    DROP COLUMN device_code,
    DROP COLUMN user_code,
    ADD COLUMN device_code_hash text NOT NULL,
    ADD COLUMN user_code_hash text NOT NULL,
    ADD CONSTRAINT oidc_device_authorizations_device_code_hash_format_check CHECK (
        device_code_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT oidc_device_authorizations_user_code_hash_format_check CHECK (
        user_code_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT oidc_device_authorizations_pkey PRIMARY KEY (device_code_hash),
    ADD CONSTRAINT oidc_device_authorizations_user_code_hash_key UNIQUE (user_code_hash);
CREATE INDEX oidc_device_authorizations_user_code_hash_idx
    ON public.oidc_device_authorizations (user_code_hash);

TRUNCATE TABLE public.org_invitations;
ALTER TABLE public.org_invitations
    DROP CONSTRAINT org_invitations_token_key,
    DROP COLUMN token,
    ADD COLUMN token_hash text NOT NULL,
    ADD CONSTRAINT org_invitations_token_hash_format_check CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT org_invitations_token_hash_key UNIQUE (token_hash);
