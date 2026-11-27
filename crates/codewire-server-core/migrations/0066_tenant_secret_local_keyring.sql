-- Allow the explicit `local-keyring` KEK provider for self-hosted tenant
-- secrets (#4121). Each provider stays bound to its own wrapped_dek prefix
-- (`vault:vN:...` vs `local:vN:...`) and matching key_version.
ALTER TABLE public.tenant_secret_deks
    DROP CONSTRAINT tenant_secret_deks_provider_check,
    DROP CONSTRAINT tenant_secret_deks_wrapped_shape_check,
    ADD CONSTRAINT tenant_secret_deks_provider_check
        CHECK ((provider = ANY (ARRAY['openbao-transit'::text, 'local-keyring'::text]))),
    ADD CONSTRAINT tenant_secret_deks_wrapped_shape_check
        CHECK (
            (length(wrapped_dek) >= 12)
            AND (length(wrapped_dek) <= 4096)
            AND (
                ((provider = 'openbao-transit'::text) AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text))
                OR ((provider = 'local-keyring'::text) AND (wrapped_dek ~ '^local:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text))
            )
            AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text))
        );

ALTER TABLE public.tenant_secret_kek_canary
    DROP CONSTRAINT tenant_secret_kek_canary_provider_check,
    DROP CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check,
    ADD CONSTRAINT tenant_secret_kek_canary_provider_check
        CHECK ((provider = ANY (ARRAY['openbao-transit'::text, 'local-keyring'::text]))),
    ADD CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check
        CHECK (
            (length(expected_authority_id) >= 1)
            AND (length(expected_authority_id) <= 255)
            AND (expected_authority_id ~ '^[A-Za-z0-9_.:-]+$'::text)
            AND (length(wrapped_dek) >= 12)
            AND (length(wrapped_dek) <= 4096)
            AND (
                ((provider = 'openbao-transit'::text) AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text))
                OR ((provider = 'local-keyring'::text) AND (wrapped_dek ~ '^local:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text))
            )
            AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text))
        );
