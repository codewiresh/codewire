-- Finalize the pre-GA OpenBao-only secret contract. This is intentionally
-- destructive and fails before changing schema unless all retired product
-- stores are empty. There is no data import: Dev has no retained customer
-- data and new writes use encrypted PostgreSQL envelopes only. Applying this
-- migration is the forward-only rollback boundary for pre-finalization images.
DO $preflight$
BEGIN
    IF EXISTS (SELECT 1 FROM public.local_secrets) THEN
        RAISE EXCEPTION 'OpenBao native-secret finalization requires local_secrets=0';
    END IF;
    IF EXISTS (SELECT 1 FROM public.tenant_secrets) THEN
        RAISE EXCEPTION 'OpenBao native-secret finalization requires tenant_secrets=0';
    END IF;
    IF EXISTS (SELECT 1 FROM public.tenant_secret_deks) THEN
        RAISE EXCEPTION 'OpenBao native-secret finalization requires tenant_secret_deks=0';
    END IF;
END
$preflight$;

-- The readiness canary is not product data. Recreate it on first startup using
-- the sole configured OpenBao Transit authority and the finalized shape.
DELETE FROM public.tenant_secret_kek_canary;

DROP TABLE public.local_secrets;
DROP TABLE public.tenant_secret_control;

ALTER TABLE public.tenant_secret_deks
    DROP CONSTRAINT tenant_secret_deks_provider_check,
    DROP CONSTRAINT tenant_secret_deks_wrapped_shape_check,
    DROP COLUMN wrapped_nonce,
    ADD CONSTRAINT tenant_secret_deks_provider_check CHECK (
        provider = 'openbao-transit'
    ),
    ADD CONSTRAINT tenant_secret_deks_wrapped_shape_check CHECK (
        length(wrapped_dek) BETWEEN 12 AND 4096
        AND wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'
        AND split_part(wrapped_dek, ':', 2) = 'v' || key_version::text
    );

ALTER TABLE public.tenant_secret_kek_canary
    DROP CONSTRAINT tenant_secret_kek_canary_provider_check,
    DROP CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check,
    DROP COLUMN wrapped_nonce,
    ALTER COLUMN expected_authority_id SET NOT NULL,
    ADD CONSTRAINT tenant_secret_kek_canary_provider_check CHECK (
        provider = 'openbao-transit'
    ),
    ADD CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check CHECK (
        length(expected_authority_id) BETWEEN 1 AND 255
        AND expected_authority_id ~ '^[A-Za-z0-9_.:-]+$'
        AND length(wrapped_dek) BETWEEN 12 AND 4096
        AND wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'
        AND split_part(wrapped_dek, ':', 2) = 'v' || key_version::text
    );

DROP TRIGGER confidential_storage_openbao_path_compat
    ON public.confidential_storage_keys;
DROP FUNCTION public.populate_confidential_storage_openbao_path();
ALTER TABLE public.confidential_storage_keys
    DROP COLUMN infisical_path;
