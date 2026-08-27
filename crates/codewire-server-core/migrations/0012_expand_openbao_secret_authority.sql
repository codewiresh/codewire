-- Expand the secret-authority schema before the OpenBao-only application
-- source consumes it. The retired recovery column remains temporarily so the
-- immediately preceding application image can still reconcile or delete an
-- environment during the deployment rollback window.
ALTER TABLE public.confidential_storage_keys
    ADD COLUMN openbao_path text;

UPDATE public.confidential_storage_keys
SET openbao_path = 'confidential-storage/' || environment_id;

ALTER TABLE public.confidential_storage_keys
    ALTER COLUMN openbao_path SET NOT NULL,
    ADD CONSTRAINT confidential_storage_keys_openbao_path_check CHECK (
        openbao_path = 'confidential-storage/' || environment_id
    );

-- The immediately preceding application source does not know about
-- openbao_path, while the next source deliberately no longer names the
-- retired column. Keep both INSERT shapes valid during the rollout window
-- while ensuring every new row has both canonical compatibility values.
CREATE FUNCTION public.populate_confidential_storage_openbao_path()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.openbao_path IS NULL THEN
        NEW.openbao_path := 'confidential-storage/' || NEW.environment_id;
    END IF;

    IF NEW.infisical_path IS NULL THEN
        NEW.infisical_path := '/confidential-storage/' || NEW.environment_id;
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER confidential_storage_openbao_path_compat
BEFORE INSERT ON public.confidential_storage_keys
FOR EACH ROW
EXECUTE FUNCTION public.populate_confidential_storage_openbao_path();

-- The current application already supports the local tenant-secret store.
-- Make that inactive source canonical while retaining the previous state in
-- the constraint only for rollback compatibility. The consuming source will
-- remove the external provider implementation; a later contract migration
-- can remove its dormant state and metadata after the rollback window closes.
ALTER TABLE public.tenant_secret_control
    DROP CONSTRAINT tenant_secret_control_state_check,
    DROP CONSTRAINT tenant_secret_control_transition_check;

UPDATE public.tenant_secret_control
SET state = CASE WHEN state = 'postgres' THEN 'postgres' ELSE 'local' END,
    source_revision = CASE WHEN state = 'postgres' THEN source_revision ELSE NULL END,
    transition_started_at = CASE
        WHEN state = 'postgres' THEN transition_started_at ELSE NULL
    END,
    verified_at = CASE WHEN state = 'postgres' THEN verified_at ELSE NULL END,
    updated_at = now();

ALTER TABLE public.tenant_secret_control
    ALTER COLUMN state SET DEFAULT 'local',
    ADD CONSTRAINT tenant_secret_control_state_check CHECK (
        state IN ('infisical', 'local', 'importing', 'postgres-readonly', 'postgres')
    ),
    ADD CONSTRAINT tenant_secret_control_transition_check CHECK (
        state IN ('infisical', 'local')
        OR (
            source_revision IS NOT NULL
            AND length(source_revision) BETWEEN 1 AND 1024
            AND transition_started_at IS NOT NULL
        )
    );

-- Add the non-secret manifest contract without requiring the current source
-- to populate it. Existing and newly created rows may remain entirely NULL
-- until the manifest-aware source reconciles them. Once populated, the tuple
-- is complete and its security identity is write-once.
ALTER TABLE public.confidential_storage_keys
    ADD COLUMN manifest_uri text,
    ADD COLUMN volume_id text,
    ADD COLUMN volume_version text,
    ADD COLUMN manifest_schema_version integer,
    ADD COLUMN device_size_bytes bigint,
    ADD COLUMN luks_uuid text,
    ADD COLUMN protection_profile text,
    ADD COLUMN backing_claim_name text,
    ADD COLUMN manifest_sha256_fingerprint text;

ALTER TABLE public.confidential_storage_keys
    ADD CONSTRAINT confidential_storage_manifest_tuple_check CHECK (
        (
            manifest_uri IS NULL
            AND volume_id IS NULL
            AND volume_version IS NULL
            AND manifest_schema_version IS NULL
            AND device_size_bytes IS NULL
            AND luks_uuid IS NULL
            AND protection_profile IS NULL
            AND backing_claim_name IS NULL
            AND manifest_sha256_fingerprint IS NULL
        )
        OR
        (
            manifest_uri IS NOT NULL
            AND volume_id IS NOT NULL
            AND volume_version IS NOT NULL
            AND manifest_schema_version IS NOT NULL
            AND device_size_bytes IS NOT NULL
            AND luks_uuid IS NOT NULL
            AND protection_profile IS NOT NULL
            AND backing_claim_name IS NOT NULL
            AND volume_id = environment_id
            AND manifest_schema_version = 1
            AND volume_version = environment_id || '-v1'
            AND manifest_uri =
                'kbs:///default/codewire-storage-manifests/' || volume_version
            AND device_size_bytes > 0
            AND device_size_bytes % 4096 = 0
            AND luks_uuid ~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND protection_profile = 'luks2-integrity-rw'
            AND backing_claim_name = 'workspace'
            AND (
                manifest_sha256_fingerprint IS NULL
                OR manifest_sha256_fingerprint ~ '^[0-9a-f]{64}$'
            )
        )
    );

CREATE FUNCTION public.enforce_confidential_storage_manifest_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.manifest_uri IS NOT NULL
       AND ROW(
           NEW.manifest_uri,
           NEW.volume_id,
           NEW.volume_version,
           NEW.manifest_schema_version,
           NEW.device_size_bytes,
           NEW.luks_uuid,
           NEW.protection_profile,
           NEW.backing_claim_name
       ) IS DISTINCT FROM ROW(
           OLD.manifest_uri,
           OLD.volume_id,
           OLD.volume_version,
           OLD.manifest_schema_version,
           OLD.device_size_bytes,
           OLD.luks_uuid,
           OLD.protection_profile,
           OLD.backing_claim_name
       ) THEN
        RAISE EXCEPTION 'confidential storage manifest identity is immutable';
    END IF;

    IF OLD.manifest_sha256_fingerprint IS NOT NULL
       AND NEW.manifest_sha256_fingerprint IS DISTINCT FROM
           OLD.manifest_sha256_fingerprint THEN
        RAISE EXCEPTION 'confidential storage manifest fingerprint is immutable';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER confidential_storage_manifest_immutability
BEFORE UPDATE OF
    manifest_uri,
    volume_id,
    volume_version,
    manifest_schema_version,
    device_size_bytes,
    luks_uuid,
    protection_profile,
    backing_claim_name,
    manifest_sha256_fingerprint
ON public.confidential_storage_keys
FOR EACH ROW
EXECUTE FUNCTION public.enforce_confidential_storage_manifest_immutability();
