-- Admit the fixed schema-3/profile-1 guest contract without rewriting any
-- content-addressed schema-2 history. Active schema-2 volumes must be cleaned
-- up with the old runtime before this migration; deleting/deleted rows remain
-- only as immutable lifecycle evidence.
ALTER TABLE public.confidential_storage_keys
    ADD COLUMN protection_profile_version integer;

DO $preflight$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.confidential_storage_keys
        WHERE manifest_schema_version = 2
          AND state NOT IN ('deleting', 'deleted')
    ) THEN
        RAISE EXCEPTION
            'schema-3 confidential storage admission requires no active schema-2 volumes';
    END IF;
END
$preflight$;

DROP TRIGGER confidential_storage_manifest_immutability
    ON public.confidential_storage_keys;
DROP FUNCTION public.enforce_confidential_storage_manifest_immutability();
ALTER TABLE public.confidential_storage_keys
    DROP CONSTRAINT confidential_storage_manifest_tuple_check;

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
            AND protection_profile_version IS NULL
            AND backing_claim_name IS NULL
            AND manifest_sha256_fingerprint IS NULL
        )
        OR
        (
            volume_id IS NOT NULL
            AND volume_version IS NOT NULL
            AND manifest_schema_version IS NOT NULL
            AND device_size_bytes IS NOT NULL
            AND luks_uuid IS NOT NULL
            AND protection_profile IS NOT NULL
            AND backing_claim_name IS NOT NULL
            AND volume_id = environment_id
            AND (
                (
                    manifest_schema_version = 2
                    AND volume_version = environment_id || '-v2'
                    AND protection_profile_version IS NULL
                    AND state IN ('deleting', 'deleted')
                )
                OR
                (
                    manifest_schema_version = 3
                    AND volume_version = environment_id || '-v3'
                    AND protection_profile_version = 1
                )
            )
            AND device_size_bytes > 0
            AND device_size_bytes % 4096 = 0
            AND luks_uuid ~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND protection_profile = 'luks2-integrity-rw'
            AND backing_claim_name = 'workspace'
            AND (
                (
                    manifest_uri IS NULL
                    AND manifest_sha256_fingerprint IS NULL
                )
                OR
                (
                    sha256_fingerprint IS NOT NULL
                    AND manifest_uri IS NOT NULL
                    AND manifest_sha256_fingerprint ~ '^[0-9a-f]{64}$'
                    AND manifest_uri =
                        'kbs:///default/codewire-storage-manifests/sha256-'
                        || manifest_sha256_fingerprint
                )
            )
        )
    );

CREATE FUNCTION public.enforce_confidential_storage_manifest_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.volume_id IS NOT NULL
       AND ROW(
           NEW.volume_id,
           NEW.volume_version,
           NEW.manifest_schema_version,
           NEW.device_size_bytes,
           NEW.luks_uuid,
           NEW.protection_profile,
           NEW.protection_profile_version,
           NEW.backing_claim_name
       ) IS DISTINCT FROM ROW(
           OLD.volume_id,
           OLD.volume_version,
           OLD.manifest_schema_version,
           OLD.device_size_bytes,
           OLD.luks_uuid,
           OLD.protection_profile,
           OLD.protection_profile_version,
           OLD.backing_claim_name
       ) THEN
        RAISE EXCEPTION 'confidential storage volume core is immutable';
    END IF;

    IF OLD.sha256_fingerprint IS NOT NULL
       AND NEW.sha256_fingerprint IS DISTINCT FROM OLD.sha256_fingerprint THEN
        RAISE EXCEPTION 'confidential storage key fingerprint is immutable';
    END IF;

    IF OLD.manifest_uri IS NOT NULL
       AND ROW(NEW.manifest_uri, NEW.manifest_sha256_fingerprint)
           IS DISTINCT FROM
           ROW(OLD.manifest_uri, OLD.manifest_sha256_fingerprint) THEN
        RAISE EXCEPTION 'confidential storage manifest content is immutable';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER confidential_storage_manifest_immutability
BEFORE UPDATE OF
    sha256_fingerprint,
    manifest_uri,
    volume_id,
    volume_version,
    manifest_schema_version,
    device_size_bytes,
    luks_uuid,
    protection_profile,
    protection_profile_version,
    backing_claim_name,
    manifest_sha256_fingerprint
ON public.confidential_storage_keys
FOR EACH ROW
EXECUTE FUNCTION public.enforce_confidential_storage_manifest_immutability();
