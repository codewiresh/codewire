-- Replace the never-consumed schema-v1 alias contract with the content-bound
-- schema-v2 contract. The manifest-aware source was not deployed before this
-- migration; fail closed if an installation contradicts that admission fact.
DO $preflight$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.confidential_storage_keys
        WHERE manifest_uri IS NOT NULL
           OR volume_id IS NOT NULL
           OR volume_version IS NOT NULL
           OR manifest_schema_version IS NOT NULL
           OR device_size_bytes IS NOT NULL
           OR luks_uuid IS NOT NULL
           OR protection_profile IS NOT NULL
           OR backing_claim_name IS NOT NULL
           OR manifest_sha256_fingerprint IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'schema-v2 confidential storage admission requires no populated manifest tuples';
    END IF;
END
$preflight$;

DROP TRIGGER confidential_storage_manifest_immutability
    ON public.confidential_storage_keys;
DROP FUNCTION public.enforce_confidential_storage_manifest_immutability();
ALTER TABLE public.confidential_storage_keys
    DROP CONSTRAINT confidential_storage_manifest_tuple_check;

-- A row progresses monotonically through three non-secret states:
-- legacy metadata, immutable volume core, and fully content-bound manifest.
-- The OpenBao recovery-key fingerprint may predate the volume core, but the
-- KBS manifest cannot be published until both fingerprints and the exact URI
-- are committed atomically by the application.
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
            volume_id IS NOT NULL
            AND volume_version IS NOT NULL
            AND manifest_schema_version IS NOT NULL
            AND device_size_bytes IS NOT NULL
            AND luks_uuid IS NOT NULL
            AND protection_profile IS NOT NULL
            AND backing_claim_name IS NOT NULL
            AND volume_id = environment_id
            AND manifest_schema_version = 2
            AND volume_version = environment_id || '-v2'
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
           NEW.backing_claim_name
       ) IS DISTINCT FROM ROW(
           OLD.volume_id,
           OLD.volume_version,
           OLD.manifest_schema_version,
           OLD.device_size_bytes,
           OLD.luks_uuid,
           OLD.protection_profile,
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
    backing_claim_name,
    manifest_sha256_fingerprint
ON public.confidential_storage_keys
FOR EACH ROW
EXECUTE FUNCTION public.enforce_confidential_storage_manifest_immutability();
