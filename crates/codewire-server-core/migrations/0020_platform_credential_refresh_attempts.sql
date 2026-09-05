-- One durable attempt per credential serializes OAuth rotation across broker
-- replicas. Only an expired reservation that has not started can be reclaimed.
-- A started provider request is never reassigned: ambiguous outcomes require
-- owner re-enrollment, while staged results can be recovered without resending.
CREATE TABLE public.platform_credential_refresh_attempts (
    credential_id text PRIMARY KEY REFERENCES public.platform_credentials(id) ON DELETE CASCADE,
    attempt_id uuid NOT NULL UNIQUE CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    expected_revocation_generation bigint NOT NULL CHECK (
        expected_revocation_generation > 0 AND expected_revocation_generation < 9223372036854775807
    ),
    expected_material_generation bigint NOT NULL CHECK (
        expected_material_generation > 0 AND expected_material_generation < 9223372036854775807
    ),
    state text NOT NULL CHECK (state IN ('reserved', 'started', 'staged', 'committed', 'unknown', 'cancelled')),
    reserved_until timestamptz NOT NULL,
    started_at timestamptz,
    started_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT platform_credential_refresh_attempts_started_check CHECK (
        (state IN ('reserved', 'cancelled') AND started_at IS NULL AND started_until IS NULL)
        OR (state IN ('started', 'staged', 'committed', 'unknown')
            AND started_at IS NOT NULL AND started_until IS NOT NULL AND started_until > started_at)
    )
);

-- Reserve a wrapped fresh DEK before the provider request. Encryption of the
-- returned material needs no new KEK-provider call, so it can be durably staged
-- even if that provider becomes unavailable after OAuth rotation.
CREATE TABLE public.platform_credential_refresh_material (
    attempt_id uuid PRIMARY KEY REFERENCES public.platform_credential_refresh_attempts(attempt_id) ON DELETE CASCADE,
    kek_provider text NOT NULL CHECK (kek_provider = 'openbao-transit'),
    key_name text NOT NULL,
    key_version bigint NOT NULL CHECK (key_version > 0 AND key_version <= 4294967295),
    wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 65536),
    wrapped_format smallint NOT NULL CHECK (wrapped_format = 1),
    ciphertext bytea CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592),
    nonce bytea CHECK (octet_length(nonce) = 12),
    format smallint CHECK (format = 1),
    CONSTRAINT platform_credential_refresh_material_envelope_check CHECK (
        (ciphertext IS NULL AND nonce IS NULL AND format IS NULL)
        OR (ciphertext IS NOT NULL AND nonce IS NOT NULL AND format IS NOT NULL)
    )
);
