-- Ordinary UID1000 cw selector requests, separate from workspace lifecycle
-- and from the unchanged ordinary Store. Prior migration bytes are immutable.
-- Evidence has no cascading owner/environment/Pod foreign key: an uncertain
-- command must remain attributable after those resources disappear.
CREATE TABLE public.environment_cw_runtime_requests (
    request_id uuid PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    organization_id text NOT NULL CHECK (octet_length(organization_id) BETWEEN 1 AND 128),
    environment_id text NOT NULL CHECK (environment_id ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    actor_user_id text NOT NULL CHECK (octet_length(actor_user_id) BETWEEN 1 AND 128),
    via_api_key boolean NOT NULL,
    delegated_organization_id text CHECK (octet_length(delegated_organization_id) BETWEEN 1 AND 128),
    pod_uid uuid NOT NULL CHECK (pod_uid <> '00000000-0000-0000-0000-000000000000'),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    request_json jsonb NOT NULL CHECK (
        jsonb_typeof(request_json) = 'object' AND octet_length(request_json::text) <= 32768),
    binding_json jsonb NOT NULL CHECK (
        jsonb_typeof(binding_json) = 'object' AND octet_length(binding_json::text) <= 32768),
    -- Canonical decimal text preserves the ordinary Store's complete u64
    -- domain without an i64 cast, floating-point JSON or a new SQLx feature.
    expected_store_generation text NOT NULL CHECK (
        expected_store_generation ~ '^(0|[1-9][0-9]{0,19})$'
        AND (length(expected_store_generation) < 20
             OR expected_store_generation COLLATE "C" <= '18446744073709551615')),
    owner_id uuid NOT NULL CHECK (owner_id <> '00000000-0000-0000-0000-000000000000'),
    mutation_lease_id text NOT NULL UNIQUE CHECK (octet_length(mutation_lease_id) BETWEEN 1 AND 128),
    phase text NOT NULL DEFAULT 'admitted' CHECK (
        phase IN ('admitted','issued','acknowledged','succeeded','failed','unknown')),
    checkpoint integer NOT NULL DEFAULT 0 CHECK (checkpoint BETWEEN 0 AND 16),
    effect text CHECK (effect IN ('bootstrap','staging','update','rollback','cleanup')),
    acknowledgements jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(acknowledgements) = 'array'
        AND jsonb_array_length(acknowledgements) <= 16
        AND octet_length(acknowledgements::text) <= 32768),
    error_code text CHECK (error_code ~ '^[a-z0-9_]{1,96}$'),
    admitted_at timestamptz NOT NULL DEFAULT now(),
    issued_at timestamptz,
    terminal_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT environment_cw_runtime_request_delegation CHECK ((
        (via_api_key AND delegated_organization_id = organization_id)
        OR (NOT via_api_key AND delegated_organization_id IS NULL)) IS TRUE),
    CONSTRAINT environment_cw_runtime_request_coordinates CHECK ((
        binding_json->>'organization_id' = organization_id
        AND binding_json->>'environment_id' = environment_id
        AND binding_json->>'pod_uid' = pod_uid::text
        AND jsonb_typeof(request_json->'expected_store_generation') = 'string'
        AND request_json->>'expected_store_generation' = expected_store_generation) IS TRUE),
    CONSTRAINT environment_cw_runtime_request_phase_metadata CHECK ((
        (phase = 'admitted' AND checkpoint = 0 AND effect IS NULL
         AND issued_at IS NULL AND terminal_at IS NULL AND error_code IS NULL
         AND jsonb_array_length(acknowledgements) = 0)
        OR (phase = 'issued' AND checkpoint > 0 AND effect IS NOT NULL
            AND issued_at IS NOT NULL AND terminal_at IS NULL AND error_code IS NULL
            AND jsonb_array_length(acknowledgements) = checkpoint - 1)
        OR (phase = 'acknowledged' AND checkpoint > 0 AND effect IS NOT NULL
            AND issued_at IS NOT NULL AND terminal_at IS NULL AND error_code IS NULL
            AND jsonb_array_length(acknowledgements) = checkpoint)
        OR (phase = 'succeeded' AND checkpoint > 0 AND effect IN ('update','rollback','cleanup')
            AND issued_at IS NOT NULL AND terminal_at IS NOT NULL AND error_code IS NULL
            AND jsonb_array_length(acknowledgements) = checkpoint)
        OR (phase = 'failed' AND terminal_at IS NOT NULL AND error_code IS NOT NULL
            AND ((checkpoint = 0 AND effect IS NULL AND issued_at IS NULL
                  AND jsonb_array_length(acknowledgements) = 0)
                 OR (checkpoint > 0 AND effect IS NOT NULL AND issued_at IS NOT NULL
                     AND jsonb_array_length(acknowledgements) IN (checkpoint - 1, checkpoint))))
        OR (phase = 'unknown' AND checkpoint > 0 AND effect IS NOT NULL
            AND issued_at IS NOT NULL AND terminal_at IS NOT NULL AND error_code IS NOT NULL
            AND jsonb_array_length(acknowledgements) = checkpoint - 1)
    ) IS TRUE)
);

-- An uncertain owner cannot be overtaken by a replacement incarnation.
CREATE UNIQUE INDEX environment_cw_runtime_one_unresolved_owner
    ON public.environment_cw_runtime_requests (environment_id)
    WHERE phase IN ('admitted','issued','acknowledged','unknown');
CREATE INDEX environment_cw_runtime_organization_requests
    ON public.environment_cw_runtime_requests (organization_id, environment_id, admitted_at);

CREATE FUNCTION public.codewire_cw_runtime_request_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime request evidence is retained';
    END IF;
    IF ROW(NEW.request_id,NEW.organization_id,NEW.environment_id,NEW.actor_user_id,
           NEW.via_api_key,NEW.delegated_organization_id,
           NEW.pod_uid,NEW.fingerprint,NEW.request_json,NEW.binding_json,
           NEW.expected_store_generation,NEW.owner_id,NEW.mutation_lease_id,NEW.admitted_at)
       IS DISTINCT FROM
       ROW(OLD.request_id,OLD.organization_id,OLD.environment_id,OLD.actor_user_id,
           OLD.via_api_key,OLD.delegated_organization_id,
           OLD.pod_uid,OLD.fingerprint,OLD.request_json,OLD.binding_json,
           OLD.expected_store_generation,OLD.owner_id,OLD.mutation_lease_id,OLD.admitted_at) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime request identity is immutable';
    END IF;
    IF OLD.phase IN ('succeeded','failed','unknown') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime terminal evidence is immutable';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    IF NOT (
        (OLD.phase IN ('admitted','acknowledged') AND NEW.phase = 'issued'
         AND NEW.checkpoint = OLD.checkpoint + 1
         AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'issued' AND NEW.phase = 'acknowledged'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at
            AND jsonb_array_length(NEW.acknowledgements) = jsonb_array_length(OLD.acknowledgements) + 1
            AND NEW.acknowledgements - (jsonb_array_length(NEW.acknowledgements) - 1) = OLD.acknowledgements)
        OR (OLD.phase = 'acknowledged' AND NEW.phase = 'succeeded'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'admitted' AND NEW.phase = 'failed'
            AND NEW.checkpoint = 0 AND NEW.effect IS NULL AND NEW.issued_at IS NULL
            AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'acknowledged' AND NEW.phase = 'failed'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'issued' AND NEW.phase IN ('failed','unknown')
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime checkpoint cannot be replayed';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER environment_cw_runtime_request_immutable
    BEFORE UPDATE OR DELETE ON public.environment_cw_runtime_requests
    FOR EACH ROW EXECUTE FUNCTION public.codewire_cw_runtime_request_immutable();
REVOKE ALL ON FUNCTION public.codewire_cw_runtime_request_immutable() FROM PUBLIC;
