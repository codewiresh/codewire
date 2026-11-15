-- Resolving a cw runtime request that ended unknown (#4518). Its row is
-- terminal evidence and kept the environment's one unresolved slot, so every
-- later update of that environment was refused until someone repaired it by
-- hand. A later update may now add, once, what it observed in the sandbox's
-- Store before admitting itself: the request's effect left the selection
-- unchanged, or applied it. The original evidence stays immutable; the
-- resolution is added beside it and frees the slot.
ALTER TABLE public.environment_cw_runtime_requests
    ADD COLUMN resolved_at timestamp with time zone,
    ADD COLUMN resolution text,
    ADD COLUMN resolved_by_request_id uuid,
    ADD COLUMN resolution_selection jsonb,
    ADD CONSTRAINT environment_cw_runtime_request_resolution CHECK ((
        (resolved_at IS NULL AND resolution IS NULL
         AND resolved_by_request_id IS NULL AND resolution_selection IS NULL)
        OR (phase = 'unknown' AND resolved_at IS NOT NULL
            AND resolution = ANY (ARRAY['unchanged'::text, 'applied'::text])
            AND resolved_by_request_id IS NOT NULL
            AND resolved_by_request_id <> request_id
            AND jsonb_typeof(resolution_selection) = 'object'
            AND octet_length(resolution_selection::text) <= 32768)
    ) IS TRUE);

-- The baseline function, with one more allowed change: an unknown request's
-- resolution, added once, with nothing else about the row changing. No other
-- update may touch the resolution columns.
CREATE OR REPLACE FUNCTION public.codewire_cw_runtime_request_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
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
    IF OLD.phase = 'unknown' AND OLD.resolved_at IS NULL AND NEW.resolved_at IS NOT NULL
       AND ROW(NEW.phase,NEW.checkpoint,NEW.effect,NEW.acknowledgements,NEW.error_code,
               NEW.issued_at,NEW.terminal_at)
           IS NOT DISTINCT FROM
           ROW(OLD.phase,OLD.checkpoint,OLD.effect,OLD.acknowledgements,OLD.error_code,
               OLD.issued_at,OLD.terminal_at) THEN
        RETURN NEW;
    END IF;
    IF ROW(NEW.resolved_at,NEW.resolution,NEW.resolved_by_request_id,NEW.resolution_selection)
       IS DISTINCT FROM
       ROW(OLD.resolved_at,OLD.resolution,OLD.resolved_by_request_id,OLD.resolution_selection) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime resolution is added once, to an unknown request';
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

-- A resolved request no longer holds its environment's one unresolved slot.
DROP INDEX public.environment_cw_runtime_one_unresolved_owner;
CREATE UNIQUE INDEX environment_cw_runtime_one_unresolved_owner
    ON public.environment_cw_runtime_requests USING btree (environment_id)
    WHERE (phase = ANY (ARRAY['admitted'::text, 'issued'::text, 'acknowledged'::text, 'unknown'::text])
           AND resolved_at IS NULL);
