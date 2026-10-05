-- Durable, value-blind platform conversation admission. No provider/prompt/
-- resolved projection material, no resource cascade, and no replay on recovery.
CREATE TABLE environment_platform_agent_requests (
    request_id uuid PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    organization_id text NOT NULL CHECK (length(organization_id) BETWEEN 1 AND 256),
    environment_id text NOT NULL CHECK (length(environment_id)=36),
    actor_user_id text NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 256),
    via_api_key boolean NOT NULL,
    delegated_organization_id text,
    pod_uid uuid NOT NULL CHECK (pod_uid <> '00000000-0000-0000-0000-000000000000'),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    mutation_json jsonb NOT NULL CHECK (jsonb_typeof(mutation_json)='object' AND octet_length(mutation_json::text)<=32768),
    binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object' AND octet_length(binding_json::text)<=32768),
    owner_id uuid NOT NULL CHECK (owner_id <> '00000000-0000-0000-0000-000000000000'),
    mutation_lease_id text NOT NULL UNIQUE,
    cleanup_of uuid,
    phase text NOT NULL DEFAULT 'admitted' CHECK (phase IN ('admitted','issued','completed','rejected','unknown')),
    receipt_json jsonb CHECK (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=32768),
    reason_code text NOT NULL DEFAULT '' CHECK (reason_code IN ('','platform-agent-command-refused','platform-agent-preissue-refused',
        'platform-agent-cancelled-before-dispatch','platform-agent-dispatch-unknown')),
    admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    issued_at timestamptz,
    terminal_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (via_api_key=(delegated_organization_id IS NOT NULL) AND
        (delegated_organization_id IS NULL OR delegated_organization_id=organization_id)),
    CHECK (cleanup_of IS NULL OR (cleanup_of<>request_id AND mutation_json->>'action'='stop')),
    CHECK ((mutation_json->>'cleanup_of_request_id') IS NOT DISTINCT FROM cleanup_of::text),
    CHECK (mutation_json->>'request_id'=request_id::text AND binding_json->>'organization_id'=organization_id
        AND binding_json->>'environment_id'=environment_id AND binding_json->>'pod_uid'=pod_uid::text),
    CHECK ((phase='admitted' AND issued_at IS NULL AND terminal_at IS NULL AND receipt_json IS NULL AND reason_code='')
        OR (phase='issued' AND issued_at IS NOT NULL AND terminal_at IS NULL AND receipt_json IS NULL AND reason_code='')
        OR (phase='completed' AND issued_at IS NOT NULL AND terminal_at IS NOT NULL AND receipt_json IS NOT NULL AND reason_code='')
        OR (phase='rejected' AND issued_at IS NOT NULL AND terminal_at IS NOT NULL AND receipt_json IS NOT NULL AND reason_code='platform-agent-command-refused')
        OR (phase='rejected' AND terminal_at IS NOT NULL AND issued_at IS NULL AND receipt_json IS NULL AND reason_code IN ('platform-agent-cancelled-before-dispatch','platform-agent-preissue-refused'))
        OR (phase='unknown' AND issued_at IS NOT NULL AND terminal_at IS NOT NULL AND reason_code ='platform-agent-dispatch-unknown'))
);

-- One original conversation, independent of the updateable CW selection.
-- A separate cleanup slot never replaces the unresolved original request.
CREATE TABLE environment_platform_agent_conversations (
    environment_id text NOT NULL,
    pod_uid uuid NOT NULL,
    session_id text NOT NULL CHECK (session_id ~ '^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    driver_id uuid NOT NULL CHECK (session_id='session-'||driver_id::text AND driver_id<>'00000000-0000-0000-0000-000000000000'),
    binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object' AND octet_length(binding_json::text)<=32768),
    support_image_sha256 text NOT NULL CHECK (support_image_sha256 ~ '^[0-9a-f]{64}$'),
    support_image_size bigint NOT NULL CHECK (support_image_size BETWEEN 4 AND 268435456),
    agent text NOT NULL CHECK (agent IN ('codex','claude')),
    launch_generation text NOT NULL CHECK (launch_generation ~ '^[1-9][0-9]{0,19}$' AND
        (length(launch_generation)<20 OR launch_generation<='18446744073709551615')),
    active_request_id uuid,
    cleanup_request_id uuid,
    known_clean boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(environment_id,pod_uid,session_id),
    CHECK (binding_json->>'environment_id'=environment_id AND binding_json->>'pod_uid'=pod_uid::text),
    CHECK (cleanup_request_id IS NULL OR (active_request_id IS NOT NULL AND cleanup_request_id<>active_request_id))
);
CREATE INDEX environment_platform_agent_request_scope
    ON environment_platform_agent_requests(organization_id,environment_id,request_id);

CREATE FUNCTION environment_platform_agent_request_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'platform agent request evidence is retained'; END IF;
    IF ROW(NEW.request_id,NEW.organization_id,NEW.environment_id,NEW.actor_user_id,NEW.via_api_key,
        NEW.delegated_organization_id,NEW.pod_uid,NEW.fingerprint,NEW.mutation_json,NEW.binding_json,
        NEW.owner_id,NEW.mutation_lease_id,NEW.cleanup_of,NEW.admitted_at)
        IS DISTINCT FROM ROW(OLD.request_id,OLD.organization_id,OLD.environment_id,OLD.actor_user_id,OLD.via_api_key,
        OLD.delegated_organization_id,OLD.pod_uid,OLD.fingerprint,OLD.mutation_json,OLD.binding_json,
        OLD.owner_id,OLD.mutation_lease_id,OLD.cleanup_of,OLD.admitted_at) THEN
        RAISE EXCEPTION 'platform agent request identity is immutable';
    END IF;
    IF OLD.phase IN ('completed','rejected','unknown') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'platform agent terminal evidence is immutable';
    END IF;
    IF NEW.phase<>OLD.phase AND NOT (
        (OLD.phase='admitted' AND NEW.phase IN ('issued','rejected')) OR
        (OLD.phase='issued' AND NEW.phase IN ('completed','rejected','unknown'))) THEN
        RAISE EXCEPTION 'platform agent request cannot replay';
    END IF;
    IF OLD.issued_at IS NOT NULL AND NEW.issued_at IS DISTINCT FROM OLD.issued_at THEN
        RAISE EXCEPTION 'platform agent issue evidence is immutable';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION environment_platform_agent_request_guard() FROM PUBLIC;
CREATE TRIGGER environment_platform_agent_request_immutable
    BEFORE UPDATE OR DELETE ON environment_platform_agent_requests
    FOR EACH ROW EXECUTE FUNCTION environment_platform_agent_request_guard();

CREATE FUNCTION environment_platform_agent_conversation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'platform agent conversation evidence is retained'; END IF;
    IF ROW(NEW.environment_id,NEW.pod_uid,NEW.session_id,NEW.driver_id,NEW.binding_json,
        NEW.support_image_sha256,NEW.support_image_size,NEW.agent) IS DISTINCT FROM
        ROW(OLD.environment_id,OLD.pod_uid,OLD.session_id,OLD.driver_id,OLD.binding_json,
        OLD.support_image_sha256,OLD.support_image_size,OLD.agent) THEN
        RAISE EXCEPTION 'platform agent original conversation is immutable';
    END IF;
    IF NEW.launch_generation<>OLD.launch_generation AND
        NEW.launch_generation::numeric<>OLD.launch_generation::numeric+1 THEN
        RAISE EXCEPTION 'platform agent generation must advance once';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION environment_platform_agent_conversation_guard() FROM PUBLIC;
CREATE TRIGGER environment_platform_agent_conversation_immutable
    BEFORE UPDATE OR DELETE ON environment_platform_agent_conversations
    FOR EACH ROW EXECUTE FUNCTION environment_platform_agent_conversation_guard();
