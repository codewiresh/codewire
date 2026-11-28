-- Host-bound secrets at a hosted Pod's first bind (#4003;
-- docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door" and
-- "Projection").
--
-- sandbox_pod_front_door_hosts.bound_routes: whether the cw-egress serving
--   the Pod said, at its latest admission, that its front door serves
--   bound-secret routes. A capability, never a list of names: a bound
--   secret's hosts are in no fixed table. An older cw-egress says nothing,
--   which is false. A first bind whose selection binds a secret's host is
--   refused (`front_door_hosts_unserved`, naming the host) unless it is true.
-- sandbox_pod_front_door_hosts.refusal_code and refusal_reason: why the
--   Pod's first bind was refused for its bound secrets, beside `unserved`
--   (migration 0069), so the create or start waiting for the Pod ends with
--   the code and its sentence rather than a timeout: a host the deployment
--   has reserved since the secret was bound (`bound_host_reserved`), two
--   values naming one host (`bound_host_conflict`), or more bound-secret
--   hosts than one environment carries (`too_many_bound_hosts`). The
--   sentence names the hosts and the keys, never a value.
-- sandbox_workspace_bindings.bound_secrets: each bound secret the Pod's
--   selected sources held at its first bind, as a JSON array of
--   {path, key, binding_id, binding_generation, prefix, hosts}
--   (codewire_access::FirstBindSecret). Written with the interception
--   decision in one statement, so a refused bind stores neither; never
--   changed for the Pod's life, which the binding's trigger enforces. The
--   credential service reads it so that a secret the Pod recorded bound and
--   that is plain now still projects the placeholder recorded here, never its
--   value. NULL for a Pod bound before this column, or by an orchestration
--   older than it: the credential service then projects raw only a secret
--   that was never bound.
--
-- The credential broker's login reads bound_secrets: infra grants SELECT
-- (bound_secrets) ON sandbox_workspace_bindings beside the columns it reads
-- today, before the credential service that reads it ships; that service
-- refuses to start without the grant.
--
-- Compatible: new columns, NULL or false for every existing row, and the
-- trigger keeps every rule it had. Older code neither reads nor writes them.
-- Rollback is forward only (docs/dev/DATABASE-MIGRATIONS.md): a new commit
-- reverts the code and keeps this file; the reverted code ignores the columns.

ALTER TABLE public.sandbox_pod_front_door_hosts
    ADD COLUMN bound_routes boolean DEFAULT false NOT NULL,
    ADD COLUMN refusal_code text,
    ADD COLUMN refusal_reason text,
    ADD CONSTRAINT sandbox_pod_front_door_hosts_refusal_check CHECK (
        (refusal_code IS NULL AND refusal_reason IS NULL)
        OR (refusal_code IS NOT NULL AND refusal_reason IS NOT NULL
            AND refusal_code IN
                ('bound_host_reserved', 'bound_host_conflict', 'too_many_bound_hosts')
            AND char_length(refusal_reason) BETWEEN 1 AND 4096)
    );

ALTER TABLE public.sandbox_workspace_bindings
    ADD COLUMN bound_secrets jsonb,
    ADD CONSTRAINT sandbox_workspace_bindings_bound_secrets_check CHECK (
        bound_secrets IS NULL
        OR CASE WHEN jsonb_typeof(bound_secrets) = 'array'
                THEN jsonb_array_length(bound_secrets) <= 16
                ELSE false END
    );

CREATE OR REPLACE FUNCTION public.codewire_workspace_binding_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() <= 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'workspace binding is removed only with its environment';
        END IF;
        RETURN OLD;
    END IF;
    IF ROW(
           NEW.pod_uid,
           NEW.environment_id,
           NEW.namespace,
           NEW.pod_name,
           NEW.claim_uid,
           NEW.sandbox_uid,
           NEW.workspace_pvc_uid,
           NEW.operation_generation,
           NEW.projection_selection_sha256,
           NEW.managed_credential_clients,
           NEW.credential_scope,
           NEW.bound_at
       ) IS DISTINCT FROM ROW(
           OLD.pod_uid,
           OLD.environment_id,
           OLD.namespace,
           OLD.pod_name,
           OLD.claim_uid,
           OLD.sandbox_uid,
           OLD.workspace_pvc_uid,
           OLD.operation_generation,
           OLD.projection_selection_sha256,
           OLD.managed_credential_clients,
           OLD.credential_scope,
           OLD.bound_at
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding is immutable except its release';
    END IF;
    IF OLD.released_at IS NOT NULL
       AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding release is final';
    END IF;
    IF OLD.interception IS NOT NULL
       AND NEW.interception IS DISTINCT FROM OLD.interception THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding interception is decided once';
    END IF;
    -- Recorded with the interception decision or never: once either is set,
    -- the bound secrets don't change.
    IF (OLD.bound_secrets IS NOT NULL OR OLD.interception IS NOT NULL)
       AND NEW.bound_secrets IS DISTINCT FROM OLD.bound_secrets THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding bound secrets are recorded once';
    END IF;
    RETURN NEW;
END;
$$;
