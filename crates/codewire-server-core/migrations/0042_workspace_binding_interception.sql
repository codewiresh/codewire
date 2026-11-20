-- Hosted interception, decided once per Pod (#4001; docs/dev/SECRETS-AND-CREDENTIALS.md,
-- "Hosted interception"). Orchestration decides at a Pod's first bind whether
-- its agents are intercepted, from the deployment switch and the Pod being a
-- broker-mode Sandbox, and stores it here. The bind, every rebind and every
-- credential relay epoch of that Pod read the stored decision, so none can
-- disagree, and a switch changed during the Pod's life takes effect only at
-- its next start (cw-security, 2026-11-19, #4001). The bind writes it; while
-- the switch is off the relay may too, as "not intercepted", for a Pod an
-- older orchestration bound. Either writes only while it is NULL, and the
-- binding's immutability trigger refuses any later change.
--
-- Every binding already recorded is not intercepted: nothing could be before
-- this. A binding recorded later stays NULL until it is decided, and the
-- relay makes no epoch for it until then.
--
-- Compatible: a new nullable column, and the trigger keeps every rule it had.
-- Older code neither reads nor writes the column. Rollback is forward only
-- (docs/dev/DATABASE-MIGRATIONS.md): a new commit reverts the code and keeps
-- this file; the reverted code ignores the column and serves every Pod as
-- before, not intercepted.

ALTER TABLE public.sandbox_workspace_bindings
    ADD COLUMN interception boolean;

UPDATE public.sandbox_workspace_bindings SET interception = false;

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
    RETURN NEW;
END;
$$;
