-- Claim-time workspace binding (Program #2238, design
-- docs/plans/2026-09-30-workspace-claim-time-binding.md section 6).
--
-- A binding records which environment one exact workspace Pod serves. The Pod
-- UID is the primary key, so Pod UID -> environment can never be reassigned:
-- rows are insert-only except released_at, which the trigger below enforces.
-- Environment -> Pod moves only through the backend pointer, which the
-- composite foreign key restricts to a binding of the same environment. At
-- most one binding per environment is live.
--
-- The change is additive. Existing backend rows keep NULL pointers, which the
-- MATCH SIMPLE foreign key ignores, and earlier binaries never read the new
-- table or columns. Rows are written later by orchestration, not here.
CREATE TABLE public.sandbox_workspace_bindings (
    pod_uid text PRIMARY KEY CHECK (pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    environment_id text NOT NULL REFERENCES public.environments(id) ON DELETE CASCADE,
    namespace text NOT NULL CHECK (btrim(namespace) <> ''),
    pod_name text NOT NULL CHECK (btrim(pod_name) <> ''),
    claim_uid text NOT NULL,
    sandbox_uid text NOT NULL,
    workspace_pvc_uid text,
    operation_generation bigint NOT NULL CHECK (operation_generation > 0),
    projection_selection_sha256 text CHECK (projection_selection_sha256 ~ '^[0-9a-f]{64}$'),
    managed_credential_clients text NOT NULL,
    credential_scope text NOT NULL CHECK (credential_scope IN ('environment','pod')),
    bound_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    UNIQUE (environment_id, pod_uid),
    -- Hardening beyond the reviewed section 6 SQL: every recorded Kubernetes
    -- UID has the canonical lowercase form, and a release never precedes its
    -- bind.
    CONSTRAINT sandbox_workspace_bindings_claim_uid_check
        CHECK (claim_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    CONSTRAINT sandbox_workspace_bindings_sandbox_uid_check
        CHECK (sandbox_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    CONSTRAINT sandbox_workspace_bindings_workspace_pvc_uid_check
        CHECK (workspace_pvc_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    CONSTRAINT sandbox_workspace_bindings_released_after_bound
        CHECK (released_at IS NULL OR released_at >= bound_at)
);
CREATE UNIQUE INDEX sandbox_workspace_bindings_live_environment
    ON public.sandbox_workspace_bindings (environment_id) WHERE released_at IS NULL;

-- Hardening beyond the reviewed section 6 SQL: a binding is insert-only except
-- its release, which may be recorded once and never cleared or moved. This
-- makes Pod UID -> environment immutable in the database, not only in code.
CREATE FUNCTION public.codewire_workspace_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
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
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_workspace_binding_immutable() FROM PUBLIC;

CREATE TRIGGER codewire_workspace_binding_immutable
BEFORE UPDATE ON public.sandbox_workspace_bindings
FOR EACH ROW EXECUTE FUNCTION public.codewire_workspace_binding_immutable();

ALTER TABLE public.sandbox_environment_backend
    ADD COLUMN pod_uid text,
    ADD COLUMN bound_at timestamptz,
    ADD COLUMN workspace_pvc_uid text,
    ADD CONSTRAINT sandbox_environment_backend_binding_fkey
        FOREIGN KEY (environment_id, pod_uid)
        REFERENCES public.sandbox_workspace_bindings (environment_id, pod_uid),
    ADD CONSTRAINT chk_sandbox_backend_binding_coherent
        CHECK ((pod_uid IS NULL) = (bound_at IS NULL)),
    -- Hardening beyond the reviewed section 6 SQL, as above.
    ADD CONSTRAINT chk_sandbox_backend_workspace_pvc_uid
        CHECK (workspace_pvc_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$');
