-- Host operations (#3609, slice 2): how orchestration runs an environment on
-- a user's own computer.
--
-- The HostDriver runs in the Temporal worker; the host's one stream is held
-- by whichever API replica accepted its AttachHost. They meet here. The
-- driver inserts an operation; the session that holds the host's stream
-- sends it, and writes back the host's result. Nothing routes between
-- replicas in memory.
--
-- hosts.session_generation fences sessions: each attach increments it, and
-- only the session holding the current generation may take operations, so a
-- lingering old stream never receives one. A claim holds the hosts row FOR
-- SHARE, so an attach waits for a claim in flight.
--
-- host_operations: one row per operation, its ID chosen by the driver. The
-- payload and the result are the encoded HostOperation and
-- HostOperationResult protos, stored and resent byte for byte: the host's
-- local supervisor journals each operation by that ID and answers a repeat
-- with the same payload with the first result, and refuses one whose
-- payload differs. So after a reattach the session sends a sent operation
-- again, unchanged, to learn its outcome. An operation is pending until a
-- session sends it, sent until the host answers, then done or failed. An
-- environment has at most one open operation at a time. An operation
-- belongs to its host and goes with it; it has no foreign key to
-- environments, so a Destroy can name a VM whose environment orchestration
-- no longer records (design §6). The environment's own path checks its
-- placement when it enqueues.
--
-- host_environments: the host's last report of each environment it holds,
-- as HostEnvironmentObservation carries it, from its Hello inventory, its
-- results and its observations, with the supervisor's own environment UUID,
-- which later operations name so a VM deleted and recreated locally is
-- never mistaken for this one. No foreign key to environments either: a
-- host may still report a VM the control plane has forgotten, and that
-- report is how the orphan is seen. `absent` is the host saying it no
-- longer has the VM: destroyed, or lost.
--
-- environments.runtime_backend says which driver runs an environment;
-- host_id names the host for one that runs on a host, always a host of the
-- environment's own organization. A host that is deleted (its owner's
-- account or organization goes) leaves its environments' rows, with
-- host_id cleared. create_request_id is a create's client request ID
-- (design §6): a retry with the same ID in the same organization finds the
-- environment the first one made, and the unique index makes a second row
-- with it impossible.
--
-- host_operation is notified on insert with the host's ID, so the session
-- that holds the host's stream sends it at once.
--
-- Compatible: the tables and the function are new; the new columns have
-- constant defaults or are nullable, and older code reads none of them.
-- Rolling back is forward only (docs/dev/DATABASE-MIGRATIONS.md).

ALTER TABLE public.hosts
    ADD COLUMN session_generation bigint DEFAULT 0 NOT NULL,
    ADD CONSTRAINT hosts_session_generation_check CHECK (session_generation >= 0),
    ADD CONSTRAINT hosts_org_id_id_key UNIQUE (org_id, id);

ALTER TABLE public.environments
    ADD COLUMN runtime_backend text DEFAULT 'kubernetes' NOT NULL,
    ADD COLUMN host_id text,
    ADD COLUMN create_request_id text,
    ADD CONSTRAINT environments_runtime_backend_check
        CHECK (runtime_backend IN ('kubernetes', 'host')),
    ADD CONSTRAINT environments_host_id_needs_host_backend
        CHECK (host_id IS NULL OR runtime_backend = 'host'),
    ADD CONSTRAINT environments_host_id_fkey
        FOREIGN KEY (org_id, host_id) REFERENCES public.hosts(org_id, id)
        ON DELETE SET NULL (host_id);

CREATE INDEX environments_host_id_idx ON public.environments (host_id)
    WHERE host_id IS NOT NULL;

CREATE UNIQUE INDEX environments_org_create_request_id_key
    ON public.environments (org_id, create_request_id)
    WHERE create_request_id IS NOT NULL;

CREATE TABLE public.host_operations (
    operation_id text NOT NULL,
    host_id text NOT NULL,
    environment_id text NOT NULL,
    expected_generation bigint NOT NULL,
    kind text NOT NULL,
    payload bytea NOT NULL,
    state text DEFAULT 'pending' NOT NULL,
    session_generation bigint,
    result bytea,
    failure text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT host_operations_pkey PRIMARY KEY (operation_id),
    CONSTRAINT host_operations_host_id_fkey
        FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON DELETE CASCADE,
    CONSTRAINT host_operations_kind_check
        CHECK (kind IN ('create', 'start', 'stop', 'destroy')),
    CONSTRAINT host_operations_state_check
        CHECK (state IN ('pending', 'sent', 'done', 'failed')),
    CONSTRAINT host_operations_expected_generation_check
        CHECK (expected_generation >= 0),
    CONSTRAINT host_operations_session_generation_check
        CHECK (session_generation >= 0),
    -- A sent or finished operation names the session and time it was sent.
    CONSTRAINT host_operations_sent_check
        CHECK (CASE WHEN state = 'pending'
                    THEN sent_at IS NULL AND session_generation IS NULL
                    ELSE sent_at IS NOT NULL AND session_generation IS NOT NULL END),
    -- A finished operation has its time; a failed one says why.
    CONSTRAINT host_operations_completed_check
        CHECK ((state IN ('done', 'failed')) = (completed_at IS NOT NULL)),
    CONSTRAINT host_operations_failure_check
        CHECK ((state = 'failed') = (failure IS NOT NULL AND failure <> ''))
);

CREATE INDEX host_operations_open_idx ON public.host_operations (host_id, created_at)
    WHERE state IN ('pending', 'sent');

CREATE INDEX host_operations_environment_id_idx ON public.host_operations (environment_id);

CREATE UNIQUE INDEX host_operations_one_open_per_environment
    ON public.host_operations (environment_id)
    WHERE state IN ('pending', 'sent');

CREATE TABLE public.host_environments (
    host_id text NOT NULL,
    environment_id text NOT NULL,
    local_environment_id uuid NOT NULL,
    generation bigint NOT NULL,
    state text NOT NULL,
    error_code text,
    vcpus integer DEFAULT 0 NOT NULL,
    memory_mib integer DEFAULT 0 NOT NULL,
    disk_bytes bigint DEFAULT 0 NOT NULL,
    ssh_host_key text,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_environments_pkey PRIMARY KEY (host_id, environment_id),
    CONSTRAINT host_environments_host_id_fkey
        FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON DELETE CASCADE,
    CONSTRAINT host_environments_generation_check CHECK (generation >= 0),
    CONSTRAINT host_environments_state_check
        CHECK (state IN ('stopped', 'starting', 'running', 'error', 'absent')),
    -- The contract's own bounds: a machine-readable cause of at most 64
    -- bytes, and a shape that is never negative.
    CONSTRAINT host_environments_error_code_check
        CHECK (error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 64),
    CONSTRAINT host_environments_shape_check
        CHECK (vcpus >= 0 AND memory_mib >= 0 AND disk_bytes >= 0)
);

CREATE FUNCTION public.codewire_notify_host_operation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('host_operation', NEW.host_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER host_operations_notify AFTER INSERT ON public.host_operations
    FOR EACH ROW EXECUTE FUNCTION public.codewire_notify_host_operation();

REVOKE ALL ON FUNCTION public.codewire_notify_host_operation() FROM PUBLIC;
