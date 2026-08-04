-- Durable resize operation records are additive and remain readable after rollback.
CREATE TABLE public.environment_resize_operations (
    id text NOT NULL,
    org_id text NOT NULL,
    environment_id text NOT NULL,
    request_id text NOT NULL,
    previous_cpu_millicores integer NOT NULL,
    previous_memory_mb integer NOT NULL,
    previous_disk_gb integer NOT NULL,
    desired_cpu_millicores integer NOT NULL,
    desired_memory_mb integer NOT NULL,
    desired_disk_gb integer NOT NULL,
    last_applied_cpu_millicores integer NOT NULL,
    last_applied_memory_mb integer NOT NULL,
    last_applied_disk_gb integer NOT NULL,
    previous_state text NOT NULL,
    previous_desired_state text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    force boolean DEFAULT false NOT NULL,
    disruption_policy text DEFAULT 'live_only'::text NOT NULL,
    planned_mode text NOT NULL,
    applied_mode text,
    pod_replaced boolean DEFAULT false NOT NULL,
    reserved_cpu_millicores integer DEFAULT 0 NOT NULL,
    reserved_memory_mb integer DEFAULT 0 NOT NULL,
    failure_code text,
    failure_message text,
    previous_pod_uid text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    completed_at timestamp without time zone,
    CONSTRAINT environment_resize_operations_pkey PRIMARY KEY (id),
    CONSTRAINT environment_resize_operations_environment_request_key UNIQUE (environment_id, request_id),
    CONSTRAINT environment_resize_operations_state_check CHECK (state = ANY (ARRAY['pending'::text, 'applying'::text, 'restarting'::text, 'completed'::text, 'failed'::text])),
    CONSTRAINT environment_resize_operations_disruption_policy_check CHECK (disruption_policy = ANY (ARRAY['live_only'::text, 'allow_restart'::text])),
    CONSTRAINT environment_resize_operations_planned_mode_check CHECK (planned_mode = ANY (ARRAY['noop'::text, 'apply_on_start'::text, 'in_place'::text, 'restart'::text])),
    CONSTRAINT environment_resize_operations_applied_mode_check CHECK (applied_mode IS NULL OR applied_mode = ANY (ARRAY['noop'::text, 'apply_on_start'::text, 'in_place'::text, 'restart'::text])),
    CONSTRAINT environment_resize_operations_previous_state_check CHECK (previous_state = ANY (ARRAY['running'::text, 'stopped'::text])),
    CONSTRAINT environment_resize_operations_previous_desired_state_check CHECK (previous_desired_state = ANY (ARRAY['started'::text, 'stopped'::text])),
    CONSTRAINT environment_resize_operations_resources_positive_check CHECK (
        previous_cpu_millicores > 0 AND previous_memory_mb > 0 AND previous_disk_gb > 0
        AND desired_cpu_millicores > 0 AND desired_memory_mb > 0 AND desired_disk_gb > 0
        AND last_applied_cpu_millicores > 0 AND last_applied_memory_mb > 0 AND last_applied_disk_gb > 0
    ),
    CONSTRAINT environment_resize_operations_disk_no_shrink_check CHECK (desired_disk_gb >= previous_disk_gb),
    CONSTRAINT environment_resize_operations_reservations_nonnegative_check CHECK (reserved_cpu_millicores >= 0 AND reserved_memory_mb >= 0),
    CONSTRAINT environment_resize_operations_terminal_check CHECK (
        (state IN ('completed', 'failed') AND completed_at IS NOT NULL)
        OR (state NOT IN ('completed', 'failed') AND completed_at IS NULL)
    ),
    CONSTRAINT environment_resize_operations_completion_mode_check CHECK (
        state <> 'completed' OR applied_mode IS NOT NULL
    ),
    CONSTRAINT environment_resize_operations_failure_check CHECK (
        (state = 'failed' AND failure_code IS NOT NULL AND btrim(failure_code) <> '' AND failure_message IS NOT NULL AND btrim(failure_message) <> '')
        OR (state <> 'failed' AND failure_code IS NULL AND failure_message IS NULL)
    ),
    CONSTRAINT environment_resize_operations_environment_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT environment_resize_operations_org_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX environment_resize_operations_one_active_per_environment
    ON public.environment_resize_operations (environment_id)
    WHERE state IN ('pending', 'applying', 'restarting');

CREATE INDEX environment_resize_operations_org_created_idx
    ON public.environment_resize_operations (org_id, created_at DESC);
