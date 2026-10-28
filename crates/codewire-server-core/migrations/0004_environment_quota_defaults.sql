-- Default environment limits for organizations without their own quota
-- (#3583). One row, editable by a global administrator, replaces the
-- constants the plan fallback used: 10 concurrent environments, 50
-- concurrent sandboxes, 32000 CPU millicores and 65536 MiB of memory. A
-- plan's workspace limit still sets the sandbox count when the plan has one.
-- Code that finds no row keeps those constants, so this migration is
-- additive and its rollback is dropping the table.
CREATE TABLE public.environment_quota_defaults (
    singleton boolean DEFAULT true NOT NULL,
    max_concurrent_environments integer NOT NULL,
    max_concurrent_sandbox integer NOT NULL,
    max_cpu_millicores integer NOT NULL,
    max_memory_mb integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_quota_defaults_pkey PRIMARY KEY (singleton),
    CONSTRAINT environment_quota_defaults_singleton_check CHECK (singleton),
    CONSTRAINT environment_quota_defaults_limits_check CHECK (
        (max_concurrent_environments = -1 OR max_concurrent_environments > 0)
        AND (max_concurrent_sandbox = -1 OR max_concurrent_sandbox > 0)
        AND (max_cpu_millicores = -1 OR max_cpu_millicores > 0)
        AND (max_memory_mb = -1 OR max_memory_mb > 0)
    )
);

INSERT INTO public.environment_quota_defaults
    (max_concurrent_environments, max_concurrent_sandbox, max_cpu_millicores, max_memory_mb)
VALUES (10, 50, 32000, 65536);
