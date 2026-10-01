-- An environment-scoped runtime dispatch records the environment it targets.
-- External cleanup of that environment then waits only for dispatches that
-- could still change it, and resolves its ambiguous dispatches once its
-- runtime is proven absent. NULL keeps the organization-wide meaning for
-- every other class, for environment creation, and for every lease admitted
-- before this column existed. The value is an opaque identifier without a
-- foreign key: leases stay as evidence after their environment and
-- organization rows are removed.
ALTER TABLE public.organization_mutation_leases
    ADD COLUMN environment_id text,
    ADD CONSTRAINT organization_mutation_leases_environment_scope_check CHECK (
        environment_id IS NULL
        OR (mutation_class = 'environment_runtime_dispatch' AND environment_id <> '')
    );
