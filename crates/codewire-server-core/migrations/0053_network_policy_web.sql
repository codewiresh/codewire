-- The built-in network policy `web` (#3997): DNS and TCP 22, 80 and 443 to
-- public addresses, the rules `open` had before `open` became the default
-- with every TCP port. A hosted environment may select it, and no
-- organization policy may take its name. The services refuse the name
-- through codewire_egress_policy::PolicyName::parse; this keeps the
-- database's checks the same lists.
--
-- Replacing the name check validates every existing policy. If one is
-- already named `web`, the migration fails inside its transaction and
-- changes nothing; delete that policy first. No row is changed.
--
-- Rollback: put back 0025's two checks, which refuses `web` selections
-- again; remove those first.
ALTER TABLE public.platform_environment_network_policies
    DROP CONSTRAINT platform_environment_network_policies_builtin_check,
    ADD CONSTRAINT platform_environment_network_policies_builtin_check
        CHECK (builtin = ANY (ARRAY['open'::text, 'web'::text, 'locked'::text]));

ALTER TABLE public.platform_network_policies
    DROP CONSTRAINT platform_network_policies_name_check,
    -- codewire_egress_policy::PolicyName.
    ADD CONSTRAINT platform_network_policies_name_check CHECK (
        name ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'
        AND name <> ALL (ARRAY['open'::text, 'web'::text, 'locked'::text, 'hosted-default'::text])
    );
