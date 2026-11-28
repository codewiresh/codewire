-- Host-bound application secrets (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md,
-- "Host-bound application secrets"). A secret may carry a binding: the
-- hosts its value is sent to and how it is presented there. The environment
-- then holds a placeholder derived from binding_id and binding_generation,
-- and the front door swaps in the value only on those hosts.
--
-- binding: the canonical binding the services wrote, validated again on
--   every read (codewire_access::HostBinding); NULL for a plain secret.
-- binding_id: made when a secret is first bound and kept until it is
--   deleted, so a placeholder outlives a new value.
-- binding_generation: moves with every change to the binding but its hosts.
-- value_version: moves with every new value, so decrypted values reused
--   within an epoch are keyed by it and a new value is read at once.
--
-- Every existing row is plain (binding NULL), at generation 0 and value
-- version 1, so nothing an environment receives changes.
--
-- Rollback: drop the four columns and the check, after making every bound
-- secret plain; an older service reads none of them.
ALTER TABLE public.tenant_secrets
    ADD COLUMN binding jsonb,
    ADD COLUMN binding_id uuid,
    ADD COLUMN binding_generation bigint NOT NULL DEFAULT 0,
    ADD COLUMN value_version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT tenant_secrets_binding_check CHECK (
        (binding IS NULL OR binding_id IS NOT NULL)
        AND (binding IS NULL OR jsonb_typeof(binding) = 'object')
        AND binding_generation >= 0
        AND value_version >= 1
    );
