-- Host environments' SSH host keys (#3609, slice 3): the key each VM on a
-- host serves on its tailnet peer, which a client verifies before it opens
-- a shell (private-docs designs/2026-11-13-host-direct-access.md, §3 and §4).
--
-- The host records a key over its session with `host_key_record`. A key is
-- written once per environment and operation generation: the generation
-- orchestration assigns when it creates or starts the VM, never one the host
-- chooses. The same key again is accepted, and a different one is refused,
-- so a host can't swap a VM's key without a real restart the client sees.
-- `host_environments.ssh_host_key` stays the host's own report and is never
-- read for verification.
--
-- A row goes with its environment and with its host. The client's lookup
-- reads only the row at the environment's current operation generation.
--
-- Compatible: a new table that nothing older reads.
-- Rollback: drop the table.

CREATE TABLE public.host_environment_ssh_host_keys (
    environment_id text NOT NULL,
    operation_generation bigint NOT NULL,
    host_id text NOT NULL,
    public_key text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_environment_ssh_host_keys_pkey
        PRIMARY KEY (environment_id, operation_generation),
    CONSTRAINT host_environment_ssh_host_keys_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT host_environment_ssh_host_keys_host_id_fkey
        FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON DELETE CASCADE,
    CONSTRAINT host_environment_ssh_host_keys_generation_check
        CHECK (operation_generation > 0),
    -- Exactly one OpenSSH ed25519 key line, as sandbox_ssh_host_keys holds.
    CONSTRAINT host_environment_ssh_host_keys_public_key_check
        CHECK (public_key ~ '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'::text)
);

CREATE INDEX host_environment_ssh_host_keys_host_id_idx
    ON public.host_environment_ssh_host_keys (host_id);
