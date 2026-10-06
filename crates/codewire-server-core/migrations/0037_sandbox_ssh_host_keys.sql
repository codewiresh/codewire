-- SSH host keys of in-sandbox daemons (Program #2238, daemon-hosted access,
-- docs/plans/2026-10-06-daemon-hosted-access.md section 3, S3).
--
-- A workspace daemon generates an Ed25519 host key when it binds and records
-- the public half through the Pod-bound workspace-binding listener. The
-- environment, generation and Pod come only from orchestration's reviewed
-- binding, never from the request. One key is recorded per environment and
-- operation generation: the primary key makes a second, different key for the
-- same generation impossible, and the only writer inserts with ON CONFLICT DO
-- NOTHING, so a recorded key is never replaced. Clients trust the key of the
-- environment's current generation only, read through the authenticated API,
-- so a start, stop or resize rotates trust with the generation.
--
-- The change is additive: earlier binaries never read the table, and rows are
-- written later by orchestration, not here. A row is removed with its
-- environment.
CREATE TABLE public.sandbox_ssh_host_keys (
    environment_id text NOT NULL REFERENCES public.environments(id) ON DELETE CASCADE,
    operation_generation bigint NOT NULL CHECK (operation_generation > 0),
    pod_uid text NOT NULL CHECK (pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    -- Exactly one OpenSSH Ed25519 public key: the algorithm, one space and
    -- the 68-character base64 encoding of its 51-byte wire blob, whose fixed
    -- prefix names the algorithm and the 32-byte key length. No comment.
    public_key text NOT NULL
        CHECK (public_key ~ '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (environment_id, operation_generation)
);
