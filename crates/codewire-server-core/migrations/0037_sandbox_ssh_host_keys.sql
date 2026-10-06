-- SSH host keys of in-sandbox daemons (Program #2238, daemon-hosted access,
-- docs/plans/2026-10-06-daemon-hosted-access.md section 3, S3).
--
-- A workspace daemon generates an Ed25519 host key when it binds and records
-- the public half through the Pod-bound workspace-binding listener. The Pod,
-- environment and generation come only from orchestration's reviewed binding,
-- never from the request. One key is recorded per bound Pod: the primary key
-- makes a second, different key for the same Pod impossible, and the only
-- writer inserts with ON CONFLICT DO NOTHING, so a recorded key is never
-- replaced. A Pod that replaces another, even within one operation
-- generation, records its own key. Clients trust only the key of the Pod
-- the environment is currently bound to, read through the authenticated API,
-- so replacing the Pod (a start, a stop or a repair) rotates trust with it.
-- The environment and generation are recorded facts.
--
-- The change is additive: earlier binaries never read the table, and rows are
-- written later by orchestration, not here. Keys of released bindings are
-- pruned when the environment's next Pod records its key, and every row is
-- removed with its environment.
CREATE TABLE public.sandbox_ssh_host_keys (
    pod_uid text PRIMARY KEY
        CHECK (pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'),
    environment_id text NOT NULL REFERENCES public.environments(id) ON DELETE CASCADE,
    operation_generation bigint NOT NULL CHECK (operation_generation > 0),
    -- Exactly one OpenSSH Ed25519 public key: the algorithm, one space and
    -- the 68-character base64 encoding of its 51-byte wire blob, whose fixed
    -- prefix names the algorithm and the 32-byte key length. No comment.
    public_key text NOT NULL
        CHECK (public_key ~ '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'),
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sandbox_ssh_host_keys_environment_idx
    ON public.sandbox_ssh_host_keys (environment_id);
