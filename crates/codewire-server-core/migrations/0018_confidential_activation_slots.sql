-- Confidential activation slots (#4281): one row per environment whose
-- confidential workspace volume is being activated in its guest.
--
-- Activating a confidential volume (opening the encrypted, integrity-protected
-- device inside the SNP guest) is slow and contends for the host's disk. Four
-- at once on one host overran the Kata agent's create deadline on Dev and none
-- recovered, so orchestration bounds how many run at once and queues the
-- rest. The bound is cluster-wide: activations per host with one
-- confidential host, and one at a time with several until per-host placement
-- exists. A row is a held slot: written before the volume's key is made
-- ready, under one transaction-scoped advisory lock, and deleted once the
-- member it activated is ready. A row whose environment is no longer active,
-- or whose lease has passed, is swept by the next acquisition, so a missed
-- release never holds a slot past its own deadline.
--
-- Deleting the environment deletes its slot.
--
-- Compatible: the table is new, and older code reads nothing from it.
-- Rollback drops the table, which frees every slot; activations already
-- running are unaffected.

CREATE TABLE public.confidential_activation_slots (
    environment_id text NOT NULL,
    acquired_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT confidential_activation_slots_pkey PRIMARY KEY (environment_id),
    CONSTRAINT confidential_activation_slots_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT confidential_activation_slots_lease_check CHECK (expires_at > acquired_at)
);
