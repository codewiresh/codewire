-- Hosted egress reports (#4000, P2b): what cw-egress enforces for each
-- sandbox Pod, and the egress records `cw policy --cloud log` reads.
--
-- Rollback: DROP TABLE public.environment_egress_records;
--           DROP TABLE public.sandbox_egress_enforcement;

-- One row per workspace Pod cw-egress serves. An identity-free warm member
-- has no environment until its bind transaction sets one; rows whose Pod is
-- gone are deleted with the Pod and swept by orchestration.
CREATE TABLE public.sandbox_egress_enforcement (
    pod_uid text NOT NULL,
    environment_id text,
    -- The node cw-egress reported from, read from its own token.
    node text NOT NULL,
    state text NOT NULL,
    revision integer,
    digest bytea,
    -- A fixed code for failed_closed, for operators only.
    detail text DEFAULT ''::text NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sandbox_egress_enforcement_pkey PRIMARY KEY (pod_uid),
    CONSTRAINT sandbox_egress_enforcement_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT sandbox_egress_enforcement_state_check
        CHECK (state = ANY (ARRAY['enforced'::text, 'failed_closed'::text, 'disconnected'::text])),
    -- Enforced names exactly one revision; nothing else names one.
    CONSTRAINT sandbox_egress_enforcement_revision_check CHECK (
        (state = 'enforced' AND revision BETWEEN 0 AND 10000
            AND digest IS NOT NULL AND octet_length(digest) = 32)
        OR (state <> 'enforced' AND revision IS NULL AND digest IS NULL)
    )
);

CREATE INDEX sandbox_egress_enforcement_environment_id_idx
    ON public.sandbox_egress_enforcement USING btree (environment_id);

-- One row per folded record: everything with the same destination, transport,
-- port, outcome and reason. At most 1,000 per environment
-- (EGRESS_RECORD_LIMIT); the least recently seen are trimmed in the writing
-- transaction. The reason is the raw one; only the owner's log reads it.
CREATE TABLE public.environment_egress_records (
    environment_id text NOT NULL,
    -- A DNS name, or an address no lease names.
    destination text NOT NULL,
    destination_is_name boolean NOT NULL,
    transport text NOT NULL,
    -- 0 for DNS.
    port integer NOT NULL,
    outcome text NOT NULL,
    -- RefusalReason::code(), or '' for a pass.
    reason text NOT NULL,
    address text,
    policy_reference text NOT NULL,
    policy_revision integer NOT NULL,
    policy_digest bytea NOT NULL,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    CONSTRAINT environment_egress_records_pkey
        PRIMARY KEY (environment_id, destination, transport, port, outcome, reason),
    CONSTRAINT environment_egress_records_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT environment_egress_records_transport_check
        CHECK (transport = ANY (ARRAY['dns'::text, 'tcp'::text, 'udp'::text])),
    CONSTRAINT environment_egress_records_port_check CHECK (
        (transport = 'dns' AND port = 0) OR (transport <> 'dns' AND port BETWEEN 1 AND 65535)
    ),
    CONSTRAINT environment_egress_records_outcome_check CHECK (
        (outcome = 'passed' AND reason = '') OR (outcome = 'refused' AND reason <> '')
    ),
    CONSTRAINT environment_egress_records_digest_check CHECK (octet_length(policy_digest) = 32),
    CONSTRAINT environment_egress_records_seen_check CHECK (first_seen <= last_seen),
    CONSTRAINT environment_egress_records_count_check CHECK (count > 0)
);

-- The trim, and the newest-first log read.
CREATE INDEX environment_egress_records_last_seen_idx
    ON public.environment_egress_records USING btree (environment_id, last_seen);
