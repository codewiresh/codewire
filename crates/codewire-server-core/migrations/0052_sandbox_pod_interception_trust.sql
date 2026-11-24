-- The interception trust each hosted Sandbox Pod's guest installed (#6200;
-- docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception"). A guest keeps
-- the trust of its first egress session for the Pod's life (#5006), and a
-- Pod's first bind stores whether its agents are intercepted (0042). Both
-- follow this row, so a switch flipped between them (a warm member created
-- before it and claimed after it) can't leave a Pod stored as intercepted
-- whose guest trusts no CA.
--
-- Orchestration writes a Pod's row at whichever comes first, its first egress
-- admission or its first bind: the switch at that moment and the Pod being a
-- broker-mode Sandbox, with INSERT ... ON CONFLICT DO NOTHING, and then reads
-- the stored row in the same transaction. Every admission gives the Pod a CA
-- exactly when its row says so; the first bind stores "intercepted" only when
-- the row says so and the switch is still on. The row is never changed: the
-- trigger refuses every UPDATE. Orchestration's sweep deletes a row only for
-- a Pod UID the API server's complete list confirms absent, and only one
-- written before that list began.
--
-- Compatible: the table is new and older code neither reads nor writes it.
-- Rollback is forward only (docs/dev/DATABASE-MIGRATIONS.md): a new commit
-- reverts the code and keeps this file; the reverted code ignores the table
-- and decides as before, from the switch.

CREATE TABLE public.sandbox_pod_interception_trust (
    pod_uid text NOT NULL,
    ca_given boolean NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sandbox_pod_interception_trust_pkey PRIMARY KEY (pod_uid),
    CONSTRAINT sandbox_pod_interception_trust_pod_uid_check
        CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text))
);

CREATE FUNCTION public.codewire_pod_interception_trust_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'a Pod''s interception trust is recorded once';
END;
$$;

CREATE TRIGGER sandbox_pod_interception_trust_immutable
    BEFORE UPDATE ON public.sandbox_pod_interception_trust
    FOR EACH ROW EXECUTE FUNCTION public.codewire_pod_interception_trust_immutable();
