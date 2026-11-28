-- The names each hosted Sandbox Pod's TLS front door has a route for, as the
-- cw-egress serving it last reported at an egress admission (#6290;
-- docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception"). cw-egress
-- builds its own front door, so only it can say what that door serves:
-- orchestration's own compiled list says what orchestration would bind, and a
-- skew between the two left Sandboxes with hosts handed to a door that had no
-- route for them (2026-11-24).
--
-- Each entry is `host:port` for an exact name, or `*.host:port` for a suffix
-- route (every name strictly under `host`). Orchestration writes a Pod's row at
-- each admission, replacing the earlier set, since the cw-egress serving the
-- Pod may have been rolled. A Pod's first bind is intercepted only when every
-- name its selection would bind is in the row; otherwise it is refused by name
-- (`front_door_hosts_unserved`), and the refused names go in `unserved`, so
-- the create or start waiting for that Pod ends with them rather than a
-- timeout. An admission never clears them. Orchestration's sweep deletes a
-- row only for a Pod UID the API server's complete list confirms absent, and
-- only one reported before that list began.
--
-- Compatible: the table is new and older code neither reads nor writes it.
-- Rollback is forward only (docs/dev/DATABASE-MIGRATIONS.md): a new commit
-- reverts the code and keeps this file; the reverted code ignores the table
-- and binds as before.

CREATE TABLE public.sandbox_pod_front_door_hosts (
    pod_uid text NOT NULL,
    hosts text[] NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL,
    unserved text[],
    CONSTRAINT sandbox_pod_front_door_hosts_pkey PRIMARY KEY (pod_uid),
    CONSTRAINT sandbox_pod_front_door_hosts_pod_uid_check
        CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT sandbox_pod_front_door_hosts_hosts_check
        CHECK ((cardinality(hosts) <= 64)),
    CONSTRAINT sandbox_pod_front_door_hosts_unserved_check
        CHECK ((unserved IS NULL OR (cardinality(unserved) BETWEEN 1 AND 64)))
);
