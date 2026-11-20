-- Idle stop (#3384) and why a stopped environment was stopped.
--
-- environments.stop_reason: who or what stopped it, set with desired_state by
-- a stop and cleared by a start, so it is set only while the environment stays
-- stopped. Today user, credit and idle; a later stop (suspension, hibernation)
-- adds its own word without a migration, so the check bounds only its shape.
--
-- environments.idle_stop_seconds: how long a running cloud sandbox may have no
-- activity before it stops, keeping its disk. 0 is off, the default for every
-- existing row and for a create that names none; otherwise 300 seconds (five
-- minutes) to 604800 (seven days).
--
-- environments.last_activity_at: the newest activity orchestration itself saw
-- (a start, a finished agent or cw runtime request, a preview request from
-- anyone). The daemon's CPU, terminal traffic and connections are read from
-- the daemon, not stored.
--
-- hosted_snapshots.idle_stop_seconds: the source's timeout when the snapshot
-- was captured, which a fork takes unless its create names one. NULL for a
-- snapshot captured before this migration, which forks as off.
--
-- Every column is nullable or has a constant default, so no row is rewritten,
-- and older code that does not read them keeps working. Rollback drops them;
-- stops then record no reason and nothing stops for being idle.
ALTER TABLE ONLY public.environments
    ADD COLUMN stop_reason text,
    ADD COLUMN idle_stop_seconds integer DEFAULT 0 NOT NULL,
    ADD COLUMN last_activity_at timestamp with time zone,
    ADD CONSTRAINT environments_stop_reason_check
        CHECK (stop_reason ~ '^[a-z_]{1,32}$'),
    ADD CONSTRAINT environments_idle_stop_seconds_check
        CHECK (idle_stop_seconds = 0 OR idle_stop_seconds BETWEEN 300 AND 604800);

ALTER TABLE ONLY public.hosted_snapshots
    ADD COLUMN idle_stop_seconds integer,
    ADD CONSTRAINT hosted_snapshots_idle_stop_seconds_check
        CHECK (idle_stop_seconds = 0 OR idle_stop_seconds BETWEEN 300 AND 604800);
