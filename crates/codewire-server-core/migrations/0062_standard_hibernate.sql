-- Hibernate for the standard runtime profile (#6647, docs/dev/SANDBOX-SLEEP.md,
-- docs/dev/BILLING.md).
--
-- environments.idle_hibernate_seconds: how long a `standard` sandbox may have
-- no activity before it hibernates to its encrypted volume and its Pod ends.
-- 0 is off (the default for every existing row and creates that name none);
-- otherwise 300 seconds (five minutes) to 604800 (seven days), strictly longer
-- than idle_suspend_seconds when both are enabled.
--
-- environments.hibernated_at, hibernate_reason, hibernate_record: present while
-- a stopped `standard` sandbox holds a restorable hibernate memory image on its
-- volume, populated only from orchestration-requested hibernate plus the Pod
-- runtime's host-observed `vm-hibernate-record` log line, and cleared on start,
-- stop, destroy, or fallback.
--
-- environments.hibernate_fallback_reason: set when a restore attempt could not
-- restore the memory image and cold-booted cleanly from disks (processes lost,
-- files kept), shown to the user until the next hibernate or stop.
--
-- hosted_snapshots.idle_hibernate_seconds: the source's idle_hibernate timeout
-- when the snapshot was captured, which a fork inherits unless overridden.
--
-- sandbox_running_sessions.rate_kind: widened to include 'hibernated', which
-- draws only allocated disk_gib at the rate card's parked_storage_per_gib_hour
-- rate, exactly like 'paused'.
--
-- Every new column is nullable or has a constant default, so no row is
-- rewritten and older code keeps working. Rollback drops the new columns and
-- restores the previous rate_kind check constraint.
ALTER TABLE ONLY public.environments
    ADD COLUMN idle_hibernate_seconds integer DEFAULT 0 NOT NULL,
    ADD COLUMN hibernated_at timestamp with time zone,
    ADD COLUMN hibernate_reason text,
    ADD COLUMN hibernate_record jsonb,
    ADD COLUMN hibernate_fallback_reason text,
    ADD CONSTRAINT environments_idle_hibernate_seconds_check
        CHECK (idle_hibernate_seconds = 0 OR idle_hibernate_seconds BETWEEN 300 AND 604800),
    ADD CONSTRAINT environments_idle_hibernate_after_suspend_check
        CHECK (idle_suspend_seconds = 0 OR idle_hibernate_seconds = 0
               OR idle_hibernate_seconds > idle_suspend_seconds),
    ADD CONSTRAINT environments_hibernate_reason_check
        CHECK (hibernate_reason IS NULL OR hibernate_reason IN ('idle', 'user')),
    ADD CONSTRAINT environments_hibernate_mark_check
        CHECK ((hibernated_at IS NULL) = (hibernate_record IS NULL)
               AND (hibernated_at IS NULL) = (hibernate_reason IS NULL));

ALTER TABLE ONLY public.hosted_snapshots
    ADD COLUMN idle_hibernate_seconds integer,
    ADD CONSTRAINT hosted_snapshots_idle_hibernate_seconds_check
        CHECK (idle_hibernate_seconds = 0 OR idle_hibernate_seconds BETWEEN 300 AND 604800);

ALTER TABLE ONLY public.sandbox_running_sessions
    DROP CONSTRAINT sandbox_running_sessions_rate_kind_check,
    ADD CONSTRAINT sandbox_running_sessions_rate_kind_check
        CHECK (rate_kind IN ('running', 'paused', 'hibernated'));
