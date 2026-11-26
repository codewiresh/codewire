-- Suspend for the standard runtime profile (#5529, docs/dev/IDLE-STOP.md,
-- "Suspend").
--
-- environments.idle_suspend_seconds: how long a running `standard` sandbox
-- may have no activity before its VM pauses inside its Pod. 0 is off, the
-- default for every existing row and for a create that names none; otherwise
-- 300 seconds (five minutes) to 604800 (seven days), as idle_stop_seconds.
--
-- environments.suspended_at: when the sandbox's daemon acknowledged a
-- suspend. NULL while it isn't suspended. A suspended sandbox's state stays
-- 'running', so every access check and action treats it as running; only
-- the periodic calls that would wake it read this column.
--
-- hosted_snapshots.idle_suspend_seconds: the source's timeout when the
-- snapshot was captured, which a fork takes unless its create names one.
-- NULL for a snapshot captured before this migration, which forks as off.
--
-- Every column is nullable or has a constant default, so no row is rewritten,
-- and older code that does not read them keeps working. Rollback drops them;
-- nothing then suspends, and a Sandbox suspended at the time wakes on its
-- next use as it would have anyway.
ALTER TABLE ONLY public.environments
    ADD COLUMN idle_suspend_seconds integer DEFAULT 0 NOT NULL,
    ADD COLUMN suspended_at timestamp with time zone,
    ADD CONSTRAINT environments_idle_suspend_seconds_check
        CHECK (idle_suspend_seconds = 0 OR idle_suspend_seconds BETWEEN 300 AND 604800);

ALTER TABLE ONLY public.hosted_snapshots
    ADD COLUMN idle_suspend_seconds integer,
    ADD CONSTRAINT hosted_snapshots_idle_suspend_seconds_check
        CHECK (idle_suspend_seconds = 0 OR idle_suspend_seconds BETWEEN 300 AND 604800);
