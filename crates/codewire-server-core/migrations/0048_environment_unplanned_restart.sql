-- An unplanned restart of a running Sandbox (#5997, SPEC.md "Unplanned
-- restarts").
--
-- environments.restarted_at: when the Sandbox was running again after a
-- restart nobody asked for. environments.restart_cause: why, one of the four
-- causes. Both are set together with #3772's sandbox_restarted code and
-- cleared together by the next start or stop a member asks for. Null for
-- every existing environment.

ALTER TABLE environments
    ADD COLUMN restarted_at TIMESTAMPTZ,
    ADD COLUMN restart_cause TEXT
        CHECK (restart_cause IN ('pod_failed', 'runtime_replaced', 'node_lost', 'configuration_changed')),
    ADD CONSTRAINT environments_restart_recorded_together
        CHECK ((restarted_at IS NULL) = (restart_cause IS NULL));
