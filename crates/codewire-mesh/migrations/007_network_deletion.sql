-- Deleted names remain reserved: old capabilities and coordinate sessions
-- identify networks by name and must never address a replacement network.
CREATE TABLE retired_network_names (
    network_id TEXT PRIMARY KEY,
    retired_at TIMESTAMPTZ NOT NULL
);

-- Validate existing rows without guessing ownership or discarding orphans.
-- The parent locks taken by these immediate foreign keys fence child inserts
-- against the network deletion transaction, including other server processes.
ALTER TABLE network_members ADD CONSTRAINT network_members_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE nodes ADD CONSTRAINT nodes_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE RESTRICT;
ALTER TABLE node_enrollments ADD CONSTRAINT node_enrollments_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE groups ADD CONSTRAINT groups_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE group_members ADD CONSTRAINT group_members_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE group_policies ADD CONSTRAINT group_policies_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE kv ADD CONSTRAINT kv_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE access_grants ADD CONSTRAINT access_grants_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
ALTER TABLE task_events ADD CONSTRAINT task_events_network_fk
    FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE;
