-- A network owner's revocation of a hosted environment's node (#3350). A
-- revoked environment never registers in that network again; the record goes
-- with the network.
CREATE TABLE environment_node_revocations (
    network_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network_id, environment_id),
    CONSTRAINT environment_node_revocations_network_fk
        FOREIGN KEY (network_id) REFERENCES networks(network_id) ON DELETE CASCADE,
    CONSTRAINT environment_node_revocations_environment_check
        CHECK (environment_id <> '')
);
