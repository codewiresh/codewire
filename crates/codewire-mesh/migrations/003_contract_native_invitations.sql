-- Codewire is first-launch and OP-5A1 proves this legacy table empty before
-- deployment. Refuse to reinterpret any plaintext capability or legacy
-- creator identity if that precondition is false.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM invites) THEN
        RAISE EXCEPTION
            'contract-native invitation migration requires an empty invites table';
    END IF;
END
$$;

DROP TABLE invites;

CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_invites_network_created
    ON invites(network_id, created_at);
