-- Hosted Mesh is first-launch only. OP-4B1 proves every Mesh application
-- table empty before this migration reaches dev, so ownership is never
-- guessed, defaulted, or backfilled from a network name.
ALTER TABLE networks
    ADD COLUMN organization_id TEXT NOT NULL;

CREATE INDEX idx_networks_organization_id ON networks(organization_id);
