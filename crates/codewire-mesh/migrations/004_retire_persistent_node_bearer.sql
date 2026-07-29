-- Retire the persistent Mesh node bearer without making this migration the
-- irreversible column-drop boundary. WI-9 removes the now-dormant columns
-- after the complete Mesh client cutover.
UPDATE nodes
SET token = ''
WHERE token <> '';

UPDATE oidc_device_flows
SET node_token = ''
WHERE node_token <> '';

DROP INDEX IF EXISTS idx_nodes_token;
