-- The typed Mesh coordinator validates canonical credentials directly.
-- Runtime-token issuer state has no remaining reader or writer.
DELETE FROM kv
WHERE namespace = 'mesh.networkauth';
