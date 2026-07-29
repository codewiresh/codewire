-- Retire the dormant primary OIDC client formerly used by hosted Mesh.
--
-- Access tokens deliberately have no foreign key to oidc_clients, so remove
-- only the exact former client's rows before deleting the client. The client
-- deletion cascades only through the schema-declared authorization, refresh,
-- and device-authorization dependents.
DELETE FROM oidc_access_tokens
WHERE client_id = 'codewire-mesh';

DELETE FROM oidc_clients
WHERE id = 'codewire-mesh';
