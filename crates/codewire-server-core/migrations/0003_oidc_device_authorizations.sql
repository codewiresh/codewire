-- RFC 8628 device-authorization requests for first-party OIDC clients.
--
-- This is intentionally distinct from the legacy /api/auth/device/* table:
-- WI-2A dual-serves the two protocols while the released-artifact observation
-- and retirement boundaries remain WI-2B through WI-2D.

CREATE TABLE oidc_device_authorizations (
    device_code text PRIMARY KEY,
    user_code text NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    user_id text REFERENCES users(id) ON DELETE CASCADE,
    auth_time bigint,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_device_authorizations_status_check
        CHECK (status IN ('pending', 'approved', 'denied')),
    CONSTRAINT oidc_device_authorizations_resolution_check CHECK (
        (status IN ('pending', 'denied') AND user_id IS NULL AND auth_time IS NULL)
        OR (status = 'approved' AND user_id IS NOT NULL)
    )
);

CREATE INDEX oidc_device_authorizations_user_code_idx
    ON oidc_device_authorizations (user_code);

CREATE INDEX oidc_device_authorizations_expires_at_idx
    ON oidc_device_authorizations (expires_at);
