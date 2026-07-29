-- Mesh no longer owns a browser login, session, or device-authorization
-- surface. Codewire is first-launch only, but retain a hard empty-state
-- precondition so this forward-only migration never discards state silently.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users)
       OR EXISTS (SELECT 1 FROM sessions)
       OR EXISTS (SELECT 1 FROM oauth_state)
       OR EXISTS (SELECT 1 FROM oidc_users)
       OR EXISTS (SELECT 1 FROM oidc_sessions)
       OR EXISTS (SELECT 1 FROM oidc_device_flows)
       OR EXISTS (SELECT 1 FROM device_codes)
       OR EXISTS (SELECT 1 FROM github_app)
       OR EXISTS (SELECT 1 FROM nodes WHERE token <> '') THEN
        RAISE EXCEPTION
            'retiring Mesh raw auth/session/device state requires every legacy table and nodes.token to be empty';
    END IF;
END
$$;

ALTER TABLE nodes DROP COLUMN token;

DROP TABLE oidc_device_flows;
DROP TABLE oidc_sessions;
DROP TABLE oidc_users;
DROP TABLE oauth_state;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE device_codes;
DROP TABLE github_app;
