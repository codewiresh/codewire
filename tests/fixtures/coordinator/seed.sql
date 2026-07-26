-- Contract fixture for the coordinator's Connect bidi stream.
--
-- The running environment supports the cross-language user/sidecar exchange;
-- the stopped environment pins D3's failed_precondition mapping. Tokens are
-- deterministic, ephemeral migration-harness credentials only.

DELETE FROM environments
WHERE id IN (
    '00000000-0000-4000-8000-000000000901',
    '00000000-0000-4000-8000-000000000902'
);

DELETE FROM environment_presets
WHERE id = 'preset_coordinator_contract';

DELETE FROM org_members
WHERE id = 'orgm_coordinator_contract';

DELETE FROM organizations
WHERE id = 'org_coordinator_contract';

DELETE FROM sessions
WHERE id = 'ses_coordinator_contract';

DELETE FROM users
WHERE id = 'usr_coordinator_contract';

INSERT INTO users (id, email, email_verified, name, is_admin)
VALUES (
    'usr_coordinator_contract',
    'coordinator-contract@codewire.test',
    true,
    'Coordinator Contract User',
    false
);

INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
VALUES (
    'ses_coordinator_contract',
    'usr_coordinator_contract',
    encode(digest('coordinator-contract-session-token', 'sha256'), 'hex'),
    NOW() + INTERVAL '4 hours',
    '127.0.0.1',
    'contract-suite'
);

INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
VALUES (
    'org_coordinator_contract',
    'Coordinator Contract Org',
    'coordinator-contract-org',
    'usr_coordinator_contract',
    NOW(),
    NOW()
);

INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES (
    'orgm_coordinator_contract',
    'org_coordinator_contract',
    'usr_coordinator_contract',
    'owner',
    NOW(),
    NOW()
);

INSERT INTO environment_presets (id, org_id, name)
VALUES (
    'preset_coordinator_contract',
    'org_coordinator_contract',
    'Coordinator Contract Preset'
);

INSERT INTO environments (
    id, org_id, created_by, type, state, name, preset_id,
    cpu_millicores, memory_mb, total_running_seconds
)
VALUES
    (
        '00000000-0000-4000-8000-000000000901',
        'org_coordinator_contract',
        'usr_coordinator_contract',
        'sandbox',
        'running',
        'coordinator-contract-running',
        'preset_coordinator_contract',
        500,
        1024,
        0
    ),
    (
        '00000000-0000-4000-8000-000000000902',
        'org_coordinator_contract',
        'usr_coordinator_contract',
        'sandbox',
        'stopped',
        'coordinator-contract-stopped',
        'preset_coordinator_contract',
        500,
        1024,
        0
    );
