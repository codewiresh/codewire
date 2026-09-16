-- Contract fixture for codewire-orchestration's Connect services.
--
-- The admin fixture user owns both organizations. A key created for the
-- primary organization must still receive existence-hiding not_found from
-- the secondary organization, proving that one key authorizes exactly one
-- organization even though its underlying user belongs to both.

DELETE FROM environment_access
WHERE id = 'enva_prereq_foreign_grant'
   OR environment_id LIKE 'env_environment_contract_%'
   OR environment_id LIKE 'env_exec_contract_%';

DELETE FROM environment_lifecycle_journal
WHERE id = 'elj_admin_contract_1';

DELETE FROM audit_logs
WHERE id IN ('audit_admin_contract_1', 'audit_admin_contract_null_metadata_1');

DELETE FROM billing_events
WHERE stripe_item_id = 'admin-contract-monthly-usage';

DELETE FROM environment_logs
WHERE id LIKE 'log_environment_contract_%'
   OR id LIKE 'log_admin_contract_%'
   OR environment_id LIKE 'env_environment_contract_%';

DELETE FROM environments
WHERE id IN (
    'env_admin_contract_read',
    'env_prereq_foreign_creator',
    'env_prereq_foreign_grant',
    'env_prereq_foreign_role'
)
   OR id LIKE 'env_environment_contract_%'
   OR id LIKE 'env_exec_contract_%'
   OR name LIKE 'environment-contract-created-%'
   OR name = 'environment-contract-quota-rejected';

DELETE FROM org_member_assignments
WHERE id = 'orgma_prereq_foreign_member';

DELETE FROM environments
WHERE preset_id IN (
    SELECT id
    FROM environment_presets
    WHERE org_id IN ('org_apikey_contract_1', 'org_apikey_contract_2')
       OR id = 'preset_contract_official'
);

DELETE FROM platform_environment_access_bindings
WHERE profile_id = '22222222-2222-4222-8222-222222222226';

DELETE FROM platform_access_profiles
WHERE id = '22222222-2222-4222-8222-222222222226';

DELETE FROM sandbox_template_config
WHERE preset_id IN (
    SELECT id
    FROM environment_presets
    WHERE org_id IN ('org_apikey_contract_1', 'org_apikey_contract_2')
       OR id = 'preset_contract_official'
);

DELETE FROM environment_presets
WHERE org_id IN (
    'org_admin_contract',
    'org_apikey_contract_1',
    'org_apikey_contract_2'
)
   OR id = 'preset_contract_official';

DELETE FROM secret_projects
WHERE org_id IN ('org_apikey_contract_1', 'org_apikey_contract_2');

DELETE FROM api_keys
WHERE org_id IN ('org_apikey_contract_1', 'org_apikey_contract_2');

DELETE FROM environment_quotas
WHERE org_id IN ('org_apikey_contract_1', 'org_apikey_contract_2');

DELETE FROM sessions
WHERE id IN (
    'ses_apikey_contract_admin',
    'ses_apikey_contract_user',
    'ses_orchestration_global_admin'
);

-- Tenant-secret envelopes have no user foreign key, so reset them explicitly.
DELETE FROM tenant_secrets
WHERE path IN (
    '/users/usr_apikey_contract_admin',
    '/users/usr_apikey_contract_user'
);

DELETE FROM tenant_secret_deks
WHERE scope = 'user'
  AND scope_id IN ('usr_apikey_contract_admin', 'usr_apikey_contract_user')
  AND NOT EXISTS (
      SELECT 1 FROM tenant_secrets
      WHERE tenant_secrets.dek_id = tenant_secret_deks.dek_id
  );

DELETE FROM org_members
WHERE id IN (
    'orgm_apikey_contract_admin_1',
    'orgm_apikey_contract_admin_2',
    'orgm_apikey_contract_user_1',
    'orgm_prereq_attacker_owner'
);

DELETE FROM organizations
WHERE id IN (
    'org_admin_contract',
    'org_apikey_contract_1',
    'org_apikey_contract_2',
    'org_prereq_attacker'
);

DELETE FROM users
WHERE id IN (
    'usr_apikey_contract_admin',
    'usr_apikey_contract_user',
    'usr_orchestration_global_admin'
);

INSERT INTO users (id, email, email_verified, name, is_admin)
VALUES
    ('usr_apikey_contract_admin', 'apikey-admin@codewire.test', true, 'API Key Contract Admin', false),
    ('usr_apikey_contract_user',  'apikey-user@codewire.test',  true, 'API Key Contract User',  false),
    ('usr_orchestration_global_admin', 'global-admin@codewire.test', true, 'Global Contract Admin', true);

INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
VALUES
    ('ses_apikey_contract_admin', 'usr_apikey_contract_admin', encode(digest('apikey-contract-admin-session-token', 'sha256'), 'hex'), NOW() + INTERVAL '4 hours', '127.0.0.1', 'contract-suite'),
    ('ses_apikey_contract_user',  'usr_apikey_contract_user',  encode(digest('apikey-contract-user-session-token', 'sha256'), 'hex'),  NOW() + INTERVAL '4 hours', '127.0.0.1', 'contract-suite'),
    ('ses_orchestration_global_admin', 'usr_orchestration_global_admin', encode(digest('orchestration-global-admin-session-token', 'sha256'), 'hex'), NOW() + INTERVAL '4 hours', '127.0.0.1', 'contract-suite');

INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
VALUES
    ('org_admin_contract', 'Admin Contract Fixtures', 'admin-contract-fixtures', 'usr_orchestration_global_admin', '2026-07-10 09:59:59', '2026-07-10 09:59:59'),
    ('org_apikey_contract_1', 'API Key Contract Primary',   'apikey-contract-primary',   'usr_apikey_contract_admin', '2026-07-10 10:00:00.123456', '2026-07-10 10:00:00.123456'),
    ('org_apikey_contract_2', 'API Key Contract Secondary', 'apikey-contract-secondary', 'usr_apikey_contract_admin', '2026-07-10 10:00:01.654321', '2026-07-10 10:00:01.654321'),
    ('org_prereq_attacker', 'Prerequisite Attacker', 'prerequisite-attacker', 'usr_apikey_contract_user', '2026-07-10 10:00:02', '2026-07-10 10:00:02');

INSERT INTO audit_logs (
    id, "timestamp", action, user_id, ip_address, user_agent, metadata, severity
)
VALUES
    (
        'audit_admin_contract_1',
        '2026-07-10 10:00:03',
        'contract.admin.fixture',
        'usr_orchestration_global_admin',
        '203.0.113.9',
        'orchestration-contract',
        '{"attempt": 1, "source": "contract"}'::jsonb,
        'info'
    ),
    (
        'audit_admin_contract_null_metadata_1',
        '2026-07-10 10:00:04',
        'contract.admin.null-metadata',
        'usr_orchestration_global_admin',
        '203.0.113.10',
        'orchestration-contract',
        'null'::jsonb,
        'info'
    );

INSERT INTO billing_events (
    event_type, org_id, amount_cents, currency, stripe_item_id, metadata, created_at
)
VALUES (
    'environment_usage',
    'org_admin_contract',
    123,
    'usd',
    'admin-contract-monthly-usage',
    '{"elapsed_seconds": 3600, "cpu_millicores": 1000, "memory_mb": 1024}'::jsonb,
    NOW()
);

INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES
    ('orgm_apikey_contract_admin_1', 'org_apikey_contract_1', 'usr_apikey_contract_admin', 'owner',  '2026-07-10 10:01:00', '2026-07-10 10:01:00'),
    ('orgm_apikey_contract_admin_2', 'org_apikey_contract_2', 'usr_apikey_contract_admin', 'owner',  '2026-07-10 10:02:00', '2026-07-10 10:02:00'),
    ('orgm_apikey_contract_user_1',  'org_apikey_contract_1', 'usr_apikey_contract_user',  'member', '2026-07-10 10:03:00', '2026-07-10 10:03:00'),
    ('orgm_prereq_attacker_owner', 'org_prereq_attacker', 'usr_apikey_contract_user', 'owner', '2026-07-10 10:03:01', '2026-07-10 10:03:01');

INSERT INTO environment_quotas (
    org_id, max_concurrent_environments, max_concurrent_sandbox,
    max_cpu_millicores, max_memory_mb
)
VALUES
    ('org_apikey_contract_1', 100, 100, 320000, 655360),
    ('org_apikey_contract_2', 0, 0, 0, 0);

INSERT INTO org_member_assignments (id, org_member_id, assignment, granted_by, created_at)
VALUES (
    'orgma_prereq_foreign_member',
    'orgm_apikey_contract_admin_2',
    'billing_admin',
    'usr_apikey_contract_admin',
    '2026-07-10 10:03:02'
);

-- SecretProject remains an independent management-plane fixture. PresetService
-- uses one global official preset for cross-organization reads and one active
-- environment proving the preset-in-use lifecycle error.
INSERT INTO secret_projects (id, org_id, name, created_at)
VALUES
    (
        'sp_preset_contract_1',
        'org_apikey_contract_1',
        'preset-contract-secrets',
        '2026-07-10 10:04:00'
    ),
    (
        '11111111-1111-4111-8111-111111111115',
        'org_apikey_contract_1',
        'wire-contract-project',
        '2026-07-10 10:04:01'
    );

-- A deliberately empty personal profile proves source admission and immutable
-- revision binding without enrolling or reading any credential material.
BEGIN;
INSERT INTO platform_access_profiles (
    id, user_id, name, current_revision, created_at, updated_at
)
VALUES (
    '22222222-2222-4222-8222-222222222226',
    'usr_apikey_contract_admin',
    'wire-contract-empty',
    1,
    '2026-07-10 10:04:02',
    '2026-07-10 10:04:02'
);
INSERT INTO platform_access_profile_revisions (profile_id, revision, created_at)
VALUES (
    '22222222-2222-4222-8222-222222222226',
    1,
    '2026-07-10 10:04:02'
);
COMMIT;

INSERT INTO environment_presets (
    id, org_id, name, slug, description, official, language,
    build_status, default_ttl_seconds, project_spec, created_at
)
VALUES
    (
        'preset_contract_official', NULL, 'Official Contract Preset',
        'official-contract', 'Global preset fixture', true, 'rust',
        'ready', 3600,
        '{"schema_version":1,"working_directory":"/workspace","environment":{"OFFICIAL":"true"},"resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:05:00.123456'
    ),
    (
        'preset_contract_in_use', 'org_apikey_contract_1',
        'In-use Contract Preset', 'preset-contract-in-use',
        'Active environment fixture', false, NULL,
        'ready', NULL,
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:06:00.654321'
    ),
    (
        'preset_admin_contract', 'org_admin_contract',
        'Admin Contract Preset', 'admin-contract-preset',
        'Admin startup timing fixture', false, NULL,
        'ready', NULL,
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:06:01'
    );

INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES (
    'env_preset_contract_in_use',
    'org_apikey_contract_1',
    'usr_apikey_contract_admin',
    'sandbox',
    'preset-contract-in-use',
    'running',
    'started',
    'preset_contract_in_use',
    '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
    '2026-07-10 10:07:00'
);

-- Cross-tenant authorization fixtures (#418/#419). The ordinary user owns
-- org_prereq_attacker and is only a member of the primary contract org. The
-- three secondary-org environments isolate the creator, path-org owner, and
-- explicit-grant shortcuts that must all fail before authorization succeeds.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES
    (
        'env_prereq_foreign_creator', 'org_apikey_contract_2',
        'usr_apikey_contract_user', 'sandbox', 'prereq-foreign-creator',
        'running', 'started', 'preset_contract_official',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:07:01'
    ),
    (
        'env_prereq_foreign_role', 'org_apikey_contract_2',
        'usr_apikey_contract_admin', 'sandbox', 'prereq-foreign-role',
        'running', 'started', 'preset_contract_official',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:07:02'
    ),
    (
        'env_prereq_foreign_grant', 'org_apikey_contract_2',
        'usr_apikey_contract_admin', 'sandbox', 'prereq-foreign-grant',
        'running', 'started', 'preset_contract_official',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:07:03'
    );

INSERT INTO environment_access (
    id, environment_id, user_id, permission, granted_by, created_at
)
VALUES (
    'enva_prereq_foreign_grant',
    'env_prereq_foreign_grant',
    'usr_apikey_contract_user',
    'owner',
    'usr_apikey_contract_admin',
    '2026-07-10 10:07:04'
);

-- PortService fixtures pin viewer/operator/owner access independently. The
-- admin fixture creates the environments so the non-admin member exercises
-- the explicit environment_access grant rather than the creator shortcut.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES
    (
        'env_port_contract_viewer', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'port-contract-viewer',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:08:00'
    ),
    (
        'env_port_contract_operator', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'port-contract-operator',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:09:00'
    ),
    (
        'env_port_contract_owner', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'port-contract-owner',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:10:00'
    );

INSERT INTO environment_access (
    id, environment_id, user_id, permission, granted_by, created_at
)
VALUES
    (
        'enva_port_contract_viewer', 'env_port_contract_viewer',
        'usr_apikey_contract_user', 'viewer', 'usr_apikey_contract_admin',
        '2026-07-10 10:11:00'
    ),
    (
        'enva_port_contract_operator', 'env_port_contract_operator',
        'usr_apikey_contract_user', 'operator', 'usr_apikey_contract_admin',
        '2026-07-10 10:12:00'
    ),
    (
        'enva_port_contract_owner', 'env_port_contract_owner',
        'usr_apikey_contract_user', 'owner', 'usr_apikey_contract_admin',
        '2026-07-10 10:13:00'
    );

-- EnvironmentService fixtures isolate every mutating unary RPC for both
-- Connect codecs. The shared get/list/trust fixture is running with no backend
-- row, so setup_complete is false and the contract emits a 2s poll interval.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    ttl_seconds, shutdown_at, protected, deletion_requested_at,
    deletion_grace_until, created_at, project_spec
)
VALUES
    (
        'env_environment_contract_read', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-read',
        'running', 'started', 'preset_contract_in_use', 3600,
        '2026-07-10 11:00:00', false, NULL, NULL, '2026-07-10 10:20:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_stop_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-stop-binary',
        'running', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:21:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_stop_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-stop-json',
        'running', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:22:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_start_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-start-binary',
        'stopped', 'stopped', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:23:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_start_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-start-json',
        'stopped', 'stopped', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:24:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_retry_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-retry-binary',
        'pending', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:25:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_retry_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-retry-json',
        'pending', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:26:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_protect_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-protect-binary',
        'stopped', 'stopped', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:27:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_protect_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-protect-json',
        'stopped', 'stopped', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:28:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_cancel_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-cancel-binary',
        'stopped', 'stopped', 'preset_contract_in_use', 3600,
        '2026-07-10 11:30:00', false, '2026-07-10 10:29:00',
        '2026-07-10 10:59:00', '2026-07-10 10:29:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_cancel_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-cancel-json',
        'stopped', 'stopped', 'preset_contract_in_use', 3600,
        '2026-07-10 11:31:00', false, '2026-07-10 10:30:00',
        '2026-07-10 11:00:00', '2026-07-10 10:30:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_ttl_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-ttl-binary',
        'running', 'started', 'preset_contract_in_use', 3600,
        '2026-07-10 12:00:00', false, NULL, NULL, '2026-07-10 10:31:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_ttl_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-ttl-json',
        'running', 'started', 'preset_contract_in_use', 3600,
        '2026-07-10 12:01:00', false, NULL, NULL, '2026-07-10 10:32:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_access_binary', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-access-binary',
        'running', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:33:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    ),
    (
        'env_environment_contract_access_json', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-access-json',
        'running', 'started', 'preset_contract_in_use', NULL,
        NULL, false, NULL, NULL, '2026-07-10 10:34:00',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
    );

-- A stopped, setup-independent environment gives the public source mutation
-- contract a stable operation fence. The test updates metadata only; it does
-- not claim a running workspace projection or child execution.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    environment_operation_generation, project_spec, created_at
)
VALUES (
    'env_environment_contract_sources',
    'org_apikey_contract_1',
    'usr_apikey_contract_admin',
    'sandbox',
    'environment-contract-sources',
    'stopped',
    'stopped',
    'preset_contract_in_use',
    7,
    '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
    '2026-07-10 10:34:01'
);

INSERT INTO environment_resize_operations (
    id, org_id, environment_id, request_id,
    previous_cpu_millicores, previous_memory_mb, previous_disk_gb,
    desired_cpu_millicores, desired_memory_mb, desired_disk_gb,
    last_applied_cpu_millicores, last_applied_memory_mb, last_applied_disk_gb,
    previous_state, previous_desired_state, state, force,
    disruption_policy, planned_mode, applied_mode, pod_replaced,
    created_at, updated_at, completed_at
)
VALUES (
    'resize_environment_contract_completed', 'org_apikey_contract_1',
    'env_environment_contract_read', 'request-environment-contract-completed',
    2000, 4096, 10, 3000, 6144, 20, 3000, 6144, 20,
    'running', 'started', 'completed', false,
    'live_only', 'in_place', 'in_place', false,
    '2026-07-10 10:40:00', '2026-07-10 10:42:00', '2026-07-10 10:42:00'
);

-- WI-7 pins every database state and desired-state enum as a literal proto
-- JSON name. Polling fixtures additionally distinguish running setup in
-- progress from setup complete; the lifecycle fixture remains untouched by
-- the happy-path mutations above.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES
    (
        'env_environment_contract_invalid_state', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-invalid-state',
        'stopped', 'stopped', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:00'
    ),
    (
        'env_environment_contract_state_pending', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-pending',
        'pending', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:01'
    ),
    (
        'env_environment_contract_state_pending_build', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-pending-build',
        'pending_build', 'stopped', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:02'
    ),
    (
        'env_environment_contract_state_building', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-building',
        'building', 'destroyed', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:03'
    ),
    (
        'env_environment_contract_state_build_failed', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-build-failed',
        'build_failed', 'archived', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:04'
    ),
    (
        'env_environment_contract_state_pulling_snapshot', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-pulling-snapshot',
        'pulling_snapshot', 'resized', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:05'
    ),
    (
        'env_environment_contract_state_creating', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-creating',
        'creating', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:06'
    ),
    (
        'env_environment_contract_state_starting', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-starting',
        'starting', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:07'
    ),
    (
        'env_environment_contract_state_running', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-running',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:08'
    ),
    (
        'env_environment_contract_state_running_complete', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-running-complete',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:09'
    ),
    (
        'env_environment_contract_state_stopping', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-stopping',
        'stopping', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:10'
    ),
    (
        'env_environment_contract_state_stopped', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-stopped',
        'stopped', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:11'
    ),
    (
        'env_environment_contract_state_archiving', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-archiving',
        'archiving', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:12'
    ),
    (
        'env_environment_contract_state_archived', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-archived',
        'archived', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:13'
    ),
    (
        'env_environment_contract_state_restoring', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-restoring',
        'restoring', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:14'
    ),
    (
        'env_environment_contract_state_resizing', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-resizing',
        'resizing', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:15'
    ),
    (
        'env_environment_contract_state_destroying', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-destroying',
        'destroying', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:16'
    ),
    (
        'env_environment_contract_state_destroyed', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-destroyed',
        'destroyed', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:17'
    ),
    (
        'env_environment_contract_state_error', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-error',
        'error', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:18'
    ),
    (
        'env_environment_contract_state_unknown', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'environment-contract-state-unknown',
        'unknown', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:19'
    );

INSERT INTO sandbox_environment_backend (
    environment_id, namespace, setup_complete
)
VALUES (
    'env_environment_contract_state_running_complete',
    'environment-contract-running-complete', true
);

-- AdminService startup fixtures use a dedicated organization and environment
-- so their four terminal phase rows cannot alter EnvironmentService streams.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES (
    'env_admin_contract_read', 'org_admin_contract',
    'usr_orchestration_global_admin', 'sandbox', 'admin-contract-read',
    'running', 'started', 'preset_admin_contract',
    '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
    NOW() - INTERVAL '5 minutes'
);

-- StreamLogs uses two rows with an identical timestamp to prove its cursor is
-- the stable (created_at, id) tuple rather than the legacy timestamp-only SSE
-- cursor. Neither row is terminal, so bounded reads return the complete list.
INSERT INTO environment_logs (
    id, environment_id, phase, status, message, metadata, created_at
)
VALUES
    (
        'log_environment_contract_01', 'env_environment_contract_read',
        'provision', 'started', 'contract log one',
        '{"attempt": 1, "source": "contract"}'::jsonb,
        '2026-07-10 10:40:00+00'
    ),
    (
        'log_environment_contract_02', 'env_environment_contract_read',
        'provision', 'running', 'contract log two', NULL,
        '2026-07-10 10:40:00+00'
    ),
    (
        'log_admin_contract_create', 'env_admin_contract_read',
        'create_claim', 'completed', 'claim created', '{"duration_ms": 100}'::jsonb,
        NOW() - INTERVAL '4 minutes'
    ),
    (
        'log_admin_contract_wait', 'env_admin_contract_read',
        'wait_for_ready', 'completed', 'sandbox ready', '{"duration_ms": 250.9}'::jsonb,
        NOW() - INTERVAL '3 minutes'
    ),
    (
        'log_admin_contract_gateway', 'env_admin_contract_read',
        'gateway_ready', 'completed', NULL, '{"duration_ms": 75}'::jsonb,
        NOW() - INTERVAL '2 minutes'
    ),
    (
        'log_admin_contract_file', 'env_admin_contract_read',
        'file_ready', 'completed', NULL, NULL,
        NOW() - INTERVAL '1 minute'
    );

INSERT INTO environment_lifecycle_journal (
    id, environment_id, kind, actor, phase, status, from_state, to_state,
    checkpoint, reason, metadata, created_at
)
VALUES (
    'elj_admin_contract_1',
    'env_admin_contract_read',
    'transition',
    'usr_orchestration_global_admin',
    'provision',
    'completed',
    'pending',
    'running',
    'gateway-ready',
    'contract fixture',
    '{"source": "contract"}'::jsonb,
    '2026-07-10 10:41:00+00'
);

-- ExecService and FileService resolve one actual daemon fixture plus one
-- deterministic unavailable target after every database gate succeeds.
INSERT INTO environments (
    id, org_id, created_by, type, name, state, desired_state, preset_id,
    project_spec, created_at
)
VALUES
    (
        'env_exec_contract_backend', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'exec-contract-backend',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:00'
    ),
    (
        'env_exec_contract_unavailable', 'org_apikey_contract_1',
        'usr_apikey_contract_admin', 'sandbox', 'exec-contract-unavailable',
        'running', 'started', 'preset_contract_in_use',
        '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb,
        '2026-07-10 10:35:01'
    );

INSERT INTO sandbox_environment_backend (environment_id, namespace, pod_name, pod_ip)
VALUES
    (
        'env_exec_contract_backend', 'exec-contract',
        'exec-contract-pod', '10.244.0.21'
    ),
    (
        'env_exec_contract_unavailable', 'exec-contract',
        'exec-contract-unavailable-pod', '10.244.0.22'
    );

-- Deterministic state for REST/Connect anti-divergence. The hash is never
-- used for authentication; only non-secret metadata and timestamp mapping are
-- asserted. Microseconds prove the comparison intentionally occurs at second
-- precision because REST truncates while Connect preserves DB precision.
INSERT INTO api_keys (
    id, user_id, org_id, name, key_hash, key_prefix, scopes,
    last_used_at, expires_at, disabled_at, created_at
)
VALUES (
    'ak_apikey_contract_parity',
    'usr_apikey_contract_admin',
    'org_apikey_contract_1',
    'contract-parity',
    '0000000000000000000000000000000000000000000000000000000000000000',
    'a1b2c3d4',
    ARRAY['environments:read', 'secrets:read'],
    '2026-07-11 12:34:56.654321',
    '2027-07-11 12:34:56.987654',
    NULL,
    '2026-07-10 01:02:03.456789'
);
