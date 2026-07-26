-- Disposable KIND fixture for the coordinator's UUID-addressed stream.
-- The billing contract fixture loaded immediately before this file provides
-- org_contract_1, usr_contract_user, its membership, and the bearer session
-- token. Coordinator authorization additionally requires a UUID environment
-- id, while the older billing fixture deliberately uses env_contract_1.
INSERT INTO environments (
    id, org_id, created_by, type, state, name, preset_id,
    cpu_millicores, memory_mb, total_running_seconds
)
VALUES (
    '00000000-0000-4000-8000-000000000501',
    'org_contract_1',
    'usr_contract_user',
    'sandbox',
    'running',
    'coordinator-kind-e2e',
    'preset_contract_1',
    500,
    1024,
    0
);
