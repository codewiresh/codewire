-- Focused proof against a synthetic test database. Temporary relation shadows
-- production tables in this connection; all proof state is rolled back.
BEGIN;
CREATE TEMP TABLE sandbox_environment_backend (
    environment_id text PRIMARY KEY,
    setup_complete boolean NOT NULL DEFAULT FALSE,
    setup_owner_generation bigint,
    setup_owner_activity_id text,
    setup_owner_attempt integer,
    setup_owner_phase integer,
    setup_owner_status text,
    setup_owner_pod_uid text
);
INSERT INTO sandbox_environment_backend
VALUES
    ('env_exec_contract_backend', FALSE, 1, 'synthetic-setup', 1, 0, 'running', 'synthetic-pod'),
    ('env_exec_contract_unavailable', FALSE, 1, 'synthetic-setup', 1, 0, 'running', 'synthetic-pod'),
    ('unrelated-runtime-ready-proof', FALSE, 7, 'preserve-activity', 3, 2, 'claimed', 'preserve-pod');

DO $proof$
BEGIN
    IF (SELECT count(*) FROM sandbox_environment_backend WHERE NOT setup_complete) <> 3 THEN
        RAISE EXCEPTION 'old synthetic rows must fail readiness';
    END IF;
END
$proof$;

\ir runtime-ready.sql

DO $proof$
BEGIN
    IF (SELECT count(*) FROM sandbox_environment_backend WHERE setup_complete) <> 2 THEN
        RAISE EXCEPTION 'only two fixture rows may become ready';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM sandbox_environment_backend
        WHERE environment_id = 'unrelated-runtime-ready-proof' AND NOT setup_complete
          AND setup_owner_generation = 7 AND setup_owner_activity_id = 'preserve-activity'
          AND setup_owner_attempt = 3 AND setup_owner_phase = 2
          AND setup_owner_status = 'claimed' AND setup_owner_pod_uid = 'preserve-pod'
    ) THEN
        RAISE EXCEPTION 'unrelated setup/readiness ownership changed';
    END IF;
END
$proof$;
ROLLBACK;
