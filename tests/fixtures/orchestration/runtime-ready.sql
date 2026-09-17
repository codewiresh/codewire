-- Current runtime adapter for the immutable listener-contract seed. These two
-- synthetic daemon bindings are already bootstrapped, not active setup owners.
-- Do not change historical seed bytes or bypass production readiness checks.
DO $fixture$
BEGIN
    UPDATE sandbox_environment_backend
    SET setup_complete = TRUE,
        setup_owner_generation = NULL,
        setup_owner_activity_id = NULL,
        setup_owner_attempt = NULL,
        setup_owner_phase = NULL,
        setup_owner_status = NULL,
        setup_owner_pod_uid = NULL
    WHERE environment_id IN ('env_exec_contract_backend', 'env_exec_contract_unavailable');

    IF (
        SELECT count(*) FROM sandbox_environment_backend
        WHERE environment_id IN ('env_exec_contract_backend', 'env_exec_contract_unavailable')
          AND setup_complete
          AND setup_owner_generation IS NULL AND setup_owner_activity_id IS NULL
          AND setup_owner_attempt IS NULL AND setup_owner_phase IS NULL
          AND setup_owner_status IS NULL AND setup_owner_pod_uid IS NULL
    ) <> 2 THEN
        RAISE EXCEPTION 'orchestration daemon fixtures must both be ready and idle';
    END IF;
END
$fixture$;
