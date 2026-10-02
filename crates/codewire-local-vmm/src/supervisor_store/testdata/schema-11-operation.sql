INSERT OR IGNORE INTO operations(
               operation_id, request_id, environment_id, kind, phase, checkpoint,
               payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, 'intent', 0, ?5, NULL, NULL, ?6, ?6)