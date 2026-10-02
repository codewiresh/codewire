CREATE TABLE supervisor_metadata (
           key TEXT PRIMARY KEY NOT NULL,
           value TEXT NOT NULL
         ) STRICT;
         CREATE TABLE environments (
           id TEXT PRIMARY KEY NOT NULL,
           name TEXT UNIQUE NOT NULL,
           desired_state TEXT NOT NULL CHECK (desired_state IN ('stopped', 'running', 'deleted')),
           observed_state TEXT NOT NULL CHECK (observed_state IN ('stopped', 'starting', 'running', 'error', 'orphaned', 'deleting')),
           vcpus INTEGER NOT NULL CHECK (vcpus BETWEEN 1 AND 32),
           memory_mib INTEGER NOT NULL CHECK (memory_mib BETWEEN 128 AND 65536),
           disk_bytes INTEGER NOT NULL CHECK (disk_bytes > 0),
           docker_disk_bytes INTEGER NOT NULL CHECK (docker_disk_bytes >= 0),
           generation INTEGER NOT NULL CHECK (generation >= 0),
           host_ports_json BLOB NOT NULL,
           mesh_attachment_json BLOB NULL,
           workspace_plan_json BLOB NOT NULL,
           project_spec_json BLOB NOT NULL,
           project_spec_sha256 TEXT NOT NULL,
           access_profile_reference TEXT NULL,
           access_profile_id TEXT NULL,
           access_profile_revision INTEGER NULL,
           runner_json BLOB NULL,
           active_artifact_generation TEXT NOT NULL,
           staging_artifact_generation TEXT NULL,
           active_workspace_generation_json BLOB NULL,
           staging_workspace_generation_json BLOB NULL,
           rollback_workspace_generation_json BLOB NULL,
           platform_source_authority_json BLOB NULL,
           CHECK (
             (access_profile_reference IS NULL AND access_profile_id IS NULL AND access_profile_revision IS NULL) OR
             (access_profile_reference IS NOT NULL AND access_profile_id IS NOT NULL AND access_profile_revision > 0)
           )
         ) STRICT;
         CREATE TABLE supervisor_settings (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           current_environment_id TEXT NULL,
           FOREIGN KEY (current_environment_id) REFERENCES environments(id) ON DELETE SET NULL
         ) STRICT;
         INSERT INTO supervisor_settings(singleton, current_environment_id) VALUES (1, NULL);
         CREATE TABLE owned_objects (
           environment_id TEXT NOT NULL,
           kind TEXT NOT NULL,
           relative_path BLOB NOT NULL,
           identity_json BLOB NULL,
           lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'staging', 'trash')),
           PRIMARY KEY (environment_id, kind, relative_path),
           FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
         ) STRICT;
         CREATE TABLE operations (
           operation_id TEXT PRIMARY KEY NOT NULL,
           request_id TEXT UNIQUE NOT NULL,
           environment_id TEXT NULL,
           kind TEXT NOT NULL,
           phase TEXT NOT NULL CHECK (phase IN ('intent', 'effect_applied', 'completed', 'failed', 'interrupted')),
           checkpoint INTEGER NOT NULL CHECK (checkpoint >= 0),
           payload_json BLOB NOT NULL,
           result_json BLOB NULL,
           error_code TEXT NULL,
           created_unix_ms INTEGER NOT NULL,
           updated_unix_ms INTEGER NOT NULL
         ) STRICT;