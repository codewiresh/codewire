//! Complete shared SQL schema and environment record decoding.
//! Linux and native admission use the same persisted contract.

use crate::host_port::{HostPortBinding, validate_canonical_host_port_bindings};
use crate::mesh_ingress::MeshAttachment;
use crate::supervisor_metadata::{
    EnvironmentRecord, PlatformSourceAuthority, RunnerRecord, SUPERVISOR_STATE_SCHEMA,
    StoredEnvironmentState, SupervisorState,
};
use crate::supervisor_store_error::SupervisorStoreError;
use crate::workspace_generation::WorkspaceGenerationRecord;
use crate::workspace_plan::WorkspacePlan;
use codewire_access::{
    AccessProfileId, AccessProfileReference, EnvironmentAccessBinding, EnvironmentId,
};
use rusqlite::Connection;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) const SCHEMA_SQL: &str = "CREATE TABLE supervisor_metadata (
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
         ) STRICT;";

pub(crate) fn load_state(connection: &Connection) -> Result<SupervisorState, SupervisorStoreError> {
    let current_id: Option<String> = connection.query_row(
        "SELECT current_environment_id FROM supervisor_settings WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT id, name, observed_state, vcpus, memory_mib, disk_bytes, docker_disk_bytes, generation, \
                host_ports_json, mesh_attachment_json, workspace_plan_json, \
                project_spec_json, project_spec_sha256, \
                access_profile_reference, access_profile_id, access_profile_revision, \
                runner_json, active_artifact_generation, staging_artifact_generation, \
                active_workspace_generation_json, staging_workspace_generation_json, \
                rollback_workspace_generation_json, platform_source_authority_json \
         FROM environments ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Vec<u8>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?,
            row.get::<_, Vec<u8>>(10)?,
            row.get::<_, Vec<u8>>(11)?,
            row.get::<_, String>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<String>>(14)?,
            row.get::<_, Option<i64>>(15)?,
            row.get::<_, Option<Vec<u8>>>(16)?,
            row.get::<_, String>(17)?,
            row.get::<_, Option<String>>(18)?,
            row.get::<_, Option<Vec<u8>>>(19)?,
            row.get::<_, Option<Vec<u8>>>(20)?,
            row.get::<_, Option<Vec<u8>>>(21)?,
            row.get::<_, Option<Vec<u8>>>(22)?,
        ))
    })?;
    let mut environments = BTreeMap::new();
    let mut current = None;
    for row in rows {
        let (
            id,
            name,
            observed_state,
            vcpus,
            memory_mib,
            disk_bytes,
            docker_disk_bytes,
            generation,
            host_ports_json,
            mesh_attachment_json,
            workspace_plan_json,
            project_spec_json,
            project_spec_sha256,
            access_profile_reference,
            access_profile_id,
            access_profile_revision,
            runner_json,
            active_artifact_generation,
            staging_artifact_generation,
            active_workspace_generation_json,
            staging_workspace_generation_json,
            rollback_workspace_generation_json,
            platform_source_authority_json,
        ) = row?;
        let id_text = id;
        let id = parse_uuid(&id_text)?;
        let runner = runner_json
            .map(|bytes| serde_json::from_slice::<RunnerRecord>(&bytes))
            .transpose()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let host_ports = serde_json::from_slice::<Vec<HostPortBinding>>(&host_ports_json)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        validate_canonical_host_port_bindings(&host_ports)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let mesh = mesh_attachment_json
            .map(|bytes| serde_json::from_slice::<MeshAttachment>(&bytes))
            .transpose()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        if mesh.as_ref().is_some_and(|mesh| mesh.validate().is_err()) {
            return Err(SupervisorStoreError::InvalidState);
        }
        let record = EnvironmentRecord {
            cw_runtime: None,
            id,
            name: name.clone(),
            state: StoredEnvironmentState::parse(&observed_state)
                .ok_or(SupervisorStoreError::InvalidState)?,
            vcpus: u8::try_from(vcpus).map_err(|_| SupervisorStoreError::InvalidState)?,
            memory_mib: u32::try_from(memory_mib)
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            disk_bytes: u64::try_from(disk_bytes)
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            docker_disk_bytes: u64::try_from(docker_disk_bytes)
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            generation: u64::try_from(generation)
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            host_ports,
            mesh,
            workspace_plan: WorkspacePlan::decode_canonical(&workspace_plan_json)
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            platform_source_authority: platform_source_authority_json
                .map(|bytes| {
                    let authority: PlatformSourceAuthority = serde_json::from_slice(&bytes)
                        .map_err(|_| SupervisorStoreError::InvalidState)?;
                    authority
                        .validate()
                        .map_err(|_| SupervisorStoreError::InvalidState)?;
                    Ok::<_, SupervisorStoreError>(authority)
                })
                .transpose()?,
            access_profile: access_profile_reference
                .map(|reference| reference.parse::<AccessProfileReference>())
                .transpose()
                .map_err(|_| SupervisorStoreError::InvalidState)?,
            access_binding: decode_access_binding(
                &id_text,
                access_profile_id,
                access_profile_revision,
            )?,
            runner,
            active_artifact_generation: Some(active_artifact_generation),
            staging_artifact_generation,
            active_workspace_generation: decode_workspace_generation(
                active_workspace_generation_json.as_deref(),
            )?,
            staging_workspace_generation: decode_workspace_generation(
                staging_workspace_generation_json.as_deref(),
            )?,
            rollback_workspace_generation: decode_workspace_generation(
                rollback_workspace_generation_json.as_deref(),
            )?,
        };
        if current_id.as_deref() == Some(id_text.as_str()) {
            current = Some(name.clone());
        }
        if environments.insert(name, record).is_some() {
            return Err(SupervisorStoreError::InvalidState);
        }
    }
    if current_id.is_some() && current.is_none() {
        return Err(SupervisorStoreError::InvalidState);
    }
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current,
        environments,
    };
    state
        .validate()
        .map_err(|_| SupervisorStoreError::InvalidState)?;
    Ok(state)
}

fn decode_access_binding(
    environment_id: &str,
    profile_id: Option<String>,
    profile_revision: Option<i64>,
) -> Result<Option<EnvironmentAccessBinding>, SupervisorStoreError> {
    match (profile_id, profile_revision) {
        (None, None) => Ok(None),
        (Some(profile_id), Some(profile_revision)) => {
            let binding = EnvironmentAccessBinding {
                environment_id: EnvironmentId::parse(environment_id.to_owned())
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
                profile_id: AccessProfileId::parse(profile_id)
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
                profile_revision: u64::try_from(profile_revision)
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
            };
            binding
                .validate()
                .map_err(|_| SupervisorStoreError::InvalidState)?;
            Ok(Some(binding))
        }
        _ => Err(SupervisorStoreError::InvalidState),
    }
}

fn decode_workspace_generation(
    bytes: Option<&[u8]>,
) -> Result<Option<WorkspaceGenerationRecord>, SupervisorStoreError> {
    bytes
        .map(WorkspaceGenerationRecord::decode_canonical)
        .transpose()
        .map_err(|_| SupervisorStoreError::InvalidState)
}

pub(crate) fn parse_uuid(value: &str) -> Result<Uuid, SupervisorStoreError> {
    let id = Uuid::parse_str(value).map_err(|_| SupervisorStoreError::InvalidState)?;
    if id.is_nil() {
        return Err(SupervisorStoreError::InvalidState);
    }
    Ok(id)
}

pub(crate) fn require_persistent_wal(connection: &Connection) -> Result<(), SupervisorStoreError> {
    fn control(connection: &Connection, value: &mut i32) -> i32 {
        // SAFETY: the connection remains borrowed for the call, `main` is a
        // static NUL-terminated schema name, and this opcode reads or writes
        // exactly the pointed-to integer.
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                std::ptr::from_mut(value).cast(),
            )
        }
    }

    let mut enabled = 1;
    if control(connection, &mut enabled) != rusqlite::ffi::SQLITE_OK {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    let mut observed = -1;
    if control(connection, &mut observed) != rusqlite::ffi::SQLITE_OK || observed != 1 {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    Ok(())
}
