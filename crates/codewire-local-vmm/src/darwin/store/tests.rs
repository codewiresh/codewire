use super::*;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rusqlite::types::Value;
use sha2::{Digest as _, Sha256};

use crate::supervisor_metadata::workspace::WorkspaceSourceMode;
use crate::supervisor_metadata::workspace_plan::WorkspacePlan;
use crate::supervisor_metadata::{EnvironmentRecord, RunnerRecord};

pub(in crate::darwin) struct Fixture {
    _temporary: tempfile::TempDir,
    pub(in crate::darwin) path: PathBuf,
    pub(in crate::darwin) boot: Uuid,
    pub(in crate::darwin) retain: Arc<AtomicBool>,
}

impl Fixture {
    pub(in crate::darwin) fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temporary.path()).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.join("native");
        PrivateRoot::create(&path).unwrap();
        Self {
            _temporary: temporary,
            path,
            boot: Uuid::new_v4(),
            retain: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(in crate::darwin) fn open(&self) -> Result<NativeStore, StoreError> {
        NativeStore::open(PrivateRoot::open(&self.path).unwrap(), self.boot)
    }

    pub(in crate::darwin) fn seed(&self, records: &[EnvironmentRecord]) {
        // Create the exact production schema, then insert complete test-owned
        // metadata. Never call Linux write_state: it synthesizes owned objects.
        drop(self.open().unwrap());
        self.edit(|connection| {
            for record in records {
                insert_record(connection, record, &record.id.to_string());
            }
            load_state(connection).unwrap().validate().unwrap();
        });
    }

    pub(in crate::darwin) fn edit(&self, edit: impl FnOnce(&Connection)) {
        let connection = Connection::open(self.path.join(DATABASE)).unwrap();
        configure_writer(&connection).unwrap();
        edit(&connection);
        connection.close().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.retain.load(Ordering::SeqCst) {
            self._temporary.disable_cleanup(true);
            eprintln!(
                "native fixture process/task cleanup uncertain; retained {}",
                self._temporary.path().display()
            );
        }
    }
}

pub(in crate::darwin) fn environment(name: &str) -> EnvironmentRecord {
    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(1024),
            disk_gib: Some(1),
        },
        ..Default::default()
    };
    let project_json = project.canonical_json().unwrap();
    let project_sha256 = format!("{:x}", Sha256::digest(&project_json));
    let record = EnvironmentRecord {
        id: Uuid::new_v4(),
        name: name.to_owned(),
        state: StoredEnvironmentState::Stopped,
        vcpus: 2,
        memory_mib: 1024,
        disk_bytes: 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        generation: 7,
        host_ports: Vec::new(),
        mesh: None,
        workspace_plan: WorkspacePlan::from_inputs(vec![WorkspaceInput::Local {
            // An inert, synthetic recorded path; never opened by these tests.
            source_path: b"/synthetic/codewire/source".to_vec(),
            identity: "b".repeat(40),
            mode: WorkspaceSourceMode::Clone,
            destination: "/workspace".to_owned(),
        }])
        .unwrap(),
        project_spec_json: Some(project_json),
        project_spec_sha256: Some(project_sha256),
        access_profile: None,
        access_binding: None,
        platform_source_authority: None,
        runner: None,
        active_artifact_generation: Some("c".repeat(64)),
        staging_artifact_generation: None,
        active_workspace_generation: None,
        staging_workspace_generation: None,
        rollback_workspace_generation: None,
    };
    let mut state = SupervisorState::default();
    state.environments.insert(name.to_owned(), record.clone());
    state.validate().unwrap();
    record
}

fn insert_record(connection: &Connection, record: &EnvironmentRecord, id_text: &str) {
    connection.execute(
        "INSERT INTO environments (id, name, desired_state, observed_state, vcpus, memory_mib, disk_bytes, docker_disk_bytes, generation, host_ports_json, mesh_attachment_json, workspace_plan_json, project_spec_json, project_spec_sha256, access_profile_reference, access_profile_id, access_profile_revision, runner_json, active_artifact_generation, staging_artifact_generation, active_workspace_generation_json, staging_workspace_generation_json, rollback_workspace_generation_json, platform_source_authority_json) VALUES (?1, ?2, 'stopped', 'stopped', ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, NULL, NULL, NULL, ?12, ?13, ?14, NULL, NULL, NULL, NULL)",
        params![id_text, record.name, record.vcpus, record.memory_mib,
            record.disk_bytes, record.docker_disk_bytes, record.generation,
            serde_json::to_vec(&record.host_ports).unwrap(),
            record.workspace_plan.encode_canonical().unwrap(), record.project_spec_json,
            record.project_spec_sha256,
            record.runner.as_ref().map(|runner| serde_json::to_vec(runner).unwrap()),
            record.active_artifact_generation, record.staging_artifact_generation],
    ).unwrap();
}

fn rows(connection: &Connection, query: &str) -> Vec<Vec<Value>> {
    let mut statement = connection.prepare(query).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<Result<Vec<Value>, _>>()
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub(in crate::darwin) fn protected_rows(connection: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "SELECT * FROM environments ORDER BY name",
        "SELECT * FROM supervisor_metadata ORDER BY key",
        "SELECT * FROM operations ORDER BY operation_id",
        "SELECT * FROM owned_objects ORDER BY environment_id, kind, relative_path",
    ]
    .iter()
    .map(|query| rows(connection, query))
    .collect()
}

#[test]
fn initializes_full_native_schema_once_and_verifies_durability_on_reopen() {
    let fixture = Fixture::new();
    let store = fixture.open().unwrap();
    assert_eq!(store.state().unwrap(), SupervisorState::default());
    let metadata = protected_rows(&store.connection);
    for (pragma, expected) in [
        ("application_id", APPLICATION_ID),
        ("user_version", SCHEMA_VERSION),
        ("fullfsync", 1),
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("trusted_schema", 0),
    ] {
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, pragma, |row| row.get::<_, i64>(0))
                .unwrap(),
            expected,
            "{pragma}"
        );
    }
    let journal: String = store
        .connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    drop(store);
    let reopened =
        NativeStore::open(PrivateRoot::open(&fixture.path).unwrap(), Uuid::new_v4()).unwrap();
    assert_eq!(
        protected_rows(&reopened.connection),
        metadata,
        "reopen must not rewrite boot or namespace"
    );
    assert_eq!(reopened.state().unwrap(), SupervisorState::default());
}

#[test]
fn selection_changes_only_settings_and_preserves_original_uuid_spelling() {
    let fixture = Fixture::new();
    let alpha = environment("alpha");
    let mut beta = environment("beta");
    beta.id = Uuid::parse_str("abcdefab-1234-4abc-8def-0123456789ab").unwrap();
    fixture.seed(std::slice::from_ref(&alpha));
    let upper_id = beta.id.to_string().to_uppercase();
    fixture.edit(|connection| insert_record(connection, &beta, &upper_id));
    let mut store = fixture.open().unwrap();
    let protected = protected_rows(&store.connection);
    assert_eq!(store.state().unwrap().environments.len(), 2);
    let state = store.select("beta", Some(beta.id)).unwrap();
    assert_eq!(state.current.as_deref(), Some("beta"));
    assert_eq!(state.environments["beta"], beta);
    assert_eq!(
        rows(
            &store.connection,
            "SELECT current_environment_id FROM supervisor_settings"
        ),
        vec![vec![Value::Text(upper_id.clone())]]
    );
    assert_eq!(protected_rows(&store.connection), protected);
    store.select("beta", None).unwrap();
    assert_eq!(protected_rows(&store.connection), protected);
    assert!(matches!(
        store.select("beta", Some(alpha.id)),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.select("missing", None),
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.state().unwrap().current.as_deref(), Some("beta"));
    drop(store);
    let reopened = fixture.open().unwrap();
    assert_eq!(reopened.state().unwrap().current.as_deref(), Some("beta"));
    assert_eq!(protected_rows(&reopened.connection), protected);
    assert_eq!(
        rows(
            &reopened.connection,
            "SELECT current_environment_id FROM supervisor_settings"
        ),
        vec![vec![Value::Text(upper_id)]]
    );
}

unsafe extern "C" fn fail_one_commit(context: *mut std::ffi::c_void) -> std::ffi::c_int {
    // SAFETY: the hook is installed only while its AtomicBool remains alive;
    // it is removed before either the flag or connection can be dropped.
    let fail = unsafe { &*context.cast::<AtomicBool>() };
    i32::from(fail.swap(false, Ordering::SeqCst))
}

#[test]
fn failed_commit_returns_no_selection_and_rolls_back_durable_settings() {
    let fixture = Fixture::new();
    fixture.seed(&[environment("alpha"), environment("beta")]);
    let fail = AtomicBool::new(true);
    let mut store = fixture.open().unwrap();
    store.select("alpha", None).unwrap();
    let protected = protected_rows(&store.connection);
    // SAFETY: this test exclusively owns the connection and the borrowed flag
    // outlives the hook, which is unregistered immediately after select returns.
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(
            store.connection.handle(),
            Some(fail_one_commit),
            std::ptr::from_ref(&fail).cast_mut().cast(),
        );
    }
    let result = store.select("beta", None);
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(store.connection.handle(), None, std::ptr::null_mut());
    }
    assert!(matches!(result, Err(StoreError::Sqlite(_))));
    assert!(
        !fail.load(Ordering::SeqCst),
        "the real SQLite commit hook must have fired"
    );
    assert_eq!(store.state().unwrap().current.as_deref(), Some("alpha"));
    assert_eq!(protected_rows(&store.connection), protected);
    drop(store);
    assert_eq!(
        fixture.open().unwrap().state().unwrap().current.as_deref(),
        Some("alpha")
    );
}

#[test]
fn closed_catalog_rejects_trigger_view_extra_index_and_altered_table_before_selection() {
    for alteration in [
        "CREATE TRIGGER unsafe_selection AFTER UPDATE ON supervisor_settings BEGIN UPDATE supervisor_metadata SET value = 'changed' WHERE key = 'platform'; END",
        "CREATE VIEW unsafe_view AS SELECT * FROM supervisor_metadata",
        "CREATE INDEX unsafe_index ON environments(generation)",
        "ALTER TABLE supervisor_settings ADD COLUMN extra TEXT",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        fixture.edit(|connection| connection.execute_batch(alteration).unwrap());
        assert!(
            matches!(fixture.open(), Err(StoreError::UnsupportedCatalog)),
            "{alteration}"
        );
        fixture.edit(|connection| {
            let platform: String = connection
                .query_row(
                    "SELECT value FROM supervisor_metadata WHERE key = 'platform'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(platform, PLATFORM);
            let current: Option<String> = connection
                .query_row(
                    "SELECT current_environment_id FROM supervisor_settings",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(current.is_none());
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM environments", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        });
    }
}

#[test]
fn foreign_formats_and_missing_or_invalid_metadata_are_retained_without_repair() {
    for alteration in [
        "PRAGMA user_version = 11",
        "PRAGMA application_id = 1",
        "DELETE FROM supervisor_metadata WHERE key = 'platform'",
        "DELETE FROM supervisor_metadata WHERE key = 'namespace_id'",
        "DELETE FROM supervisor_metadata WHERE key = 'host_boot_id'",
        "UPDATE supervisor_metadata SET value = 'linux-v1' WHERE key = 'platform'",
        "UPDATE supervisor_metadata SET value = 'boot-a' WHERE key = 'host_boot_id'",
        "UPDATE supervisor_metadata SET value = '00000000-0000-0000-0000-000000000000' WHERE key = 'namespace_id'",
        "INSERT INTO supervisor_metadata VALUES ('unexpected', 'retained')",
        "DELETE FROM supervisor_settings",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        let mut before = Vec::new();
        fixture.edit(|connection| {
            connection.execute_batch(alteration).unwrap();
            before = protected_rows(connection);
        });
        assert!(fixture.open().is_err(), "{alteration}");
        fixture.edit(|connection| assert_eq!(protected_rows(connection), before, "{alteration}"));
    }
}

#[test]
fn every_operation_phase_and_owned_object_blocks_admission_without_replay() {
    for phase in [
        "intent",
        "effect_applied",
        "completed",
        "failed",
        "interrupted",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        fixture.edit(|connection| {
            connection.execute("INSERT INTO operations VALUES (?1, ?2, NULL, 'delete', ?3, 0, ?4, NULL, NULL, 1, 1)",
                params![Uuid::new_v4().to_string(), Uuid::new_v4().to_string(), phase, b"{}".as_slice()]).unwrap();
        });
        assert!(
            matches!(fixture.open(), Err(StoreError::UnsupportedAuthority)),
            "{phase}"
        );
        fixture.edit(|connection| {
            assert_eq!(
                rows(connection, "SELECT phase, checkpoint FROM operations"),
                vec![vec![Value::Text(phase.to_owned()), Value::Integer(0)]]
            )
        });
    }
    let fixture = Fixture::new();
    let record = environment("dev");
    fixture.seed(std::slice::from_ref(&record));
    fixture.edit(|connection| {
        connection
            .execute(
                "INSERT INTO owned_objects VALUES (?1, 'runner', ?2, NULL, 'active')",
                params![record.id.to_string(), b"retained/runner".as_slice()],
            )
            .unwrap();
    });
    assert!(matches!(
        fixture.open(),
        Err(StoreError::UnsupportedAuthority)
    ));
    fixture.edit(|connection| {
        assert_eq!(
            rows(connection, "SELECT kind, relative_path FROM owned_objects"),
            vec![vec![
                Value::Text("runner".to_owned()),
                Value::Blob(b"retained/runner".to_vec())
            ]]
        )
    });
}

#[test]
fn desired_observed_staging_and_legacy_runner_authority_are_not_admitted() {
    for alteration in [
        "UPDATE environments SET desired_state = 'running'",
        "UPDATE environments SET observed_state = 'error'",
        "UPDATE environments SET staging_artifact_generation = printf('%064d', 1)",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        fixture.edit(|connection| connection.execute_batch(alteration).unwrap());
        assert!(
            matches!(fixture.open(), Err(StoreError::UnsupportedAuthority)),
            "{alteration}"
        );
    }
    let fixture = Fixture::new();
    let mut record = environment("dev");
    // Complete legacy serialized identity, recognized as retained authority;
    // these invented fixture identifiers are never adopted or signaled.
    record.runner = Some(serde_json::from_value::<RunnerRecord>(serde_json::json!({
        "process": { "pid": 123, "boot_id": "synthetic-boot", "start_time_ticks": 456,
            "executable": "/synthetic/cw", "executable_file": { "device": 1, "inode": 2,
                "size": 3, "uid": super::super::path::current_uid(), "mode": 33152, "links": 1 },
            "executable_sha256": "a".repeat(64) },
        "socket": { "device": 4, "inode": 5, "uid": super::super::path::current_uid(), "mode": 49536 },
        "artifact_generation": "c".repeat(64)
    })).unwrap());
    fixture.seed(&[record]);
    assert!(matches!(
        fixture.open(),
        Err(StoreError::UnsupportedAuthority)
    ));
}

#[test]
fn complete_legacy_direct_share_record_is_rejected_without_opening_its_source() {
    let fixture = Fixture::new();
    let mut record = environment("dev");
    let identity = serde_json::from_value(serde_json::json!({ "device_major": 1, "device_minor": 2,
        "inode": 3, "mount_id": 4, "owner_uid": super::super::path::current_uid(), "filesystem_magic": 61267 })).unwrap();
    record.workspace_plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::Direct {
        source_path: b"/synthetic/never-open-this-share".to_vec(),
        identity,
        destination: "/workspace/share".to_owned(),
        read_only: true,
    }])
    .unwrap();
    fixture.seed(&[record]);
    assert!(matches!(
        fixture.open(),
        Err(StoreError::UnsupportedAuthority)
    ));
    assert!(!fixture.path.join("environments").exists());
}

#[test]
fn empty_database_with_nonempty_wal_is_rejected_before_sqlite_can_remove_evidence() {
    let fixture = Fixture::new();
    let root = PrivateRoot::open(&fixture.path).unwrap();
    root.create_regular(Path::new(DATABASE), 0o600, true)
        .unwrap();
    let mut wal = root
        .create_regular(Path::new(SIDECARS[0]), 0o600, true)
        .unwrap()
        .into_file();
    std::io::Write::write_all(&mut wal, b"synthetic retained WAL evidence").unwrap();
    drop(wal);
    let before = fs::read(fixture.path.join(SIDECARS[0])).unwrap();
    assert!(matches!(
        fixture.open(),
        Err(StoreError::IncompleteInitialization)
    ));
    assert_eq!(fs::metadata(fixture.path.join(DATABASE)).unwrap().len(), 0);
    assert_eq!(fs::read(fixture.path.join(SIDECARS[0])).unwrap(), before);
    assert!(!fixture.path.join(SIDECARS[1]).exists());
}

#[test]
fn missing_sidecars_are_created_without_losing_committed_main_state() {
    let fixture = Fixture::new();
    fixture.seed(&[environment("dev")]);
    fixture.edit(|connection| {
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
    });
    for name in SIDECARS {
        fs::remove_file(fixture.path.join(name)).unwrap();
    }
    let store = fixture.open().unwrap();
    assert_eq!(store.state().unwrap().environments.len(), 1);
    for name in SIDECARS {
        assert!(fixture.path.join(name).is_file());
    }
}

#[test]
fn database_and_each_sidecar_replacement_fail_closed_and_retain_replacements() {
    for name in [DATABASE, SIDECARS[0], SIDECARS[1]] {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        let mut store = fixture.open().unwrap();
        let retained = fixture.path.parent().unwrap().join("retained-original");
        fs::rename(fixture.path.join(name), &retained).unwrap();
        let replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixture.path.join(name))
            .unwrap();
        fs::set_permissions(fixture.path.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        drop(replacement);
        assert!(store.state().is_err(), "{name}");
        assert!(store.select("dev", None).is_err(), "{name}");
        assert!(retained.exists());
        assert!(fixture.path.join(name).exists());
    }
}

const PROBE_MODE: &str = "CODEWIRE_NATIVE_STORE_TEST_PROBE";
const PROBE_DATABASE: &str = "CODEWIRE_NATIVE_STORE_TEST_DATABASE";

fn run_probe(fixture: &Fixture, mode: &str) {
    struct ChildGuard<'a> {
        child: std::process::Child,
        fixture: &'a Fixture,
    }
    impl Drop for ChildGuard<'_> {
        fn drop(&mut self) {
            if self.fixture.retain.load(Ordering::SeqCst) {
                // An earlier failed wait is not undone by retrying in Drop.
                return;
            }
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) => {
                    self.fixture.retain.store(true, Ordering::SeqCst);
                    eprintln!("native SQLite probe wait uncertain; no signal: {error}");
                    return;
                }
                Ok(None) => {}
            }
            // This guard is the exclusive waiter for its freshly spawned
            // child; no PID is reconstructed. Reject observed auto-reaping or
            // ownership uncertainty before signaling this disposable child.
            if let Err(error) = super::super::process::observe_owned_child(&mut self.child) {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                self.fixture.retain.store(true, Ordering::SeqCst);
                eprintln!("native SQLite probe ownership uncertain; no signal: {error}");
                return;
            }
            if let Err(error) = self.child.kill() {
                eprintln!("native SQLite probe cleanup signal failed: {error}");
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    result => {
                        self.fixture.retain.store(true, Ordering::SeqCst);
                        eprintln!("native SQLite probe cleanup uncertain: {result:?}");
                        return;
                    }
                }
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut child = ChildGuard {
        child: Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "darwin::store::tests::sqlite_child_probe",
                "--ignored",
                "--nocapture",
            ])
            .env(PROBE_MODE, mode)
            .env(PROBE_DATABASE, fixture.path.join(DATABASE))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
        fixture,
    };
    loop {
        assert!(
            Instant::now() < deadline,
            "native SQLite child probe timed out"
        );
        match child.child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    Instant::now() < deadline,
                    "native SQLite probe completed beyond its deadline"
                );
                assert!(status.success(), "probe {mode}: {status}");
                return;
            }
            Ok(None) => {}
            Err(error) => {
                fixture.retain.store(true, Ordering::SeqCst);
                panic!("native SQLite probe wait uncertain: {error}");
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "subprocess-only SQLite crash/lock probe, run by native store tests"]
fn sqlite_child_probe() {
    let mode = std::env::var(PROBE_MODE).expect("parent must select probe mode");
    let path = std::env::var_os(PROBE_DATABASE).expect("parent must provide disposable database");
    let connection = Connection::open(PathBuf::from(path)).unwrap();
    connection.busy_timeout(Duration::ZERO).unwrap();
    if mode == "lock" {
        let error = connection.execute_batch("BEGIN IMMEDIATE").unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        return;
    }
    configure_writer(&connection).unwrap();
    connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .unwrap();
    match mode.as_str() {
        "select" => {
            connection.execute_batch("UPDATE supervisor_settings SET current_environment_id = (SELECT id FROM environments WHERE name = 'dev')").unwrap();
        }
        "remove-platform" => {
            connection
                .execute_batch("DELETE FROM supervisor_metadata WHERE key = 'platform'")
                .unwrap();
        }
        _ => panic!("unknown synthetic probe mode"),
    }
    // Simulate a process exit after durable WAL commit, before SQLite close can
    // checkpoint it. The OS, not an invented fixture WAL, owns lock teardown.
    std::process::exit(0);
}

#[test]
fn missing_shm_recovers_real_wal_only_committed_selection() {
    let fixture = Fixture::new();
    fixture.seed(&[environment("dev")]);
    fixture.edit(|connection| {
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
    });
    let main = fs::read(fixture.path.join(DATABASE)).unwrap();
    run_probe(&fixture, "select");
    assert_eq!(
        fs::read(fixture.path.join(DATABASE)).unwrap(),
        main,
        "selection must still be WAL-only"
    );
    assert!(fs::metadata(fixture.path.join(SIDECARS[0])).unwrap().len() > 32);
    fs::remove_file(fixture.path.join(SIDECARS[1])).unwrap();
    let store = fixture.open().unwrap();
    assert_eq!(store.state().unwrap().current.as_deref(), Some("dev"));
}

#[test]
fn wal_only_missing_metadata_is_rejected_not_repaired_from_main_pages() {
    let fixture = Fixture::new();
    fixture.seed(&[environment("dev")]);
    run_probe(&fixture, "remove-platform");
    fs::remove_file(fixture.path.join(SIDECARS[1])).unwrap();
    assert!(matches!(fixture.open(), Err(StoreError::InvalidMetadata)));
    fixture.edit(|connection| {
        assert!(
            rows(
                connection,
                "SELECT value FROM supervisor_metadata WHERE key = 'platform'"
            )
            .is_empty()
        )
    });
}

#[test]
fn borrowed_identity_revalidation_preserves_real_cross_process_sqlite_write_lock() {
    let fixture = Fixture::new();
    fixture.seed(&[environment("dev")]);
    let store = fixture.open().unwrap();
    store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    run_probe(&fixture, "lock");
    for _ in 0..4 {
        store.revalidate().unwrap();
    }
    run_probe(&fixture, "lock");
    store.connection.execute_batch("ROLLBACK").unwrap();
}
