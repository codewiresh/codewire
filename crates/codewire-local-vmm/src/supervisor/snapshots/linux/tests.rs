//! Local disk snapshot tests: capture and its refusals, the sign-in scrub
//! against the raw image, the manifest, placement, deletion and the store's
//! reconciliation.

use std::process::Command as ProcessCommand;

use codewire_ext4_scrub::parse_extent;

use super::*;
use crate::supervisor::tests::{
    project_environment, test_supervisor_core, test_supervisor_service, test_workspace_generation,
};

const MIB: u64 = 1024 * 1024;

fn tool(name: &str) -> PathBuf {
    crate::host::e2fsprogs(name).expect("e2fsprogs for snapshot tests")
}

/// A sparse ext4 image of `bytes`, formatted as Codewire formats disks.
fn ext4_image(path: &Path, bytes: u64) {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.set_len(bytes).unwrap();
    drop(file);
    let status = ProcessCommand::new(tool("mkfs.ext4"))
        .args(crate::host::EXT4_FORMAT)
        .args(["-q", "-F"])
        .arg(path)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
}

/// Run debugfs on `image` unconfined, as a test's own setup.
fn debugfs_setup(image: &Path, request: &str) -> Vec<u8> {
    let output = ProcessCommand::new(tool("debugfs"))
        .args(["-w", "-R", request])
        .arg(image)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PAGER", "__none__")
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

fn plant(image: &Path, scratch: &Path, destination: &str, contents: &[u8]) {
    let host = scratch.join(Uuid::new_v4().simple().to_string());
    fs::write(&host, contents).unwrap();
    debugfs_setup(
        image,
        &format!("write {} {destination}", host.to_str().unwrap()),
    );
    fs::remove_file(host).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn codex_login(access_token: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "auth_mode": "chatgpt",
        "tokens": {
            "id_token": "synthetic-id-token",
            "access_token": access_token,
            "refresh_token": codewire_daemon::codex_home::CODEX_MANAGED_REFRESH_TOKEN,
            "account_id": "synthetic-account",
        },
    }))
    .unwrap()
}

fn claude_login(access_token: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "claudeAiOauth": {
            "accessToken": access_token,
            "refreshToken": format!(
                "{}{}",
                codewire_daemon::claude_home::CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX,
                "0123456789abcdef0123456789abcdef"
            ),
            "expiresAt": 1,
            "scopes": ["user:inference"],
        },
        "codewireManaged": 1,
    }))
    .unwrap()
}

/// A stopped environment whose disks exist: a 256 MiB state disk and its
/// active root generation's disk.
struct Source {
    _parent: tempfile::TempDir,
    service: SupervisorRpc,
    environment: EnvironmentRecord,
    paths: VmPaths,
    scratch: tempfile::TempDir,
}

fn source(state: StoredEnvironmentState) -> Source {
    let mut environment = project_environment();
    environment.state = state;
    environment.disk_bytes = crate::state::MINIMUM_STATE_DISK_BYTES;
    environment.active_workspace_generation = Some(test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"snapshot-source",
    ));
    let (parent, core) = test_supervisor_core(environment.clone());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let paths = VmPaths::create(&engine, environment.id).unwrap();
    ext4_image(&paths.state_disk, environment.disk_bytes);
    let storage =
        workspace_storage_generation(environment.active_workspace_generation.as_ref().unwrap())
            .unwrap();
    let generation = crate::state::RootGenerationPaths::create(&paths, &storage).unwrap();
    ext4_image(&generation.root_disk, crate::state::MINIMUM_ROOT_DISK_BYTES);
    Source {
        _parent: parent,
        service: test_supervisor_service(core),
        environment,
        paths,
        scratch: tempfile::tempdir().unwrap(),
    }
}

fn config(source: &Source) -> NativeRuntimeConfig {
    source.service.supervisor.config.clone()
}

async fn capture_named(source: &Source, name: &str) -> Result<v1::Snapshot, Status> {
    source
        .service
        .create_snapshot(Request::new(v1::CreateSnapshotRequest {
            environment: source.environment.name.clone(),
            name: name.to_owned(),
            account: None,
        }))
        .await
        .map(Response::into_inner)
}

fn snapshot_dir(source: &Source, snapshot: &v1::Snapshot) -> PathBuf {
    config(source)
        .engine_root()
        .join(SNAPSHOTS_DIRECTORY)
        .join(&snapshot.id)
}

#[tokio::test]
async fn capture_refuses_a_running_or_unknown_source_and_a_taken_name() {
    let running = source(StoredEnvironmentState::Running);
    let error = capture_named(&running, "s1").await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        error
            .message()
            .contains("is running; stop it first (`cw stop dev`)"),
        "{}",
        error.message()
    );

    let stopped = source(StoredEnvironmentState::Stopped);
    let error = stopped
        .service
        .create_snapshot(Request::new(v1::CreateSnapshotRequest {
            environment: "missing".to_owned(),
            name: "s1".to_owned(),
            account: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    let error = capture_named(&stopped, "-bad").await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);

    capture_named(&stopped, "s1").await.unwrap();
    let error = capture_named(&stopped, "s1").await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::AlreadyExists);
    assert!(
        error.message().contains("cw snapshot rm s1"),
        "{}",
        error.message()
    );
}

#[tokio::test]
async fn capture_refuses_any_staged_change() {
    for stage in 0..3 {
        let mut environment = project_environment();
        environment.state = StoredEnvironmentState::Stopped;
        let generation = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"staged",
        );
        environment.active_workspace_generation = Some(generation.clone());
        match stage {
            0 => environment.staging_workspace_generation = Some(generation),
            1 => environment.staging_artifact_generation = Some("c".repeat(64)),
            _ => {
                environment.cw_runtime = Some(CwRuntimeBinding {
                    schema_version: 1,
                    active_catalog_generation: "d".repeat(64),
                    staging_catalog_generation: Some("e".repeat(64)),
                    rollback_catalog_generation: None,
                });
            }
        }
        let (_parent, core) = test_supervisor_core(environment);
        let service = test_supervisor_service(core);
        let error = service
            .create_snapshot(Request::new(v1::CreateSnapshotRequest {
                environment: "dev".to_owned(),
                name: "s1".to_owned(),
                account: None,
            }))
            .await
            .unwrap_err();
        if stage == 0 {
            // A staged workspace no operation owns stops the name's drain
            // itself, before capture looks at the environment.
            continue;
        }
        assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{stage}");
        assert!(
            error.message().contains("unfinished"),
            "{}",
            error.message()
        );
    }

    let source = source(StoredEnvironmentState::Stopped);
    fs::write(source.paths.disks_dir.join("docker.raw.staging"), b"").unwrap();
    fs::set_permissions(
        source.paths.disks_dir.join("docker.raw.staging"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let error = capture_named(&source, "s1").await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("Docker disk is being resized"));
    // A refused capture leaves no staging behind.
    let snapshots = config(&source).engine_root().join(SNAPSHOTS_DIRECTORY);
    assert_eq!(fs::read_dir(snapshots).unwrap().count(), 0);
}

#[tokio::test]
async fn capture_removes_every_delivered_sign_in_from_the_copy_only() {
    let source = source(StoredEnvironmentState::Stopped);
    let state = source.paths.state_disk.clone();
    let codex_token = format!("cw-snapshot-test-codex-{}", Uuid::new_v4().simple());
    let claude_token = format!("sk-ant-oat01-cw-snapshot-test-{}", Uuid::new_v4().simple());
    let stale_token = format!("cw-snapshot-test-stale-{}", Uuid::new_v4().simple());
    let users_token = format!("cw-snapshot-test-users-own-{}", Uuid::new_v4().simple());
    for directory in [
        "/agent-homes",
        "/agent-homes/codex",
        "/home",
        "/home/.claude",
    ] {
        debugfs_setup(&state, &format!("mkdir {directory}"));
    }
    let scratch = source.scratch.path();
    plant(
        &state,
        scratch,
        "/agent-homes/codex/auth.json",
        &codex_login(&codex_token),
    );
    plant(
        &state,
        scratch,
        "/agent-homes/codex/.auth.json.codewire.0123456789abcdef0123456789abcdef.new",
        &codex_login(&codex_token),
    );
    plant(
        &state,
        scratch,
        "/home/.claude/.credentials.json",
        &claude_login(&claude_token),
    );
    // The user's own login stays.
    let users_own = serde_json::to_vec(&serde_json::json!({
        "claudeAiOauth": { "accessToken": users_token, "refreshToken": "sk-ant-ort01-users-own" },
    }))
    .unwrap();
    plant(
        &state,
        scratch,
        "/home/.claude/.credentials.json.codewire.0123456789abcdef0123456789abcdef.aside",
        &users_own,
    );
    // The guest's live cw runtime selection, bound to the source's id.
    for directory in [
        "/codewire",
        "/codewire/cw-runtime",
        "/codewire/cw-runtime/view",
        "/codewire/cw-runtime/view/0123abcd",
    ] {
        debugfs_setup(&state, &format!("mkdir {directory}"));
    }
    plant(&state, scratch, "/codewire/cw-runtime/control.lock", b"");
    plant(
        &state,
        scratch,
        "/codewire/cw-runtime/view/selection.json",
        b"{}",
    );
    plant(
        &state,
        scratch,
        "/codewire/cw-runtime/view/0123abcd/cw",
        b"binary",
    );
    plant(&state, scratch, "/codewire/boot-stage", b"ready\n");
    // An earlier delivery the daemon replaced: its blocks are free but still
    // hold the token.
    plant(
        &state,
        scratch,
        "/home/.claude/old.json",
        &claude_login(&stale_token),
    );
    debugfs_setup(&state, "rm /home/.claude/old.json");
    let before = fs::read(&state).unwrap();
    for token in [&codex_token, &claude_token, &stale_token, &users_token] {
        assert!(contains(&before, token.as_bytes()), "{token} planted");
    }

    let started = std::time::Instant::now();
    let snapshot = capture_named(&source, "s1").await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(60));
    assert_eq!(snapshot.removed_logins, 3);
    assert_eq!(snapshot.consistency, "clean");
    assert_eq!(snapshot.locations, ["local"]);
    assert_eq!(snapshot.disks.len(), 2);

    let copy = fs::read(snapshot_dir(&source, &snapshot).join("disks/state.raw")).unwrap();
    for token in [&codex_token, &claude_token, &stale_token] {
        assert!(
            !contains(&copy, token.as_bytes()),
            "{token} left in the copy"
        );
    }
    assert!(
        contains(&copy, users_token.as_bytes()),
        "the user's own login is kept"
    );
    let copy_path = snapshot_dir(&source, &snapshot).join("disks/state.raw");
    let listing = String::from_utf8(debugfs_setup(&copy_path, "ls -p /codewire")).unwrap();
    assert!(!listing.contains("/cw-runtime/"), "{listing}");
    assert!(listing.contains("/boot-stage/"), "{listing}");
    // The source is never written.
    assert_eq!(fs::read(&state).unwrap(), before);
}

#[tokio::test]
async fn the_manifest_round_trips_and_a_changed_one_is_refused() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let id = canonical_id(&snapshot.id).unwrap();
    let config = config(&source);
    let (row, manifest) = ready_snapshot(&config, id).unwrap();
    assert_eq!(row.name, "s1");
    assert_eq!(manifest.source.environment_id, source.environment.id);
    assert_eq!(manifest.workspace_plan, source.environment.workspace_plan);
    assert_eq!(
        Some(&manifest.root_generation),
        source.environment.active_workspace_generation.as_ref()
    );
    let reencoded: Manifest =
        serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(reencoded, manifest);
    // The pinned artifact generation and the image are retention roots.
    let mut content = BTreeMap::new();
    let mut artifacts = BTreeSet::new();
    retain(&config, &mut content, &mut artifacts).unwrap();
    assert!(artifacts.contains(&"b".repeat(64)));
    assert!(content.contains_key(&manifest.root_generation.image.config.digest));

    let path = snapshot_dir(&source, &snapshot).join(MANIFEST_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut changed = fs::read(&path).unwrap();
    changed.extend_from_slice(b"\n");
    fs::write(&path, changed).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(
        ready_snapshot(&config, id),
        Err(SupervisorError::InvalidState)
    ));
}

#[tokio::test]
async fn placement_publishes_one_complete_tree_and_replays() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let id = canonical_id(&snapshot.id).unwrap();
    let config = config(&source);
    let fork = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let sizes = (source.environment.disk_bytes, 0);

    let root = place_snapshot_tree(&config, id, fork, operation, sizes).unwrap();
    assert_eq!(
        Some(&root),
        source.environment.active_workspace_generation.as_ref()
    );
    let vm = config.engine_root().join("vms").join(fork.to_string());
    let placed = crate::state::StateDiskIdentity::capture(&vm.join("disks/state.raw")).unwrap();
    let original = crate::state::StateDiskIdentity::capture(&source.paths.state_disk).unwrap();
    assert_eq!(placed.filesystem_uuid, original.filesystem_uuid);
    assert_eq!(placed.file.size, original.file.size);
    let storage = workspace_storage_generation(&root).unwrap();
    assert!(
        vm.join("generations")
            .join(&storage)
            .join("root.raw")
            .is_file()
    );
    // The tree holds only names a VM tree allows.
    crate::state::validate_owned_vm_tree(&PrivateRoot::open(&vm).unwrap()).unwrap();
    // A replay after the rename finds it and only checks it.
    place_snapshot_tree(&config, id, fork, operation, sizes).unwrap();
    // No staging is left.
    let snapshots = config.engine_root().join(SNAPSHOTS_DIRECTORY);
    let names = fs::read_dir(&snapshots)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, std::slice::from_ref(&snapshot.id));

    // Sizes other than the record's are refused.
    assert!(place_snapshot_tree(&config, id, Uuid::new_v4(), Uuid::new_v4(), (1, 0)).is_err());
}

#[tokio::test]
async fn a_failed_placement_publishes_nothing() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let id = canonical_id(&snapshot.id).unwrap();
    let config = config(&source);
    let storage = workspace_storage_generation(
        source
            .environment
            .active_workspace_generation
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    // The last disk copied is missing.
    fs::remove_file(
        snapshot_dir(&source, &snapshot)
            .join("root")
            .join(&storage)
            .join("root.raw"),
    )
    .unwrap();
    let fork = Uuid::new_v4();
    assert!(
        place_snapshot_tree(
            &config,
            id,
            fork,
            Uuid::new_v4(),
            (source.environment.disk_bytes, 0)
        )
        .is_err()
    );
    assert!(
        !config
            .engine_root()
            .join("vms")
            .join(fork.to_string())
            .exists()
    );
    let staging = fs::read_dir(config.engine_root().join(SNAPSHOTS_DIRECTORY))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(RESTORE_STAGING_PREFIX)
        })
        .count();
    assert_eq!(staging, 0);
}

#[tokio::test]
async fn delete_waits_for_a_restore_and_then_removes_exactly_the_snapshot() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let config = config(&source);
    let directory = snapshot_dir(&source, &snapshot);
    let restore = File::open(&directory).unwrap();
    flock(&restore, FlockOperation::LockShared).unwrap();
    let error = delete(&config, "s1").unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(directory.exists());
    drop(restore);

    let removed = delete(&config, "s1").unwrap();
    assert_eq!(removed.id, snapshot.id);
    assert!(!directory.exists());
    assert!(
        fs::read_dir(config.engine_root().join(TRASH_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(
        get(&config, "s1").unwrap_err().code(),
        tonic::Code::NotFound
    );
    assert!(list(&config).unwrap().is_empty());
    // The source and its disks are untouched.
    assert!(source.paths.state_disk.is_file());
    let error = delete(&config, "s1").unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
}

#[test]
fn reconciliation_brings_rows_and_directories_into_agreement_both_ways() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("runtime");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = root.join("engine");
    fs::create_dir(&engine).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
    let store = SnapshotStore::open(&PrivateRoot::open(&root).unwrap()).unwrap();
    let snapshots = snapshots_root(&engine).unwrap();
    let private_dirs = |path: &Path| {
        fs::create_dir_all(path).unwrap();
        let mut current = path.to_owned();
        while current != engine {
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
            current = current.parent().unwrap().to_owned();
        }
    };
    let private_file = |path: &Path, mode: u32| {
        fs::write(path, b"disk").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    let make_dir = |name: &str| {
        let path = snapshots.path().join(name);
        private_dirs(&path.join("disks"));
        private_file(&path.join("disks/state.raw"), 0o600);
        private_file(&path.join(MANIFEST_FILE), 0o400);
        path
    };
    let row = |id: Uuid, name: &str, state: SnapshotState| SnapshotRow {
        kind: crate::snapshot_store::SnapshotKind::Disk,
        id,
        name: name.to_owned(),
        state,
        created_unix_ms: 1,
        manifest_sha256: "a".repeat(64),
        retained: Retained::default(),
    };
    // Kept: a ready row with its directory.
    let kept = Uuid::new_v4();
    let kept_dir = make_dir(&kept.to_string());
    store
        .insert(&row(kept, "kept", SnapshotState::Ready))
        .unwrap();
    // A directory with no row but its capture intent: a crash between
    // rename and insert.
    let unnamed_id = Uuid::new_v4();
    let unnamed = make_dir(&unnamed_id.to_string());
    store.record_intent(unnamed_id).unwrap();
    // A directory with neither, whose manifest cannot be verified: kept,
    // unlisted.
    let unverified = make_dir(&Uuid::new_v4().to_string());
    // An intent whose capture never published.
    store.record_intent(Uuid::new_v4()).unwrap();
    // A row with no directory.
    let lost = Uuid::new_v4();
    store
        .insert(&row(lost, "lost", SnapshotState::Ready))
        .unwrap();
    // A delete that stopped after marking.
    let deleting = Uuid::new_v4();
    let deleting_dir = make_dir(&deleting.to_string());
    store
        .insert(&row(deleting, "deleting", SnapshotState::Ready))
        .unwrap();
    assert!(store.mark_deleting(deleting).unwrap());
    // Staging from an interrupted capture and an interrupted restore.
    let capture_staging = make_dir(&format!("{CAPTURE_STAGING_PREFIX}{}", Uuid::new_v4()));
    let restore_staging = snapshots
        .path()
        .join(format!("{RESTORE_STAGING_PREFIX}{}", Uuid::new_v4()));
    private_dirs(&restore_staging.join("vm/disks"));
    private_file(&restore_staging.join("vm/disks/state.raw"), 0o600);
    // A staging tree a call in this process is still writing.
    let busy = make_dir(&format!("{CAPTURE_STAGING_PREFIX}{}", Uuid::new_v4()));
    let _busy = InFlight::new(busy.file_name().unwrap().to_str().unwrap().to_owned());
    // A delete that stopped in trash.
    let trash = trash_root(&engine).unwrap();
    let trashed = trash.path().join(format!(
        "{TRASH_PREFIX}{}-{}",
        Uuid::new_v4(),
        Uuid::new_v4()
    ));
    private_dirs(&trashed.join("disks"));
    private_file(&trashed.join("disks/docker.raw"), 0o600);
    // Something no snapshot holds stays for the orphan inventory.
    let foreign = snapshots.path().join("not-a-snapshot");
    private_dirs(&foreign);

    reconcile(&engine, &store).unwrap();

    assert!(kept_dir.join("disks/state.raw").exists());
    for gone in [
        &unnamed,
        &deleting_dir,
        &capture_staging,
        &restore_staging,
        &trashed,
    ] {
        assert!(!gone.exists(), "{}", gone.display());
    }
    assert!(foreign.exists());
    assert!(unverified.join("disks/state.raw").exists());
    assert!(busy.join("disks/state.raw").exists());
    assert!(store.intents().unwrap().is_empty());
    let names = store
        .list()
        .unwrap()
        .into_iter()
        .map(|row| row.name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["kept"]);
    // A second pass changes nothing.
    reconcile(&engine, &store).unwrap();
    assert!(kept_dir.join("disks/state.raw").exists());
}

fn restore_request(manifest: &Manifest) -> v1::CreateEnvironmentRequest {
    let project: codewire_project::ProjectSpec =
        serde_json::from_str(&manifest.project_spec_json).unwrap();
    let resources = &project.resources;
    v1::CreateEnvironmentRequest {
        name: "fork".to_owned(),
        source_path: manifest.source_inputs.source_path.clone(),
        vcpus: resources.cpu_millicores.unwrap() / 1000,
        memory_mib: u32::try_from(resources.memory_mib.unwrap()).unwrap(),
        disk_bytes: resources.disk_gib.unwrap() * 1024 * MIB,
        docker_disk_bytes: manifest.resources.docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json: manifest.project_spec_json.as_bytes().to_vec(),
        project_spec_sha256: manifest.project_spec_sha256.clone(),
        implicit_path_mode: manifest.source_inputs.implicit_path_mode.clone(),
        local_mounts: local_mounts(manifest),
        implicit_vm_only: manifest.source_inputs.implicit_vm_only.clone(),
        snapshot: Some(v1::SnapshotRestore {
            snapshot_id: manifest.id.to_string(),
            vcpus: 2,
            memory_mib: 4096,
            share_mounts: false,
            account: None,
        }),
        ..Default::default()
    }
}

fn account(user: &str) -> v1::PlatformAccount {
    v1::PlatformAccount {
        server_url: "https://platform.example".to_owned(),
        organization_id: "organization-1".to_owned(),
        user_id: user.to_owned(),
    }
}

#[tokio::test]
async fn a_restore_is_refused_for_another_account_and_unshared_direct_mounts() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let config = config(&source);
    let (row, mut manifest) = ready_snapshot(&config, canonical_id(&snapshot.id).unwrap()).unwrap();

    let request = restore_request(&manifest);
    validate_create(&request).unwrap();
    admit_restore_request(&row, &manifest, &request).unwrap();

    // Both sides signed in, to different accounts: refused.
    let signed_in = |request: &v1::CreateEnvironmentRequest, user: Option<&str>| {
        let mut request = request.clone();
        request.snapshot.as_mut().unwrap().account = user.map(account);
        request
    };
    manifest.platform_account = PlatformAccount::from_proto(Some(&account("user-a"))).unwrap();
    let error =
        admit_restore_request(&row, &manifest, &signed_in(&request, Some("user-b"))).unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(
        error.message().contains("user user-a"),
        "{}",
        error.message()
    );
    let mut other_organization = signed_in(&request, Some("user-a"));
    other_organization
        .snapshot
        .as_mut()
        .unwrap()
        .account
        .as_mut()
        .unwrap()
        .organization_id = "organization-2".to_owned();
    assert_eq!(
        admit_restore_request(&row, &manifest, &other_organization)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    // The same account, or either side signed out: nothing to compare.
    admit_restore_request(&row, &manifest, &signed_in(&request, Some("user-a"))).unwrap();
    admit_restore_request(&row, &manifest, &signed_in(&request, None)).unwrap();
    manifest.platform_account = None;
    admit_restore_request(&row, &manifest, &signed_in(&request, Some("user-b"))).unwrap();

    // Another project, another Docker disk, other workspace inputs.
    let mut changed = request.clone();
    changed.docker_disk_bytes = 8 * 1024 * MIB;
    assert_eq!(
        admit_restore_request(&row, &manifest, &changed)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut changed = request.clone();
    changed.source_path = "/elsewhere".to_owned();
    assert_eq!(
        admit_restore_request(&row, &manifest, &changed)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let mut changed = request.clone();
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(&changed.project_spec_json).unwrap();
    project.image = "ghcr.io/example/other".to_owned();
    changed.project_spec_json = project.canonical_json().unwrap();
    changed.project_spec_sha256 = format!("{:x}", Sha256::digest(&changed.project_spec_json));
    assert_eq!(
        admit_restore_request(&row, &manifest, &changed)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    // A direct mount needs --share-mounts.
    let folder = tempfile::tempdir_in(source.scratch.path()).unwrap();
    let admitted = crate::direct_share::admit_direct_share(folder.path(), &[]).unwrap();
    manifest.workspace_plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::direct(
        &admitted,
        "/workspace/fixtures",
        true,
        Vec::new(),
    )])
    .unwrap();
    manifest.source_inputs = SourceInputs {
        source_path: String::new(),
        implicit_path_mode: String::new(),
        implicit_vm_only: Vec::new(),
    };
    let mut direct = restore_request(&manifest);
    let error = admit_restore_request(&row, &manifest, &direct).unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        error.message().contains("--share-mounts"),
        "{}",
        error.message()
    );
    direct.snapshot.as_mut().unwrap().share_mounts = true;
    admit_restore_request(&row, &manifest, &direct).unwrap();
}

#[test]
fn a_restore_selection_round_trips_through_the_journaled_payload() {
    let id = Uuid::new_v4();
    let request = v1::CreateEnvironmentRequest {
        snapshot: Some(v1::SnapshotRestore {
            snapshot_id: id.to_string(),
            vcpus: 4,
            memory_mib: 8192,
            share_mounts: true,
            account: Some(account("user-a")),
        }),
        ..Default::default()
    };
    let mut payload = serde_json::json!({ "name": "fork" });
    journal_payload(&mut payload, &request).unwrap();
    let fields = payload.as_object().unwrap();
    assert_eq!(from_payload(fields).unwrap(), request.snapshot);

    // A create that restores nothing journals no key.
    let mut plain = serde_json::json!({ "name": "dev" });
    journal_payload(&mut plain, &v1::CreateEnvironmentRequest::default()).unwrap();
    assert_eq!(plain, serde_json::json!({ "name": "dev" }));
    assert_eq!(from_payload(plain.as_object().unwrap()).unwrap(), None);

    for invalid in [
        serde_json::json!({ "id": "not-an-id", "vcpus": 1, "memory_mib": 512, "share_mounts": false, "account": null }),
        serde_json::json!({ "id": id, "vcpus": 0, "memory_mib": 512, "share_mounts": false, "account": null }),
        serde_json::json!({ "id": id, "vcpus": 1, "memory_mib": 512, "account": null }),
        serde_json::json!({ "id": id, "vcpus": 1, "memory_mib": 512, "share_mounts": false }),
        serde_json::json!({ "id": id, "vcpus": 1, "memory_mib": 512, "share_mounts": false, "account": { "server_url": "", "organization_id": "o", "user_id": "u" } }),
        serde_json::json!({ "id": id, "vcpus": 1, "memory_mib": 512, "share_mounts": false, "account": null, "extra": 1 }),
    ] {
        let fields = serde_json::json!({ "snapshot": invalid });
        assert!(from_payload(fields.as_object().unwrap()).is_err());
    }
    let mut bad = request.clone();
    bad.snapshot.as_mut().unwrap().snapshot_id = id.simple().to_string();
    assert!(journal_payload(&mut serde_json::json!({}), &bad).is_err());
}

#[test]
fn listings_and_entries_parse_by_the_daemons_rules() {
    let entries = parse_listing(
        b"/2/040755/0/0/.//\n/2/040755/0/0/..//\n/14/100600/1000/1000/auth.json/7/\n/15/040700/0/0/sub//\n",
    );
    assert_eq!(
        entries,
        [
            DirectoryEntry {
                name: Some("auth.json".to_owned()),
                regular: true,
                directory: false,
                size: 7,
            },
            DirectoryEntry {
                name: Some("sub".to_owned()),
                regular: false,
                directory: true,
                size: 0,
            },
        ]
    );
    // A name with a newline, or that is not UTF-8, cannot be Codewire's: its
    // pieces are skipped or it stays nameless, and nothing fails.
    let odd = parse_listing(
        b"/16/100600/1000/1000/notes\nmore/3/\n/17/100600/1000/1000/\xff\xfe/4/\n/18/100600/1000/1000/with space/5/\ngarbage\n",
    );
    assert_eq!(odd.len(), 2);
    assert!(odd.iter().all(|entry| entry.name.is_none()));
    assert!(parse_listing(b"").is_empty());

    assert_eq!(LoginKind::Codex.entry("auth.json"), LoginEntry::File);
    assert_eq!(
        LoginKind::Codex.entry(".auth.json.codewire.0123abcd.new"),
        LoginEntry::WriteInProgress
    );
    assert_eq!(
        LoginKind::Codex.entry(".auth.json.codewire.0123abcd.aside"),
        LoginEntry::Temporary
    );
    assert_eq!(LoginKind::Codex.entry("config.toml"), LoginEntry::Other);
    assert_eq!(
        LoginKind::Claude.entry(".credentials.json"),
        LoginEntry::File
    );
    assert_eq!(
        LoginKind::Claude.entry(".credentials.json.codewire.0123abcd.new"),
        LoginEntry::WriteInProgress
    );
    assert_eq!(
        LoginKind::Claude.entry("credentials.json"),
        LoginEntry::Other
    );
    // A write in progress is Codewire's whatever it holds.
    assert!(LoginKind::Codex.codewire(".auth.json.codewire.0123abcd.new", b"not json"));
    assert!(!LoginKind::Codex.codewire(".auth.json.codewire.0123abcd.aside", b"{}"));
}

#[tokio::test]
async fn a_token_left_in_freed_blocks_is_absent_from_the_snapshot() {
    let source = source(StoredEnvironmentState::Stopped);
    let state = source.paths.state_disk.clone();
    let token = format!("cw-snapshot-test-freed-{}", Uuid::new_v4().simple());
    debugfs_setup(&state, "mkdir /srv");
    // A file the user wrote and deleted: its blocks are free but hold it.
    let mut written = Vec::new();
    while written.len() < 256 * 1024 {
        written.extend_from_slice(token.as_bytes());
        written.push(b'\n');
    }
    plant(&state, source.scratch.path(), "/srv/notes.txt", &written);
    debugfs_setup(&state, "rm /srv/notes.txt");
    assert!(contains(&fs::read(&state).unwrap(), token.as_bytes()));

    let snapshot = capture_named(&source, "s1").await.unwrap();

    let copy = fs::read(snapshot_dir(&source, &snapshot).join("disks/state.raw")).unwrap();
    assert!(
        !contains(&copy, token.as_bytes()),
        "a freed block kept the token"
    );
    assert!(
        contains(&fs::read(&state).unwrap(), token.as_bytes()),
        "the source is untouched"
    );
}

#[tokio::test]
async fn capture_removes_a_write_in_progress_unread_and_a_cleared_claude_store() {
    let source = source(StoredEnvironmentState::Stopped);
    let state = source.paths.state_disk.clone();
    let token = format!("cw-snapshot-test-rules-{}", Uuid::new_v4().simple());
    for directory in [
        "/agent-homes",
        "/agent-homes/codex",
        "/home",
        "/home/.claude",
    ] {
        debugfs_setup(&state, &format!("mkdir {directory}"));
    }
    let scratch = source.scratch.path();
    // Not even JSON: a write in progress is Codewire's whatever it holds.
    plant(
        &state,
        scratch,
        "/agent-homes/codex/.auth.json.codewire.0123456789abcdef0123456789abcdef.new",
        format!("{{\"tokens\": {{\"access_token\": \"{token}").as_bytes(),
    );
    // Claude Code's cleared copy beside the marker.
    plant(
        &state,
        scratch,
        "/home/.claude/.credentials.json",
        &serde_json::to_vec(&serde_json::json!({
            "claudeAiOauth": { "accessToken": token, "refreshToken": "", "expiresAt": 0 },
            "codewireManaged": 1,
        }))
        .unwrap(),
    );

    let snapshot = capture_named(&source, "s1").await.unwrap();

    assert_eq!(snapshot.removed_logins, 2);
    let copy = fs::read(snapshot_dir(&source, &snapshot).join("disks/state.raw")).unwrap();
    assert!(!contains(&copy, token.as_bytes()));
}

#[tokio::test]
async fn snapshots_survive_the_loss_of_their_store_and_are_listed_again() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let config = config(&source);
    forget_store(&config);
    for file in [crate::snapshot_store::DATABASE_FILE, RETENTION_FILE] {
        fs::remove_file(config.root.join(file)).unwrap();
    }

    let listed = list(&config).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, snapshot.id);
    assert_eq!(listed[0].name, "s1");
    assert!(
        snapshot_dir(&source, &snapshot)
            .join("disks/state.raw")
            .is_file()
    );
    let (_, manifest) = ready_snapshot(&config, canonical_id(&snapshot.id).unwrap()).unwrap();
    // Its retention is recorded again too, for the next supervisor.
    forget_store(&config);
    let mut content = BTreeMap::new();
    let mut artifacts = BTreeSet::new();
    retain(&config, &mut content, &mut artifacts).unwrap();
    assert!(artifacts.contains(manifest.root_generation.artifact_generation().unwrap()));
}

#[tokio::test]
async fn a_snapshot_name_is_never_a_uuid() {
    let source = source(StoredEnvironmentState::Stopped);
    let error = capture_named(&source, &Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("UUID"), "{}", error.message());
}

/// A restoring create named `name`, journaled and recorded up to
/// ProvisionWorkspace.
fn journaled_restore(
    source: &Source,
    manifest: &Manifest,
    name: &str,
) -> (v1::CreateEnvironmentRequest, Uuid, OperationRecord) {
    let mut request = restore_request(manifest);
    request.name = name.to_owned();
    let fork = Uuid::new_v4();
    let payload = create_operation_payload(&request, &manifest.workspace_plan).unwrap();
    let supervisor = &source.service.supervisor;
    let mut core = supervisor.core();
    let mut operation = begin_create_operation(
        &core.store,
        Uuid::parse_str(&request.request_id).unwrap(),
        fork,
        &payload,
        &DirectShareDiscriminators::default(),
    )
    .unwrap();
    let mut environment = source.environment.clone();
    environment.id = fork;
    environment.name = request.name.clone();
    environment.state = StoredEnvironmentState::Starting;
    environment.generation = 0;
    environment.active_workspace_generation = None;
    environment.project_spec_json = Some(request.project_spec_json.clone());
    environment.project_spec_sha256 = Some(request.project_spec_sha256.clone());
    let mut state = core.state.clone();
    state.environments.insert(request.name.clone(), environment);
    core.store.replace_state(&state).unwrap();
    core.state = state;
    for _ in 0..2 {
        operation = core
            .store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
    }
    drop(core);
    assert_eq!(
        next_effect(OperationKind::Create, operation.checkpoint).unwrap(),
        Some(LifecycleEffect::ProvisionWorkspace)
    );
    (request, fork, operation)
}

#[tokio::test]
async fn provision_workspace_places_records_and_checkpoints_and_replays_either_window() {
    let source = source(StoredEnvironmentState::Stopped);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let snapshot_id = canonical_id(&snapshot.id).unwrap();
    let config = config(&source);
    let (_, manifest) = ready_snapshot(&config, snapshot_id).unwrap();
    let supervisor = &source.service.supervisor;
    let sizes = (source.environment.disk_bytes, 0);

    // A first run: placed, recorded and checkpointed.
    let (request, fork, operation) = journaled_restore(&source, &manifest, "fork-1");
    let advanced = place_disks(supervisor, &request, fork, &operation)
        .await
        .unwrap();
    assert_eq!(advanced.checkpoint, operation.checkpoint + 1);
    let recorded = supervisor.environment("fork-1").unwrap();
    assert_eq!(
        recorded.active_workspace_generation.as_ref(),
        Some(&manifest.root_generation)
    );
    let tree = config.engine_root().join("vms").join(fork.to_string());
    assert!(tree.join("disks/state.raw").is_file());

    // A replay after the tree was published but before it was recorded.
    let (request, fork, operation) = journaled_restore(&source, &manifest, "fork-2");
    place_snapshot_tree(&config, snapshot_id, fork, operation.operation_id, sizes).unwrap();
    let advanced = place_disks(supervisor, &request, fork, &operation)
        .await
        .unwrap();
    assert_eq!(advanced.checkpoint, operation.checkpoint + 1);

    // A replay after it was recorded but before the checkpoint.
    let (request, fork, operation) = journaled_restore(&source, &manifest, "fork-3");
    place_snapshot_tree(&config, snapshot_id, fork, operation.operation_id, sizes).unwrap();
    supervisor
        .update_environment("fork-3", |environment| {
            environment.active_workspace_generation = Some(manifest.root_generation.clone());
            Ok(())
        })
        .unwrap();
    let advanced = place_disks(supervisor, &request, fork, &operation)
        .await
        .unwrap();
    assert_eq!(advanced.checkpoint, operation.checkpoint + 1);
    assert_eq!(
        next_effect(OperationKind::Create, advanced.checkpoint).unwrap(),
        Some(LifecycleEffect::StageWorkspaceGeneration)
    );
}

/// A fake snapshot directory, private as the real ones.
fn fake_snapshot_dir(engine: &Path, name: &str) -> PathBuf {
    let path = engine.join(SNAPSHOTS_DIRECTORY).join(name);
    fs::create_dir_all(path.join("disks")).unwrap();
    for directory in [&path, &path.join("disks")] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(path.join("disks/state.raw"), b"disk").unwrap();
    fs::set_permissions(
        path.join("disks/state.raw"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    path
}

fn private_runtime() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("runtime");
    let engine = root.join("engine");
    fs::create_dir_all(engine.join(SNAPSHOTS_DIRECTORY)).unwrap();
    for directory in [&root, &engine, &engine.join(SNAPSHOTS_DIRECTORY)] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (parent, root, engine)
}

#[test]
fn reconcile_holds_the_in_flight_lock_while_a_capture_finishes() {
    let (_parent, root, engine) = private_runtime();
    let store = Arc::new(SnapshotStore::open(&PrivateRoot::open(&root).unwrap()).unwrap());
    // A capture between publication and its row: published directory,
    // recorded intent, its id in flight.
    let id = Uuid::new_v4();
    let directory = fake_snapshot_dir(&engine, &id.to_string());
    store.record_intent(id).unwrap();
    let capture = InFlight::new(id.to_string());
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (finish, finished) = std::sync::mpsc::channel();
    {
        let store = Arc::clone(&store);
        let released = Arc::clone(&released);
        // Reconciliation has read the store, intent included; the capture
        // now inserts its row, ends its intent and releases its id.
        set_test_hook(&engine, "reconcile-read", move || {
            let released_by_worker = Arc::clone(&released);
            let worker = std::thread::spawn(move || {
                store
                    .insert(&SnapshotRow {
                        kind: crate::snapshot_store::SnapshotKind::Disk,
                        id,
                        name: "s1".to_owned(),
                        state: SnapshotState::Ready,
                        created_unix_ms: 1,
                        manifest_sha256: "a".repeat(64),
                        retained: Retained::default(),
                    })
                    .unwrap();
                drop(capture);
                released_by_worker.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            std::thread::sleep(Duration::from_millis(200));
            // The release waits for reconciliation's lock.
            assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
            finish.send(worker).unwrap();
        });
    }

    reconcile(&engine, &store).unwrap();

    finished.recv().unwrap().join().unwrap();
    assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        directory.join("disks/state.raw").exists(),
        "the capture's directory survives"
    );
    assert_eq!(store.find(&id.to_string()).unwrap().unwrap().name, "s1");
    assert!(store.intents().unwrap().is_empty());
}

#[tokio::test]
async fn a_reconcile_between_a_captures_publication_and_its_row_removes_nothing() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let engine = config.engine_root();
    let (ran, reconciled) = std::sync::mpsc::channel();
    {
        let config = config.clone();
        let engine = engine.clone();
        set_test_hook(&engine.clone(), "capture-published", move || {
            let store = store(&config).unwrap();
            reconcile(&engine, &store).unwrap();
            ran.send(()).unwrap();
        });
    }
    let snapshot = capture_named(&source, "s1").await.unwrap();
    reconciled.recv().unwrap();
    assert!(
        snapshot_dir(&source, &snapshot)
            .join("disks/state.raw")
            .is_file()
    );
    let listed = list(&config).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(store(&config).unwrap().intents().unwrap().is_empty());
}

#[tokio::test]
async fn a_verified_directory_with_an_intent_is_adopted_and_a_marked_one_is_deleted() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let engine = config.engine_root();
    let kept = capture_named(&source, "s1").await.unwrap();
    let marked = capture_named(&source, "s2").await.unwrap();
    // The store is lost; one capture's intent survives, as from a crash
    // between publication and its row. The other was being deleted.
    let store = store(&config).unwrap();
    for snapshot in [&kept, &marked] {
        store.remove(canonical_id(&snapshot.id).unwrap()).unwrap();
    }
    store
        .record_intent(canonical_id(&kept.id).unwrap())
        .unwrap();
    let directory = snapshots_root(&engine)
        .unwrap()
        .open_private_directory(Path::new(&marked.id), 0o700)
        .unwrap();
    mark_directory_deleting(&directory).unwrap();

    reconcile(&engine, &store).unwrap();

    let names = store
        .list()
        .unwrap()
        .into_iter()
        .map(|row| row.name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["s1"]);
    assert!(snapshot_dir(&source, &kept).exists());
    assert!(!snapshot_dir(&source, &marked).exists());
    assert!(store.intents().unwrap().is_empty());
}

#[tokio::test]
async fn retention_comes_from_the_manifests_and_fails_closed() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let (_, manifest) = ready_snapshot(&config, canonical_id(&snapshot.id).unwrap()).unwrap();
    let artifact = manifest
        .root_generation
        .artifact_generation()
        .unwrap()
        .to_owned();

    // Both the store and the record lost: the manifests say what to keep,
    // read-only.
    forget_store(&config);
    for file in [crate::snapshot_store::DATABASE_FILE, RETENTION_FILE] {
        fs::remove_file(config.root.join(file)).unwrap();
    }
    let mut content = BTreeMap::new();
    let mut artifacts = BTreeSet::new();
    retain(&config, &mut content, &mut artifacts).unwrap();
    assert!(artifacts.contains(&artifact));
    assert!(
        !config
            .root
            .join(crate::snapshot_store::DATABASE_FILE)
            .exists(),
        "no SQLite"
    );

    // A record that cannot be read keeps everything on disk.
    forget_store(&config);
    fs::write(config.root.join(RETENTION_FILE), b"not json").unwrap();
    fs::set_permissions(
        config.root.join(RETENTION_FILE),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let generations = config.engine_root().join("runtime-artifacts/generations");
    fs::create_dir_all(&generations).unwrap();
    let other = "e".repeat(64);
    fs::write(generations.join(format!("{other}.json")), b"{}").unwrap();
    let blobs = config.engine_root().join("content/blobs");
    fs::create_dir_all(&blobs).unwrap();
    let blob = "f".repeat(64);
    fs::write(blobs.join(&blob), b"blob").unwrap();
    let mut content = BTreeMap::new();
    let mut artifacts = BTreeSet::new();
    retain(&config, &mut content, &mut artifacts).unwrap();
    assert!(artifacts.contains(&other));
    assert_eq!(
        content.get(&Sha256Digest::parse(&format!("sha256:{blob}")).unwrap()),
        Some(&4)
    );
    // A manifest that cannot be read fails the derivation closed too.
    forget_store(&config);
    fs::remove_file(config.root.join(RETENTION_FILE)).unwrap();
    let path = snapshot_dir(&source, &snapshot).join(MANIFEST_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"{").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let mut artifacts = BTreeSet::new();
    retain(&config, &mut BTreeMap::new(), &mut artifacts).unwrap();
    assert!(artifacts.contains(&other));
}

#[tokio::test]
async fn a_token_in_an_unwritten_extent_over_freed_blocks_is_absent_from_the_snapshot() {
    let source = source(StoredEnvironmentState::Stopped);
    let state = source.paths.state_disk.clone();
    let token = format!("cw-snapshot-test-unwritten-{}", Uuid::new_v4().simple());
    debugfs_setup(&state, "mkdir /srv");
    let mut written = Vec::new();
    while written.len() < 128 * 1024 {
        written.extend_from_slice(token.as_bytes());
        written.push(b'\n');
    }
    plant(&state, source.scratch.path(), "/srv/old.json", &written);
    debugfs_setup(&state, "rm /srv/old.json");
    // A new file takes those blocks as an unwritten extent, never written,
    // and a file keeps blocks past its end.
    plant(&state, source.scratch.path(), "/srv/preallocated", b"");
    debugfs_setup(&state, "fallocate /srv/preallocated 0 63");
    // The token is inside that file's unwritten extent, not only in free
    // blocks.
    let stat = String::from_utf8(debugfs_setup(&state, "stat /srv/preallocated")).unwrap();
    let extents = stat
        .lines()
        .skip_while(|line| *line != "EXTENTS:")
        .nth(1)
        .unwrap()
        .to_owned();
    let mut in_unwritten = false;
    let source_bytes = fs::read(&state).unwrap();
    for entry in extents.split(", ") {
        if let Some(Some(extent)) = parse_extent(entry.trim())
            && extent.unwritten
        {
            let start = usize::try_from(extent.physical * 4096).unwrap();
            let end = start + usize::try_from(extent.length * 4096).unwrap();
            in_unwritten |= contains(&source_bytes[start..end], token.as_bytes());
        }
    }
    assert!(in_unwritten, "{extents}");

    let snapshot = capture_named(&source, "s1").await.unwrap();

    let copy = fs::read(snapshot_dir(&source, &snapshot).join("disks/state.raw")).unwrap();
    assert!(
        !contains(&copy, token.as_bytes()),
        "an unwritten extent kept the token"
    );
}

#[tokio::test]
async fn blocks_past_the_end_of_an_indirect_mapped_file_are_punched() {
    let scratch = tempfile::tempdir().unwrap();
    let image = scratch.path().join("indirect.raw");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&image)
        .unwrap();
    file.set_len(64 * MIB).unwrap();
    drop(file);
    // No extents: every file is mapped by indirect blocks.
    let status = ProcessCommand::new(tool("mkfs.ext4"))
        .args(["-q", "-F", "-b", "4096", "-O", "^extent,^64bit"])
        .arg(&image)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
    let token = format!("cw-snapshot-test-indirect-{}", Uuid::new_v4().simple());
    let mut written = Vec::new();
    while written.len() < 128 * 1024 {
        written.extend_from_slice(token.as_bytes());
        written.push(b'\n');
    }
    plant(&image, scratch.path(), "/indirect", &written);
    // The file now ends inside its second block: the rest of its blocks
    // hold the token past its end.
    debugfs_setup(&image, "sif /indirect size 5000");
    let stat = String::from_utf8(debugfs_setup(&image, "stat /indirect")).unwrap();
    assert!(stat.contains("BLOCKS:"), "{stat}");
    let map = stat
        .lines()
        .skip_while(|line| *line != "BLOCKS:")
        .nth(1)
        .unwrap()
        .to_owned();
    let past_end = map
        .split(", ")
        .filter_map(|entry| parse_extent(entry.trim()).unwrap())
        .flat_map(|extent| {
            (extent.logical..extent.logical + extent.length)
                .zip(extent.physical..)
                .filter(|(logical, _)| *logical >= 2)
                .map(|(_, physical)| physical)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(past_end.len() > 20, "{map}");
    let before = fs::read(&image).unwrap();
    for block in &past_end {
        let start = usize::try_from(block * 4096).unwrap();
        assert!(before[start..start + 4096].iter().any(|byte| *byte != 0));
    }

    punch_unreadable_blocks(&image, 4096).await.unwrap();

    let after = fs::read(&image).unwrap();
    for block in &past_end {
        let start = usize::try_from(block * 4096).unwrap();
        assert!(
            after[start..start + 4096].iter().all(|byte| *byte == 0),
            "block {block} past the end kept data"
        );
    }
    // What the file still holds is untouched.
    assert!(contains(&after, token.as_bytes()));
}

/// Make an ext4 image with the verity feature at `image`, of `bytes`.
fn verity_image(image: &Path, bytes: u64) {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(image)
        .unwrap();
    file.set_len(bytes).unwrap();
    drop(file);
    let status = ProcessCommand::new(tool("mkfs.ext4"))
        .args(crate::host::EXT4_FORMAT)
        .args(["-q", "-F", "-O", "verity"])
        .arg(image)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        crate::state::read_ext4_superblock(&File::open(image).unwrap(), image)
            .unwrap()
            .verity
    );
}

/// Plant at `path` a file of 20 blocks holding `token`, cut to one block,
/// optionally marked as an fs-verity file; its blocks past that end, logical
/// and physical. A verity file's tree would start at logical block 16.
fn plant_past_its_end(
    image: &Path,
    scratch: &Path,
    path: &str,
    token: &str,
    verity: bool,
) -> Vec<(u64, u64)> {
    let mut written = Vec::new();
    while written.len() < 20 * 4096 {
        written.extend_from_slice(token.as_bytes());
        written.push(b'\n');
    }
    written.truncate(20 * 4096);
    plant(image, scratch, path, &written);
    debugfs_setup(image, &format!("sif {path} size 4096"));
    let stat = String::from_utf8(debugfs_setup(image, &format!("stat {path}"))).unwrap();
    if verity {
        let flags = stat
            .split_whitespace()
            .skip_while(|word| *word != "Flags:")
            .nth(1)
            .and_then(|flags| flags.strip_prefix("0x"))
            .map(|flags| u64::from_str_radix(flags, 16).unwrap())
            .unwrap();
        debugfs_setup(
            image,
            &format!("sif {path} flags {:#x}", flags | 0x0010_0000),
        );
    }
    let past_end: Vec<(u64, u64)> = stat
        .lines()
        .skip_while(|line| *line != "EXTENTS:")
        .nth(1)
        .unwrap()
        .split(", ")
        .filter_map(|entry| parse_extent(entry.trim()).unwrap())
        .flat_map(|extent| {
            (extent.logical..extent.logical + extent.length)
                .zip(extent.physical..)
                .filter(|(logical, _)| *logical >= 1)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(past_end.len(), 19, "{stat}");
    past_end
}

fn disk_block(image: &[u8], physical: u64) -> &[u8] {
    let start = usize::try_from(physical * 4096).unwrap();
    &image[start..start + 4096]
}

#[tokio::test]
async fn a_verity_files_merkle_tree_is_kept_and_a_plain_files_tail_punched() {
    let scratch = tempfile::tempdir().unwrap();
    let image = scratch.path().join("verity.raw");
    verity_image(&image, 64 * MIB);
    let token = format!("cw-snapshot-test-verity-{}", Uuid::new_v4().simple());
    let verity = plant_past_its_end(&image, scratch.path(), "/verity", &token, true);
    let plain = plant_past_its_end(&image, scratch.path(), "/plain", &token, false);
    let before = fs::read(&image).unwrap();

    punch_unreadable_blocks(&image, 4096).await.unwrap();

    let after = fs::read(&image).unwrap();
    assert_verity_tail(&verity, &before, &after, &token);
    for (_, physical) in plain {
        assert!(
            disk_block(&after, physical).iter().all(|byte| *byte == 0),
            "block {physical} past the end kept data"
        );
    }
}

/// Of a verity file's blocks past its end, those before its tree at logical
/// block 16 were punched and the tree is unchanged.
fn assert_verity_tail(blocks: &[(u64, u64)], before: &[u8], after: &[u8], token: &str) {
    for &(logical, physical) in blocks {
        assert!(contains(disk_block(before, physical), token.as_bytes()));
        if logical < 16 {
            assert!(
                disk_block(after, physical).iter().all(|byte| *byte == 0),
                "block {physical} before the tree kept data"
            );
        } else {
            assert_eq!(
                disk_block(after, physical),
                disk_block(before, physical),
                "tree block {physical} changed"
            );
        }
    }
}

#[tokio::test]
async fn a_state_disk_with_the_verity_feature_is_captured_with_its_merkle_trees() {
    let source = source(StoredEnvironmentState::Stopped);
    let state = &source.paths.state_disk;
    fs::remove_file(state).unwrap();
    verity_image(state, source.environment.disk_bytes);
    let token = format!("cw-snapshot-test-verity-{}", Uuid::new_v4().simple());
    let verity = plant_past_its_end(state, source.scratch.path(), "/verity", &token, true);
    let original = fs::read(state).unwrap();

    let snapshot = capture_named(&source, "s1").await.unwrap();

    let copy_path = snapshot_dir(&source, &snapshot).join("disks/state.raw");
    let stat = String::from_utf8(debugfs_setup(&copy_path, "stat /verity")).unwrap();
    assert!(
        stat.contains("Flags: 0x180000") && stat.contains("Size: 4096"),
        "{stat}"
    );
    let copy = fs::read(&copy_path).unwrap();
    assert_verity_tail(&verity, &original, &copy, &token);
}

#[tokio::test]
async fn a_delete_that_cannot_mark_its_row_removes_its_marker() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let engine = config.engine_root();
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let directory = snapshot_dir(&source, &snapshot);
    let store = store(&config).unwrap();
    let id = canonical_id(&snapshot.id).unwrap();
    // The row changes between the marker and its own marking.
    {
        let store = Arc::clone(&store);
        let directory = directory.clone();
        set_test_hook(&engine, "delete-marked", move || {
            assert!(directory.join(DELETING_MARKER).exists());
            store.remove(id).unwrap();
        });
    }

    delete(&config, "s1").unwrap_err();

    assert!(
        !directory.join(DELETING_MARKER).exists(),
        "a failed delete leaves no marker"
    );
    assert!(directory.join("disks/state.raw").exists());
    // The snapshot, row-less now, is adopted again rather than removed.
    reconcile(&engine, &store).unwrap();
    assert_eq!(store.find("s1").unwrap().unwrap().id, id);
    assert!(directory.join("disks/state.raw").exists());
}

#[tokio::test]
async fn reconcile_leaves_a_marked_snapshot_a_restore_holds() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let engine = config.engine_root();
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let directory = snapshot_dir(&source, &snapshot);
    let store = store(&config).unwrap();
    // A delete marked the directory, then failed before its row changed,
    // while a restore reads the snapshot.
    let marked = snapshots_root(&engine)
        .unwrap()
        .open_private_directory(Path::new(&snapshot.id), 0o700)
        .unwrap();
    mark_directory_deleting(&marked).unwrap();
    drop(marked);
    let restore = File::open(&directory).unwrap();
    flock(&restore, FlockOperation::LockShared).unwrap();

    reconcile(&engine, &store).unwrap();

    assert!(
        directory.join("disks/state.raw").exists(),
        "a restore holds it"
    );
    assert!(store.find("s1").unwrap().is_some(), "its row stays too");

    drop(restore);
    // A child another test forks holds a copy of the restore's descriptor,
    // and so its shared lock, until it execs; a pass then leaves the snapshot
    // for a later one, as it would for a restore.
    for _ in 0..100 {
        reconcile(&engine, &store).unwrap();
        if !directory.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!directory.exists());
    assert!(store.find("s1").unwrap().is_none());
}

#[test]
fn reconcile_removes_leftovers_after_releasing_the_in_flight_lock() {
    let (_parent, root, engine) = private_runtime();
    let store = SnapshotStore::open(&PrivateRoot::open(&root).unwrap()).unwrap();
    let leftover = Uuid::new_v4();
    let directory = fake_snapshot_dir(&engine, &leftover.to_string());
    store.record_intent(leftover).unwrap();
    let staging_name = format!("{CAPTURE_STAGING_PREFIX}{}", Uuid::new_v4());
    let staging = fake_snapshot_dir(&engine, &staging_name);
    // This test's trash trees, among what other tests hold in flight.
    let suffixes = [format!("-{leftover}"), format!("-{staging_name}")];
    let ours = {
        let suffixes = suffixes.clone();
        move |busy: &BTreeSet<String>| {
            busy.iter()
                .filter(|name| {
                    name.starts_with(TRASH_PREFIX)
                        && suffixes
                            .iter()
                            .any(|suffix| name.ends_with(suffix.as_str()))
                })
                .count()
        }
    };
    let (seen, observed) = std::sync::mpsc::channel();
    {
        let ours = ours.clone();
        set_test_hook(&engine, "reconcile-removing", move || {
            // The lock is free (other tests may hold it a moment) while the
            // trees, moved to trash, wait to go.
            let mut held = None;
            for _ in 0..200 {
                if let Ok(busy) = IN_FLIGHT.get().unwrap().try_lock() {
                    held = Some(ours(&busy));
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            seen.send(held).unwrap();
        });
    }

    reconcile(&engine, &store).unwrap();

    assert_eq!(observed.recv().unwrap(), Some(2));
    assert!(!directory.exists());
    assert!(!staging.exists());
    assert!(
        fs::read_dir(engine.join(TRASH_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(ours(&in_flight()), 0);
}

#[tokio::test]
async fn an_adoption_publishes_retention_again() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let id = canonical_id(&snapshot.id).unwrap();
    let (_, manifest) = ready_snapshot(&config, id).unwrap();
    let artifact = manifest
        .root_generation
        .artifact_generation()
        .unwrap()
        .to_owned();
    // The row is lost in a running process, and retention republished
    // without it.
    let store = store(&config).unwrap();
    store.remove(id).unwrap();
    publish_retention(&config, &store, None).unwrap();
    let retained = |config: &NativeRuntimeConfig| {
        let mut artifacts = BTreeSet::new();
        retain(config, &mut BTreeMap::new(), &mut artifacts).unwrap();
        artifacts.contains(&artifact)
    };
    assert!(!retained(&config));

    settle(&config, &store).unwrap();

    assert!(store.find("s1").unwrap().is_some());
    assert!(retained(&config), "retention keeps the adopted snapshot");
    forget_store(&config);
    assert!(retained(&config), "and so does the record");
}

#[tokio::test]
async fn keeping_everything_fails_when_it_cannot_list_what_is_on_disk() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    capture_named(&source, "s1").await.unwrap();
    forget_store(&config);
    // An unreadable record: collection keeps everything it can list.
    fs::write(config.root.join(RETENTION_FILE), b"not json").unwrap();
    fs::set_permissions(
        config.root.join(RETENTION_FILE),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let blobs = config.engine_root().join("content/blobs");
    fs::create_dir_all(&blobs).unwrap();
    retain(&config, &mut BTreeMap::new(), &mut BTreeSet::new()).unwrap();
    // A listing it cannot read fails it, so collection skips the round. A
    // file in the directory's place fails the listing for any user, root
    // included, where permission bits would not.
    fs::remove_dir_all(&blobs).unwrap();
    fs::write(&blobs, b"").unwrap();
    let result = retain(&config, &mut BTreeMap::new(), &mut BTreeSet::new());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// VM checkpoints in the same store (#3046 R4).

/// Publish a VM checkpoint of the source, made from disk snapshot
/// `snapshot`'s files plus `vmm/` files a VMM would have written.
async fn publish_checkpoint(source: &Source, snapshot: &v1::Snapshot, name: &str) -> SnapshotRow {
    publish_checkpoint_with_catalog(source, snapshot, name, None).await
}

async fn publish_checkpoint_with_catalog(
    source: &Source,
    snapshot: &v1::Snapshot,
    name: &str,
    cw_runtime_catalog_generation: Option<String>,
) -> SnapshotRow {
    let config = config(source);
    let engine = config.engine_root();
    let (_, disk) = ready_snapshot(&config, canonical_id(&snapshot.id).unwrap()).unwrap();
    let operation = Uuid::new_v4();
    let staging_name = format!("{CAPTURE_STAGING_PREFIX}{operation}");
    let staging = snapshots_root(&engine).unwrap().path().join(&staging_name);
    let from = snapshot_dir(source, snapshot);
    let copy = |relative: &str| {
        let target = staging.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        for directory in [target.parent().unwrap(), &staging] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::copy(from.join(relative), &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    };
    copy("disks/state.raw");
    let storage = disk.storage_generation().unwrap();
    copy(&format!("root/{storage}/root.raw"));
    fs::set_permissions(staging.join("root"), fs::Permissions::from_mode(0o700)).unwrap();
    let vmm = staging.join("vmm");
    fs::create_dir(&vmm).unwrap();
    fs::set_permissions(&vmm, fs::Permissions::from_mode(0o700)).unwrap();
    let memory_bytes = u64::from(disk.resources.memory_mib) * MIB;
    fs::write(vmm.join("config.json"), b"{\"cpus\":{}}").unwrap();
    fs::write(vmm.join("state.json"), b"{\"snapshot_data\":{}}").unwrap();
    File::create(vmm.join("memory-ranges"))
        .unwrap()
        .set_len(memory_bytes)
        .unwrap();
    for file in crate::state::CHECKPOINT_VMM_FILES {
        fs::set_permissions(vmm.join(file), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let digest = |file: &str| format!("{:x}", Sha256::digest(fs::read(vmm.join(file)).unwrap()));
    let mut manifest = disk.clone();
    manifest.schema_version = CHECKPOINT_MANIFEST_SCHEMA_VERSION;
    manifest.kind = "checkpoint".to_owned();
    manifest.id = Uuid::new_v4();
    manifest.name = name.to_owned();
    manifest.consistency = Consistency::Paired;
    manifest.removed_logins = 0;
    manifest.checkpoint = Some(crate::supervisor::checkpoints::CheckpointManifest {
        source_generation: 3,
        vsock_cid: 7,
        vmm: crate::supervisor::checkpoints::VmmPin {
            version: "v54.0".to_owned(),
            sha256: "c".repeat(64),
        },
        guest_checkpoint_abi: codewire_vmm_guest_probe::GUEST_CHECKPOINT_ABI,
        host: crate::supervisor::checkpoints::HostIdentity {
            cpu: "synthetic:1:2:3".to_owned(),
            kernel_release: "6.0.0-synthetic".to_owned(),
        },
        memory_bytes,
        config_sha256: digest("config.json"),
        state_sha256: digest("state.json"),
        setup_disk_bytes: None,
        boot: crate::supervisor::checkpoints::BootBindings {
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                .encode()
                .to_owned(),
            docker: false,
            cw_runtime_catalog_generation,
            daemon_vsock_port: 7777,
        },
        timings: crate::supervisor::checkpoints::Timings::default(),
    });
    let store = store(&config).unwrap();
    publish(&config, &store, staging_name, &manifest, &mut || {})
        .await
        .unwrap()
}

#[tokio::test]
async fn checkpoints_and_snapshots_share_the_store_but_not_their_commands() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let row = publish_checkpoint(&source, &snapshot, "c1").await;
    assert_eq!(
        row.kind,
        SnapshotKind::Checkpoint {
            source_environment_id: source.environment.id
        }
    );
    // One name space: a snapshot cannot take a checkpoint's name.
    assert_eq!(
        capture_named(&source, "c1").await.unwrap_err().code(),
        tonic::Code::AlreadyExists
    );
    // Each command family sees only its own kind.
    assert_eq!(
        list(&config)
            .unwrap()
            .into_iter()
            .map(|snapshot| snapshot.name)
            .collect::<Vec<_>>(),
        ["s1"]
    );
    let checkpoints = list_ready(&config, true).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].0.name, "c1");
    assert!(
        get(&config, "c1")
            .unwrap_err()
            .message()
            .contains("is a VM checkpoint")
    );
    assert!(delete(&config, "c1").is_err());
    assert!(
        find_ready(&config, "s1", true)
            .unwrap_err()
            .message()
            .contains("is a disk snapshot")
    );
    // A create from the checkpoint's id is a fork: it finds the checkpoint.
    assert!(
        ready_snapshot(&config, row.id)
            .unwrap()
            .1
            .checkpoint
            .is_some()
    );
    assert_eq!(
        store(&config)
            .unwrap()
            .checkpoint_count(source.environment.id)
            .unwrap(),
        1
    );
    let removed = delete_ready(&config, "c1", true, |row, _| Ok(row.name.clone())).unwrap();
    assert_eq!(removed, "c1");
    assert!(list_ready(&config, true).unwrap().is_empty());
    assert!(
        !config
            .engine_root()
            .join("snapshots")
            .join(row.id.to_string())
            .exists()
    );
}

#[tokio::test]
async fn a_checkpoint_survives_the_loss_of_the_store_only_with_its_own_vmm_files() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let kept = publish_checkpoint(&source, &snapshot, "c1").await;
    let tampered = publish_checkpoint(&source, &snapshot, "c2").await;
    // c2's state file no longer matches its manifest.
    let state = config
        .engine_root()
        .join("snapshots")
        .join(tampered.id.to_string())
        .join("vmm/state.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&state, b"{\"changed\":true}").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
    forget_store(&config);
    for file in [crate::snapshot_store::DATABASE_FILE, RETENTION_FILE] {
        fs::remove_file(config.root.join(file)).unwrap();
    }
    let adopted = list_ready(&config, true).unwrap();
    assert_eq!(adopted.len(), 1);
    assert_eq!(adopted[0].0, {
        let mut row = kept.clone();
        row.created_unix_ms = adopted[0].0.created_unix_ms;
        row
    });
    assert!(adopted[0].0.kind.is_checkpoint());
}

#[tokio::test]
async fn a_fork_needs_its_checkpoints_recorded_cw_runtime_and_never_another() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    // The checkpoint's memory was booted with a catalog the store no longer
    // has; the installed runtime is never a substitute.
    let missing = "e".repeat(64);
    let row = publish_checkpoint_with_catalog(&source, &snapshot, "c1", Some(missing)).await;
    let (_, manifest) = find_ready(&config, &row.id.to_string(), true).unwrap();
    let mut request = restore_request(&manifest);
    let restore = request.snapshot.as_mut().unwrap();
    restore.vcpus = u32::from(manifest.resources.vcpus);
    restore.memory_mib = manifest.resources.memory_mib;
    let refused = restore_plan(&source.service.supervisor, &request)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        "VM checkpoint c1's cw runtime is no longer in the local store; it cannot be forked"
    );
    assert!(
        crate::supervisor::snapshots::open_recorded_cw_runtime_catalog(&config, &"e".repeat(64))
            .is_err()
    );
}

#[tokio::test]
async fn a_stop_for_restore_needs_the_checkpoint_files_the_restore_will_use() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let intact = |row: &SnapshotRow| {
        let (_, manifest) = find_ready(&config, &row.id.to_string(), true).unwrap();
        let checkpoint = manifest.checkpoint.clone().unwrap();
        crate::supervisor::checkpoints::linux::stored_files_intact(
            &config,
            row.id,
            &manifest,
            &checkpoint,
        )
    };
    let stored = |row: &SnapshotRow, relative: &str| {
        config
            .engine_root()
            .join("snapshots")
            .join(row.id.to_string())
            .join(relative)
    };
    let kept = publish_checkpoint(&source, &snapshot, "c1").await;
    intact(&kept).unwrap();

    // A changed VMM state file.
    let state_changed = publish_checkpoint(&source, &snapshot, "c2").await;
    let state = stored(&state_changed, "vmm/state.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&state, b"{\"changed\":true}").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(intact(&state_changed).is_err());

    // A stored disk that is no longer its recorded size.
    let disk_changed = publish_checkpoint(&source, &snapshot, "c3").await;
    let disk = stored(&disk_changed, "disks/state.raw");
    let length = fs::metadata(&disk).unwrap().len();
    File::options()
        .write(true)
        .open(&disk)
        .unwrap()
        .set_len(length + 4096)
        .unwrap();
    assert!(intact(&disk_changed).is_err());

    // A memory file that is no longer the recorded size.
    let memory_changed = publish_checkpoint(&source, &snapshot, "c4").await;
    let memory = stored(&memory_changed, "vmm/memory-ranges");
    fs::set_permissions(&memory, fs::Permissions::from_mode(0o600)).unwrap();
    File::options()
        .write(true)
        .open(&memory)
        .unwrap()
        .set_len(4096)
        .unwrap();
    fs::set_permissions(&memory, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(intact(&memory_changed).is_err());

    // The intact one is unaffected by its siblings' damage.
    intact(&kept).unwrap();
}

#[tokio::test]
async fn a_restore_after_a_stop_for_it_that_fails_leaves_the_stopped_source_on_its_own_disks() {
    // The state after a Stop for a restore: the source is stopped. Its
    // checkpoint is then found damaged, so the restore must refuse before it
    // places anything.
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    let damaged = publish_checkpoint(&source, &snapshot, "c1").await;
    let state = config
        .engine_root()
        .join("snapshots")
        .join(damaged.id.to_string())
        .join("vmm/state.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&state, b"{\"changed\":true}").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
    let disk_before = fs::read(&source.paths.state_disk).unwrap();
    let inode_before = fs::metadata(&source.paths.state_disk).unwrap().ino();

    use crate::control::v1::local_checkpoint_service_server::LocalCheckpointService as _;
    use std::os::unix::fs::MetadataExt as _;
    let refused = source
        .service
        .restore_checkpoint(Request::new(v1::RestoreCheckpointRequest {
            checkpoint: "c1".to_owned(),
            account: None,
            request_id: Uuid::new_v4().to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused.message().contains("VM checkpoint c1 is damaged"),
        "{}",
        refused.message()
    );

    let environment = source.service.supervisor.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert_eq!(
        fs::metadata(&source.paths.state_disk).unwrap().ino(),
        inode_before
    );
    assert!(fs::read(&source.paths.state_disk).unwrap() == disk_before);
    assert!(
        source
            .service
            .supervisor
            .core()
            .store
            .pending_operations()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_deleted_environment_takes_its_checkpoints_with_it() {
    let source = source(StoredEnvironmentState::Stopped);
    let config = config(&source);
    let snapshot = capture_named(&source, "s1").await.unwrap();
    publish_checkpoint(&source, &snapshot, "c1").await;
    publish_checkpoint(&source, &snapshot, "c2").await;
    crate::supervisor::checkpoints::retire_for_environment(
        &source.service.supervisor,
        source.environment.id,
    )
    .await
    .unwrap();
    assert!(list_ready(&config, true).unwrap().is_empty());
    // The disk snapshot stays; a replay changes nothing.
    assert_eq!(list(&config).unwrap().len(), 1);
    crate::supervisor::checkpoints::retire_for_environment(
        &source.service.supervisor,
        source.environment.id,
    )
    .await
    .unwrap();
}

#[test]
fn a_checkpoint_manifest_must_name_its_own_kind_and_memory() {
    let mut checkpoint = crate::supervisor::checkpoints::CheckpointManifest {
        source_generation: 1,
        vsock_cid: 3,
        vmm: crate::supervisor::checkpoints::VmmPin {
            version: "v54.0".to_owned(),
            sha256: "a".repeat(64),
        },
        guest_checkpoint_abi: codewire_vmm_guest_probe::GUEST_CHECKPOINT_ABI,
        host: crate::supervisor::checkpoints::HostIdentity {
            cpu: "x".to_owned(),
            kernel_release: String::new(),
        },
        memory_bytes: 512 * MIB,
        config_sha256: "b".repeat(64),
        state_sha256: "c".repeat(64),
        setup_disk_bytes: None,
        boot: crate::supervisor::checkpoints::BootBindings {
            skill_snapshot_sha256: None,
            environment_projection_sha256: Some("d".repeat(64)),
            managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                .encode()
                .to_owned(),
            docker: true,
            cw_runtime_catalog_generation: None,
            daemon_vsock_port: 7777,
        },
        timings: crate::supervisor::checkpoints::Timings::default(),
    };
    checkpoint.validate(512).unwrap();
    assert!(checkpoint.validate(1024).is_err());
    for broken in [
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| c.source_generation = 0,
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| c.vsock_cid = 2,
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| c.guest_checkpoint_abi = 99,
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| {
            c.vmm.sha256 = "short".to_owned()
        },
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| {
            c.boot.managed_credential_clients = "bogus".to_owned()
        },
        |c: &mut crate::supervisor::checkpoints::CheckpointManifest| c.setup_disk_bytes = Some(0),
    ] {
        let mut changed = checkpoint.clone();
        broken(&mut changed);
        assert!(changed.validate(512).is_err());
    }
    checkpoint.setup_disk_bytes = Some(MIB);
    checkpoint.validate(512).unwrap();
}
