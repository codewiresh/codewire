use std::sync::atomic::AtomicUsize;

use super::*;
use crate::artifact::{ArtifactArchitecture, ArtifactLock, ArtifactSpec};
use crate::direct_share::DirectShareDiscriminator;
use crate::oci::{OciArchitecture, ResolvedDescriptor, ResolvedImage, Sha256Digest};
use crate::uds::bind_owner_only;
use codewire_access::builtin_provider_catalog;
use codewire_local_credentials::{LocalCredentialClient, serve_local_credential_authority};
use codewire_protected_store::EphemeralProtectedStore;

#[test]
fn request_destinations_allow_only_repositories_inside_repositories() {
    let project = |destinations: &[&str]| codewire_project::ProjectSpec {
        repositories: destinations
            .iter()
            .map(|destination| codewire_project::RepositorySpec {
                source: "https://example.test/org/app.git".to_owned(),
                destination: (*destination).to_owned(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let mount = |destination: &str| v1::LocalMountInput {
        destination: destination.to_owned(),
        ..Default::default()
    };
    validate_request_destinations(&project(&["/workspace/root", "/workspace/root/web"]), &[])
        .unwrap();
    for (repositories, mounts) in [
        (vec!["/workspace/a", "/workspace/a"], vec![]),
        (vec!["/workspace/a"], vec![mount("/workspace/a/c")]),
        // `-` sorts before `/`; a neighbours-only check missed this.
        (
            vec!["/workspace/a-b", "/workspace/a/c"],
            vec![mount("/workspace/a")],
        ),
    ] {
        assert!(matches!(
            validate_request_destinations(&project(&repositories), &mounts),
            Err(SupervisorError::InvalidRequest)
        ));
    }
}

/// Bounds a wait for a started supervisor's listener after its startup
/// reconciliation. The socket appearing, or the supervisor exiting, ends
/// the wait; the bound only turns a hang into a failure. 2 s failed on a
/// slow CI slot that stalled I/O (#3239).
const LISTENER_HANG_GUARD: Duration = Duration::from_secs(120);

/// Starts a supervisor that must refuse to start, and returns its error.
/// The supervisor exiting ends the wait; one that listens instead fails at
/// once rather than serving until the run is stopped (#3321).
async fn refused_startup(config: &NativeRuntimeConfig) -> SupervisorError {
    let socket = config.supervisor_socket();
    let existing = SocketIdentity::capture(&socket).ok();
    let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
    tokio::time::timeout(LISTENER_HANG_GUARD, async {
        loop {
            if supervisor.is_finished() {
                return (&mut supervisor)
                    .await
                    .unwrap()
                    .expect_err("supervisor startup succeeded");
            }
            if let Ok(identity) = SocketIdentity::capture(&socket)
                && Some(&identity) != existing.as_ref()
            {
                supervisor.abort();
                panic!("supervisor listened instead of refusing to start");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hang guard: supervisor startup neither refused nor listened")
}

fn project_intent(vcpus: u32, memory_mib: u32, disk_gib: u64) -> (Vec<u8>, String) {
    let spec = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(vcpus * 1_000),
            memory_mib: Some(u64::from(memory_mib)),
            disk_gib: Some(disk_gib),
        },
        ..Default::default()
    };
    let bytes = spec.canonical_json().unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    (bytes, digest)
}

fn test_digest(seed: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(seed))).unwrap()
}

fn install_test_artifact_generation(engine: &PrivateRoot, kernel_bytes: &[u8]) -> (String, String) {
    fn spec(path: &str, bytes: &[u8]) -> ArtifactSpec {
        ArtifactSpec {
            path: path.into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            architecture: ArtifactArchitecture::host().unwrap(),
        }
    }

    let cloud_hypervisor = spec("bin/cloud-hypervisor", b"cloud-hypervisor");
    let kernel = spec("boot/kernel", kernel_bytes);
    let initramfs = spec("boot/initramfs", b"initramfs");
    let lock = ArtifactLock::for_test(cloud_hypervisor.clone(), kernel.clone(), initramfs.clone());
    RuntimeArtifactStore::create(engine).unwrap();
    let blobs = engine.path().join("runtime-artifacts/blobs");
    for (prefix, artifact, bytes, permissions) in [
        (
            "x",
            &cloud_hypervisor,
            b"cloud-hypervisor".as_slice(),
            0o500,
        ),
        ("r", &kernel, kernel_bytes, 0o400),
        ("r", &initramfs, b"initramfs".as_slice(), 0o400),
    ] {
        let path = blobs.join(format!("{prefix}-{}", artifact.sha256));
        if !path.exists() {
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(permissions)).unwrap();
        }
    }
    let generation = lock.generation().unwrap();
    let manifest = engine
        .path()
        .join("runtime-artifacts/generations")
        .join(format!("{generation}.json"));
    fs::write(&manifest, lock.canonical_json().unwrap()).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400)).unwrap();
    (generation, kernel.sha256)
}

#[cfg(target_arch = "x86_64")]
fn install_test_guest_generation(engine: &PrivateRoot, marker: &[u8]) -> String {
    // A synthetic static ELF writes the exact version reply using Linux
    // syscalls. This exercises real retained-asset admission without a VMM,
    // a compiler dependency, or a bypass in the production preflight.
    let reply = b"cloud-hypervisor v54.0\n";
    let mut elf = vec![0_u8; 120];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&(0x400000_u64 + 120).to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5_u32.to_le_bytes());
    elf[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    elf.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0xbe]);
    elf.extend_from_slice(&(0x400000_u64 + 156).to_le_bytes());
    elf.push(0xba);
    elf.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    elf.extend_from_slice(&[0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
    assert_eq!(elf.len(), 156);
    elf.extend_from_slice(reply);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf[104..112].copy_from_slice(&size.to_le_bytes());
    let mut init = elf.clone();
    init.extend_from_slice(marker);
    let initramfs = codewire_vmm_guest_probe::canonical_guest_root_newc(&init, &elf, &elf).unwrap();
    let mut kernel = vec![0_u8; 0x240];
    kernel[510..512].copy_from_slice(&[0x55, 0xaa]);
    kernel[0x202..0x206].copy_from_slice(b"HdrS");
    let spec = |path: &str, bytes: &[u8]| ArtifactSpec {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        architecture: ArtifactArchitecture::X86_64,
    };
    let cloud_hypervisor = spec("bin/cloud-hypervisor", &elf);
    let kernel_spec = spec("boot/kernel", &kernel);
    let initramfs_spec = spec("boot/initramfs", &initramfs);
    let lock = ArtifactLock::for_test(
        cloud_hypervisor.clone(),
        kernel_spec.clone(),
        initramfs_spec.clone(),
    );
    RuntimeArtifactStore::create(engine).unwrap();
    let store = engine.path().join("runtime-artifacts");
    for (prefix, spec, bytes, mode) in [
        ("x", &cloud_hypervisor, elf.as_slice(), 0o500),
        ("r", &kernel_spec, kernel.as_slice(), 0o400),
        ("r", &initramfs_spec, initramfs.as_slice(), 0o400),
    ] {
        let path = store
            .join("blobs")
            .join(format!("{prefix}-{}", spec.sha256));
        if path.exists() {
            assert_eq!(fs::read(path).unwrap(), bytes);
        } else {
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    let generation = lock.generation().unwrap();
    let path = store.join("generations").join(format!("{generation}.json"));
    fs::write(&path, lock.canonical_json().unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    generation
}

pub(super) fn test_workspace_generation(
    project_spec_json: &[u8],
    project_sha256: &str,
    seed: &[u8],
) -> WorkspaceGenerationRecord {
    test_workspace_generation_with_artifact(
        project_spec_json,
        project_sha256,
        &"b".repeat(64),
        seed,
    )
}

pub(super) fn test_workspace_generation_with_artifact(
    project_spec_json: &[u8],
    project_sha256: &str,
    artifact_generation: &str,
    seed: &[u8],
) -> WorkspaceGenerationRecord {
    let project: codewire_project::ProjectSpec = serde_json::from_slice(project_spec_json).unwrap();
    let manifest = ResolvedDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
        digest: test_digest(&[seed, b"-manifest"].concat()),
        size: 128,
    };
    WorkspaceGenerationRecord::new(
        project_spec_json,
        project_sha256.to_owned(),
        artifact_generation.to_owned(),
        ResolvedImage {
            source_reference: project.image,
            architecture: OciArchitecture::native().unwrap(),
            source: manifest.clone(),
            manifest,
            config: ResolvedDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                digest: test_digest(&[seed, b"-config"].concat()),
                size: 128,
            },
            layers: Vec::new(),
        },
        crate::state::MINIMUM_ROOT_DISK_BYTES,
    )
    .unwrap()
}

struct RuntimeTransitionFixture {
    old_artifact: String,
    next_artifact: String,
    old_workspace: WorkspaceGenerationRecord,
    next_workspace: WorkspaceGenerationRecord,
}

fn same_image_runtime_transition(environment: &EnvironmentRecord) -> RuntimeTransitionFixture {
    let project_json = environment.project_spec_json.as_deref().unwrap();
    let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
    let old_artifact = "b".repeat(64);
    let next_artifact = "c".repeat(64);
    let old_workspace = test_workspace_generation_with_artifact(
        project_json,
        project_sha256,
        &old_artifact,
        b"same-image",
    );
    let next_workspace = test_workspace_generation_with_artifact(
        project_json,
        project_sha256,
        &next_artifact,
        b"same-image",
    );
    assert_eq!(
        old_workspace.root_generation,
        next_workspace.root_generation
    );
    assert_ne!(
        workspace_storage_generation(&old_workspace).unwrap(),
        workspace_storage_generation(&next_workspace).unwrap()
    );
    RuntimeTransitionFixture {
        old_artifact,
        next_artifact,
        old_workspace,
        next_workspace,
    }
}

pub(super) fn project_environment() -> EnvironmentRecord {
    let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
    EnvironmentRecord {
        cw_runtime: None,
        id: Uuid::new_v4(),
        name: "dev".to_owned(),
        state: StoredEnvironmentState::Stopped,
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        generation: 1,
        host_ports: Vec::new(),
        mesh: None,
        workspace_plan: WorkspacePlan::local(&crate::workspace::WorkspaceSource {
            vm_only: Vec::new(),
            source_path: PathBuf::from("/workspace/source"),
            commit: "a".repeat(40),
            mode: WorkspaceSourceMode::Clone,
        })
        .unwrap(),
        project_spec_json: Some(project_spec_json),
        project_spec_sha256: Some(project_spec_sha256),
        access_profile: None,
        access_binding: None,
        platform_source_authority: None,
        runner: None,
        active_artifact_generation: Some("b".repeat(64)),
        staging_artifact_generation: None,
        active_workspace_generation: None,
        staging_workspace_generation: None,
        rollback_workspace_generation: None,
    }
}

#[cfg(target_os = "linux")]
fn direct_workspace_plan(source: &Path) -> WorkspacePlan {
    let admitted = crate::direct_share::admit_direct_share(source, &[]).unwrap();
    WorkspacePlan::from_inputs(vec![WorkspaceInput::direct(
        &admitted,
        "/workspace/fixtures",
        true,
        Vec::new(),
    )])
    .unwrap()
}

fn project_environment_with_secret_selection(
    secrets: codewire_project::SecretBindings,
    environment_values: BTreeMap<String, String>,
) -> EnvironmentRecord {
    let mut environment = project_environment();
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.secrets = secrets;
    project.environment = environment_values;
    if project.secrets.organization
        || project.secrets.user == Some(codewire_project::StoragePlacement::Platform)
        || project.secrets.project.starts_with("platform:")
    {
        environment.platform_source_authority = Some(
            sources::PlatformSourceAuthority::from_proto(&v1::PlatformSourceAuthority {
                anthropic_form: String::new(),
                server_url: "https://codewire.example".into(),
                organization_id: "synthetic-org".into(),
                user_id: "synthetic-user".into(),
                profile_slots: Vec::new(),
            })
            .unwrap(),
        );
    }
    let project_spec_json = project.canonical_json().unwrap();
    let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
    environment.project_spec_json = Some(project_spec_json.clone());
    environment.project_spec_sha256 = Some(project_spec_sha256.clone());
    environment.active_workspace_generation = Some(test_workspace_generation(
        &project_spec_json,
        &project_spec_sha256,
        b"workload-secret-selection",
    ));
    environment.validate("dev").unwrap();
    environment
}

async fn start_test_credential_authority(
    core: &Supervisor,
) -> (
    LocalCredentialClient,
    tokio::task::JoinHandle<Result<(), codewire_local_credentials::AuthorityRuntimeError>>,
) {
    let config = core.config.credential_authority_config();
    // The authority process prepares its socket directory before serving.
    assert_eq!(
        crate::socket_dir::prepare(&config.root).unwrap(),
        config.socket_dir
    );
    let server_config = config.clone();
    let server = tokio::spawn(async move {
        serve_local_credential_authority(
            server_config,
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match LocalCredentialClient::connect(&config).await {
            Ok(client) => return (client, server),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("test credential authority did not start: {error}"),
        }
    }
}

async fn bind_test_environment_access(
    core: &Supervisor,
    authority: &mut LocalCredentialClient,
) -> EnvironmentAccessBinding {
    let profile = authority
        .create_profile(
            &codewire_access::AccessProfileName::parse("work").unwrap(),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
    let binding = EnvironmentAccessBinding {
        environment_id: access_environment_id(core.environment("dev").unwrap().id).unwrap(),
        profile_id: profile.profile.id,
        profile_revision: profile.profile.revision,
    };
    authority
        .create_environment_access_binding(&binding)
        .await
        .unwrap();
    core.update_environment("dev", |environment| {
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(binding.clone());
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("local:id:{}", binding.profile_id),
        });
        let json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
        environment.project_spec_json = Some(json);
        environment.validate("dev").unwrap();
        Ok(())
    })
    .unwrap();
    binding
}

pub(super) fn project_environment_with_access() -> EnvironmentRecord {
    let mut environment = project_environment();
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.credentials = Some(codewire_project::CredentialBinding {
        profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
    });
    let project_spec_json = project.canonical_json().unwrap();
    environment.project_spec_sha256 = Some(format!(
        "{:x}",
        Sha256::digest(project_spec_json.as_slice())
    ));
    environment.project_spec_json = Some(project_spec_json);
    environment.access_profile = Some("user/work".parse().unwrap());
    environment.access_binding = Some(EnvironmentAccessBinding {
        environment_id: access_environment_id(environment.id).unwrap(),
        profile_id: AccessProfileId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        profile_revision: 7,
    });
    environment.validate("dev").unwrap();
    environment
}

/// A platform profile pins its selection as a local one does, but the
/// authority holds no local binding for it.
fn project_environment_with_platform_profile() -> EnvironmentRecord {
    let mut environment = project_environment_with_access();
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.credentials = Some(codewire_project::CredentialBinding {
        profile: "platform:id:11111111-1111-4111-8111-111111111111".into(),
    });
    let project_spec_json = project.canonical_json().unwrap();
    environment.project_spec_sha256 = Some(format!(
        "{:x}",
        Sha256::digest(project_spec_json.as_slice())
    ));
    environment.project_spec_json = Some(project_spec_json);
    environment.platform_source_authority = Some(
        sources::PlatformSourceAuthority::from_proto(&v1::PlatformSourceAuthority {
            anthropic_form: String::new(),
            server_url: "https://codewire.example".into(),
            organization_id: "synthetic-org".into(),
            user_id: "synthetic-user".into(),
            profile_slots: Vec::new(),
        })
        .unwrap(),
    );
    environment.validate("dev").unwrap();
    environment
}

fn workspace_update_payload(
    environment: &EnvironmentRecord,
    project_spec_json: &[u8],
    project_spec_sha256: &str,
    was_running: bool,
) -> serde_json::Value {
    let active = environment.active_workspace_generation.as_ref().unwrap();
    serde_json::json!({
        "name": environment.name,
        "project_spec_json": std::str::from_utf8(project_spec_json).unwrap(),
        "project_spec_sha256": project_spec_sha256,
        "prior_storage_generation": workspace_storage_generation(active).unwrap(),
        "target_generation": environment.generation + 1,
        "was_running": was_running,
    })
}

fn workspace_rollback_payload(
    environment: &EnvironmentRecord,
    was_running: bool,
) -> serde_json::Value {
    let active = environment.active_workspace_generation.as_ref().unwrap();
    let rollback = environment.rollback_workspace_generation.as_ref().unwrap();
    serde_json::json!({
        "name": environment.name,
        "prior_storage_generation": workspace_storage_generation(active).unwrap(),
        "rollback_storage_generation": workspace_storage_generation(rollback).unwrap(),
        "target_generation": environment.generation + 1,
        "was_running": was_running,
    })
}

fn test_workspace_transition_operation(
    environment: &EnvironmentRecord,
    kind: OperationKind,
    payload: serde_json::Value,
    checkpoint: u32,
) -> OperationRecord {
    OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        environment_id: Some(environment.id),
        kind,
        phase: if checkpoint == 0 {
            OperationPhase::Intent
        } else {
            OperationPhase::EffectApplied
        },
        checkpoint,
        payload,
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    }
}

pub(super) fn begin_and_advance_test_operation(
    store: &SupervisorStore,
    environment_id: Uuid,
    kind: OperationKind,
    payload: &serde_json::Value,
    checkpoint: u32,
) -> OperationRecord {
    assert!(usize::try_from(checkpoint).unwrap() <= crate::lifecycle::effects(kind).len());
    let mut operation = store
        .begin_operation(Uuid::new_v4(), Some(environment_id), kind, payload)
        .unwrap();
    for _ in 0..checkpoint {
        operation = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
    }
    operation
}

pub(super) fn test_supervisor_core(
    environment: EnvironmentRecord,
) -> (tempfile::TempDir, SupervisorCore) {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    root.ensure_dir(Path::new("engine"), 0o700).unwrap();
    prepare_runner_socket_dir(root.path()).unwrap();
    let lock = SupervisorLock::acquire(&root).unwrap();
    let (store, _) = SupervisorStore::open(&root).unwrap();
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some(environment.name.clone()),
        environments: [(environment.name.clone(), environment)].into(),
    };
    store.replace_state(&state).unwrap();
    let core = SupervisorCore {
        config: NativeRuntimeConfig {
            root: root_path,
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock.json"),
            mesh_data_dir: parent.path().join("mesh-auth"),
            platform_config_dir: parent.path().join("platform-auth"),
            credential_authority_root: parent.path().join("credentials"),
            executable: PathBuf::from("/usr/bin/true"),
        },
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images: retained_images::RetainedImages::default(),
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        admitted_here: HashMap::new(),
        selections: 0,
        retiring: false,
        operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
        log: None,
        network_policies: Arc::new(
            crate::network_policy_store::NetworkPolicyStore::in_memory().unwrap(),
        ),
        _lock: lock,
    };
    (parent, core)
}

/// Leave a dead owner-only endpoint at `socket`: bound, then closed.
fn stale_supervisor_endpoint(socket: &Path) -> SocketIdentity {
    drop(bound_unlistened_socket(socket));
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
    SocketIdentity::capture(socket).unwrap()
}

/// A Unix stream socket bound at `socket` that never listens, as a dead
/// supervisor's endpoint is. A closed listener is not dead: a child that
/// another test thread forks while it is open holds it until that child
/// execs, and it accepts connections meanwhile (CI run 12471).
fn bound_unlistened_socket(socket: &Path) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: plain socket creation; the descriptor is owned at once.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    assert!(descriptor >= 0, "{}", io::Error::last_os_error());
    // SAFETY: the descriptor was just created and is owned only here.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: setting the close-on-exec flag of an owned descriptor.
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    // SAFETY: an all-zero sockaddr_un is a valid empty address.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = socket.as_os_str().as_bytes();
    assert!(path.len() < address.sun_path.len());
    for (slot, byte) in address.sun_path.iter_mut().zip(path) {
        *slot = *byte as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = u8::try_from(length).unwrap();
    }
    // SAFETY: the address is a live, correctly sized local.
    let bound = unsafe {
        libc::bind(
            descriptor,
            (&raw const address).cast(),
            libc::socklen_t::try_from(length).unwrap(),
        )
    };
    assert_eq!(bound, 0, "{}", io::Error::last_os_error());
    owned
}

/// Other tests in this binary fork children from their own threads. A
/// stale endpoint must still refuse while one of those children holds its
/// inherited descriptor.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_stale_endpoint_refuses_while_a_forked_child_holds_it() {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;

    let (_parent, core) = test_supervisor_core(project_environment());
    let mut config = core.config.clone();
    config.executable = std::env::current_exe().unwrap();
    drop(core);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = config.supervisor_socket();
    let endpoint = bound_unlistened_socket(&socket);
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();

    // Another thread forks a child that inherits `endpoint` and holds it
    // until it execs, half a second after it reports that it exists.
    let mut forked = [0; 2];
    // SAFETY: `forked` has room for the two descriptors.
    assert_eq!(
        unsafe { libc::pipe2(forked.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe(2) returned two new descriptors owned only here.
    let (ready, report) = unsafe {
        (
            std::fs::File::from_raw_fd(forked[0]),
            std::os::fd::OwnedFd::from_raw_fd(forked[1]),
        )
    };
    let report_fd = report.as_raw_fd();
    let endpoint_fd = endpoint.as_raw_fd();
    let forking = std::thread::spawn(move || {
        let mut command = std::process::Command::new("/usr/bin/true");
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                // Keep only the endpoint and the report pipe through the
                // wait, so this child holds no other test's descriptors.
                let low = endpoint_fd.min(report_fd) as u32;
                let high = endpoint_fd.max(report_fd) as u32;
                for (first, end) in [(3, low), (low + 1, high), (high + 1, u32::MAX)] {
                    if first < end && libc::syscall(libc::SYS_close_range, first, end - 1, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if libc::write(report_fd, b"f".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                libc::usleep(500_000);
                Ok(())
            });
        }
        let status = command.status().unwrap();
        drop(report);
        status
    });
    let mut byte = [0_u8; 1];
    io::Read::read_exact(&mut &ready, &mut byte).unwrap();
    drop(endpoint);

    let error = NativeSupervisorClient::connect_for_config(&socket, &config)
        .await
        .err()
        .expect("a stale endpoint refuses connections");
    assert!(error.refused_connection(), "{error:?}");
    assert!(forking.join().unwrap().success());
}

#[tokio::test]
async fn refused_endpoint_is_replaced_only_by_the_lock_holder() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let mut config = core.config.clone();
    config.executable = std::env::current_exe().unwrap();
    // Keep the core's lock rather than releasing and taking it again: a
    // child another test thread forks meanwhile would hold the released
    // lock until it execs.
    let SupervisorCore { _lock: held, .. } = core;
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = config.supervisor_socket();
    let stale = stale_supervisor_endpoint(&socket);
    let error = NativeSupervisorClient::connect_for_config(&socket, &config)
        .await
        .err()
        .expect("a closed endpoint refuses connections");
    assert!(error.refused_connection(), "{error:?}");

    // A live owner keeps the lock for its whole life. A second supervisor
    // then fails before it binds, and the endpoint stays exactly as it is.
    let error = refused_startup(&config).await;
    assert!(
        matches!(error, SupervisorError::AlreadyRunning),
        "{error:?}"
    );
    assert_eq!(SocketIdentity::capture(&socket).unwrap(), stale);

    // Once no owner holds the lock, the new supervisor replaces it. Until
    // a child another test thread forked has execed, it may still hold
    // the released lock, so a supervisor that meets it is started again.
    // Each attempt waits on the supervisor's own state, serving the
    // replaced endpoint or exiting, not on a clock: under load, startup
    // and such a child's exec can each take seconds (#3207).
    drop(held);
    let (replaced, mut supervisor) = tokio::time::timeout(HANG_GUARD, async {
        loop {
            let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
            let served = loop {
                if supervisor.is_finished() {
                    break None;
                }
                if let Ok(identity) = SocketIdentity::capture(&socket)
                    && identity != stale
                    && NativeSupervisorClient::connect(&socket).await.is_ok()
                {
                    break Some(identity);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            if let Some(identity) = served {
                break (identity, supervisor);
            }
            let finished = (&mut supervisor).await.unwrap();
            assert!(
                matches!(finished, Err(SupervisorError::AlreadyRunning)),
                "{finished:?}"
            );
            // A supervisor that lost the lock never touches the endpoint.
            assert_eq!(SocketIdentity::capture(&socket).unwrap(), stale);
        }
    })
    .await
    .expect("hang guard: the lock holder never replaced the refused endpoint");
    assert_ne!(replaced, stale);
    assert!(!supervisor.is_finished());
    supervisor.abort();
    assert!((&mut supervisor).await.unwrap_err().is_cancelled());
}

/// A bound on a wait whose progress is observed state, so a failure means
/// a hang rather than a slow host.
const HANG_GUARD: Duration = Duration::from_secs(120);

#[tokio::test]
async fn client_leaves_a_refused_endpoint_whose_lock_is_held() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let mut config = core.config.clone();
    // The started process exits at once, as a supervisor that cannot take
    // the lock does; the client itself never unlinks the endpoint.
    config.executable = PathBuf::from("/usr/bin/false");
    // Keep the core's lock rather than releasing and taking it again.
    let SupervisorCore { _lock: _held, .. } = core;
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = config.supervisor_socket();
    let stale = stale_supervisor_endpoint(&socket);
    let error = NativeSupervisorClient::connect_or_start(&config)
        .await
        .err()
        .expect("no supervisor can take over a held lock");
    assert!(
        matches!(&error, SupervisorError::EndpointNotReplaced(path) if *path == socket),
        "{error:?}"
    );
    assert_eq!(SocketIdentity::capture(&socket).unwrap(), stale);
}

pub(super) fn test_supervisor(core: SupervisorCore) -> Arc<Supervisor> {
    Supervisor::new(core, watch::channel(false).0)
}

pub(super) fn test_supervisor_service(core: SupervisorCore) -> SupervisorRpc {
    let operation_reader = SupervisorOperationReader::open(&core.root).unwrap();
    let operation_events = core.store.operation_events();
    let operation_progress = core.operation_progress.clone();
    let info = supervisor_info(&core.config);
    let host_keys = Arc::new(ssh::HostKeys::new(&core.config.root));
    let network_policies = Arc::clone(&core.network_policies);
    SupervisorRpc {
        info,
        supervisor: test_supervisor(core),
        operation_reader: Arc::new(Mutex::new(operation_reader)),
        operation_events,
        operation_progress,
        host_keys,
        ssh_streams: Arc::default(),
        network_policies,
        hold_drains: Arc::default(),
    }
}

pub(super) fn spawn_test_supervisor_server(
    socket: &Path,
    service: SupervisorRpc,
) -> (
    SocketIdentity,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (listener, socket_identity) = bind_owner_only_listener(socket).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, public_api::supervisor_router(service))
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    (socket_identity, shutdown_tx, server)
}

#[derive(Clone, Copy)]
pub(super) enum TestRunnerProtocolReply {
    Version(u32),
    Failure(tonic::Code),
}

#[derive(Clone)]
struct TestRunnerProtocolService {
    reply: TestRunnerProtocolReply,
    useful_calls: Arc<AtomicUsize>,
    shutdown_effect: Option<Arc<std::sync::Mutex<Option<std::process::ChildStdin>>>>,
    info_gate: Option<RunnerInfoGate>,
}

/// Holds a runner's `get_runner_info` once it is entered, until released,
/// as a runner that will not answer holds the operation calling it.
#[derive(Clone, Default)]
pub(super) struct RunnerInfoGate {
    pub(super) entered: Arc<tokio::sync::Notify>,
    pub(super) release: Arc<tokio::sync::Notify>,
}

impl TestRunnerProtocolService {
    fn unexpected_use<T>(&self) -> Result<Response<T>, Status> {
        self.useful_calls.fetch_add(1, Ordering::Relaxed);
        Err(Status::unimplemented("test runner RPC is not implemented"))
    }
}

#[tonic::async_trait]
impl crate::control::v1::environment_runner_service_server::EnvironmentRunnerService
    for TestRunnerProtocolService
{
    async fn get_runner_protocol_info(
        &self,
        _request: Request<v1::GetRunnerProtocolInfoRequest>,
    ) -> Result<Response<v1::RunnerProtocolInfo>, Status> {
        match self.reply {
            TestRunnerProtocolReply::Version(protocol_version) => {
                Ok(Response::new(v1::RunnerProtocolInfo { protocol_version }))
            }
            TestRunnerProtocolReply::Failure(code) => {
                Err(Status::new(code, "untrusted test peer detail"))
            }
        }
    }

    async fn adopt_runner(
        &self,
        _request: Request<v1::AdoptRunnerRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        self.unexpected_use()
    }

    async fn get_runner_info(
        &self,
        _request: Request<v1::GetRunnerInfoRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        if let Some(gate) = &self.info_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.unexpected_use()
    }

    type WatchRunnerStream =
        Pin<Box<dyn Stream<Item = Result<v1::RunnerEvent, Status>> + Send + 'static>>;

    async fn watch_runner(
        &self,
        _request: Request<v1::WatchRunnerRequest>,
    ) -> Result<Response<Self::WatchRunnerStream>, Status> {
        self.unexpected_use()
    }

    async fn start_vm(
        &self,
        _request: Request<v1::StartVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        self.unexpected_use()
    }

    async fn stop_vm(
        &self,
        _request: Request<v1::StopVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        self.unexpected_use()
    }

    async fn grow_state_disk(
        &self,
        _request: Request<v1::GrowStateDiskRequest>,
    ) -> Result<Response<v1::GrowStateDiskResponse>, Status> {
        self.unexpected_use()
    }

    async fn set_host_ports(
        &self,
        _request: Request<v1::SetHostPortsRequest>,
    ) -> Result<Response<v1::SetHostPortsResponse>, Status> {
        self.unexpected_use()
    }

    async fn replace_network_policy(
        &self,
        _request: Request<v1::ReplaceNetworkPolicyRequest>,
    ) -> Result<Response<v1::ReplaceNetworkPolicyResponse>, Status> {
        self.unexpected_use()
    }

    async fn prepare_retire_runner(
        &self,
        _request: Request<v1::PrepareRetireRunnerRequest>,
    ) -> Result<Response<v1::PrepareRetireRunnerResponse>, Status> {
        self.unexpected_use()
    }

    async fn shutdown_runner(
        &self,
        _request: Request<v1::ShutdownRunnerRequest>,
    ) -> Result<Response<v1::ShutdownRunnerResponse>, Status> {
        if let Some(effect) = &self.shutdown_effect {
            if let Some(mut input) = effect.lock().unwrap().take() {
                std::io::Write::write_all(&mut input, b"retire\n").unwrap();
            }
            return Err(Status::unavailable(
                "synthetic response lost after shutdown effect",
            ));
        }
        self.unexpected_use()
    }

    async fn get_daemon_access(
        &self,
        _request: Request<v1::GetDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        self.unexpected_use()
    }

    async fn get_generation_daemon_access(
        &self,
        _request: Request<v1::GetGenerationDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        self.unexpected_use()
    }

    async fn checkpoint_vm(
        &self,
        _request: Request<v1::CheckpointVmRequest>,
    ) -> Result<Response<v1::CheckpointVmResponse>, Status> {
        self.unexpected_use()
    }
}

fn spawn_test_runner_protocol_server(
    socket: &Path,
    reply: TestRunnerProtocolReply,
) -> (
    SocketIdentity,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    spawn_gated_test_runner_server(socket, reply, None)
}

/// A test runner whose `get_runner_info` waits at `info_gate`, if any.
pub(super) fn spawn_gated_test_runner_server(
    socket: &Path,
    reply: TestRunnerProtocolReply,
    info_gate: Option<RunnerInfoGate>,
) -> (
    SocketIdentity,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (incoming, socket_identity) = bind_owner_only(socket).unwrap();
    let useful_calls = Arc::new(AtomicUsize::new(0));
    let service = TestRunnerProtocolService {
        reply,
        useful_calls: Arc::clone(&useful_calls),
        shutdown_effect: None,
        info_gate,
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
                .add_service(
                    crate::control::v1::environment_runner_service_server::EnvironmentRunnerServiceServer::new(
                        service,
                    ),
                )
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
    });
    (socket_identity, useful_calls, shutdown_tx, server)
}

fn attach_test_runner_process(
    core: &mut SupervisorCore,
    socket_identity: SocketIdentity,
) -> (Uuid, ProcessIdentity) {
    attach_named_test_runner_process(core, "dev", socket_identity)
}

fn running_executable(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        ProcessIdentity::capture(pid)
            .ok()
            .map(|identity| identity.executable)
    }
}

// These two shutdown fixtures retain the unreaped Child before any readiness
// assertion, including the single strict LiveProcess capture.
struct ShutdownTestChild(Child);

impl ShutdownTestChild {
    fn capture(&mut self, executable: &Path) -> LiveProcess {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            assert!(
                self.0.try_wait().unwrap().is_none(),
                "shutdown test child exited before its expected executable"
            );
            if running_executable(self.0.id()).as_deref() == Some(executable) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown test child did not reach its expected executable"
            );
            std::thread::yield_now();
        }
        LiveProcess::capture_child(self.0.id(), executable).unwrap()
    }
}

impl Drop for ShutdownTestChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                eprintln!("shutdown test child cleanup status unknown: {error}");
                return;
            }
        }
        // Only failure cleanup can reach this point: both positive fixture
        // paths already require their original Child to have been reaped.
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        if let Err(error) = self.0.kill() {
            eprintln!("shutdown test child cleanup kill failed: {error}");
        }
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(None) => {
                    eprintln!("shutdown test child cleanup did not finish within one second");
                    return;
                }
                Err(error) => {
                    eprintln!("shutdown test child cleanup status unknown: {error}");
                    return;
                }
            }
        }
    }
}

#[tokio::test]
async fn unacknowledged_runner_shutdown_still_observes_natural_exit() {
    use crate::control::v1::environment_runner_service_server::EnvironmentRunnerServiceServer;
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = parent.path().join("shutdown.sock");
    // Darwin's /bin/sh re-executes the selected shell, so its image would
    // change under the capture; start that real shell directly.
    #[cfg(target_os = "macos")]
    let executable = fs::canonicalize("/bin/bash").unwrap();
    #[cfg(target_os = "linux")]
    let executable = fs::canonicalize("/bin/sh").unwrap();
    let mut child = ShutdownTestChild(
        crate::test_child(&mut Command::new(&executable))
            .args([
                "-c",
                "read -r retirement_command; test \"$retirement_command\" = retire",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let live = child.capture(&executable);
    let service = TestRunnerProtocolService {
        reply: TestRunnerProtocolReply::Version(
            crate::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION,
        ),
        useful_calls: Arc::new(AtomicUsize::new(0)),
        shutdown_effect: Some(Arc::new(std::sync::Mutex::new(child.0.stdin.take()))),
        info_gate: None,
    };
    let (incoming, identity) = bind_owner_only(&socket).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EnvironmentRunnerServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let mut client = RunnerClient::connect(&socket).await.unwrap();
    // The mock performs the actual child shutdown effect, then returns an
    // unavailable response. The supervisor must still observe normal exit,
    // with the Child retained here rather than moved into a detached wait.
    assert!(
        request_runner_shutdown_and_observe(&mut client, Uuid::new_v4(), 1, &live)
            .await
            .unwrap()
    );
    assert!(child.0.try_wait().unwrap().unwrap().success());
    assert!(live.is_exited().unwrap());
    drop(client);
    stop.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &identity).unwrap();
}

#[tokio::test]
async fn unresponsive_runner_retains_child_and_exact_pidfd_for_fallback() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = parent.path().join("unresponsive.sock");
    let (identity, calls, stop, server) = spawn_test_runner_protocol_server(
        &socket,
        TestRunnerProtocolReply::Version(crate::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION),
    );
    let executable = fs::canonicalize("/bin/sleep").unwrap();
    let mut child = ShutdownTestChild(
        crate::test_child(&mut Command::new(&executable))
            .arg("60")
            .spawn()
            .unwrap(),
    );
    let live = child.capture(&executable);
    let mut client = RunnerClient::connect(&socket).await.unwrap();
    assert!(
        !request_runner_shutdown_and_observe(&mut client, Uuid::new_v4(), 1, &live)
            .await
            .unwrap()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(child.0.try_wait().unwrap().is_none());
    live.signal(Signal::KILL).unwrap();
    assert!(!child.0.wait().unwrap().success());
    assert!(live.is_exited().unwrap());
    drop(client);
    stop.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &identity).unwrap();
}

pub(super) fn attach_named_test_runner_process(
    core: &mut SupervisorCore,
    name: &str,
    socket_identity: SocketIdentity,
) -> (Uuid, ProcessIdentity) {
    attach_test_runner_process_running(
        core,
        name,
        socket_identity,
        &fs::canonicalize("/bin/sleep").unwrap(),
    )
}

/// A recorded running runner that runs `executable`.
fn attach_test_runner_process_running(
    core: &mut SupervisorCore,
    name: &str,
    socket_identity: SocketIdentity,
    executable: &Path,
) -> (Uuid, ProcessIdentity) {
    let executable = executable.to_path_buf();
    let child = crate::test_child(&mut Command::new(&executable))
        .arg("60")
        .spawn()
        .unwrap();
    // The core owns the Child, and a test drops the core without killing
    // it; the test process ends it at exit instead (#3813).
    crate::reap_at_exit(child.id());
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while running_executable(child.id()).as_deref() != Some(executable.as_path()) {
        assert!(
            std::time::Instant::now() < deadline,
            "test runner child did not reach its expected executable"
        );
        std::thread::yield_now();
    }
    let environment_id = core.environment(name).unwrap().id;
    let live = LiveProcess::capture_child(child.id(), &executable).unwrap();
    let process_identity = live.identity().clone();
    let runner = RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: process_identity.clone(),
        socket: socket_identity,
        artifact_generation: core
            .environment(name)
            .unwrap()
            .active_artifact_generation
            .clone()
            .unwrap(),
        error_code: None,
    };
    let environment = core.environment_mut(name).unwrap();
    environment.state = StoredEnvironmentState::Running;
    environment.runner = Some(runner);
    core.save().unwrap();
    core.live_runners.insert(environment_id, Arc::new(live));
    core.children.insert(environment_id, child);
    (environment_id, process_identity)
}

fn test_supervisor_core_after_host_reboot(
    environment: EnvironmentRecord,
    kind: OperationKind,
    payload: &serde_json::Value,
    checkpoint: u32,
) -> (tempfile::TempDir, SupervisorCore) {
    assert!(checkpoint > 0);
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    root.ensure_dir(Path::new("engine"), 0o700).unwrap();
    prepare_runner_socket_dir(root.path()).unwrap();
    let (store, _) = SupervisorStore::open_for_boot(&root, "boot-before").unwrap();
    let environment_id = environment.id;
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some(environment.name.clone()),
        environments: [(environment.name.clone(), environment)].into(),
    };
    store.replace_state(&state).unwrap();
    begin_and_advance_test_operation(&store, environment_id, kind, payload, checkpoint);
    drop(store);

    let (store, _) = SupervisorStore::open_for_boot(&root, "boot-after").unwrap();
    assert_eq!(
        store
            .host_reboot_interrupted_workspace_transitions()
            .unwrap()
            .len(),
        1
    );
    drop(store);
    let (store, state) = SupervisorStore::open_for_boot(&root, "boot-after-again").unwrap();
    assert_eq!(
        store
            .host_reboot_interrupted_workspace_transitions()
            .unwrap()
            .len(),
        1
    );
    let lock = SupervisorLock::acquire(&root).unwrap();
    let core = SupervisorCore {
        config: NativeRuntimeConfig {
            root: root_path,
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock.json"),
            mesh_data_dir: parent.path().join("mesh-auth"),
            platform_config_dir: parent.path().join("platform-auth"),
            credential_authority_root: parent.path().join("credentials"),
            executable: PathBuf::from("/usr/bin/true"),
        },
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images: retained_images::RetainedImages::default(),
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        admitted_here: HashMap::new(),
        selections: 0,
        retiring: false,
        operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
        log: None,
        network_policies: Arc::new(
            crate::network_policy_store::NetworkPolicyStore::in_memory().unwrap(),
        ),
        _lock: lock,
    };
    (parent, core)
}

#[test]
fn readiness_promotion_rotates_only_durable_workspace_generations() {
    let mut environment = project_environment();
    let project_spec_json = environment.project_spec_json.as_deref().unwrap();
    let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
    let active = test_workspace_generation(project_spec_json, project_sha256, b"active");
    let staging = test_workspace_generation(project_spec_json, project_sha256, b"staging");
    let old_rollback =
        test_workspace_generation(project_spec_json, project_sha256, b"old-rollback");
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.rollback_workspace_generation = Some(old_rollback.clone());
    environment.validate("dev").unwrap();

    let displaced = environment.promote_staging_workspace_generation().unwrap();

    assert_eq!(environment.active_workspace_generation, Some(staging));
    assert_eq!(environment.rollback_workspace_generation, Some(active));
    assert_eq!(displaced, Some(old_rollback));
    assert!(environment.staging_workspace_generation.is_none());
    environment.validate("dev").unwrap();
}

#[test]
fn artifact_transition_and_rollback_keep_distinct_exact_storage_generations() {
    let mut environment = project_environment();
    let RuntimeTransitionFixture {
        old_artifact,
        next_artifact,
        old_workspace: active,
        next_workspace: staging,
    } = same_image_runtime_transition(&environment);
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.staging_artifact_generation = Some(next_artifact.clone());
    environment.validate("dev").unwrap();

    assert!(
        environment
            .promote_staging_workspace_generation()
            .unwrap()
            .is_none()
    );

    assert_eq!(environment.active_artifact_generation, Some(next_artifact));
    assert_eq!(
        environment.active_workspace_generation,
        Some(staging.clone())
    );
    assert_eq!(
        environment.rollback_workspace_generation,
        Some(active.clone())
    );
    assert_eq!(
        referenced_root_storage_generations(&environment)
            .unwrap()
            .len(),
        2
    );

    let active_storage =
        workspace_storage_generation(environment.active_workspace_generation.as_ref().unwrap())
            .unwrap();
    let rollback_storage =
        workspace_storage_generation(environment.rollback_workspace_generation.as_ref().unwrap())
            .unwrap();
    environment
        .stage_rollback_workspace_generation(&active_storage, &rollback_storage)
        .unwrap();
    assert_eq!(
        environment.staging_artifact_generation,
        Some(old_artifact.clone())
    );
    let _displaced = environment.promote_staging_workspace_generation().unwrap();

    assert_eq!(environment.active_artifact_generation, Some(old_artifact));
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert_eq!(environment.rollback_workspace_generation, Some(staging));
    environment.validate("dev").unwrap();
}

#[tokio::test]
async fn replayed_runtime_only_update_promotes_the_exact_staging_artifact() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let RuntimeTransitionFixture {
        old_artifact: _,
        next_artifact,
        old_workspace: active,
        next_workspace: staging,
    } = same_image_runtime_transition(&environment);
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.staging_artifact_generation = Some(next_artifact.clone());
    environment.validate("dev").unwrap();
    let payload = workspace_update_payload(&environment, &project_json, &project_sha256, false);
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            payload.clone(),
            1,
        ),
        &environment,
    )
    .unwrap();
    assert!(workspace_transition_requires_boot(&environment, &parameters).unwrap());
    reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = begin_and_advance_test_operation(
        &core.core().store,
        environment_id,
        OperationKind::UpdateWorkspace,
        &payload,
        7,
    );
    let request_id = operation.request_id;

    core.drain_pending(true).await.unwrap();

    let operation = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(operation.phase, OperationPhase::Completed);
    assert_eq!(operation.checkpoint, 10);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert_eq!(environment.generation, 2);
    assert_eq!(environment.active_artifact_generation, Some(next_artifact));
    assert!(environment.staging_artifact_generation.is_none());
    assert_eq!(environment.active_workspace_generation, Some(staging));
    assert_eq!(environment.rollback_workspace_generation, Some(active));
    environment.validate("dev").unwrap();
}

#[test]
fn workspace_update_journal_distinguishes_explicit_skill_refresh() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    environment.active_workspace_generation = Some(test_workspace_generation(
        &project_json,
        &project_sha256,
        b"active",
    ));
    let mut payload = workspace_update_payload(&environment, &project_json, &project_sha256, false);
    payload
        .as_object_mut()
        .unwrap()
        .insert("refresh_skills".to_owned(), true.into());
    let operation = test_workspace_transition_operation(
        &environment,
        OperationKind::UpdateWorkspace,
        payload,
        0,
    );
    assert!(
        workspace_transition_parameters(&operation, &environment)
            .unwrap()
            .refresh_skills
    );
}

#[tokio::test]
async fn replayed_runtime_only_rollback_restores_the_exact_prior_artifact() {
    let mut environment = project_environment();
    let RuntimeTransitionFixture {
        old_artifact: prior_artifact,
        next_artifact: current_artifact,
        old_workspace: rollback,
        next_workspace: active,
    } = same_image_runtime_transition(&environment);
    environment.state = StoredEnvironmentState::Running;
    environment.active_artifact_generation = Some(current_artifact.clone());
    environment.active_workspace_generation = Some(active.clone());
    environment.rollback_workspace_generation = Some(rollback.clone());
    environment.validate("dev").unwrap();
    let payload = workspace_rollback_payload(&environment, true);
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::RollbackWorkspace,
            payload.clone(),
            0,
        ),
        &environment,
    )
    .unwrap();
    let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    else {
        unreachable!()
    };
    environment
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            rollback_storage_generation,
        )
        .unwrap();
    assert_eq!(
        environment.staging_artifact_generation,
        Some(prior_artifact.clone())
    );
    environment.validate("dev").unwrap();
    reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = begin_and_advance_test_operation(
        &core.core().store,
        environment_id,
        OperationKind::RollbackWorkspace,
        &payload,
        7,
    );
    let request_id = operation.request_id;

    core.drain_pending(true).await.unwrap();

    let operation = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(operation.phase, OperationPhase::Completed);
    assert_eq!(operation.checkpoint, 10);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert_eq!(environment.generation, 2);
    assert_eq!(environment.active_artifact_generation, Some(prior_artifact));
    assert!(environment.staging_artifact_generation.is_none());
    assert_eq!(environment.active_workspace_generation, Some(rollback));
    assert_eq!(environment.rollback_workspace_generation, Some(active));
    environment.validate("dev").unwrap();
}

#[test]
fn rollback_journal_rejects_a_different_artifact_with_the_same_oci_root() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"b".repeat(64),
        b"same-image",
    );
    let rollback = test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"c".repeat(64),
        b"same-image",
    );
    environment.active_workspace_generation = Some(active);
    environment.rollback_workspace_generation = Some(rollback);
    environment.validate("dev").unwrap();
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        environment_id: Some(environment.id),
        kind: OperationKind::RollbackWorkspace,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: workspace_rollback_payload(&environment, false),
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };
    let parameters = workspace_transition_parameters(&operation, &environment).unwrap();

    environment.rollback_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"d".repeat(64),
        b"same-image",
    ));
    environment.validate("dev").unwrap();

    assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
}

fn set_test_current_project(
    environment: &mut EnvironmentRecord,
    project: &codewire_project::ProjectSpec,
) {
    let bytes = project.canonical_json().unwrap();
    environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
    environment.project_spec_json = Some(bytes);
}

fn test_selectors() -> (
    codewire_project::SecretBindings,
    Option<codewire_project::CredentialBinding>,
) {
    (
        codewire_project::SecretBindings {
            project: "local:id:11111111-1111-4111-8111-111111111111".to_owned(),
            user: Some(codewire_project::StoragePlacement::Local),
            organization: false,
        },
        Some(codewire_project::CredentialBinding {
            profile: "local:id:22222222-2222-4222-8222-222222222222".to_owned(),
        }),
    )
}

fn workspace_with_test_skills(environment: &mut EnvironmentRecord) -> WorkspaceGenerationRecord {
    let baseline = test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"installed-skills",
    );
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.install_command = "printf installed".to_owned();
    project.agents.tools = vec!["codex".to_owned()];
    project.skills = vec![codewire_project::SkillSelection {
        source: codewire_project::SkillSource::User,
        reference: "rust".to_owned(),
        agents: vec!["codex".to_owned()],
    }];
    set_test_current_project(environment, &project);
    let skill = codewire_vmm_guest_probe::SkillSnapshot::new(
        codewire_vmm_guest_probe::SkillSnapshotSource::User,
        "user:rust".to_owned(),
        "rust".to_owned(),
        "c".repeat(64),
        "rust",
        &["codex".to_owned()],
    )
    .unwrap();
    let plan = codewire_vmm_guest_probe::SkillSnapshotPlan::new(
        environment.project_spec_sha256.clone().unwrap(),
        3,
        vec![skill],
    )
    .unwrap();
    WorkspaceGenerationRecord::new_with_skill_snapshot(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.clone().unwrap(),
        baseline.artifact_generation,
        baseline.image,
        baseline.root_disk_bytes,
        Some(plan),
    )
    .unwrap()
}

#[test]
fn workspace_update_and_rollback_preserve_current_sources_without_mutating_built_records() {
    let mut environment = project_environment();
    let mut historical: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    historical.secrets.project = "local:id:33333333-3333-4333-8333-333333333333".to_owned();
    historical.credentials = Some(codewire_project::CredentialBinding {
        profile: "local:id:44444444-4444-4444-8444-444444444444".to_owned(),
    });
    set_test_current_project(&mut environment, &historical);
    let active = test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"active",
    );
    let active_bytes = active.encode_canonical().unwrap();
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    (current.secrets, current.credentials) = test_selectors();
    set_test_current_project(&mut environment, &current);
    environment.active_workspace_generation = Some(active.clone());
    environment.access_profile = Some("user/current".parse().unwrap());
    environment.access_binding = Some(EnvironmentAccessBinding {
        environment_id: access_environment_id(environment.id).unwrap(),
        profile_id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        profile_revision: 7,
    });
    let selected_profile = environment.access_profile.clone();
    let selected_binding = environment.access_binding.clone();
    let mut target = current.clone();
    target.install_command = "printf newer-install".to_owned();
    let target_json = target.canonical_json().unwrap();
    let target_sha256 = format!("{:x}", Sha256::digest(&target_json));
    let staging = test_workspace_generation(&target_json, &target_sha256, b"staging");
    let staging_bytes = staging.encode_canonical().unwrap();
    environment.staging_workspace_generation = Some(staging.clone());
    environment.promote_staging_workspace_generation().unwrap();
    let after: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    assert_eq!(after, target);
    assert_eq!(environment.access_profile, selected_profile);
    assert_eq!(environment.access_binding, selected_binding);
    assert_eq!(
        environment
            .active_workspace_generation
            .as_ref()
            .unwrap()
            .encode_canonical()
            .unwrap(),
        staging_bytes
    );
    assert_eq!(
        environment
            .rollback_workspace_generation
            .as_ref()
            .unwrap()
            .encode_canonical()
            .unwrap(),
        active_bytes
    );

    // A later source-CAS clears both selectors. Rolling back the root may
    // restore old install intent, but cannot restore either old selector.
    current = target;
    current.secrets = Default::default();
    current.credentials = None;
    set_test_current_project(&mut environment, &current);
    environment.access_profile = None;
    environment.access_binding = None;
    environment
        .stage_rollback_workspace_generation(
            &workspace_storage_generation(&staging).unwrap(),
            &workspace_storage_generation(&active).unwrap(),
        )
        .unwrap();
    environment.promote_staging_workspace_generation().unwrap();
    let after: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    assert!(after.install_command.is_empty());
    assert!(after.secrets.is_empty());
    assert!(after.credentials.is_none());
    assert!(environment.access_profile.is_none());
    assert!(environment.access_binding.is_none());
    assert_eq!(
        environment
            .active_workspace_generation
            .as_ref()
            .unwrap()
            .encode_canonical()
            .unwrap(),
        active_bytes
    );
    assert_eq!(
        environment
            .rollback_workspace_generation
            .as_ref()
            .unwrap()
            .encode_canonical()
            .unwrap(),
        staging_bytes
    );
    active
        .validate_for_project_intent(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
        )
        .unwrap();
}

#[test]
fn workspace_no_boot_completion_retains_source_only_current_intent() {
    let mut environment = project_environment();
    let built = test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"same-root",
    );
    let built_bytes = built.encode_canonical().unwrap();
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    (current.secrets, current.credentials) = test_selectors();
    set_test_current_project(&mut environment, &current);
    let current_json = environment.project_spec_json.clone();
    let current_sha256 = environment.project_spec_sha256.clone();
    environment.active_workspace_generation = Some(built.clone());
    environment.staging_workspace_generation = Some(built);
    environment
        .finish_staging_workspace_update_without_boot()
        .unwrap();
    assert_eq!(environment.project_spec_json, current_json);
    assert_eq!(environment.project_spec_sha256, current_sha256);
    assert_eq!(
        environment
            .active_workspace_generation
            .as_ref()
            .unwrap()
            .encode_canonical()
            .unwrap(),
        built_bytes
    );
    assert!(environment.staging_workspace_generation.is_none());
}

#[test]
fn workspace_source_drift_requires_the_dedicated_source_cas() {
    let mut environment = project_environment();
    environment.active_workspace_generation = Some(test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"active",
    ));
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    (current.secrets, current.credentials) = test_selectors();
    set_test_current_project(&mut environment, &current);
    let changes: &[fn(&mut codewire_project::ProjectSpec)] = &[
        |project| project.secrets.user = None,
        |project| project.secrets.project.clear(),
        |project| project.secrets.organization = true,
        |project| project.credentials = None,
    ];
    for change in changes {
        let mut target = current.clone();
        change(&mut target);
        let target_json = target.canonical_json().unwrap();
        let target_sha256 = format!("{:x}", Sha256::digest(&target_json));
        let operation = test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            workspace_update_payload(&environment, &target_json, &target_sha256, false),
            0,
        );
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
        assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
    }
    let current_json = environment.project_spec_json.as_deref().unwrap();
    let current_sha256 = environment.project_spec_sha256.as_deref().unwrap();
    let operation = test_workspace_transition_operation(
        &environment,
        OperationKind::UpdateWorkspace,
        workspace_update_payload(&environment, current_json, current_sha256, false),
        0,
    );
    let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
    validate_workspace_transition_start(&environment, &parameters).unwrap();
}

#[test]
fn skill_refresh_allows_only_source_divergence_from_the_built_intent() {
    let mut environment = project_environment();
    let built = workspace_with_test_skills(&mut environment);
    let plan = built.skill_snapshot().unwrap().cloned();
    environment.active_workspace_generation = Some(built.clone());
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    (current.secrets, current.credentials) = test_selectors();
    set_test_current_project(&mut environment, &current);
    let mut payload = workspace_update_payload(
        &environment,
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        false,
    );
    payload
        .as_object_mut()
        .unwrap()
        .insert("refresh_skills".to_owned(), true.into());
    let operation = test_workspace_transition_operation(
        &environment,
        OperationKind::UpdateWorkspace,
        payload,
        0,
    );
    let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
    validate_workspace_transition_start(&environment, &parameters).unwrap();
    assert_eq!(
        environment
            .active_workspace_generation
            .as_ref()
            .unwrap()
            .skill_snapshot()
            .unwrap(),
        plan.as_ref()
    );
    let mut drift = current;
    drift.install_command = "printf unapproved-install-change".to_owned();
    let drift_json = drift.canonical_json().unwrap();
    let drift_sha256 = format!("{:x}", Sha256::digest(&drift_json));
    let mut payload = workspace_update_payload(&environment, &drift_json, &drift_sha256, false);
    payload
        .as_object_mut()
        .unwrap()
        .insert("refresh_skills".to_owned(), true.into());
    let operation = test_workspace_transition_operation(
        &environment,
        OperationKind::UpdateWorkspace,
        payload,
        0,
    );
    let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
    assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
}

#[tokio::test]
async fn skill_refresh_replay_uses_current_intent_after_a_source_only_change() {
    let mut environment = project_environment();
    let mut historical: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    historical.secrets.project = "local:id:11111111-1111-4111-8111-111111111111".to_owned();
    set_test_current_project(&mut environment, &historical);
    let built = workspace_with_test_skills(&mut environment);
    environment.active_workspace_generation = Some(built.clone());
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    current.secrets = Default::default();
    set_test_current_project(&mut environment, &current);
    let mut payload = workspace_update_payload(
        &environment,
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        false,
    );
    payload
        .as_object_mut()
        .unwrap()
        .insert("refresh_skills".to_owned(), true.into());
    assert_ne!(
        environment.project_spec_sha256.as_deref(),
        Some(built.project_sha256.as_str())
    );
    let environment_id = environment.id;
    let request_id = Uuid::new_v4();
    let (_parent, core) = test_supervisor_core(environment);
    // A terminal synthetic operation proves request/payload identity
    // without scheduling a runner, registry read or skill-material read.
    let operation = core
        .store
        .begin_operation(
            request_id,
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();
    let result = environment_operation_result(core.environment("dev").unwrap());
    core.store
        .advance_operation(
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Completed,
            Some(&result),
            None,
        )
        .unwrap();
    let service = test_supervisor_service(core);
    let response = service
        .refresh_environment_skills(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: request_id.to_string(),
            environment_id: environment_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.operation_id, operation.operation_id.to_string());
    assert_eq!(response.phase, v1::OperationPhase::Completed as i32);
    let core = &service.supervisor;
    assert_eq!(
        core.core()
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap()
            .payload,
        payload
    );
    assert_eq!(
        core.environment("dev").unwrap().active_workspace_generation,
        Some(built)
    );
    assert!(!core.config.credential_authority_root.exists());
}

#[test]
fn workspace_update_cannot_change_the_bound_access_profile() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    environment.active_workspace_generation = Some(test_workspace_generation(
        &project_json,
        &project_sha256,
        b"active",
    ));
    let mut next_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&project_json).unwrap();
    next_project.credentials = Some(codewire_project::CredentialBinding {
        profile: "local:id:22222222-2222-4222-8222-222222222222".to_owned(),
    });
    let next_project_json = next_project.canonical_json().unwrap();
    let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
    let payload = workspace_update_payload(
        &environment,
        &next_project_json,
        &next_project_sha256,
        false,
    );
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            payload,
            0,
        ),
        &environment,
    )
    .unwrap();

    assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
}

#[test]
fn workspace_update_enforces_exact_source_equality_before_staging() {
    let environment = project_environment_with_secret_selection(
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Platform),
            project: format!("local:id:{}", Uuid::new_v4()),
            ..Default::default()
        },
        BTreeMap::new(),
    );
    let original = environment.clone();
    let active_project_json = environment.project_spec_json.clone().unwrap();
    let active_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let mut target_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&active_project_json).unwrap();
    target_project.secrets.project = format!("local:id:{}", Uuid::new_v4());
    let target_project_json = target_project.canonical_json().unwrap();
    let target_project_sha256 = format!("{:x}", Sha256::digest(&target_project_json));
    let changed = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            workspace_update_payload(
                &environment,
                &target_project_json,
                &target_project_sha256,
                false,
            ),
            0,
        ),
        &environment,
    )
    .unwrap();
    reject_workspace_transition_workload_secrets(&environment, &changed).unwrap();
    assert!(matches!(
        validate_workspace_transition_start(&environment, &changed),
        Err(SupervisorError::InvalidState)
    ));

    let unchanged = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            workspace_update_payload(
                &environment,
                &active_project_json,
                &active_project_sha256,
                false,
            ),
            0,
        ),
        &environment,
    )
    .unwrap();
    reject_workspace_transition_workload_secrets(&environment, &unchanged).unwrap();
    validate_workspace_transition_start(&environment, &unchanged).unwrap();

    assert_eq!(environment, original);
    assert!(environment.staging_workspace_generation.is_none());
}

#[test]
fn workspace_rollback_uses_valid_current_mixed_sources_and_rejects_missing_authority() {
    let mut environment = project_environment();
    let original_project_json = environment.project_spec_json.clone().unwrap();
    let mut rollback_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&original_project_json).unwrap();
    rollback_project.secrets.user = Some(codewire_project::StoragePlacement::Local);
    let rollback_project_json = rollback_project.canonical_json().unwrap();
    let rollback_project_sha256 = format!("{:x}", Sha256::digest(&rollback_project_json));
    let rollback = test_workspace_generation(
        &rollback_project_json,
        &rollback_project_sha256,
        b"secret-rollback",
    );
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(&original_project_json).unwrap();
    current.secrets.user = Some(codewire_project::StoragePlacement::Platform);
    current.secrets.project = format!("local:id:{}", Uuid::new_v4());
    set_test_current_project(&mut environment, &current);
    let active_project_json = environment.project_spec_json.clone().unwrap();
    let active_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    environment.active_workspace_generation = Some(test_workspace_generation(
        &active_project_json,
        &active_project_sha256,
        b"active-before-secret-rollback",
    ));
    environment.rollback_workspace_generation = Some(rollback.clone());
    environment.platform_source_authority =
        project_environment_with_secret_selection(current.secrets.clone(), BTreeMap::new())
            .platform_source_authority;
    environment.validate("dev").unwrap();
    let payload = workspace_rollback_payload(&environment, false);
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::RollbackWorkspace,
            payload,
            0,
        ),
        &environment,
    )
    .unwrap();
    let original = environment.clone();
    reject_workspace_transition_workload_secrets(&environment, &parameters).unwrap();
    validate_workspace_transition_start(&environment, &parameters).unwrap();

    let mut staged = environment.clone();
    staged
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            match &parameters.intent {
                WorkspaceTransitionIntent::Rollback {
                    rollback_storage_generation,
                } => rollback_storage_generation,
                _ => unreachable!(),
            },
        )
        .unwrap();
    assert_eq!(staged.project_spec_json, original.project_spec_json);
    assert_eq!(staged.project_spec_sha256, original.project_spec_sha256);
    assert_eq!(staged.staging_workspace_generation, Some(rollback));
    assert!(staged.rollback_workspace_generation.is_none());
    let boot = sources::projection_environment_for_boot(&staged).unwrap();
    let boot_project: codewire_project::ProjectSpec =
        serde_json::from_slice(boot.project_spec_json.as_deref().unwrap()).unwrap();
    assert_eq!(boot_project.secrets, current.secrets);

    let mut missing_authority = original.clone();
    missing_authority.platform_source_authority = None;
    assert!(matches!(
        reject_workspace_transition_workload_secrets(&missing_authority, &parameters),
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
    assert_eq!(
        missing_authority.project_spec_json,
        original.project_spec_json
    );
    assert_eq!(
        missing_authority.rollback_workspace_generation,
        original.rollback_workspace_generation
    );
}

#[tokio::test]
async fn exact_noop_update_replays_without_reboot_or_rollback_rotation() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(&project_json, &project_sha256, b"active");
    let rollback = test_workspace_generation(&project_json, &project_sha256, b"rollback");
    environment.state = StoredEnvironmentState::Running;
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(active.clone());
    environment.rollback_workspace_generation = Some(rollback.clone());
    environment.staging_artifact_generation = Some("b".repeat(64));
    environment.validate("dev").unwrap();
    let environment_id = environment.id;
    let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();
    let mut operation = operation;
    for _ in 0..2 {
        operation = core
            .core()
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

    core.drain_pending(true).await.unwrap();

    let completed = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(completed.phase, OperationPhase::Completed);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert_eq!(environment.generation, 1);
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert!(environment.staging_workspace_generation.is_none());
    assert_eq!(environment.rollback_workspace_generation, Some(rollback));
    assert!(environment.staging_artifact_generation.is_none());
    environment.validate("dev").unwrap();
}

#[test]
fn changed_project_promotion_keeps_the_active_generation_rebuildable() {
    let mut environment = project_environment();
    let old_project_json = environment.project_spec_json.clone().unwrap();
    let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
    let mut next_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&old_project_json).unwrap();
    next_project.image = "registry.example/codewire/workspace:next".to_owned();
    let next_project_json = next_project.canonical_json().unwrap();
    let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
    let staging = test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.validate("dev").unwrap();

    assert!(
        environment
            .promote_staging_workspace_generation()
            .unwrap()
            .is_none()
    );

    assert_eq!(environment.project_spec_json, Some(next_project_json));
    assert_eq!(
        environment.project_spec_sha256.as_deref(),
        Some(next_project_sha256.as_str())
    );
    assert_eq!(environment.active_workspace_generation, Some(staging));
    let rollback = environment.rollback_workspace_generation.as_ref().unwrap();
    assert_eq!(rollback.root_generation, active.root_generation);
    assert_eq!(rollback.project_spec_json.as_bytes(), old_project_json);
    rollback.validate().unwrap();
    environment.validate("dev").unwrap();
}

#[tokio::test]
async fn failed_workspace_update_discards_only_staging_and_keeps_active_bootable() {
    let mut environment = project_environment();
    let old_project_json = environment.project_spec_json.clone().unwrap();
    let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
    let mut next_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&old_project_json).unwrap();
    next_project.image = "registry.example/codewire/workspace:next".to_owned();
    let next_project_json = next_project.canonical_json().unwrap();
    let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
    let staging = test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
    environment.state = StoredEnvironmentState::Running;
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging);
    let environment_id = environment.id;
    let payload =
        workspace_update_payload(&environment, &next_project_json, &next_project_sha256, true);
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();
    let operation = core
        .core()
        .store
        .advance_operation(
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::EffectApplied,
            None,
            None,
        )
        .unwrap();

    let failed = core
        .abort_workspace_transition(&operation, "dev", "workspace_update_failed")
        .await
        .unwrap();

    assert_eq!(failed.phase, OperationPhase::Failed);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert!(environment.staging_workspace_generation.is_none());
    assert_eq!(
        environment.project_spec_json.as_deref(),
        Some(old_project_json.as_slice())
    );
    environment.validate("dev").unwrap();
}

#[test]
fn boot_projection_tracks_incoming_workspace_and_current_sources_through_promotion() {
    for rollback in [false, true] {
        let mut environment = project_environment_with_secret_selection(
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
            BTreeMap::from([("OLD_KEY".into(), "old-ordinary-value".into())]),
        );
        let original_json = environment.project_spec_json.clone();
        let original_hash = environment.project_spec_sha256.clone();
        let mut incoming: codewire_project::ProjectSpec =
            serde_json::from_slice(original_json.as_ref().unwrap()).unwrap();
        incoming.environment = BTreeMap::from([("NEW_KEY".into(), "new-ordinary-value".into())]);
        // Saved workspace metadata may predate a source change. Neither a
        // rebuild nor rollback may revive its old source selection.
        incoming.secrets = Default::default();
        let json = incoming.canonical_json().unwrap();
        let hash = format!("{:x}", Sha256::digest(&json));
        let generation = test_workspace_generation(&json, &hash, b"incoming");
        if rollback {
            environment.rollback_workspace_generation = Some(generation);
            let active_storage = workspace_storage_generation(
                environment.active_workspace_generation.as_ref().unwrap(),
            )
            .unwrap();
            let rollback_storage = workspace_storage_generation(
                environment.rollback_workspace_generation.as_ref().unwrap(),
            )
            .unwrap();
            environment
                .stage_rollback_workspace_generation(&active_storage, &rollback_storage)
                .unwrap();
        } else {
            environment.staging_workspace_generation = Some(generation);
        }
        let boot = sources::projection_environment_for_boot(&environment).unwrap();
        assert_eq!(environment.project_spec_json, original_json);
        assert_eq!(environment.project_spec_sha256, original_hash);
        let binding = sources::local_launch_projection(&boot).unwrap().unwrap();
        assert!(binding.selection.user);
        assert_eq!(
            binding.selection.overridden_keys,
            BTreeSet::from(["NEW_KEY".into()])
        );
        assert_ne!(boot.project_spec_sha256, original_hash);
        environment.promote_staging_workspace_generation().unwrap();
        assert_eq!(environment.project_spec_json, boot.project_spec_json);
        assert_eq!(environment.project_spec_sha256, boot.project_spec_sha256);
        assert_eq!(
            sources::local_launch_projection(&environment).unwrap(),
            Some(binding)
        );
    }
}

#[test]
fn platform_profile_routing_requires_exact_metadata_not_a_local_fallback() {
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(project_environment().project_spec_json.as_ref().unwrap()).unwrap();
    project.credentials = Some(codewire_project::CredentialBinding {
        profile: "platform:id:11111111-1111-4111-8111-111111111111".into(),
    });
    assert!(project.secrets.is_empty());
    reject_undeliverable_workload_secrets(&project).unwrap();
    assert!(
        sources::validate_source_metadata(
            &project,
            "11111111-1111-4111-8111-111111111111",
            7,
            "user/work",
            None
        )
        .is_err()
    );
}

#[tokio::test]
async fn replayed_workspace_promotion_atomically_rotates_project_and_generation() {
    let mut environment = project_environment();
    let old_project_json = environment.project_spec_json.clone().unwrap();
    let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
    let mut next_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&old_project_json).unwrap();
    next_project.image = "registry.example/codewire/workspace:next".to_owned();
    let next_project_json = next_project.canonical_json().unwrap();
    let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
    let staging = test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    let environment_id = environment.id;
    let payload = workspace_update_payload(
        &environment,
        &next_project_json,
        &next_project_sha256,
        false,
    );
    reserve_boot_generation(&mut environment, 2).unwrap();
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let mut operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();
    for _ in 0..7 {
        operation = core
            .core()
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

    core.core()
        .recover_host_reboot_workspace_transitions()
        .unwrap();
    assert!(
        core.environment("dev")
            .unwrap()
            .staging_workspace_generation
            .is_some()
    );

    let request_id = operation.request_id;
    core.drain_pending(true).await.unwrap();
    let operation = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();

    assert_eq!(operation.phase, OperationPhase::Completed);
    assert_eq!(operation.checkpoint, 10);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert_eq!(environment.generation, 2);
    assert_eq!(environment.active_workspace_generation, Some(staging));
    assert_eq!(environment.rollback_workspace_generation, Some(active));
    assert_eq!(
        environment.project_spec_json.as_deref(),
        Some(next_project_json.as_slice())
    );
    environment.validate("dev").unwrap();
}

#[tokio::test]
async fn replayed_workspace_rollback_atomically_restores_the_prior_project() {
    let mut environment = project_environment();
    let old_project_json = environment.project_spec_json.clone().unwrap();
    let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let rollback = test_workspace_generation(&old_project_json, &old_project_sha256, b"rollback");
    let mut next_project: codewire_project::ProjectSpec =
        serde_json::from_slice(&old_project_json).unwrap();
    next_project.image = "registry.example/codewire/workspace:next".to_owned();
    let next_project_json = next_project.canonical_json().unwrap();
    let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
    let active = test_workspace_generation(&next_project_json, &next_project_sha256, b"active");
    environment.project_spec_json = Some(next_project_json);
    environment.project_spec_sha256 = Some(next_project_sha256);
    environment.active_workspace_generation = Some(active.clone());
    environment.rollback_workspace_generation = Some(rollback.clone());
    let payload = workspace_rollback_payload(&environment, true);
    let parameters = workspace_transition_parameters(
        &OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(environment.id),
            kind: OperationKind::RollbackWorkspace,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: payload.clone(),
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        },
        &environment,
    )
    .unwrap();
    let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    else {
        unreachable!()
    };
    environment
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            rollback_storage_generation,
        )
        .unwrap();
    reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let mut operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::RollbackWorkspace,
            &payload,
        )
        .unwrap();
    for _ in 0..7 {
        operation = core
            .core()
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
    let request_id = operation.request_id;

    core.drain_pending(true).await.unwrap();

    let operation = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(operation.phase, OperationPhase::Completed);
    assert_eq!(operation.checkpoint, 10);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert_eq!(environment.generation, 2);
    assert_eq!(environment.active_workspace_generation, Some(rollback));
    assert_eq!(environment.rollback_workspace_generation, Some(active));
    assert_eq!(
        environment.project_spec_json.as_deref(),
        Some(old_project_json.as_slice())
    );
    environment.validate("dev").unwrap();
}

#[test]
fn rollback_staging_and_abort_restore_the_exact_prior_slots() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(&project_json, &project_sha256, b"active");
    let rollback = test_workspace_generation(&project_json, &project_sha256, b"rollback");
    environment.active_workspace_generation = Some(active.clone());
    environment.rollback_workspace_generation = Some(rollback.clone());
    let payload = workspace_rollback_payload(&environment, true);
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        environment_id: Some(environment.id),
        kind: OperationKind::RollbackWorkspace,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload,
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };
    let parameters = workspace_transition_parameters(&operation, &environment).unwrap();

    environment
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            match &parameters.intent {
                WorkspaceTransitionIntent::Rollback {
                    rollback_storage_generation,
                } => rollback_storage_generation,
                WorkspaceTransitionIntent::Update { .. } => unreachable!(),
            },
        )
        .unwrap();
    assert_eq!(
        environment.active_workspace_generation,
        Some(active.clone())
    );
    assert_eq!(
        environment.staging_workspace_generation,
        Some(rollback.clone())
    );
    assert!(environment.rollback_workspace_generation.is_none());
    assert!(workspace_transition_requires_boot(&environment, &parameters).unwrap());

    environment
        .restore_staged_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            match &parameters.intent {
                WorkspaceTransitionIntent::Rollback {
                    rollback_storage_generation,
                } => rollback_storage_generation,
                WorkspaceTransitionIntent::Update { .. } => unreachable!(),
            },
        )
        .unwrap();
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert!(environment.staging_workspace_generation.is_none());
    assert_eq!(environment.rollback_workspace_generation, Some(rollback));
    environment.validate("dev").unwrap();
}

#[test]
fn host_reboot_discards_a_runtime_update_at_every_precommit_checkpoint() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let RuntimeTransitionFixture {
        old_artifact: active_artifact,
        next_artifact: staging_artifact,
        old_workspace: active,
        next_workspace: staging,
    } = same_image_runtime_transition(&environment);
    environment.state = StoredEnvironmentState::Running;
    environment.active_workspace_generation = Some(active.clone());
    environment.validate("dev").unwrap();
    let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);

    for checkpoint in 1..=7 {
        let mut interrupted = environment.clone();
        if checkpoint >= 2 {
            interrupted.staging_workspace_generation = Some(staging.clone());
            interrupted.staging_artifact_generation = Some(staging_artifact.clone());
        }
        if checkpoint >= 4 {
            interrupted.state = StoredEnvironmentState::Stopped;
        }
        if checkpoint >= 5 {
            reserve_boot_generation(&mut interrupted, 2).unwrap();
        }
        let (_parent, mut core) = test_supervisor_core_after_host_reboot(
            interrupted,
            OperationKind::UpdateWorkspace,
            &payload,
            checkpoint,
        );

        core.recover_host_reboot_workspace_transitions().unwrap();

        let recovered = core.environment("dev").unwrap();
        assert_eq!(recovered.active_workspace_generation, Some(active.clone()));
        assert_eq!(
            recovered.active_artifact_generation,
            Some(active_artifact.clone())
        );
        assert!(recovered.staging_workspace_generation.is_none());
        assert!(recovered.staging_artifact_generation.is_none());
        assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
        assert_eq!(recovered.generation, if checkpoint >= 5 { 2 } else { 1 });
        recovered.validate("dev").unwrap();
        core.ensure_no_unowned_workspace_staging("dev").unwrap();
        assert!(
            core.store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn host_reboot_restores_a_runtime_rollback_at_every_precommit_checkpoint() {
    let mut base = project_environment();
    let RuntimeTransitionFixture {
        old_artifact: rollback_artifact,
        next_artifact: active_artifact,
        old_workspace: rollback,
        next_workspace: active,
    } = same_image_runtime_transition(&base);
    base.state = StoredEnvironmentState::Running;
    base.active_artifact_generation = Some(active_artifact.clone());
    base.active_workspace_generation = Some(active.clone());
    base.rollback_workspace_generation = Some(rollback.clone());
    base.validate("dev").unwrap();
    let payload = workspace_rollback_payload(&base, true);
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &base,
            OperationKind::RollbackWorkspace,
            payload.clone(),
            0,
        ),
        &base,
    )
    .unwrap();
    let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    else {
        unreachable!()
    };
    for checkpoint in 1..=7 {
        let mut interrupted = base.clone();
        if checkpoint >= 2 {
            interrupted
                .stage_rollback_workspace_generation(
                    &parameters.prior_storage_generation,
                    rollback_storage_generation,
                )
                .unwrap();
        }
        if checkpoint >= 4 {
            interrupted.state = StoredEnvironmentState::Stopped;
        }
        if checkpoint >= 5 {
            reserve_boot_generation(&mut interrupted, 2).unwrap();
        }
        assert_eq!(
            interrupted.staging_artifact_generation,
            (checkpoint >= 2).then(|| rollback_artifact.clone())
        );
        interrupted.validate("dev").unwrap();
        let (_parent, mut core) = test_supervisor_core_after_host_reboot(
            interrupted,
            OperationKind::RollbackWorkspace,
            &payload,
            checkpoint,
        );

        core.recover_host_reboot_workspace_transitions().unwrap();

        let recovered = core.environment("dev").unwrap();
        assert_eq!(recovered.active_workspace_generation, Some(active.clone()));
        assert_eq!(
            recovered.active_artifact_generation,
            Some(active_artifact.clone())
        );
        assert!(recovered.staging_workspace_generation.is_none());
        assert!(recovered.staging_artifact_generation.is_none());
        assert_eq!(
            recovered.rollback_workspace_generation,
            Some(rollback.clone())
        );
        assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
        assert_eq!(recovered.generation, if checkpoint >= 5 { 2 } else { 1 });
        recovered.validate("dev").unwrap();
        core.ensure_no_unowned_workspace_staging("dev").unwrap();
        assert!(
            core.store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn host_reboot_keeps_a_committed_runtime_update() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let RuntimeTransitionFixture {
        old_artifact: _,
        next_artifact,
        old_workspace: active,
        next_workspace: staging,
    } = same_image_runtime_transition(&environment);
    environment.state = StoredEnvironmentState::Running;
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.staging_artifact_generation = Some(next_artifact.clone());
    environment.validate("dev").unwrap();
    let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);
    environment.promote_staging_workspace_generation().unwrap();
    environment.generation = 2;
    environment.validate("dev").unwrap();
    let (_parent, mut core) = test_supervisor_core_after_host_reboot(
        environment,
        OperationKind::UpdateWorkspace,
        &payload,
        8,
    );

    core.recover_host_reboot_workspace_transitions().unwrap();

    let recovered = core.environment("dev").unwrap();
    assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
    assert_eq!(recovered.generation, 2);
    assert_eq!(recovered.active_artifact_generation, Some(next_artifact));
    assert!(recovered.staging_artifact_generation.is_none());
    assert_eq!(recovered.active_workspace_generation, Some(staging));
    assert_eq!(recovered.rollback_workspace_generation, Some(active));
    recovered.validate("dev").unwrap();
    assert!(
        core.store
            .host_reboot_interrupted_workspace_transitions()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn host_reboot_keeps_a_committed_runtime_rollback() {
    let mut environment = project_environment();
    let RuntimeTransitionFixture {
        old_artifact: rollback_artifact,
        next_artifact: active_artifact,
        old_workspace: rollback,
        next_workspace: active,
    } = same_image_runtime_transition(&environment);
    environment.active_artifact_generation = Some(active_artifact);
    environment.active_workspace_generation = Some(active.clone());
    environment.rollback_workspace_generation = Some(rollback.clone());
    environment.validate("dev").unwrap();
    let payload = workspace_rollback_payload(&environment, false);
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::RollbackWorkspace,
            payload.clone(),
            0,
        ),
        &environment,
    )
    .unwrap();
    let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    else {
        unreachable!()
    };
    environment
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            rollback_storage_generation,
        )
        .unwrap();
    environment.promote_staging_workspace_generation().unwrap();
    environment.generation = 2;
    environment.validate("dev").unwrap();
    let (_parent, mut core) = test_supervisor_core_after_host_reboot(
        environment,
        OperationKind::RollbackWorkspace,
        &payload,
        8,
    );

    core.recover_host_reboot_workspace_transitions().unwrap();

    let recovered = core.environment("dev").unwrap();
    assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
    assert_eq!(recovered.generation, 2);
    assert_eq!(
        recovered.active_artifact_generation,
        Some(rollback_artifact)
    );
    assert!(recovered.staging_artifact_generation.is_none());
    assert_eq!(recovered.active_workspace_generation, Some(rollback));
    assert_eq!(recovered.rollback_workspace_generation, Some(active));
    recovered.validate("dev").unwrap();
    assert!(
        core.store
            .host_reboot_interrupted_workspace_transitions()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn durable_workspace_records_are_the_only_retained_storage_generations() {
    let mut environment = project_environment();
    let project_spec_json = environment.project_spec_json.as_deref().unwrap();
    let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
    let active = test_workspace_generation(project_spec_json, project_sha256, b"active");
    let staging = test_workspace_generation(project_spec_json, project_sha256, b"staging");
    let old_rollback =
        test_workspace_generation(project_spec_json, project_sha256, b"old-rollback");
    let artifact = environment
        .active_artifact_generation
        .as_deref()
        .unwrap()
        .to_owned();
    environment.active_workspace_generation = Some(active.clone());
    environment.staging_workspace_generation = Some(staging.clone());
    environment.rollback_workspace_generation = Some(old_rollback.clone());

    let before = referenced_root_storage_generations(&environment).unwrap();
    assert_eq!(before.len(), 3);
    for generation in [&active, &staging, &old_rollback] {
        assert!(
            before.contains(
                &oci_storage_generation(
                    &generation.root_generation,
                    &artifact,
                    generation.root_disk_bytes,
                )
                .unwrap()
            )
        );
    }

    assert_eq!(
        environment.promote_staging_workspace_generation().unwrap(),
        Some(old_rollback.clone())
    );
    let after = referenced_root_storage_generations(&environment).unwrap();
    assert_eq!(after.len(), 2);
    assert!(
        !after.contains(
            &oci_storage_generation(
                &old_rollback.root_generation,
                &artifact,
                old_rollback.root_disk_bytes,
            )
            .unwrap()
        )
    );
}

#[test]
fn artifact_retention_includes_active_staging_rollback_and_runner() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = "b".repeat(64);
    let staging = "c".repeat(64);
    let rollback = "d".repeat(64);
    let runner = "e".repeat(64);
    environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &active,
        b"active",
    ));
    environment.staging_artifact_generation = Some(staging.clone());
    environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &staging,
        b"staging",
    ));
    environment.rollback_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &rollback,
        b"rollback",
    ));
    environment.runner = Some(RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: ProcessIdentity {
            pid: 42,
            boot_id: "boot".to_owned(),
            start_time_ticks: 7,
            executable: PathBuf::from("/proc/self/exe"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                uid: 4,
                mode: 0o100500,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "f".repeat(64),
        },
        socket: SocketIdentity {
            device: 1,
            inode: 2,
            uid: 4,
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation: runner.clone(),
        error_code: None,
    });
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some("dev".to_owned()),
        environments: [("dev".to_owned(), environment)].into(),
    };

    assert_eq!(
        referenced_artifact_generations(&state).unwrap(),
        BTreeSet::from([active, staging, rollback, runner])
    );
}

#[test]
fn shared_content_reachability_rejects_conflicting_descriptor_sizes() {
    let mut first = project_environment();
    first.active_workspace_generation = Some(test_workspace_generation(
        first.project_spec_json.as_deref().unwrap(),
        first.project_spec_sha256.as_deref().unwrap(),
        b"first",
    ));
    let mut second = project_environment();
    second.id = Uuid::new_v4();
    second.name = "second".to_owned();
    let mut second_generation = test_workspace_generation(
        second.project_spec_json.as_deref().unwrap(),
        second.project_spec_sha256.as_deref().unwrap(),
        b"second",
    );
    second_generation.image.config.digest = first
        .active_workspace_generation
        .as_ref()
        .unwrap()
        .image
        .config
        .digest
        .clone();
    second_generation.image.config.size += 1;
    second.active_workspace_generation = Some(second_generation);
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some("dev".to_owned()),
        environments: [("dev".to_owned(), first), ("second".to_owned(), second)].into(),
    };

    assert!(matches!(
        referenced_content_blobs(&state),
        Err(SupervisorError::InvalidState)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn admitted_active_workspace_boots_without_registry_or_cas_access() {
    let engine = tempfile::tempdir().unwrap();
    fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut environment = project_environment();
    let generation = test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"offline-active",
    );
    let storage_generation = oci_storage_generation(
        &generation.root_generation,
        environment.active_artifact_generation.as_deref().unwrap(),
        generation.root_disk_bytes,
    )
    .unwrap();
    crate::generation::ensure_empty_root_generation(
        engine.path(),
        environment.id,
        &storage_generation,
        generation.root_disk_bytes,
    )
    .unwrap();
    environment.active_workspace_generation = Some(generation.clone());

    let boot = prepare_workspace_boot(engine.path(), engine.path(), &[], &environment).unwrap();

    assert_eq!(boot.root_generation, storage_generation);
    assert_eq!(boot.root_disk_bytes, generation.root_disk_bytes);
    assert!(boot.setup_root_generation.is_empty());
    assert_eq!(boot.setup_total_bytes, 0);
    assert!(boot.setup_header_sha256.is_empty());
    assert!(!engine.path().join("content").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn source_only_changes_reuse_the_admitted_root_setup_and_skill_identity() {
    let engine = tempfile::tempdir().unwrap();
    fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut environment = project_environment();
    let built = workspace_with_test_skills(&mut environment);
    let built_bytes = built.encode_canonical().unwrap();
    let skill_sha256 = built
        .skill_snapshot()
        .unwrap()
        .unwrap()
        .sha256()
        .unwrap()
        .to_string();
    let storage_generation = workspace_storage_generation(&built).unwrap();
    let root = crate::generation::ensure_empty_root_generation(
        engine.path(),
        environment.id,
        &storage_generation,
        built.root_disk_bytes,
    )
    .unwrap();
    let identity = root.identity;
    let modified = fs::metadata(&root.path).unwrap().modified().unwrap();
    environment.active_workspace_generation = Some(built.clone());
    let mut current: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    (current.secrets, current.credentials) = test_selectors();
    set_test_current_project(&mut environment, &current);
    for state in [
        StoredEnvironmentState::Stopped,
        StoredEnvironmentState::Running,
    ] {
        environment.state = state;
        let boot = prepare_workspace_boot(engine.path(), engine.path(), &[], &environment).unwrap();
        assert_eq!(boot.root_generation, storage_generation);
        assert_eq!(boot.skill_snapshot_sha256, skill_sha256);
        assert!(boot.setup_root_generation.is_empty());
        assert!(boot.setup_header_sha256.is_empty());
        assert_eq!(boot.setup_total_bytes, 0);
        assert_eq!(
            crate::state::StateDiskIdentity::capture(&root.path).unwrap(),
            identity
        );
        assert_eq!(
            fs::metadata(&root.path).unwrap().modified().unwrap(),
            modified
        );
        assert_eq!(
            environment
                .active_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            built_bytes
        );
    }
    assert!(!engine.path().join("content").exists());
}

#[test]
fn boot_and_rollback_delivery_checks_use_current_not_historical_sources() {
    let mut environment = project_environment();
    let empty = test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"empty-built-sources",
    );
    let mut selected: codewire_project::ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    selected.secrets.user = Some(codewire_project::StoragePlacement::Platform);
    let selected_json = selected.canonical_json().unwrap();
    let selected_sha256 = format!("{:x}", Sha256::digest(&selected_json));
    let historical =
        test_workspace_generation(&selected_json, &selected_sha256, b"historical-sources");
    environment.active_workspace_generation = Some(empty.clone());
    environment.rollback_workspace_generation = Some(historical.clone());
    let parameters = workspace_transition_parameters(
        &test_workspace_transition_operation(
            &environment,
            OperationKind::RollbackWorkspace,
            workspace_rollback_payload(&environment, false),
            0,
        ),
        &environment,
    )
    .unwrap();
    // Historical selectors are metadata, not current delivery authority.
    reject_workspace_transition_workload_secrets(&environment, &parameters).unwrap();
    validate_workspace_transition_start(&environment, &parameters).unwrap();
    environment.staging_workspace_generation = Some(historical.clone());
    validate_environment_workload_secret_delivery(&environment, true).unwrap();
    environment.active_workspace_generation = Some(historical);
    validate_environment_workload_secret_delivery(&environment, false).unwrap();

    set_test_current_project(&mut environment, &selected);
    environment.active_workspace_generation = Some(empty);
    for staging in [false, true] {
        assert!(matches!(
            validate_environment_workload_secret_delivery(&environment, staging),
            Err(SupervisorError::EnvironmentAccessUnavailable),
        ));
    }
    let mut corrupt = environment;
    corrupt.project_spec_sha256 = Some("f".repeat(64));
    assert!(matches!(
        validate_environment_workload_secret_delivery(&corrupt, true),
        Err(SupervisorError::InvalidState),
    ));
}

#[tokio::test]
async fn native_create_rejects_each_unpinned_platform_source_before_state_mutation() {
    for (index, secrets) in [
        codewire_project::SecretBindings {
            organization: true,
            ..Default::default()
        },
        codewire_project::SecretBindings {
            project: "platform:id:11111111-1111-4111-8111-111111111111".to_owned(),
            ..Default::default()
        },
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Platform),
            ..Default::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        let selected = project_environment_with_secret_selection(secrets, BTreeMap::new());
        let name = format!("secret-{index}");
        let request_id = Uuid::new_v4();
        let request = v1::CreateEnvironmentRequest {
            snapshot: None,
            network_policy: String::new(),
            implicit_vm_only: Vec::new(),
            name: name.clone(),
            source_path: "/workspace/source".to_owned(),
            vcpus: u32::from(selected.vcpus),
            memory_mib: selected.memory_mib,
            disk_bytes: selected.disk_bytes,
            docker_disk_bytes: 0,
            request_id: request_id.to_string(),
            project_spec_json: selected.project_spec_json.unwrap(),
            project_spec_sha256: selected.project_spec_sha256.unwrap(),
            implicit_path_mode: "clone".to_owned(),
            local_mounts: Vec::new(),
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        let (_parent, core) = test_supervisor_core(project_environment());
        let credential_root = core.config.credential_authority_root.clone();
        let service = test_supervisor_service(core);

        let error = service
            .create_environment(Request::new(request))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let core = &service.supervisor;
        assert!(
            core.core()
                .store
                .operation_by_request(request_id)
                .unwrap()
                .is_none()
        );
        assert!(!core.core().state.environments.contains_key(&name));
        assert!(!credential_root.exists());
    }
}

#[tokio::test]
async fn native_start_journals_admitted_mixed_sources_before_runtime_authority() {
    let environment = project_environment_with_secret_selection(
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Platform),
            project: format!("local:id:{}", Uuid::new_v4()),
            ..Default::default()
        },
        BTreeMap::new(),
    );
    let environment_id = environment.id;
    let expected_generation = environment.generation.checked_add(1).unwrap();
    let (_parent, core) = test_supervisor_core(environment);
    let credential_root = core.config.credential_authority_root.clone();
    let service = test_supervisor_service(core);
    service.hold_drains.store(true, Ordering::Release);
    let request_id = Uuid::new_v4();

    let submitted = service
        .start_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: request_id.to_string(),
            environment_id: environment_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(submitted.kind, v1::OperationKind::Start as i32);
    assert_eq!(submitted.phase, v1::OperationPhase::Intent as i32);
    assert_eq!(submitted.checkpoint, 0);
    let core = &service.supervisor;
    let pending = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.request_id, request_id);
    assert_eq!(pending.environment_id, Some(environment_id));
    assert_eq!(pending.kind, OperationKind::Start);
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    assert_eq!(
        pending.payload,
        serde_json::json!({"name": "dev", "generation": expected_generation})
    );
    assert_eq!(pending.operation_id.to_string(), submitted.operation_id);
    assert_eq!(
        supervisor_effect(pending.kind, pending.checkpoint).unwrap(),
        Some(LifecycleEffect::RequireEnvironmentAccess)
    );
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Stopped
    );
    assert!(!credential_root.exists());
}

#[test]
fn platform_sources_are_admitted_at_boot_with_exact_material_free_binding() {
    for secrets in [
        codewire_project::SecretBindings {
            organization: true,
            ..Default::default()
        },
        codewire_project::SecretBindings {
            project: "platform:id:11111111-1111-4111-8111-111111111111".to_owned(),
            ..Default::default()
        },
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Platform),
            ..Default::default()
        },
    ] {
        let environment = project_environment_with_secret_selection(secrets, BTreeMap::new());
        validate_environment_workload_secret_delivery(&environment, false).unwrap();
        assert!(
            sources::platform::broker_binding(&environment, Path::new("/synthetic/config"))
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn ordinary_environment_keys_do_not_require_the_credential_authority() {
    let environment = project_environment_with_secret_selection(
        codewire_project::SecretBindings::default(),
        BTreeMap::from([("PUBLIC_VALUE".to_owned(), "ordinary-value".to_owned())]),
    );
    validate_environment_workload_secret_delivery(&environment, false).unwrap();
}

#[test]
fn local_application_sources_are_admitted_with_original_key_precedence_and_no_profile() {
    for secrets in [
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Local),
            ..Default::default()
        },
        codewire_project::SecretBindings {
            project: "local:id:11111111-1111-4111-8111-111111111111".into(),
            ..Default::default()
        },
    ] {
        let environment = project_environment_with_secret_selection(
            secrets,
            BTreeMap::from([("EXPLICIT".into(), "ordinary-value".into())]),
        );
        validate_environment_workload_secret_delivery(&environment, false).unwrap();
        let projection = sources::local_launch_projection(&environment)
            .unwrap()
            .unwrap();
        assert!(projection.selection.overridden_keys.contains("EXPLICIT"));
        assert!(environment.access_binding.is_none());
        assert!(environment.proto(false).requires_credential_authority);
    }
}

#[test]
fn environment_proto_requires_the_authority_for_selected_sources_or_profiles() {
    assert!(
        !project_environment()
            .proto(false)
            .requires_credential_authority
    );
    assert!(
        project_environment_with_access()
            .proto(false)
            .requires_credential_authority
    );
    for secrets in [
        codewire_project::SecretBindings {
            organization: true,
            ..Default::default()
        },
        codewire_project::SecretBindings {
            project: "local:id:11111111-1111-4111-8111-111111111111".to_owned(),
            ..Default::default()
        },
        codewire_project::SecretBindings {
            user: Some(codewire_project::StoragePlacement::Local),
            ..Default::default()
        },
    ] {
        assert!(
            project_environment_with_secret_selection(secrets, BTreeMap::new())
                .proto(false)
                .requires_credential_authority
        );
    }
    assert!(
        !project_environment_with_secret_selection(
            codewire_project::SecretBindings::default(),
            BTreeMap::from([("PUBLIC_VALUE".to_owned(), "ordinary-value".to_owned())]),
        )
        .proto(false)
        .requires_credential_authority
    );
}

#[cfg(target_os = "linux")]
#[test]
fn staging_workspace_never_boots_when_exact_cached_content_is_absent() {
    let engine = tempfile::tempdir().unwrap();
    fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut environment = project_environment();
    environment.staging_workspace_generation = Some(test_workspace_generation(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        b"missing-content",
    ));

    assert!(matches!(
        prepare_workspace_boot(engine.path(), engine.path(), &[], &environment),
        Err(SupervisorError::SetupPack(SetupPackError::Registry(
            RegistryResolverError::Content(ContentStoreError::BlobMissing)
        )))
    ));
    assert!(environment.active_workspace_generation.is_none());
}

#[test]
fn environment_names_are_single_safe_components() {
    for valid in ["dev", "dev-1", "a_b.c", "9"] {
        assert!(valid_environment_name(valid));
    }
    for invalid in ["", "-dev", "../dev", "dev/name", "two words"] {
        assert!(!valid_environment_name(invalid));
    }
}

#[test]
fn supervisor_state_serialization_contains_no_secret_field() {
    let environment = project_environment_with_access();
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some(environment.name.clone()),
        environments: [(environment.name.clone(), environment)].into(),
    };
    state.validate().unwrap();
    let encoded = serde_json::to_string(&state).unwrap().to_ascii_lowercase();
    assert!(encoded.contains("11111111-1111-4111-8111-111111111111"));
    assert!(!encoded.contains("token"));
    assert!(!encoded.contains("credential"));
    assert!(!encoded.contains("capability"));
}

#[test]
fn canonical_project_intent_is_digest_and_resource_bound() {
    let (bytes, digest) = project_intent(2, 16 * 1024, 20);
    let disk_bytes = 20 * 1024 * 1024 * 1024;
    validate_project_intent(&bytes, &digest, Some((2, 16 * 1024, disk_bytes))).unwrap();

    let mut selected: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
    selected.secrets.user = Some(codewire_project::StoragePlacement::Local);
    selected
        .environment
        .insert("EXPLICIT".into(), "wins".into());
    let selected = selected.canonical_json().unwrap();
    let selected_digest = format!("{:x}", Sha256::digest(&selected));
    validate_project_intent(
        &selected,
        &selected_digest,
        Some((2, 16 * 1024, disk_bytes)),
    )
    .unwrap();

    let mut wrong_digest = digest.clone();
    wrong_digest.replace_range(0..1, "f");
    if wrong_digest == digest {
        wrong_digest.replace_range(0..1, "e");
    }
    assert!(
        validate_project_intent(&bytes, &wrong_digest, Some((2, 16 * 1024, disk_bytes)),).is_err()
    );
    assert!(validate_project_intent(&bytes, &digest, Some((4, 16 * 1024, disk_bytes))).is_err());

    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    let noncanonical_digest = format!("{:x}", Sha256::digest(&noncanonical));
    assert!(
        validate_project_intent(
            &noncanonical,
            &noncanonical_digest,
            Some((2, 16 * 1024, disk_bytes)),
        )
        .is_err()
    );
}

#[test]
fn canonical_project_setup_is_admitted_but_still_digest_bound() {
    let (bytes, _) = project_intent(2, 16 * 1024, 20);
    let mut project: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
    project.install_command = "printf install".to_owned();
    project.startup_script = "printf startup".to_owned();
    let bytes = project.canonical_json().unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    validate_project_intent(
        &bytes,
        &digest,
        Some((2, 16 * 1024, 20 * 1024 * 1024 * 1024)),
    )
    .unwrap();
    project.startup_script = "printf changed".to_owned();
    assert!(validate_project_intent(&project.canonical_json().unwrap(), &digest, None).is_err());
    project.agents.install = Some(true);
    let bytes = project.canonical_json().unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    assert!(validate_project_intent(&bytes, &digest, None).is_err());
}

#[test]
fn stored_creation_intent_remains_valid_after_runtime_resource_resize() {
    let mut environment = project_environment();
    let creation_intent = environment.project_spec_json.clone().unwrap();
    let creation_digest = environment.project_spec_sha256.clone().unwrap();

    environment.vcpus = 3;
    environment.memory_mib = 12 * 1024;
    environment.disk_bytes = 21 * 1024 * 1024 * 1024;

    environment.validate("dev").unwrap();
    assert_eq!(environment.project_spec_json, Some(creation_intent));
    assert_eq!(environment.project_spec_sha256, Some(creation_digest));
}

#[test]
fn create_journal_reconstructs_exact_canonical_project_intent() {
    let (project_spec_json, _) = project_intent(2, 16 * 1024, 20);
    let mut project: codewire_project::ProjectSpec =
        serde_json::from_slice(&project_spec_json).unwrap();
    project.application_ports = vec![codewire_project::ApplicationPort {
        port: 3_000,
        label: "app".to_owned(),
        access: String::new(),
    }];
    project.credentials = Some(codewire_project::CredentialBinding {
        profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
    });
    project.install_command = "printf install".to_owned();
    project.startup_script = "printf startup".to_owned();
    let project_spec_json = project.canonical_json().unwrap();
    let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "dev".to_owned(),
        source_path: "/workspace/source".to_owned(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: crate::state::MINIMUM_DOCKER_DISK_BYTES,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json,
        project_spec_sha256,
        implicit_path_mode: "clone".to_owned(),
        local_mounts: Vec::new(),
        host_ports: vec![v1::HostPortBinding {
            host_port: 18_080,
            guest_port: 3_000,
        }],
        mesh: Some(v1::MeshAttachment {
            mesh_url: "https://mesh.example.test/base".to_owned(),
            organization_id: "org-test".to_owned(),
            network_id: "network-test".to_owned(),
            node_name: "dev".to_owned(),
            guest_ports: vec![3_000],
            auth_source: v1::MeshEnrollmentAuthSource::StandaloneLocal as i32,
        }),
        access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        access_profile_revision: 7,
        access_profile_reference: "user/work".to_owned(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let mut incomplete = request.clone();
    incomplete.access_profile_revision = 0;
    assert!(matches!(
        validate_create(&incomplete),
        Err(SupervisorError::InvalidRequest)
    ));
    let mut invalid_docker = request.clone();
    invalid_docker.docker_disk_bytes = crate::state::MINIMUM_DOCKER_DISK_BYTES - 1;
    assert!(matches!(
        validate_create(&invalid_docker),
        Err(SupervisorError::InvalidRequest)
    ));
    let workspace_plan = WorkspacePlan::local(&crate::workspace::WorkspaceSource {
        vm_only: Vec::new(),
        source_path: PathBuf::from("/workspace/source"),
        commit: "a".repeat(40),
        mode: WorkspaceSourceMode::Clone,
    })
    .unwrap();
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::parse_str(&request.request_id).unwrap(),
        environment_id: Some(Uuid::new_v4()),
        kind: OperationKind::Create,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: create_operation_payload(&request, &workspace_plan).unwrap(),
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };

    let environment_id = operation.environment_id.unwrap();
    assert_eq!(
        create_request_from_operation(&operation).unwrap(),
        (request.clone(), workspace_plan.clone())
    );
    // #2537: a selection is journaled and replays; without one the
    // payload keeps its earlier shape, so older journals still replay.
    assert!(operation.payload.get("network_policy").is_none());
    let selecting = v1::CreateEnvironmentRequest {
        network_policy: "local:work".to_owned(),
        ..request.clone()
    };
    let selecting_operation = OperationRecord {
        payload: create_operation_payload(&selecting, &workspace_plan).unwrap(),
        ..operation.clone()
    };
    assert_eq!(
        create_request_from_operation(&selecting_operation).unwrap(),
        (selecting, workspace_plan.clone())
    );
    let mut empty_selection = selecting_operation.clone();
    empty_selection.payload["network_policy"] = "".into();
    assert!(create_request_from_operation(&empty_selection).is_err());
    let (binding, reference) = create_request_access_binding(
        &create_request_from_operation(&operation).unwrap().0,
        environment_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(binding.environment_id.as_str(), environment_id.to_string());
    assert_eq!(
        binding.profile_id.as_str(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(binding.profile_revision, 7);
    assert_eq!(reference.to_string(), "user/work");
}

#[test]
fn host_port_updates_withdraw_then_publish_into_one_canonical_set() {
    let current = vec![HostPortBinding::new(18_080, 3_000).unwrap()];
    let request = |add: &[(u32, u32)], remove: &[u32]| v1::UpdateHostPortsRequest {
        name: "dev".to_owned(),
        request_id: Uuid::new_v4().to_string(),
        environment_id: String::new(),
        add: add
            .iter()
            .map(|(host_port, guest_port)| v1::HostPortBinding {
                host_port: *host_port,
                guest_port: *guest_port,
            })
            .collect(),
        remove: remove.to_vec(),
    };
    assert_eq!(
        updated_host_ports(&current, &request(&[(18_079, 47_321)], &[])).unwrap(),
        vec![
            HostPortBinding::new(18_079, 47_321).unwrap(),
            HostPortBinding::new(18_080, 3_000).unwrap(),
        ]
    );
    assert_eq!(
        updated_host_ports(&current, &request(&[(18_080, 47_321)], &[18_080])).unwrap(),
        vec![HostPortBinding::new(18_080, 47_321).unwrap()]
    );
    assert!(
        updated_host_ports(&current, &request(&[], &[18_080]))
            .unwrap()
            .is_empty()
    );
    for (add, remove, code) in [
        (&[][..], &[][..], tonic::Code::InvalidArgument),
        (
            &[(18_080, 47_321)][..],
            &[][..],
            tonic::Code::FailedPrecondition,
        ),
        (
            &[(18_081, 3_000)][..],
            &[][..],
            tonic::Code::FailedPrecondition,
        ),
        (&[][..], &[18_081][..], tonic::Code::FailedPrecondition),
        (
            &[(18_081, 7_777)][..],
            &[][..],
            tonic::Code::InvalidArgument,
        ),
        (&[(0, 47_321)][..], &[][..], tonic::Code::InvalidArgument),
        (
            &[(70_000, 47_321)][..],
            &[][..],
            tonic::Code::InvalidArgument,
        ),
    ] {
        assert_eq!(
            updated_host_ports(&current, &request(add, remove))
                .unwrap_err()
                .code(),
            code,
            "{add:?} {remove:?}"
        );
    }
}

#[tokio::test]
async fn a_stopped_environment_records_updated_host_ports_for_its_next_start() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    core.core().environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    core.core().save().unwrap();
    let environment_id = core.environment("dev").unwrap().id;
    // Any guest port may be published after create, not only declared ones.
    let target = vec![HostPortBinding::new(18_080, 47_321).unwrap()];
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateHostPorts,
            &serde_json::json!({
                "name": "dev",
                "add": [[18_080, 47_321]],
                "remove": [],
                "target": target,
            }),
        )
        .unwrap();
    let completed = core.update_host_ports("dev", &operation).await.unwrap();
    assert!(
        supervisor_effect(completed.kind, completed.checkpoint)
            .unwrap()
            .is_none()
    );
    assert_eq!(core.environment("dev").unwrap().host_ports, target);
    assert_eq!(
        SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"].host_ports,
        target
    );
}

#[test]
fn local_host_ports_are_canonical_and_must_target_declared_application_ports() {
    let canonical = canonicalize_host_ports_proto(&[
        v1::HostPortBinding {
            host_port: 18_081,
            guest_port: 3_001,
        },
        v1::HostPortBinding {
            host_port: 18_080,
            guest_port: 3_000,
        },
    ])
    .unwrap();
    assert_eq!(canonical[0].host_port, 18_080);
    assert_eq!(canonical[1].host_port, 18_081);

    let project = codewire_project::ProjectSpec {
        application_ports: vec![codewire_project::ApplicationPort {
            port: 3_000,
            label: String::new(),
            access: String::new(),
        }],
        ..Default::default()
    };
    assert!(
        validate_host_ports_for_project(&[HostPortBinding::new(18_080, 3_000).unwrap()], &project,)
            .is_ok()
    );
    assert!(matches!(
        validate_host_ports_for_project(&[HostPortBinding::new(18_081, 3_001).unwrap()], &project,)
            .map_err(SupervisorError::from),
        Err(SupervisorError::InvalidRequest)
    ));
}

#[test]
fn local_mesh_attachment_is_exact_environment_and_project_port_intent() {
    let project = codewire_project::ProjectSpec {
        application_ports: vec![
            codewire_project::ApplicationPort {
                port: 8_080,
                ..Default::default()
            },
            codewire_project::ApplicationPort {
                port: 3_000,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let raw = v1::MeshAttachment {
        mesh_url: " https://MESH.example.test/base/ ".to_owned(),
        organization_id: " org-test ".to_owned(),
        network_id: " network-test ".to_owned(),
        node_name: " dev ".to_owned(),
        guest_ports: vec![8_080, 3_000],
        auth_source: v1::MeshEnrollmentAuthSource::HostedCurrent as i32,
    };
    let canonical = canonicalize_mesh_attachment_proto(Some(&raw))
        .unwrap()
        .unwrap();
    assert_eq!(canonical.mesh_url, "https://mesh.example.test/base");
    assert_eq!(canonical.node_name, "dev");
    assert_eq!(canonical.guest_ports, vec![3_000, 8_080]);
    assert_eq!(
        canonical.auth_source,
        v1::MeshEnrollmentAuthSource::HostedCurrent as i32
    );
    let attachment = mesh_attachment_from_proto(Some(&canonical))
        .unwrap()
        .unwrap();
    assert_eq!(
        attachment.auth_source,
        MeshEnrollmentAuthSource::HostedCurrent
    );
    validate_mesh_for_project(&attachment, &project).unwrap();

    let mut wrong_ports = attachment.clone();
    wrong_ports.guest_ports = vec![3_000];
    assert!(validate_mesh_for_project(&wrong_ports, &project).is_err());
}

#[test]
fn create_journal_reconstructs_copy_mounts_and_accepts_explicit_direct_shape() {
    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        working_directory: "/workspace/fixtures".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(16 * 1024),
            disk_gib: Some(20),
        },
        ..Default::default()
    };
    let project_spec_json = project.canonical_json().unwrap();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "copy".to_owned(),
        source_path: String::new(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        request_id: Uuid::new_v4().to_string(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
        project_spec_json,
        implicit_path_mode: String::new(),
        local_mounts: vec![v1::LocalMountInput {
            vm_only: Vec::new(),
            source_path: b"/host/fixtures".to_vec(),
            destination: "/workspace/fixtures".to_owned(),
            mode: v1::LocalMountMode::Copy as i32,
            read_only: None,
        }],
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let workspace_plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::local(
        &crate::workspace::WorkspaceSource {
            vm_only: Vec::new(),
            source_path: PathBuf::from("/host/fixtures"),
            commit: "a".repeat(40),
            mode: WorkspaceSourceMode::Copy,
        },
        "/workspace/fixtures",
    )])
    .unwrap();
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::parse_str(&request.request_id).unwrap(),
        environment_id: Some(Uuid::new_v4()),
        kind: OperationKind::Create,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: create_operation_payload(&request, &workspace_plan).unwrap(),
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };

    assert_eq!(
        create_request_from_operation(&operation).unwrap(),
        (request.clone(), workspace_plan)
    );

    let mut direct = request;
    direct.local_mounts[0].mode = v1::LocalMountMode::Direct as i32;
    direct.local_mounts[0].read_only = Some(true);
    validate_create(&direct).unwrap();
    direct.local_mounts[0].read_only = None;
    assert!(matches!(
        validate_create(&direct),
        Err(SupervisorError::InvalidRequest)
    ));
}

#[tokio::test]
async fn create_preparation_admits_an_explicit_copy_mount_without_an_implicit_path() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("fixture.txt"), b"copy fixture").unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        working_directory: "/workspace/fixtures".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(16 * 1024),
            disk_gib: Some(20),
        },
        ..Default::default()
    };
    let project_spec_json = project.canonical_json().unwrap();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "copy".to_owned(),
        source_path: String::new(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        request_id: Uuid::new_v4().to_string(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
        project_spec_json,
        implicit_path_mode: String::new(),
        local_mounts: vec![v1::LocalMountInput {
            vm_only: Vec::new(),
            source_path: source.as_os_str().as_bytes().to_vec(),
            destination: "/workspace/fixtures".to_owned(),
            mode: v1::LocalMountMode::Copy as i32,
            read_only: None,
        }],
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let (plan, _) = core
        .prepare_create_workspace_plan(&request, Uuid::new_v4())
        .await
        .unwrap();

    assert_eq!(plan.inputs.len(), 1);
    assert!(matches!(
        &plan.inputs[0],
        WorkspaceInput::Local {
            source_path,
            mode: WorkspaceSourceMode::Copy,
            destination,
            ..
        } if source_path == source.as_os_str().as_bytes()
            && destination == "/workspace/fixtures"
    ));
    plan.validate_for_project(&project).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn create_preparation_binds_an_explicit_direct_mount_for_durable_replay() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("fixture.txt"), b"direct fixture").unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        working_directory: "/workspace/fixtures".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(16 * 1024),
            disk_gib: Some(20),
        },
        ..Default::default()
    };
    let project_spec_json = project.canonical_json().unwrap();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "direct".to_owned(),
        source_path: String::new(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        request_id: Uuid::new_v4().to_string(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
        project_spec_json,
        implicit_path_mode: String::new(),
        local_mounts: vec![v1::LocalMountInput {
            vm_only: vec!["node_modules".to_owned(), "web/target".to_owned()],
            source_path: source.as_os_str().as_bytes().to_vec(),
            destination: "/workspace/fixtures".to_owned(),
            mode: v1::LocalMountMode::Direct as i32,
            read_only: Some(false),
        }],
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let (plan, discriminators) = core
        .prepare_create_workspace_plan(&request, Uuid::new_v4())
        .await
        .unwrap();

    assert_eq!(plan.inputs.len(), 1);
    assert!(matches!(
        &plan.inputs[0],
        WorkspaceInput::Direct {
            source_path,
            destination,
            read_only: false,
            ..
        } if source_path == source.as_os_str().as_bytes()
            && destination == "/workspace/fixtures"
    ));
    // The admission's discriminator travels with the plan, to be
    // recorded in the create's own transaction (#3209).
    assert!(
        discriminators
            .get(&plan.inputs[0].direct_identity_sha256().unwrap())
            .is_some()
    );
    plan.validate_for_project(&project).unwrap();
    let guest = plan.direct_share_plan().unwrap().unwrap();
    assert_eq!(guest.mounts()[0].tag(), "cw-direct-00");
    // The kept paths reach the digest-bound guest plan and the runner.
    assert_eq!(guest.mounts()[0].vm_only(), ["node_modules", "web/target"]);
    assert_eq!(
        direct_share_attachments_to_proto(&plan).unwrap()[0].vm_only,
        ["node_modules", "web/target"]
    );
    assert!(
        !guest
            .encode_canonical()
            .unwrap()
            .windows(source.as_os_str().as_bytes().len())
            .any(|window| window == source.as_os_str().as_bytes())
    );

    let encoded = create_operation_payload(&request, &plan).unwrap();
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::parse_str(&request.request_id).unwrap(),
        environment_id: Some(Uuid::new_v4()),
        kind: OperationKind::Create,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: encoded,
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };
    assert_eq!(
        create_request_from_operation(&operation).unwrap(),
        (request.clone(), plan.clone())
    );

    // The request and its plan must agree on the kept paths.
    let mut mismatched = request.clone();
    mismatched.local_mounts[0].vm_only = vec!["node_modules".to_owned()];
    assert!(matches!(
        validate_request_workspace_plan(&mismatched, &project, &plan),
        Err(SupervisorError::InvalidRequest)
    ));
    // A read-only share keeps nothing in the VM.
    let mut read_only = request;
    read_only.local_mounts[0].read_only = Some(true);
    assert!(matches!(
        validate_create(&read_only),
        Err(SupervisorError::InvalidRequest)
    ));
    read_only.local_mounts[0].vm_only.clear();
    validate_create(&read_only).unwrap();
}

#[tokio::test]
async fn create_copies_the_implicit_source_without_its_kept_paths() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("main.rs"), b"fn main() {}\n").unwrap();
    fs::create_dir_all(source.path().join("node_modules/pkg")).unwrap();
    fs::write(source.path().join("node_modules/pkg/index.js"), b"1").unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(16 * 1024),
            disk_gib: Some(20),
        },
        ..Default::default()
    };
    let project_spec_json = project.canonical_json().unwrap();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: vec!["node_modules".to_owned(), ".venv".to_owned()],
        name: "copy".to_owned(),
        source_path: source.to_string_lossy().into_owned(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        request_id: Uuid::new_v4().to_string(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
        project_spec_json,
        implicit_path_mode: "copy".to_owned(),
        local_mounts: Vec::new(),
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let (plan, _) = core
        .prepare_create_workspace_plan(&request, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(plan.inputs[0].vm_only(), ["node_modules", ".venv"]);
    let unskipped = crate::workspace::inspect_workspace(
        &source,
        WorkspaceSelection::Copy,
        workspace_content_limit(request.disk_bytes),
    )
    .unwrap();
    let WorkspaceInput::Local { identity, .. } = &plan.inputs[0] else {
        panic!("expected the implicit copy input");
    };
    assert_ne!(*identity, unskipped.commit);
    assert!(plan.direct_share_plan().unwrap().is_none());

    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::parse_str(&request.request_id).unwrap(),
        environment_id: Some(Uuid::new_v4()),
        kind: OperationKind::Create,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload: create_operation_payload(&request, &plan).unwrap(),
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };
    assert_eq!(
        create_request_from_operation(&operation).unwrap(),
        (request.clone(), plan.clone())
    );

    let mut mismatched = request.clone();
    mismatched.implicit_vm_only = vec!["node_modules".to_owned()];
    assert!(matches!(
        validate_request_workspace_plan(&mismatched, &project, &plan),
        Err(SupervisorError::InvalidRequest)
    ));
    // A clone takes only committed files and skips nothing.
    let mut clone = request.clone();
    clone.implicit_path_mode = "clone".to_owned();
    assert!(matches!(
        validate_create(&clone),
        Err(SupervisorError::InvalidRequest)
    ));
    // Overlapping patterns are valid: the outermost match wins.
    let mut patterns = request.clone();
    patterns.implicit_vm_only = vec!["node_modules".to_owned(), "**/node_modules".to_owned()];
    validate_create(&patterns).unwrap();
    for invalid in [
        vec!["../escape".to_owned()],
        vec!["/abs".to_owned()],
        vec!["a".to_owned(), "a".to_owned()],
        vec![".git".to_owned()],
        vec!["**".to_owned()],
        vec!["*/.git".to_owned()],
    ] {
        let mut unsafe_request = request.clone();
        unsafe_request.implicit_vm_only = invalid;
        assert!(matches!(
            validate_create(&unsafe_request),
            Err(SupervisorError::InvalidRequest)
        ));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn create_revalidates_a_direct_share_before_its_first_lifecycle_effect() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let workspace_plan = direct_workspace_plan(&source);
    let fixture = project_environment_with_access();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "new-environment".to_owned(),
        source_path: String::new(),
        vcpus: u32::from(fixture.vcpus),
        memory_mib: fixture.memory_mib,
        disk_bytes: fixture.disk_bytes,
        docker_disk_bytes: fixture.docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json: fixture.project_spec_json.unwrap(),
        project_spec_sha256: fixture.project_spec_sha256.unwrap(),
        implicit_path_mode: String::new(),
        local_mounts: vec![v1::LocalMountInput {
            vm_only: Vec::new(),
            source_path: source.as_os_str().as_bytes().to_vec(),
            destination: "/workspace/fixtures".to_owned(),
            mode: v1::LocalMountMode::Direct as i32,
            read_only: Some(true),
        }],
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        access_profile_revision: 7,
        access_profile_reference: "user/work".to_owned(),
        platform_source_authority: None,
    };
    validate_create(&request).unwrap();
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let environment_id = Uuid::new_v4();
    let operation = core
        .store
        .begin_operation(
            Uuid::parse_str(&request.request_id).unwrap(),
            Some(environment_id),
            OperationKind::Create,
            &create_operation_payload(&request, &workspace_plan).unwrap(),
        )
        .unwrap();
    let credential_root = source.join("new-credential-authority");
    core.config.credential_authority_root = credential_root.clone();
    let core = test_supervisor(core);

    let error = core
        .create(&request, &workspace_plan, &operation)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.checkpoint, 0);
    assert!(!core.core().state.environments.contains_key(&request.name));
    assert!(!credential_root.exists());
    assert!(core.core().children.is_empty());
    assert!(core.core().live_runners.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn replayed_create_quarantines_its_live_runner_when_private_roots_are_unresolvable() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let workspace_plan = direct_workspace_plan(&source);
    let mut environment = project_environment();
    environment.workspace_plan = workspace_plan.clone();
    let environment_id = environment.id;
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "dev".to_owned(),
        source_path: String::new(),
        vcpus: u32::from(environment.vcpus),
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
        docker_disk_bytes: environment.docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
        project_spec_json: environment.project_spec_json.clone().unwrap(),
        implicit_path_mode: String::new(),
        local_mounts: vec![v1::LocalMountInput {
            vm_only: Vec::new(),
            source_path: source.as_os_str().as_bytes().to_vec(),
            destination: "/workspace/fixtures".to_owned(),
            mode: v1::LocalMountMode::Direct as i32,
            read_only: Some(true),
        }],
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = core
        .store
        .begin_operation(
            Uuid::parse_str(&request.request_id).unwrap(),
            Some(environment_id),
            OperationKind::Create,
            &create_operation_payload(&request, &workspace_plan).unwrap(),
        )
        .unwrap();
    let runner_socket = core.config.runner_socket(environment_id);
    let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, runner_socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
    core.save().unwrap();
    let platform_alias = _parent.path().join("platform-alias");
    std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias).unwrap();
    core.config.platform_config_dir = platform_alias;
    let core = test_supervisor(core);

    let error = core
        .create(&request, &workspace_plan, &operation)
        .await
        .unwrap_err();

    assert!(matches!(error, SupervisorError::InvalidConfiguration));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.checkpoint, 0);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!runner_socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));

    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn start_revalidates_a_direct_share_before_access_and_runner_effects() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment_with_access();
    environment.workspace_plan = direct_workspace_plan(&source);
    let original_generation = environment.generation;
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": original_generation + 1}),
        )
        .unwrap();
    let credential_root = source.join("new-credential-authority");
    core.config.credential_authority_root = credential_root.clone();
    let core = test_supervisor(core);

    let error = core.start("dev", &operation).await.unwrap_err();

    assert!(matches!(
        error,
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.checkpoint, 0);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert_eq!(environment.generation, original_generation);
    assert!(environment.runner.is_none());
    assert!(!credential_root.exists());
    assert!(core.core().children.is_empty());
    assert!(core.core().live_runners.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn workspace_transition_revalidates_a_direct_share_before_access_and_staging() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment_with_access();
    environment.workspace_plan = direct_workspace_plan(&source);
    let project_spec_json = environment.project_spec_json.clone().unwrap();
    let project_spec_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(
        &project_spec_json,
        &project_spec_sha256,
        b"direct-share-transition",
    );
    environment.active_workspace_generation = Some(active.clone());
    environment.state = StoredEnvironmentState::Running;
    environment.validate("dev").unwrap();
    let environment_id = environment.id;
    let payload =
        workspace_update_payload(&environment, &project_spec_json, &project_spec_sha256, true);
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();
    let credential_root = source.join("new-credential-authority");
    core.config.credential_authority_root = credential_root.clone();
    let core = test_supervisor(core);

    let error = core
        .workspace_transition("dev", &operation)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.checkpoint, 0);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert!(environment.staging_workspace_generation.is_none());
    assert!(environment.runner.is_none());
    assert!(!credential_root.exists());
    assert!(core.core().children.is_empty());
    assert!(core.core().live_runners.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn restart_revalidates_a_direct_share_before_access_and_stop_effects() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment_with_access();
    environment.workspace_plan = direct_workspace_plan(&source);
    environment.state = StoredEnvironmentState::Running;
    let environment_id = environment.id;
    let payload = serde_json::json!({
        "name": "dev",
        "vcpus": environment.vcpus,
        "memory_mib": environment.memory_mib,
        "disk_bytes": environment.disk_bytes,
        "was_running": true,
        "target_generation": environment.generation + 1,
    });
    let (_parent, mut core) = test_supervisor_core(environment);
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Restart,
            &payload,
        )
        .unwrap();
    let credential_root = source.join("new-credential-authority");
    core.config.credential_authority_root = credential_root.clone();
    let core = test_supervisor(core);

    let error = core.resize("dev", &operation).await.unwrap_err();

    assert!(matches!(
        error,
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.checkpoint, 0);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert!(environment.runner.is_none());
    assert!(!credential_root.exists());
    assert!(core.core().children.is_empty());
    assert!(core.core().live_runners.is_empty());
}

/// A share directory and the inode number it was admitted with.
#[cfg(target_os = "linux")]
fn direct_share_inode(plan: &WorkspacePlan) -> u64 {
    match &plan.inputs[0] {
        WorkspaceInput::Direct { identity, .. } => identity.inode(),
        _ => unreachable!("a direct plan"),
    }
}

/// After the share at `source` was recreated, whether `reused` its inode
/// number, a start refuses it, except where the filesystem has no file
/// handle (overlay) and the number was reused: the documented limit.
#[cfg(target_os = "linux")]
async fn assert_start_refuses_a_recreated_share(
    core: &Arc<Supervisor>,
    recorded: &DirectShareDiscriminator,
    reused: bool,
) {
    if reused && recorded == &DirectShareDiscriminator::Unsupported {
        core.revalidate_environment_workspace_plan_for_boot("dev")
            .await
            .expect("without a handle a reused inode number is accepted");
        return;
    }
    assert!(matches!(
        core.ensure_vm_started("dev", 2, Uuid::new_v4()).await,
        Err(SupervisorError::WorkspacePlan(
            WorkspacePlanError::DirectShareChanged
        ))
    ));
}

/// #3209, end to end in the supervisor: the create records the share's
/// discriminator in its own transaction; while the VM is stopped nothing
/// holds the directory, so `rm -rf` and `mkdir` at its path can give the
/// new one the same inode number (TMPDIR on ext4 does); the next start
/// refuses it all the same.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_start_refuses_a_direct_share_recreated_while_stopped() {
    let parent = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(parent.path()).unwrap().join("share");
    fs::create_dir(&source).unwrap();
    let (input, discriminator) =
        prepare_direct_input(&source, "/workspace/fixtures", true, Vec::new(), &[]).unwrap();
    let mut discriminators = DirectShareDiscriminators::default();
    discriminators.insert(
        input.direct_identity_sha256().unwrap(),
        discriminator.clone(),
    );
    let mut environment = project_environment();
    environment.workspace_plan = WorkspacePlan::from_inputs(vec![input]).unwrap();
    let environment_id = environment.id;
    let inode = direct_share_inode(&environment.workspace_plan);
    let (_parent, core) = test_supervisor_core(environment);
    begin_create_operation(
        &core.store,
        Uuid::new_v4(),
        environment_id,
        &serde_json::json!({"name": "dev"}),
        &discriminators,
    )
    .unwrap();
    let core = test_supervisor(core);

    let reused = crate::direct_share::recreate_directory_reusing_inode(&source, inode);

    assert_start_refuses_a_recreated_share(&core, &discriminator, reused).await;
    assert!(core.environment("dev").unwrap().runner.is_none());
}

/// #3209 upgrade: a database written before discriminators has none. The
/// first supervisor start records one for each share that still matches,
/// so a share recreated after the upgrade is refused at its next start,
/// and a later start never records the replacement.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_records_discriminators_for_shares_admitted_before_them() {
    let parent = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(parent.path()).unwrap().join("share");
    fs::create_dir(&source).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let environment_id = environment.id;
    let identity_sha256 = environment.workspace_plan.inputs[0]
        .direct_identity_sha256()
        .unwrap();
    let inode = direct_share_inode(&environment.workspace_plan);
    let (_parent, core) = test_supervisor_core(environment);
    assert!(
        core.store
            .direct_share_discriminators(environment_id)
            .unwrap()
            .is_empty()
    );
    let core = test_supervisor(core);

    core.record_direct_share_discriminators_for_startup()
        .await
        .unwrap();
    let recorded = core
        .core()
        .store
        .direct_share_discriminators(environment_id)
        .unwrap();
    let discriminator = recorded
        .get(&identity_sha256)
        .cloned()
        .expect("the sweep records the matching share");

    let reused = crate::direct_share::recreate_directory_reusing_inode(&source, inode);
    core.record_direct_share_discriminators_for_startup()
        .await
        .unwrap();
    assert_eq!(
        core.core()
            .store
            .direct_share_discriminators(environment_id)
            .unwrap(),
        recorded
    );
    assert_start_refuses_a_recreated_share(&core, &discriminator, reused).await;
}

/// #3209 handoff: the checked shares go into the runner's StartVm and
/// stay held until it returns, so a directory recreated at a share's
/// path meanwhile cannot take its inode number (TMPDIR on ext4 would
/// otherwise reuse it) and the runner's (device, inode) reopen refuses it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn checked_shares_stay_held_until_the_runner_start_returns() {
    let parent = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(parent.path()).unwrap().join("share");
    fs::create_dir(&source).unwrap();
    let plan = direct_workspace_plan(&source);
    let inode = direct_share_inode(&plan);
    let checked = plan
        .check_direct_shares(&[], &DirectShareDiscriminators::default())
        .unwrap();

    let reused = while_holding_direct_shares(checked, async {
        crate::direct_share::recreate_directory_reusing_inode(&source, inode)
    })
    .await;

    assert!(!reused);
    assert!(matches!(
        plan.inputs[0].direct_source(&[]),
        Err(WorkspacePlanError::DirectShareChanged)
    ));
}

/// #3209: reading or recording discriminators can fail in the store,
/// which says nothing about the shares. The reconcile fails, and the
/// live runner exposing them is not ended.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_store_failure_recording_discriminators_never_quarantines_a_runner() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let (_parent, mut core) = test_supervisor_core(environment);
    let socket = core
        .config
        .runner_socket(core.environment("dev").unwrap().id);
    let (socket_identity, _useful_calls, shutdown_tx, server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
    let (environment_id, _process_identity) =
        attach_test_runner_process(&mut core, socket_identity);
    // Nothing recorded yet, so the check must record, and the store is
    // halted as at shutdown.
    core.store.stop();
    let core = test_supervisor(core);

    let reconciled = core.reconcile_runner("dev", false).await;

    assert!(matches!(reconciled, Err(SupervisorError::Store(_))));
    assert!(core.environment("dev").unwrap().runner.is_some());
    assert!(
        core.core()
            .children
            .get_mut(&environment_id)
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    let mut child = core.core().children.remove(&environment_id).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

/// #3209 runner sockets: a record read back from the store holds no pin.
/// Reconcile pins the socket while the verified runner lives, and only
/// the socket the record names, so a removal after the kill compares
/// with a held inode.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn reconcile_pins_a_recovered_runner_socket_while_its_runner_lives() {
    for replace_socket in [false, true] {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let socket = core
            .config
            .runner_socket(core.environment("dev").unwrap().id);
        let (socket_identity, _useful_calls, shutdown_tx, server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
        let recorded = socket_identity.clone();
        let (environment_id, _process_identity) =
            attach_test_runner_process(&mut core, socket_identity);
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        let runner = core
            .environment_mut("dev")
            .unwrap()
            .runner
            .as_mut()
            .unwrap();
        runner.socket =
            serde_json::from_value(serde_json::to_value(&runner.socket).unwrap()).unwrap();
        assert!(!runner.socket.pin.is_pinned());
        let _replacement = replace_socket.then(|| {
            remove_bound_socket(&socket, &recorded).unwrap();
            bind_owner_only(&socket).unwrap()
        });
        let core = test_supervisor(core);

        let _ = core.reconcile_runner("dev", false).await;

        let environment = core.environment("dev").unwrap();
        if replace_socket {
            assert!(
                environment
                    .runner
                    .as_ref()
                    .is_none_or(|runner| !runner.socket.pin.is_pinned())
            );
        } else {
            let runner = environment.runner.as_ref().unwrap();
            assert!(runner.socket.pin.is_pinned());
            assert_eq!(runner.socket, recorded);
        }
        detached_child.kill().unwrap();
        detached_child.wait().unwrap();
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ensure_vm_started_revalidates_a_direct_share_as_defense_in_depth() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let (_parent, mut core) = test_supervisor_core(environment);
    core.config.credential_authority_root = source.join("new-credential-authority");
    let core = test_supervisor(core);

    let error = core
        .ensure_vm_started("dev", 2, Uuid::new_v4())
        .await
        .unwrap_err();

    assert!(matches!(
        &error,
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
    ));
    assert!(core.environment("dev").unwrap().runner.is_none());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ensure_vm_started_quarantines_a_live_runner_for_an_unresolvable_private_root() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    let runner_socket = core.config.runner_socket(environment_id);
    let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, runner_socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
    core.save().unwrap();
    let platform_alias = _parent.path().join("platform-alias");
    std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias).unwrap();
    core.config.platform_config_dir = platform_alias;
    let core = test_supervisor(core);

    let error = core
        .ensure_vm_started("dev", 2, Uuid::new_v4())
        .await
        .unwrap_err();

    assert!(matches!(error, SupervisorError::InvalidConfiguration));
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!runner_socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));

    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[test]
fn vsock_cid_is_stable_and_not_reserved() {
    let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
    assert_eq!(allocate_vsock_cid(id), allocate_vsock_cid(id));
    assert!((3..u32::MAX).contains(&allocate_vsock_cid(id)));
}

#[test]
fn supervisor_lock_excludes_a_second_store_mutator_until_release() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(parent.path()).unwrap();
    let first = SupervisorLock::acquire(&root).unwrap();

    assert!(matches!(
        SupervisorLock::acquire(&root),
        Err(SupervisorError::AlreadyRunning)
    ));
    drop(first);
    SupervisorLock::acquire(&root).unwrap();
}

#[test]
fn supervisor_lock_tolerates_a_transient_inherited_descriptor() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(parent.path()).unwrap();
    let first = SupervisorLock::acquire(&root).unwrap();
    let inherited = first.0.try_clone().unwrap();
    drop(first);

    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        drop(inherited);
    });
    SupervisorLock::acquire(&root).unwrap();
    releaser.join().unwrap();
}

#[test]
fn native_state_requires_project_intent_and_runtime_generation() {
    let mut environment = project_environment();
    assert!(environment.validate("dev").is_ok());

    environment.project_spec_json = None;
    environment.project_spec_sha256 = None;
    assert!(matches!(
        environment.validate("dev").map_err(SupervisorError::from),
        Err(SupervisorError::InvalidState)
    ));

    let mut environment = project_environment();
    environment.active_artifact_generation = None;
    assert!(matches!(
        environment.validate("dev").map_err(SupervisorError::from),
        Err(SupervisorError::InvalidState)
    ));
}

#[test]
fn start_operation_requires_an_exact_explicit_generation() {
    let operation = |payload| OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        environment_id: Some(Uuid::new_v4()),
        kind: OperationKind::Start,
        phase: OperationPhase::Intent,
        checkpoint: 0,
        payload,
        result: None,
        error_code: None,
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };

    assert_eq!(
        start_operation_generation(&operation(serde_json::json!({
            "name": "dev",
            "generation": 2,
        })))
        .unwrap(),
        2
    );
    for payload in [
        serde_json::json!({"name": "dev"}),
        serde_json::json!({"name": "dev", "generation": 0}),
        serde_json::json!({"name": "dev", "generation": 2, "compat": true}),
        serde_json::json!({"generation": 2, "compat": true}),
    ] {
        assert!(matches!(
            start_operation_generation(&operation(payload)),
            Err(SupervisorError::InvalidState)
        ));
    }
}

#[test]
fn boot_generation_is_reserved_monotonically_before_runner_use() {
    let mut environment = project_environment();
    assert_eq!(environment.generation, 1);

    reserve_boot_generation(&mut environment, 2).unwrap();
    assert_eq!(environment.generation, 2);
    assert_eq!(environment.state, StoredEnvironmentState::Starting);
    reserve_boot_generation(&mut environment, 2).unwrap();

    environment.state = StoredEnvironmentState::Error;
    assert!(matches!(
        reserve_boot_generation(&mut environment, 2),
        Err(SupervisorError::InvalidState)
    ));
    reserve_boot_generation(&mut environment, 3).unwrap();
    assert_eq!(environment.generation, 3);
    assert_eq!(environment.state, StoredEnvironmentState::Starting);
    assert!(matches!(
        reserve_boot_generation(&mut environment, 2),
        Err(SupervisorError::InvalidState)
    ));
}

#[test]
fn oci_storage_generation_binds_content_artifacts_and_disk_policy() {
    let oci_generation = "a".repeat(64);
    let artifact_generation = "b".repeat(64);
    let first = oci_storage_generation(
        &oci_generation,
        &artifact_generation,
        DEFAULT_OCI_ROOT_DISK_BYTES,
    )
    .unwrap();
    assert!(valid_sha256(&first));
    assert_eq!(
        oci_storage_generation(
            &oci_generation,
            &artifact_generation,
            DEFAULT_OCI_ROOT_DISK_BYTES,
        )
        .unwrap(),
        first
    );
    assert_ne!(
        oci_storage_generation(
            &"c".repeat(64),
            &artifact_generation,
            DEFAULT_OCI_ROOT_DISK_BYTES,
        )
        .unwrap(),
        first
    );
    assert_ne!(
        oci_storage_generation(
            &oci_generation,
            &"c".repeat(64),
            DEFAULT_OCI_ROOT_DISK_BYTES,
        )
        .unwrap(),
        first
    );
    assert_ne!(
        oci_storage_generation(
            &oci_generation,
            &artifact_generation,
            DEFAULT_OCI_ROOT_DISK_BYTES + 1024 * 1024,
        )
        .unwrap(),
        first
    );
}

#[test]
fn staging_artifacts_are_selected_only_for_a_staging_boot() {
    let mut environment = project_environment();
    let project_json = environment.project_spec_json.clone().unwrap();
    let project_sha256 = environment.project_spec_sha256.clone().unwrap();
    environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"b".repeat(64),
        b"active",
    ));
    environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"b".repeat(64),
        b"staging",
    ));
    assert_eq!(
        artifact_generation_for_boot(&environment, true).unwrap(),
        "b".repeat(64)
    );
    environment.staging_artifact_generation = Some("c".repeat(64));
    environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
        &project_json,
        &project_sha256,
        &"c".repeat(64),
        b"staging",
    ));
    assert_eq!(
        artifact_generation_for_boot(&environment, true).unwrap(),
        "c".repeat(64)
    );
    assert_eq!(
        artifact_generation_for_boot(&environment, false).unwrap(),
        "b".repeat(64)
    );
}

#[test]
fn retried_create_keeps_the_first_journaled_environment_id() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    let (store, _) = SupervisorStore::open(&root).unwrap();
    let request_id = Uuid::new_v4();
    let payload = serde_json::json!({"name": "dev"});
    let environment_id = Uuid::new_v4();
    let mut admitted = DirectShareDiscriminators::default();
    admitted.insert("a".repeat(64), DirectShareDiscriminator::Unsupported);
    let mut replayed = DirectShareDiscriminators::default();
    replayed.insert("b".repeat(64), DirectShareDiscriminator::Unsupported);

    let first =
        begin_create_operation(&store, request_id, environment_id, &payload, &admitted).unwrap();
    let retried =
        begin_create_operation(&store, request_id, environment_id, &payload, &replayed).unwrap();

    assert_eq!(retried, first);
    assert_eq!(first.environment_id, Some(environment_id));
    // The create's own transaction recorded its admission discriminators,
    // and a replay keeps them (#3209).
    assert_eq!(
        store.direct_share_discriminators(environment_id).unwrap(),
        admitted
    );
    for (changed_id, changed_payload) in [
        (Uuid::new_v4(), payload.clone()),
        (environment_id, serde_json::json!({"name": "other"})),
    ] {
        assert!(matches!(
            begin_create_operation(&store, request_id, changed_id, &changed_payload, &admitted),
            Err(SupervisorError::Store(
                SupervisorStoreError::RequestCollision
            ))
        ));
    }
    assert!(begin_create_operation(&store, request_id, Uuid::nil(), &payload, &admitted).is_err());
}

#[test]
fn operation_watch_failure_preserves_code_and_safe_operation_identity() {
    let operation_id = Uuid::new_v4().to_string();
    let failure = operation_watch_failure(
        &operation_id,
        Status::cancelled("raw transport detail must not be reflected"),
    );

    assert_eq!(failure.code(), tonic::Code::Cancelled);
    assert_eq!(
        failure.message(),
        format!("local lifecycle operation {operation_id} watch failed before a terminal result")
    );
    assert!(!failure.message().contains("raw transport detail"));
}

#[tokio::test]
async fn staging_boundary_collects_only_unreferenced_root_and_content_storage() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    root.ensure_dir(Path::new("engine"), 0o700).unwrap();
    prepare_runner_socket_dir(root.path()).unwrap();
    let lock = SupervisorLock::acquire(&root).unwrap();
    let (store, _) = SupervisorStore::open(&root).unwrap();
    let engine = PrivateRoot::open(&root_path.join("engine")).unwrap();
    let (active_artifact, active_kernel) =
        install_test_artifact_generation(&engine, b"current-kernel");
    let (stale_artifact, stale_kernel) = install_test_artifact_generation(&engine, b"stale-kernel");
    let mut environment = project_environment();
    environment.active_artifact_generation = Some(active_artifact.clone());
    let active = test_workspace_generation_with_artifact(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        &active_artifact,
        b"active",
    );
    let active_storage = oci_storage_generation(
        &active.root_generation,
        environment.active_artifact_generation.as_deref().unwrap(),
        active.root_disk_bytes,
    )
    .unwrap();
    let stale_storage = "f".repeat(64);
    environment.active_workspace_generation = Some(active);
    let paths = VmPaths::create(&engine, environment.id).unwrap();
    for storage in [&active_storage, &stale_storage] {
        let generation = crate::state::RootGenerationPaths::create(&paths, storage).unwrap();
        fs::write(&generation.root_disk, b"root").unwrap();
        fs::set_permissions(&generation.root_disk, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some("dev".to_owned()),
        environments: [("dev".to_owned(), environment)].into(),
    };
    let retained_content = referenced_content_blobs(&state).unwrap();
    ContentStore::create(&engine).unwrap();
    let blobs = engine.path().join("content/blobs");
    for (digest, size) in &retained_content {
        fs::write(
            blobs.join(digest.hex()),
            vec![0_u8; usize::try_from(*size).unwrap()],
        )
        .unwrap();
        fs::set_permissions(blobs.join(digest.hex()), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let stale_content = Sha256Digest::parse(&format!("sha256:{}", "e".repeat(64))).unwrap();
    fs::write(blobs.join(stale_content.hex()), b"stale").unwrap();
    fs::set_permissions(
        blobs.join(stale_content.hex()),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    store.replace_state(&state).unwrap();
    let core = SupervisorCore {
        config: NativeRuntimeConfig {
            root: root_path,
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock.json"),
            mesh_data_dir: parent.path().join("mesh-auth"),
            platform_config_dir: parent.path().join("platform-auth"),
            credential_authority_root: parent.path().join("credentials"),
            executable: PathBuf::from("/usr/bin/true"),
        },
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images: retained_images::RetainedImages::default(),
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        admitted_here: HashMap::new(),
        selections: 0,
        retiring: false,
        operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
        log: None,
        network_policies: Arc::new(
            crate::network_policy_store::NetworkPolicyStore::in_memory().unwrap(),
        ),
        _lock: lock,
    };
    let core = test_supervisor(core);

    // A staged environment stages nothing more; beginning a stage still
    // collects.
    let writer = core.begin_staging("dev").await.unwrap();
    assert_eq!(core.stage_workspace_generation("dev").await.unwrap(), None);
    drop(writer);
    assert!(paths.generations_dir.join(active_storage).is_dir());
    assert!(!paths.generations_dir.join(stale_storage).exists());
    for digest in retained_content.keys() {
        assert!(blobs.join(digest.hex()).is_file());
    }
    assert!(!blobs.join(stale_content.hex()).exists());
    let artifact_manifests = engine.path().join("runtime-artifacts/generations");
    let artifact_blobs = engine.path().join("runtime-artifacts/blobs");
    assert!(
        artifact_manifests
            .join(format!("{active_artifact}.json"))
            .is_file()
    );
    assert!(artifact_blobs.join(format!("r-{active_kernel}")).is_file());
    assert!(
        !artifact_manifests
            .join(format!("{stale_artifact}.json"))
            .exists()
    );
    assert!(!artifact_blobs.join(format!("r-{stale_kernel}")).exists());
}

#[tokio::test]
async fn select_environment_persists_the_new_current_environment() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let mut selected = project_environment();
    selected.name = "selected".to_owned();
    let selected_id = selected.id;
    core.state
        .environments
        .insert(selected.name.clone(), selected);
    core.save().unwrap();
    let service = test_supervisor_service(core);

    let response = service
        .select_environment(Request::new(v1::EnvironmentSelector {
            name: "selected".to_owned(),
            request_id: Uuid::new_v4().to_string(),
            environment_id: selected_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.id, selected_id.to_string());
    assert!(response.selected);

    let core = &service.supervisor;
    assert_eq!(core.core().state.current.as_deref(), Some("selected"));
    let (_, persisted) = SupervisorStore::inspect(&core.root).unwrap();
    assert_eq!(persisted.current.as_deref(), Some("selected"));
}

#[tokio::test]
async fn select_environment_rejects_a_recreated_identity_without_changing_current() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);

    let error = service
        .select_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: Uuid::new_v4().to_string(),
            environment_id: Uuid::new_v4().to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);

    let core = &service.supervisor;
    assert_eq!(core.core().state.current.as_deref(), Some("dev"));
}

#[tokio::test]
async fn lifecycle_rpc_commits_before_the_detached_worker_completes() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let submitted = service
        .stop_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: Uuid::new_v4().to_string(),
            environment_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        v1::OperationPhase::try_from(submitted.phase).unwrap(),
        v1::OperationPhase::Intent
    );
    assert_eq!(submitted.checkpoint, 0);

    let response = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: submitted.operation_id.clone(),
        }))
        .await
        .unwrap();
    let mut stream = response.into_inner();
    let terminal = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(update) = futures::StreamExt::next(&mut stream).await {
            let update = update.unwrap();
            if operation_terminal(&update).unwrap() {
                return update;
            }
        }
        panic!("operation watch ended before completion")
    })
    .await
    .unwrap();
    assert_eq!(
        v1::OperationPhase::try_from(terminal.phase).unwrap(),
        v1::OperationPhase::Completed
    );
    assert!(terminal.checkpoint > submitted.checkpoint);
}

#[tokio::test]
async fn broker_stop_does_not_treat_missing_authority_as_proven_child_death() {
    let (_parent, core) = test_supervisor_core(project_environment_with_access());
    let core = test_supervisor(core);
    let environment = core.environment("dev").unwrap().clone();
    assert!(environment.generation > 0);
    assert!(matches!(
        core.stop_environment_broker_if_present(&environment).await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
}

#[tokio::test]
async fn broker_stop_accepts_exact_authority_ack_without_changing_profile_binding() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let (mut authority, server) = start_test_credential_authority(&core).await;
    let binding = bind_test_environment_access(&core, &mut authority).await;
    let environment = core.environment("dev").unwrap().clone();
    core.stop_environment_broker_if_present(&environment)
        .await
        .unwrap();
    assert_eq!(
        authority
            .get_environment_access_binding(&binding.environment_id)
            .await
            .unwrap()
            .binding,
        binding
    );
    drop(authority);
    server.abort();
    let _ = server.await;
}

/// #2924: removing an environment ends its broker's supervision. Access
/// revocation finds no local binding for a platform profile or a
/// projection, so delete itself stops the exact generation's broker,
/// before its runner goes, and cannot proceed without that drain.
#[tokio::test]
async fn delete_stops_the_environment_broker_before_retiring_its_runner() {
    for environment in [
        project_environment_with_platform_profile(),
        project_environment_with_secret_selection(
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
            BTreeMap::new(),
        ),
        project_environment_with_access(),
    ] {
        assert!(environment.generation > 0);
        let environment_id = environment.id;
        let (_parent, core) = test_supervisor_core(environment);
        let core = test_supervisor(core);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let paths = VmPaths::create(&engine, environment_id).unwrap();
        assert!(matches!(
            core.prepare_environment_for_delete("dev").await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        assert_eq!(core.environment("dev").unwrap().id, environment_id);
        assert!(paths.vm_dir.exists());

        // With the authority present, its acknowledgement lets the delete
        // go on to the runner, which this fixture cannot boot.
        let (authority, server) = start_test_credential_authority(&core).await;
        assert!(!matches!(
            core.prepare_environment_for_delete("dev").await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        drop(authority);
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn client_bootstrap_requires_the_exact_profile_binding_without_material_access() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let empty = core.environment("dev").unwrap().clone();
    assert_eq!(
        core.managed_credential_clients_for_boot(&empty, 1)
            .await
            .unwrap(),
        Default::default()
    );
    let (mut authority, server) = start_test_credential_authority(&core).await;
    let binding = bind_test_environment_access(&core, &mut authority).await;
    let environment = core.environment("dev").unwrap().clone();
    assert_eq!(
        core.managed_credential_clients_for_boot(&environment, 1)
            .await
            .unwrap(),
        Default::default()
    );
    // The store's GitHub connection is granted to the profile, never an
    // entry of it; once it exists, boot configures git for it.
    authority
        .add_credential(
            codewire_local_credentials::NewCredential {
                provider: codewire_access::ProviderId::parse("github").unwrap(),
                authentication_kind: codewire_access::CredentialAuthKind::OAuth,
                display_name: "github".to_owned(),
                account_hint: None,
                expires_at_unix: None,
            },
            codewire_protected_store::ProtectedValue::from_slice(b"synthetic-github-login")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        core.managed_credential_clients_for_boot(&environment, 1)
            .await
            .unwrap(),
        codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap()
    );
    let mut wrong = environment.clone();
    wrong.access_binding.as_mut().unwrap().profile_revision = binding.profile_revision + 1;
    assert!(matches!(
        core.managed_credential_clients_for_boot(&wrong, 1).await,
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
    let mut platform = environment.clone();
    let mut spec: codewire_project::ProjectSpec =
        serde_json::from_slice(platform.project_spec_json.as_deref().unwrap()).unwrap();
    spec.credentials.as_mut().unwrap().profile = format!("platform:id:{}", binding.profile_id);
    set_test_current_project(&mut platform, &spec);
    assert!(matches!(
        core.managed_credential_clients_for_boot(&platform, 1).await,
        Err(SupervisorError::EnvironmentAccessUnavailable)
    ));
    drop(authority);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn bound_environment_fails_closed_when_the_authority_is_unavailable() {
    let environment = project_environment_with_access();
    let public = environment.proto(true);
    assert_eq!(public.access_profile, "user/work");
    assert_eq!(public.access_profile_revision, 7);
    assert_eq!(
        public.access_profile_id,
        "11111111-1111-4111-8111-111111111111"
    );
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);

    assert!(matches!(
        core.require_environment_access("dev").await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    assert!(
        core.revoke_environment_access_best_effort(Uuid::new_v4())
            .await
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn credential_broker_rpc_quarantines_an_unsafe_runner_before_authority_use() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment_with_access();
    environment.workspace_plan = direct_workspace_plan(&source);
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    let socket = core.config.runner_socket(environment_id);
    let (socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    let mut detached_child = core.children.remove(&environment_id).unwrap();
    core.live_runners.remove(&environment_id).unwrap();
    core.config.credential_authority_root = source.join("new-credential-authority");
    let service = test_supervisor_service(core);

    let error = LocalSupervisorService::ensure_credential_broker(
        &service,
        Request::new(read_selector("dev")),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "direct-share source changed after admission"
    );
    let core = &service.supervisor;
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!core.core().live_runners.contains_key(&environment_id));
    assert!(!core.core().children.contains_key(&environment_id));
    assert!(!socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));
    let _ = detached_child.wait().unwrap();
    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[tokio::test]
async fn credential_broker_requires_an_exact_runner_after_reconciliation() {
    let mut environment = project_environment_with_access();
    environment.state = StoredEnvironmentState::Running;
    let (_parent, core) = test_supervisor_core(environment);
    assert!(matches!(
        core.credential_broker_ensure_request("dev"),
        Err(SupervisorError::NotRunning)
    ));
    let service = test_supervisor_service(core);

    let error = LocalSupervisorService::ensure_credential_broker(
        &service,
        Request::new(read_selector("dev")),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(error.message(), "local environment is not running");
    let core = &service.supervisor;
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
}

// Adopts the detached runner through recovery, which Darwin never does.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn credential_broker_rejects_a_replaced_runner_socket_before_authority_use() {
    let environment = project_environment_with_access();
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    let socket = core.config.runner_socket(environment_id);
    let (socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
    let recorded_socket = socket_identity.clone();
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    let mut detached_child = core.children.remove(&environment_id).unwrap();
    core.live_runners.remove(&environment_id).unwrap();
    remove_bound_socket(&socket, &recorded_socket).unwrap();
    fs::write(&socket, b"untrusted replacement").unwrap();
    let service = test_supervisor_service(core);

    let error = LocalSupervisorService::ensure_credential_broker(
        &service,
        Request::new(read_selector("dev")),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "local environment ownership is orphaned; inspect it with `cw doctor local`"
    );
    let core = &service.supervisor;
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Orphaned);
    assert!(environment.runner.is_some());
    assert_eq!(fs::read(&socket).unwrap(), b"untrusted replacement");
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(LiveProcess::recover(&process_identity).is_ok());
    detached_child.kill().unwrap();
    detached_child.wait().unwrap();
    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[test]
fn reconcile_observation_applies_the_target_state_and_generation() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let before = core.environment("dev").unwrap().clone();
    let target_generation = before.generation + 1;
    let payload = reconcile_operation_payload(
        &before,
        StoredEnvironmentState::Running,
        target_generation,
        false,
        None,
    );
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(before.id),
            OperationKind::Reconcile,
            &payload,
        )
        .unwrap();

    let applied = core.apply_reconcile_operation(&operation).unwrap();

    assert_eq!(applied.checkpoint, 1);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Running
    );
    assert_eq!(
        core.environment("dev").unwrap().generation,
        target_generation
    );
}

#[test]
fn stale_reconcile_observation_is_checkpointed_without_overwriting_newer_state() {
    let runner_record = |pid, inode| RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: ProcessIdentity {
            pid,
            boot_id: "synthetic-boot".to_owned(),
            start_time_ticks: u64::from(pid),
            executable: PathBuf::from("/usr/bin/true"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode,
                size: 1,
                uid: crate::host::path::current_uid(),
                mode: 0o100755,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "f".repeat(64),
        },
        socket: SocketIdentity {
            device: 1,
            inode,
            uid: crate::host::path::current_uid(),
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation: "b".repeat(64),
        error_code: None,
    };
    let mut environment = project_environment();
    environment.runner = Some(runner_record(41, 101));
    let (_parent, mut core) = test_supervisor_core(environment);
    let before = core.environment("dev").unwrap().clone();
    let payload = reconcile_operation_payload(
        &before,
        StoredEnvironmentState::Running,
        before.generation + 1,
        false,
        None,
    );
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(before.id),
            OperationKind::Reconcile,
            &payload,
        )
        .unwrap();
    let replacement = runner_record(42, 102);
    core.environment_mut("dev").unwrap().runner = Some(replacement.clone());
    core.save().unwrap();

    let applied = core.apply_reconcile_operation(&operation).unwrap();

    assert_eq!(applied.checkpoint, 1);
    assert_eq!(core.environment("dev").unwrap().state, before.state);
    assert_eq!(
        core.environment("dev").unwrap().generation,
        before.generation
    );
    assert_eq!(core.environment("dev").unwrap().runner, Some(replacement));
}

#[test]
fn reconcile_intent_rejects_missing_precondition_fields() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let before = core.environment("dev").unwrap().clone();
    let operation = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(before.id),
            OperationKind::Reconcile,
            &serde_json::json!({
                "name": "dev",
                "observed_state": "running",
                "generation": before.generation + 1,
                "clear_runner": false,
                "runner_error_code": null,
            }),
        )
        .unwrap();

    assert!(matches!(
        core.apply_reconcile_operation(&operation),
        Err(SupervisorError::InvalidState)
    ));
    let persisted = core
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();

    assert_eq!(persisted.phase, OperationPhase::Intent);
    assert_eq!(persisted.checkpoint, 0);
    assert_eq!(core.environment("dev").unwrap(), &before);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_quarantines_an_exposing_unsafe_runner_before_listen_but_preserves_an_idle_one() {
    for persisted_state in [
        StoredEnvironmentState::Running,
        StoredEnvironmentState::Stopped,
    ] {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runner_socket = core.config.runner_socket(environment_id);
        let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
        let recorded_runner_socket = runner_socket_identity.clone();
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, runner_socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        core.environment_mut("dev").unwrap().state = persisted_state;
        core.save().unwrap();
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        core.config.credential_authority_root = source.join("new-credential-authority");
        let config = core.config.clone();
        assert!(core.store.pending_operations().unwrap().is_empty());
        drop(core);

        let supervisor_socket = config.supervisor_socket();
        let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
        let supervisor_socket_identity = tokio::select! {
            result = &mut supervisor => {
                panic!("supervisor exited before listening: {result:?}");
            }
            identity = tokio::time::timeout(LISTENER_HANG_GUARD, async {
                loop {
                    if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                        break identity;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }) => identity.expect("supervisor did not reach its listener after startup reconciliation"),
        };

        let root = PrivateRoot::open(&config.root).unwrap();
        let (_store, state) = SupervisorStore::inspect(&root).unwrap();
        let environment = state.environments.get("dev").unwrap();
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        if persisted_state == StoredEnvironmentState::Running {
            assert_eq!(environment.state, StoredEnvironmentState::Error);
            assert!(environment.runner.is_none());
            assert!(!runner_socket.exists());
            assert!(matches!(
                LiveProcess::recover(&process_identity),
                Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
            ));
        } else {
            assert_eq!(environment.state, StoredEnvironmentState::Stopped);
            assert!(environment.runner.is_some());
            assert!(runner_socket.exists());
            assert!(LiveProcess::recover(&process_identity).is_ok());
        }
        drop(_store);
        drop(root);

        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
        if persisted_state == StoredEnvironmentState::Stopped {
            detached_child.kill().unwrap();
        }
        let _ = detached_child.wait().unwrap();
        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
        if persisted_state == StoredEnvironmentState::Stopped {
            remove_bound_socket(&runner_socket, &recorded_runner_socket).unwrap();
        }
    }
}

/// A runner that outlived its supervisor while its cw was rebuilt in
/// place runs a replaced executable. Startup retires that exact runner
/// and serves the root, instead of stopping for good with "process
/// identity data is malformed" (#3355).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_retires_a_runner_whose_executable_was_replaced() {
    let environment = project_environment();
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runner_socket = core.config.runner_socket(environment_id);
    let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
    let directory = fs::canonicalize(_parent.path()).unwrap();
    let executable = directory.join("recorded_runner");
    fs::copy(fs::canonicalize("/bin/sleep").unwrap(), &executable).unwrap();
    let (_, process_identity) =
        attach_test_runner_process_running(&mut core, "dev", runner_socket_identity, &executable);
    let mut detached_child = core.children.remove(&environment_id).unwrap();
    core.live_runners.remove(&environment_id).unwrap();
    let config = core.config.clone();
    drop(core);

    // The supervisor is gone and cw is rebuilt in place.
    let rebuilt = directory.join("rebuilt");
    fs::copy(&executable, &rebuilt).unwrap();
    fs::rename(&rebuilt, &executable).unwrap();
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ExecutableReplaced)
    ));

    let supervisor_socket = config.supervisor_socket();
    let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
    let supervisor_socket_identity = tokio::select! {
        result = &mut supervisor => {
            panic!("supervisor exited before listening: {result:?}");
        }
        identity = tokio::time::timeout(LISTENER_HANG_GUARD, async {
            loop {
                if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                    break identity;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }) => identity.expect("supervisor did not reach its listener after startup reconciliation"),
    };

    let root = PrivateRoot::open(&config.root).unwrap();
    let (store, state) = SupervisorStore::inspect(&root).unwrap();
    let environment = state.environments.get("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!runner_socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    let status = detached_child.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
    drop(store);
    drop(root);

    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_replay_cannot_restore_a_runner_quarantined_for_an_unsafe_share() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runner_socket = core.config.runner_socket(environment_id);
    let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, runner_socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
    core.save().unwrap();
    let before = core.environment("dev").unwrap().clone();
    let stale_payload = reconcile_operation_payload(
        &before,
        StoredEnvironmentState::Running,
        before.generation,
        false,
        None,
    );
    let stale = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Reconcile,
            &stale_payload,
        )
        .unwrap();
    let mut detached_child = core.children.remove(&environment_id).unwrap();
    core.live_runners.remove(&environment_id).unwrap();
    core.config.credential_authority_root = source.join("new-credential-authority");
    let config = core.config.clone();
    drop(core);

    let supervisor_socket = config.supervisor_socket();
    let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
    let supervisor_socket_identity = tokio::select! {
        result = &mut supervisor => {
            panic!("supervisor exited before listening: {result:?}");
        }
        identity = tokio::time::timeout(LISTENER_HANG_GUARD, async {
            loop {
                if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                    break identity;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }) => identity.expect("supervisor did not listen after quarantining the unsafe runner"),
    };
    let root = PrivateRoot::open(&config.root).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let reader = SupervisorOperationReader::open(&root).unwrap();
            let operation = reader.operation_by_id(stale.operation_id).unwrap().unwrap();
            if operation.phase == OperationPhase::Completed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let (_store, state) = SupervisorStore::inspect(&root).unwrap();
    let environment = state.environments.get("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!runner_socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));
    let _ = detached_child.wait().unwrap();
    drop(_store);
    drop(root);

    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_quarantines_an_exposing_runner_when_a_private_root_is_unresolvable() {
    let source = tempfile::tempdir().unwrap();
    let source = fs::canonicalize(source.path()).unwrap();
    let mut environment = project_environment();
    environment.workspace_plan = direct_workspace_plan(&source);
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runner_socket = core.config.runner_socket(environment_id);
    let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
        spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
    let (attached_environment_id, process_identity) =
        attach_test_runner_process(&mut core, runner_socket_identity);
    assert_eq!(attached_environment_id, environment_id);
    let mut detached_child = core.children.remove(&environment_id).unwrap();
    core.live_runners.remove(&environment_id).unwrap();
    let platform_alias = _parent.path().join("platform-alias");
    std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias).unwrap();
    core.config.platform_config_dir = platform_alias;
    let config = core.config.clone();
    drop(core);

    let error = refused_startup(&config).await;

    assert!(matches!(error, SupervisorError::InvalidConfiguration));
    assert!(!config.supervisor_socket().exists());
    let root = PrivateRoot::open(&config.root).unwrap();
    let (_store, state) = SupervisorStore::inspect(&root).unwrap();
    let environment = state.environments.get("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert!(!runner_socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        LiveProcess::recover(&process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));
    let _ = detached_child.wait().unwrap();

    shutdown_tx.send(()).unwrap();
    runner_server.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_quarantines_every_unsafe_runner_before_returning_an_earlier_runner_error() {
    let unsafe_source = tempfile::tempdir().unwrap();
    let unsafe_source = fs::canonicalize(unsafe_source.path()).unwrap();
    let mut valid_environment = project_environment();
    valid_environment.name = "a-valid".to_owned();
    let (_parent, mut core) = test_supervisor_core(valid_environment);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let valid_environment_id = core.environment("a-valid").unwrap().id;
    let mut unsafe_environment = project_environment();
    unsafe_environment.id = Uuid::new_v4();
    unsafe_environment.name = "z-unsafe".to_owned();
    unsafe_environment.workspace_plan = direct_workspace_plan(&unsafe_source);
    let unsafe_environment_id = unsafe_environment.id;
    core.state
        .environments
        .insert(unsafe_environment.name.clone(), unsafe_environment);
    core.save().unwrap();

    let valid_socket = core.config.runner_socket(valid_environment_id);
    let (valid_socket_identity, valid_calls, valid_shutdown, valid_server) =
        spawn_test_runner_protocol_server(
            &valid_socket,
            TestRunnerProtocolReply::Failure(tonic::Code::Unavailable),
        );
    let recorded_valid_socket = valid_socket_identity.clone();
    let (attached_valid_id, valid_process_identity) =
        attach_named_test_runner_process(&mut core, "a-valid", valid_socket_identity);
    assert_eq!(attached_valid_id, valid_environment_id);
    let mut valid_child = core.children.remove(&valid_environment_id).unwrap();
    core.live_runners.remove(&valid_environment_id).unwrap();

    let unsafe_socket = core.config.runner_socket(unsafe_environment_id);
    let (unsafe_socket_identity, unsafe_calls, unsafe_shutdown, unsafe_server) =
        spawn_test_runner_protocol_server(&unsafe_socket, TestRunnerProtocolReply::Version(2));
    let (attached_unsafe_id, unsafe_process_identity) =
        attach_named_test_runner_process(&mut core, "z-unsafe", unsafe_socket_identity);
    assert_eq!(attached_unsafe_id, unsafe_environment_id);
    let mut unsafe_child = core.children.remove(&unsafe_environment_id).unwrap();
    core.live_runners.remove(&unsafe_environment_id).unwrap();
    core.config.credential_authority_root = unsafe_source.join("new-credential-authority");
    let config = core.config.clone();
    assert!(core.store.pending_operations().unwrap().is_empty());
    drop(core);

    let error = refused_startup(&config).await;

    assert!(
        matches!(
            error,
            SupervisorError::RunnerService(RunnerServiceError::RunnerProtocolInfoUnavailable)
        ),
        "unexpected startup error: {error:?}"
    );
    assert!(!config.supervisor_socket().exists());
    let root = PrivateRoot::open(&config.root).unwrap();
    let (_store, state) = SupervisorStore::inspect(&root).unwrap();
    let valid_environment = state.environments.get("a-valid").unwrap();
    assert_eq!(valid_environment.state, StoredEnvironmentState::Running);
    assert!(valid_environment.runner.is_some());
    assert!(valid_socket.exists());
    assert!(LiveProcess::recover(&valid_process_identity).is_ok());
    let unsafe_environment = state.environments.get("z-unsafe").unwrap();
    assert_eq!(unsafe_environment.state, StoredEnvironmentState::Error);
    assert!(unsafe_environment.runner.is_none());
    assert!(!unsafe_socket.exists());
    assert!(matches!(
        LiveProcess::recover(&unsafe_process_identity),
        Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
    ));
    assert_eq!(valid_calls.load(Ordering::Relaxed), 0);
    assert_eq!(unsafe_calls.load(Ordering::Relaxed), 0);

    valid_child.kill().unwrap();
    valid_child.wait().unwrap();
    let _ = unsafe_child.wait().unwrap();
    valid_shutdown.send(()).unwrap();
    valid_server.await.unwrap();
    remove_bound_socket(&valid_socket, &recorded_valid_socket).unwrap();
    unsafe_shutdown.send(()).unwrap();
    unsafe_server.await.unwrap();
}

#[tokio::test]
async fn startup_does_not_serve_a_running_state_without_an_exact_runner() {
    let mut environment = project_environment();
    environment.state = StoredEnvironmentState::Running;
    let (_parent, core) = test_supervisor_core(environment);
    fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = core.config.clone();
    assert!(core.store.pending_operations().unwrap().is_empty());
    drop(core);

    let supervisor_socket = config.supervisor_socket();
    let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
    let supervisor_socket_identity = tokio::select! {
        result = &mut supervisor => {
            panic!("supervisor exited before listening: {result:?}");
        }
        identity = tokio::time::timeout(LISTENER_HANG_GUARD, async {
            loop {
                if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                    break identity;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }) => identity.expect("supervisor did not reach its listener after startup reconciliation"),
    };

    let root = PrivateRoot::open(&config.root).unwrap();
    let (_store, state) = SupervisorStore::inspect(&root).unwrap();
    let environment = state.environments.get("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    drop(_store);
    drop(root);

    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
}

#[tokio::test]
async fn recovering_start_waits_for_the_owner_authority_without_losing_intent() {
    let environment = project_environment_with_access();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": 2}),
        )
        .unwrap();

    assert!(matches!(
        core.drain_pending(true).await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Stopped
    );
}

#[tokio::test]
async fn recovering_create_waits_at_its_latest_checkpoint_for_the_owner_authority() {
    let mut environment = project_environment_with_access();
    environment.state = StoredEnvironmentState::Starting;
    environment.generation = 0;
    let environment_id = environment.id;
    let workspace_plan = environment.workspace_plan.clone();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: environment.name.clone(),
        source_path: "/workspace/source".to_owned(),
        vcpus: u32::from(environment.vcpus),
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
        docker_disk_bytes: environment.docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json: environment.project_spec_json.clone().unwrap(),
        project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
        implicit_path_mode: "clone".to_owned(),
        local_mounts: Vec::new(),
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        access_profile_revision: 7,
        access_profile_reference: "user/work".to_owned(),
        platform_source_authority: None,
    };
    let payload = create_operation_payload(&request, &workspace_plan).unwrap();
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = begin_and_advance_test_operation(
        &core.core().store,
        environment_id,
        OperationKind::Create,
        &payload,
        1,
    );

    assert!(matches!(
        core.drain_pending(true).await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::EffectApplied);
    assert_eq!(pending.checkpoint, 1);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Starting
    );
}

#[tokio::test]
async fn recovering_restart_waits_for_the_owner_authority_without_losing_intent() {
    let mut environment = project_environment_with_access();
    environment.state = StoredEnvironmentState::Running;
    let environment_id = environment.id;
    let payload = serde_json::json!({
        "name": "dev",
        "vcpus": environment.vcpus,
        "memory_mib": environment.memory_mib,
        "disk_bytes": environment.disk_bytes,
        "was_running": true,
        "target_generation": environment.generation + 1,
    });
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Restart,
            &payload,
        )
        .unwrap();

    assert!(matches!(
        core.drain_pending(true).await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Running
    );
}

#[tokio::test]
async fn recovering_workspace_update_is_not_aborted_while_the_authority_is_absent() {
    let mut environment = project_environment_with_access();
    let project_spec_json = environment.project_spec_json.clone().unwrap();
    let project_spec_sha256 = environment.project_spec_sha256.clone().unwrap();
    let active = test_workspace_generation(
        &project_spec_json,
        &project_spec_sha256,
        b"authority-recovery",
    );
    environment.active_workspace_generation = Some(active.clone());
    environment.state = StoredEnvironmentState::Running;
    environment.validate("dev").unwrap();
    let environment_id = environment.id;
    let payload =
        workspace_update_payload(&environment, &project_spec_json, &project_spec_sha256, true);
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::UpdateWorkspace,
            &payload,
        )
        .unwrap();

    assert!(matches!(
        core.drain_pending(true).await,
        Err(SupervisorError::CredentialAuthorityUnavailable)
    ));
    let pending = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Running);
    assert_eq!(environment.active_workspace_generation, Some(active));
    assert!(environment.staging_workspace_generation.is_none());
}

#[tokio::test]
async fn a_new_mutation_cannot_terminalize_an_authority_deferred_recovery() {
    let environment = project_environment_with_access();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let pending_request_id = Uuid::new_v4();
    core.store
        .begin_operation(
            pending_request_id,
            Some(environment_id),
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": 2}),
        )
        .unwrap();
    let service = test_supervisor_service(core);
    let new_request_id = Uuid::new_v4();

    let error = service
        .stop_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: new_request_id.to_string(),
            environment_id: environment_id.to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert_eq!(error.message(), "local credential authority is unavailable");
    let core = &service.supervisor;
    assert!(
        core.core()
            .store
            .operation_by_request(new_request_id)
            .unwrap()
            .is_none()
    );
    let pending = core
        .core()
        .store
        .operation_by_request(pending_request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Stopped
    );
}

#[tokio::test]
async fn preboot_delete_replays_after_failed_workspace_admission() {
    for (staged, revoke_access) in [(false, false), (false, true), (true, false)] {
        let mut environment = project_environment();
        environment.generation = 0;
        environment.state = StoredEnvironmentState::Starting;
        if staged {
            environment.staging_workspace_generation =
                Some(test_workspace_generation_with_artifact(
                    environment.project_spec_json.as_deref().unwrap(),
                    environment.project_spec_sha256.as_deref().unwrap(),
                    environment.active_artifact_generation.as_deref().unwrap(),
                    b"synthetic-preboot-image",
                ));
        }
        let environment_id = environment.id;
        let (parent, mut core) = test_supervisor_core(environment);
        // A spawn would fail: deleting this preboot state must need
        // neither an executable runner nor an admitted workspace image.
        core.config.executable = parent.path().join("must-not-spawn");
        let core = test_supervisor(core);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let paths = VmPaths::create(&engine, environment_id).unwrap();
        let create = begin_and_advance_test_operation(
            &core.core().store,
            environment_id,
            OperationKind::Create,
            &serde_json::json!({"name": "dev"}),
            if staged { 4 } else { 3 },
        );
        assert_eq!(
            supervisor_effect(create.kind, create.checkpoint).unwrap(),
            Some(if staged {
                LifecycleEffect::RecordStarting
            } else {
                LifecycleEffect::StageWorkspaceGeneration
            }),
        );
        let failure_code = if staged {
            "create_failed"
        } else {
            "create_registry_blob_stream"
        };
        core.core()
            .fail_operation_with_environment_error(&create, "dev", failure_code)
            .unwrap();
        let delete = core
            .core()
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Delete,
                &serde_json::json!({"name": "dev", "revoke_access": revoke_access}),
            )
            .unwrap();

        core.drain_pending(true).await.unwrap();

        let reader = SupervisorOperationReader::open(&core.root).unwrap();
        let deleted = reader
            .operation_by_id(delete.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(deleted.phase, OperationPhase::Completed);
        assert_eq!(deleted.result.as_ref().unwrap()["removed"], true);
        // Absent authority remains an honest pending revocation, not a
        // reason to boot the failed environment or conceal cleanup work.
        assert_eq!(
            deleted.result.as_ref().unwrap()["cleanup_pending"],
            revoke_access
        );
        let failed = reader
            .operation_by_id(create.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(failed.phase, OperationPhase::Failed);
        assert_eq!(failed.error_code.as_deref(), Some(failure_code));
        assert!(core.core().state.environments.is_empty());
        assert!(core.core().state.current.is_none());
        assert!(core.core().children.is_empty());
        assert!(core.core().live_runners.is_empty());
        assert!(!paths.vm_dir.exists());
        assert!(matches!(
            deletion_tree_location(
                &core.config.engine_root(),
                environment_id,
                delete.operation_id
            )
            .unwrap(),
            DeletionTreeLocation::Missing,
        ));
    }
}

#[tokio::test]
async fn preboot_delete_does_not_skip_missing_workspace_after_boot_or_stop() {
    for (generation, state) in [
        (1, StoredEnvironmentState::Error),
        (1, StoredEnvironmentState::Stopped),
        (0, StoredEnvironmentState::Stopped),
    ] {
        let mut environment = project_environment();
        environment.generation = generation;
        environment.state = state;
        let environment_id = environment.id;
        let (_parent, core) = test_supervisor_core(environment);
        let core = test_supervisor(core);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let paths = VmPaths::create(&engine, environment_id).unwrap();

        assert!(matches!(
            core.prepare_environment_for_delete("dev").await,
            Err(SupervisorError::InvalidState),
        ));
        assert!(paths.vm_dir.exists());
        assert!(core.core().state.environments.contains_key("dev"));
    }
}

#[tokio::test]
async fn preboot_delete_does_not_reclassify_a_recorded_dead_runner() {
    let environment = project_environment();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let core = test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let paths = VmPaths::create(&engine, environment_id).unwrap();
    let (listener, identity) =
        bind_owner_only_listener(&core.config.runner_socket(environment_id)).unwrap();
    attach_test_runner_process(&mut core.core(), identity);
    {
        let mut guard = core.core();
        let environment = guard.environment_mut("dev").unwrap();
        environment.generation = 0;
        environment.state = StoredEnvironmentState::Error;
        guard.save().unwrap();
    }
    let mut child = core.core().children.remove(&environment_id).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(matches!(
        core.prepare_environment_for_delete("dev").await,
        Err(SupervisorError::InvalidState),
    ));
    assert!(
        core.environment("dev").unwrap().runner.is_none(),
        "reconciliation observed the dead runner"
    );
    assert!(paths.vm_dir.exists());
    drop(listener);
}

#[test]
fn delete_cleanup_boots_the_staged_artifact_of_a_create_that_failed_at_vm_start() {
    let mut environment = project_environment();
    let artifact = environment.active_artifact_generation.clone().unwrap();
    environment.generation = 1;
    environment.state = StoredEnvironmentState::Error;
    // Without any workspace generation there is nothing to boot.
    assert!(matches!(
        delete_cleanup_artifact_generation(&environment),
        Err(SupervisorError::InvalidState)
    ));
    let generation = test_workspace_generation_with_artifact(
        environment.project_spec_json.as_deref().unwrap(),
        environment.project_spec_sha256.as_deref().unwrap(),
        &artifact,
        b"failed-at-vm-start",
    );
    environment.staging_workspace_generation = Some(generation.clone());
    assert_eq!(
        delete_cleanup_artifact_generation(&environment).unwrap(),
        artifact
    );
    // A promoted environment keeps using its active generation.
    environment.active_workspace_generation = Some(generation);
    environment.staging_workspace_generation = None;
    assert_eq!(
        delete_cleanup_artifact_generation(&environment).unwrap(),
        artifact
    );
}

#[tokio::test]
async fn a_delete_that_fails_before_trash_is_retained_and_does_not_stop_the_worker() {
    for recovering in [true, false] {
        let mut environment = project_environment();
        // Booted, no runner and no workspace to boot: PrepareDelete fails.
        environment.generation = 1;
        environment.state = StoredEnvironmentState::Stopped;
        let environment_id = environment.id;
        let (_parent, core) = test_supervisor_core(environment);
        let core = test_supervisor(core);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let paths = VmPaths::create(&engine, environment_id).unwrap();
        let delete = core
            .core()
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Delete,
                &serde_json::json!({"name": "dev", "revoke_access": false}),
            )
            .unwrap();

        if recovering {
            core.drain_pending(true).await.unwrap();
        } else {
            core.drain_pending(false).await.unwrap();
        }

        let failed = SupervisorOperationReader::open(&core.root)
            .unwrap()
            .operation_by_id(delete.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(failed.phase, OperationPhase::Failed);
        assert_eq!(
            failed.error_code.as_deref(),
            Some(if recovering {
                "delete_interrupted"
            } else {
                "delete_failed"
            })
        );
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Error
        );
        assert!(paths.vm_dir.exists());
        assert!(core.core().store.pending_operations().unwrap().is_empty());
        // Replaying again finds nothing to do.
        core.drain_pending(true).await.unwrap();
    }
}

#[tokio::test]
async fn a_watch_of_an_unfinished_operation_ends_when_the_supervisor_stops() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let operation = {
        let core = &service.supervisor;
        let environment = core.environment("dev").unwrap();
        core.core()
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment.id),
                OperationKind::Delete,
                &serde_json::json!({"name": "dev", "revoke_access": false}),
            )
            .unwrap()
    };
    let mut stream = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: operation.operation_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    let initial = tokio::time::timeout(
        Duration::from_secs(5),
        futures::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(initial.is_ok());
    service.supervisor.shutdown.send(true).unwrap();
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        futures::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
    assert_eq!(ended.code(), tonic::Code::Unavailable);
    assert!(ended.message().contains("run the command again"));
    let refused = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: operation.operation_id.to_string(),
        }))
        .await
        .err()
        .unwrap();
    assert_eq!(refused.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn delete_replay_preserves_the_stable_environment_precondition() {
    let environment = project_environment();
    let environment_id = environment.id;
    let request_id = Uuid::new_v4();
    let (_parent, core) = test_supervisor_core(environment);
    core.store
        .begin_operation(
            request_id,
            Some(environment_id),
            OperationKind::Delete,
            &serde_json::json!({"name": "dev", "revoke_access": false}),
        )
        .unwrap();
    let service = test_supervisor_service(core);

    let error = service
        .delete_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: request_id.to_string(),
            environment_id: Uuid::new_v4().to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    assert_eq!(error.message(), "local environment was not found");
    let core = &service.supervisor;
    let pending = core
        .core()
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, OperationPhase::Intent);
    assert_eq!(pending.checkpoint, 0);
    assert_eq!(core.environment("dev").unwrap().id, environment_id);
}

#[tokio::test]
async fn start_replay_cannot_cross_a_recreated_environment_identity() {
    let environment = project_environment();
    let current_environment_id = environment.id;
    let prior_environment_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let (_parent, core) = test_supervisor_core(environment);
    core.store
        .begin_operation(
            request_id,
            Some(prior_environment_id),
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": 2}),
        )
        .unwrap();
    let service = test_supervisor_service(core);

    let error = service
        .start_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: request_id.to_string(),
            environment_id: current_environment_id.to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Aborted);
    assert_eq!(error.message(), "local lifecycle request ID collision");
}

#[tokio::test]
async fn native_client_waits_for_the_durable_terminal_operation() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let socket = core.config.supervisor_socket();
    let service = test_supervisor_service(core);
    let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_service = service.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, public_api::supervisor_router(server_service))
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let mut client = NativeSupervisorClient::connect(&socket).await.unwrap();
    let environment = client.stop("dev").await.unwrap();
    assert_eq!(
        v1::EnvironmentState::try_from(environment.state).unwrap(),
        v1::EnvironmentState::Stopped
    );
    {
        let core = &service.supervisor;
        assert!(core.core().store.pending_operations().unwrap().is_empty());
    }

    drop(client);
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
}

#[tokio::test]
async fn native_client_admits_the_current_protocol_and_configuration() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let config = core.config.clone();
    let socket = config.supervisor_socket();
    let service = test_supervisor_service(core);
    let (socket_identity, shutdown_tx, server) = spawn_test_supervisor_server(&socket, service);

    // The in-process RPC fixture has no native-supervisor role argv.
    // Keep full-digest/protocol proof on the generic pinned API.
    let mut client =
        NativeSupervisorClient::connect_admitted(&socket, Some(config.configuration_digest()))
            .await
            .unwrap();
    assert_eq!(client.list().await.unwrap().len(), 1);

    drop(client);
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
}

#[tokio::test]
async fn native_client_rejects_an_old_supervisor_without_the_info_rpc() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("runtime");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("supervisor.sock");
    let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
    let app = axum::Router::new().route(
        "/codewire.local.v1.LocalSupervisorService/GetSupervisorInfo",
        axum::routing::post(|| async {
            let mut response = axum::response::Response::new(axum::body::Body::empty());
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
            response.headers_mut().insert(
                http::HeaderName::from_static("grpc-status"),
                http::HeaderValue::from_static("12"),
            );
            response
        }),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let error = match NativeSupervisorClient::connect(&socket).await {
        Ok(_) => panic!("old supervisor was admitted"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        SupervisorError::SupervisorProtocolUnavailable
    ));
    assert_eq!(
        error.to_string(),
        "the running native supervisor does not implement the required compatibility protocol"
    );

    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
}

#[tokio::test]
async fn a_supervisor_listening_on_the_roots_own_socket_is_admitted_not_replaced() {
    let (parent, core) = test_supervisor_core(project_environment());
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = core.config.clone();
    drop(core);
    // Where a supervisor from before #2735 (protocol 10) listens.
    let legacy = config.legacy_supervisor_socket();
    let _listener = std::os::unix::net::UnixListener::bind(&legacy).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    let error = match NativeSupervisorClient::connect_or_start(&config).await {
        Ok(_) => panic!("this test process was admitted as a supervisor"),
        Err(error) => error,
    };
    // Admission ran against it (this process is no supervisor), and no
    // replacement started at the current socket.
    assert!(
        matches!(
            &error,
            SupervisorError::Uds(UdsError::SupervisorPeerAdmission(_))
        ),
        "{error:?}"
    );
    assert!(!config.supervisor_socket().exists());
    assert!(legacy.exists());
}

#[tokio::test]
async fn connect_or_start_rejects_a_live_supervisor_with_different_configuration() {
    let (parent, core) = test_supervisor_core(project_environment());
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = core.config.clone();
    let socket = config.supervisor_socket();
    let service = test_supervisor_service(core);
    let (socket_identity, shutdown_tx, server) = spawn_test_supervisor_server(&socket, service);
    let mut wrong_config = config.clone();
    wrong_config.credential_authority_root = config
        .credential_authority_root
        .with_file_name("different-credentials");

    let error = match NativeSupervisorClient::connect_admitted(
        &socket,
        Some(wrong_config.configuration_digest()),
    )
    .await
    .map_err(SupervisorError::from)
    {
        Ok(_) => panic!("differently configured supervisor was admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, SupervisorError::SupervisorConfigurationMismatch),
        "unexpected compatibility error: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the running native supervisor uses a different runtime configuration"
    );
    // The production entry additionally refuses this process, whose
    // executable is neither this cw nor a retained managed version, before
    // any startup fallback or metadata effects.
    assert!(matches!(
        NativeSupervisorClient::connect_or_start(&wrong_config).await,
        Err(SupervisorError::Uds(UdsError::SupervisorPeerAdmission(_)))
    ));
    // The incompatible live process remains available; only this reuse
    // attempt failed, and no replacement was started over its socket.
    assert!(NativeSupervisorClient::connect(&socket).await.is_ok());

    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
    remove_bound_socket(&socket, &socket_identity).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reconcile_quarantines_an_unsafe_recovered_runner_without_trusting_its_socket() {
    for replace_socket in [false, true] {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let (_parent, mut core) = test_supervisor_core(environment);
        let socket = core
            .config
            .runner_socket(core.environment("dev").unwrap().id);
        let (socket_identity, useful_calls, shutdown_tx, server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
        let recorded_socket = socket_identity.clone();
        let (environment_id, process_identity) =
            attach_test_runner_process(&mut core, socket_identity);
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();

        if replace_socket {
            remove_bound_socket(&socket, &recorded_socket).unwrap();
            fs::write(&socket, b"untrusted replacement").unwrap();
        }
        core.config.credential_authority_root = source.join("new-credential-authority");
        let core = test_supervisor(core);

        core.reconcile("dev").await.unwrap();

        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!core.core().live_runners.contains_key(&environment_id));
        assert!(!core.core().children.contains_key(&environment_id));
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        if replace_socket {
            assert_eq!(fs::read(&socket).unwrap(), b"untrusted replacement");
        } else {
            assert!(!socket.exists());
        }
        let _ = detached_child.wait().unwrap();
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn incompatible_runner_inspection_preserves_custody_and_explicit_cleanup_works() {
    for reply in [
        TestRunnerProtocolReply::Version(3),
        TestRunnerProtocolReply::Failure(tonic::Code::Unimplemented),
    ] {
        for delete in [false, true] {
            let (_parent, mut core) = test_supervisor_core(project_environment());
            let socket = core
                .config
                .runner_socket(core.environment("dev").unwrap().id);
            let (socket_identity, useful_calls, shutdown_tx, server) =
                spawn_test_runner_protocol_server(&socket, reply);
            let (environment_id, process_identity) =
                attach_test_runner_process(&mut core, socket_identity);
            let before = core.environment("dev").unwrap().clone();

            let service = test_supervisor_service(core);
            service
                .supervisor
                .reconcile_exposing_runners_for_startup()
                .await
                .unwrap();
            let listed = service
                .list_environments(Request::new(v1::ListEnvironmentsRequest {}))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(listed.environments.len(), 1);
            assert_eq!(
                listed.environments[0].error_code,
                "runner_protocol_unsupported"
            );
            let inspected = service
                .get_environment(Request::new(read_selector("dev")))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(inspected.state, v1::EnvironmentState::Running as i32);
            assert_eq!(inspected.error_code, "runner_protocol_unsupported");
            let core = &service.supervisor;
            assert_eq!(core.environment("dev").unwrap(), before);
            assert_eq!(
                SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
                before
            );
            assert!(core.core().live_runners.contains_key(&environment_id));
            assert!(
                core.core()
                    .children
                    .get_mut(&environment_id)
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none()
            );
            assert!(socket.exists());
            assert!(matches!(
                core.runner_client_for_artifact(
                    "dev",
                    &before.runner.as_ref().unwrap().artifact_generation
                )
                .await,
                Err(SupervisorError::RunnerProtocolUnsupported)
            ));
            assert_eq!(useful_calls.load(Ordering::Relaxed), 0);

            if delete {
                core.prepare_environment_for_delete("dev").await.unwrap();
            } else {
                core.ensure_vm_stopped("dev").await.unwrap();
            }
            assert!(core.environment("dev").unwrap().runner.is_none());
            assert!(!core.core().live_runners.contains_key(&environment_id));
            assert!(!core.core().children.contains_key(&environment_id));
            assert!(!socket.exists());
            assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
            assert!(matches!(
                LiveProcess::recover(&process_identity),
                Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
            ));
            shutdown_tx.send(()).unwrap();
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn reconcile_does_not_kill_a_runner_for_a_transient_protocol_query_failure() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let socket = core
        .config
        .runner_socket(core.environment("dev").unwrap().id);
    let (socket_identity, useful_calls, shutdown_tx, server) = spawn_test_runner_protocol_server(
        &socket,
        TestRunnerProtocolReply::Failure(tonic::Code::Unavailable),
    );
    let (environment_id, _process_identity) =
        attach_test_runner_process(&mut core.core(), socket_identity);

    let error = core.reconcile("dev").await.unwrap_err();

    assert!(matches!(
        error,
        SupervisorError::RunnerService(RunnerServiceError::RunnerProtocolInfoUnavailable)
    ));
    assert!(!error.to_string().contains("untrusted test peer detail"));
    assert!(core.environment("dev").unwrap().runner.is_some());
    assert!(core.core().live_runners.contains_key(&environment_id));
    assert!(
        core.core()
            .children
            .get_mut(&environment_id)
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert!(socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);

    core.terminate_recorded_runner("dev").await.unwrap();
    core.core().mark_runner_dead("dev").unwrap();
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn old_guest_start_refuses_before_checkpoint_or_runner_effects() {
    for (checkpoint, staged) in [(0, false), (1, false), (0, true), (3, true)] {
        let (_parent, core) = test_supervisor_core(project_environment());
        let core = test_supervisor(core);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let generation =
            install_test_guest_generation(&engine, b"\0CWGUESTABI\0seed=8;cw_catalog=0\0");
        {
            let mut guard = core.core();
            let environment = guard.environment_mut("dev").unwrap();
            if staged {
                environment.active_workspace_generation =
                    Some(test_workspace_generation_with_artifact(
                        environment.project_spec_json.as_deref().unwrap(),
                        environment.project_spec_sha256.as_deref().unwrap(),
                        &generation,
                        b"old-start-guest",
                    ));
            }
            environment.active_artifact_generation = Some(generation);
            guard.save().unwrap();
        }
        let socket = core
            .config
            .runner_socket(core.environment("dev").unwrap().id);
        let (socket_identity, useful_calls, shutdown_tx, server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(3));
        let (environment_id, _) = attach_test_runner_process(&mut core.core(), socket_identity);
        let before = core.environment("dev").unwrap().clone();
        let operation = begin_and_advance_test_operation(
            &core.core().store,
            environment_id,
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": before.generation + 1}),
            checkpoint,
        );

        let error = core.start("dev", &operation).await.unwrap_err();
        assert!(matches!(
            error,
            SupervisorError::Artifact(
                crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_)
            )
        ));
        assert_eq!(core.environment("dev").unwrap(), before);
        assert_eq!(
            SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
            before
        );
        assert_eq!(
            core.core()
                .store
                .operation_by_request(operation.request_id)
                .unwrap()
                .unwrap(),
            operation
        );
        assert!(
            core.core()
                .children
                .get_mut(&environment_id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        assert!(socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);

        core.terminate_recorded_runner("dev").await.unwrap();
        core.core().mark_runner_dead("dev").unwrap();
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn first_start_admits_only_its_retained_boot_assets() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let generation =
        install_test_guest_generation(&engine, codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER);
    core.core()
        .environment_mut("dev")
        .unwrap()
        .active_artifact_generation = Some(generation.clone());
    core.core().save().unwrap();
    // First staging must use retained assets, even when installed defaults
    // changed or are invalid. It must not implicitly select a cw runtime.
    fs::write(
        &core.config.artifact_lock,
        b"invalid installed boot default",
    )
    .unwrap();
    fs::write(
        core.config.cw_runtime_lock(),
        b"invalid installed cw default",
    )
    .unwrap();
    let before = core.environment("dev").unwrap().clone();
    core.admit_start_boot_inputs("dev").await.unwrap();
    assert_eq!(core.environment("dev").unwrap(), before);
    assert!(!core.config.engine_root().join("cw-runtimes").exists());

    for retained in [None, Some("B".repeat(64))] {
        core.core()
            .environment_mut("dev")
            .unwrap()
            .active_artifact_generation = retained;
        assert!(matches!(
            core.admit_start_boot_inputs("dev").await,
            Err(SupervisorError::InvalidState)
        ));
    }
    core.core()
        .environment_mut("dev")
        .unwrap()
        .active_artifact_generation = Some(generation.clone());
    core.core()
        .environment_mut("dev")
        .unwrap()
        .staging_artifact_generation = Some(generation);
    assert!(matches!(
        core.admit_start_boot_inputs("dev").await,
        Err(SupervisorError::InvalidState)
    ));
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn restart_without_a_workspace_refuses_before_retiring_a_live_runner() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let generation =
        install_test_guest_generation(&engine, codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER);
    core.core()
        .environment_mut("dev")
        .unwrap()
        .active_artifact_generation = Some(generation);
    core.core().save().unwrap();
    let socket = core
        .config
        .runner_socket(core.environment("dev").unwrap().id);
    let (socket_identity, useful_calls, shutdown_tx, server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(3));
    let (environment_id, _) = attach_test_runner_process(&mut core.core(), socket_identity);
    let before = core.environment("dev").unwrap().clone();
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Restart,
            &serde_json::json!({"name": "dev", "vcpus": before.vcpus,
                "memory_mib": before.memory_mib, "disk_bytes": before.disk_bytes,
                "was_running": true, "target_generation": before.generation + 1}),
        )
        .unwrap();
    core.reconcile("dev").await.unwrap();
    assert!(matches!(
        core.require_environment_guest_seed_abi("dev", false).await,
        Err(SupervisorError::InvalidState)
    ));
    assert!(matches!(
        core.resize("dev", &operation).await,
        Err(SupervisorError::ReplacementPreflight(inner))
        if matches!(inner.as_ref(), SupervisorError::InvalidState)
    ));
    assert_eq!(core.environment("dev").unwrap(), before);
    assert_eq!(
        SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
        before
    );
    assert!(
        core.core()
            .children
            .get_mut(&environment_id)
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert!(socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    core.ensure_vm_stopped("dev").await.unwrap();
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn old_guest_restart_refuses_before_retiring_an_incompatible_runner() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let generation = install_test_guest_generation(&engine, b"\0CWGUESTABI\0seed=8;cw_catalog=0\0");
    {
        let mut guard = core.core();
        let environment = guard.environment_mut("dev").unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            &generation,
            b"old-guest",
        ));
        environment.active_artifact_generation = Some(generation);
        guard.save().unwrap();
    }
    let socket = core
        .config
        .runner_socket(core.environment("dev").unwrap().id);
    let (socket_identity, useful_calls, shutdown_tx, server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(3));
    let (environment_id, _) = attach_test_runner_process(&mut core.core(), socket_identity);
    let before = core.environment("dev").unwrap().clone();
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Restart,
            &serde_json::json!({"name": "dev", "vcpus": before.vcpus,
                "memory_mib": before.memory_mib, "disk_bytes": before.disk_bytes,
                "was_running": true, "target_generation": before.generation + 1}),
        )
        .unwrap();
    core.reconcile("dev").await.unwrap();
    let error = core.resize("dev", &operation).await.unwrap_err();
    assert!(
        matches!(&error, SupervisorError::ReplacementPreflight(inner)
            if matches!(inner.as_ref(), SupervisorError::Artifact(
                crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_))))
    );
    let status = Status::from(error);
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(status.message().contains("boot assets"));
    assert_eq!(core.environment("dev").unwrap(), before);
    assert_eq!(
        SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
        before
    );
    assert!(
        core.core()
            .children
            .get_mut(&environment_id)
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert!(socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    assert!(core.environment("dev").unwrap().cw_runtime.is_none());
    core.ensure_vm_stopped("dev").await.unwrap();
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ordinary_boot_keeps_an_unbound_environment_unbound() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    core.core().environment_mut("dev").unwrap().state = StoredEnvironmentState::Running;
    core.core().save().unwrap();
    // A newly installed, even invalid, default is outside this environment's
    // retained selection. Ordinary start/restart must not read or bind it.
    fs::write(core.config.cw_runtime_lock(), b"invalid installed default").unwrap();
    let before = core.environment("dev").unwrap().clone();
    assert!(
        core.admit_environment_cw_runtime("dev")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(core.environment("dev").unwrap(), before);
    assert_eq!(
        SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
        before
    );
    assert!(!core.config.engine_root().join("cw-runtimes").exists());
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn workspace_rollback_preflight_restores_metadata_without_stopping_the_vm() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let core = test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let active =
        install_test_guest_generation(&engine, codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER);
    let old = install_test_guest_generation(&engine, b"\0CWGUESTABI\0seed=8;cw_catalog=0\0");
    {
        let mut guard = core.core();
        let environment = guard.environment_mut("dev").unwrap();
        let json = environment.project_spec_json.as_deref().unwrap();
        let sha = environment.project_spec_sha256.as_deref().unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
            json, sha, &active, b"active",
        ));
        environment.rollback_workspace_generation = Some(test_workspace_generation_with_artifact(
            json,
            sha,
            &old,
            b"rollback",
        ));
        environment.active_artifact_generation = Some(active);
        guard.save().unwrap();
    }
    let socket = core
        .config
        .runner_socket(core.environment("dev").unwrap().id);
    let (identity, useful_calls, shutdown_tx, server) =
        spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(3));
    let (environment_id, _) = attach_test_runner_process(&mut core.core(), identity);
    let before = core.environment("dev").unwrap().clone();
    let operation = core
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::RollbackWorkspace,
            &workspace_rollback_payload(&before, true),
        )
        .unwrap();

    core.drain_pending(false).await.unwrap();

    let failed = core
        .core()
        .store
        .operation_by_request(operation.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(failed.phase, OperationPhase::Failed);
    // The StopVm preflight fails at checkpoint 2; recording its terminal
    // failure advances the journal without performing the stop effect.
    assert_eq!(failed.checkpoint, 3);
    assert_eq!(
        failed.error_code.as_deref(),
        Some("workspace_rollback_preflight")
    );
    assert_eq!(core.environment("dev").unwrap(), before);
    assert_eq!(
        SupervisorStore::inspect(&core.root).unwrap().1.environments["dev"],
        before
    );
    assert!(core.core().store.pending_operations().unwrap().is_empty());
    assert!(
        core.core()
            .children
            .get_mut(&environment_id)
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert!(socket.exists());
    assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
    core.ensure_vm_stopped("dev").await.unwrap();
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[test]
fn staging_a_runtime_preserves_the_active_runner_attachment() {
    let mut environment = project_environment();
    environment.state = StoredEnvironmentState::Running;
    environment.cw_runtime = Some(CwRuntimeBinding {
        schema_version: 1,
        active_catalog_generation: "a".repeat(64),
        staging_catalog_generation: Some("b".repeat(64)),
        rollback_catalog_generation: None,
    });
    let record = RunnerRecord {
        process: ProcessIdentity {
            pid: 42,
            boot_id: "boot".to_owned(),
            start_time_ticks: 1,
            executable: PathBuf::from("/bin/cw"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode: 1,
                size: 1,
                uid: unsafe { libc::getuid() },
                mode: 0o100500,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "d".repeat(64),
        },
        socket: SocketIdentity {
            uid: unsafe { libc::getuid() },
            device: 1,
            inode: 2,
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation: environment.active_artifact_generation.clone().unwrap(),
        cw_runtime_catalog_generation: Some("a".repeat(64)),
        error_code: None,
    };
    let mut info = v1::RunnerInfo {
        cw_runtime_catalog_generation: "a".repeat(64),
        ..Default::default()
    };
    assert!(runner_cw_runtime_identity_matches(
        &environment,
        &record,
        &info,
        StoredEnvironmentState::Running
    ));
    info.cw_runtime_catalog_generation = "b".repeat(64);
    assert!(!runner_cw_runtime_identity_matches(
        &environment,
        &record,
        &info,
        StoredEnvironmentState::Running
    ));
    let mut next_record = record.clone();
    next_record.cw_runtime_catalog_generation = None;
    environment.state = StoredEnvironmentState::Starting;
    assert!(runner_cw_runtime_identity_matches(
        &environment,
        &next_record,
        &info,
        StoredEnvironmentState::Running
    ));
    info.cw_runtime_catalog_generation = "c".repeat(64);
    assert!(!runner_cw_runtime_identity_matches(
        &environment,
        &next_record,
        &info,
        StoredEnvironmentState::Running
    ));
    info.cw_runtime_catalog_generation.clear();
    assert!(runner_cw_runtime_identity_matches(
        &environment,
        &next_record,
        &info,
        StoredEnvironmentState::Stopped
    ));
    assert!(!runner_cw_runtime_identity_matches(
        &environment,
        &next_record,
        &info,
        StoredEnvironmentState::Running
    ));
}

#[test]
fn supervisor_info_refuses_outside_the_supported_range_and_a_bad_digest_shape() {
    let config = test_supervisor_core(project_environment()).1.config;
    let mut info = supervisor_info(&config);
    info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1;
    let error = admit_supervisor_info(&info, None).unwrap_err();
    assert!(matches!(
        error,
        SupervisorError::SupervisorProtocolMismatch {
            expected: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
            actual,
        } if actual == NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1
    ));
    assert!(
        error
            .to_string()
            .starts_with("a newer cw runs your local VMs")
    );

    info.protocol_version = crate::supervisor_config::MINIMUM_SUPERVISOR_PROTOCOL_VERSION - 1;
    assert!(matches!(
        admit_supervisor_info(&info, None),
        Err(SupervisorError::SupervisorProtocolMismatch { .. })
    ));

    info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION;
    info.configuration_sha256.pop();
    assert!(matches!(
        admit_supervisor_info(&info, None),
        Err(SupervisorError::InvalidSupervisorInfo)
    ));
}

#[test]
fn forbidden_direct_roots_resolve_existing_configuration_symlinks() {
    let private = tempfile::tempdir().unwrap();
    let real_platform = private.path().join("real-platform");
    fs::create_dir(&real_platform).unwrap();
    fs::set_permissions(&real_platform, fs::Permissions::from_mode(0o700)).unwrap();
    let platform_alias = private.path().join("platform-alias");
    std::os::unix::fs::symlink(&real_platform, &platform_alias).unwrap();
    let (_runtime, mut core) = test_supervisor_core(project_environment());
    core.config.platform_config_dir = platform_alias;

    let forbidden_roots = core.config.direct_share_forbidden_roots().unwrap();

    assert!(forbidden_roots.contains(&fs::canonicalize(&real_platform).unwrap()));
    assert!(matches!(
        prepare_direct_input(
            &fs::canonicalize(private.path()).unwrap(),
            "/workspace/private",
            true,
            Vec::new(),
            &forbidden_roots,
        ),
        Err(WorkspacePlanError::DirectShareInvalid)
    ));
    assert!(matches!(
        prepare_direct_input(
            &fs::canonicalize(&real_platform).unwrap(),
            "/workspace/private",
            true,
            Vec::new(),
            &forbidden_roots,
        ),
        Err(WorkspacePlanError::DirectShareInvalid)
    ));
}

#[test]
fn forbidden_direct_roots_resolve_missing_suffix_beneath_a_symlink() {
    let private = tempfile::tempdir().unwrap();
    let real_platform = private.path().join("real-platform");
    fs::create_dir(&real_platform).unwrap();
    let platform_alias = private.path().join("platform-alias");
    std::os::unix::fs::symlink(&real_platform, &platform_alias).unwrap();
    let configured = platform_alias.join("future/config");
    let expected = real_platform.join("future/config");
    let (_runtime, mut core) = test_supervisor_core(project_environment());
    core.config.platform_config_dir = configured;

    let before_creation = core.config.direct_share_forbidden_roots().unwrap();
    assert!(before_creation.contains(&expected));

    fs::create_dir_all(&expected).unwrap();
    let after_creation = core.config.direct_share_forbidden_roots().unwrap();
    assert!(after_creation.contains(&fs::canonicalize(expected).unwrap()));
}

/// The per-user socket directories hold the supervisor's, VMs' and the
/// credential authority's sockets; no direct share may expose them.
#[test]
fn the_socket_directories_are_never_shared() {
    let (_runtime, core) = test_supervisor_core(project_environment());
    let sockets = crate::socket_dir::prepare(&core.config.root).unwrap();
    let base = fs::canonicalize(sockets.parent().unwrap()).unwrap();
    let forbidden_roots = core.config.direct_share_forbidden_roots().unwrap();
    assert!(forbidden_roots.contains(&base), "{forbidden_roots:?}");
    for source in [&base, &sockets] {
        assert!(matches!(
            prepare_direct_input(
                source,
                "/workspace/private",
                true,
                Vec::new(),
                &forbidden_roots
            ),
            Err(WorkspacePlanError::DirectShareInvalid)
        ));
    }
}

#[tokio::test]
async fn operation_watch_starts_from_durable_state_and_ends_at_terminal_state() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let operation = {
        let core = &service.supervisor;
        let environment = core.environment("dev").unwrap();
        core.core()
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment.id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 1}),
            )
            .unwrap()
    };
    let operation_id = operation.operation_id;
    let response = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: operation_id.to_string(),
        }))
        .await
        .unwrap();
    let mut stream = response.into_inner();
    let initial = tokio::time::timeout(
        Duration::from_secs(1),
        futures::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(initial.operation_id, operation_id.to_string());
    assert_eq!(initial.checkpoint, 0);
    assert_eq!(
        v1::OperationStage::try_from(initial.stage).unwrap(),
        v1::OperationStage::RequireEnvironmentAccess
    );

    assert!(
        service
            .operation_progress
            .send(OperationProgress {
                operation_id,
                event: v1::RunnerEvent {
                    sequence: 4,
                    runner: Some(v1::RunnerInfo {
                        cw_runtime_catalog_generation: String::new(),
                        environment_id: operation.environment_id.unwrap().to_string(),
                        state: v1::EnvironmentState::Starting as i32,
                        generation: 1,
                        artifact_generation: "a".repeat(64),
                        error_code: String::new(),
                    }),
                    stage: v1::RunnerStage::GuestInit as i32,
                    guest_sequence: 3,
                    guest_stage: v1::GuestBootStage::WorkspacePlanReady as i32,
                    error_code: String::new(),
                },
            })
            .is_ok()
    );
    let progress = tokio::time::timeout(
        Duration::from_secs(1),
        futures::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(progress.checkpoint, initial.checkpoint);
    assert_eq!(progress.progress_sequence, 4);
    assert_eq!(
        v1::RunnerStage::try_from(progress.runner_stage).unwrap(),
        v1::RunnerStage::GuestInit
    );
    assert_eq!(progress.guest_sequence, 3);

    {
        let core = &service.supervisor;
        let result = environment_operation_result(&core.environment("dev").unwrap());
        core.core()
            .store
            .advance_operation(
                operation_id,
                operation.checkpoint,
                OperationPhase::Completed,
                Some(&result),
                None,
            )
            .unwrap();
    }
    let terminal = tokio::time::timeout(
        Duration::from_secs(1),
        futures::StreamExt::next(&mut stream),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(
        v1::OperationPhase::try_from(terminal.phase).unwrap(),
        v1::OperationPhase::Completed
    );
    assert_eq!(
        v1::OperationStage::try_from(terminal.stage).unwrap(),
        v1::OperationStage::Completed
    );
    assert!(terminal.result.is_some());
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut stream)
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn dropping_an_operation_watch_does_not_cancel_the_durable_operation() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let operation = {
        let core = &service.supervisor;
        let environment = core.environment("dev").unwrap();
        core.core()
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment.id),
                OperationKind::Stop,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap()
    };
    let response = service
        .watch_operation(Request::new(v1::WatchOperationRequest {
            operation_id: operation.operation_id.to_string(),
        }))
        .await
        .unwrap();
    let mut stream = response.into_inner();
    assert!(futures::StreamExt::next(&mut stream).await.unwrap().is_ok());
    drop(stream);

    let completed = {
        let core = &service.supervisor;
        let result = environment_operation_result(&core.environment("dev").unwrap());
        core.core()
            .store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Completed,
                Some(&result),
                None,
            )
            .unwrap()
    };
    assert_eq!(
        service.operation(operation.operation_id).await.unwrap(),
        completed
    );
}

fn artifact_is_present(engine: &PrivateRoot, generation: &str) -> bool {
    engine
        .path()
        .join(format!("runtime-artifacts/generations/{generation}.json"))
        .is_file()
}

#[tokio::test]
async fn generation_publication_serializes_all_generation_collectors() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);

    // Model the create/staging transaction after it has published bytes to
    // the three generation stores but before it has durably published the
    // references: a content writer in flight (#2978). No collection may run
    // across that boundary.
    let writer = service.supervisor.content_writer().await;
    let create = &service.supervisor;
    let engine = PrivateRoot::open(&create.config.engine_root()).unwrap();
    let (candidate_artifact, candidate_kernel) =
        install_test_artifact_generation(&engine, b"candidate-kernel");
    let (stale_artifact, stale_kernel) = install_test_artifact_generation(&engine, b"stale-kernel");
    let candidate_workspace = test_workspace_generation_with_artifact(
        create
            .environment("dev")
            .unwrap()
            .project_spec_json
            .as_deref()
            .unwrap(),
        create
            .environment("dev")
            .unwrap()
            .project_spec_sha256
            .as_deref()
            .unwrap(),
        &candidate_artifact,
        b"candidate",
    );
    let candidate_storage = workspace_storage_generation(&candidate_workspace).unwrap();
    let stale_storage = "f".repeat(64);
    let paths = VmPaths::create(&engine, create.environment("dev").unwrap().id).unwrap();
    for storage in [&candidate_storage, &stale_storage] {
        let generation = crate::state::RootGenerationPaths::create(&paths, storage).unwrap();
        fs::write(&generation.root_disk, b"root").unwrap();
        fs::set_permissions(&generation.root_disk, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut published_state = create.core().state.clone();
    let published_environment = published_state.environments.get_mut("dev").unwrap();
    published_environment.active_artifact_generation = Some(candidate_artifact.clone());
    published_environment.active_workspace_generation = Some(candidate_workspace);
    let retained_content = referenced_content_blobs(&published_state).unwrap();
    ContentStore::create(&engine).unwrap();
    let blobs = engine.path().join("content/blobs");
    for (digest, size) in &retained_content {
        fs::write(
            blobs.join(digest.hex()),
            vec![0_u8; usize::try_from(*size).unwrap()],
        )
        .unwrap();
        fs::set_permissions(blobs.join(digest.hex()), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let stale_content = Sha256Digest::parse(&format!("sha256:{}", "e".repeat(64))).unwrap();
    fs::write(blobs.join(stale_content.hex()), b"stale").unwrap();
    fs::set_permissions(
        blobs.join(stale_content.hex()),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();

    let collector = tokio::spawn(Arc::clone(&service.supervisor).run_collector());
    // With the writer in flight a collection is only wanted: nothing is
    // removed, not even what nothing will reference.
    assert!(!create.collect_if_idle().await.unwrap());
    tokio::task::yield_now().await;
    assert!(blobs.join(stale_content.hex()).is_file());
    assert!(artifact_is_present(&engine, &stale_artifact));

    {
        let mut core = create.core();
        core.state = published_state;
        core.save().unwrap();
    }
    drop(writer);

    // The writer's end lets the collector task run the wanted collection.
    // One collection removes the stale content, then the stale runtime
    // artifact's manifest and blob, so the wait ends when all three are
    // gone. The bound only turns a collection that never runs into a
    // failure; a stalled CI slot can take seconds over it.
    let artifact_manifests = engine.path().join("runtime-artifacts/generations");
    let artifact_blobs = engine.path().join("runtime-artifacts/blobs");
    let stale = [
        blobs.join(stale_content.hex()),
        artifact_manifests.join(format!("{stale_artifact}.json")),
        artifact_blobs.join(format!("r-{stale_kernel}")),
    ];
    tokio::time::timeout(Duration::from_secs(60), async {
        while stale.iter().any(|path| path.exists()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the wanted collection runs once the writer ends");
    collector.abort();
    assert_eq!(
        create
            .collect_unreferenced_workspace_roots("dev")
            .await
            .unwrap(),
        vec![stale_storage]
    );
    assert!(paths.generations_dir.join(candidate_storage).is_dir());
    for digest in retained_content.keys() {
        assert!(blobs.join(digest.hex()).is_file());
    }
    assert!(!blobs.join(stale_content.hex()).exists());
    assert!(
        artifact_manifests
            .join(format!("{candidate_artifact}.json"))
            .is_file()
    );
    assert!(
        artifact_blobs
            .join(format!("r-{candidate_kernel}"))
            .is_file()
    );
    assert!(
        !artifact_manifests
            .join(format!("{stale_artifact}.json"))
            .exists()
    );
    assert!(!artifact_blobs.join(format!("r-{stale_kernel}")).exists());
}

#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
#[tokio::test]
async fn synthetic_image_pin_reopens_matches_exactly_and_survives_precreate_collection() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let image = crate::oci::install_test_synthetic_image_pin(&engine).await;
    let exact = RegistryReference::parse(&image.source_reference).unwrap();
    let ordinary = RegistryReference::parse("registry.example/codewire/workspace:latest").unwrap();
    let same_digest_other_repository = RegistryReference::parse(&format!(
        "registry.example/other/workspace@{}",
        image.source.digest
    ))
    .unwrap();

    core.admit_synthetic_workspace_image_pin().unwrap();
    assert_eq!(
        core.matching_synthetic_workspace_image(&exact).unwrap(),
        Some(image.clone())
    );
    assert_eq!(
        core.matching_synthetic_workspace_image(&ordinary).unwrap(),
        None
    );
    assert_eq!(
        core.matching_synthetic_workspace_image(&same_digest_other_repository)
            .unwrap(),
        None
    );

    let content = ContentStore::create(&engine).unwrap();
    let stale_bytes = bytes::Bytes::from_static(b"stale pre-create content");
    let stale_digest = test_digest(&stale_bytes);
    content
        .admit_bytes(&stale_digest, stale_bytes.clone())
        .await
        .unwrap();

    core.collect_content_now().unwrap();

    for descriptor in [&image.source, &image.manifest, &image.config] {
        assert!(
            content
                .contains_verified(&descriptor.digest, descriptor.size)
                .unwrap()
        );
    }
    for layer in &image.layers {
        assert!(
            content
                .contains_verified(&layer.descriptor.digest, layer.descriptor.size)
                .unwrap()
        );
    }
    assert!(
        !content
            .contains_verified(&stale_digest, stale_bytes.len() as u64)
            .unwrap()
    );
    let inventory = orphan_inventory_response(&core.root, &core.state, &BTreeSet::new()).unwrap();
    assert!(
        inventory
            .orphans
            .iter()
            .all(|orphan| orphan.kind != "oci_content")
    );

    // The supervisor keeps no in-memory pin; a second admission and match
    // exercise the same verified disk reopen used after a process restart.
    core.admit_synthetic_workspace_image_pin().unwrap();
    assert_eq!(
        core.matching_synthetic_workspace_image(&exact).unwrap(),
        Some(image)
    );
}

#[tokio::test]
async fn content_collection_retains_bundles_owned_by_pending_creates() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let content = ContentStore::create(&engine).unwrap();
    let bundle_bytes = bytes::Bytes::from_static(b"pending repository bundle");
    let bundle_digest = test_digest(&bundle_bytes);
    content
        .admit_bytes(&bundle_digest, bundle_bytes.clone())
        .await
        .unwrap();
    let stale_bytes = bytes::Bytes::from_static(b"stale content");
    let stale_digest = test_digest(&stale_bytes);
    content
        .admit_bytes(&stale_digest, stale_bytes.clone())
        .await
        .unwrap();

    let project = codewire_project::ProjectSpec {
        image: "registry.example/codewire/workspace:latest".to_owned(),
        repositories: vec![codewire_project::RepositorySpec {
            source: "https://example.test/org/app.git".to_owned(),
            revision: String::new(),
            branch: "main".to_owned(),
            destination: "/workspace/app".to_owned(),
            known_hosts: Vec::new(),
        }],
        working_directory: "/workspace/app".to_owned(),
        resources: codewire_project::ResourceSpec {
            cpu_millicores: Some(2_000),
            memory_mib: Some(16 * 1024),
            disk_gib: Some(20),
        },
        ..Default::default()
    };
    let project_spec_json = project.canonical_json().unwrap();
    let request_id = Uuid::new_v4();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "pending".to_owned(),
        source_path: String::new(),
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
        docker_disk_bytes: 0,
        request_id: request_id.to_string(),
        project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
        project_spec_json,
        implicit_path_mode: String::new(),
        local_mounts: Vec::new(),
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    let workspace_plan = WorkspacePlan {
        schema_version: 1,
        inputs: vec![crate::workspace_plan::WorkspaceInput::Repository {
            source: "https://example.test/org/app.git".to_owned(),
            commit: "a".repeat(40),
            branch: "main".to_owned(),
            destination: "/workspace/app".to_owned(),
            bundle_digest: bundle_digest.clone(),
            bundle_size: bundle_bytes.len() as u64,
        }],
    };
    let payload = create_operation_payload(&request, &workspace_plan).unwrap();
    let operation = core
        .store
        .begin_operation(
            request_id,
            Some(Uuid::new_v4()),
            OperationKind::Create,
            &payload,
        )
        .unwrap();

    core.collect_content_now().unwrap();
    assert!(
        content
            .contains_verified(&bundle_digest, bundle_bytes.len() as u64)
            .unwrap()
    );
    assert!(
        !content
            .contains_verified(&stale_digest, stale_bytes.len() as u64)
            .unwrap()
    );

    core.store
        .advance_operation(
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Failed,
            None,
            Some("test_failure"),
        )
        .unwrap();
    core.collect_content_now().unwrap();
    assert!(
        !content
            .contains_verified(&bundle_digest, bundle_bytes.len() as u64)
            .unwrap()
    );
}

#[test]
fn create_failure_codes_are_closed_and_discard_opaque_error_details() {
    const CANARY: &str = "synthetic-create-failure-secret-must-not-escape";
    let cases = [
        (
            SupervisorError::AlreadyExists(CANARY.to_owned()),
            "create_name_taken",
        ),
        (
            SupervisorError::CredentialAuthorityUnavailable,
            "create_credential_authority_unavailable",
        ),
        (
            SupervisorError::EnvironmentAccessUnavailable,
            "create_access_unavailable",
        ),
        (
            SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::NotFound),
            "create_access_binding_not_found",
        ),
        (
            SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::FailedPrecondition),
            "create_access_binding_precondition",
        ),
        (
            SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::DataLoss),
            "create_access_binding_metadata",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::Transport),
            "create_registry_transport",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::AuthenticationFailed),
            "create_registry_auth_failed",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::NotFound),
            "create_registry_not_found",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::InvalidManifest),
            "create_registry_admission",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::Content(
                ContentStoreError::Stream,
            )),
            "create_registry_blob_stream",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::Content(
                ContentStoreError::SizeMismatch {
                    expected: 3,
                    actual: 2,
                },
            )),
            "create_registry_blob_integrity",
        ),
        (
            SupervisorError::RegistryResolver(RegistryResolverError::Content(
                ContentStoreError::UnexpectedObject(PathBuf::from(CANARY)),
            )),
            "create_registry_content_store",
        ),
        (
            SupervisorError::SkillSnapshot(SkillSnapshotPreparationError::MissingRepositorySkill(
                CANARY.to_owned(),
            )),
            "create_skill_snapshot",
        ),
        (
            SupervisorError::SkillSnapshot(SkillSnapshotPreparationError::Io {
                path: PathBuf::from(CANARY),
                source: io::Error::other(CANARY),
            }),
            "create_skill_snapshot",
        ),
        (
            SupervisorError::ContentStore(ContentStoreError::Io(io::Error::other(CANARY))),
            "create_content_store",
        ),
        (
            SupervisorError::Io {
                path: PathBuf::from(CANARY),
                source: io::Error::other(CANARY),
            },
            "create_filesystem",
        ),
        (SupervisorError::VmStart(CANARY.to_owned()), "create_failed"),
        (
            SupervisorError::Workspace(WorkspaceError::NestedRepositoryTracked {
                parent: CANARY.to_owned(),
                child: CANARY.to_owned(),
            }),
            "create_nested_repository_tracked",
        ),
        (
            SupervisorError::GuestDockerToolingMissing,
            "create_guest_docker_tooling_missing",
        ),
        (
            SupervisorError::GuestSetupFailed,
            "create_guest_setup_failed",
        ),
        (
            SupervisorError::GuestWorkspaceFailed,
            "create_guest_workspace_failed",
        ),
        (
            SupervisorError::HostPortUnavailable,
            "create_host_port_unavailable",
        ),
    ];
    for (error, expected) in cases {
        let code = create_failure_code(&error);
        assert_eq!(code, expected);
        assert!(code.len() <= 64);
        assert!(
            code.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        assert!(!code.contains(CANARY));
    }
}

/// #3271: a store directory that is not private fails any operation
/// with one closed code, so the CLI can name the directory; every other
/// store failure keeps its generic cause.
#[test]
fn an_unsafe_runtime_artifact_store_has_its_own_code() {
    let unsafe_store = SupervisorError::UnsafeRuntimeArtifactStore {
        location: "runtime_artifacts_blobs",
    };
    assert_eq!(
        create_failure_code(&unsafe_store),
        "runtime_artifact_store_unsafe"
    );
    for prefix in ["start", "resize", "workspace_update"] {
        assert_eq!(
            lifecycle_failure_code(prefix, &unsafe_store, None),
            "runtime_artifact_store_unsafe"
        );
    }
    assert_eq!(lifecycle_failure_cause(&unsafe_store), "artifact_store");
    assert!(matches!(
        artifact_store_error(crate::artifact_store::RuntimeArtifactStoreError::InvalidGeneration),
        SupervisorError::ArtifactStore
    ));
    assert_eq!(
        create_failure_code(&SupervisorError::ArtifactStore),
        create_failure_code(&SupervisorError::Serve)
    );
}

#[test]
fn lifecycle_failure_causes_are_closed_codes_that_discard_error_text() {
    const CANARY: &str = "synthetic-secret-value-in-error-text-must-not-escape";
    let cases = [
        (SupervisorError::VmStart(CANARY.to_owned()), "vm_start"),
        (SupervisorError::NotFound(CANARY.to_owned()), "not_found"),
        (
            SupervisorError::AlreadyExists(CANARY.to_owned()),
            "already_exists",
        ),
        (
            SupervisorError::EndpointNotReplaced(PathBuf::from(CANARY)),
            "endpoint_not_replaced",
        ),
        (
            SupervisorError::Io {
                path: PathBuf::from(CANARY),
                source: io::Error::other(CANARY),
            },
            "filesystem",
        ),
        (
            SupervisorError::ContentStore(ContentStoreError::Io(io::Error::other(CANARY))),
            "content_store",
        ),
        (
            SupervisorError::SkillSnapshot(SkillSnapshotPreparationError::MissingRepositorySkill(
                CANARY.to_owned(),
            )),
            "skill_snapshot",
        ),
        (
            SupervisorError::ReplacementPreflight(Box::new(SupervisorError::VmStart(
                CANARY.to_owned(),
            ))),
            "replacement_preflight",
        ),
        (
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged),
            "direct_share_changed",
        ),
        (
            SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::PermissionDenied),
            "access_binding_denied",
        ),
        (
            SupervisorError::WorkloadSecretDeliveryUnavailable,
            "workload_secret_delivery_unavailable",
        ),
        (SupervisorError::RunnerStartTimeout, "runner_start_timeout"),
        (SupervisorError::NotRunning, "not_running"),
        (
            SupervisorError::HostPortUnavailable,
            "host_port_unavailable",
        ),
        (SupervisorError::GuestSetupFailed, "guest_setup_failed"),
        (
            SupervisorError::GuestWorkspaceFailed,
            "guest_workspace_failed",
        ),
    ];
    for (error, expected) in &cases {
        let cause = lifecycle_failure_cause(error);
        assert_eq!(cause, *expected);
        assert!(cause.len() <= MAXIMUM_LIFECYCLE_CAUSE_BYTES, "{cause}");
        assert!(runner_event_error_code_valid(cause), "{cause}");
        for prefix in [
            "start",
            "stop",
            "resize",
            "workspace_update",
            "workspace_rollback",
            "host_ports",
            "environment_sources",
        ] {
            let code = lifecycle_failure_code(prefix, error, None);
            assert_eq!(code, format!("{prefix}_{cause}"));
            assert!(runner_event_error_code_valid(&code), "{code}");
            assert!(!code.contains(CANARY));
        }
    }
    // The kept start codes are the general rule's own results.
    assert_eq!(
        lifecycle_failure_code("start", &SupervisorError::HostPortUnavailable, None),
        "start_host_port_unavailable"
    );
    assert_eq!(
        lifecycle_failure_code(
            "start",
            &SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged),
            None
        ),
        "start_direct_share_changed"
    );

    // A failed VM start names the runner's own closed code, and only a
    // valid one: a runner cannot pass text through it.
    let start = SupervisorError::VmStart(CANARY.to_owned());
    for (runner_code, expected) in [
        (
            Some("guest_start_failed"),
            "environment_sources_guest_start_failed",
        ),
        (
            Some("vmm_start_failed"),
            "environment_sources_vmm_start_failed",
        ),
        (Some(CANARY), "environment_sources_vm_start"),
        (None, "environment_sources_vm_start"),
    ] {
        assert_eq!(
            lifecycle_failure_code("environment_sources", &start, runner_code),
            expected
        );
    }
    // Another error never takes a stale runner code.
    assert_eq!(
        lifecycle_failure_code(
            "environment_sources",
            &SupervisorError::NotRunning,
            Some("guest_start_failed")
        ),
        "environment_sources_not_running"
    );
}

#[test]
fn a_stop_discards_the_guest_state_only_when_admitted_for_a_restore() {
    let id = Uuid::new_v4().to_string();
    let payload = |value: serde_json::Value| stop_payload_checkpoint(&value, "dev");
    assert_eq!(payload(serde_json::json!({"name": "dev"})), Some(false));
    assert_eq!(
        payload(serde_json::json!({"name": "dev", "discard_for_checkpoint": id})),
        Some(true)
    );
    for refused in [
        serde_json::json!({"name": "other"}),
        serde_json::json!({"name": "other", "discard_for_checkpoint": id}),
        serde_json::json!({"name": "dev", "discard_for_checkpoint": Uuid::nil().to_string()}),
        serde_json::json!({"name": "dev", "discard_for_checkpoint": "c1"}),
        serde_json::json!({"name": "dev", "discard_for_checkpoint": true}),
        serde_json::json!({"name": "dev", "discard": id}),
        serde_json::json!({"name": "dev", "discard_for_checkpoint": id, "extra": 1}),
        serde_json::json!({}),
        serde_json::json!("dev"),
    ] {
        assert_eq!(payload(refused.clone()), None, "{refused}");
    }
}

#[tokio::test]
async fn effect_timing_log_names_the_effect_and_its_duration_only() {
    let environment = project_environment();
    let environment_id = environment.id;
    let (_parent, core) = test_supervisor_core(environment);
    let log = DiagnosticLog::adopt(
        diagnostic_log::open_child_log(&core.root, diagnostic_log::SUPERVISOR_LOG).unwrap(),
    )
    .unwrap();
    let operation = begin_and_advance_test_operation(
        &core.store,
        environment_id,
        OperationKind::Start,
        &serde_json::json!({ "name": "dev" }),
        2,
    );
    let started = std::time::Instant::now() - std::time::Duration::from_millis(1_250);
    log_effect_timing(
        Some(&log),
        &operation,
        "stage_workspace_generation",
        started,
    );
    log_effect_timing(None, &operation, "start_vm", started);
    let text = std::fs::read_to_string(
        core.root
            .path()
            .join(diagnostic_log::LOG_DIRECTORY)
            .join(diagnostic_log::SUPERVISOR_LOG),
    )
    .unwrap();
    let line = text
        .lines()
        .find(|line| line.contains("event=operation_effect"))
        .unwrap();
    assert!(line.contains(" kind=start "));
    assert!(line.contains(&format!(" operation={} ", operation.operation_id)));
    assert!(line.contains(" effect=stage_workspace_generation "));
    assert!(line.contains(&format!(" environment={environment_id} ")));
    let elapsed: u64 = line
        .rsplit("elapsed_ms=")
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!((1_250..60_000).contains(&elapsed));
    assert_eq!(text.matches("event=operation_effect").count(), 1);
}

#[tokio::test]
async fn operation_failure_log_names_effect_and_cause_but_never_error_text() {
    const CANARY: &str = "synthetic-application-secret-value-must-not-be-logged";
    let environment = project_environment();
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    core.log = Some(Arc::new(
        DiagnosticLog::adopt(
            diagnostic_log::open_child_log(&core.root, diagnostic_log::SUPERVISOR_LOG).unwrap(),
        )
        .unwrap(),
    ));
    core.environment_mut("dev").unwrap().runner = Some(RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: ProcessIdentity {
            pid: 42,
            boot_id: "boot".to_owned(),
            start_time_ticks: 7,
            executable: PathBuf::from("/proc/self/exe"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                uid: 4,
                mode: 0o100500,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "f".repeat(64),
        },
        socket: SocketIdentity {
            device: 1,
            inode: 2,
            uid: 4,
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation: "b".repeat(64),
        error_code: Some("guest_start_failed".to_owned()),
    });
    let operation = begin_and_advance_test_operation(
        &core.store,
        environment_id,
        OperationKind::Start,
        &serde_json::json!({ "name": "dev" }),
        4,
    );
    let error = SupervisorError::VmStart(CANARY.to_owned());
    let code = lifecycle_failure_code("start", &error, core.recorded_runner_error_code("dev"));
    assert_eq!(code, "start_guest_start_failed");
    core.log_operation_failure(&operation, "dev", &error, &code);

    let log = fs::read_to_string(
        core.root
            .path()
            .join(diagnostic_log::LOG_DIRECTORY)
            .join(diagnostic_log::SUPERVISOR_LOG),
    )
    .unwrap();
    let line = log.lines().next().unwrap();
    assert!(
        line.ends_with(&format!(
            " event=operation_failed kind=start operation={} effect=start_vm cause=vm_start \
                 environment={environment_id} runner_error=guest_start_failed \
                 error_code=start_guest_start_failed",
            operation.operation_id
        )),
        "{line}"
    );
    assert_eq!(log.lines().count(), 1);
    assert!(!log.contains(CANARY));
}

#[tokio::test]
async fn create_failure_code_survives_replay_storage_and_public_operation_without_details() {
    const CANARY: &str = "synthetic-content-path-must-not-escape";
    for (recovering, expected_code) in [
        (false, "create_content_store"),
        (true, "create_interrupted"),
    ] {
        let mut environment = project_environment();
        environment.generation = 0;
        let environment_id = environment.id;
        let request = v1::CreateEnvironmentRequest {
            name: environment.name.clone(),
            source_path: "/workspace/source".to_owned(),
            vcpus: u32::from(environment.vcpus),
            memory_mib: environment.memory_mib,
            disk_bytes: environment.disk_bytes,
            docker_disk_bytes: 0,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json: environment.project_spec_json.clone().unwrap(),
            project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
            implicit_path_mode: "clone".to_owned(),
            ..Default::default()
        };
        let payload = create_operation_payload(&request, &environment.workspace_plan).unwrap();
        let (_parent, core) = test_supervisor_core(environment);
        let core = test_supervisor(core);
        let operation = begin_and_advance_test_operation(
            &core.core().store,
            environment_id,
            OperationKind::Create,
            &payload,
            3,
        );
        assert_eq!(
            supervisor_effect(operation.kind, operation.checkpoint).unwrap(),
            Some(LifecycleEffect::StageWorkspaceGeneration),
        );
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        ContentStore::create(&engine).unwrap();
        // The real staging boundary rejects this synthetic unknown object
        // before any registry request, skill execution, runner or VM boot.
        let unexpected = engine.path().join("content").join(CANARY);
        fs::write(&unexpected, b"synthetic-invalid-content-object").unwrap();

        core.drain_pending(recovering).await.unwrap();

        let reader = SupervisorOperationReader::open(&core.root).unwrap();
        let persisted = reader
            .operation_by_id(operation.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.phase, OperationPhase::Failed);
        assert_eq!(persisted.checkpoint, 4);
        assert_eq!(persisted.error_code.as_deref(), Some(expected_code));
        assert!(persisted.result.is_none());
        // The failed create rolled back through the ordinary delete: no
        // record remains, and the create keeps its own error code.
        let history = reader
            .recent_environment_operations(environment_id)
            .unwrap();
        assert!(
            matches!(core.environment("dev"), Err(SupervisorError::NotFound(_))),
            "{expected_code}: environment {:?}; operations {:?}",
            core.environment("dev").map(|environment| environment.state),
            history
                .iter()
                .map(|operation| (
                    operation.kind,
                    operation.phase,
                    operation.error_code.clone()
                ))
                .collect::<Vec<_>>()
        );
        let rollback = history
            .into_iter()
            .find(|operation| operation.kind == OperationKind::Delete)
            .expect("the failed create began its rollback delete");
        assert_eq!(rollback.phase, OperationPhase::Completed);
        assert!(core.core().store.pending_operations().unwrap().is_empty());
        assert!(unexpected.is_file(), "unsafe objects remain quarantined");
        let public = operation_proto(&persisted).unwrap();
        assert_eq!(public.error_code, expected_code);
        assert_eq!(public.checkpoint, 4);
        assert_eq!(public.stage, v1::OperationStage::Failed as i32);
        let failure = operation_outcome(public).unwrap_err();
        assert_eq!(failure.code(), tonic::Code::FailedPrecondition);
        assert!(
            failure
                .message()
                .contains(&format!("failed: {expected_code}")),
            "{}",
            failure.message()
        );
        assert!(!failure.message().contains(CANARY));
        assert!(
            !serde_json::to_string(&persisted.payload)
                .unwrap()
                .contains(CANARY)
        );
    }
}

#[tokio::test]
async fn startup_rolls_back_environments_left_by_failed_creates() {
    // Left in `error` by a create that failed before rollback existed.
    let mut stranded = project_environment();
    stranded.state = StoredEnvironmentState::Error;
    stranded.generation = 0;
    let stranded_id = stranded.id;
    let (_parent, core) = test_supervisor_core(stranded);
    let core = test_supervisor(core);
    // A once-running environment in `error` is recoverable, not stranded.
    let mut recoverable = project_environment();
    recoverable.name = "kept".to_owned();
    recoverable.state = StoredEnvironmentState::Error;
    let mut next_state = core.core().state.clone();
    next_state
        .environments
        .insert("kept".to_owned(), recoverable.clone());
    core.core().store.replace_state(&next_state).unwrap();
    core.core().state = next_state;

    core.core().begin_rollback_of_failed_creates().unwrap();
    // A second start before the worker ran begins nothing new.
    core.core().begin_rollback_of_failed_creates().unwrap();
    let pending = core.core().store.pending_operations().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, OperationKind::Delete);
    assert_eq!(pending[0].environment_id, Some(stranded_id));

    core.drain_pending(true).await.unwrap();

    assert!(matches!(
        core.environment("dev"),
        Err(SupervisorError::NotFound(_))
    ));
    assert_eq!(core.environment("kept").unwrap(), recoverable);
    assert!(core.core().store.pending_operations().unwrap().is_empty());
}

#[test]
fn failed_create_never_marks_a_different_environment_error() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    let lock = SupervisorLock::acquire(&root).unwrap();
    let (store, _) = SupervisorStore::open(&root).unwrap();
    let existing_id = Uuid::new_v4();
    let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
    let existing = EnvironmentRecord {
        cw_runtime: None,
        id: existing_id,
        name: "dev".to_owned(),
        state: StoredEnvironmentState::Running,
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
        docker_disk_bytes: 0,
        generation: 1,
        host_ports: Vec::new(),
        mesh: None,
        workspace_plan: WorkspacePlan::local(&crate::workspace::WorkspaceSource {
            vm_only: Vec::new(),
            source_path: PathBuf::from("/workspace/source"),
            commit: "a".repeat(40),
            mode: WorkspaceSourceMode::Clone,
        })
        .unwrap(),
        project_spec_json: Some(project_spec_json),
        project_spec_sha256: Some(project_spec_sha256),
        access_profile: None,
        access_binding: None,
        platform_source_authority: None,
        runner: None,
        active_artifact_generation: Some("b".repeat(64)),
        staging_artifact_generation: None,
        active_workspace_generation: None,
        staging_workspace_generation: None,
        rollback_workspace_generation: None,
    };
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some("dev".to_owned()),
        environments: [("dev".to_owned(), existing)].into(),
    };
    store.replace_state(&state).unwrap();
    let operation = store
        .begin_operation(
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            OperationKind::Create,
            &serde_json::json!({"name": "dev"}),
        )
        .unwrap();
    let mut core = SupervisorCore {
        config: NativeRuntimeConfig {
            root: root_path,
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock.json"),
            mesh_data_dir: parent.path().join("mesh-auth"),
            platform_config_dir: parent.path().join("platform-auth"),
            credential_authority_root: parent.path().join("credentials"),
            executable: PathBuf::from("/usr/bin/true"),
        },
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images: retained_images::RetainedImages::default(),
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        admitted_here: HashMap::new(),
        selections: 0,
        retiring: false,
        operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
        log: None,
        network_policies: Arc::new(
            crate::network_policy_store::NetworkPolicyStore::in_memory().unwrap(),
        ),
        _lock: lock,
    };

    let failed = core
        .fail_operation_with_environment_error(&operation, "dev", "create_failed")
        .unwrap();

    assert_eq!(failed.phase, OperationPhase::Failed);
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Running
    );
    assert_eq!(core.environment("dev").unwrap().id, existing_id);
}

#[test]
fn replay_failure_uses_the_latest_checkpoint_and_unwedges_the_environment() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("runtime");
    fs::create_dir(&root_path).unwrap();
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&root_path).unwrap();
    let lock = SupervisorLock::acquire(&root).unwrap();
    let (store, _) = SupervisorStore::open(&root).unwrap();
    let environment = project_environment();
    let environment_id = environment.id;
    let state = SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some("dev".to_owned()),
        environments: [("dev".to_owned(), environment)].into(),
    };
    store.replace_state(&state).unwrap();
    let request_id = Uuid::new_v4();
    let operation = store
        .begin_operation(
            request_id,
            Some(environment_id),
            OperationKind::Start,
            &serde_json::json!({"name": "dev", "generation": 2}),
        )
        .unwrap();
    store
        .advance_operation(
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::EffectApplied,
            None,
            None,
        )
        .unwrap();
    let mut core = SupervisorCore {
        config: NativeRuntimeConfig {
            root: root_path,
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock.json"),
            mesh_data_dir: parent.path().join("mesh-auth"),
            platform_config_dir: parent.path().join("platform-auth"),
            credential_authority_root: parent.path().join("credentials"),
            executable: PathBuf::from("/usr/bin/true"),
        },
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images: retained_images::RetainedImages::default(),
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        admitted_here: HashMap::new(),
        selections: 0,
        retiring: false,
        operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
        log: None,
        network_policies: Arc::new(
            crate::network_policy_store::NetworkPolicyStore::in_memory().unwrap(),
        ),
        _lock: lock,
    };

    core.fail_replayed_operation(&operation, "dev", "start_interrupted")
        .unwrap();

    let failed = core
        .store
        .operation_by_request(request_id)
        .unwrap()
        .unwrap();
    assert_eq!(failed.phase, OperationPhase::Failed);
    assert_eq!(failed.checkpoint, 2);
    assert_eq!(failed.error_code.as_deref(), Some("start_interrupted"));
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Error
    );
}

#[test]
fn runner_artifact_identity_is_exact() {
    let generation = "a".repeat(64);
    assert!(runner_artifact_identity_matches(&generation, &generation));
    assert!(!runner_artifact_identity_matches(
        &generation,
        &"b".repeat(64)
    ));
    assert!(!runner_artifact_identity_matches("invalid", "invalid"));
    assert!(!runner_artifact_identity_matches("", ""));
}

#[cfg(target_os = "linux")]
#[test]
fn managed_cw_runtime_binds_selected_uuid_and_active_runner_artifacts() {
    let mut environment = project_environment();
    let generation = environment.active_artifact_generation.clone().unwrap();
    environment.state = StoredEnvironmentState::Running;
    environment.runner = Some(RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: ProcessIdentity {
            pid: 42,
            boot_id: "synthetic".to_owned(),
            start_time_ticks: 7,
            executable: PathBuf::from("/proc/self/exe"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                uid: 1000,
                mode: 0o100500,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "f".repeat(64),
        },
        socket: SocketIdentity {
            device: 1,
            inode: 2,
            uid: 1000,
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation: generation.clone(),
        error_code: None,
    });
    assert_eq!(
        managed_runtime_artifact_generation(&environment, environment.id).unwrap(),
        generation
    );
    assert_eq!(
        managed_runtime_artifact_generation(&environment, Uuid::new_v4())
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    environment.runner.as_mut().unwrap().artifact_generation = "c".repeat(64);
    assert!(managed_runtime_artifact_generation(&environment, environment.id).is_err());
    environment.runner.as_mut().unwrap().artifact_generation = generation;
    environment.state = StoredEnvironmentState::Stopped;
    assert!(managed_runtime_artifact_generation(&environment, environment.id).is_err());
    environment.state = StoredEnvironmentState::Running;
    environment.active_artifact_generation = None;
    assert!(managed_runtime_artifact_generation(&environment, environment.id).is_err());
}

#[test]
fn runner_start_accepts_only_the_exact_queried_prior_baseline() {
    let prior = (3, StoredEnvironmentState::Error);
    assert!(runner_event_is_prior_baseline(
        3,
        StoredEnvironmentState::Error,
        v1::RunnerStage::Error,
        0,
        v1::GuestBootStage::Unspecified,
        true,
        prior,
    ));
    for generation in [2, 4] {
        assert!(!runner_event_is_prior_baseline(
            generation,
            StoredEnvironmentState::Error,
            v1::RunnerStage::Error,
            0,
            v1::GuestBootStage::Unspecified,
            true,
            prior,
        ));
    }
    assert!(!runner_event_is_prior_baseline(
        3,
        StoredEnvironmentState::Error,
        v1::RunnerStage::Error,
        1,
        v1::GuestBootStage::RootMounted,
        true,
        prior,
    ));
    assert!(!runner_event_is_prior_baseline(
        3,
        StoredEnvironmentState::Error,
        v1::RunnerStage::Error,
        0,
        v1::GuestBootStage::Unspecified,
        false,
        prior,
    ));
    for stage in [v1::RunnerStage::Ready, v1::RunnerStage::Stopped] {
        assert!(runner_event_is_prior_baseline(
            3,
            StoredEnvironmentState::Stopped,
            stage,
            0,
            v1::GuestBootStage::Unspecified,
            false,
            (3, StoredEnvironmentState::Stopped),
        ));
    }
}

#[test]
fn live_runner_mismatch_is_rejected_before_artifact_replacement() {
    let active = "a".repeat(64);
    let requested = "b".repeat(64);
    for state in [
        StoredEnvironmentState::Stopped,
        StoredEnvironmentState::Starting,
        StoredEnvironmentState::Running,
        StoredEnvironmentState::Error,
        StoredEnvironmentState::Orphaned,
    ] {
        assert_eq!(
            runner_artifact_disposition(&active, &active, state),
            RunnerArtifactDisposition::Reuse
        );
    }
    for state in [
        StoredEnvironmentState::Starting,
        StoredEnvironmentState::Running,
    ] {
        assert_eq!(
            runner_artifact_disposition(&active, &requested, state),
            RunnerArtifactDisposition::RejectLiveMismatch
        );
    }
    for state in [
        StoredEnvironmentState::Stopped,
        StoredEnvironmentState::Error,
        StoredEnvironmentState::Orphaned,
    ] {
        assert_eq!(
            runner_artifact_disposition(&active, &requested, state),
            RunnerArtifactDisposition::ReplaceStopped
        );
    }
}
