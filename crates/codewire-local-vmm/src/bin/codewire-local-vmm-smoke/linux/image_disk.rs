//! The image-disk run (#4646): build the fixture's image disk with the
//! builder guest, then boot two VMs over it.

use super::*;
use codewire_local_vmm::image_disk::{ImageDiskAttachment, ImageDiskStore};
use codewire_local_vmm::linux::path::PrivateRoot;
use codewire_local_vmm::oci::{
    ContentStore, OciArchitecture, ResolvedDescriptor, ResolvedImage, ResolvedLayer, Sha256Digest,
};
use codewire_local_vmm::setup_pack::{SetupPackRequest, ensure_attached_setup_pack};
use codewire_vmm_guest_probe::image_disk::image_root_generation;

const IMAGE_DISK_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

/// #4646: the builder guest unpacks the fixture image onto an image
/// disk, then two VMs boot over that one disk. Their setup packs carry no
/// layer, so a workspace that runs proves its lower is the image disk.
pub(super) async fn image_disk_proof(arguments: Args) -> SmokeResult<()> {
    let resources = arguments
        .resources
        .ok_or_else(|| failure("run resource configuration is missing"))?;
    let runner = CloudHypervisorRunner::new(arguments.runner_config()).await?;
    runner.preflight()?;
    let engine = PrivateRoot::open(&arguments.state_root)?;
    let content = ContentStore::create(&engine)?;
    let (image, project, config) = admit_smoke_image(&runner, &content).await?;
    let (_, image_architecture) = smoke_setup_architecture()?;
    let disks = ImageDiskStore::create(&engine)?;
    let image_disk_id = codewire_local_vmm::image_disk::image_disk_id(
        image_architecture,
        image.manifest.digest.hex(),
    )?;
    let lock = disks.lock(&image_disk_id, Instant::now() + IMAGE_DISK_LOCK_TIMEOUT)?;
    let building = Instant::now();
    let admitted = runner
        .build_image_disk(&disks, &lock, &content, &image)
        .await?;
    observation(
        "image_disk.build_elapsed_ms",
        building.elapsed().as_millis(),
    );
    observation("image_disk.id", &admitted.record.image_disk_id);
    if let Some(directory) = &arguments.publish {
        // The disk itself is copied sparse by the caller, which also sizes
        // it to its content; the record and config are written here.
        fs::write(
            directory.join("record.json"),
            serde_json::to_vec(&admitted.record)?,
        )?;
        fs::write(directory.join("config.json"), &config)?;
        observation("image_disk.path", admitted.path.display());
        observation("image_disk.build_id", &admitted.record.build_id);
    }
    let attachment = ImageDiskAttachment::Stored {
        image_disk_id: admitted.record.image_disk_id.clone(),
        build_id: admitted.record.build_id.clone(),
    };
    // The second VM is the point: the same disk, not rebuilt.
    let second = arguments
        .second_vm_id
        .ok_or_else(|| failure("second VM ID missing after argument admission"))?;
    for (index, vm_id) in [arguments.vm_id, second].into_iter().enumerate() {
        observation(&format!("image_disk.vm.{index}.id"), vm_id);
        let booted = boot_over_image_disk(
            &runner,
            &arguments,
            resources,
            vm_id,
            &content,
            &image,
            &project,
            &attachment,
        )
        .await;
        // A failed VM is kept for diagnosis; the cleanup subcommand removes it.
        booted?;
        let cleanup_id = Uuid::new_v4();
        move_stopped_vm_to_trash(&arguments.state_root, vm_id, cleanup_id)?;
        cleanup_trashed_vm(&arguments.state_root, vm_id, cleanup_id)?;
        observation(&format!("image_disk.vm.{index}.removed"), true);
    }
    disks.revalidate(&admitted)?;
    observation("image_disk.unchanged_after_boots", true);
    drop(lock);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn boot_over_image_disk(
    runner: &CloudHypervisorRunner,
    arguments: &Args,
    resources: RunResources,
    vm_id: Uuid,
    content: &ContentStore,
    image: &ResolvedImage,
    project: &[u8],
    attachment: &ImageDiskAttachment,
) -> SmokeResult<()> {
    let build_id = codewire_local_vmm::image_disk::build_id_bytes(attachment.build_id())
        .ok_or_else(|| failure("image disk build id is invalid"))?;
    let project_sha256 = Sha256Value::calculate(project);
    let root_generation = image_root_generation(
        project_sha256,
        Sha256Value::parse_hex(attachment.image_disk_id())?,
        build_id,
    )
    .to_string();
    ensure_empty_root_generation(
        &arguments.state_root,
        vm_id,
        ROOT_GENERATION,
        ROOT_DISK_BYTES,
    )?;
    let pack = ensure_attached_setup_pack(
        &arguments.state_root,
        vm_id,
        content,
        SetupPackRequest {
            project_json: project,
            project_sha256: &project_sha256.to_string(),
            storage_generation: ROOT_GENERATION,
            root_generation: &root_generation,
            image,
        },
        build_id,
    )?;
    if !pack.header.layers.is_empty() {
        return Err(failure("an attach setup pack carried a layer"));
    }
    let setup = SetupBinding::new(
        pack.header.total_bytes,
        pack.header.root_generation,
        pack.header_sha256,
    )?;
    let mut request = request_with_setup(1, arguments, resources, setup);
    request.vm_id = vm_id;
    request.vsock_cid = cid_for(vm_id);
    request.image_disk = Some(attachment.clone());
    let booting = Instant::now();
    let prepared = match runner.prepare(request).await {
        Ok(prepared) => prepared,
        Err(error) => {
            observation("image_disk.prepare_error", runner_error_class(&error));
            return Err(Box::new(error));
        }
    };
    let mut running = match runner.start(prepared).await {
        Ok(running) => running,
        Err(error) => {
            observation("image_disk.start_error", runner_error_class(&error));
            return Err(Box::new(error));
        }
    };
    observation("image_disk.step", "started");
    attach_network_worker(&mut running, SETUP_NETWORK_READY_TIMEOUT).await?;
    observation("image_disk.step", "network_attached");
    let client = connect_ready_daemon(&mut running).await?;
    observation("image_disk.step", "daemon_ready");
    observation(
        &format!("image_disk.vm.{vm_id}.daemon_ready_ms"),
        booting.elapsed().as_millis(),
    );
    let output = run_workspace_command(
        &client,
        "test -x /bin/busybox && echo upper-ok > /root/upper && /bin/busybox cat /root/upper && /bin/busybox ls /bin | tr '\\n' ' '".to_owned(),
    )
    .await?;
    if !output.contains("upper-ok") || !output.contains("busybox") {
        return Err(failure(
            "the workspace over the image disk is not the fixture image",
        ));
    }
    observation(&format!("image_disk.vm.{vm_id}.workspace"), output.trim());
    drop(client);
    let stopping = Instant::now();
    let exit = running.stop().await?;
    drop(running);
    if !matches!(exit, ExitClass::GuestShutdown) {
        return Err(failure(
            "a VM over the image disk did not shut down cleanly",
        ));
    }
    observation(
        &format!("image_disk.vm.{vm_id}.stop_ms"),
        stopping.elapsed().as_millis(),
    );
    Ok(())
}

/// The smoke's fixture image, admitted into the content store as a real
/// image: one uncompressed layer with the sealed BusyBox.
async fn admit_smoke_image(
    runner: &CloudHypervisorRunner,
    content: &ContentStore,
) -> SmokeResult<(ResolvedImage, Vec<u8>, Vec<u8>)> {
    let busybox = runner.read_sealed_guest_busybox()?;
    let layer = smoke_workspace_layer(&busybox)?;
    let (_, image_architecture) = smoke_setup_architecture()?;
    let architecture = match image_architecture {
        "amd64" => OciArchitecture::Amd64,
        _ => OciArchitecture::Arm64,
    };
    let digest =
        |bytes: &[u8]| Sha256Digest::parse(&format!("sha256:{}", Sha256Value::calculate(bytes)));
    let layer_digest = digest(&layer)?;
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": image_architecture,
        "os": "linux",
        "config": {
            "User": "0",
            "Env": ["HOME=/root", "PATH=/bin", "SHELL=/bin/sh"],
            "WorkingDir": "/workspace"
        },
        "rootfs": {"type": "layers", "diff_ids": [layer_digest.as_str()]}
    }))?;
    let config_digest = digest(&config)?;
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest.as_str(), "size": config.len()},
        "layers": [{"mediaType": OCI_LAYER, "digest": layer_digest.as_str(), "size": layer.len()}]
    }))?;
    let manifest_digest = digest(&manifest)?;
    for (object, bytes) in [
        (&manifest_digest, &manifest),
        (&config_digest, &config),
        (&layer_digest, &layer),
    ] {
        content
            .admit_bytes(object, bytes::Bytes::copy_from_slice(bytes))
            .await?;
    }
    let manifest_descriptor = ResolvedDescriptor {
        media_type: OCI_MANIFEST.to_owned(),
        digest: manifest_digest.clone(),
        size: manifest.len() as u64,
    };
    let image = ResolvedImage {
        source_reference: format!(
            "example.invalid/codewire/kvm-smoke@{}",
            manifest_digest.as_str()
        ),
        architecture,
        source: manifest_descriptor.clone(),
        manifest: manifest_descriptor,
        config: ResolvedDescriptor {
            media_type: OCI_CONFIG.to_owned(),
            digest: config_digest,
            size: config.len() as u64,
        },
        layers: vec![ResolvedLayer {
            descriptor: ResolvedDescriptor {
                media_type: OCI_LAYER.to_owned(),
                digest: layer_digest.clone(),
                size: layer.len() as u64,
            },
            diff_id: layer_digest,
        }],
    };
    image.verify_cached(content)?;
    let project = ProjectSpec {
        image: "example.invalid/codewire/kvm-smoke".to_owned(),
        ..ProjectSpec::default()
    }
    .canonical_json()?;
    Ok((image, project, config))
}
