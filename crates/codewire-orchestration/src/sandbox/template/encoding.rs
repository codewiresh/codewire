//! Deterministic encoding helpers for Kata policy init-data.

use super::TemplateOpts;
use super::runtime_policy::{DOCKER_MODE_GUEST_DIND, dind_image};
use base64::Engine;
use crc32fast::Hasher as Crc32Hasher;
use sha2::{Digest, Sha256};

const CODEWIRE_KATA_AGENT_POLICY_REGO: &str = r#"package agent_policy

# Codewire-owned base policy for commodity Kata Agent Policy and confidential
# CoCo bootstrap. Commodity uses this only as defense in depth: without SNP/TDX
# the host can still replace the guest image, agent, or policy.
default AddARPNeighborsRequest := true
default AddSwapPathRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := true
default GetDiagnosticDataRequest := false
default GetIPTablesRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemAgentCompactConfig := true
default MemAgentMemcgConfig := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResizeVolumeRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetIPTablesRequest := true
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default VolumeStatsRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
"#;

pub(super) fn kata_policy_init_data_annotation(
    opts: &TemplateOpts,
    authorize_workspace_storage: bool,
) -> String {
    gzip_base64(&build_codewire_kata_policy_init_data(
        opts,
        authorize_workspace_storage,
    ))
}

pub(super) fn build_codewire_kata_policy_init_data(
    opts: &TemplateOpts,
    authorize_workspace_storage: bool,
) -> String {
    let policy = build_codewire_kata_policy(opts, authorize_workspace_storage);
    let mut payload = format!(
        "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"policy.rego\" = '''\n{policy}'''\n"
    );

    if authorize_workspace_storage
        && opts.runtime_profile_spec().profile == super::RUNTIME_PROFILE_CONFIDENTIAL
        && opts.disk_gib > 0
        && valid_protected_workspace_contract(opts)
    {
        payload.push_str("\"codewire_workspace_storage_key_id\" = ");
        payload.push_str(&toml_string(&opts.environment_id));
        payload.push('\n');
    }

    let kbs_url = opts.kata_coco_kbs_url.trim();
    let kbs_ca_pem = opts.kata_coco_kbs_ca_pem.trim();
    if kbs_url.is_empty() {
        return payload;
    }

    payload.push_str("\n\"aa.toml\" = '''\n[token_configs]\n[token_configs.kbs]\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    if !kbs_ca_pem.is_empty() {
        payload.push_str("\ncert = ");
        payload.push_str(&toml_string(kbs_ca_pem));
    }
    payload.push_str("\n'''\n\n\"cdh.toml\" = '''\nsocket = \"unix:///run/confidential-containers/cdh.sock\"\n\n[kbc]\nname = \"cc_kbc\"\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    if !kbs_ca_pem.is_empty() {
        payload.push_str("\nkbs_cert = ");
        payload.push_str(&toml_string(kbs_ca_pem));
    }
    // Keep the image table absent. guest-components uses
    // ImageConfig::from_kernel_cmdline() only when [image] is omitted; adding a
    // partial table here would silently discard agent.image_registry_auth.
    payload.push_str("\n'''\n");
    payload
}

fn build_codewire_kata_policy(opts: &TemplateOpts, authorize_workspace_storage: bool) -> String {
    let mut policy = CODEWIRE_KATA_AGENT_POLICY_REGO.to_string();
    if !authorize_workspace_storage
        || opts.runtime_profile_spec().profile != super::RUNTIME_PROFILE_CONFIDENTIAL
        || opts.disk_gib <= 0
    {
        policy.push_str("default CreateContainerRequest := true\n");
        return policy;
    }
    if !valid_protected_workspace_contract(opts) {
        policy.push_str("default CreateContainerRequest := false\n");
        return policy;
    }

    let manifest_uri = &opts.confidential_storage_manifest_uri;
    let mount_name = format!("confidential-{}", hex_sha256(manifest_uri.as_bytes()));
    let mount_point = format!("/run/kata-containers/shared/containers/passthrough/{mount_name}");
    let mut containers = serde_json::Map::new();
    containers.insert(
        "workspace".into(),
        serde_json::json!({
            "image": opts.image,
            "mount_destinations": ["/home/codewire", "/workspace"],
        }),
    );
    if opts.runtime_profile_spec().docker_mode == DOCKER_MODE_GUEST_DIND {
        containers.insert(
            "dind".into(),
            serde_json::json!({
                "image": dind_image(opts),
                "mount_destinations": ["/workspace"],
            }),
        );
    }
    let contract = serde_json::json!({
        "device_path": super::KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
        "manifest_uri": manifest_uri,
        "requested_access": 2,
        "storage_fstype": "confidential-storage",
        "mount_point": mount_point,
        "mount_type": "bind",
        "mount_options": ["rbind", "rprivate", "rw"],
        "fs_group": {
            "group_id": 1000,
            "group_change_policy": 1,
        },
        "containers": containers,
    });
    let contract = serde_json::to_string_pretty(&contract).expect("serialize policy contract");
    policy.push_str(CODEWIRE_KATA_CONFIDENTIAL_STORAGE_POLICY_REGO);
    policy.push_str("\ncodewire_confidential_storage := ");
    policy.push_str(&contract);
    policy.push('\n');
    policy
}

fn valid_protected_workspace_contract(opts: &TemplateOpts) -> bool {
    crate::confidential_storage::validate_manifest_uri(&opts.confidential_storage_manifest_uri)
        && crate::confidential_storage::validate_environment_id(&opts.environment_id).is_ok()
}

const CODEWIRE_KATA_CONFIDENTIAL_STORAGE_POLICY_REGO: &str = r#"
default CreateContainerRequest := false

# Containers without a protected workspace mount keep the established
# Codewire lifecycle policy. A plaintext or missing-storage downgrade at one
# of the protected destinations is denied.
CreateContainerRequest := true if {
    name := input.OCI.Annotations["io.kubernetes.cri.container-name"]
    is_null(object.get(codewire_confidential_storage.containers, name, null))
    confidential_candidates := [storage | some storage in input.storages; codewire_is_confidential_storage_candidate(storage)]
    count(confidential_candidates) == 0
    protected_mounts := [mount | some mount in input.OCI.Mounts; codewire_is_protected_destination(mount.destination)]
    count(protected_mounts) == 0
}

CreateContainerRequest := true if {
    name := input.OCI.Annotations["io.kubernetes.cri.container-name"]
    expected := codewire_confidential_storage.containers[name]
    input.OCI.Annotations["io.kubernetes.cri.image-name"] == expected.image

    confidential_candidates := [storage | some storage in input.storages; codewire_is_confidential_storage_candidate(storage)]
    count(confidential_candidates) == 1
    storage := confidential_candidates[0]
    codewire_confidential_storage_matches(storage)

    protected_mounts := [mount | some mount in input.OCI.Mounts; codewire_is_protected_destination(mount.destination)]
    count(protected_mounts) == count(expected.mount_destinations)
    every destination in expected.mount_destinations {
        some mount in protected_mounts
        mount.destination == destination
        codewire_confidential_mount_matches(storage, mount)
    }
    every mount in protected_mounts {
        mount.destination in expected.mount_destinations
        codewire_confidential_mount_matches(storage, mount)
    }

    raw_agent_devices := [device | some device in input.devices; device.container_path == codewire_confidential_storage.device_path]
    count(raw_agent_devices) == 0
    raw_oci_devices := [device | some device in input.OCI.Linux.Devices; device.Path == codewire_confidential_storage.device_path]
    count(raw_oci_devices) == 0
}

codewire_is_protected_destination(destination) if {
    destination in {"/home/codewire", "/workspace"}
}

codewire_is_confidential_storage_candidate(storage) if {
    storage.fstype == "confidential-storage"
}
codewire_is_confidential_storage_candidate(storage) if {
    storage.confidential_storage != null
}

codewire_confidential_storage_matches(storage) if {
    storage.driver_options == []
    storage.fstype == codewire_confidential_storage.storage_fstype
    storage.fs_group == codewire_confidential_storage.fs_group
    storage.mount_point == codewire_confidential_storage.mount_point
    storage.options == []
    storage.shared == false
    codewire_confidential_device_transport(storage)
    storage.confidential_storage.manifest_uri == codewire_confidential_storage.manifest_uri
    storage.confidential_storage.requested_access == codewire_confidential_storage.requested_access
}

codewire_confidential_device_transport(storage) if {
    storage.driver == "blk"
    regex.match("^[0-9a-f]{2}(/[0-9a-f]{2})?$", storage.source)
}
codewire_confidential_device_transport(storage) if {
    storage.driver == "scsi"
    regex.match("^[0-9]+:[0-9]+$", storage.source)
}

codewire_confidential_mount_matches(storage, mount) if {
    mount.source == storage.mount_point
    mount.type_ == codewire_confidential_storage.mount_type
    mount.options == codewire_confidential_storage.mount_options
}
"#;

fn hex_sha256(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub(super) fn gzip_base64(payload: &str) -> String {
    let data = payload.as_bytes();
    let mut out = Vec::with_capacity(data.len() + 32);
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);

    let mut write_block = |chunk: &[u8], final_block: bool| {
        out.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    };

    if data.is_empty() {
        write_block(&[], true);
    } else {
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + 65_535).min(data.len());
            write_block(&data[offset..end], end == data.len());
            offset = end;
        }
    }

    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    out.extend_from_slice(&hasher.finalize().to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());

    base64::engine::general_purpose::STANDARD.encode(out)
}
