//! Deterministic encoding helpers for Kata policy init-data.

use base64::Engine;
use crc32fast::Hasher as Crc32Hasher;

use super::TemplateOpts;

const CODEWIRE_KATA_AGENT_POLICY_REGO: &str = r#"package agent_policy

# Codewire-owned base policy for commodity Kata Agent Policy and confidential
# CoCo bootstrap. Commodity uses this only as defense in depth: without SNP/TDX
# the host can still replace the guest image, agent, or policy.
default AddARPNeighborsRequest := true
default AddSwapPathRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
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

pub(super) fn kata_policy_init_data_annotation(opts: &TemplateOpts) -> String {
    gzip_base64(&build_codewire_kata_policy_init_data(
        &opts.kata_coco_kbs_url,
        &opts.kata_coco_kbs_ca_pem,
        &opts.kata_coco_test_resource_uri,
        &opts.kata_coco_test_resource_path,
        if opts.runtime_profile_spec().profile == super::RUNTIME_PROFILE_CONFIDENTIAL {
            &opts.environment_id
        } else {
            ""
        },
    ))
}

pub(super) fn build_codewire_kata_policy_init_data(
    kbs_url: &str,
    kbs_ca_pem: &str,
    test_resource_uri: &str,
    test_resource_path: &str,
    workspace_storage_key_id: &str,
) -> String {
    let mut payload = format!(
        "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"policy.rego\" = '''\n{CODEWIRE_KATA_AGENT_POLICY_REGO}'''\n"
    );

    let kbs_url = kbs_url.trim();
    let kbs_ca_pem = kbs_ca_pem.trim();
    let workspace_storage_key_id = workspace_storage_key_id.trim();
    if !workspace_storage_key_id.is_empty() {
        payload.push_str("\"codewire_workspace_storage_key_id\" = ");
        payload.push_str(&toml_string(workspace_storage_key_id));
        payload.push('\n');

        let key_uri = crate::confidential_storage::kbs_uri(workspace_storage_key_id);
        let registry = serde_json::json!({
            "version": 1,
            "volumes": [{
                "profile": "luks2-integrity-ext4",
                "volumeId": workspace_storage_key_id,
                "keyUri": key_uri,
            }],
        });
        payload.push_str("\"confidential_storage\" = ");
        payload.push_str(&toml_string(&registry.to_string()));
        payload.push('\n');
    }
    if kbs_url.is_empty() {
        return payload;
    }
    let _ = test_resource_uri;
    let _ = test_resource_path;

    payload.push_str("\n\"aa.toml\" = '''\n[token_configs]\n[token_configs.kbs]\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    if !kbs_ca_pem.is_empty() {
        payload.push_str("\ncert = ");
        payload.push_str(&toml_string(kbs_ca_pem));
    }
    payload.push_str("\n'''\n\n\"cdh.toml\" = '''\nsocket = \"unix:///run/confidential-containers/cdh.sock\"\n\n[kbc]\nname = \"cc_kbc\"\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    payload.push('\n');
    if !kbs_ca_pem.is_empty() {
        payload.push_str("\n[image]\nextra_root_certificates = [");
        payload.push_str(&toml_string(kbs_ca_pem));
        payload.push_str("]\n");
    }
    payload.push_str("'''\n");
    payload
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
