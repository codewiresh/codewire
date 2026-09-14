//! Synthetic ARM64 OCI setup using the production pack codecs, never a registry.
use super::*;
use codewire_project::ProjectSpec;
use codewire_vmm_guest_probe::{
    LayerEncoding, SetupBlob, SetupLayerBlob, SetupObject, Sha256Value, oci_root_generation,
};

const BUSYBOX_SHA256: &str = "198f6f675a49ac734082e054b823d3e2e947180ca2f632852ae1c09e950fd676";

pub(super) fn run(options: BTreeMap<String, String>) -> Result<()> {
    exact_keys(&options, &["--busybox-fd", "--output-fd"])?;
    let busybox_fd = descriptor(&options, "--busybox-fd")?;
    let output_fd = descriptor(&options, "--output-fd")?;
    if busybox_fd == output_fd {
        return Err(invalid().into());
    }
    let mut input = private_file(busybox_fd, false)?;
    let mut output = private_file(output_fd, true)?;
    if input.metadata()?.len() > 8 * 1024 * 1024 || output.metadata()?.len() != 0 {
        return Err(invalid().into());
    }
    let mut busybox = Vec::new();
    input.read_to_end(&mut busybox)?;
    // Same exact Alpine arm64 payload pinned by build-local-vmm-initramfs.sh.
    if Sha256Value::calculate(&busybox).to_string() != BUSYBOX_SHA256 {
        return Err(invalid().into());
    }
    output.write_all(&setup_pack(&busybox)?)?;
    output.sync_all()?;
    Ok(())
}

fn setup_pack(busybox: &[u8]) -> Result<Vec<u8>> {
    let layer = workspace_layer(busybox)?;
    let project = ProjectSpec {
        image: "example.invalid/codewire/vz-production-init:synthetic".to_owned(),
        ..ProjectSpec::default()
    }
    .canonical_json()?;
    let diff_id = Sha256Value::calculate(&layer);
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "arm64", "os": "linux",
        "config": { "User": "0", "Env": ["HOME=/root", "PATH=/bin", "SHELL=/bin/sh"],
            "WorkingDir": "/workspace" },
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{diff_id}")] }
    }))?;
    let project_sha256 = Sha256Value::calculate(&project);
    let manifest_sha256 =
        Sha256Value::calculate(b"codewire-vz-production-init-synthetic-manifest-v1");
    let header = SetupHeader::layout(
        oci_root_generation(project_sha256, manifest_sha256, SetupArchitecture::Arm64),
        manifest_sha256,
        SetupArchitecture::Arm64,
        SetupBlob {
            size: project.len() as u64,
            sha256: project_sha256,
        },
        SetupBlob {
            size: config.len() as u64,
            sha256: Sha256Value::calculate(&config),
        },
        vec![SetupLayerBlob {
            blob: SetupBlob {
                size: layer.len() as u64,
                sha256: Sha256Value::calculate(&layer),
            },
            diff_id,
            encoding: LayerEncoding::Tar,
        }],
    )?;
    let mut pack = vec![0; usize::try_from(header.total_bytes)?];
    pack[..SETUP_HEADER_LEN].copy_from_slice(&header.encode()?);
    copy_object(&mut pack, header.project, &project)?;
    copy_object(&mut pack, header.config, &config)?;
    copy_object(&mut pack, header.layers[0].object, &layer)?;
    Ok(pack)
}

fn copy_object(pack: &mut [u8], object: SetupObject, contents: &[u8]) -> Result<()> {
    let start = usize::try_from(object.offset)?;
    let end = start
        .checked_add(usize::try_from(object.size)?)
        .ok_or_else(invalid)?;
    let destination = pack.get_mut(start..end).ok_or_else(invalid)?;
    if destination.len() != contents.len() {
        return Err(invalid().into());
    }
    destination.copy_from_slice(contents);
    Ok(())
}

fn workspace_layer(busybox: &[u8]) -> Result<Vec<u8>> {
    if busybox.is_empty() {
        return Err(invalid().into());
    }
    let mut builder = tar::Builder::new(Vec::new());
    for (path, mode) in [
        ("bin", 0o755),
        ("dev", 0o755),
        ("proc", 0o555),
        ("root", 0o700),
        ("run", 0o755),
        ("sys", 0o555),
        ("tmp", 0o1777),
        ("workspace", 0o700),
    ] {
        entry(
            &mut builder,
            path,
            tar::EntryType::Directory,
            mode,
            None,
            &[],
        )?;
    }
    entry(
        &mut builder,
        "bin/busybox",
        tar::EntryType::Regular,
        0o755,
        None,
        busybox,
    )?;
    for applet in ["grep", "sh", "sleep", "tr", "wget"] {
        entry(
            &mut builder,
            &format!("bin/{applet}"),
            tar::EntryType::Symlink,
            0o777,
            Some(b"busybox"),
            &[],
        )?;
    }
    builder.finish()?;
    Ok(builder.into_inner()?)
}

fn entry(
    builder: &mut tar::Builder<Vec<u8>>,
    path: &str,
    kind: tar::EntryType,
    mode: u32,
    link: Option<&[u8]>,
    bytes: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_path(path)?;
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1);
    header.set_size(bytes.len() as u64);
    if let Some(link) = link {
        header.set_link_name_literal(link)?;
    }
    header.set_cksum();
    builder.append(&header, io::Cursor::new(bytes))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_pack_uses_complete_production_layout_and_arm64_bindings() {
        let pack = setup_pack(b"synthetic static tool bytes").unwrap();
        assert_eq!(pack, setup_pack(b"synthetic static tool bytes").unwrap());
        let header = SetupHeader::decode(&pack[..SETUP_HEADER_LEN]).unwrap();
        assert_eq!(header.architecture, SetupArchitecture::Arm64);
        assert_eq!(header.total_bytes as usize, pack.len());
        for object in [header.project, header.config, header.layers[0].object] {
            let bytes = &pack[object.offset as usize..(object.offset + object.size) as usize];
            assert_eq!(Sha256Value::calculate(bytes), object.sha256);
        }
        assert_ne!(pack, setup_pack(b"different synthetic tool bytes").unwrap());
    }

    #[test]
    fn empty_tool_and_bad_object_ranges_are_rejected() {
        assert!(setup_pack(&[]).is_err());
        let pack = setup_pack(b"synthetic").unwrap();
        let header = SetupHeader::decode(&pack[..SETUP_HEADER_LEN]).unwrap();
        assert!(copy_object(&mut [], header.project, b"wrong").is_err());
    }
}
