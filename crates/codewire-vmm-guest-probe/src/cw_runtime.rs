//! Public identity and bounded membership of an immutable cw runtime catalog.
//! Runtime selection is independent of the boot and workspace generations.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const CW_RUNTIME_SOURCE: &str = "/codewire-cw";
pub const CW_RUNTIME_ROOT: &str = "/run/codewire-runtime/cw";
pub const CW_RUNTIME_PROVENANCE_ENTRY: &[u8] = b"codewire-cw/provenance.json";
pub const CW_RUNTIME_MAX_BYTES: usize = 256 * 1024 * 1024;
pub const CW_RUNTIME_MAX_PROVENANCE: usize = 16 * 1024;
pub const CW_RUNTIME_MAX_VERSIONS: usize = 16;
pub const CW_RUNTIME_MAX_CATALOG: usize = CW_RUNTIME_MAX_VERSIONS * CW_RUNTIME_MAX_PROVENANCE;
pub const CW_RUNTIME_MAX_TOTAL_BYTES: u64 =
    CW_RUNTIME_MAX_VERSIONS as u64 * CW_RUNTIME_MAX_BYTES as u64;
pub const CW_RUNTIME_DISK_SERIAL: &str = "CWRUNTIME1";
pub const CW_RUNTIME_PACK_HEADER_BYTES: usize = 24;
pub const CW_RUNTIME_MAX_PACK: usize =
    CW_RUNTIME_PACK_HEADER_BYTES + CW_RUNTIME_MAX_PROVENANCE + CW_RUNTIME_MAX_BYTES;
const CW_RUNTIME_PACK_MAGIC: &[u8; 8] = b"CWRPACK1";

/// A fixed two-object transport, with no archive paths, links or extension
/// records. The externally admitted pack digest and image index select it.
pub fn decode_runtime_pack(bytes: &[u8]) -> Result<(CwRuntimeProvenance, &[u8]), &'static str> {
    if !(CW_RUNTIME_PACK_HEADER_BYTES..=CW_RUNTIME_MAX_PACK).contains(&bytes.len())
        || bytes.get(..8) != Some(CW_RUNTIME_PACK_MAGIC.as_slice())
    {
        return Err("invalid cw runtime pack framing");
    }
    let provenance_len = usize::try_from(u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
        .map_err(|_| "cw runtime provenance length overflow")?;
    let payload_len = usize::try_from(u64::from_le_bytes(bytes[16..24].try_into().unwrap()))
        .map_err(|_| "cw runtime payload length overflow")?;
    if !(1..=CW_RUNTIME_MAX_PROVENANCE).contains(&provenance_len)
        || !(64..=CW_RUNTIME_MAX_BYTES).contains(&payload_len)
    {
        return Err("cw runtime pack exceeds its object bounds");
    }
    let start = CW_RUNTIME_PACK_HEADER_BYTES + provenance_len;
    if start.checked_add(payload_len) != Some(bytes.len()) {
        return Err("cw runtime pack has truncated or trailing bytes");
    }
    let provenance = CwRuntimeProvenance::decode(&bytes[CW_RUNTIME_PACK_HEADER_BYTES..start])?;
    let payload = &bytes[start..];
    provenance.validate_payload(payload)?;
    Ok((provenance, payload))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwImageDescriptor {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwImagePayload {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub record_version: u32,
    pub package_version: String,
    pub target: String,
    pub source_revision: String,
    pub source_tree_sha256: String,
    pub rustc: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeProvenance {
    pub schema_version: u32,
    pub image_index_sha256: String,
    pub image_manifest: CwImageDescriptor,
    pub image_config: CwImageDescriptor,
    pub image_layer: CwImageDescriptor,
    pub layer_diff_id: String,
    pub payload: CwImagePayload,
}

/// Sorted membership and the default for new conversations. A retained
/// conversation continues to name its own payload digest, not this default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeCatalog {
    pub schema_version: u32,
    pub active_sha256: String,
    pub runtimes: Vec<CwRuntimeProvenance>,
}

impl CwRuntimeCatalog {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > CW_RUNTIME_MAX_CATALOG {
            return Err("cw runtime catalog exceeds its bound");
        }
        let catalog: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid cw runtime catalog")?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !hex(&self.active_sha256, 64)
            || self.runtimes.is_empty()
            || self.runtimes.len() > CW_RUNTIME_MAX_VERSIONS
        {
            return Err("unsupported cw runtime catalog");
        }
        let mut previous: Option<&str> = None;
        let mut total = 0_u64;
        for runtime in &self.runtimes {
            runtime.validate()?;
            let digest = runtime.payload.sha256.as_str();
            if previous.is_some_and(|previous| previous >= digest) {
                return Err("cw runtime catalog membership is not unique and sorted");
            }
            previous = Some(digest);
            total = total
                .checked_add(runtime.payload.size)
                .ok_or("cw runtime catalog size overflow")?;
        }
        if total > CW_RUNTIME_MAX_TOTAL_BYTES || self.runtime(&self.active_sha256).is_none() {
            return Err("cw runtime catalog cannot admit its active payload");
        }
        Ok(())
    }

    pub fn runtime(&self, sha256: &str) -> Option<&CwRuntimeProvenance> {
        self.runtimes
            .iter()
            .find(|runtime| runtime.payload.sha256 == sha256)
    }

    pub fn active(&self) -> Result<&CwRuntimeProvenance, &'static str> {
        self.validate()?;
        self.runtime(&self.active_sha256)
            .ok_or("cw runtime catalog omitted its active payload")
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| "encode cw runtime catalog")?;
        bytes.push(b'\n');
        if bytes.len() > CW_RUNTIME_MAX_CATALOG {
            return Err("cw runtime catalog exceeds its bound");
        }
        Ok(bytes)
    }
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl CwRuntimeProvenance {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > CW_RUNTIME_MAX_PROVENANCE {
            return Err("cw boot provenance exceeds its bound");
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid cw boot provenance")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let payload = &self.payload;
        let descriptors = [&self.image_manifest, &self.image_config, &self.image_layer];
        if self.schema_version != 1
            || !hex(&self.image_index_sha256, 64)
            || descriptors.iter().any(|descriptor| {
                !hex(&descriptor.sha256, 64)
                    || descriptor.size == 0
                    || descriptor.size > (CW_RUNTIME_MAX_BYTES + 4 * 1024 * 1024) as u64
            })
            || self.layer_diff_id != self.image_layer.sha256
            || payload.schema_version != 2
            || payload.protocol_version != 1
            || payload.record_version != 1
            || payload.package_version.is_empty()
            || payload.package_version.len() > 64
            || !payload
                .package_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
            || payload.target != "x86_64-unknown-linux-musl"
            || !hex(&payload.source_revision, 40)
            || !hex(&payload.source_tree_sha256, 64)
            || !hex(&payload.sha256, 64)
            || !payload.rustc.starts_with("rustc 1.93.0 ")
            || payload.rustc.len() > 128
            || !(64..=CW_RUNTIME_MAX_BYTES as u64).contains(&payload.size)
        {
            return Err("unsupported cw image identity");
        }
        Ok(())
    }

    pub fn validate_payload(&self, cw: &[u8]) -> Result<(), &'static str> {
        self.validate()?;
        if cw.len() as u64 != self.payload.size
            || format!("{:x}", Sha256::digest(cw)) != self.payload.sha256
        {
            return Err("cw boot payload identity changed");
        }
        validate_static_cw(cw)
    }

    pub fn executable(&self) -> String {
        format!("{CW_RUNTIME_ROOT}/{}/cw", self.payload.sha256)
    }

    pub fn archive_entry(&self) -> String {
        format!("codewire-cw/{}/cw", self.payload.sha256)
    }
}

/// A static x86_64 ELF may contain a static PIE dynamic table, but may neither
/// request a guest interpreter nor name a shared-library dependency.
pub fn validate_static_cw(bytes: &[u8]) -> Result<(), &'static str> {
    let invalid = "cw must be a bounded static x86_64 ELF";
    if !(64..=CW_RUNTIME_MAX_BYTES).contains(&bytes.len())
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16::from_le_bytes(bytes[16..18].try_into().unwrap()), 2 | 3)
        || u16::from_le_bytes(bytes[18..20].try_into().unwrap()) != 62
    {
        return Err(invalid);
    }
    let offset = usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap()))
        .map_err(|_| invalid)?;
    let size = usize::from(u16::from_le_bytes(bytes[54..56].try_into().unwrap()));
    let count = usize::from(u16::from_le_bytes(bytes[56..58].try_into().unwrap()));
    if offset < 64 || size != 56 || !(1..=128).contains(&count) {
        return Err(invalid);
    }
    let end = offset
        .checked_add(size.checked_mul(count).ok_or(invalid)?)
        .ok_or(invalid)?;
    for header in bytes.get(offset..end).ok_or(invalid)?.chunks_exact(size) {
        match u32::from_le_bytes(header[..4].try_into().unwrap()) {
            3 => return Err(invalid),
            2 => {
                let start = usize::try_from(u64::from_le_bytes(header[8..16].try_into().unwrap()))
                    .map_err(|_| invalid)?;
                let length =
                    usize::try_from(u64::from_le_bytes(header[32..40].try_into().unwrap()))
                        .map_err(|_| invalid)?;
                let end = start.checked_add(length).ok_or(invalid)?;
                let dynamic = bytes.get(start..end).ok_or(invalid)?;
                if !length.is_multiple_of(16) {
                    return Err(invalid);
                }
                for entry in dynamic.chunks_exact(16) {
                    match i64::from_le_bytes(entry[..8].try_into().unwrap()) {
                        0 => break,
                        1 => return Err(invalid),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture() -> (Vec<u8>, Vec<u8>) {
    let mut cw = vec![0_u8; 136];
    cw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    cw[16..18].copy_from_slice(&2_u16.to_le_bytes());
    cw[18..20].copy_from_slice(&62_u16.to_le_bytes());
    cw[32..40].copy_from_slice(&64_u64.to_le_bytes());
    cw[54..56].copy_from_slice(&56_u16.to_le_bytes());
    cw[56..58].copy_from_slice(&1_u16.to_le_bytes());
    cw[64..68].copy_from_slice(&1_u32.to_le_bytes());
    let descriptor = CwImageDescriptor {
        sha256: "c".repeat(64),
        size: 10240,
    };
    let provenance = CwRuntimeProvenance {
        schema_version: 1,
        image_index_sha256: "d".repeat(64),
        image_manifest: descriptor.clone(),
        image_config: descriptor.clone(),
        image_layer: descriptor,
        layer_diff_id: "c".repeat(64),
        payload: CwImagePayload {
            schema_version: 2,
            protocol_version: 1,
            record_version: 1,
            package_version: "0.1.0".to_owned(),
            target: "x86_64-unknown-linux-musl".to_owned(),
            source_revision: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            rustc: "rustc 1.93.0 (synthetic fixture)".to_owned(),
            sha256: format!("{:x}", Sha256::digest(&cw)),
            size: cw.len() as u64,
        },
    };
    (cw, serde_json::to_vec(&provenance).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_pack_refuses_ambiguous_lengths_and_corrupt_payloads() {
        let (cw, provenance) = fixture();
        let mut pack = CW_RUNTIME_PACK_MAGIC.to_vec();
        pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
        pack.extend_from_slice(&(cw.len() as u64).to_le_bytes());
        pack.extend_from_slice(&provenance);
        pack.extend_from_slice(&cw);
        let (identity, decoded) = decode_runtime_pack(&pack).unwrap();
        assert_eq!(decoded, cw);
        assert_eq!(
            identity.payload.sha256,
            format!("{:x}", Sha256::digest(&cw))
        );
        for range in [0..7, 0..24, 0..pack.len() - 1] {
            assert!(decode_runtime_pack(&pack[range]).is_err());
        }
        let mut changed = pack.clone();
        changed.push(0);
        assert!(decode_runtime_pack(&changed).is_err());
        changed = pack.clone();
        changed[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_runtime_pack(&changed).is_err());
        changed = pack;
        *changed.last_mut().unwrap() ^= 1;
        assert!(decode_runtime_pack(&changed).is_err());
    }
    #[test]
    fn catalog_admits_retained_history_independently_of_the_active_default() {
        let (_, bytes) = fixture();
        let old = CwRuntimeProvenance::decode(&bytes).unwrap();
        let mut current = old.clone();
        current.payload.sha256 = "f".repeat(64);
        current.payload.source_revision = "e".repeat(40);
        let catalog = CwRuntimeCatalog {
            schema_version: 1,
            active_sha256: current.payload.sha256.clone(),
            runtimes: vec![old.clone(), current.clone()],
        };
        assert_eq!(
            CwRuntimeCatalog::decode(&catalog.encode().unwrap()).unwrap(),
            catalog
        );
        assert_eq!(catalog.active().unwrap(), &current);
        assert_eq!(catalog.runtime(&old.payload.sha256).unwrap(), &old);
        let mut changed = catalog.clone();
        changed.active_sha256 = "0".repeat(64);
        assert!(changed.validate().is_err());
        changed = catalog.clone();
        changed.runtimes.reverse();
        assert!(changed.validate().is_err());
        changed = catalog;
        changed.runtimes = vec![old; CW_RUNTIME_MAX_VERSIONS + 1];
        assert!(changed.validate().is_err());
    }
    #[test]
    fn cw_provenance_binds_image_payload_and_protocol() {
        let (cw, bytes) = fixture();
        let provenance = CwRuntimeProvenance::decode(&bytes).unwrap();
        provenance.validate_payload(&cw).unwrap();
        assert_eq!(
            provenance.executable(),
            format!("{CW_RUNTIME_ROOT}/{}/cw", provenance.payload.sha256)
        );
        let mut changed = cw.clone();
        changed[135] = 1;
        assert!(provenance.validate_payload(&changed).is_err());
        let mut changed = provenance.clone();
        changed.payload.protocol_version = 2;
        assert!(changed.validate_payload(&cw).is_err());
        changed = provenance.clone();
        changed.layer_diff_id = "e".repeat(64);
        assert!(changed.validate().is_err());
        changed = provenance;
        changed.payload.size = CW_RUNTIME_MAX_BYTES as u64 + 1;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn cw_provenance_refuses_duplicate_unknown_and_unbounded_metadata() {
        let (_, bytes) = fixture();
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(CwRuntimeProvenance::decode(duplicate.as_bytes()).is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        unknown["path"] = serde_json::json!("/host/runtime");
        assert!(CwRuntimeProvenance::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
        assert!(CwRuntimeProvenance::decode(&vec![b' '; CW_RUNTIME_MAX_PROVENANCE + 1]).is_err());
    }
}
