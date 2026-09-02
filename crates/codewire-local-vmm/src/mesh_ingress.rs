//! Private, generation-bound admission for host-side Codewire Mesh streams.
//!
//! The future host Mesh process owns WireGuard, UDP, DERP, coordinator state,
//! and every Mesh credential. It may hand the confined network worker only one
//! already-connected AF_UNIX stream bridge plus this authenticated record. The
//! worker admits the stream only for an immutable guest-port allowlist.

use std::collections::BTreeSet;

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::{Host, Url};
use uuid::Uuid;

use crate::host_port::RESERVED_GUEST_DAEMON_PORT;

pub const MESH_INGRESS_CONTROL_KEY_LEN: usize = 32;
pub const MESH_INGRESS_CONTROL_FRAME_LEN: usize = 80;
pub const MAX_MESH_INGRESS_PORTS: usize = 64;
const MAX_MESH_URL_BYTES: usize = 2_048;
const MAX_MESH_ID_BYTES: usize = 255;

const MESH_INGRESS_CONTROL_MAGIC: &[u8; 8] = b"CWMESHI1";
const MESH_INGRESS_CONTROL_TAG_OFFSET: usize = 48;

type HmacSha256 = Hmac<Sha256>;

/// Non-secret durable intent for attaching one local environment to one exact
/// Mesh network. Every field may appear in local status output. The endpoint
/// may identify a deployment, but this contract has no bearer/auth field and
/// rejects URL userinfo, query parameters, fragments, and cleartext remote
/// transport.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshAttachment {
    pub mesh_url: String,
    pub organization_id: String,
    pub network_id: String,
    pub node_name: String,
    pub guest_ports: Vec<u16>,
}

impl MeshAttachment {
    pub fn new(
        mesh_url: &str,
        organization_id: &str,
        network_id: &str,
        node_name: &str,
        guest_ports: impl IntoIterator<Item = u16>,
    ) -> Result<Self, MeshIngressError> {
        Ok(Self {
            mesh_url: canonical_mesh_url(mesh_url)?,
            organization_id: canonical_mesh_identifier(organization_id, MAX_MESH_ID_BYTES)
                .ok_or(MeshIngressError::InvalidAttachment)?,
            network_id: canonical_mesh_identifier(network_id, MAX_MESH_ID_BYTES)
                .ok_or(MeshIngressError::InvalidAttachment)?,
            node_name: canonical_mesh_node_name(node_name)
                .ok_or(MeshIngressError::InvalidAttachment)?,
            guest_ports: canonical_mesh_ingress_ports(guest_ports)?,
        })
    }

    pub fn validate(&self) -> Result<(), MeshIngressError> {
        let canonical = Self::new(
            &self.mesh_url,
            &self.organization_id,
            &self.network_id,
            &self.node_name,
            self.guest_ports.iter().copied(),
        )?;
        if canonical != *self {
            return Err(MeshIngressError::InvalidAttachment);
        }
        Ok(())
    }
}

fn canonical_mesh_url(raw: &str) -> Result<String, MeshIngressError> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.is_empty() || raw.len() > MAX_MESH_URL_BYTES {
        return Err(MeshIngressError::InvalidAttachment);
    }
    let parsed = Url::parse(raw).map_err(|_| MeshIngressError::InvalidAttachment)?;
    if parsed.cannot_be_a_base()
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.scheme(), "http" | "https")
    {
        return Err(MeshIngressError::InvalidAttachment);
    }
    if parsed.scheme() == "http" && !mesh_host_is_loopback(parsed.host()) {
        return Err(MeshIngressError::InsecureAttachment);
    }
    let canonical = parsed.as_str().trim_end_matches('/').to_owned();
    if canonical.is_empty() || canonical.len() > MAX_MESH_URL_BYTES {
        return Err(MeshIngressError::InvalidAttachment);
    }
    Ok(canonical)
}

fn mesh_host_is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn canonical_mesh_identifier(raw: &str, maximum: usize) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty()
        && value.len() <= maximum
        && value.chars().all(|character| !character.is_control()))
    .then(|| value.to_owned())
}

fn canonical_mesh_node_name(raw: &str) -> Option<String> {
    let value = raw.trim();
    let bytes = value.as_bytes();
    (!bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then(|| value.to_owned())
}

pub(crate) fn is_mesh_ingress_control_frame(frame: &[u8; MESH_INGRESS_CONTROL_FRAME_LEN]) -> bool {
    &frame[..MESH_INGRESS_CONTROL_MAGIC.len()] == MESH_INGRESS_CONTROL_MAGIC
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MeshIngressBinding {
    pub guest_port: u16,
}

impl MeshIngressBinding {
    pub fn new(guest_port: u16) -> Result<Self, MeshIngressError> {
        let binding = Self { guest_port };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(self) -> Result<(), MeshIngressError> {
        if self.guest_port == 0 || self.guest_port == RESERVED_GUEST_DAEMON_PORT {
            return Err(MeshIngressError::InvalidBinding);
        }
        Ok(())
    }
}

/// Return one sorted, unique, bounded immutable Mesh guest-port set.
pub fn canonical_mesh_ingress_ports(
    ports: impl IntoIterator<Item = u16>,
) -> Result<Vec<u16>, MeshIngressError> {
    let mut ports = ports.into_iter().collect::<Vec<_>>();
    if ports.len() > MAX_MESH_INGRESS_PORTS {
        return Err(MeshIngressError::TooManyPorts);
    }
    ports.sort_unstable();
    validate_canonical_mesh_ingress_ports(&ports)?;
    Ok(ports)
}

/// Validate a caller-provided canonical Mesh guest-port set.
pub fn validate_canonical_mesh_ingress_ports(ports: &[u16]) -> Result<(), MeshIngressError> {
    if ports.len() > MAX_MESH_INGRESS_PORTS {
        return Err(MeshIngressError::TooManyPorts);
    }
    let mut prior = None;
    for port in ports {
        MeshIngressBinding::new(*port)?;
        if prior.is_some_and(|prior| prior >= *port) {
            return Err(MeshIngressError::DuplicatePort);
        }
        prior = Some(*port);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshIngressControlFrame {
    pub binding: MeshIngressBinding,
    pub sequence: u64,
}

impl MeshIngressControlFrame {
    pub fn encode(
        vm_id: Uuid,
        generation: u64,
        sequence: u64,
        binding: MeshIngressBinding,
        key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    ) -> Result<[u8; MESH_INGRESS_CONTROL_FRAME_LEN], MeshIngressError> {
        validate_control_identity(vm_id, generation, sequence, key)?;
        binding.validate()?;
        let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
        frame[..8].copy_from_slice(MESH_INGRESS_CONTROL_MAGIC);
        frame[8..24].copy_from_slice(vm_id.as_bytes());
        frame[24..32].copy_from_slice(&generation.to_le_bytes());
        frame[32..40].copy_from_slice(&sequence.to_le_bytes());
        frame[40..42].copy_from_slice(&binding.guest_port.to_le_bytes());
        let tag = authenticate(&frame[..MESH_INGRESS_CONTROL_TAG_OFFSET], key)?;
        frame[MESH_INGRESS_CONTROL_TAG_OFFSET..].copy_from_slice(&tag);
        Ok(frame)
    }
}

pub struct MeshIngressControlReceiver {
    vm_id: Uuid,
    generation: u64,
    next_sequence: u64,
    allowed_ports: BTreeSet<u16>,
}

impl MeshIngressControlReceiver {
    pub fn new(
        vm_id: Uuid,
        generation: u64,
        allowed_ports: &[u16],
    ) -> Result<Self, MeshIngressError> {
        if vm_id.is_nil() || generation == 0 {
            return Err(MeshIngressError::InvalidIdentity);
        }
        validate_canonical_mesh_ingress_ports(allowed_ports)?;
        Ok(Self {
            vm_id,
            generation,
            next_sequence: 1,
            allowed_ports: allowed_ports.iter().copied().collect(),
        })
    }

    pub fn decode(
        &mut self,
        frame: &[u8; MESH_INGRESS_CONTROL_FRAME_LEN],
        key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    ) -> Result<MeshIngressControlFrame, MeshIngressError> {
        if &frame[..8] != MESH_INGRESS_CONTROL_MAGIC
            || frame[42..MESH_INGRESS_CONTROL_TAG_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            || key.iter().all(|byte| *byte == 0)
        {
            return Err(MeshIngressError::InvalidFrame);
        }
        let vm_id = Uuid::from_slice(&frame[8..24]).map_err(|_| MeshIngressError::InvalidFrame)?;
        let generation = u64::from_le_bytes(
            frame[24..32]
                .try_into()
                .expect("fixed Mesh ingress generation"),
        );
        let sequence = u64::from_le_bytes(
            frame[32..40]
                .try_into()
                .expect("fixed Mesh ingress sequence"),
        );
        if vm_id != self.vm_id || generation != self.generation || sequence != self.next_sequence {
            return Err(MeshIngressError::InvalidFrame);
        }
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MeshIngressError::InvalidKey)?;
        mac.update(&frame[..MESH_INGRESS_CONTROL_TAG_OFFSET]);
        mac.verify_slice(&frame[MESH_INGRESS_CONTROL_TAG_OFFSET..])
            .map_err(|_| MeshIngressError::Authentication)?;
        let binding = MeshIngressBinding::new(u16::from_le_bytes(
            frame[40..42]
                .try_into()
                .expect("fixed Mesh ingress guest port"),
        ))?;
        if !self.allowed_ports.contains(&binding.guest_port) {
            return Err(MeshIngressError::PortDenied);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(MeshIngressError::SequenceOverflow)?;
        Ok(MeshIngressControlFrame { binding, sequence })
    }
}

fn validate_control_identity(
    vm_id: Uuid,
    generation: u64,
    sequence: u64,
    key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
) -> Result<(), MeshIngressError> {
    if vm_id.is_nil() || generation == 0 || sequence == 0 {
        return Err(MeshIngressError::InvalidIdentity);
    }
    if key.iter().all(|byte| *byte == 0) {
        return Err(MeshIngressError::InvalidKey);
    }
    Ok(())
}

fn authenticate(
    message: &[u8],
    key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
) -> Result<[u8; 32], MeshIngressError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MeshIngressError::InvalidKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeshIngressError {
    #[error("Mesh attachment is invalid")]
    InvalidAttachment,
    #[error("remote Mesh attachment requires HTTPS")]
    InsecureAttachment,
    #[error("Mesh ingress binding is invalid")]
    InvalidBinding,
    #[error("too many Mesh ingress ports")]
    TooManyPorts,
    #[error("Mesh ingress ports are duplicated or not canonical")]
    DuplicatePort,
    #[error("Mesh ingress control identity is invalid")]
    InvalidIdentity,
    #[error("Mesh ingress control key is invalid")]
    InvalidKey,
    #[error("Mesh ingress control frame is invalid")]
    InvalidFrame,
    #[error("Mesh ingress control authentication failed")]
    Authentication,
    #[error("Mesh ingress guest port is not allowed")]
    PortDenied,
    #[error("Mesh ingress control sequence overflowed")]
    SequenceOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    fn key() -> [u8; MESH_INGRESS_CONTROL_KEY_LEN] {
        [0x4d; MESH_INGRESS_CONTROL_KEY_LEN]
    }

    #[test]
    fn ports_are_sorted_unique_bounded_and_reserve_the_daemon() {
        assert_eq!(
            canonical_mesh_ingress_ports([8_080, 22, 4_432]).unwrap(),
            vec![22, 4_432, 8_080]
        );
        assert_eq!(
            canonical_mesh_ingress_ports([22, 22]),
            Err(MeshIngressError::DuplicatePort)
        );
        assert_eq!(
            canonical_mesh_ingress_ports([RESERVED_GUEST_DAEMON_PORT]),
            Err(MeshIngressError::InvalidBinding)
        );
        assert_eq!(
            canonical_mesh_ingress_ports(1..=(MAX_MESH_INGRESS_PORTS as u16 + 1)),
            Err(MeshIngressError::TooManyPorts)
        );
    }

    #[test]
    fn attachment_is_canonical_bounded_and_has_no_auth_field() {
        let attachment = MeshAttachment::new(
            " https://MESH.example.test/base/ ",
            "org-test",
            "network_test",
            "dev.local",
            [8_080, 3_000],
        )
        .unwrap();
        assert_eq!(attachment.mesh_url, "https://mesh.example.test/base");
        assert_eq!(attachment.guest_ports, vec![3_000, 8_080]);
        attachment.validate().unwrap();
        assert_eq!(
            MeshAttachment::new(
                "https://mesh.example.test",
                "organization / β",
                "project network",
                "dev",
                [],
            )
            .unwrap()
            .network_id,
            "project network"
        );

        let mut noncanonical = attachment.clone();
        noncanonical.guest_ports.reverse();
        assert_eq!(
            noncanonical.validate(),
            Err(MeshIngressError::InvalidAttachment)
        );
        for denied in [
            "http://mesh.example.test",
            "https://user:secret@mesh.example.test",
            "https://mesh.example.test?token=secret",
            "file:///tmp/mesh",
        ] {
            assert!(MeshAttachment::new(denied, "org", "network", "node", []).is_err());
        }
        MeshAttachment::new("http://127.0.0.1:18090", "org", "network", "node", []).unwrap();
    }

    #[test]
    fn frames_bind_identity_port_sequence_key_and_allowlist() {
        let (vm_id, generation) = identity();
        let allowed = canonical_mesh_ingress_ports([22, 3_000]).unwrap();
        let binding = MeshIngressBinding::new(3_000).unwrap();
        let frame = MeshIngressControlFrame::encode(vm_id, generation, 1, binding, &key()).unwrap();
        let mut receiver = MeshIngressControlReceiver::new(vm_id, generation, &allowed).unwrap();
        assert_eq!(receiver.decode(&frame, &key()).unwrap().binding, binding);
        assert_eq!(
            receiver.decode(&frame, &key()),
            Err(MeshIngressError::InvalidFrame)
        );

        let denied = MeshIngressControlFrame::encode(
            vm_id,
            generation,
            1,
            MeshIngressBinding::new(4_000).unwrap(),
            &key(),
        )
        .unwrap();
        let mut receiver = MeshIngressControlReceiver::new(vm_id, generation, &allowed).unwrap();
        assert_eq!(
            receiver.decode(&denied, &key()),
            Err(MeshIngressError::PortDenied)
        );

        for forged in [
            MeshIngressControlFrame::encode(vm_id, generation + 1, 1, binding, &key()).unwrap(),
            MeshIngressControlFrame::encode(vm_id, generation, 2, binding, &key()).unwrap(),
        ] {
            let mut receiver =
                MeshIngressControlReceiver::new(vm_id, generation, &allowed).unwrap();
            assert_eq!(
                receiver.decode(&forged, &key()),
                Err(MeshIngressError::InvalidFrame)
            );
        }

        let mut receiver = MeshIngressControlReceiver::new(vm_id, generation, &allowed).unwrap();
        assert_eq!(
            receiver.decode(&frame, &[0x2a; MESH_INGRESS_CONTROL_KEY_LEN]),
            Err(MeshIngressError::Authentication)
        );

        let mut forged_port = frame;
        forged_port[40] ^= 1;
        let mut receiver = MeshIngressControlReceiver::new(vm_id, generation, &allowed).unwrap();
        assert_eq!(
            receiver.decode(&forged_port, &key()),
            Err(MeshIngressError::Authentication)
        );
    }
}
