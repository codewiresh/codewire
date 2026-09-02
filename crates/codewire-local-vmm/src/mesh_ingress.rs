//! Private, generation-bound admission for host-side Codewire Mesh streams.
//!
//! The future host Mesh process owns WireGuard, UDP, DERP, coordinator state,
//! and every Mesh credential. It may hand the confined network worker only one
//! already-connected AF_UNIX stream bridge plus this authenticated record. The
//! worker admits the stream only for an immutable guest-port allowlist.

use std::collections::BTreeSet;

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use uuid::Uuid;

use crate::host_port::RESERVED_GUEST_DAEMON_PORT;

pub const MESH_INGRESS_CONTROL_KEY_LEN: usize = 32;
pub const MESH_INGRESS_CONTROL_FRAME_LEN: usize = 80;
pub const MAX_MESH_INGRESS_PORTS: usize = 64;

const MESH_INGRESS_CONTROL_MAGIC: &[u8; 8] = b"CWMESHI1";
const MESH_INGRESS_CONTROL_TAG_OFFSET: usize = 48;

type HmacSha256 = Hmac<Sha256>;

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
