use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::descriptor::bounded_file;
use super::{Result, invalid};

pub(super) const FRAME_LEN: usize = 128;
pub(super) const BINDING_LEN: usize = 4096;
const STATUS_MAGIC: &[u8; 8] = b"CWCPST1\0";
const CONTROL_MAGIC: &[u8; 8] = b"CWCPCT1\0";
const STATUS_DOMAIN: &[u8] = b"codewire-console-pair-status-v1\0";
const CONTROL_DOMAIN: &[u8] = b"codewire-console-pair-control-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Profile {
    ConsolePair,
    #[cfg(feature = "macos-product-network-fixture")]
    ProductNetwork,
}

impl Profile {
    fn magic(self, control: bool) -> &'static [u8; 8] {
        match self {
            Self::ConsolePair => {
                if control {
                    CONTROL_MAGIC
                } else {
                    STATUS_MAGIC
                }
            }
            #[cfg(feature = "macos-product-network-fixture")]
            Self::ProductNetwork => {
                if control {
                    b"CWPNCT1\0"
                } else {
                    b"CWPNST1\0"
                }
            }
        }
    }

    fn domain(self, control: bool) -> &'static [u8] {
        match self {
            Self::ConsolePair => {
                if control {
                    CONTROL_DOMAIN
                } else {
                    STATUS_DOMAIN
                }
            }
            #[cfg(feature = "macos-product-network-fixture")]
            Self::ProductNetwork => {
                if control {
                    b"codewire-product-network-control-v1\0"
                } else {
                    b"codewire-product-network-status-v1\0"
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Role {
    Guest = 1,
    Service = 2,
}

impl Role {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "guest" => Ok(Self::Guest),
            "service" => Ok(Self::Service),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Status {
    PortsReady = 1,
    Prepared = 2,
    GuestArmed = 3,
    HostReady = 4,
    WorkerReady = 5,
    PacketCompleted = 6,
    EofObserved = 7,
    NoEofObserved = 8,
    Cancelled = 9,
    ChildrenReaped = 10,
    Failed = 11,
    PacketClosed = 12,
    EofArmed = 13,
    #[cfg(feature = "macos-product-network-fixture")]
    TopologyReady = 14,
    #[cfg(feature = "macos-product-network-fixture")]
    EndpointReady = 15,
    #[cfg(feature = "macos-product-network-fixture")]
    BrokerPrepared = 16,
    #[cfg(feature = "macos-product-network-fixture")]
    BrokerReady = 17,
    #[cfg(feature = "macos-product-network-fixture")]
    WorkerBrokerReady = 18,
    #[cfg(feature = "macos-product-network-fixture")]
    EndpointCompleted = 19,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Control {
    Start = 1,
    Cancel = 2,
    ClosePacket = 3,
    ObserveEof = 4,
    PowerOff = 5,
}

pub(super) struct Binding {
    pub profile: Profile,
    pub role: Role,
    pub vm_id: Uuid,
    pub generation: u64,
    pub nonce: [u8; 32],
    pub network_key: Zeroizing<[u8; 32]>,
    status_key: Zeroizing<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    schema_version: u32,
    role: String,
    #[serde(rename = "vmID")]
    vm_id: String,
    generation: u64,
    run_nonce: String,
    network_key: String,
    status_key: String,
}

// Separate strict structs preserve rejection of even a null/unknown kind in
// the old mode. Neither binary auto-detects a profile from untrusted input.
#[cfg(feature = "macos-product-network-fixture")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductDocument {
    schema_version: u32,
    kind: String,
    role: String,
    #[serde(rename = "vmID")]
    vm_id: String,
    generation: u64,
    run_nonce: String,
    network_key: String,
    status_key: String,
}

#[cfg(feature = "macos-product-network-fixture")]
impl Drop for ProductDocument {
    fn drop(&mut self) {
        self.network_key.zeroize();
        self.status_key.zeroize();
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        self.network_key.zeroize();
        self.status_key.zeroize();
    }
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut bytes = [0; 32];
    for (index, part) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[index] = nibble(part[0]) * 16 + nibble(part[1]);
    }
    if bytes == [0; 32] {
        return Err(invalid());
    }
    Ok(bytes)
}

impl Binding {
    pub(super) fn decode(bytes: &[u8], role: Role) -> Result<Self> {
        Self::decode_for(bytes, role, Profile::ConsolePair)
    }

    pub(super) fn decode_for(bytes: &[u8], role: Role, profile: Profile) -> Result<Self> {
        if bytes.len() != BINDING_LEN {
            return Err(invalid());
        }
        let end = bytes.iter().position(|b| *b == 0).ok_or_else(invalid)?;
        if end == 0 || end > 2048 || bytes[end..].iter().any(|b| *b != 0) {
            return Err(invalid());
        }
        let document: Document = match profile {
            Profile::ConsolePair => {
                let value: Document =
                    serde_json::from_slice(&bytes[..end]).map_err(|_| invalid())?;
                if value.schema_version != 1 {
                    return Err(invalid());
                }
                value
            }
            #[cfg(feature = "macos-product-network-fixture")]
            Profile::ProductNetwork => {
                let mut value: ProductDocument =
                    serde_json::from_slice(&bytes[..end]).map_err(|_| invalid())?;
                if value.schema_version != 2 || value.kind != "product-network" {
                    return Err(invalid());
                }
                Document {
                    schema_version: value.schema_version,
                    role: std::mem::take(&mut value.role),
                    vm_id: std::mem::take(&mut value.vm_id),
                    generation: value.generation,
                    run_nonce: std::mem::take(&mut value.run_nonce),
                    network_key: std::mem::take(&mut value.network_key),
                    status_key: std::mem::take(&mut value.status_key),
                }
            }
        };
        let parsed_role = Role::parse(&document.role)?;
        let vm_id = Uuid::parse_str(&document.vm_id).map_err(|_| invalid())?;
        if parsed_role != role
            || vm_id.is_nil()
            || vm_id.to_string() != document.vm_id
            || document.generation == 0
        {
            return Err(invalid());
        }
        let network_key = Zeroizing::new(hex32(&document.network_key)?);
        let status_key = Zeroizing::new(hex32(&document.status_key)?);
        if network_key == status_key {
            return Err(invalid());
        }
        Ok(Self {
            profile,
            role,
            vm_id,
            generation: document.generation,
            nonce: hex32(&document.run_nonce)?,
            network_key,
            status_key,
        })
    }

    pub(super) fn read(role: Role, deadline: Instant) -> Result<Self> {
        Self::read_for(role, deadline, Profile::ConsolePair)
    }

    pub(super) fn read_for(role: Role, deadline: Instant, profile: Profile) -> Result<Self> {
        loop {
            let path = codewire_vmm_guest_probe::guest::find_disk_by_serial(
                Path::new("/sys/class/block"),
                Path::new("/dev"),
                "CWCONSOLEPAIR1",
            );
            match path {
                Ok(path) => {
                    let component = path.file_name().ok_or_else(invalid)?;
                    let device = bounded_file(
                        &Path::new("/sys/class/block").join(component).join("dev"),
                        32,
                    )?;
                    let expected = super::descriptor::dev_number(&device)?;
                    let mut file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(path)?;
                    let metadata = file.metadata()?;
                    if !metadata.file_type().is_block_device() || metadata.rdev() != expected {
                        return Err(invalid());
                    }
                    let mut size: u64 = 0;
                    // Linux BLKGETSIZE64: the admitted binding is exactly one
                    // 4096-byte read-only artifact, not a prefix of another disk.
                    if unsafe { libc::ioctl(file.as_raw_fd(), 0x8008_1272_u32 as _, &raw mut size) }
                        != 0
                        || size != BINDING_LEN as u64
                    {
                        return Err(invalid());
                    }
                    let mut read_only: libc::c_int = 0;
                    if unsafe { libc::ioctl(file.as_raw_fd(), 0x125e_u32 as _, &raw mut read_only) }
                        != 0
                        || read_only != 1
                    {
                        return Err(invalid());
                    }
                    let mut bytes = Zeroizing::new([0_u8; BINDING_LEN]);
                    file.read_exact(bytes.as_mut())?;
                    return match profile {
                        Profile::ConsolePair => Self::decode(bytes.as_ref(), role),
                        #[cfg(feature = "macos-product-network-fixture")]
                        Profile::ProductNetwork => Self::decode_for(bytes.as_ref(), role, profile),
                    };
                }
                Err(error) => {
                    if error.to_string().starts_with("multiple ") || Instant::now() >= deadline {
                        return Err(invalid());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn frame(&self, code: u8, sequence: u64, control: bool) -> [u8; FRAME_LEN] {
        let mut bytes = [0; FRAME_LEN];
        bytes[..8].copy_from_slice(self.profile.magic(control));
        bytes[8] = self.role as u8;
        bytes[9] = code;
        bytes[16..32].copy_from_slice(self.vm_id.as_bytes());
        bytes[32..40].copy_from_slice(&self.generation.to_le_bytes());
        bytes[40..72].copy_from_slice(&self.nonce);
        bytes[72..80].copy_from_slice(&sequence.to_le_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(self.status_key.as_ref()).expect("fixed key");
        mac.update(self.profile.domain(control));
        mac.update(&bytes[..96]);
        bytes[96..].copy_from_slice(&mac.finalize().into_bytes());
        bytes
    }

    pub(super) fn status(&self, code: Status, sequence: u64) -> [u8; FRAME_LEN] {
        self.frame(code as u8, sequence, false)
    }

    pub(super) fn reaped(
        &self,
        sequence: u64,
        worker: i32,
        adapter: i32,
    ) -> Result<[u8; FRAME_LEN]> {
        if self.role != Role::Service || self.profile != Profile::ConsolePair {
            return Err(invalid());
        }
        let mut bytes = self.frame(Status::ChildrenReaped as u8, sequence, false);
        bytes[80..84].copy_from_slice(&worker.to_le_bytes());
        bytes[84..88].copy_from_slice(&adapter.to_le_bytes());
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.status_key.as_ref()).map_err(|_| invalid())?;
        mac.update(STATUS_DOMAIN);
        mac.update(&bytes[..96]);
        bytes[96..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }

    #[cfg(feature = "macos-product-network-fixture")]
    pub(super) fn product_reaped(&self, sequence: u64, waits: [i32; 4]) -> Result<[u8; FRAME_LEN]> {
        if self.role != Role::Service || self.profile != Profile::ProductNetwork {
            return Err(invalid());
        }
        let mut bytes = self.frame(Status::ChildrenReaped as u8, sequence, false);
        for (index, wait) in waits.into_iter().enumerate() {
            bytes[80 + index * 4..84 + index * 4].copy_from_slice(&wait.to_le_bytes());
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.status_key.as_ref()).map_err(|_| invalid())?;
        mac.update(self.profile.domain(false));
        mac.update(&bytes[..96]);
        bytes[96..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }

    pub(super) fn control(&self, bytes: &[u8], sequence: u64) -> Result<Control> {
        if bytes.len() != FRAME_LEN || sequence == 0 {
            return Err(invalid());
        }
        let expected = self.frame(bytes[9], sequence, true);
        if bytes[..96] != expected[..96] {
            return Err(invalid());
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.status_key.as_ref()).map_err(|_| invalid())?;
        mac.update(self.profile.domain(true));
        mac.update(&bytes[..96]);
        mac.verify_slice(&bytes[96..]).map_err(|_| invalid())?;
        match bytes[9] {
            1 => Ok(Control::Start),
            2 => Ok(Control::Cancel),
            3 => Ok(Control::ClosePacket),
            4 => Ok(Control::ObserveEof),
            5 => Ok(Control::PowerOff),
            _ => Err(invalid()),
        }
    }

    #[cfg(test)]
    pub(super) fn test_control(&self, code: Control, sequence: u64) -> [u8; FRAME_LEN] {
        self.frame(code as u8, sequence, true)
    }
}
