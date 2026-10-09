//! The release-signature verifier built into cw. It runs no external program
//! and accepts one narrow OpenPGP profile: what
//! scripts/ci/release/sign-cw-release.sh produces with the pinned key. That
//! is a v4 RSA primary key with only self-certified user IDs, and exactly one
//! v4 detached binary-document signature by that key over SHA-2. ring
//! supplies the digests and the RSA PKCS#1 v1.5 verification.
//!
//! The key is compiled in, so its state cannot change at runtime: import
//! fails closed on anything that could limit it (a revocation, an expiry, a
//! subkey, a direct-key or third-party signature). Signature refusals match
//! the GnuPG wrapper this replaces: a bad, expired, wrongly classed, SHA-1 or
//! doubled signature, or one by any other key. As with GnuPG, a signature
//! dated in the future is accepted, so a client clock behind the signer's
//! never refuses a fresh release.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ring::digest;
use ring::signature::{self, RsaPublicKeyComponents};

use crate::release::{MAX_SIGNATURE_BYTES, valid_fingerprint, validate_signature};

const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_PACKETS: usize = 64;
const PUBLIC_KEY: u8 = 6;
const SIGNATURE: u8 = 2;
const USER_ID: u8 = 13;
const RSA: u8 = 1;
const BINARY_DOCUMENT: u8 = 0x00;
const SIGN_FLAG: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("compiled release key is malformed, outside its profile or differs from its pin")]
    Key,
    #[error("compiled release key is revoked, expiring or cannot sign")]
    KeyUnusable,
    #[error("release signature is malformed or outside the accepted profile")]
    Malformed,
    #[error("release must have exactly one valid detached signature by its pinned primary key")]
    Bad,
    #[error("release signature has expired")]
    Expired,
}

type Result<T> = std::result::Result<T, SignatureError>;
/// A framing failure; each caller maps it to its own refusal.
type Parse<T> = std::result::Result<T, ()>;

/// The pinned primary release key, admitted from its compiled armored bytes.
#[derive(Debug, Clone)]
pub struct ReleaseKey {
    packet: Vec<u8>,
    fingerprint: [u8; 20],
    created: u64,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl ReleaseKey {
    /// Admit `armored` only when it is exactly the pinned primary key, with
    /// a valid self-certification for signing and nothing that limits it.
    pub fn import(armored: &[u8], fingerprint: &str) -> Result<Self> {
        Self::import_at(armored, fingerprint, now())
    }

    pub fn verify(&self, data: &[u8], armored_signature: &[u8]) -> Result<()> {
        self.verify_at(data, armored_signature, now())
    }

    fn import_at(armored: &[u8], fingerprint: &str, now: u64) -> Result<Self> {
        if !valid_fingerprint(fingerprint) || armored.is_empty() || armored.len() > MAX_KEY_BYTES {
            return Err(SignatureError::Key);
        }
        let bytes = dearmor(armored, "PUBLIC KEY BLOCK").map_err(|()| SignatureError::Key)?;
        let packets = packets(&bytes).map_err(|()| SignatureError::Key)?;
        let (first, rest) = packets.split_first().ok_or(SignatureError::Key)?;
        if first.tag != PUBLIC_KEY {
            return Err(SignatureError::Key);
        }
        let key = Self::primary(first.body)?;
        if hex(&key.fingerprint) != fingerprint {
            return Err(SignatureError::Key);
        }

        // Grammar: the key, then user IDs, each followed by its own
        // self-certifications. Every other packet or signature is refused.
        let mut uid: Option<&[u8]> = None;
        let mut certified = false;
        for packet in rest {
            match packet.tag {
                USER_ID => uid = Some(packet.body),
                SIGNATURE => {
                    let signature =
                        Signature::parse(packet.body).map_err(|()| SignatureError::Key)?;
                    match signature.class {
                        0x10..=0x13 => {}
                        0x20 | 0x28 | 0x30 => return Err(SignatureError::KeyUnusable),
                        _ => return Err(SignatureError::Key),
                    }
                    let uid = uid.ok_or(SignatureError::Key)?;
                    if !signature.issued_by(&key.fingerprint) {
                        return Err(SignatureError::Key);
                    }
                    if signature.key_expiry.is_some_and(|seconds| seconds != 0) {
                        return Err(SignatureError::KeyUnusable);
                    }
                    let mut message = key.packet.clone();
                    message.push(0xb4);
                    message.extend_from_slice(&len32(uid.len())?);
                    message.extend_from_slice(uid);
                    key.check(&signature, message, now)
                        .map_err(|_| SignatureError::Key)?;
                    certified |= signature.flags.is_some_and(|flags| flags & SIGN_FLAG != 0);
                }
                _ => return Err(SignatureError::Key),
            }
        }
        if !certified {
            return Err(SignatureError::KeyUnusable);
        }
        Ok(key)
    }

    fn verify_at(&self, data: &[u8], armored: &[u8], now: u64) -> Result<()> {
        validate_signature(armored).map_err(|_| SignatureError::Malformed)?;
        let bytes = dearmor(armored, "SIGNATURE").map_err(|()| SignatureError::Malformed)?;
        let packets = packets(&bytes).map_err(|()| SignatureError::Malformed)?;
        let [packet] = packets.as_slice() else {
            return Err(SignatureError::Bad);
        };
        if packet.tag != SIGNATURE {
            return Err(SignatureError::Malformed);
        }
        let signature = Signature::parse(packet.body).map_err(|()| SignatureError::Malformed)?;
        if signature.class != BINARY_DOCUMENT || !signature.issued_by(&self.fingerprint) {
            return Err(SignatureError::Bad);
        }
        self.check(&signature, data.to_vec(), now)
    }

    fn primary(body: &[u8]) -> Result<Self> {
        let mut reader = Reader(body);
        let version = reader.u8().map_err(|()| SignatureError::Key)?;
        let created = reader.u32().map_err(|()| SignatureError::Key)?;
        let algorithm = reader.u8().map_err(|()| SignatureError::Key)?;
        if version != 4 || algorithm != RSA {
            return Err(SignatureError::Key);
        }
        let n = reader.mpi().map_err(|()| SignatureError::Key)?.to_vec();
        let e = reader.mpi().map_err(|()| SignatureError::Key)?.to_vec();
        if !reader.0.is_empty() || !(2048..=8192).contains(&bit_length(&n)) || e.len() > 8 {
            return Err(SignatureError::Key);
        }
        let mut packet = vec![0x99];
        packet.extend_from_slice(&len16(body.len()).map_err(|_| SignatureError::Key)?);
        packet.extend_from_slice(body);
        let sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &packet);
        let fingerprint = sha1.as_ref().try_into().map_err(|_| SignatureError::Key)?;
        Ok(Self {
            packet,
            fingerprint,
            created: u64::from(created),
            n,
            e,
        })
    }

    /// Verify one parsed signature over `message`, the bytes that precede
    /// its trailer, by this key.
    fn check(&self, signature: &Signature, mut message: Vec<u8>, now: u64) -> Result<()> {
        if signature.algorithm != RSA || signature.created < self.created {
            return Err(SignatureError::Bad);
        }
        if signature
            .expiry
            .filter(|seconds| *seconds != 0)
            .is_some_and(|seconds| now >= signature.created + seconds)
        {
            return Err(SignatureError::Expired);
        }
        let (algorithm, parameters) = match signature.hash {
            8 => (&digest::SHA256, &signature::RSA_PKCS1_2048_8192_SHA256),
            9 => (&digest::SHA384, &signature::RSA_PKCS1_2048_8192_SHA384),
            10 => (&digest::SHA512, &signature::RSA_PKCS1_2048_8192_SHA512),
            _ => return Err(SignatureError::Bad),
        };
        message.extend_from_slice(&signature.trailer);
        if digest::digest(algorithm, &message).as_ref()[..2] != signature.left16 {
            return Err(SignatureError::Bad);
        }
        let width = self.n.len();
        if signature.value.len() > width {
            return Err(SignatureError::Bad);
        }
        let mut value = vec![0; width - signature.value.len()];
        value.extend_from_slice(&signature.value);
        RsaPublicKeyComponents {
            n: &self.n,
            e: &self.e,
        }
        .verify(parameters, &message, &value)
        .map_err(|_| SignatureError::Bad)
    }
}

struct Signature {
    class: u8,
    algorithm: u8,
    hash: u8,
    created: u64,
    expiry: Option<u64>,
    key_expiry: Option<u64>,
    flags: Option<u8>,
    issuer_ids: Vec<[u8; 8]>,
    issuer_fingerprints: Vec<[u8; 20]>,
    trailer: Vec<u8>,
    left16: [u8; 2],
    value: Vec<u8>,
}

impl Signature {
    fn parse(body: &[u8]) -> Parse<Self> {
        let mut reader = Reader(body);
        if reader.u8()? != 4 {
            return Err(());
        }
        let class = reader.u8()?;
        let algorithm = reader.u8()?;
        let hash = reader.u8()?;
        let hashed_length = usize::from(reader.u16()?);
        let hashed = reader.take(hashed_length)?;
        let unhashed_length = usize::from(reader.u16()?);
        let unhashed = reader.take(unhashed_length)?;
        let left16 = reader.take(2)?.try_into().map_err(|_| ())?;
        let value = reader.mpi()?.to_vec();
        if !reader.0.is_empty() {
            return Err(());
        }

        let mut signature = Self {
            class,
            algorithm,
            hash,
            created: 0,
            expiry: None,
            key_expiry: None,
            flags: None,
            issuer_ids: Vec::new(),
            issuer_fingerprints: Vec::new(),
            trailer: Vec::new(),
            left16,
            value,
        };
        let mut created = None;
        for Subpacket {
            critical,
            kind,
            data,
        } in subpackets(hashed)?
        {
            match kind {
                2 if data.len() == 4 && created.is_none() => {
                    created = Some(u64::from(u32::from_be_bytes(
                        data.try_into().map_err(|_| ())?,
                    )));
                }
                3 if data.len() == 4 && signature.expiry.is_none() => {
                    signature.expiry = Some(u64::from(u32::from_be_bytes(
                        data.try_into().map_err(|_| ())?,
                    )));
                }
                9 if data.len() == 4 && signature.key_expiry.is_none() => {
                    signature.key_expiry = Some(u64::from(u32::from_be_bytes(
                        data.try_into().map_err(|_| ())?,
                    )));
                }
                27 if !data.is_empty() && signature.flags.is_none() => {
                    signature.flags = Some(data[0]);
                }
                16 | 33 => signature.issuer(kind, data)?,
                // Preferences and the primary user ID flag do not change
                // whether a signature is valid.
                11 | 21 | 22 | 23 | 25 | 30 => {}
                2 | 3 | 9 | 27 => return Err(()),
                _ if critical => return Err(()),
                _ => {}
            }
        }
        // Unhashed subpackets are unauthenticated: only the issuer, which
        // must still name the pinned key, is read from them.
        for subpacket in subpackets(unhashed)? {
            if subpacket.kind == 16 || subpacket.kind == 33 {
                signature.issuer(subpacket.kind, subpacket.data)?;
            }
        }
        signature.created = created.ok_or(())?;

        signature.trailer = Vec::with_capacity(hashed_length + 12);
        signature
            .trailer
            .extend_from_slice(&[4, class, algorithm, hash]);
        signature
            .trailer
            .extend_from_slice(&len16(hashed_length).map_err(|_| ())?);
        signature.trailer.extend_from_slice(hashed);
        signature.trailer.extend_from_slice(&[4, 0xff]);
        signature
            .trailer
            .extend_from_slice(&len32(hashed_length + 6).map_err(|_| ())?);
        Ok(signature)
    }

    fn issuer(&mut self, kind: u8, data: &[u8]) -> Parse<()> {
        match (kind, data) {
            (16, id) => self.issuer_ids.push(id.try_into().map_err(|_| ())?),
            (33, [4, fingerprint @ ..]) => self
                .issuer_fingerprints
                .push(fingerprint.try_into().map_err(|_| ())?),
            _ => return Err(()),
        }
        Ok(())
    }

    /// Every issuer named, hashed or not, must be the pinned primary key.
    fn issued_by(&self, fingerprint: &[u8; 20]) -> bool {
        (!self.issuer_ids.is_empty() || !self.issuer_fingerprints.is_empty())
            && self.issuer_ids.iter().all(|id| id == &fingerprint[12..])
            && self.issuer_fingerprints.iter().all(|f| f == fingerprint)
    }
}

struct Subpacket<'a> {
    critical: bool,
    kind: u8,
    data: &'a [u8],
}

struct Packet<'a> {
    tag: u8,
    body: &'a [u8],
}

fn packets(mut bytes: &[u8]) -> Parse<Vec<Packet<'_>>> {
    let mut packets = Vec::new();
    while !bytes.is_empty() {
        if packets.len() == MAX_PACKETS {
            return Err(());
        }
        let mut reader = Reader(bytes);
        let header = reader.u8()?;
        if header & 0x80 == 0 {
            return Err(());
        }
        let (tag, length) = if header & 0x40 != 0 {
            let first = reader.u8()?;
            let length = match first {
                0..=191 => usize::from(first),
                192..=223 => (usize::from(first - 192) << 8) + usize::from(reader.u8()?) + 192,
                255 => usize::try_from(reader.u32()?).map_err(|_| ())?,
                // Partial body lengths never frame a key or a signature.
                _ => return Err(()),
            };
            (header & 0x3f, length)
        } else {
            let length = match header & 0x03 {
                0 => usize::from(reader.u8()?),
                1 => usize::from(reader.u16()?),
                2 => usize::try_from(reader.u32()?).map_err(|_| ())?,
                _ => return Err(()),
            };
            ((header >> 2) & 0x0f, length)
        };
        let body = reader.take(length)?;
        packets.push(Packet { tag, body });
        bytes = reader.0;
    }
    Ok(packets)
}

fn subpackets(mut bytes: &[u8]) -> Parse<Vec<Subpacket<'_>>> {
    let mut values = Vec::new();
    while !bytes.is_empty() {
        let mut reader = Reader(bytes);
        let first = reader.u8()?;
        let length = match first {
            0..=191 => usize::from(first),
            192..=254 => (usize::from(first - 192) << 8) + usize::from(reader.u8()?) + 192,
            255 => usize::try_from(reader.u32()?).map_err(|_| ())?,
        };
        let body = reader.take(length)?;
        let (kind, data) = body.split_first().ok_or(())?;
        values.push(Subpacket {
            critical: kind & 0x80 != 0,
            kind: kind & 0x7f,
            data,
        });
        bytes = reader.0;
    }
    Ok(values)
}

/// Decode one LF-framed ASCII armor block of `label` without headers,
/// checking its CRC-24 when present.
fn dearmor(bytes: &[u8], label: &str) -> Parse<Vec<u8>> {
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    if !text.is_ascii() || text.contains('\r') {
        return Err(());
    }
    let begin = format!("-----BEGIN PGP {label}-----");
    let end = format!("-----END PGP {label}-----");
    let mut lines = text.strip_suffix('\n').ok_or(())?.split('\n');
    if lines.next() != Some(begin.as_str()) {
        return Err(());
    }
    // GnuPG writes no armor headers; the blank separator line follows.
    if lines.next() != Some("") {
        return Err(());
    }
    let mut body = String::new();
    let mut checksum = None;
    let mut ended = false;
    for line in lines {
        if ended {
            return Err(());
        }
        if line == end {
            ended = true;
        } else if let Some(value) = line.strip_prefix('=') {
            if checksum.is_some() || value.len() != 4 {
                return Err(());
            }
            checksum = Some(value);
        } else if checksum.is_none()
            && line.len() <= 76
            && line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            body.push_str(line);
        } else {
            return Err(());
        }
    }
    if !ended {
        return Err(());
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(&body).map_err(|_| ())?;
    if decoded.is_empty() || decoded.len() > MAX_SIGNATURE_BYTES.max(MAX_KEY_BYTES) {
        return Err(());
    }
    if let Some(checksum) = checksum {
        let expected = engine.decode(checksum).map_err(|_| ())?;
        if expected.as_slice() != &crc24(&decoded).to_be_bytes()[1..] {
            return Err(());
        }
    }
    Ok(decoded)
}

fn crc24(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0x00b7_04ce;
    for byte in bytes {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Parse<&'a [u8]> {
        if length > self.0.len() {
            return Err(());
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }

    fn u8(&mut self) -> Parse<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Parse<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| ())?,
        ))
    }

    fn u32(&mut self) -> Parse<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| ())?,
        ))
    }

    /// One canonical MPI: its bit count is exact and it has no leading zero.
    fn mpi(&mut self) -> Parse<&'a [u8]> {
        let bits = usize::from(self.u16()?);
        let value = self.take(bits.div_ceil(8))?;
        if value.is_empty() || bit_length(value) != bits {
            return Err(());
        }
        Ok(value)
    }
}

fn bit_length(value: &[u8]) -> usize {
    match value.first() {
        Some(first) if *first != 0 => (value.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
        _ => 0,
    }
}

fn len16(length: usize) -> Parse<[u8; 2]> {
    u16::try_from(length).map(u16::to_be_bytes).map_err(|_| ())
}

fn len32(length: usize) -> Result<[u8; 4]> {
    u32::try_from(length)
        .map(u32::to_be_bytes)
        .map_err(|_| SignatureError::Malformed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests;
