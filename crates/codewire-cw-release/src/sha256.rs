//! SHA-256 for files and streams.
//!
//! The workspace's `sha2` 0.10 runs in software on Apple silicon (about
//! 220 MB/s on an M1), so hashing a 40 MB cw took about 0.18 s (#2549).
//! `ring` uses the CPU's SHA instructions on aarch64 and x86_64. Large inputs
//! (executables, runtime blobs, image layers, disk packs) are hashed here;
//! small digests may stay on `sha2`. Both compute the same SHA-256.

use std::fmt;
use std::io::{self, Read, Write};

/// An incremental SHA-256 with the shape of `sha2::Sha256`'s common methods.
#[derive(Clone)]
pub struct Sha256(ring::digest::Context);

impl Sha256 {
    pub fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    pub fn finalize(self) -> Sha256Hash {
        let digest = self.0.finish();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        Sha256Hash(bytes)
    }

    /// The hash of `data` in one call.
    pub fn digest(data: impl AsRef<[u8]>) -> Sha256Hash {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256")
    }
}

/// Hashing what is written, so `io::copy` can feed it.
impl Write for Sha256 {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The hash of everything `reader` yields.
pub fn sha256_reader(mut reader: impl Read) -> io::Result<Sha256Hash> {
    let mut hasher = Sha256::new();
    io::copy(&mut reader, &mut hasher)?;
    Ok(hasher.finalize())
}

/// A SHA-256 hash. `{:x}` writes its 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Sha256Hash> for [u8; 32] {
    fn from(hash: Sha256Hash) -> Self {
        hash.0
    }
}

impl fmt::LowerHex for Sha256Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Hash({self:x})")
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;

    #[test]
    fn matches_sha2_for_empty_small_and_multi_block_inputs() {
        let large: Vec<u8> = (0..3_000_000_u32).map(|value| value as u8).collect();
        for input in [&b""[..], b"abc", &large[..]] {
            let expected = format!("{:x}", sha2::Sha256::digest(input));
            assert_eq!(format!("{:x}", Sha256::digest(input)), expected);
            let mut split = Sha256::new();
            for chunk in input.chunks(65_537) {
                split.update(chunk);
            }
            assert_eq!(format!("{:x}", split.finalize()), expected);
            assert_eq!(format!("{:x}", sha256_reader(input).unwrap()), expected);
        }
        assert_eq!(
            format!("{:x}", Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let bytes: [u8; 32] = Sha256::digest(b"abc").into();
        assert_eq!(bytes[..], sha2::Sha256::digest(b"abc")[..]);
    }
}
