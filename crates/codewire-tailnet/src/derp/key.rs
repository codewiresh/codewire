//! DERP node keys and the NaCl-box handshake crypto.
//!
//! DERP authenticates the handshake with a NaCl `crypto_box`
//! (Curve25519 ECDH + XSalsa20-Poly1305). On the Go side this is
//! `golang.org/x/crypto/nacl/box` via `tailscale.com/types/key`'s
//! `NodePrivate.SealTo` / `OpenFrom`. The on-wire ciphertext layout is
//! a 24-byte random nonce **prepended** to the box output:
//!
//! ```text
//! sealed = nonce[24] || box(plaintext, nonce, peer_pub, our_priv)
//! ```
//!
//! `crypto_box`'s [`SalsaBox`] is `CryptoBox<Salsa20>`, i.e. exactly the
//! same primitive, so the two interop byte-for-byte. We do the
//! nonce-prefix framing here to match Go.
//!
//! Note on clamping: Go's `key.NewNode()` clamps the 32-byte scalar.
//! `crypto_box::SecretKey` (backed by `x25519-dalek`) clamps internally
//! on every scalar-mult, so a freshly generated key and a key parsed
//! from raw bytes both behave identically to the Go side. We generate
//! via `SecretKey::generate` and never need to clamp by hand.

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore},
};
use rand_core::{CryptoRng, RngCore};

use super::Error;

/// Length of a raw Curve25519 public key on the wire.
pub const KEY_LEN: usize = 32;
/// Length of the NaCl box nonce prefix.
pub const NONCE_LEN: usize = 24;

/// A DERP node private key (Curve25519). Mirrors Go `key.NodePrivate`.
#[derive(Clone)]
pub struct NodePrivate {
    secret: SecretKey,
}

/// A DERP node public key (Curve25519). Mirrors Go `key.NodePublic`.
///
/// Equality / hashing are over the raw 32 bytes — DERP uses these keys as
/// routing addresses, so byte identity is what matters.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NodePublic {
    raw: [u8; KEY_LEN],
}

impl NodePrivate {
    /// Admit a control-channel peer before treating a box as possession proof.
    ///
    /// DERP's existing byte-address parsing remains unchanged. A separate
    /// application protocol must reject noncontributory Curve25519 inputs;
    /// otherwise an all-zero shared secret can impersonate a key holder.
    pub fn require_contributory(&self, peer: &NodePublic) -> Result<(), Error> {
        let secret = crate::wg::StaticSecret::from(self.secret.to_bytes());
        let public = crate::wg::PublicKey::from(*peer.as_bytes());
        if !secret.diffie_hellman(&public).was_contributory() {
            return Err(Error::Crypto("noncontributory control public key"));
        }
        Ok(())
    }

    /// Generate a fresh node private key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            secret: SecretKey::generate(rng),
        }
    }

    /// Parse a private key from its raw 32-byte scalar.
    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self {
            secret: SecretKey::from(raw),
        }
    }

    /// The corresponding public key.
    pub fn public(&self) -> NodePublic {
        NodePublic {
            raw: self.secret.public_key().to_bytes(),
        }
    }

    /// Seal `cleartext` to `peer`, authenticated from us, matching Go's
    /// `NodePrivate.SealTo`: returns `nonce[24] || box(...)`.
    pub fn seal_to<R: RngCore + CryptoRng>(
        &self,
        peer: &NodePublic,
        cleartext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let b = SalsaBox::new(&peer.to_crypto_box()?, &self.secret);
        let nonce = SalsaBox::generate_nonce(rng);
        let ct = b
            .encrypt(&nonce, cleartext)
            .map_err(|_| Error::Crypto("box seal failed"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a box produced by [`Self::seal_to`] from `peer`, matching Go's
    /// `NodePrivate.OpenFrom`. Input is `nonce[24] || box(...)`.
    pub fn open_from(&self, peer: &NodePublic, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < NONCE_LEN {
            return Err(Error::Crypto("sealed message shorter than nonce"));
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let b = SalsaBox::new(&peer.to_crypto_box()?, &self.secret);
        b.decrypt(nonce.into(), ct)
            .map_err(|_| Error::Crypto("box open failed"))
    }
}

impl NodePublic {
    /// Parse a public key from its raw 32 bytes.
    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self { raw }
    }

    /// Parse from a byte slice, erroring if the length is wrong.
    pub fn from_slice(b: &[u8]) -> Result<Self, Error> {
        let raw: [u8; KEY_LEN] = b
            .try_into()
            .map_err(|_| Error::Crypto("public key wrong length"))?;
        Ok(Self { raw })
    }

    /// The raw 32-byte encoding used on the DERP wire.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.raw
    }

    fn to_crypto_box(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from(self.raw))
    }
}

impl std::fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Short hex prefix, like Tailscale's key debug output.
        write!(f, "NodePublic(")?;
        for b in &self.raw[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

#[cfg(test)]
mod member_control_tests {
    use super::*;

    #[test]
    fn member_control_refuses_nonzero_low_order_keys_and_accepts_generated_keys() {
        let secret = NodePrivate::from_raw([0x42; KEY_LEN]);
        for first in [0, 1] {
            let mut bytes = [0; KEY_LEN];
            bytes[0] = first;
            assert!(
                secret
                    .require_contributory(&NodePublic::from_raw(bytes))
                    .is_err()
            );
        }
        let other = NodePrivate::from_raw([0x73; KEY_LEN]);
        secret.require_contributory(&other.public()).unwrap();
        let box_bytes = secret
            .seal_to(&other.public(), b"control", &mut rand::rngs::OsRng)
            .unwrap();
        assert_eq!(
            other.open_from(&secret.public(), &box_bytes).unwrap(),
            b"control"
        );
    }
}
