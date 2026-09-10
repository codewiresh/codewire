//! The finite, material-free subset of the OpenSSH agent protocol.

use super::SshAgentError;

pub(super) const FAILURE: u8 = 5;
pub(super) const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
pub(super) const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
pub(super) const MAX_KEY_BYTES: usize = 16 * 1024;
pub(super) const MAX_DATA_BYTES: usize = 64 * 1024;
pub(super) const MAX_FRAME_BYTES: usize = MAX_KEY_BYTES + MAX_DATA_BYTES + 32;

/// Supported plain public keys; certificates and hardware-backed keys are not
/// silently converted into another kind of identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshKeyAlgorithm {
    /// A plain Ed25519 key.
    Ed25519,
    /// A plain RSA key, with a 2048 through 8192-bit modulus.
    Rsa { bits: u32 },
}

/// Public metadata only. The imported key's arbitrary comment is discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshPublicIdentity {
    algorithm: SshKeyAlgorithm,
    blob: Vec<u8>,
}

impl SshPublicIdentity {
    /// The supported key algorithm.
    pub fn algorithm(&self) -> SshKeyAlgorithm {
        self.algorithm
    }

    /// RFC SSH public-key encoding, not a private key or file reference.
    pub fn key_blob(&self) -> &[u8] {
        &self.blob
    }

    pub(super) fn from_agent_response(response: &[u8]) -> Result<Self, SshAgentError> {
        let mut input = Input::new(response);
        if input.byte()? != IDENTITIES_ANSWER || input.u32()? != 1 {
            return Err(SshAgentError::InvalidKey);
        }
        let blob = input.string(MAX_KEY_BYTES)?;
        let _discarded_comment = input.string(MAX_KEY_BYTES)?;
        input.finish()?;
        let mut key = Input::new(blob);
        let algorithm = match key.string(32)? {
            b"ssh-ed25519" => {
                if key.string(32)?.len() != 32 {
                    return Err(SshAgentError::InvalidKey);
                }
                SshKeyAlgorithm::Ed25519
            }
            b"ssh-rsa" => {
                let exponent = positive_mpint(key.string(9)?)?;
                if exponent.is_empty()
                    || exponent.len() > 8
                    || exponent.last().unwrap() & 1 == 0
                    || (exponent.len() == 1 && exponent[0] < 3)
                {
                    return Err(SshAgentError::InvalidKey);
                }
                let modulus = positive_mpint(key.string(1025)?)?;
                let Some(first) = modulus.first() else {
                    return Err(SshAgentError::InvalidKey);
                };
                let bits = (modulus.len() as u32) * 8 - first.leading_zeros();
                if !(2048..=8192).contains(&bits) {
                    return Err(SshAgentError::InvalidKey);
                }
                SshKeyAlgorithm::Rsa { bits }
            }
            _ => return Err(SshAgentError::InvalidKey),
        };
        key.finish()?;
        Ok(Self {
            algorithm,
            blob: blob.to_vec(),
        })
    }

    pub(super) fn identities_response(&self) -> Vec<u8> {
        let mut response = vec![IDENTITIES_ANSWER];
        response.extend_from_slice(&1_u32.to_be_bytes());
        put_string(&mut response, &self.blob);
        put_string(&mut response, b"codewire-selected-key");
        response
    }

    pub(super) fn admit_request(
        &self,
        request: &[u8],
    ) -> Result<Option<&'static [u8]>, SshAgentError> {
        if request.is_empty() || request.len() > MAX_FRAME_BYTES {
            return Err(SshAgentError::Denied);
        }
        let mut input = Input::new(request);
        match input.byte()? {
            REQUEST_IDENTITIES => {
                input.finish()?;
                Ok(None)
            }
            SIGN_REQUEST => {
                if input.string(MAX_KEY_BYTES)? != self.blob {
                    return Err(SshAgentError::Denied);
                }
                let data = input.string(MAX_DATA_BYTES)?;
                if data.is_empty() {
                    return Err(SshAgentError::Denied);
                }
                let flags = input.u32()?;
                input.finish()?;
                match (self.algorithm, flags) {
                    (SshKeyAlgorithm::Ed25519, 0) => Ok(Some(b"ssh-ed25519")),
                    (SshKeyAlgorithm::Rsa { .. }, 2) => Ok(Some(b"rsa-sha2-256")),
                    (SshKeyAlgorithm::Rsa { .. }, 4) => Ok(Some(b"rsa-sha2-512")),
                    // In particular, RSA flags=0 requests SHA1 and is denied.
                    _ => Err(SshAgentError::Denied),
                }
            }
            // Includes add/remove, lock/unlock, PKCS11, extensions and queries.
            _ => Err(SshAgentError::Denied),
        }
    }

    pub(super) fn validate_signature(
        &self,
        response: &[u8],
        expected: &[u8],
    ) -> Result<(), SshAgentError> {
        let mut input = Input::new(response);
        if input.byte()? != SIGN_RESPONSE {
            return Err(SshAgentError::Failed);
        }
        let mut signature = Input::new(input.string(MAX_KEY_BYTES)?);
        input.finish()?;
        if signature.string(32)? != expected {
            return Err(SshAgentError::Failed);
        }
        let bytes = signature.string(1024)?;
        let valid = match self.algorithm {
            SshKeyAlgorithm::Ed25519 => bytes.len() == 64,
            SshKeyAlgorithm::Rsa { bits } => {
                !bytes.is_empty() && bytes.len() <= bits.div_ceil(8) as usize
            }
        };
        signature.finish()?;
        if !valid {
            return Err(SshAgentError::Failed);
        }
        Ok(())
    }
}

fn positive_mpint(bytes: &[u8]) -> Result<&[u8], SshAgentError> {
    match bytes {
        [] => Err(SshAgentError::InvalidKey),
        [0, rest @ ..] if rest.first().is_some_and(|byte| byte & 0x80 != 0) => Ok(rest),
        [first, ..] if *first != 0 && first & 0x80 == 0 => Ok(bytes),
        _ => Err(SshAgentError::InvalidKey),
    }
}

pub(super) fn put_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

struct Input<'a> {
    remaining: &'a [u8],
}

impl<'a> Input<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], SshAgentError> {
        let result = self.remaining.get(..count).ok_or(SshAgentError::Denied)?;
        self.remaining = &self.remaining[count..];
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, SshAgentError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, SshAgentError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SshAgentError::Denied)?,
        ))
    }
    fn string(&mut self, limit: usize) -> Result<&'a [u8], SshAgentError> {
        let count = self.u32()? as usize;
        if count > limit {
            return Err(SshAgentError::Denied);
        }
        self.take(count)
    }
    fn finish(self) -> Result<(), SshAgentError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(SshAgentError::Denied)
        }
    }
}
