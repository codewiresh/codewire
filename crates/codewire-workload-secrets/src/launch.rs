//! One-launch application values. This is a transport codec, not authority:
//! callers authenticate both peers and authorize the exact selected sources
//! before reading material, then recheck the operation before delivery/exec.
//!
//! A fresh recipient is consumed when opening a response, preventing reuse by
//! the same launcher. Sealed boxes hide material from relaying control
//! processes; they do not authenticate the sender. The authenticated runtime
//! channel must provide that property. Never put plaintext in durable state.

use std::{collections::BTreeMap, fmt};

use crypto_box::SecretKey;
use curve25519_dalek::MontgomeryPoint;
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{MAX_WORKLOAD_SECRETS, validate_workload_secret_key, validate_workload_secret_value};

/// Aggregate encoded application values, including names and framing. The
/// launcher must also check its complete argv/environment against exec limits.
pub const MAX_ENVIRONMENT_PROJECTION_BYTES: usize = 256 * 1024;
/// A response cannot extend the owning operation's deadline.
pub const MAX_PROJECTION_LIFETIME_MS: u64 = 30_000;

mod composition;
pub use composition::{
    MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES, ProjectionContributor, compose_environment_projection,
    seal_environment_projection, seal_environment_projection_fragment,
};

/// The existing environment operation and its exact resolved selection.
/// `selection_sha256` binds origin, server/organization, source IDs, and
/// selected profile revision as applicable; it is not a new secret generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionContext {
    pub environment_id: [u8; 16],
    pub operation_generation: u64,
    pub selection_sha256: [u8; 32],
    pub deadline_unix_ms: u64,
}

impl ProjectionContext {
    /// Validate before material access and again before releasing the result.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), ProjectionError> {
        let remaining = self.deadline_unix_ms.checked_sub(now_unix_ms);
        if self.environment_id == [0; 16]
            || self.operation_generation == 0
            || self.selection_sha256 == [0; 32]
            || !remaining
                .is_some_and(|remaining| (1..=MAX_PROJECTION_LIFETIME_MS).contains(&remaining))
        {
            return Err(ProjectionError::InvalidContext);
        }
        Ok(())
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.environment_id);
        bytes.extend_from_slice(&self.operation_generation.to_be_bytes());
        bytes.extend_from_slice(&self.selection_sha256);
        bytes.extend_from_slice(&self.deadline_unix_ms.to_be_bytes());
    }
}

/// Values intentionally visible to one receiving workload, never serialized
/// by generic metadata APIs and never included in Debug output.
pub struct EnvironmentProjection {
    entries: BTreeMap<String, Zeroizing<Vec<u8>>>,
    encoded_len: usize,
}

impl EnvironmentProjection {
    /// Takes ownership of already-authorized values. Duplicate names and
    /// oversized aggregate environments fail as a whole, never partially.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (String, Zeroizing<Vec<u8>>)>,
    ) -> Result<Self, ProjectionError> {
        let mut projection = Self {
            entries: BTreeMap::new(),
            encoded_len: 4,
        };
        for (key, value) in entries {
            validate_workload_secret_key(&key).map_err(|_| ProjectionError::InvalidValues)?;
            validate_workload_secret_value(&value).map_err(|_| ProjectionError::InvalidValues)?;
            projection.encoded_len = projection
                .encoded_len
                .checked_add(8 + key.len() + value.len())
                .ok_or(ProjectionError::InvalidValues)?;
            if projection.encoded_len > MAX_ENVIRONMENT_PROJECTION_BYTES
                || projection.entries.len() >= MAX_WORKLOAD_SECRETS
                || projection.entries.contains_key(&key)
            {
                return Err(ProjectionError::InvalidValues);
            }
            projection.entries.insert(key, value);
        }
        Ok(projection)
    }

    /// Borrow values only at the actual launcher boundary. No generic raw-read
    /// RPC should expose this operation to a sandbox or metadata client.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.entries.iter().map(|(key, value)| {
            (
                key.as_str(),
                std::str::from_utf8(value).expect("validated projection UTF-8"),
            )
        })
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (key, value) in &self.entries {
            bytes.extend_from_slice(&(key.len() as u32).to_be_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value);
        }
    }

    fn decode(mut bytes: &[u8]) -> Result<Self, ProjectionError> {
        if bytes.len() > MAX_ENVIRONMENT_PROJECTION_BYTES {
            return Err(ProjectionError::InvalidValues);
        }
        let count = read_u32(&mut bytes)? as usize;
        if count > MAX_WORKLOAD_SECRETS {
            return Err(ProjectionError::InvalidValues);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let key_len = read_u32(&mut bytes)? as usize;
            let key = std::str::from_utf8(take(&mut bytes, key_len)?)
                .map_err(|_| ProjectionError::InvalidValues)?
                .to_owned();
            if entries.last().is_some_and(|(previous, _)| previous >= &key) {
                return Err(ProjectionError::InvalidValues);
            }
            let value_len = read_u32(&mut bytes)? as usize;
            let value = Zeroizing::new(take(&mut bytes, value_len)?.to_vec());
            entries.push((key, value));
        }
        if !bytes.is_empty() {
            return Err(ProjectionError::InvalidValues);
        }
        Self::from_entries(entries)
    }
}

impl fmt::Debug for EnvironmentProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentProjection")
            .field("entry_count", &self.entries.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// A new ephemeral keypair retained by the actual launcher, not its supervisor
/// or workflow. Opening consumes it even on failure; retries require a fresh
/// authenticated request, recipient and authorization check.
pub struct ProjectionRecipient(SecretKey);

impl Default for ProjectionRecipient {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectionRecipient {
    pub fn new() -> Self {
        Self(SecretKey::generate(&mut OsRng))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.public_key().to_bytes()
    }

    pub fn open(
        self,
        ciphertext: &[u8],
        expected: &ProjectionContext,
        now_unix_ms: u64,
    ) -> Result<EnvironmentProjection, ProjectionError> {
        composition::open_bundle(self, ciphertext, expected, now_unix_ms)
    }

    /// Open one Codex login sealed for this recipient, consuming it even on
    /// failure. A projection never opens as a login, nor a login as a
    /// projection: each has its own outer and inner domain.
    pub fn open_codex_login(
        self,
        ciphertext: &[u8],
        expected: &crate::CodexLoginContext,
        now_unix_ms: u64,
    ) -> Result<crate::OpenedCodexLogin, crate::CodexLoginError> {
        crate::codex_login::open(&self.0, ciphertext, expected, now_unix_ms)
    }
}

impl fmt::Debug for ProjectionRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionRecipient")
            .finish_non_exhaustive()
    }
}

/// Reject noncontributory recipient keys before any protected source is read.
pub fn validate_projection_recipient(recipient: [u8; 32]) -> Result<(), ProjectionError> {
    // Reject noncontributory public keys, including noncanonical low-order
    // aliases. The fixed public scalar here is only a validation probe.
    if MontgomeryPoint(recipient)
        .mul_clamped([0x42; 32])
        .to_bytes()
        == [0; 32]
    {
        return Err(ProjectionError::InvalidEnvelope);
    }
    Ok(())
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], ProjectionError> {
    let (value, remaining) = bytes
        .split_at_checked(count)
        .ok_or(ProjectionError::InvalidValues)?;
    *bytes = remaining;
    Ok(value)
}

fn read_u32(bytes: &mut &[u8]) -> Result<u32, ProjectionError> {
    Ok(u32::from_be_bytes(
        take(bytes, 4)?
            .try_into()
            .map_err(|_| ProjectionError::InvalidValues)?,
    ))
}

/// Errors never include key names, material, plaintext or ciphertext.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProjectionError {
    #[error("environment projection context is invalid or expired")]
    InvalidContext,
    #[error("environment projection values are invalid or exceed limits")]
    InvalidValues,
    #[error("environment projection envelope is invalid")]
    InvalidEnvelope,
}

#[cfg(test)]
mod tests;
