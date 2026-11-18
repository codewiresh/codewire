//! The first bytes of a guest's egress stream, and cw-egress's answer.
//!
//! Guest to cw-egress: `MAGIC`, the session protocol version the guest speaks
//! (u16, little endian), the token's length (u16, little endian), the token,
//! then a 32-byte guest nonce. cw-egress reads the magic and the version
//! before anything else. A version it does not accept gets [`VERSION_ANSWER`]
//! and a close; an admitted stream gets `MAGIC` and cw-egress's own 32-byte
//! nonce, then the network session begins. Every other refusal is a close
//! with no answer.
//!
//! The version answer is sent before the token is read, so it is one
//! constant: it depends on nothing the guest sent, not even which version was
//! refused (hosted-egress.md, "Version skew with the daemon").

use std::ops::RangeInclusive;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::protocol::NETWORK_PROTOCOL_VERSION;

pub const MAGIC: [u8; 8] = *b"CWEGRS01";
pub const VERSION_REFUSED_MAGIC: [u8; 8] = *b"CWEGRSV\0";
pub const NONCE_LEN: usize = 32;
/// A projected service-account token is a JWT of a few hundred bytes to a
/// few KiB; anything longer is refused before it is read.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// The session versions cw-egress accepts: the current one and the previous
/// shipped one, because cw-egress and the daemon roll out separately. When the
/// session version rises, the start stays at the previous version for one
/// release and cw-egress keeps speaking it.
pub const ACCEPTED_VERSIONS: RangeInclusive<u16> =
    NETWORK_PROTOCOL_VERSION..=NETWORK_PROTOCOL_VERSION;
/// The magic and the version: everything cw-egress reads before it decides
/// whether to answer a version refusal.
pub const PREFIX_LEN: usize = MAGIC.len() + 2;
pub const TOKEN_LEN_LEN: usize = 2;
pub const ANSWER_MAGIC_LEN: usize = MAGIC.len();
pub const ADMITTED_ANSWER_LEN: usize = MAGIC.len() + NONCE_LEN;
pub const VERSION_ANSWER_LEN: usize = VERSION_REFUSED_MAGIC.len() + 4;
pub const VERSION_ANSWER: [u8; VERSION_ANSWER_LEN] = version_answer();

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HelloError {
    #[error("the stream does not start with the egress magic")]
    Magic,
    #[error("the guest speaks session version {0}, which is not accepted")]
    Version(u16),
    #[error("the token length {0} is empty or over the limit")]
    TokenLength(usize),
    #[error("the token is not UTF-8")]
    TokenEncoding,
    #[error("the hello is {actual} bytes, not {expected}")]
    Length { actual: usize, expected: usize },
}

/// What the guest sent. The token is wiped when the hello is dropped.
pub struct GuestHello {
    pub version: u16,
    pub token: Zeroizing<String>,
    pub nonce: [u8; NONCE_LEN],
}

impl GuestHello {
    pub fn encode(&self) -> Result<Vec<u8>, HelloError> {
        let length = checked_token_len(self.token.len())?;
        let mut bytes =
            Vec::with_capacity(PREFIX_LEN + TOKEN_LEN_LEN + self.token.len() + NONCE_LEN);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(self.token.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        Ok(bytes)
    }
}

/// Reads the magic and the version. [`HelloError::Version`] is the one error
/// cw-egress answers, with [`VERSION_ANSWER`].
pub fn decode_prefix(prefix: &[u8; PREFIX_LEN]) -> Result<u16, HelloError> {
    if prefix[..MAGIC.len()] != MAGIC {
        return Err(HelloError::Magic);
    }
    let version = u16::from_le_bytes([prefix[MAGIC.len()], prefix[MAGIC.len() + 1]]);
    if !ACCEPTED_VERSIONS.contains(&version) {
        return Err(HelloError::Version(version));
    }
    Ok(version)
}

/// Reads the token's length and returns how many bytes follow it: the token
/// and the nonce. A reader reads exactly that many and passes them to
/// [`decode_body`].
pub fn body_len(token_len: &[u8; TOKEN_LEN_LEN]) -> Result<usize, HelloError> {
    let length = usize::from(u16::from_le_bytes(*token_len));
    checked_token_len(length)?;
    Ok(length + NONCE_LEN)
}

pub fn decode_body(version: u16, body: &[u8]) -> Result<GuestHello, HelloError> {
    let Some(token_len) = body.len().checked_sub(NONCE_LEN) else {
        return Err(HelloError::Length {
            actual: body.len(),
            expected: NONCE_LEN,
        });
    };
    checked_token_len(token_len)?;
    let (token, nonce) = body.split_at(token_len);
    let token = std::str::from_utf8(token).map_err(|_| HelloError::TokenEncoding)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| HelloError::Length {
        actual: nonce.len(),
        expected: NONCE_LEN,
    })?;
    Ok(GuestHello {
        version,
        token: Zeroizing::new(token.to_owned()),
        nonce,
    })
}

pub fn encode_answer(nonce: &[u8; NONCE_LEN]) -> [u8; ADMITTED_ANSWER_LEN] {
    let mut answer = [0_u8; ADMITTED_ANSWER_LEN];
    answer[..MAGIC.len()].copy_from_slice(&MAGIC);
    answer[MAGIC.len()..].copy_from_slice(nonce);
    answer
}

const fn version_answer() -> [u8; VERSION_ANSWER_LEN] {
    let lowest = ACCEPTED_VERSIONS.start().to_le_bytes();
    let highest = ACCEPTED_VERSIONS.end().to_le_bytes();
    let mut answer = [0_u8; VERSION_ANSWER_LEN];
    let mut index = 0;
    while index < VERSION_REFUSED_MAGIC.len() {
        answer[index] = VERSION_REFUSED_MAGIC[index];
        index += 1;
    }
    answer[8] = lowest[0];
    answer[9] = lowest[1];
    answer[10] = highest[0];
    answer[11] = highest[1];
    answer
}

/// cw-egress's answer, as the guest reads it.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Admitted { nonce: [u8; NONCE_LEN] },
    VersionRefused { lowest: u16, highest: u16 },
}

/// Reads an answer's magic and returns how many bytes follow it. The two
/// answers differ in length, so a guest reads the magic first, then exactly
/// this many, and passes both to [`decode_answer`].
pub fn answer_tail_len(magic: &[u8; ANSWER_MAGIC_LEN]) -> Result<usize, HelloError> {
    if *magic == MAGIC {
        Ok(NONCE_LEN)
    } else if *magic == VERSION_REFUSED_MAGIC {
        Ok(VERSION_ANSWER_LEN - VERSION_REFUSED_MAGIC.len())
    } else {
        Err(HelloError::Magic)
    }
}

pub fn decode_answer(magic: &[u8; ANSWER_MAGIC_LEN], tail: &[u8]) -> Result<Answer, HelloError> {
    let expected = answer_tail_len(magic)?;
    if tail.len() != expected {
        return Err(HelloError::Length {
            actual: tail.len(),
            expected,
        });
    }
    if *magic == VERSION_REFUSED_MAGIC {
        return Ok(Answer::VersionRefused {
            lowest: u16::from_le_bytes([tail[0], tail[1]]),
            highest: u16::from_le_bytes([tail[2], tail[3]]),
        });
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(tail);
    Ok(Answer::Admitted { nonce })
}

fn checked_token_len(length: usize) -> Result<u16, HelloError> {
    if length == 0 || length > MAX_TOKEN_LEN {
        return Err(HelloError::TokenLength(length));
    }
    u16::try_from(length).map_err(|_| HelloError::TokenLength(length))
}

#[cfg(test)]
mod tests;
