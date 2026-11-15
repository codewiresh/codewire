//! The first bytes of a guest's egress stream, and cw-egress's answer.
//!
//! Guest to cw-egress: `MAGIC`, the token's length (u16, little endian), the
//! token, then a 32-byte guest nonce. cw-egress answers an admitted stream with
//! `MAGIC` and its own 32-byte nonce, then the network session begins. A
//! refused stream is closed with no answer.

use thiserror::Error;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 8] = *b"CWEGRS01";
pub const NONCE_LEN: usize = 32;
/// A projected service-account token is a JWT of a few hundred bytes to a
/// few KiB; anything longer is refused before it is read.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
pub const HEADER_LEN: usize = MAGIC.len() + 2;
pub const ANSWER_LEN: usize = MAGIC.len() + NONCE_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HelloError {
    #[error("the stream does not start with the egress magic")]
    Magic,
    #[error("the token length {0} is empty or over the limit")]
    TokenLength(usize),
    #[error("the token is not UTF-8")]
    TokenEncoding,
    #[error("the hello is {actual} bytes, not {expected}")]
    Length { actual: usize, expected: usize },
}

/// What the guest sent. The token is wiped when the hello is dropped.
pub struct GuestHello {
    pub token: Zeroizing<String>,
    pub nonce: [u8; NONCE_LEN],
}

impl GuestHello {
    pub fn encode(&self) -> Result<Vec<u8>, HelloError> {
        let length = checked_token_len(self.token.len())?;
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.token.len() + NONCE_LEN);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(self.token.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        Ok(bytes)
    }
}

/// Reads the header and returns how many bytes follow it: the token and the
/// nonce. A reader reads exactly that many and passes them to [`decode_body`].
pub fn body_len(header: &[u8; HEADER_LEN]) -> Result<usize, HelloError> {
    if header[..MAGIC.len()] != MAGIC {
        return Err(HelloError::Magic);
    }
    let length = u16::from_le_bytes([header[MAGIC.len()], header[MAGIC.len() + 1]]);
    let length = usize::from(length);
    checked_token_len(length)?;
    Ok(length + NONCE_LEN)
}

pub fn decode_body(body: &[u8]) -> Result<GuestHello, HelloError> {
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
        token: Zeroizing::new(token.to_owned()),
        nonce,
    })
}

pub fn encode_answer(nonce: &[u8; NONCE_LEN]) -> [u8; ANSWER_LEN] {
    let mut answer = [0_u8; ANSWER_LEN];
    answer[..MAGIC.len()].copy_from_slice(&MAGIC);
    answer[MAGIC.len()..].copy_from_slice(nonce);
    answer
}

pub fn decode_answer(answer: &[u8; ANSWER_LEN]) -> Result<[u8; NONCE_LEN], HelloError> {
    if answer[..MAGIC.len()] != MAGIC {
        return Err(HelloError::Magic);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&answer[MAGIC.len()..]);
    Ok(nonce)
}

fn checked_token_len(length: usize) -> Result<u16, HelloError> {
    if length == 0 || length > MAX_TOKEN_LEN {
        return Err(HelloError::TokenLength(length));
    }
    u16::try_from(length).map_err(|_| HelloError::TokenLength(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(token: &str) -> GuestHello {
        GuestHello {
            token: Zeroizing::new(token.to_owned()),
            nonce: [7; NONCE_LEN],
        }
    }

    #[test]
    fn a_hello_round_trips() {
        let bytes = hello("header.payload.signature").encode().unwrap();
        let header: [u8; HEADER_LEN] = bytes[..HEADER_LEN].try_into().unwrap();
        let body = &bytes[HEADER_LEN..];
        assert_eq!(body_len(&header).unwrap(), body.len());
        let decoded = decode_body(body).unwrap();
        assert_eq!(decoded.token.as_str(), "header.payload.signature");
        assert_eq!(decoded.nonce, [7; NONCE_LEN]);
    }

    #[test]
    fn a_stream_that_is_not_an_egress_hello_is_refused_before_the_token_is_read() {
        let mut header = [0_u8; HEADER_LEN];
        header[..4].copy_from_slice(b"GET ");
        assert_eq!(body_len(&header), Err(HelloError::Magic));
    }

    #[test]
    fn an_empty_or_oversized_token_is_refused_from_the_header() {
        let mut header = [0_u8; HEADER_LEN];
        header[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert_eq!(body_len(&header), Err(HelloError::TokenLength(0)));
        let over = u16::try_from(MAX_TOKEN_LEN + 1).unwrap();
        header[MAGIC.len()..].copy_from_slice(&over.to_le_bytes());
        assert_eq!(
            body_len(&header),
            Err(HelloError::TokenLength(MAX_TOKEN_LEN + 1))
        );
        assert!(hello("").encode().is_err());
    }

    #[test]
    fn the_answer_round_trips_and_a_wrong_magic_is_refused() {
        let answer = encode_answer(&[9; NONCE_LEN]);
        assert_eq!(decode_answer(&answer).unwrap(), [9; NONCE_LEN]);
        let mut wrong = answer;
        wrong[0] ^= 1;
        assert_eq!(decode_answer(&wrong), Err(HelloError::Magic));
    }
}
