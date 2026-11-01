//! Framing for the `session@codewire.sh` SSH subsystem (#3827).
//!
//! A durable session attachment over an environment's tailnet SSH connection
//! carries the public `AttachSessionRequest` and `AttachSessionResponse`
//! messages, the same ones `EnvironmentSessionService.AttachSession` carries
//! through the API, so a client keeps one decoder for both transports. Each
//! message is a 4-byte big-endian length followed by its encoding.
//!
//! The client's first request opens the attachment (`open`); then it sends
//! stdin, resize and detach. Closing the channel detaches, and the session
//! keeps running. The server reports a refusal or failure on the channel's
//! stderr and ends it with exit status 1.

use buffa::Message;

/// The SSH subsystem name a client requests on a session channel.
pub const SESSION_SUBSYSTEM: &str = "session@codewire.sh";

/// The largest encoded message either side sends or accepts.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

const LENGTH_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("session frame of {0} bytes exceeds the {MAX_FRAME_BYTES}-byte limit")]
    TooLarge(usize),
    #[error("session frame is not a valid message")]
    Decode,
}

/// Encode one message as a frame.
pub fn encode_frame<M: Message>(message: &M) -> Result<Vec<u8>, FrameError> {
    let body = message.encode_to_vec();
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(body.len()));
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    let mut frame = Vec::with_capacity(LENGTH_BYTES + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Collects channel bytes and yields whole messages, in order.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The next whole message, or `None` until more bytes arrive. A length
    /// over the limit is refused before its body is buffered.
    pub fn next_message<M: Message>(&mut self) -> Result<Option<M>, FrameError> {
        let Some(header) = self.buffer.first_chunk::<LENGTH_BYTES>() else {
            return Ok(None);
        };
        let length = u32::from_be_bytes(*header) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge(length));
        }
        if self.buffer.len() < LENGTH_BYTES + length {
            return Ok(None);
        }
        let message = M::decode_from_slice(&self.buffer[LENGTH_BYTES..LENGTH_BYTES + length])
            .map_err(|_| FrameError::Decode)?;
        self.buffer.drain(..LENGTH_BYTES + length);
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttachSessionOpen, AttachSessionRequest, attach_session_request};

    fn stdin(data: &[u8]) -> AttachSessionRequest {
        AttachSessionRequest {
            input: Some(attach_session_request::Input::Stdin(data.to_vec())),
            ..Default::default()
        }
    }

    #[test]
    fn frames_round_trip_across_arbitrary_splits() {
        let open = AttachSessionRequest {
            input: Some(attach_session_request::Input::Open(Box::new(
                AttachSessionOpen {
                    org_id: "org".into(),
                    environment_id: "env".into(),
                    session_id: "session".into(),
                    output_offset: 42,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        let mut wire = encode_frame(&open).unwrap();
        wire.extend(encode_frame(&stdin(b"ls\r")).unwrap());

        // Byte by byte: nothing is yielded before a frame is whole.
        let mut decoder = FrameDecoder::default();
        let mut decoded = Vec::new();
        for byte in wire {
            decoder.push(&[byte]);
            while let Some(message) = decoder.next_message::<AttachSessionRequest>().unwrap() {
                decoded.push(message);
            }
        }
        assert_eq!(decoded, vec![open, stdin(b"ls\r")]);
    }

    #[test]
    fn an_oversized_length_is_refused_before_its_body_arrives() {
        let mut decoder = FrameDecoder::default();
        decoder.push(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert_eq!(
            decoder.next_message::<AttachSessionRequest>(),
            Err(FrameError::TooLarge(MAX_FRAME_BYTES + 1))
        );
        assert!(matches!(
            encode_frame(&stdin(&vec![0; MAX_FRAME_BYTES])),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn a_body_that_is_not_a_message_is_refused() {
        let mut decoder = FrameDecoder::default();
        decoder.push(&2_u32.to_be_bytes());
        decoder.push(&[0xff, 0xff]);
        assert_eq!(
            decoder.next_message::<AttachSessionRequest>(),
            Err(FrameError::Decode)
        );
    }
}
