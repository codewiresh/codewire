//! Closed OpenSSH agent payload codec. Payloads exclude the outer four-byte
//! length prefix; the stream owner must enforce
//! [`MAX_PAYLOAD_BYTES`](crate::ssh::agent::MAX_PAYLOAD_BYTES) before
//! allocating or reading one. This module owns no stream, key, request ID,
//! deadline, grant or pending operation.
//!
//! Public keys and signatures are opaque bounded blobs here. The selected-agent
//! authority still enforces the exact key and supported signature algorithm.

use super::{
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES, MAX_SIGNING_DATA_BYTES, SshOperation, invalid, v1,
    validate_operation, validate_result,
};
use tonic::Status;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const IDENTITY_COMMENT: &[u8] = b"codewire-selected-key";

/// The existing selected-agent payload ceiling, excluding the length prefix.
pub const MAX_PAYLOAD_BYTES: usize = MAX_PUBLIC_KEY_BYTES + MAX_SIGNING_DATA_BYTES + 32;

/// Decode only identities or sign. Unsupported commands, malformed lengths,
/// trailing bytes and oversized payloads are rejected without retained input.
pub fn decode_request(payload: &[u8]) -> Result<v1::credential_ssh_request::Operation, Status> {
    use v1::credential_ssh_request::Operation;
    let mut input = Input::new(payload)?;
    let operation = match input.byte()? {
        REQUEST_IDENTITIES => {
            input.finish()?;
            Operation::Identities(v1::CredentialSshIdentitiesRequest {})
        }
        SIGN_REQUEST => {
            let public_key_blob = input.string(MAX_PUBLIC_KEY_BYTES)?;
            let data = input.string(MAX_SIGNING_DATA_BYTES)?;
            let flags = input.u32()?;
            input.finish()?;
            Operation::Sign(v1::CredentialSshSignRequest {
                public_key_blob: public_key_blob.to_vec(),
                data: data.to_vec(),
                flags,
            })
        }
        _ => return Err(invalid()),
    };
    validate_operation(&operation)?;
    Ok(operation)
}

/// Encode a bounded operation without minting a request ID or deadline.
pub fn encode_request(
    operation: &v1::credential_ssh_request::Operation,
) -> Result<Vec<u8>, Status> {
    use v1::credential_ssh_request::Operation;
    validate_operation(operation)?;
    match operation {
        Operation::Identities(_) => Ok(vec![REQUEST_IDENTITIES]),
        Operation::Sign(sign) => {
            let mut output = Vec::with_capacity(13 + sign.public_key_blob.len() + sign.data.len());
            output.push(SIGN_REQUEST);
            put_string(&mut output, &sign.public_key_blob)?;
            put_string(&mut output, &sign.data)?;
            output.extend_from_slice(&sign.flags.to_be_bytes());
            Ok(output)
        }
    }
}

/// Decode one matching terminal. Identities must contain exactly one key;
/// its bounded arbitrary comment is discarded. Wire failure has no reason
/// detail and maps to the closed Denied variant for either operation.
pub fn decode_response(
    payload: &[u8],
    operation: SshOperation,
) -> Result<v1::credential_ssh_response::Result, Status> {
    use v1::credential_ssh_response::Result as SshResult;
    let mut input = Input::new(payload)?;
    let result = match input.byte()? {
        FAILURE => {
            input.finish()?;
            SshResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32)
        }
        IDENTITIES_ANSWER if operation == SshOperation::Identities => {
            if input.u32()? != 1 {
                return Err(invalid());
            }
            let public_key_blob = input.string(MAX_PUBLIC_KEY_BYTES)?;
            let _discarded_comment = input.string(MAX_PUBLIC_KEY_BYTES)?;
            input.finish()?;
            SshResult::Identity(v1::CredentialSshIdentity {
                public_key_blob: public_key_blob.to_vec(),
            })
        }
        SIGN_RESPONSE if operation == SshOperation::Sign => {
            let signature_blob = input.string(MAX_SIGNATURE_BYTES)?;
            input.finish()?;
            SshResult::Signature(v1::CredentialSshSignature {
                signature_blob: signature_blob.to_vec(),
            })
        }
        _ => return Err(invalid()),
    };
    validate_result(&result, operation)?;
    Ok(result)
}

/// Encode exactly one identity, one signature, or the fixed wire failure.
/// Imported comments and internal failure details never cross this boundary.
pub fn encode_response(
    result: &v1::credential_ssh_response::Result,
    operation: SshOperation,
) -> Result<Vec<u8>, Status> {
    use v1::credential_ssh_response::Result as SshResult;
    validate_result(result, operation)?;
    match result {
        SshResult::Identity(identity) => {
            let mut output =
                Vec::with_capacity(13 + identity.public_key_blob.len() + IDENTITY_COMMENT.len());
            output.push(IDENTITIES_ANSWER);
            output.extend_from_slice(&1_u32.to_be_bytes());
            put_string(&mut output, &identity.public_key_blob)?;
            put_string(&mut output, IDENTITY_COMMENT)?;
            Ok(output)
        }
        SshResult::Signature(signature) => {
            let mut output = Vec::with_capacity(5 + signature.signature_blob.len());
            output.push(SIGN_RESPONSE);
            put_string(&mut output, &signature.signature_blob)?;
            Ok(output)
        }
        SshResult::Failure(_) => Ok(vec![FAILURE]),
    }
}

fn put_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Status> {
    let count = u32::try_from(value.len()).map_err(|_| invalid())?;
    output.extend_from_slice(&count.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Input<'a> {
    remaining: &'a [u8],
}

impl<'a> Input<'a> {
    fn new(payload: &'a [u8]) -> Result<Self, Status> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid());
        }
        Ok(Self { remaining: payload })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Status> {
        let result = self.remaining.get(..count).ok_or_else(invalid)?;
        self.remaining = &self.remaining[count..];
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, Status> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Status> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid())?,
        ))
    }

    fn string(&mut self, limit: usize) -> Result<&'a [u8], Status> {
        let count = usize::try_from(self.u32()?).map_err(|_| invalid())?;
        if count > limit {
            return Err(invalid());
        }
        self.take(count)
    }

    fn finish(self) -> Result<(), Status> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[cfg(test)]
mod tests;
