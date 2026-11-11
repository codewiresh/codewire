//! Reading a TLS ClientHello without answering it.
//!
//! Only the framing and the server_name extension are parsed: enough to decide
//! whether the connection is for the bound host. Rustls parses the whole
//! message again during the handshake.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::MAX_CLIENT_HELLO_BYTES;

const RECORD_HEADER_BYTES: usize = 5;
const HANDSHAKE_HEADER_BYTES: usize = 4;
const MAX_RECORD_BYTES: usize = 1 << 14;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: usize = 0;
const NAME_TYPE_HOST_NAME: usize = 0;

pub(crate) enum Hello {
    /// A complete ClientHello and its host_name, if it has one.
    ClientHello { server_name: Option<Vec<u8>> },
    /// Anything else, including a stream that ends before a whole ClientHello.
    NotClientHello,
}

pub(crate) enum HelloError {
    /// A ClientHello that would need more than [`MAX_CLIENT_HELLO_BYTES`].
    TooLarge,
    Io,
}

/// Reads handshake records into `read` until they hold a whole ClientHello.
/// Never reads past the record it needs, nor past [`MAX_CLIENT_HELLO_BYTES`];
/// `read` always holds exactly the bytes taken from `stream`.
pub(crate) async fn read_client_hello<S>(
    stream: &mut S,
    read: &mut BytesMut,
) -> Result<Hello, HelloError>
where
    S: AsyncRead + Unpin,
{
    let mut handshake = Vec::new();
    loop {
        let start = read.len();
        if start + RECORD_HEADER_BYTES > MAX_CLIENT_HELLO_BYTES {
            return Err(HelloError::TooLarge);
        }
        // One byte decides most non-TLS traffic, so little is taken from it.
        if !fill(stream, read, start + 1).await? || read[start] != CONTENT_TYPE_HANDSHAKE {
            return Ok(Hello::NotClientHello);
        }
        if !fill(stream, read, start + RECORD_HEADER_BYTES).await? {
            return Ok(Hello::NotClientHello);
        }
        let length = usize::from(u16::from_be_bytes([read[start + 3], read[start + 4]]));
        if read[start + 1] != 3 || length == 0 || length > MAX_RECORD_BYTES {
            return Ok(Hello::NotClientHello);
        }
        let end = start + RECORD_HEADER_BYTES + length;
        if end > MAX_CLIENT_HELLO_BYTES {
            return Err(HelloError::TooLarge);
        }
        if !fill(stream, read, end).await? {
            return Ok(Hello::NotClientHello);
        }
        handshake.extend_from_slice(&read[start + RECORD_HEADER_BYTES..end]);
        if handshake[0] != HANDSHAKE_CLIENT_HELLO {
            return Ok(Hello::NotClientHello);
        }
        if handshake.len() < HANDSHAKE_HEADER_BYTES {
            continue;
        }
        let body = usize::from(handshake[1]) << 16
            | usize::from(handshake[2]) << 8
            | usize::from(handshake[3]);
        if RECORD_HEADER_BYTES + HANDSHAKE_HEADER_BYTES + body > MAX_CLIENT_HELLO_BYTES {
            return Err(HelloError::TooLarge);
        }
        let Some(message) = handshake.get(HANDSHAKE_HEADER_BYTES..HANDSHAKE_HEADER_BYTES + body)
        else {
            continue;
        };
        return Ok(match server_name(message) {
            ServerName::HostName(name) => Hello::ClientHello {
                server_name: Some(name.to_vec()),
            },
            ServerName::Absent => Hello::ClientHello { server_name: None },
            ServerName::Malformed => Hello::NotClientHello,
        });
    }
}

/// Reads until `read` holds `want` bytes, never more; false at end of stream.
async fn fill<S>(stream: &mut S, read: &mut BytesMut, want: usize) -> Result<bool, HelloError>
where
    S: AsyncRead + Unpin,
{
    read.reserve(want.saturating_sub(read.len()));
    while read.len() < want {
        let missing = (want - read.len()) as u64;
        match (&mut *stream).take(missing).read_buf(read).await {
            Ok(0) => return Ok(false),
            Ok(_) => {}
            Err(_) => return Err(HelloError::Io),
        }
    }
    Ok(true)
}

enum ServerName<'a> {
    HostName(&'a [u8]),
    Absent,
    Malformed,
}

/// The host_name in a ClientHello body (RFC 8446 4.1.2, RFC 6066 3).
fn server_name(body: &[u8]) -> ServerName<'_> {
    parse_server_name(body).map_or(ServerName::Malformed, |name| {
        name.map_or(ServerName::Absent, ServerName::HostName)
    })
}

fn parse_server_name(body: &[u8]) -> Option<Option<&[u8]>> {
    let mut hello = Reader(body);
    hello.take(2 + 32)?; // legacy_version, random
    let session_id = hello.u8()?;
    if session_id > 32 {
        return None;
    }
    hello.take(session_id)?;
    let cipher_suites = hello.u16()?;
    hello.take(cipher_suites)?;
    let compression_methods = hello.u8()?;
    hello.take(compression_methods)?;
    if hello.0.is_empty() {
        return Some(None); // no extensions at all
    }
    let mut extensions = Reader(hello.vec16()?);
    if !hello.0.is_empty() {
        return None;
    }
    let mut found = None;
    let mut seen = false;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if kind != EXTENSION_SERVER_NAME {
            continue;
        }
        if seen {
            return None;
        }
        seen = true;
        let mut list = Reader(data);
        let mut names = Reader(list.vec16()?);
        if !list.0.is_empty() {
            return None;
        }
        while !names.0.is_empty() {
            let name_type = names.u8()?;
            let name = names.vec16()?;
            if name_type == NAME_TYPE_HOST_NAME {
                // At most one name of a type, and never an empty one.
                if found.is_some() || name.is_empty() {
                    return None;
                }
                found = Some(name);
            }
        }
    }
    Some(found)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|bytes| usize::from(bytes[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(length)
    }
}
