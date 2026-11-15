//! The guest's half of a network session: authenticate the host's handshake
//! on an accepted or dialled stream, then carry packets between the guest's
//! TUN device and that stream. A local VM runs it over vsock; a hosted
//! sandbox runs it over its stream to cw-egress.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{
    NETWORK_FRAME_HEADER_LEN, NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN,
    NETWORK_MAX_PACKET_BYTES, NetworkError, NetworkGuestAck, NetworkHostHello, NetworkHostReady,
    NetworkKey, NetworkRole, NetworkSession, encoded_network_frame_len,
};

/// Where the guest's side of the handshake failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GuestHandshakeError {
    #[error("read the host hello")]
    ReadHello,
    #[error("authenticate the host hello")]
    AuthenticateHello,
    #[error("write the guest acknowledgement")]
    WriteAcknowledgement,
    #[error("read the host ready")]
    ReadReady,
    #[error("authenticate the host ready")]
    AuthenticateReady,
    #[error("start the session")]
    Session,
}

/// Why a bridged session ended.
#[derive(Debug, Error)]
pub enum GuestBridgeError {
    #[error("read the guest TUN device")]
    ReadTun(#[source] io::Error),
    #[error("write the guest TUN device")]
    WriteTun(#[source] io::Error),
    #[error("read a session frame")]
    ReadFrame(#[source] io::Error),
    #[error("write a session frame")]
    WriteFrame(#[source] io::Error),
    #[error("a session frame failed authentication or framing")]
    Frame(#[source] NetworkError),
    #[error("the host supplied a non-canonical IPv4 packet")]
    NonCanonicalPacket,
}

/// Run the guest's side of the handshake on `stream`: read and authenticate
/// the host hello for `vm_id` and `generation`, acknowledge it, and
/// authenticate the host ready.
pub async fn authenticate_guest<S>(
    mut stream: S,
    key: &NetworkKey,
    vm_id: uuid::Uuid,
    generation: u64,
) -> Result<(S, NetworkSession), GuestHandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    stream
        .read_exact(&mut hello)
        .await
        .map_err(|_| GuestHandshakeError::ReadHello)?;
    let hello = NetworkHostHello::decode(&hello, key, vm_id, generation)
        .map_err(|_| GuestHandshakeError::AuthenticateHello)?;
    let acknowledgement = NetworkGuestAck::new(hello.nonce)
        .map_err(|_| GuestHandshakeError::AuthenticateHello)?
        .encode(key);
    stream
        .write_all(&acknowledgement)
        .await
        .map_err(|_| GuestHandshakeError::WriteAcknowledgement)?;
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    stream
        .read_exact(&mut ready)
        .await
        .map_err(|_| GuestHandshakeError::ReadReady)?;
    NetworkHostReady::decode(&ready, key, &hello.nonce)
        .map_err(|_| GuestHandshakeError::AuthenticateReady)?;
    let session = NetworkSession::new(key, &hello.nonce, NetworkRole::Guest)
        .map_err(|_| GuestHandshakeError::Session)?;
    Ok((stream, session))
}

/// Carry packets between `tun` and the authenticated `stream` until either
/// side fails. Only canonical IPv4 packets of at most `mtu` bytes cross in
/// either direction: the guest drops others it reads, and a host that sends
/// one ends the session.
pub async fn bridge_guest<S>(
    stream: S,
    session: NetworkSession,
    tun: Arc<AsyncFd<OwnedFd>>,
    mtu: usize,
) -> Result<(), GuestBridgeError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let outbound_session = Arc::clone(&session);
    let outbound_tun = Arc::clone(&tun);
    let outbound = async move {
        loop {
            let packet = read_tun_packet(&outbound_tun)
                .await
                .map_err(GuestBridgeError::ReadTun)?;
            if !canonical_ipv4_packet(&packet, mtu) {
                continue;
            }
            let frame = outbound_session
                .lock()
                .await
                .encode_packet(&packet)
                .map_err(GuestBridgeError::Frame)?;
            stream_write
                .write_all(&frame)
                .await
                .map_err(GuestBridgeError::WriteFrame)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), GuestBridgeError>(())
    };
    let inbound_session = Arc::clone(&session);
    let inbound = async move {
        loop {
            let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
            stream_read
                .read_exact(&mut header)
                .await
                .map_err(GuestBridgeError::ReadFrame)?;
            let frame_len = encoded_network_frame_len(&header).map_err(GuestBridgeError::Frame)?;
            let mut frame = vec![0_u8; frame_len];
            frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
            stream_read
                .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
                .await
                .map_err(GuestBridgeError::ReadFrame)?;
            let packet = inbound_session
                .lock()
                .await
                .decode_packet(&frame)
                .map_err(GuestBridgeError::Frame)?;
            if !canonical_ipv4_packet(&packet, mtu) {
                return Err(GuestBridgeError::NonCanonicalPacket);
            }
            write_tun_packet(&tun, &packet)
                .await
                .map_err(GuestBridgeError::WriteTun)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), GuestBridgeError>(())
    };
    tokio::try_join!(outbound, inbound)?;
    Ok(())
}

fn canonical_ipv4_packet(packet: &[u8], mtu: usize) -> bool {
    if !(20..=mtu).contains(&packet.len()) || packet[0] >> 4 != 4 {
        return false;
    }
    let header_words = usize::from(packet[0] & 0x0f);
    if header_words < 5
        || header_words
            .checked_mul(4)
            .is_none_or(|length| length > packet.len())
    {
        return false;
    }
    usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
}

/// Read one packet from the TUN device, waiting until it is readable.
pub async fn read_tun_packet(tun: &AsyncFd<OwnedFd>) -> io::Result<Vec<u8>> {
    let mut packet = vec![0_u8; NETWORK_MAX_PACKET_BYTES];
    loop {
        let mut ready = tun.readable().await?;
        match ready.try_io(|descriptor| {
            rustix::io::read(descriptor.get_ref(), &mut packet).map_err(io::Error::from)
        }) {
            Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(Ok(length)) => {
                packet.truncate(length);
                return Ok(packet);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

async fn write_tun_packet(tun: &AsyncFd<OwnedFd>, packet: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = tun.writable().await?;
        match ready.try_io(|descriptor| {
            rustix::io::write(descriptor.get_ref(), packet).map_err(io::Error::from)
        }) {
            Ok(Ok(length)) if length == packet.len() => return Ok(()),
            Ok(Ok(_)) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests;
