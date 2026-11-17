//! A hosted daemon's platform connections, which leave by the Pod's own
//! interface rather than the TUN (#4000; `designs/hosted-egress.md`, "What
//! leaves by the Pod interface, and how").
//!
//! The TUN is the guest's default route. A socket bound to the Pod interface
//! with `SO_BINDTODEVICE` is routed by the Pod table instead, through the
//! init container's output-interface rule, and so reaches the in-cluster
//! peers the Pod's NetworkPolicy names: cw-egress, the binding, the public
//! gateway's Service and DERP. Every platform dial goes through here. One that
//! doesn't goes into the TUN, and the broker refuses it as a protected range,
//! so a missed call site fails closed and shows in the refusal log.
//!
//! An unprivileged process may bind a socket to a device once, since Linux
//! 5.7. A refused bind is an error here, never a fallback to an unbound
//! socket.

use std::io;
use std::net::SocketAddrV4;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use super::HOSTED_POD_INTERFACE;

/// Connect to a platform peer by the Pod's interface.
pub async fn connect_tcp(peer: SocketAddrV4) -> io::Result<TcpStream> {
    connect_tcp_by(peer, HOSTED_POD_INTERFACE).await
}

/// An unconnected TCP socket bound to the Pod's interface, for a caller that
/// sets its own options before it connects.
pub fn tcp_socket() -> io::Result<TcpSocket> {
    tcp_socket_by(HOSTED_POD_INTERFACE)
}

/// A UDP socket at `local`, bound to the Pod's interface.
pub async fn bind_udp(local: SocketAddrV4) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local).await?;
    socket
        .bind_device(Some(HOSTED_POD_INTERFACE.as_bytes()))
        .map_err(|error| refused(HOSTED_POD_INTERFACE, error))?;
    Ok(socket)
}

/// [`connect_tcp`] by `interface`: the guest's egress connector dials by
/// loopback in its tests.
pub(crate) async fn connect_tcp_by(peer: SocketAddrV4, interface: &str) -> io::Result<TcpStream> {
    tcp_socket_by(interface)?.connect(peer.into()).await
}

fn tcp_socket_by(interface: &str) -> io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| refused(interface, error))?;
    Ok(socket)
}

fn refused(interface: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("bind a platform connection to the Pod interface {interface}: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn a_connection_bound_to_an_interface_reaches_a_peer_on_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let std::net::SocketAddr::V4(peer) = listener.local_addr().unwrap() else {
            unreachable!("an IPv4 listener has an IPv4 address");
        };
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let mut stream = connect_tcp_by(peer, "lo").await.unwrap();
        let mut reply = [0_u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        accept.await.unwrap();
        assert_eq!(
            tcp_socket_by("lo").unwrap().device().unwrap().as_deref(),
            Some(&b"lo"[..])
        );
    }

    #[tokio::test]
    async fn an_interface_the_kernel_refuses_is_an_error_never_an_unbound_socket() {
        let error = tcp_socket_by("cwnosuch0").unwrap_err();
        assert!(
            error.to_string().contains("Pod interface cwnosuch0"),
            "{error}"
        );
    }
}
