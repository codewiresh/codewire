//! Host-side Pod UDP `:31000` bridge for `standard` Sandboxes (#6637).
//!
//! Runs in the unconfined runner process (never inside the confined network
//! worker, which denies `socket`/`bind`/`sendto`/`recvfrom`). When a Pod
//! configures non-empty literal `CODEWIRE_POD_UDP_PEERS`, this binds Pod
//! `0.0.0.0:31000` and bridges datagrams over a pre-connected `UnixStream` to
//! the confined worker.
//!
//! Invariants (cw-security, #6637):
//! - Never binds `0.0.0.0:31000` when `allowed_peers` is empty.
//! - Enforces the exact literal IPv4:port allowlist in both directions
//!   (defense-in-depth at the host boundary even if the worker were compromised).
//! - Rejects payloads exceeding `MAX_UDP_BRIDGE_PAYLOAD` (`MTU - 28`).
//! - Uses bounded drop-on-full queueing (`try_send`) and never calls
//!   `Suspender::wake()`, so inbound UDP while the VM is paused drops cleanly.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use codewire_egress_worker::session::{
    MAX_UDP_BRIDGE_PAYLOAD, TAILNET_UDP_PORT, read_udp_bridge_frame, write_udp_bridge_frame,
};
use tokio::net::{UdpSocket, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Bounded inbound queue depth from Pod UDP `:31000` to the worker stream.
const HOST_UDP_QUEUE_CAPACITY: usize = 64;

/// Running host-side UDP `:31000` bridge owned by `NetworkWorkerProcess`.
/// Dropping it aborts both forwarding tasks and closes the Pod UDP socket.
pub(super) struct HostUdpBridge {
    tasks: [JoinHandle<()>; 3],
}

impl HostUdpBridge {
    /// Binds `0.0.0.0:31000` in the Pod's network namespace and spawns the
    /// allowlisted UDP forwarder over `worker_stream`.
    pub(super) async fn bind_pod_port(
        worker_stream: UnixStream,
        allowed_peers: Vec<SocketAddrV4>,
    ) -> io::Result<Self> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, TAILNET_UDP_PORT));
        let (bridge, _) = Self::bind_at(bind_addr, worker_stream, allowed_peers).await?;
        Ok(bridge)
    }

    async fn bind_at(
        bind_addr: SocketAddr,
        worker_stream: UnixStream,
        allowed_peers: Vec<SocketAddrV4>,
    ) -> io::Result<(Self, SocketAddr)> {
        if allowed_peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP bridge requires at least one allowlisted peer",
            ));
        }
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let allowed: Arc<[SocketAddrV4]> = allowed_peers.into();
        let (mut worker_read, mut worker_write) = worker_stream.into_split();
        let (inbound_tx, mut inbound_rx) =
            mpsc::channel::<(SocketAddrV4, Vec<u8>)>(HOST_UDP_QUEUE_CAPACITY);

        // Outbound: worker -> Pod UDP socket (strict destination allowlist).
        let out_socket = Arc::clone(&socket);
        let out_allowed = Arc::clone(&allowed);
        let outbound_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_UDP_BRIDGE_PAYLOAD];
            while let Ok(Some((destination, len))) =
                read_udp_bridge_frame(&mut worker_read, &mut buffer).await
            {
                if !out_allowed.contains(&destination) || len > MAX_UDP_BRIDGE_PAYLOAD {
                    continue;
                }
                // Best-effort non-blocking UDP send; transient kernel buffer
                // pressure drops the datagram rather than stalling the bridge.
                let _ = out_socket.try_send_to(&buffer[..len], SocketAddr::V4(destination));
            }
        });

        // Inbound recv: Pod UDP socket -> bounded drop-on-full channel.
        // Never wakes Suspender; non-allowlisted senders and oversized datagrams
        // are dropped before allocating or queueing.
        let in_socket = Arc::clone(&socket);
        let in_allowed = Arc::clone(&allowed);
        let inbound_recv_task = tokio::spawn(async move {
            // Allocate one extra byte so datagrams strictly larger than
            // MAX_UDP_BRIDGE_PAYLOAD are detected and dropped cleanly.
            let mut buffer = vec![0_u8; MAX_UDP_BRIDGE_PAYLOAD + 1];
            loop {
                let Ok((len, sender)) = in_socket.recv_from(&mut buffer).await else {
                    break;
                };
                let SocketAddr::V4(source) = sender else {
                    continue;
                };
                if !in_allowed.contains(&source) || len > MAX_UDP_BRIDGE_PAYLOAD {
                    continue;
                }
                // Drop-on-full: an inbound flood or paused VM never blocks recv.
                let _ = inbound_tx.try_send((source, buffer[..len].to_vec()));
            }
        });

        // Inbound write: bounded channel -> worker stream.
        let inbound_write_task = tokio::spawn(async move {
            while let Some((source, payload)) = inbound_rx.recv().await {
                if write_udp_bridge_frame(&mut worker_write, source, &payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok((
            Self {
                tasks: [outbound_task, inbound_recv_task, inbound_write_task],
            },
            local_addr,
        ))
    }
}

impl Drop for HostUdpBridge {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn host_bridge_forwards_allowlisted_peer_and_drops_unlisted_and_oversized() {
        let allowed_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let allowed_addr = match allowed_peer.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unreachable!(),
        };
        let unlisted_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unlisted_addr = match unlisted_peer.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unreachable!(),
        };

        let (runner_end, mut worker_end) = UnixStream::pair().unwrap();
        let (bridge, host_bind) = HostUdpBridge::bind_at(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            runner_end,
            vec![allowed_addr],
        )
        .await
        .unwrap();

        // Outbound: allowlisted peer receives datagram; unlisted peer does not.
        write_udp_bridge_frame(&mut worker_end, unlisted_addr, b"must-not-leave")
            .await
            .unwrap();
        write_udp_bridge_frame(&mut worker_end, allowed_addr, b"allowed-out")
            .await
            .unwrap();

        let mut buf = [0_u8; 64];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(2), allowed_peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"allowed-out");
        assert_eq!(from, host_bind);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                unlisted_peer.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "unlisted destination must not receive UDP"
        );

        // Inbound: unlisted sender dropped, oversized datagram dropped,
        // allowlisted sender delivered.
        unlisted_peer
            .send_to(b"untrusted-in", host_bind)
            .await
            .unwrap();
        allowed_peer
            .send_to(&vec![0xee; MAX_UDP_BRIDGE_PAYLOAD + 1], host_bind)
            .await
            .unwrap();
        allowed_peer
            .send_to(b"allowed-in", host_bind)
            .await
            .unwrap();

        let mut recv_buf = vec![0_u8; MAX_UDP_BRIDGE_PAYLOAD];
        let (src, len) = tokio::time::timeout(
            Duration::from_secs(2),
            read_udp_bridge_frame(&mut worker_end, &mut recv_buf),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(src, allowed_addr);
        assert_eq!(&recv_buf[..len], b"allowed-in");

        drop(bridge);
    }

    #[tokio::test]
    async fn host_bridge_rejects_empty_allowlist_without_binding() {
        let (runner_end, _worker_end) = UnixStream::pair().unwrap();
        let result = HostUdpBridge::bind_at(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            runner_end,
            Vec::new(),
        )
        .await;
        assert!(result.is_err());
    }
}
