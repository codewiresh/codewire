//! Exercise the pinned SSH packet writer over the real TCP adapter while
//! deliberately holding ACKs. This checks a protocol boundary, not throughput.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_tailnet::netstack::{Netstack, TcpStream};
use russh::{ChannelId, ChannelMsg, client, server};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot, watch};

#[derive(Default)]
struct FlushProgress {
    completed: AtomicUsize,
    written_bytes: AtomicU64,
    flushed_bytes: AtomicU64,
    changed: Notify,
}

impl FlushProgress {
    async fn after(&self, previous: usize) {
        while self.completed.load(Ordering::Acquire) <= previous {
            self.changed.notified().await;
        }
    }

    async fn through(&self, written_bytes: u64) {
        while self.flushed_bytes.load(Ordering::Acquire) < written_bytes {
            self.changed.notified().await;
        }
    }
}

struct ObservedStream {
    inner: TcpStream,
    progress: Arc<FlushProgress>,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(bytes)) = result {
            self.progress
                .written_bytes
                .fetch_add(bytes as u64, Ordering::Release);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Ok(())) = result {
            self.progress.flushed_bytes.store(
                self.progress.written_bytes.load(Ordering::Acquire),
                Ordering::Release,
            );
            self.progress.completed.fetch_add(1, Ordering::Release);
            self.progress.changed.notify_one();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct AcceptSyntheticKey;

impl client::Handler for AcceptSyntheticKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct OpenChannel {
    opened: Option<oneshot::Sender<(ChannelId, server::Handle, usize)>>,
    progress: Arc<FlushProgress>,
}

impl server::Handler for OpenChannel {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let before_confirmation = self.progress.completed.load(Ordering::Acquire);
        reply.accept().await;
        self.opened
            .take()
            .unwrap()
            .send((channel.id(), session.handle(), before_confirmation))
            .unwrap();
        Ok(())
    }
}

// Preserve packet order and the existing packet-queue bound while ACKs are
// held. Releasing the gate drains the retained packets before newer packets.
async fn gated_wire(
    mut packets: mpsc::Receiver<Vec<u8>>,
    to_peer: mpsc::Sender<Vec<u8>>,
    mut hold: watch::Receiver<bool>,
    retained: Arc<Notify>,
) {
    let mut pending = VecDeque::new();
    loop {
        tokio::select! {
            changed = hold.changed() => { if changed.is_err() { return; } }
            packet = packets.recv(), if pending.len() < 256 => {
                let Some(packet) = packet else { return; };
                pending.push_back(packet);
                if *hold.borrow() { retained.notify_one(); }
            }
        }
        let forwarding = !*hold.borrow();
        if forwarding {
            while let Some(packet) = pending.pop_front() {
                if to_peer.send(packet).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[tokio::test]
async fn ssh_packet_flush_does_not_wait_for_the_receivers_ack() {
    let (a_out, packets) = mpsc::channel(256);
    let (to_b, b_in) = mpsc::channel(256);
    let (b_out, a_in) = mpsc::channel(256);
    let (gate, hold) = watch::channel(false);
    let retained = Arc::new(Notify::new());
    let wire = tokio::spawn(gated_wire(packets, to_b, hold, retained.clone()));
    let a_ip: Ipv6Addr = "fd7a:115c:a1e0::a".parse().unwrap();
    let b_ip: Ipv6Addr = "fd7a:115c:a1e0::b".parse().unwrap();
    let a = Netstack::new(IpAddr::V6(a_ip), 48, a_in, a_out);
    let b = Netstack::new(IpAddr::V6(b_ip), 48, b_in, b_out);
    let mut listener = b.bind(2223).await.unwrap();
    let progress = Arc::new(FlushProgress::default());
    let server_progress = progress.clone();
    let (opened, opened_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let key = russh::keys::PrivateKey::from(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&rand::random()),
        );
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let stream = listener.accept().await.unwrap();
        server::run_stream(
            config,
            ObservedStream {
                inner: stream,
                progress: server_progress.clone(),
            },
            OpenChannel {
                opened: Some(opened),
                progress: server_progress,
            },
        )
        .await
        .unwrap()
        .await
        .unwrap();
    });
    let stream = a
        .connect(SocketAddr::new(IpAddr::V6(b_ip), 2223))
        .await
        .unwrap();
    let mut client = client::connect_stream(
        Arc::new(client::Config::default()),
        stream,
        AcceptSyntheticKey,
    )
    .await
    .unwrap();
    assert!(matches!(
        client.authenticate_none("synthetic").await.unwrap(),
        client::AuthResult::Success
    ));
    let mut channel = client.channel_open_session().await.unwrap();
    let (id, handle, before_confirmation) = opened_rx.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), progress.after(before_confirmation))
        .await
        .expect("handshake confirmation flushed before holding ACKs");

    gate.send(true).unwrap();
    let payload: Vec<_> = (0..8192).map(|n| (n % 251) as u8).collect();
    handle.data(id, payload.clone()).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while received.len() < payload.len() {
            let ChannelMsg::Data { data } = channel.wait().await.unwrap() else {
                continue;
            };
            received.extend_from_slice(&data);
        }
    })
    .await
    .expect("real SSH channel receives the encrypted payload");
    assert_eq!(received, payload);
    // Receiving the whole payload proves all its successful raw writes have
    // happened. An unrelated earlier control flush cannot satisfy this target.
    let through_payload = progress.written_bytes.load(Ordering::Acquire);
    tokio::time::timeout(Duration::from_secs(2), retained.notified())
        .await
        .expect("receiver ACK remains behind the gate");
    tokio::time::timeout(Duration::from_secs(2), progress.through(through_payload))
        .await
        .expect("real SSH packet-writer flush must finish before the held ACK is released");

    gate.send(false).unwrap();
    handle.eof(id).await.unwrap();
    handle.close(id).await.unwrap();
    let mut eof = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(message) = channel.wait().await {
            if matches!(message, ChannelMsg::Eof) {
                eof = true;
            }
        }
    })
    .await
    .expect("SSH channel closes after its complete payload");
    assert!(eof);
    client
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("real SSH shutdown completes")
        .unwrap();
    wire.abort();
}
