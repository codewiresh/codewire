//! Reconnecting DERP transport adapter for [`crate::conn::Conn`].
//!
//! This wraps the low-level DERP client in the `Transport` channel shape used
//! by the WireGuard tunnel. Gateway and CLI callers can share the same
//! reconnect/backpressure behavior while deriving their DERP target from their
//! own runtime configuration.

use std::collections::VecDeque;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::mpsc;

use crate::conn::{Transport, WgDatagram};
use crate::derp::{self, BoxedStream, NodePrivate, ReceivedMessage};
use crate::wg::StaticSecret;

const DERP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const DERP_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const DERP_PENDING_DATAGRAM_LIMIT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpTarget {
    pub host: String,
    pub port: u16,
    pub transport: DerpTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpTransport {
    Plain,
    Tls { skip_verify: bool },
}

impl DerpTarget {
    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub async fn connect_derp_transport(
    target: &DerpTarget,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    let secret_bytes = secret.to_bytes();
    let initial = connect_derp_client(target, secret_bytes).await?;

    let (to_transport, mut to_transport_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (from_transport_tx, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    let target = target.clone();

    tokio::spawn(async move {
        let mut pending = VecDeque::new();
        let mut next_client = Some(initial);
        let mut reconnect_delay = DERP_RECONNECT_INITIAL_DELAY;

        loop {
            let mut client = match next_client.take() {
                Some(client) => client,
                None => loop {
                    match connect_derp_client(&target, secret_bytes).await {
                        Ok(client) => break client,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                delay_ms = reconnect_delay.as_millis(),
                                derp_host = %target.host,
                                derp_port = target.port,
                                "rust tailnet DERP transport reconnect failed"
                            );
                            let sleep = tokio::time::sleep(reconnect_delay);
                            tokio::pin!(sleep);
                            loop {
                                tokio::select! {
                                    _ = &mut sleep => break,
                                    maybe = to_transport_rx.recv() => {
                                        let Some(dg) = maybe else { return; };
                                        queue_pending_derp_datagram(&mut pending, dg);
                                    }
                                }
                            }
                            reconnect_delay = (reconnect_delay * 2).min(DERP_RECONNECT_MAX_DELAY);
                        }
                    }
                },
            };

            tracing::info!(
                derp_host = %target.host,
                derp_port = target.port,
                "rust tailnet DERP transport connected"
            );
            reconnect_delay = DERP_RECONNECT_INITIAL_DELAY;

            loop {
                while let Some(dg) = pending.pop_front() {
                    if let Err(err) = client.send(&dg.peer, &dg.data).await {
                        queue_pending_derp_datagram_front(&mut pending, dg);
                        tracing::warn!(
                            error = %err,
                            "rust tailnet DERP transport send failed; reconnecting"
                        );
                        break;
                    }
                }
                if !pending.is_empty() {
                    break;
                }

                tokio::select! {
                    maybe = to_transport_rx.recv() => {
                        let Some(dg) = maybe else { return; };
                        if let Err(err) = client.send(&dg.peer, &dg.data).await {
                            queue_pending_derp_datagram(&mut pending, dg);
                            tracing::warn!(
                                error = %err,
                                "rust tailnet DERP transport send failed; reconnecting"
                            );
                            break;
                        }
                    }
                    msg = client.recv() => {
                        match msg {
                            Ok(ReceivedMessage::Packet { source, data }) => {
                                if from_transport_tx.send(WgDatagram { peer: source, data }).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "rust tailnet DERP transport receive failed; reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(Transport {
        to_transport,
        from_transport,
        peer_updates: None,
        path_probe: None,
        local_endpoint_updates: None,
    })
}

async fn connect_derp_client(
    target: &DerpTarget,
    secret_bytes: [u8; 32],
) -> Result<derp::Client<BoxedStream>, derp::Error> {
    let private = NodePrivate::from_raw(secret_bytes);
    let mut rng = OsRng;
    let addr = target.addr();

    match target.transport {
        DerpTransport::Plain => {
            let client = derp::connect_plain(&addr, &target.host, private, &mut rng).await?;
            Ok(client.boxed())
        }
        DerpTransport::Tls { skip_verify } => {
            let tls_config = if skip_verify {
                derp::insecure_tls_config_for_tests()
            } else {
                derp::webpki_tls_config()
            };
            let client =
                derp::connect_tls(&addr, &target.host, tls_config, private, &mut rng).await?;
            Ok(client.boxed())
        }
    }
}

fn queue_pending_derp_datagram(pending: &mut VecDeque<WgDatagram>, dg: WgDatagram) {
    if pending.len() >= DERP_PENDING_DATAGRAM_LIMIT {
        pending.pop_front();
    }
    pending.push_back(dg);
}

fn queue_pending_derp_datagram_front(pending: &mut VecDeque<WgDatagram>, dg: WgDatagram) {
    if pending.len() >= DERP_PENDING_DATAGRAM_LIMIT {
        pending.pop_back();
    }
    pending.push_front(dg);
}
