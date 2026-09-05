//! Reconnecting DERP transport adapter for [`crate::conn::Conn`].
//!
//! This wraps the low-level DERP client in the `Transport` channel shape used
//! by the WireGuard tunnel. Gateway and CLI callers can share the same
//! reconnect/backpressure behavior while deriving their DERP target from their
//! own runtime configuration.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::sync::mpsc;

use crate::conn::{Transport, WgDatagram};
use crate::derp::{self, BoxedStream, NodePrivate, ReceivedMessage};
use crate::wg::StaticSecret;

const DERP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const DERP_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const DERP_PENDING_DATAGRAM_LIMIT: usize = 1024;
const MAX_RESOLVED_DERP_ADDRESSES: usize = 16;

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
    connect_derp_transport_inner(target, None, secret).await
}

/// Connect and reconnect using only an already-resolved address set while
/// retaining [`DerpTarget::host`] for HTTP authority and TLS verification.
/// This prevents a filesystem-confined host transport from silently falling
/// back to libc/Tokio name resolution after startup.
pub async fn connect_derp_transport_resolved(
    target: &DerpTarget,
    addresses: Vec<SocketAddr>,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    let addresses = validate_resolved_addresses(target, addresses)?;
    connect_derp_transport_inner(target, Some(addresses), secret).await
}

async fn connect_derp_transport_inner(
    target: &DerpTarget,
    addresses: Option<Arc<[SocketAddr]>>,
    secret: &StaticSecret,
) -> Result<Transport, derp::Error> {
    let secret_bytes = secret.to_bytes();
    let initial = connect_derp_client(target, addresses.as_deref(), secret_bytes).await?;

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
                    match connect_derp_client(&target, addresses.as_deref(), secret_bytes).await {
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
    addresses: Option<&[SocketAddr]>,
    secret_bytes: [u8; 32],
) -> Result<derp::Client<BoxedStream>, derp::Error> {
    let private = NodePrivate::from_raw(secret_bytes);
    let candidates = addresses
        .map(|addresses| {
            addresses
                .iter()
                .copied()
                .map(ConnectAddress::Resolved)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![ConnectAddress::Named(target.addr())]);
    let mut last_error = None;
    for address in candidates {
        let mut rng = OsRng;
        let result = match (target.transport.clone(), address) {
            (DerpTransport::Plain, ConnectAddress::Named(address)) => {
                derp::connect_plain(&address, &target.host, private.clone(), &mut rng)
                    .await
                    .map(|client| client.boxed())
            }
            (DerpTransport::Plain, ConnectAddress::Resolved(address)) => {
                derp::connect_plain_resolved(address, &target.host, private.clone(), &mut rng)
                    .await
                    .map(|client| client.boxed())
            }
            (DerpTransport::Tls { skip_verify }, address) => {
                let tls_config = if skip_verify {
                    derp::insecure_tls_config_for_tests()
                } else {
                    derp::webpki_tls_config()
                };
                match address {
                    ConnectAddress::Named(address) => derp::connect_tls(
                        &address,
                        &target.host,
                        tls_config,
                        private.clone(),
                        &mut rng,
                    )
                    .await
                    .map(|client| client.boxed()),
                    ConnectAddress::Resolved(address) => derp::connect_tls_resolved(
                        address,
                        &target.host,
                        tls_config,
                        private.clone(),
                        &mut rng,
                    )
                    .await
                    .map(|client| client.boxed()),
                }
            }
        };
        match result {
            Ok(client) => return Ok(client),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(derp::Error::Protocol("DERP resolved address set is empty")))
}

enum ConnectAddress {
    Named(String),
    Resolved(SocketAddr),
}

fn validate_resolved_addresses(
    target: &DerpTarget,
    addresses: Vec<SocketAddr>,
) -> Result<Arc<[SocketAddr]>, derp::Error> {
    if target.host.trim().is_empty()
        || target.port == 0
        || addresses.is_empty()
        || addresses.len() > MAX_RESOLVED_DERP_ADDRESSES
        || addresses.iter().any(|address| {
            address.port() != target.port
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
        })
    {
        return Err(derp::Error::Protocol("invalid resolved DERP target"));
    }
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    Ok(Arc::from(addresses))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> DerpTarget {
        DerpTarget {
            host: "relay.example.com".to_owned(),
            port: 443,
            transport: DerpTransport::Tls { skip_verify: false },
        }
    }

    #[test]
    fn resolved_targets_are_exact_port_bound_and_deduplicated() {
        let addresses = validate_resolved_addresses(
            &target(),
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.10:443".parse().unwrap(),
                "192.0.2.10:443".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(
            validate_resolved_addresses(&target(), vec!["192.0.2.10:8443".parse().unwrap()])
                .is_err()
        );
        assert!(
            validate_resolved_addresses(&target(), vec!["0.0.0.0:443".parse().unwrap()]).is_err()
        );
        assert!(validate_resolved_addresses(&target(), Vec::new()).is_err());
    }
}
