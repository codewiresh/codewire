use std::env;
use std::net::{IpAddr, SocketAddr};

use crate::{
    MeshKey, Relay, self_signed_tls_config, serve_mesh_discovery, serve_plain, serve_stun,
    serve_tls,
};
use codewire_tailnet::derp::NodePrivate;
use rand::rngs::OsRng;
use tokio::net::{TcpListener, UdpSocket};

/// Run the standalone DERP listener assembly on the caller's Tokio runtime.
/// The retained cw role uses the identical configuration and shutdown path.
pub async fn run_from_env() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let plain_addr = plain_listen_addr()?;
    let tls_addr = tls_listen_addr()?;
    let stun_addr = stun_listen_addr()?;
    if plain_addr.is_none() && tls_addr.is_none() && stun_addr.is_none() {
        return Err("no DERP HTTP, TLS, or STUN listeners enabled".into());
    }

    let mesh_key = mesh_key()?;
    let relay = match mesh_key {
        Some(mesh_key) => Relay::new_with_mesh_key(NodePrivate::generate(&mut OsRng), mesh_key),
        None => Relay::new(NodePrivate::generate(&mut OsRng)),
    };
    let mut tasks = tokio::task::JoinSet::new();

    if let (Some(_), Some(hostname)) = (mesh_key, mesh_hostname()?) {
        let relay = relay.clone();
        let self_ip = self_ip()?;
        tracing::info!(%hostname, "codewire derp mesh discovery started");
        tasks.spawn(serve_mesh_discovery(relay, hostname, 8080, self_ip));
    }

    if let Some(addr) = plain_addr {
        let listener = TcpListener::bind(addr).await?;
        let relay = relay.clone();
        tracing::info!(listen_addr = %addr, public_key = ?relay.public_key(), "codewire derp http listener started");
        tasks.spawn(serve_plain(listener, relay));
    }

    if let Some(addr) = tls_addr {
        let listener = TcpListener::bind(addr).await?;
        let tls_config = self_signed_tls_config(&tls_hosts()?)?;
        let relay = relay.clone();
        tracing::info!(listen_addr = %addr, public_key = ?relay.public_key(), "codewire derp tls listener started");
        tasks.spawn(serve_tls(listener, relay, tls_config));
    }

    if let Some(addr) = stun_addr {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(listen_addr = %addr, "codewire derp stun listener started");
        tasks.spawn(serve_stun(socket));
    }

    tokio::select! {
        result = tasks.join_next() => {
            if let Some(result) = result {
                result??;
            }
        }
        signal = shutdown_signal() => {
            signal?;
            tracing::info!("codewire derp shutdown signal received");
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn plain_listen_addr() -> Result<Option<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(raw) = env::var("LISTEN_ADDR") {
        return Ok(Some(raw.parse()?));
    }

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    if port.is_empty() || port == "-1" {
        return Ok(None);
    }
    Ok(Some(format!("0.0.0.0:{port}").parse()?))
}

fn tls_listen_addr() -> Result<Option<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(raw) = env::var("TLS_LISTEN_ADDR") {
        return Ok(Some(raw.parse()?));
    }

    let Ok(port) = env::var("TLS_PORT") else {
        return Ok(None);
    };
    if port.is_empty() || port == "-1" {
        return Ok(None);
    }
    Ok(Some(format!("0.0.0.0:{port}").parse()?))
}

fn stun_listen_addr() -> Result<Option<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(raw) = env::var("STUN_LISTEN_ADDR") {
        if raw.is_empty() || raw == "-1" {
            return Ok(None);
        }
        return Ok(Some(raw.parse()?));
    }

    let port = env::var("STUN_PORT").unwrap_or_else(|_| "3478".to_string());
    if port.is_empty() || port == "-1" {
        return Ok(None);
    }
    Ok(Some(format!("0.0.0.0:{port}").parse()?))
}

fn tls_hosts() -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(env::var("TLS_HOSTS")
        .unwrap_or_else(|_| "127.0.0.1,localhost".to_string())
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn mesh_key() -> Result<Option<MeshKey>, Box<dyn std::error::Error + Send + Sync>> {
    let Ok(raw) = env::var("DERP_MESH_KEY") else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(MeshKey::parse(&raw)?))
}

fn mesh_hostname() -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let Ok(raw) = env::var("DERP_MESH_HOSTNAME") else {
        return Ok(None);
    };
    let host = raw.trim();
    if host.is_empty() {
        return Ok(None);
    }
    Ok(Some(host.to_string()))
}

fn self_ip() -> Result<Option<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let Ok(raw) = env::var("MY_POD_IP") else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    Ok(Some(raw.parse()?))
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = term.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
