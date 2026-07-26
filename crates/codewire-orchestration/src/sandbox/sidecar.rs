//! Sidecar readiness — the Rust analog of `CheckSidecarReady` /
//! `ConnectSidecarSFTP` in `internal/sandbox/client.go`: port-forward
//! to the gateway sidecar's SSH port, handshake as user `codewire`
//! with no credentials (none-auth, like Go's empty Auth list), open
//! the `sftp` subsystem, and complete the SFTP INIT/VERSION exchange —
//! the exact connection path the API's file routes use at runtime.

use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::client::SandboxClient;

/// SSH port the gateway sidecar listens on (sandbox.DefaultGatewaySSHPort).
pub const DEFAULT_GATEWAY_SSH_PORT: u16 = 2222;
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A live raw port-forward stream. Holds the kube port-forwarder so
/// the underlying stream stays open for the caller's lifetime.
pub struct PortForwardedStream {
    stream: Box<dyn AsyncReadWrite>,
    _pf: Option<kube::api::Portforwarder>,
}

impl PortForwardedStream {
    pub fn stream_mut(&mut self) -> &mut dyn AsyncReadWrite {
        self.stream.as_mut()
    }

    pub fn into_parts(self) -> (Box<dyn AsyncReadWrite>, Option<kube::api::Portforwarder>) {
        (self.stream, self._pf)
    }
}

struct AcceptAllKeys;

impl russh::client::Handler for AcceptAllKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Mirrors Go's gossh.InsecureIgnoreHostKey(): sandbox sidecars
        // have ephemeral host keys.
        Ok(true)
    }
}

fn sidecar_ssh_config() -> Arc<russh::client::Config> {
    let mut config = russh::client::Config::default();
    // The Go gateway server currently advertises the post-quantum ML-KEM
    // hybrid KEX, but russh 0.61 and x/crypto/ssh do not interoperate
    // reliably on that path. OpenSSH clients negotiate curve25519 here, so
    // keep the in-cluster readiness/file client on the same conservative KEX
    // set until the gateway server is ported or the libraries converge.
    config.preferred.kex = Cow::Borrowed(&[
        russh::kex::CURVE25519,
        russh::kex::CURVE25519_PRE_RFC_8731,
        russh::kex::DH_G14_SHA256,
    ]);
    Arc::new(config)
}

impl SandboxClient {
    /// Opens a raw kube port-forward stream to the environment pod.
    pub async fn port_forward_stream(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let pod_name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("port-forward: resolve pod name: {e}"))?;
        self.port_forward_pod_stream(&pod_name, port).await
    }

    pub async fn gateway_port_forward_stream(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let pod_name = self
            .gateway_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("gateway port-forward: resolve pod name: {e}"))?;
        self.port_forward_pod_stream(&pod_name, port).await
    }

    pub async fn gateway_pod_name(&self, env_id: &str) -> anyhow::Result<String> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let labels = format!("codewire.sh/environment-id={env_id},codewire.sh/type=gateway");
        let list = pods
            .list(&ListParams::default().labels(&labels))
            .await
            .map_err(|e| anyhow::anyhow!("list gateway pods: {e}"))?;
        let pod = list
            .items
            .into_iter()
            .find(|pod| {
                pod.status
                    .as_ref()
                    .and_then(|status| status.phase.as_deref())
                    .is_some_and(|phase| phase == "Running")
            })
            .ok_or_else(|| anyhow::anyhow!("no running gateway pod for env {env_id}"))?;
        pod.metadata
            .name
            .ok_or_else(|| anyhow::anyhow!("gateway pod has no name"))
    }

    async fn port_forward_pod_stream(
        &self,
        pod_name: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let direct_error = match self.direct_pod_stream(pod_name, port).await {
            Ok(stream) => {
                return Ok(PortForwardedStream {
                    stream: Box::new(stream),
                    _pf: None,
                });
            }
            Err(err) => err,
        };

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let mut pf = pods
            .portforward(pod_name, &[port])
            .await
            .map_err(|e| anyhow::anyhow!("direct pod TCP: {direct_error}; port-forward: {e}"))?;
        let stream = pf
            .take_stream(port)
            .ok_or_else(|| anyhow::anyhow!("port-forward: no stream for port {port}"))?;

        Ok(PortForwardedStream {
            stream: Box::new(stream),
            _pf: Some(pf),
        })
    }

    async fn direct_pod_stream(&self, pod_name: &str, port: u16) -> anyhow::Result<TcpStream> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let pod = pods
            .get(pod_name)
            .await
            .map_err(|e| anyhow::anyhow!("get pod {pod_name}: {e}"))?;
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|status| status.pod_ip.as_deref())
            .filter(|ip| !ip.is_empty())
            .ok_or_else(|| anyhow::anyhow!("pod {pod_name} has no pod IP"))?;
        let ip: IpAddr = pod_ip
            .parse()
            .map_err(|e| anyhow::anyhow!("parse pod IP {pod_ip}: {e}"))?;
        let addr = SocketAddr::new(ip, port);

        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("connect {addr}: timed out"))?
            .map_err(|e| anyhow::anyhow!("connect {addr}: {e}"))
    }

    /// Mirrors `CheckSidecarReady`.
    pub async fn check_sidecar_ready(&self, env_id: &str, port: u16) -> anyhow::Result<()> {
        let stream = self
            .gateway_port_forward_stream(env_id, port)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness connect: {e}"))?;
        let (stream, _pf) = stream.into_parts();

        let mut handle = russh::client::connect_stream(sidecar_ssh_config(), stream, AcceptAllKeys)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness ssh handshake: {e}"))?;

        let authenticated = handle
            .authenticate_none("codewire")
            .await
            .map(|r| matches!(r, russh::client::AuthResult::Success))
            .unwrap_or(false);
        if !authenticated {
            anyhow::bail!("sidecar readiness ssh handshake: none-auth rejected");
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness sftp init: open session: {e}"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness sftp init: subsystem: {e}"))?;
        let session = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness sftp init: {e}"))?;
        session
            .canonicalize(".")
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness sftp realpath: {e}"))?;
        let _ = session.close().await;

        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }

    /// Mirrors `ConnectSidecarSFTP`: port-forward to the gateway
    /// sidecar's SSH port, none-auth as `codewire`, open the `sftp`
    /// subsystem, and return a live [`russh_sftp`] session. The returned
    /// [`SidecarSftp`] owns the port-forwarder and SSH handle, so the
    /// caller must keep it alive for the duration of the transfer
    /// (dropping it tears down the tunnel, like Go's `cleanup`).
    pub async fn connect_sidecar_sftp(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<SidecarSftp> {
        let stream = self
            .gateway_port_forward_stream(env_id, port)
            .await
            .map_err(|e| anyhow::anyhow!("sftp connect: {e}"))?;
        let (stream, pf) = stream.into_parts();

        let mut handle = russh::client::connect_stream(sidecar_ssh_config(), stream, AcceptAllKeys)
            .await
            .map_err(|e| anyhow::anyhow!("sftp ssh handshake: {e}"))?;

        let authenticated = handle
            .authenticate_none("codewire")
            .await
            .map(|r| matches!(r, russh::client::AuthResult::Success))
            .unwrap_or(false);
        if !authenticated {
            anyhow::bail!("sftp ssh handshake: none-auth rejected");
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow::anyhow!("sftp open session: {e}"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| anyhow::anyhow!("sftp subsystem: {e}"))?;

        let session = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| anyhow::anyhow!("sftp session init: {e}"))?;

        Ok(SidecarSftp {
            session,
            _handle: handle,
            _pf: pf,
        })
    }
}

/// A live SFTP session over a sidecar port-forward. Holds the SSH handle
/// and port-forwarder so the tunnel stays open for the session's
/// lifetime; drop it to tear everything down (Go: the `cleanup` closure).
pub struct SidecarSftp {
    session: russh_sftp::client::SftpSession,
    _handle: russh::client::Handle<AcceptAllKeys>,
    _pf: Option<kube::api::Portforwarder>,
}

impl SidecarSftp {
    /// The underlying russh-sftp session for file operations.
    pub fn session(&self) -> &russh_sftp::client::SftpSession {
        &self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_config_uses_classic_kex() {
        let config = sidecar_ssh_config();
        assert_eq!(config.preferred.kex[0], russh::kex::CURVE25519);
        assert!(
            !config
                .preferred
                .kex
                .contains(&russh::kex::MLKEM768X25519_SHA256)
        );
    }
}
