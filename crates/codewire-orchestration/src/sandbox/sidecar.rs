//! SSH readiness and file access against the workspace daemon's SSH server
//! (design §3, L4): connect to the current workspace Pod's SSH port over the
//! Pod network, handshake as user `codewire` with no credentials (none-auth;
//! only orchestration may reach that port), open the `sftp` subsystem, and
//! complete the SFTP INIT/VERSION exchange — the exact connection path the
//! API's file routes use at runtime.

use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::client::SandboxClient;
use super::host_keys::HostKeyStore;

/// The workspace daemon's SSH port, which only orchestration may reach.
pub const WORKSPACE_SSH_PORT: u16 = codewire_gateway_proto::WORKSPACE_DAEMON_SSH_PORT;
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Between access readiness attempts.
const ACCESS_READY_POLL: Duration = Duration::from_millis(250);
/// How long one access readiness attempt may take, connect to key exchange.
const ACCESS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A live raw port-forward stream. Holds the kube port-forwarder so
/// the underlying stream stays open for the caller's lifetime.
pub struct PortForwardedStream {
    stream: Box<dyn AsyncReadWrite>,
    _pf: Option<kube::api::Portforwarder>,
}

impl PortForwardedStream {
    pub fn into_parts(self) -> (Box<dyn AsyncReadWrite>, Option<kube::api::Portforwarder>) {
        (self.stream, self._pf)
    }
}

impl AsyncRead for PortForwardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_read(context, buffer)
    }
}

impl AsyncWrite for PortForwardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.stream.as_mut()).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut()).poll_shutdown(context)
    }
}

async fn direct_stream(pod: &Pod, pod_name: &str, port: u16) -> anyhow::Result<TcpStream> {
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

/// Accepts exactly the host key recorded for the environment's current
/// generation.
struct PinnedHostKey(russh::keys::PublicKey);

impl PinnedHostKey {
    async fn current(env_id: &str, host_keys: &dyn HostKeyStore) -> anyhow::Result<Self> {
        let (_, key) = host_keys
            .current_host_key(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("read the recorded host key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("no host key is recorded for the current generation"))?;
        Ok(Self(russh::keys::PublicKey::from_openssh(&key).map_err(
            |_| anyhow::anyhow!("the recorded host key is not an OpenSSH key"),
        )?))
    }
}

impl russh::client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(
            server_public_key,
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.0.key_data()
        ))
    }
}

struct AcceptAllKeys;

impl russh::client::Handler for AcceptAllKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Workspace daemons have per-generation public host keys, and only
        // orchestration reaches this port. Host certificates
        // remain unsupported when the library exposes both identity types.
        Ok(matches!(
            server_public_key,
            russh::keys::PublicKeyOrCertificate::PublicKey { .. }
        ))
    }
}

fn sidecar_ssh_config() -> Arc<russh::client::Config> {
    let mut config = russh::client::Config::default();
    // Keep the in-cluster readiness/file client on the conservative KEX set
    // OpenSSH clients negotiate with the environment's SSH server; russh and
    // other servers' post-quantum ML-KEM hybrids have not interoperated
    // reliably.
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

    /// A stream to `port` of the current workspace Pod: the exact Pod the
    /// bound Sandbox controls, over the Pod network, else through a kube
    /// port-forward to that Pod.
    pub async fn workspace_ssh_stream(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<PortForwardedStream> {
        let pod = self
            .current_workspace_pod_object(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("workspace SSH: {e}"))?;
        let pod_name = pod
            .metadata
            .name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("workspace SSH: the Pod has no name"))?;
        let direct_error = match direct_stream(&pod, &pod_name, port).await {
            Ok(stream) => {
                return Ok(PortForwardedStream {
                    stream: Box::new(stream),
                    _pf: None,
                });
            }
            Err(err) => err,
        };
        self.forwarded_stream(&pod_name, port, direct_error).await
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
        self.forwarded_stream(pod_name, port, direct_error).await
    }

    async fn forwarded_stream(
        &self,
        pod_name: &str,
        port: u16,
        direct_error: anyhow::Error,
    ) -> anyhow::Result<PortForwardedStream> {
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
        direct_stream(&pod, pod_name, port).await
    }

    /// The `access_ready` stage (design L4): the environment's current
    /// generation has a recorded host key, and the current workspace Pod's
    /// SSH port completes a key exchange presenting exactly that key. The
    /// daemon records its key only once bound, so this proves the bound
    /// daemon serves SSH.
    pub async fn wait_for_workspace_access_ready(
        &self,
        env_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        self.wait_for_workspace_access_ready_on(env_id, WORKSPACE_SSH_PORT, timeout, host_keys)
            .await
    }

    async fn wait_for_workspace_access_ready_on(
        &self,
        env_id: &str,
        port: u16,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        let mut last = None;
        let ready = tokio::time::timeout(timeout, async {
            loop {
                let attempt = tokio::time::timeout(
                    ACCESS_HANDSHAKE_TIMEOUT,
                    self.pinned_key_exchange(env_id, port, host_keys),
                )
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("SSH key exchange timed out")));
                match attempt {
                    Ok(()) => return,
                    Err(error) => last = Some(error),
                }
                tokio::time::sleep(ACCESS_READY_POLL).await;
            }
        })
        .await;
        ready.map_err(|_| match last.take() {
            Some(error) => anyhow::anyhow!("workspace SSH access readiness timed out: {error}"),
            None => anyhow::anyhow!("workspace SSH access readiness timed out"),
        })
    }

    async fn pinned_key_exchange(
        &self,
        env_id: &str,
        port: u16,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        let pinned = PinnedHostKey::current(env_id, host_keys).await?;
        let (stream, _pf) = self.workspace_ssh_stream(env_id, port).await?.into_parts();
        let handle = russh::client::connect_stream(sidecar_ssh_config(), stream, pinned)
            .await
            .map_err(|e| anyhow::anyhow!("SSH key exchange with the recorded host key: {e}"))?;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }

    /// The workspace daemon's SSH server, presenting the host key recorded
    /// for the current generation, completes a none-auth handshake and an
    /// SFTP exchange: the health check after setup.
    pub async fn check_sidecar_ready(
        &self,
        env_id: &str,
        port: u16,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()> {
        let pinned = PinnedHostKey::current(env_id, host_keys)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness host key: {e}"))?;
        let stream = self
            .workspace_ssh_stream(env_id, port)
            .await
            .map_err(|e| anyhow::anyhow!("sidecar readiness connect: {e}"))?;
        let (stream, _pf) = stream.into_parts();

        let mut handle = russh::client::connect_stream(sidecar_ssh_config(), stream, pinned)
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

    /// Connect to the workspace daemon's SSH server, none-auth as
    /// `codewire`, open the `sftp` subsystem, and return a live
    /// [`russh_sftp`] session. The returned [`SidecarSftp`] owns the
    /// stream and SSH handle, so the caller must keep it alive for the
    /// duration of the transfer (dropping it tears down the connection).
    pub async fn connect_sidecar_sftp(
        &self,
        env_id: &str,
        port: u16,
    ) -> anyhow::Result<SidecarSftp> {
        let stream = self
            .workspace_ssh_stream(env_id, port)
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
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, Response, StatusCode, header};
    use serde_json::json;
    use std::sync::Mutex;

    const NAMESPACE: &str = "synthetic-sandboxes";
    const ENVIRONMENT: &str = "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000001";
    const SANDBOX_UID: &str = "5a4db0c5-e29b-41d4-a716-446655440000";

    /// The Claim, its bound Sandbox and the Pod that Sandbox controls, at
    /// `pod_ip`. Records every path the client reads.
    fn workspace_chain(
        pod_ip: &str,
        controller_uid: &str,
    ) -> (SandboxClient, Arc<Mutex<Vec<String>>>) {
        let claim = crate::sandbox::claim_name(ENVIRONMENT);
        let objects = [
            (
                format!(
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxclaims/{claim}"
                ),
                json!({"apiVersion":"extensions.agents.x-k8s.io/v1beta1","kind":"SandboxClaim",
                    "metadata":{"name":claim,"namespace":NAMESPACE,"uid":"c0ffee00-e29b-41d4-a716-446655440000"},
                    "status":{"sandbox":{"name":"sandbox-a"}}}),
            ),
            (
                format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/sandbox-a"),
                json!({"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
                    "metadata":{"name":"sandbox-a","namespace":NAMESPACE,"uid":SANDBOX_UID,
                        "annotations":{"agents.x-k8s.io/pod-name":"workspace-a"}}}),
            ),
            (
                format!("/api/v1/namespaces/{NAMESPACE}/pods/workspace-a"),
                json!({"apiVersion":"v1","kind":"Pod",
                    "metadata":{"name":"workspace-a","namespace":NAMESPACE,"uid":"7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
                        "labels":{"codewire.sh/type":"workspace"},
                        "ownerReferences":[{"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
                            "name":"sandbox-a","uid":controller_uid,"controller":true}]},
                    "status":{"phase":"Running","podIP":pod_ip}}),
            ),
        ];
        let paths = Arc::new(Mutex::new(Vec::new()));
        let recorded = paths.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let recorded = recorded.clone();
            let objects = objects.clone();
            async move {
                let path = request.uri().path().to_owned();
                recorded.lock().unwrap().push(path.clone());
                let (status, body) = objects.iter().find(|(known, _)| *known == path).map_or(
                    (StatusCode::NOT_FOUND, json!({"kind":"Status","code":404})),
                    |(_, object)| (StatusCode::OK, object.clone()),
                );
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        (
            SandboxClient::new(kube::Client::new(service, "default"), NAMESPACE),
            paths,
        )
    }

    #[tokio::test]
    async fn ssh_reaches_the_bound_workspace_pod_over_the_pod_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, paths) = workspace_chain("127.0.0.1", SANDBOX_UID);
        let accepted = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = client
            .workspace_ssh_stream(ENVIRONMENT, port)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // A direct Pod-network connection, never a kube port-forward, and
        // never a gateway lookup: only the Claim → Sandbox → Pod chain.
        assert!(stream.into_parts().1.is_none());
        let paths = paths.lock().unwrap().clone();
        assert_eq!(paths.len(), 3, "{paths:?}");
        assert!(paths[2].ends_with("/pods/workspace-a"));
        assert!(paths.iter().all(|path| !path.contains("gateway")));
    }

    /// A store holding one recorded key, or none.
    struct Recorded(Option<String>);

    #[async_trait::async_trait]
    impl HostKeyStore for Recorded {
        async fn current_host_key(
            &self,
            _environment_id: &str,
        ) -> Result<Option<(i64, String)>, sqlx::Error> {
            Ok(self.0.clone().map(|key| (3, key)))
        }
    }

    struct Refusing;

    impl russh::server::Handler for Refusing {
        type Error = russh::Error;
    }

    fn host_key(seed: u8) -> russh::keys::PrivateKey {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    /// An SSH server on `listener` presenting `key`, for every connection.
    fn ssh_server(listener: tokio::net::TcpListener, key: russh::keys::PrivateKey) {
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, stream, Refusing).await {
                        let _ = session.await;
                    }
                });
            }
        });
    }

    fn openssh(key: &russh::keys::PrivateKey) -> String {
        key.public_key().to_openssh().unwrap()
    }

    #[tokio::test]
    async fn access_is_ready_once_the_pod_presents_the_recorded_host_key() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_secs(10),
                &Recorded(Some(openssh(&host_key(1)))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn access_is_not_ready_without_the_current_recorded_key() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        ssh_server(listener, host_key(1));
        let (client, _) = workspace_chain("127.0.0.1", SANDBOX_UID);
        // Another key, as a previous generation's, or none recorded yet.
        for (store, reason) in [
            (Recorded(Some(openssh(&host_key(2)))), "recorded host key"),
            (Recorded(None), "no host key is recorded"),
        ] {
            let error = client
                .wait_for_workspace_access_ready_on(
                    ENVIRONMENT,
                    port,
                    Duration::from_millis(1_500),
                    &store,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
        // A port that is not SSH never becomes ready.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        drop(silent);
        let error = client
            .wait_for_workspace_access_ready_on(
                ENVIRONMENT,
                port,
                Duration::from_millis(600),
                &Recorded(Some(openssh(&host_key(1)))),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
    }

    #[tokio::test]
    async fn a_pod_another_sandbox_controls_is_never_reached() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, _) = workspace_chain("127.0.0.1", "5a4db0c5-9dad-11d1-80b4-00c04fd430c8");
        assert!(
            client
                .workspace_ssh_stream(ENVIRONMENT, port)
                .await
                .is_err()
        );
        // Refused before any connection to the Pod.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        // The workspace SSH port is the daemon's, from the shared contract.
        assert_eq!(
            WORKSPACE_SSH_PORT,
            codewire_gateway_proto::WORKSPACE_DAEMON_SSH_PORT
        );
    }

    #[tokio::test]
    async fn sidecar_accepts_public_keys_and_rejects_host_certificates() {
        use russh::keys::ssh_key::{
            PrivateKey,
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        };

        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let public_key = key.public_key().clone().into();
        assert!(
            russh::client::Handler::check_server_key(&mut AcceptAllKeys, &public_key)
                .await
                .unwrap()
        );

        let mut builder = Builder::new(
            vec![0; 32],
            key.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("sidecar.test").unwrap();
        let certificate = builder.sign(&key).unwrap().into();
        assert!(
            !russh::client::Handler::check_server_key(&mut AcceptAllKeys, &certificate)
                .await
                .unwrap()
        );
    }

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
