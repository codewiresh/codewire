//! Test-only Linux peer for the native VM ↔ named Dev Mesh acceptance path.
//!
//! This example is not installed as part of `cw`. Build it explicitly with:
//! `cargo build --locked -p codewire-cli-bin --example dev_mesh_probe`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the Codewire Dev Mesh probe is only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    match linux::probe().await {
        Ok(receipt) => println!("{}", receipt.to_json()),
        Err(_) => fail(),
    }
}

#[cfg(target_os = "linux")]
fn fail() -> ! {
    eprintln!("Codewire Dev Mesh probe failed");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::error::Error as StdError;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use codewire_cli::config::{self, PlatformConfig};
    use codewire_client::{
        ClientConfig, CodewireClient, CoordinatorHandlers, CredentialStore as _,
        FileCredentialStore, MeshCoordinateIdentity, MeshCoordinatorPeerSession, OAuthClient,
        RefreshingTokenProvider,
    };
    use codewire_tailnet::conn::{Conn, Options as ConnOptions, PeerTransport};
    use codewire_tailnet::derp_transport::{DerpTarget, DerpTransport, connect_derp_transport};
    use codewire_tailnet::direct_udp;
    use codewire_tailnet::disco::DiscoPrivate;
    use codewire_tailnet::node::{Node, NodePublic, prefix_from_uuid};
    use codewire_tailnet::wg::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
    use tokio::sync::{mpsc, watch};
    use uuid::Uuid;

    const SERVER_URL: &str = "https://codewire-dev.sh";
    const MESH_URL: &str = "https://mesh.codewire-dev.sh";
    const RECEIPT_VERSION: &str = "codewire-dev-mesh-probe:v1";
    const EXPECTED_PORT: u16 = 28_083;
    const NETWORK_DEADLINE: Duration = Duration::from_secs(45);
    const SETUP_DEADLINE: Duration = Duration::from_secs(15);
    const MAX_ID_BYTES: usize = 128;
    const MAX_DERP_NODES: usize = 64;
    const MAX_HOST_BYTES: usize = 253;
    const RESPONSE_PREFIX: &str = "codewire-native-mesh:";
    const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

    type Error = Box<dyn StdError + Send + Sync>;
    type Result<T> = std::result::Result<T, Error>;

    fn error() -> Error {
        std::io::Error::other("Codewire Dev Mesh probe failed").into()
    }

    fn require(condition: bool) -> Result<()> {
        if condition { Ok(()) } else { Err(error()) }
    }

    const REQUIRED_ENV: [&str; 9] = [
        "CW_CONFIG_DIR",
        "CODEWIRE_DEV_MESH_PROBE_ORG",
        "CODEWIRE_DEV_MESH_PROBE_USER",
        "CODEWIRE_DEV_MESH_PROBE_EMAIL",
        "CODEWIRE_DEV_MESH_PROBE_NETWORK",
        "CODEWIRE_DEV_MESH_PROBE_NODE",
        "CODEWIRE_DEV_MESH_PROBE_ENVIRONMENT",
        "CODEWIRE_DEV_MESH_PROBE_PORT",
        "CODEWIRE_DEV_MESH_PROBE_NONCE",
    ];

    const FORBIDDEN_OVERRIDES: [&str; 5] = [
        "CODEWIRE_API_KEY",
        "CODEWIRE_DEV_SMOKE_API_KEY",
        "CODEWIRE_SERVER_URL",
        "CODEWIRE_MESH_URL",
        "CODEWIRE_MESH_AUTH_TOKEN",
    ];

    #[derive(Debug)]
    struct Inputs {
        config_dir: PathBuf,
        organization_id: String,
        user_id: String,
        email: String,
        network_id: String,
        node_name: String,
        environment_id: Uuid,
        port: u16,
        nonce: String,
    }

    impl Inputs {
        fn from_process() -> Result<Self> {
            for name in FORBIDDEN_OVERRIDES {
                require(std::env::var_os(name).is_none())?;
            }
            let values = REQUIRED_ENV
                .into_iter()
                .map(|name| {
                    let value = std::env::var(name).map_err(|_| error())?;
                    Ok((name.to_string(), value))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Self::from_values(&values)
        }

        fn from_values(values: &BTreeMap<String, String>) -> Result<Self> {
            let get = |name: &str| values.get(name).cloned().ok_or_else(error);
            let config_dir = PathBuf::from(get("CW_CONFIG_DIR")?);
            let organization_id = validated_hex_id(get("CODEWIRE_DEV_MESH_PROBE_ORG")?)?;
            let user_id = validated_hex_id(get("CODEWIRE_DEV_MESH_PROBE_USER")?)?;
            let email = validated_email(get("CODEWIRE_DEV_MESH_PROBE_EMAIL")?)?;
            let network_id = validated_id(get("CODEWIRE_DEV_MESH_PROBE_NETWORK")?)?;
            let node_name = validated_id(get("CODEWIRE_DEV_MESH_PROBE_NODE")?)?;
            let environment_id = get("CODEWIRE_DEV_MESH_PROBE_ENVIRONMENT")?
                .parse::<Uuid>()
                .map_err(|_| error())?;
            require(!environment_id.is_nil())?;
            let port = get("CODEWIRE_DEV_MESH_PROBE_PORT")?
                .parse::<u16>()
                .map_err(|_| error())?;
            require(port == EXPECTED_PORT)?;
            let nonce = get("CODEWIRE_DEV_MESH_PROBE_NONCE")?;
            require(is_nonce(&nonce))?;
            Ok(Self {
                config_dir,
                organization_id,
                user_id,
                email,
                network_id,
                node_name,
                environment_id,
                port,
                nonce,
            })
        }
    }

    #[derive(Debug)]
    pub(super) struct Receipt {
        version: &'static str,
        server_url: &'static str,
        mesh_url: &'static str,
        organization_id: String,
        user_id: String,
        network_id: String,
        node_name: String,
        environment_id: Uuid,
        port: u16,
        nonce: String,
        transport: &'static str,
    }

    impl Receipt {
        pub(super) fn to_json(&self) -> String {
            format!(
                concat!(
                    r#"{{"version":"{}","server_url":"{}","mesh_url":"{}","#,
                    r#""organization_id":"{}","user_id":"{}","network_id":"{}","#,
                    r#""node_name":"{}","environment_id":"{}","port":{},"#,
                    r#""nonce":"{}","transport":"{}"}}"#
                ),
                self.version,
                self.server_url,
                self.mesh_url,
                self.organization_id,
                self.user_id,
                self.network_id,
                self.node_name,
                self.environment_id,
                self.port,
                self.nonce,
                self.transport,
            )
        }
    }

    #[derive(Clone, Debug)]
    struct DerpRegionSpec {
        region_id: i32,
        nodes: Vec<DerpNodeSpec>,
    }

    #[derive(Clone, Debug)]
    struct DerpNodeSpec {
        host: String,
        derp_port: Option<u16>,
        stun_only: bool,
        stun_port: Option<u16>,
        insecure: bool,
        can_port_80: bool,
        force_http: bool,
        scheme: Option<String>,
        transport: Option<String>,
    }

    #[derive(Debug)]
    struct DerpPlan {
        target: DerpTarget,
        preferred_region: i32,
        stun_servers: Vec<(String, u16)>,
    }

    struct DialPeer {
        conn: Arc<Conn>,
        peer: Option<Node>,
        coordinator_task: tokio::task::JoinHandle<()>,
        _direct_udp: direct_udp::Handle,
    }

    impl Drop for DialPeer {
        fn drop(&mut self) {
            self.coordinator_task.abort();
            self.conn.clear_node_callback();
            self.conn.close();
        }
    }

    pub(super) async fn probe() -> Result<Receipt> {
        let inputs = Inputs::from_process()?;
        validate_login_layout(&inputs.config_dir)?;
        let (client, platform) = authenticated_client(&inputs.config_dir)?;
        validate_login_config(&platform, &inputs)?;

        tokio::time::timeout(NETWORK_DEADLINE, run_network_probe(client, inputs))
            .await
            .map_err(|_| error())?
    }

    fn authenticated_client(config_dir: &Path) -> Result<(CodewireClient, PlatformConfig)> {
        let platform = config::load_platform_config(config_dir).map_err(|_| error())?;
        let store = FileCredentialStore::at(config_dir.join("credentials.json"));
        let credentials = store.load().map_err(|_| error())?.ok_or_else(error)?;
        require(exact_origin(credentials.issuer(), SERVER_URL))?;
        credentials.bearer_token().map_err(|_| error())?;
        let oauth = OAuthClient::for_server_url(SERVER_URL).map_err(|_| error())?;
        let provider = RefreshingTokenProvider::from_store(oauth, store).map_err(|_| error())?;
        let client_config = ClientConfig::new(SERVER_URL)?
            .with_mesh_url(MESH_URL)?
            .with_user_agent("codewire-dev-mesh-probe/v1")?;
        let client = CodewireClient::new(client_config, provider)?;
        Ok((client, platform))
    }

    fn validate_login_config(platform: &PlatformConfig, inputs: &Inputs) -> Result<()> {
        require(
            exact_origin(&platform.server_url, SERVER_URL)
                && platform.default_org == inputs.organization_id,
        )?;
        Ok(())
    }

    async fn run_network_probe(client: CodewireClient, inputs: Inputs) -> Result<Receipt> {
        let session = client.auth().get_session().await.map_err(|_| error())?;
        let user = session.user.ok_or_else(error)?;
        require(
            session.session.is_some() && user.id == inputs.user_id && user.email == inputs.email,
        )?;

        let identity =
            MeshCoordinateIdentity::dial(inputs.organization_id.clone(), inputs.network_id.clone());
        let mut coordinator = client
            .connect_mesh_coordinator_with_setup_timeout(identity, SETUP_DEADLINE)
            .await
            .map_err(|_| error())?;
        let map = coordinator.take_setup_derp_map().map_err(|_| error())?;
        let regions = map
            .get("Regions")
            .and_then(|value| value.as_object())
            .ok_or_else(error)?;
        let mut keys = regions.keys().collect::<Vec<_>>();
        keys.sort();
        let mut specs = Vec::new();
        let mut node_count = 0_usize;
        for key in keys {
            let region = regions.get(key).ok_or_else(error)?;
            let region_id = region
                .get("RegionID")
                .and_then(|value| value.as_i64())
                .and_then(|value| i32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(error)?;
            let nodes = region
                .get("Nodes")
                .and_then(|value| value.as_array())
                .ok_or_else(error)?;
            node_count = node_count
                .checked_add(nodes.len())
                .filter(|count| *count <= MAX_DERP_NODES)
                .ok_or_else(error)?;
            let mut node_specs = Vec::new();
            for node in nodes {
                let string_field = |name| {
                    node.get(name)
                        .map(|value| value.as_str().map(ToOwned::to_owned).ok_or_else(error))
                        .transpose()
                };
                let bool_field = |name| {
                    node.get(name)
                        .map(|value| value.as_bool().ok_or_else(error))
                        .transpose()
                        .map(|value| value.unwrap_or(false))
                };
                let port_field = |name| -> Result<Option<u16>> {
                    node.get(name)
                        .map(|value| {
                            let value = value.as_i64().ok_or_else(error)?;
                            if value <= 0 {
                                return Ok(None);
                            }
                            Ok(Some(u16::try_from(value).map_err(|_| error())?))
                        })
                        .transpose()
                        .map(|value| value.flatten())
                };
                node_specs.push(DerpNodeSpec {
                    host: string_field("HostName")?.ok_or_else(error)?,
                    derp_port: port_field("DERPPort")?,
                    stun_only: bool_field("STUNOnly")?,
                    stun_port: port_field("STUNPort")?,
                    insecure: bool_field("InsecureForTests")?,
                    can_port_80: bool_field("CanPort80")?,
                    force_http: bool_field("ForceHTTP")?,
                    scheme: string_field("Scheme")?,
                    transport: string_field("Transport")?,
                });
            }
            specs.push(DerpRegionSpec {
                region_id,
                nodes: node_specs,
            });
        }
        let plan = strict_derp_plan(&specs)?;
        let stun_servers = resolve_stun_servers(&plan.stun_servers).await?;
        let mut dial = connect_dial_peer(&inputs, coordinator, plan, stun_servers).await?;

        let mut stream = dial
            .conn
            .dial_context_tcp(SocketAddr::new(
                prefix_from_uuid(&inputs.environment_id).addr(),
                inputs.port,
            ))
            .await
            .map_err(|_| error())?;
        exchange(&mut stream, &inputs.nonce).await?;
        drop(stream);

        let peer = dial.peer.as_ref().ok_or_else(error)?;
        let transport = transport_name(dial.conn.probe_peer_path(peer)?.transport)?;
        dial.coordinator_task.abort();
        let _ = (&mut dial.coordinator_task).await;
        dial.conn.clear_node_callback();
        dial.conn.close();

        Ok(Receipt {
            version: RECEIPT_VERSION,
            server_url: SERVER_URL,
            mesh_url: MESH_URL,
            organization_id: inputs.organization_id,
            user_id: inputs.user_id,
            network_id: inputs.network_id,
            node_name: inputs.node_name,
            environment_id: inputs.environment_id,
            port: inputs.port,
            nonce: inputs.nonce,
            transport,
        })
    }

    async fn connect_dial_peer(
        inputs: &Inputs,
        mut coordinator: MeshCoordinatorPeerSession,
        plan: DerpPlan,
        stun_servers: Vec<SocketAddr>,
    ) -> Result<DialPeer> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let fallback = connect_derp_transport(&plan.target, &secret)
            .await
            .map_err(|_| error())?;
        let disco_private = DiscoPrivate::generate(&mut OsRng);
        let local_node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
        let (transport, direct_udp) = direct_udp::wrap_transport(
            fallback,
            direct_udp::Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                Vec::new(),
                local_node_key,
                disco_private.clone(),
            )
            .with_stun_servers(stun_servers),
        )
        .await
        .map_err(|_| error())?;

        let dial_id = Uuid::new_v4();
        let mut options = ConnOptions::new(dial_id);
        options.addresses = vec![prefix_from_uuid(&dial_id)];
        options.endpoints = direct_udp.advertised_endpoints();
        options.private_key = Some(secret);
        options.disco_private = Some(disco_private);
        let conn = Arc::new(Conn::new(options, transport)?);
        conn.set_preferred_derp(plan.preferred_region);

        coordinator
            .subscribe(inputs.node_name.clone())
            .await
            .map_err(|_| error())?;
        let (node_tx, node_rx) = mpsc::unbounded_channel();
        conn.set_node_callback(move |node| {
            let _ = node_tx.send(node.clone());
        });
        let (target_tx, target_rx) = watch::channel(None::<Node>);
        let target_address = prefix_from_uuid(&inputs.environment_id);
        let update_conn = Arc::clone(&conn);
        let coordinator_task = tokio::spawn(async move {
            let _ = coordinator
                .run_with_node_updates(
                    node_rx,
                    CoordinatorHandlers {
                        on_peers: move |nodes| {
                            if update_conn.update_peers(nodes).is_err() {
                                return;
                            }
                            // Mesh `Node.id` is coordinator-stable and is not the
                            // native environment UUID. The exact subscription
                            // scopes the name; the advertised ULA scopes the VM.
                            if let Some(peer) = nodes
                                .iter()
                                .find(|node| node.addresses.contains(&target_address))
                            {
                                let _ = target_tx.send(Some(peer.clone()));
                            }
                        },
                        on_derp_map: |_| {},
                    },
                )
                .await;
        });
        let mut dial = DialPeer {
            conn,
            peer: None,
            coordinator_task,
            _direct_udp: direct_udp,
        };
        let mut target_rx = target_rx;
        loop {
            if let Some(peer) = target_rx.borrow().clone() {
                dial.peer = Some(peer);
                return Ok(dial);
            }
            tokio::select! {
                changed = target_rx.changed() => {
                    require(changed.is_ok())?;
                }
                _ = &mut dial.coordinator_task => {
                    return Err(error());
                }
            }
        }
    }

    async fn exchange<S>(stream: &mut S, nonce: &str) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request = format!("{nonce}\n");
        stream.write_all(request.as_bytes()).await?;
        stream.shutdown().await?;

        let expected = format!("{RESPONSE_PREFIX}{nonce}\n");
        let mut response = vec![0_u8; expected.len()];
        stream.read_exact(&mut response).await?;
        require(response == expected.as_bytes())?;
        let mut trailing = [0_u8; 1];
        require(stream.read(&mut trailing).await? == 0)?;
        Ok(())
    }

    fn strict_derp_plan(regions: &[DerpRegionSpec]) -> Result<DerpPlan> {
        let mut relay = None;
        let mut stun_servers = Vec::new();
        let mut node_count = 0_usize;
        for region in regions {
            require(region.region_id > 0)?;
            node_count = node_count
                .checked_add(region.nodes.len())
                .filter(|count| *count <= MAX_DERP_NODES)
                .ok_or_else(error)?;
            for node in &region.nodes {
                let host = strict_host(&node.host)?;
                require(!node.insecure)?;
                if node.stun_only {
                    let port = node.stun_port.ok_or_else(error)?;
                    if !stun_servers.contains(&(host.clone(), port)) {
                        stun_servers.push((host, port));
                    }
                    continue;
                }
                require(verified_tls_node(node))?;
                if relay.is_none() {
                    relay = Some(DerpPlan {
                        target: DerpTarget {
                            host,
                            port: node.derp_port.unwrap_or(443),
                            transport: DerpTransport::Tls { skip_verify: false },
                        },
                        preferred_region: region.region_id,
                        stun_servers: Vec::new(),
                    });
                }
            }
        }
        let mut plan = relay.ok_or_else(error)?;
        plan.stun_servers = stun_servers;
        Ok(plan)
    }

    fn verified_tls_node(node: &DerpNodeSpec) -> bool {
        !node.insecure
            && !node.can_port_80
            && !node.force_http
            && node
                .scheme
                .as_deref()
                .is_none_or(|scheme| scheme.eq_ignore_ascii_case("https"))
            && node
                .transport
                .as_deref()
                .is_none_or(|transport| transport.eq_ignore_ascii_case("tls"))
    }

    fn strict_host(raw: &str) -> Result<String> {
        require(
            !raw.is_empty()
                && raw.len() <= MAX_HOST_BYTES
                && raw.is_ascii()
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')),
        )?;
        Ok(raw.to_string())
    }

    async fn resolve_stun_servers(servers: &[(String, u16)]) -> Result<Vec<SocketAddr>> {
        let mut resolved = Vec::new();
        for (host, port) in servers {
            let addresses = tokio::net::lookup_host((host.as_str(), *port))
                .await
                .map_err(|_| error())?;
            for address in addresses {
                if !resolved.contains(&address) {
                    resolved.push(address);
                }
            }
        }
        Ok(resolved)
    }

    fn validate_login_layout(config_dir: &Path) -> Result<()> {
        require(config_dir.is_absolute())?;
        let runtime = config_dir.parent().ok_or_else(error)?;
        require(
            config_dir.file_name().and_then(|name| name.to_str()) == Some("login")
                && valid_runtime_name(runtime),
        )?;
        validate_private_directory(runtime)?;
        let directory = fs::File::open(runtime)?;
        let mut statistics = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `directory` is a live descriptor and `statistics` points to
        // writable storage of the exact type required by `fstatfs`.
        let result = unsafe { libc::fstatfs(directory.as_raw_fd(), statistics.as_mut_ptr()) };
        require(result == 0)?;
        // SAFETY: successful `fstatfs` initialized the structure.
        let statistics = unsafe { statistics.assume_init() };
        require(statistics.f_type == TMPFS_MAGIC)?;
        validate_private_directory(config_dir)?;
        validate_private_file(&config_dir.join("config.json"))?;
        validate_private_file(&config_dir.join("credentials.json"))?;
        Ok(())
    }

    fn valid_runtime_name(runtime: &Path) -> bool {
        runtime
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(".cwlp-"))
            .is_some_and(|suffix| {
                suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
    }

    fn validate_private_directory(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        let canonical = fs::canonicalize(path)?;
        require(
            path.is_absolute()
                && canonical == path
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == effective_uid()
                && metadata.permissions().mode() & 0o077 == 0,
        )
    }

    fn validate_private_file(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        let canonical = fs::canonicalize(path)?;
        require(
            canonical == path
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == effective_uid()
                && metadata.permissions().mode() & 0o777 == 0o600,
        )
    }

    fn effective_uid() -> u32 {
        // SAFETY: `geteuid` reads process metadata and has no pointer arguments.
        unsafe { libc::geteuid() }
    }

    fn exact_origin(raw: &str, expected: &str) -> bool {
        raw.trim_end_matches('/') == expected
    }

    fn validated_hex_id(value: String) -> Result<String> {
        require(
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        )?;
        Ok(value)
    }

    fn validated_id(value: String) -> Result<String> {
        require(
            !value.is_empty()
                && value.len() <= MAX_ID_BYTES
                && value.is_ascii()
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                }),
        )?;
        Ok(value)
    }

    fn validated_email(value: String) -> Result<String> {
        require(
            !value.is_empty()
                && value.len() <= MAX_ID_BYTES
                && value.contains('@')
                && value.is_ascii()
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
                }),
        )?;
        Ok(value)
    }

    fn is_nonce(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn transport_name(transport: PeerTransport) -> Result<&'static str> {
        match transport {
            PeerTransport::DirectUdp => Ok("direct_udp"),
            PeerTransport::PeerRelay => Ok("peer_relay"),
            PeerTransport::DerpRelay => Ok("derp_relay"),
            PeerTransport::Unknown => Err(error()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn values() -> BTreeMap<String, String> {
            BTreeMap::from([
                (
                    "CW_CONFIG_DIR".into(),
                    "/run/user/1000/.cwlp-Ab12cd/login".into(),
                ),
                ("CODEWIRE_DEV_MESH_PROBE_ORG".into(), "a".repeat(32)),
                ("CODEWIRE_DEV_MESH_PROBE_USER".into(), "b".repeat(32)),
                (
                    "CODEWIRE_DEV_MESH_PROBE_EMAIL".into(),
                    "owner@example.test".into(),
                ),
                (
                    "CODEWIRE_DEV_MESH_PROBE_NETWORK".into(),
                    "network-alpha".into(),
                ),
                ("CODEWIRE_DEV_MESH_PROBE_NODE".into(), "node-alpha".into()),
                (
                    "CODEWIRE_DEV_MESH_PROBE_ENVIRONMENT".into(),
                    "12345678-1234-5678-9234-567812345678".into(),
                ),
                (
                    "CODEWIRE_DEV_MESH_PROBE_PORT".into(),
                    EXPECTED_PORT.to_string(),
                ),
                ("CODEWIRE_DEV_MESH_PROBE_NONCE".into(), "a".repeat(64)),
            ])
        }

        fn regions(insecure: bool, port: u16) -> Vec<DerpRegionSpec> {
            vec![DerpRegionSpec {
                region_id: 1,
                nodes: vec![
                    DerpNodeSpec {
                        host: "derp.codewire-dev.sh".into(),
                        derp_port: Some(port),
                        stun_only: false,
                        stun_port: None,
                        insecure,
                        can_port_80: false,
                        force_http: false,
                        scheme: None,
                        transport: None,
                    },
                    DerpNodeSpec {
                        host: "stun.codewire-dev.sh".into(),
                        derp_port: None,
                        stun_only: true,
                        stun_port: Some(3478),
                        insecure: false,
                        can_port_80: false,
                        force_http: false,
                        scheme: None,
                        transport: None,
                    },
                ],
            }]
        }

        #[test]
        fn inputs_require_exact_port_uuid_and_lowercase_nonce() {
            let accepted = Inputs::from_values(&values()).unwrap();
            assert_eq!(accepted.port, EXPECTED_PORT);

            let mut invalid = values();
            invalid.insert("CODEWIRE_DEV_MESH_PROBE_PORT".into(), "22".into());
            assert!(Inputs::from_values(&invalid).is_err());
            let mut invalid = values();
            invalid.insert("CODEWIRE_DEV_MESH_PROBE_NONCE".into(), "A".repeat(64));
            assert!(Inputs::from_values(&invalid).is_err());
            let mut invalid = values();
            invalid.insert(
                "CODEWIRE_DEV_MESH_PROBE_ENVIRONMENT".into(),
                Uuid::nil().to_string(),
            );
            assert!(Inputs::from_values(&invalid).is_err());
        }

        #[test]
        fn derp_plan_keeps_certificate_verification_on_nonstandard_ports() {
            let plan = strict_derp_plan(&regions(false, 8443)).unwrap();
            assert_eq!(plan.target.port, 8443);
            assert_eq!(plan.preferred_region, 1);
            assert_eq!(
                plan.stun_servers,
                vec![("stun.codewire-dev.sh".into(), 3478)]
            );
            assert!(matches!(
                plan.target.transport,
                DerpTransport::Tls { skip_verify: false }
            ));
        }

        #[test]
        fn derp_plan_rejects_insecure_and_plain_fixture_metadata() {
            assert!(strict_derp_plan(&regions(true, 443)).is_err());
            let mut plain = regions(false, 443);
            plain[0].nodes[0].transport = Some("http".into());
            assert!(strict_derp_plan(&plain).is_err());
            let mut port_80 = regions(false, 443);
            port_80[0].nodes[0].can_port_80 = true;
            assert!(strict_derp_plan(&port_80).is_err());
        }

        #[tokio::test]
        async fn exchange_half_closes_and_requires_exact_response_then_eof() {
            let nonce = "b".repeat(64);
            let (mut probe, mut guest) = tokio::io::duplex(256);
            let expected_nonce = nonce.clone();
            let guest_task = tokio::spawn(async move {
                let mut request = vec![0_u8; 65];
                guest.read_exact(&mut request).await.unwrap();
                assert_eq!(request, format!("{expected_nonce}\n").as_bytes());
                let mut eof = [0_u8; 1];
                assert_eq!(guest.read(&mut eof).await.unwrap(), 0);
                guest
                    .write_all(format!("{RESPONSE_PREFIX}{expected_nonce}\n").as_bytes())
                    .await
                    .unwrap();
                guest.shutdown().await.unwrap();
            });
            exchange(&mut probe, &nonce).await.unwrap();
            guest_task.await.unwrap();
        }

        #[tokio::test]
        async fn exchange_rejects_trailing_guest_output() {
            let nonce = "c".repeat(64);
            let (mut probe, mut guest) = tokio::io::duplex(256);
            let expected_nonce = nonce.clone();
            let guest_task = tokio::spawn(async move {
                let mut request = vec![0_u8; 65];
                guest.read_exact(&mut request).await.unwrap();
                guest
                    .write_all(format!("{RESPONSE_PREFIX}{expected_nonce}\nunrelated").as_bytes())
                    .await
                    .unwrap();
                guest.shutdown().await.unwrap();
            });
            assert!(exchange(&mut probe, &nonce).await.is_err());
            guest_task.await.unwrap();
        }

        #[test]
        fn runtime_shape_is_exact_and_receipt_contains_only_agreed_fields() {
            assert!(valid_runtime_name(Path::new("/run/user/1000/.cwlp-Ab12cd")));
            assert!(!valid_runtime_name(Path::new(
                "/run/user/1000/.cwlp-too-long"
            )));
            let receipt = Receipt {
                version: RECEIPT_VERSION,
                server_url: SERVER_URL,
                mesh_url: MESH_URL,
                organization_id: "a".repeat(32),
                user_id: "b".repeat(32),
                network_id: "network-alpha".into(),
                node_name: "node-alpha".into(),
                environment_id: "12345678-1234-5678-9234-567812345678".parse().unwrap(),
                port: EXPECTED_PORT,
                nonce: "d".repeat(64),
                transport: "derp_relay",
            };
            assert_eq!(
                receipt.to_json(),
                concat!(
                    r#"{"version":"codewire-dev-mesh-probe:v1","server_url":"https://codewire-dev.sh","#,
                    r#""mesh_url":"https://mesh.codewire-dev.sh","organization_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
                    r#""user_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","network_id":"network-alpha","#,
                    r#""node_name":"node-alpha","environment_id":"12345678-1234-5678-9234-567812345678","#,
                    r#""port":28083,"nonce":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","#,
                    r#""transport":"derp_relay"}"#
                )
            );
        }

        #[test]
        fn login_layout_requires_private_tmpfs_files() {
            let runtime = tempfile::Builder::new()
                .prefix(".cwlp-")
                .tempdir_in("/dev/shm")
                .unwrap();
            fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let login = runtime.path().join("login");
            fs::create_dir(&login).unwrap();
            fs::set_permissions(&login, fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["config.json", "credentials.json"] {
                let path = login.join(name);
                fs::write(&path, b"{}\n").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            validate_login_layout(&login).unwrap();

            fs::set_permissions(
                login.join("credentials.json"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(validate_login_layout(&login).is_err());
        }
    }
}
