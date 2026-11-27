//! The Pod runtime's side of a hosted guest (#5602): what it reads from the
//! Pod for the hosted daemon, the platform peers its host end may reach, and
//! the two ports it publishes.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use codewire_vmm_guest_probe::hosted_control::{
    HOSTED_DAEMON_GUEST_PORT, HOSTED_DAEMON_INGRESS_VSOCK_PORT, HOSTED_ENVIRONMENT_NAMES,
    HOSTED_INGRESS_CONNECT, HOSTED_INGRESS_IDLE, HOSTED_INGRESS_MAX_JOINS,
    HOSTED_SSH_INGRESS_VSOCK_PORT, HostedMessage, HostedSettings, HostedTokens, join_until_idle,
};
use std::sync::Arc;

use tokio::net::TcpListener;

use super::hibernate::HibernateControl;
use super::suspend::{PausableVm, Suspender};
use super::*;
use crate::runner::RunningVm;

/// The daemon's ports on the Pod's address and the guest's ingress port each
/// is joined to. Exactly these two are published (cw-security's condition).
/// The guest joins each to one fixed address in the workspace namespace; the
/// runner's host-port forwarders, which go through the local daemon's
/// `ForwardTcp` and refuse the platform's own listeners, are not used.
pub(super) const PUBLISHED_PORTS: [(u16, u32); 2] = [
    (7_777, HOSTED_DAEMON_INGRESS_VSOCK_PORT),
    (2_222, HOSTED_SSH_INGRESS_VSOCK_PORT),
];
/// The daemon's listen address, which the Pod sets for a Kata guest.
const SHIM_ADDRESS_NAME: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";

/// How long a just-started guest may take to listen for its settings.
const HAND_OVER_TIMEOUT: Duration = Duration::from_secs(60);
const HAND_OVER_RETRY: Duration = Duration::from_millis(100);
const MAX_ROOT_FILE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 16 * 1024;

/// The roots and tokens, where a Kata Pod's daemon finds them; the template
/// mounts them at the same paths on this runtime's container.
#[derive(Debug, Clone)]
pub struct HostedPaths {
    pub binding_tls_roots: PathBuf,
    pub coordinator_extra_roots: PathBuf,
    pub binding_token: PathBuf,
    pub credential_token: PathBuf,
    /// The Pod's `cw-egress` token, read in broker mode only.
    pub egress_token: PathBuf,
}

impl Default for HostedPaths {
    fn default() -> Self {
        Self {
            binding_tls_roots: codewire_daemon_proto::WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH.into(),
            coordinator_extra_roots: codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_MOUNT_PATH
                .into(),
            binding_token: Path::new(codewire_daemon_proto::WORKSPACE_BINDING_TOKEN_MOUNT_PATH)
                .join("token"),
            credential_token: codewire_access::CODEX_PLATFORM_TOKEN_FILE.into(),
            egress_token: codewire_daemon_proto::EGRESS_TOKEN_PATH.into(),
        }
    }
}

/// The daemon's settings, read afresh from this Pod: the fixed variable
/// names only, and the roots ConfigMaps' files.
pub(super) fn read_settings(
    variable: impl Fn(&str) -> Option<String>,
    paths: &HostedPaths,
) -> Result<HostedSettings, PodRuntimeError> {
    let mut environment: BTreeMap<String, String> = HOSTED_ENVIRONMENT_NAMES
        .iter()
        .filter_map(|name| variable(name).map(|value| ((*name).to_owned(), value)))
        .collect();
    // The Pod's 7777 reaches the daemon at its own port in the guest.
    environment.insert(
        SHIM_ADDRESS_NAME.to_owned(),
        format!("127.0.0.1:{HOSTED_DAEMON_GUEST_PORT}"),
    );
    let settings = HostedSettings {
        environment,
        binding_tls_roots: read_roots(&paths.binding_tls_roots)?,
        coordinator_extra_roots: read_roots(&paths.coordinator_extra_roots)?,
    };
    settings
        .validate()
        .map_err(|_| PodRuntimeError::Setting("the hosted daemon's settings"))?;
    Ok(settings)
}

/// A ConfigMap volume's files. Its names are the keys; the kubelet's own
/// `..data` entries are skipped. An absent directory is an empty one: the
/// coordinator's extra roots are mounted only on local clusters.
fn read_roots(directory: &Path) -> Result<BTreeMap<String, String>, PodRuntimeError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.into()),
    };
    let mut files = BTreeMap::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(name) = name.to_str().filter(|name| !name.starts_with('.')) else {
            continue;
        };
        let bytes = read_bounded(&directory.join(name), MAX_ROOT_FILE_BYTES)
            .map_err(|_| PodRuntimeError::Setting("a trust roots file"))?;
        let text =
            String::from_utf8(bytes).map_err(|_| PodRuntimeError::Setting("a trust roots file"))?;
        files.insert(name.to_owned(), text);
    }
    Ok(files)
}

/// The tokens that cross ([`HostedTokens`]): the binding token, which the Pod
/// always has; the credential workspace token, when the credential runtime is
/// set up; and in broker mode alone, the Pod's `cw-egress` token, which that
/// mode needs. A guest-carried guest never gets the egress token, though the
/// Pod mounts it.
pub(super) fn read_tokens(
    paths: &HostedPaths,
    mode: EgressMode,
) -> Result<HostedTokens, PodRuntimeError> {
    let token = |path: &Path| -> Result<Option<String>, PodRuntimeError> {
        match read_bounded(path, MAX_TOKEN_BYTES) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(|text| Some(text.trim_end().to_owned()))
                .map_err(|_| PodRuntimeError::Setting("a projected token")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PodRuntimeError::Setting("a projected token")),
        }
    };
    let tokens = HostedTokens {
        binding: token(&paths.binding_token)?
            .ok_or(PodRuntimeError::Setting("the binding token"))?,
        credential: token(&paths.credential_token)?,
        egress: match mode {
            EgressMode::GuestCarried => None,
            EgressMode::Broker => Some(
                token(&paths.egress_token)?.ok_or(PodRuntimeError::Setting("the egress token"))?,
            ),
        },
    };
    tokens
        .validate()
        .map_err(|_| PodRuntimeError::Setting("a projected token"))?;
    Ok(tokens)
}

/// `CODEWIRE_POD_PLATFORM_PEERS`: comma-separated literal `IPv4:port` pairs.
/// The policy refuses names and the reserved classes; this also refuses any
/// address on one of the Pod's own interfaces.
pub(super) fn parse_platform_peers(value: &str) -> Result<Vec<SocketAddrV4>, PodRuntimeError> {
    let invalid = || PodRuntimeError::Setting("CODEWIRE_POD_PLATFORM_PEERS");
    let own = interface_addresses()?;
    value
        .split(',')
        .filter(|peer| !peer.is_empty())
        .map(|peer| {
            let address = codewire_egress_policy::platform_peer(peer).map_err(|_| invalid())?;
            if own.contains(address.ip()) {
                return Err(invalid());
            }
            Ok(address)
        })
        .collect()
}

/// `CODEWIRE_POD_UDP_PEERS`: optional comma-separated literal `IPv4:port`
/// tailnet UDP peers bridged on Pod `:31000` (#6637). Empty means the bridge
/// stays off and `:31000` is never bound. Non-empty strings fail closed on
/// empty tokens, special/invalid IPv4 addresses, port 0, own interface IPs,
/// or more than [`MAX_UDP_BRIDGE_PEERS`] unique entries.
pub(super) fn parse_udp_peers(value: &str) -> Result<Vec<SocketAddrV4>, PodRuntimeError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let own = interface_addresses()?;
    parse_udp_peers_with_own(value, &own)
}

pub(super) fn parse_udp_peers_with_own(
    value: &str,
    own: &[Ipv4Addr],
) -> Result<Vec<SocketAddrV4>, PodRuntimeError> {
    use codewire_daemon_proto::POD_RUNTIME_UDP_PEERS_ENV;
    use codewire_egress_worker::session::MAX_UDP_BRIDGE_PEERS;

    let invalid = || PodRuntimeError::Setting(POD_RUNTIME_UDP_PEERS_ENV);
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut parsed = Vec::new();
    for peer in value.split(',') {
        if peer.is_empty() {
            return Err(invalid());
        }
        let address = codewire_egress_policy::platform_peer(peer).map_err(|_| invalid())?;
        if own.contains(address.ip()) {
            return Err(invalid());
        }
        parsed.push(address);
    }
    parsed.sort();
    parsed.dedup();
    if parsed.len() > MAX_UDP_BRIDGE_PEERS {
        return Err(invalid());
    }
    Ok(parsed)
}

/// The IPv4 addresses on this network namespace's interfaces.
fn interface_addresses() -> io::Result<Vec<Ipv4Addr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list it owns into a live local pointer.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: each entry is part of the list getifaddrs returned, which
        // stays alive until freeifaddrs below.
        let current = unsafe { &*entry };
        // SAFETY: an AF_INET address is a sockaddr_in, per getifaddrs(3).
        if !current.ifa_addr.is_null()
            && i32::from(unsafe { (*current.ifa_addr).sa_family }) == libc::AF_INET
        {
            // SAFETY: as above, the family says this is a sockaddr_in.
            let inet = unsafe { &*current.ifa_addr.cast::<libc::sockaddr_in>() };
            addresses.push(Ipv4Addr::from(u32::from_be(inet.sin_addr.s_addr)));
        }
        entry = current.ifa_next;
    }
    // SAFETY: the list came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(list) };
    Ok(addresses)
}

/// Sends the settings and first tokens, so the guest can start its
/// workspace. The VM has only just started, so the first send retries until
/// the guest's control listener answers or [`HAND_OVER_TIMEOUT`] passes.
pub(super) async fn hand_over(
    running: &RunningVm,
    settings: HostedSettings,
    tokens: HostedTokens,
) -> Result<(), PodRuntimeError> {
    let settings = HostedMessage::Settings(settings);
    let deadline = tokio::time::Instant::now() + HAND_OVER_TIMEOUT;
    loop {
        match running.send_hosted(&settings).await {
            Ok(()) => break,
            Err(crate::runner::HostedSendError::Connect(_))
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(HAND_OVER_RETRY).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    running.send_hosted(&HostedMessage::Tokens(tokens)).await?;
    Ok(())
}

/// Guest-to-host control channels: vsock `7784` (suspend, hibernate,
/// `rebind-ok`) and guest log forwarding. Opened immediately on both cold and
/// restored boots without opening Pod TCP ports `7777`/`2222`.
pub(super) fn open_control_channels<V: PausableVm>(
    vsock_socket: &Path,
    suspender: Arc<Suspender<V>>,
    hibernate: Arc<HibernateControl>,
) -> Result<Vec<tokio::task::JoinHandle<()>>, PodRuntimeError> {
    Ok(vec![
        super::suspend::listen(vsock_socket, suspender, hibernate)?,
        super::guest_log::forward(vsock_socket)?,
    ])
}

/// The Pod's two published TCP ports (`7777` and `2222`), each waking a
/// suspended VM first. On a restored boot these are opened ONLY after the
/// restored daemon signals `rebind-ok\n` (`docs/dev/SANDBOX-SLEEP.md`, #6647).
pub(super) async fn open_published_ports<V: PausableVm>(
    vsock_socket: &Path,
    suspender: Arc<Suspender<V>>,
) -> Result<Vec<tokio::task::JoinHandle<()>>, PodRuntimeError> {
    let mut tasks = Vec::new();
    for (published, ingress) in PUBLISHED_PORTS {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, published)).await?;
        tasks.push(tokio::spawn(serve_published(
            listener,
            vsock_socket.to_owned(),
            ingress,
            Arc::clone(&suspender),
        )));
    }
    Ok(tasks)
}

/// Joins each connection on one of the Pod's published ports, byte for byte,
/// to the guest's ingress port for it over the VM's hybrid vsock socket: at
/// most [`HOSTED_INGRESS_MAX_JOINS`] at once, refused over that, each closed
/// after [`HOSTED_INGRESS_IDLE`] without a byte. A connection to a suspended
/// VM wakes it first and reaches the guest only once it runs again.
pub(super) async fn serve_published<V: PausableVm>(
    listener: TcpListener,
    socket: PathBuf,
    ingress: u32,
    suspender: Arc<Suspender<V>>,
) {
    let joins = Arc::new(tokio::sync::Semaphore::new(HOSTED_INGRESS_MAX_JOINS));
    loop {
        let Ok((inbound, _)) = listener.accept().await else {
            continue;
        };
        // Over the cap the connection is refused, never queued.
        let Ok(permit) = Arc::clone(&joins).try_acquire_owned() else {
            continue;
        };
        let socket = socket.clone();
        let suspender = Arc::clone(&suspender);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = suspender.wake().await {
                eprintln!("standard runtime: a connection could not wake the VM: {error}");
                return;
            }
            let Ok(Ok(guest)) = tokio::time::timeout(
                HOSTED_INGRESS_CONNECT,
                crate::hybrid_vsock::connect_hybrid_vsock(&socket, ingress),
            )
            .await
            else {
                return;
            };
            // Either side closing, or an idle join, ends it.
            let _ = join_until_idle(inbound, guest, HOSTED_INGRESS_IDLE).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_fixed_names_and_roots_cross_and_tokens_are_read_whole() {
        let directory = tempfile::tempdir().unwrap();
        let roots = directory.path().join("roots");
        fs::create_dir(&roots).unwrap();
        fs::write(roots.join("ca.crt"), b"-----BEGIN CERTIFICATE-----\n").unwrap();
        fs::create_dir(roots.join("..data")).unwrap();
        let token = directory.path().join("token");
        fs::write(&token, b"eyJh.eyJz.c2ln\n").unwrap();
        let paths = HostedPaths {
            binding_tls_roots: roots,
            coordinator_extra_roots: directory.path().join("absent"),
            binding_token: token,
            credential_token: directory.path().join("absent-token"),
            egress_token: directory.path().join("absent-egress-token"),
        };
        let settings = read_settings(
            |name| match name {
                "CODEWIRE_POD_UID" => Some("uid".to_owned()),
                _ => None,
            },
            &paths,
        )
        .unwrap();
        assert_eq!(settings.environment.len(), 2);
        assert_eq!(settings.environment[SHIM_ADDRESS_NAME], "127.0.0.1:17777");
        assert_eq!(settings.binding_tls_roots.len(), 1);
        assert!(settings.coordinator_extra_roots.is_empty());
        let tokens = read_tokens(&paths, EgressMode::GuestCarried).unwrap();
        assert_eq!(tokens.binding, "eyJh.eyJz.c2ln");
        assert_eq!(tokens.credential, None);
    }

    /// The egress token crosses in broker mode alone, whole and as the
    /// kubelet last wrote it, and a broker-mode Pod without it does not boot.
    #[test]
    fn only_a_broker_mode_guest_gets_the_egress_token_and_needs_it() {
        let directory = tempfile::tempdir().unwrap();
        let binding = directory.path().join("binding");
        fs::write(&binding, b"eyJh.eyJi.c2ln\n").unwrap();
        let egress = directory.path().join("egress");
        let paths = HostedPaths {
            binding_tls_roots: directory.path().join("absent"),
            coordinator_extra_roots: directory.path().join("absent"),
            binding_token: binding,
            credential_token: directory.path().join("absent-token"),
            egress_token: egress.clone(),
        };
        assert!(matches!(
            read_tokens(&paths, EgressMode::Broker),
            Err(PodRuntimeError::Setting("the egress token"))
        ));
        fs::write(&egress, b"eyJh.eyJl.c2ln\n").unwrap();
        assert_eq!(
            read_tokens(&paths, EgressMode::Broker)
                .unwrap()
                .egress
                .as_deref(),
            Some("eyJh.eyJl.c2ln")
        );
        assert_eq!(
            read_tokens(&paths, EgressMode::GuestCarried)
                .unwrap()
                .egress,
            None
        );
        // A rotation is seen as a change, so the refresh resends all three.
        let first = read_tokens(&paths, EgressMode::Broker).unwrap();
        fs::write(&egress, b"eyJh.eyJm.c2ln\n").unwrap();
        assert_ne!(read_tokens(&paths, EgressMode::Broker).unwrap(), first);
    }

    #[test]
    fn the_pod_publishes_exactly_its_two_ports_each_to_its_own_ingress() {
        assert_eq!(
            PUBLISHED_PORTS.map(|(published, _)| published),
            [7_777, codewire_daemon_proto::WORKSPACE_SSH_PORT]
        );
        assert_ne!(PUBLISHED_PORTS[0].1, PUBLISHED_PORTS[1].1);
    }

    #[test]
    fn a_peer_on_the_pods_own_address_is_refused() {
        assert!(parse_platform_peers("127.0.0.1:443").is_err());
        let own = interface_addresses().unwrap();
        if let Some(address) = own.iter().find(|address| !address.is_loopback()) {
            assert!(parse_platform_peers(&format!("{address}:443")).is_err());
        }
        assert!(parse_platform_peers("binding:443").is_err());
        assert_eq!(
            parse_platform_peers("192.0.2.10:443,192.0.2.11:8443")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_platform_peers("").unwrap().is_empty());
    }
}
