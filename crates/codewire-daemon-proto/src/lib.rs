use std::fmt;

use tonic::metadata::{Ascii, MetadataValue};

pub const DAEMON_AUTH_TOKEN_HEADER: &str = "x-codewire-daemon-token";
/// Fixed-purpose hosted exec could not certify a clean terminal child status.
/// Lifecycle callers must recover the exact Pod on this status, conservatively
/// including a real child that exits with the same code.
pub const HOSTED_EXEC_AMBIGUOUS_EXIT_CODE: i32 = 125;
/// Exact projected-token purpose for a workspace authenticating credential
/// access through the credential relay, not the Kubernetes API.
pub const CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE: &str = "codewire.internal.credential-workspace.v1";
/// Exact projected-token purpose for orchestration relaying a bound
/// workspace daemon's credential bridge to the isolated credential broker.
/// The broker pins it to [`CREDENTIAL_RELAY_SERVICE_ACCOUNT`] in its own
/// (server) namespace; it authorizes no other exchange.
pub const CREDENTIAL_RELAY_TOKEN_AUDIENCE: &str = "codewire.internal.credential-relay.v1";
/// The only service account that may present a credential-relay token.
pub const CREDENTIAL_RELAY_SERVICE_ACCOUNT: &str = "codewire-orchestration";
pub const CREDENTIAL_RELAY_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/credential-relay";
pub const CREDENTIAL_RELAY_TOKEN_PATH: &str = "/var/run/secrets/codewire/credential-relay/token";
pub const CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// The public UDP relay's data-plane port, the one relay port a workspace may
/// reach.
pub const UDP_RELAY_DATA_PORT: u16 = 41641;
/// The DERP servers' STUN port, the one DERP port a workspace may reach
/// directly; DERP itself is reached through the public edge.
pub const DERP_STUN_PORT: u16 = 3478;
/// The service account every workspace Pod runs as. A workspace-binding token
/// is accepted only for it.
pub const SANDBOX_SERVICE_ACCOUNT: &str = "codewire-sandbox";
/// Orchestration's internal Connect listener behind TLS, which Mesh calls.
pub const ORCHESTRATION_INTERNAL_TLS_PORT: u16 = 8088;
/// Exact projected-token purpose for an identity-free workspace Pod fetching
/// its own binding from the dedicated workspace-binding listener. It is
/// distinct from the credential audiences, so a token
/// projected for this purpose cannot be replayed against any other exchange.
pub const WORKSPACE_BINDING_TOKEN_AUDIENCE: &str = "codewire.internal.workspace-binding.v1";
pub const WORKSPACE_BINDING_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/workspace-binding";
pub const WORKSPACE_BINDING_TOKEN_PATH: &str = "/var/run/secrets/codewire/workspace-binding/token";
pub const WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// Dedicated orchestration listener that serves only `WorkspaceBindingService`.
pub const WORKSPACE_BINDING_PORT: u16 = 8087;
/// Exact projected-token purpose for a broker-mode workspace Pod opening its
/// egress stream to the cw-egress on its node (#4000). cw-egress forwards it
/// to orchestration, which reviews it for [`SANDBOX_SERVICE_ACCOUNT`].
pub const EGRESS_TOKEN_AUDIENCE: &str = "codewire.internal.egress.v1";
pub const EGRESS_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/codewire/egress";
pub const EGRESS_TOKEN_PATH: &str = "/var/run/secrets/codewire/egress/token";
pub const EGRESS_TOKEN_EXPIRATION_SECONDS: i64 = 600;
/// cw-egress's stream address on the Pod's node, as `address:port`. A Pod
/// without it has no hosted egress, and its daemon opens no stream.
pub const EGRESS_STREAM_ADDR_ENV: &str = "CODEWIRE_EGRESS_STREAM_ADDR";
/// The cluster DNS Service's bare IPv4 address, the egress self-check's DNS
/// target (port 53). Missing or unparsable fails the check closed.
pub const CLUSTER_DNS_IP_ENV: &str = "CODEWIRE_CLUSTER_DNS_IP";
/// The binding Service's `address:port` for a hosted egress Pod, which
/// resolves no names. The binding URL keeps the TLS name.
pub const WORKSPACE_BINDING_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_BINDING_ADDR";
/// The public gateway's in-cluster `address:port` for a hosted egress Pod:
/// the tailnet coordinator's address when [`COORDINATOR_ADDR_ENV`] is unset,
/// as the coordinator URL falls back to the API URL.
pub const API_ADDR_ENV: &str = "CODEWIRE_API_ADDR";
/// The tailnet coordinator's in-cluster `address:port`, when it is not the
/// API's. Its URL, from the access grant, keeps the TLS name.
pub const COORDINATOR_ADDR_ENV: &str = "CODEWIRE_COORDINATOR_ADDR";
/// Mesh's in-cluster `address:port`, rendered only with a Mesh URL.
pub const MESH_ADDR_ENV: &str = "CODEWIRE_MESH_ADDR";
/// The deployment's own DERP relay as `hostname=address:port`: the DERP map
/// node with that hostname is dialled at that address, under that name.
pub const DERP_ADDR_ENV: &str = "CODEWIRE_DERP_ADDR";
/// Where a hosted egress daemon installs the egress trust before it serves:
/// the interception CA, or a comment-only file for none (#4001). The
/// broker-mode Pod template points `NODE_EXTRA_CA_CERTS` here.
pub const HOSTED_EGRESS_TRUST_CA_PATH: &str = "/codewire/run/egress-trust/ca.pem";
/// Exact projected-token purpose for cw-egress calling orchestration's
/// `EgressService`. Orchestration accepts it only for
/// [`EGRESS_NODE_SERVICE_ACCOUNT`] in its own (server) namespace, and reads
/// the caller's node from the caller's live Pod.
pub const EGRESS_NODE_TOKEN_AUDIENCE: &str = "codewire.internal.egress-node.v1";
/// The only service account that may present an egress-node token.
pub const EGRESS_NODE_SERVICE_ACCOUNT: &str = "codewire-egress";
/// cw-egress's stream port, on the Pod network, reached through its
/// node-local Service.
pub const EGRESS_STREAM_PORT: u16 = 8089;
/// Selects the hosted daemon's binding mode: the URL of the dedicated
/// workspace-binding listener. A binding-mode Pod carries no environment
/// identity; it comes only from the bind response.
pub const WORKSPACE_BINDING_URL_ENV: &str = "CODEWIRE_WORKSPACE_BINDING_URL";
/// The public roots the workspace daemon verifies the binding listener's TLS
/// identity with: orchestration's internal CA, the single key `ca.crt` of the
/// sandbox-namespace ConfigMap `codewire-orchestration-internal-roots`,
/// mounted read-only into the workspace container of every Pod whose binding
/// URL is rendered.
pub const WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH: &str =
    "/run/codewire-orchestration-internal-roots";
pub const WORKSPACE_BINDING_TLS_ROOTS_FILE: &str =
    "/run/codewire-orchestration-internal-roots/ca.crt";
/// The workspace Pod's own UID from the downward API. The daemon compares it
/// with the reviewed Pod UID in the bind response.
pub const WORKSPACE_POD_UID_ENV: &str = "CODEWIRE_POD_UID";
/// A confidential workspace's measured trust anchors (Program #2238 B2c).
/// Its workspace container carries them as env entries, which the measured
/// Kata policy pins exactly, so the init-data that Trustee authorizes commits
/// to them.
///
/// The binding listener's public roots: a PEM bundle. In a confidential
/// workspace the daemon trusts only these for 8087, never the mounted roots,
/// which the host supplies there.
pub const WORKSPACE_MEASURED_BINDING_ROOTS_ENV: &str = "CODEWIRE_MEASURED_BINDING_ROOTS";
/// The only environment a confidential workspace may bind as: the UUID its
/// init-data already measures as the storage key ID.
pub const WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV: &str = "CODEWIRE_MEASURED_ENVIRONMENT_ID";
/// The largest measured roots bundle the daemon accepts.
pub const WORKSPACE_MEASURED_BINDING_ROOTS_MAX_BYTES: usize = 64 * 1024;
/// Owner-only (0700) daemon state directory under the Pod's `/codewire/run`.
pub const HOSTED_DAEMON_STATE_DIRECTORY: &str = "/codewire/run/daemon";
/// The daemon's local Unix socket for `cw network connect` (#3350): a
/// process in the workspace asks for one TCP stream to another member of the
/// environment's Mesh network. It lives in the owner-only state directory.
pub const HOSTED_DAEMON_MESH_SOCKET: &str = "/codewire/run/daemon/mesh.sock";

/// The one request line on [`HOSTED_DAEMON_MESH_SOCKET`]:
/// `CWMESHCONNECT1 <node> <port>\n`. The daemon answers `OK\n` and then
/// carries the stream, or `ERR <reason>\n` and closes.
pub const MESH_CONNECT_PREFIX: &str = "CWMESHCONNECT1";

/// The longest request or answer line on [`HOSTED_DAEMON_MESH_SOCKET`].
pub const MESH_CONNECT_MAX_LINE: usize = 128;

/// A Mesh node name a connect request may name: 1 to 63 letters, digits,
/// `.`, `_` or `-`, starting with a letter or digit.
pub fn valid_mesh_node_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The request line for one stream to `port` on `node`.
pub fn mesh_connect_request(node: &str, port: u16) -> Option<String> {
    (valid_mesh_node_name(node) && port > 0)
        .then(|| format!("{MESH_CONNECT_PREFIX} {node} {port}\n"))
}

/// The node and port of one request line, without its newline.
pub fn parse_mesh_connect_request(line: &str) -> Option<(&str, u16)> {
    let mut parts = line.split(' ');
    let (Some(MESH_CONNECT_PREFIX), Some(node), Some(port), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let port = port.parse::<u16>().ok().filter(|port| *port > 0)?;
    valid_mesh_node_name(node).then_some((node, port))
}

/// Local readiness marker: the daemon process is up and its binding loop
/// runs. It never depends on binding, because orchestration binds a Pod only
/// after the Pod is Ready.
pub const HOSTED_DAEMON_READY_FILE: &str = "/codewire/run/daemon/ready";
/// Owner-read-only (0400) copy of a bound daemon's credential, read by the
/// fixed-purpose hosted exec instead of its inherited environment.
pub const HOSTED_DAEMON_CREDENTIAL_FILE: &str = "/codewire/run/daemon/credential";
/// Workspace access is ready: the daemon is bound, its SSH server listens on
/// [`WORKSPACE_SSH_PORT`] and its host key is recorded. Tailnet comes up
/// after, asynchronously, and is not part of this marker.
pub const HOSTED_DAEMON_ACCESS_READY_FILE: &str = "/codewire/run/daemon/access-ready";
/// The bound daemon's SSH listener in the workspace Pod. Only orchestration
/// (its SSH proxy and setup health check) may reach it.
pub const WORKSPACE_SSH_PORT: u16 = 2222;
/// The environment desktop's VNC listener on the workload's loopback
/// (`docs/dev/SANDBOX-DESKTOP.md`). It asks for no password, so the only ways
/// to it are the two that admit a viewer: an SSH local forward and
/// orchestration's desktop stream, both through `ForwardTcp`. It is therefore
/// not one of the [`PLATFORM_WORKLOAD_LISTENERS`], which forwarding refuses.
/// Every path that publishes a guest port, or serves a published one, refuses
/// this port instead, whether or not a desktop runs.
pub const DESKTOP_VNC_PORT: u16 = 5901;
/// What a refusal to publish or serve [`DESKTOP_VNC_PORT`] says. It names the
/// path that works today; `cw desktop` replaces it here when that command
/// ships.
pub const DESKTOP_VNC_PORT_REFUSAL: &str = "port 5901 is reserved for this environment's desktop and is never published; \
     reach it with an SSH local forward";
/// The port the image's Chromium listens on, on the workload's loopback, when
/// a launch turns its remote debugging on (`docs/dev/SANDBOX-DESKTOP.md`,
/// "The browser"). The debugging protocol has no authentication: whatever
/// reaches the port drives that browser and reads its sessions. Like
/// [`DESKTOP_VNC_PORT`] it is no platform listener, so an SSH forward
/// reaches it, and no path publishes or serves it.
pub const BROWSER_DEBUG_PORT: u16 = 9222;
/// What a refusal to publish or serve [`BROWSER_DEBUG_PORT`] says.
pub const BROWSER_DEBUG_PORT_REFUSAL: &str = "port 9222 is reserved for the browser's remote debugging, which has no authentication, \
     and is never published; reach it with an SSH local forward";
/// The guest ports that are never published and never served when published
/// earlier, ascending.
pub const UNPUBLISHED_WORKLOAD_PORTS: [u16; 2] = [DESKTOP_VNC_PORT, BROWSER_DEBUG_PORT];

/// What a refusal to publish or serve guest port `port` says, when it is one
/// of the [`UNPUBLISHED_WORKLOAD_PORTS`]; `None` for every other port.
pub fn unpublished_port_refusal(port: u16) -> Option<&'static str> {
    match port {
        DESKTOP_VNC_PORT => Some(DESKTOP_VNC_PORT_REFUSAL),
        BROWSER_DEBUG_PORT => Some(BROWSER_DEBUG_PORT_REFUSAL),
        _ => None,
    }
}

/// A session's Codewire server inside a hosted sandbox (#5100): the
/// deployment's public origin from its binding. It names no identity and
/// authenticates nothing; `cw` uses it only after every server configured
/// another way, and only through [`sandbox_server_origin`].
pub const SANDBOX_SERVER_URL_ENV: &str = "CODEWIRE_SANDBOX_SERVER_URL";

/// `value` without a trailing `/` when it is an absolute `https` origin: a
/// lowercase host name, optionally with a port, and no userinfo, path, query
/// or fragment. Anything else is refused, never corrected, since anything in
/// the sandbox can set the variable.
pub fn sandbox_server_origin(value: &str) -> Option<&str> {
    let origin = value.strip_suffix('/').unwrap_or(value);
    let authority = origin.strip_prefix("https://")?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && !host.starts_with(['.', '-']);
    let port_ok = port.is_none_or(|port| {
        port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    });
    (host_ok && port_ok).then_some(origin)
}

/// The health diagnostic in which a bound daemon reports the saved project
/// defaults and Git author it wrote for its binding (#3684). Healthy, its
/// message names the binding's generation; setup skips its own write only then.
pub const WORKSPACE_DEFAULTS_DIAGNOSTIC: &str = "workspace_defaults";

/// A healthy [`WORKSPACE_DEFAULTS_DIAGNOSTIC`]'s message for `generation`.
pub fn workspace_defaults_message(generation: u64) -> String {
    format!("written for generation {generation}")
}

/// The generation in a healthy [`WORKSPACE_DEFAULTS_DIAGNOSTIC`]'s message.
pub fn workspace_defaults_generation(message: &str) -> Option<i64> {
    message
        .strip_prefix("written for generation ")?
        .parse()
        .ok()
}
/// The bound daemon's tailnet direct-UDP port in the workspace Pod: the
/// target of the environment's direct-UDP LoadBalancer, reachable from the
/// world only.
pub const WORKSPACE_TAILNET_UDP_PORT: u16 = 31000;
/// Extra roots the bound daemon trusts for the public coordinator, beside
/// the WebPKI roots: a PEM bundle mounted read-only only by a local cluster
/// whose coordinator edge has a cluster-owned authority. Dev and Production
/// never mount it. A present but malformed bundle fails closed.
pub const COORDINATOR_EXTRA_ROOTS_MOUNT_PATH: &str = "/run/codewire-coordinator-extra-roots";
pub const COORDINATOR_EXTRA_ROOTS_FILE: &str = "/run/codewire-coordinator-extra-roots/ca.crt";
/// The only ConfigMap that may supply those extra roots, and only where
/// orchestration is configured to mount it (`SANDBOX_COORDINATOR_EXTRA_ROOTS`,
/// a local cluster). Dev and Production never mount it.
pub const COORDINATOR_EXTRA_ROOTS_CONFIGMAP: &str = "codewire-coordinator-extra-roots";
/// Server-side long-poll requested by an unbound daemon; the listener clamps
/// it to its own maximum.
pub const WORKSPACE_BINDING_WAIT_SECONDS: u32 = 20;
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_MINIMUM_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_CAPABILITY_EXEC: &str = "exec.v1";
pub const DAEMON_CAPABILITY_PTY: &str = "pty.v1";
pub const DAEMON_CAPABILITY_FILES: &str = "files.v1";
pub const DAEMON_CAPABILITY_HEALTH: &str = "health.v1";
pub const DAEMON_CAPABILITY_SESSIONS: &str = "sessions.v1";
pub const DAEMON_CAPABILITY_ATTACH: &str = "attach.v1";
pub const DAEMON_CAPABILITY_SESSION_INPUT: &str = "session_input.v1";
pub const DAEMON_CAPABILITY_SESSION_METADATA: &str = "session_metadata.v1";
/// A launch may set `end_after_detached_seconds`: the session ends once no
/// client has been attached for that long. An older daemon would ignore the
/// field and keep the session forever, so a launch that sets it requires this.
pub const DAEMON_CAPABILITY_SESSION_END_AFTER_DETACHED: &str = "session_end_after_detached.v1";
/// The longest `end_after_detached_seconds` a launch may set: 7 days. A
/// session meant to outlive that is a durable session, launched without it.
pub const SESSION_END_AFTER_DETACHED_MAX_SECONDS: u32 = 7 * 24 * 60 * 60;
/// File operations act as the workload user: files they create belong to
/// that user and access is checked as theirs, also where the daemon itself
/// runs as root, as a local VM's guest daemon does (#3025).
pub const DAEMON_CAPABILITY_WORKLOAD_FILES: &str = "files.workload_user.v1";
/// `ForwardTcp` connects to a loopback address inside the workload's network
/// namespace as the workload user, for SSH port forwarding served outside it
/// (#3025).
pub const DAEMON_CAPABILITY_FORWARD_TCP: &str = "forward.workload_loopback.v1";
/// `StartDesktop`, `GetDesktop` and `StopDesktop`: the environment's
/// graphical desktop (`docs/dev/SANDBOX-DESKTOP.md`). The daemon has it
/// whatever image the environment runs; an image without a desktop is the
/// `unavailable` state, so a client can tell the two apart.
pub const DAEMON_CAPABILITY_DESKTOP_VNC: &str = "desktop.vnc.v1";
/// The durable session the desktop runs as. No other session may take the
/// name, and stopping this one stops the desktop.
pub const DESKTOP_SESSION_NAME: &str = "codewire-desktop";
/// The desktop's X display.
pub const DESKTOP_DISPLAY: &str = ":1";
pub const SESSION_INPUT_MAX_BYTES: usize = 64 * 1024;
pub const SESSION_INPUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const DAEMON_CAPABILITY_CREDENTIAL_BRIDGE: &str = "credential_bridge.v1";
// Version4 uses the current complete recipient-sealed projection bundle. Old
// single-ciphertext peers fail admission instead of discovering it at launch.
pub const CREDENTIAL_BRIDGE_PROTOCOL_VERSION: u32 = 4;
pub const CREDENTIAL_BRIDGE_LOOPBACK_PORT: u16 = 38_081;

/// The TCP listeners the platform itself runs inside a workload, by port.
pub type PlatformListeners = std::collections::BTreeMap<u16, &'static str>;

/// The platform's fixed TCP listeners inside every workload, each with the
/// constant its component binds: the credential bridge's loopback ingress
/// ([`CREDENTIAL_BRIDGE_LOOPBACK_PORT`]) and the daemon's SSH server
/// ([`WORKSPACE_SSH_PORT`]). Docker in a workload listens on a Unix socket
/// only. Workload access never reaches these ports: SSH port forwarding
/// refuses them, and the tailnet never serves them as application ports. The
/// credential bridge answers provider requests with the creator's
/// credentials injected, so a forward to it would carry that authority off
/// the workload, for example to the localhost of a machine running VS Code,
/// which forwards every listening port it sees (#3068).
pub const PLATFORM_WORKLOAD_LISTENERS: [(u16, &str); 2] = [
    (CREDENTIAL_BRIDGE_LOOPBACK_PORT, "the credential bridge"),
    (WORKSPACE_SSH_PORT, "the workspace SSH server"),
];

/// The platform's TCP listeners in a workload whose daemon serves its gRPC
/// API on `daemon_port`, a per-placement setting: the fixed ones in
/// [`PLATFORM_WORKLOAD_LISTENERS`] plus the daemon itself.
pub fn platform_listeners(daemon_port: Option<u16>) -> PlatformListeners {
    PLATFORM_WORKLOAD_LISTENERS
        .into_iter()
        .chain(daemon_port.map(|port| (port, "the workspace daemon")))
        .collect()
}
/// The whole body a request carries in one `CredentialBridgeRequest`. A
/// streamed request body (see [`CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM`])
/// has no size limit; it is bounded by time and by credit instead.
pub const CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// The cumulative response body a guest accepts for a request whose body was
/// not streamed. A streamed request's response has no size limit.
pub const CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
/// The request body frames a host lets a guest send ahead of its consumer:
/// with [`CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES`] per frame, at most 1 MiB.
pub const CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES: u32 = 16;
/// While a streamed request's body, or its response body, flows, either side
/// fails the request after this long with no bytes.
pub const CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);
/// After a streamed request's body is complete, how long the host waits for the
/// first response byte. GitHub can be silent while it indexes a large pack.
pub const CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);
pub const CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES: usize = 64 * 1024;
/// The upgraded-stream bytes either side of a front-door session lets its
/// peer send ahead of what it has written out (#3999): one stalled WebSocket
/// holds at most this much, and never the session's other requests.
pub const CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES: u32 = 256 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_HEADERS: usize = 64;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES: usize = 128;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_HEADER_BYTES: usize = 64 * 1024;
pub const CREDENTIAL_BRIDGE_MAX_IN_FLIGHT: usize = 16;
/// Response header on the broker's admitted `CredentialBridge` stream: one
/// value per optional operation this broker serves. The relay copies the
/// known values into the daemon's `CredentialBridgeOpen.capabilities`.
pub const CREDENTIAL_BRIDGE_CAPABILITIES_HEADER: &str = "x-codewire-credential-bridge-capabilities";
/// Response header on the broker's admitted `CredentialBridge` stream: the
/// epoch's verified identity expiry, in decimal Unix seconds. The broker ends
/// the epoch then. The relay uses it only to schedule and check the next
/// epoch's admission before this one ends.
pub const CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER: &str = "x-codewire-credential-bridge-expires-at";
/// Response header on the broker's admitted `CredentialBridge` stream: the
/// epoch's front-door handle (#4001), 32 random bytes as binary metadata. A
/// `FrontDoorBridge` stream presents it, with the same relay and workspace
/// authorization, to join that epoch. It grants nothing alone, lives only as
/// long as its epoch, and the relay never passes it to the daemon or guest.
pub const CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER: &str = "x-codewire-credential-bridge-epoch-bin";
/// Request header on the relay's `CredentialBridge` stream: whether the
/// epoch's Pod is intercepted (#4001), exactly `true` or `false`, as its
/// first bind stored it. The credential service lets front-door sessions join
/// the epoch, and delivers only placeholder logins on it, exactly when it is
/// `true`, and refuses the epoch when it is repeated or anything else. A
/// missing value reads as `false` while the service's hosted placeholders are
/// off, so a relay older than this header keeps working through a rollout,
/// and refuses the epoch while they are on. Only the relay's own admission
/// path reads it.
pub const CREDENTIAL_BRIDGE_INTERCEPTED_HEADER: &str = "x-codewire-credential-bridge-intercepted";
/// Bytes in a front-door epoch handle.
pub const CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES: usize = 32;
/// The broker serves `CodexLoginRequest` on this epoch. A daemon sends that
/// frame only when its epoch's Open lists this value: an older broker or
/// relay ends the epoch on an unknown frame.
pub const CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN: &str = "codex-login";
/// The broker serves `ClaudeLoginRequest` on this epoch, under the same rule.
pub const CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN: &str = "claude-login";
/// The host accepts a GitHub Git request whose body streams in
/// `CredentialBridgeRequestBody` frames under `CredentialBridgeRequestCredit`,
/// with no request or response size limit. Without it a guest sends the whole
/// body in one request, at most [`CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES`], and
/// accepts at most [`CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES`] back.
pub const CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM: &str = "request-body-stream";
/// Every optional operation a current host may list. Unknown values are
/// ignored by the relay; an Open is bounded to this many entries.
pub const CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES: &[&str] = &[
    CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
    CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
    CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
];
/// The session is a front door's: a TLS front door outside the environment
/// speaking the guest side of the bridge, whose requests carry their
/// `intercepted_host`. Nothing lists this yet.
pub const CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR: &str = "front-door.v1";
/// The session carries WebSocket upgrades and their byte streams. Nothing
/// lists this yet.
pub const CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET: &str = "websocket.v1";
/// The host reports origins it learns from a provider's routing reply.
/// Nothing lists this yet.
pub const CREDENTIAL_BRIDGE_CAPABILITY_ROUTED_ORIGIN: &str = "routed-origin.v1";
/// Operations only a front-door session may list. Kept apart from
/// [`CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES`], so the daemon client, which
/// forwards only known names, never offers one to a session that belongs to
/// an environment.
pub const CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES: &[&str] = &[
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
    CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET,
    CREDENTIAL_BRIDGE_CAPABILITY_ROUTED_ORIGIN,
];
pub const CREDENTIAL_BRIDGE_MAX_CAPABILITIES: usize = 8;
pub const CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES: usize = 64;

/// A bounded, canonical capability name: lowercase ASCII letters, digits,
/// `-` and `.`. Shape only; a listed capability confers no authority.
pub fn valid_credential_bridge_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
}
pub const CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES: usize =
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + CREDENTIAL_BRIDGE_MAX_HEADER_BYTES + 128 * 1024;
pub const DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_EXEC,
    DAEMON_CAPABILITY_PTY,
    DAEMON_CAPABILITY_FILES,
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSION_INPUT,
    DAEMON_CAPABILITY_SESSION_METADATA,
    DAEMON_CAPABILITY_SESSION_END_AFTER_DETACHED,
    DAEMON_CAPABILITY_WORKLOAD_FILES,
    DAEMON_CAPABILITY_FORWARD_TCP,
    DAEMON_CAPABILITY_DESKTOP_VNC,
];

pub const HOST_DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSION_INPUT,
    DAEMON_CAPABILITY_SESSION_METADATA,
    DAEMON_CAPABILITY_SESSION_END_AFTER_DETACHED,
];

/// Empty means unnamed. Named sessions use a bounded, shell-safe label.
pub fn valid_session_name(name: &str) -> bool {
    name.is_empty()
        || (name.len() <= 64
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

/// Material-free framing checks for the closed selected-key SSH transport.
pub mod ssh;

/// Canonical names-only framing for fixed-role native projection composition.
pub mod projection;

mod desktop;
mod login_debug;

/// Validated credential for the private environment-daemon RPC boundary.
///
/// The token is deliberately not optional: every daemon transport, including
/// the private hosted TCP/ClusterIP adapter, must authenticate each RPC. Its
/// `Debug` representation never exposes credential bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct DaemonAuthToken(String);

impl DaemonAuthToken {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidDaemonAuthToken> {
        let value = value.into();
        if value.is_empty() || !value.is_ascii() || value.trim() != value {
            return Err(InvalidDaemonAuthToken);
        }
        MetadataValue::<Ascii>::try_from(value.as_str()).map_err(|_| InvalidDaemonAuthToken)?;
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DaemonAuthToken {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}

impl fmt::Debug for DaemonAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DaemonAuthToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDaemonAuthToken;

impl fmt::Display for InvalidDaemonAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("daemon auth token must be nonblank canonical ASCII metadata")
    }
}

impl std::error::Error for InvalidDaemonAuthToken {}

/// Neutral material-free credential bridge frames shared by native and
/// platform transports. The package deliberately carries no service authority.
pub mod codewire {
    pub mod bridge {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/codewire.bridge.v1.rs"));

            impl credential_bridge_guest_message::Payload {
                /// A front-door session's frame: an upgrade or one of its
                /// byte stream's frames. Nothing sends one yet, and every
                /// current reader treats one as an unknown frame, which is
                /// what an older peer decodes it as.
                pub fn is_front_door(&self) -> bool {
                    matches!(
                        self,
                        Self::Upgrade(_)
                            | Self::StreamData(_)
                            | Self::StreamCredit(_)
                            | Self::StreamClose(_)
                    )
                }
            }

            impl credential_bridge_host_message::Payload {
                /// A front-door session's frame: an accepted upgrade, one of
                /// its byte stream's frames, or an interception hint. Nothing
                /// sends one yet, and every current reader treats one as an
                /// unknown frame, which is what an older peer decodes it as.
                pub fn is_front_door(&self) -> bool {
                    matches!(
                        self,
                        Self::UpgradeAccepted(_)
                            | Self::StreamData(_)
                            | Self::StreamCredit(_)
                            | Self::StreamClose(_)
                            | Self::InterceptionHint(_)
                    )
                }
            }
        }
    }
}

pub mod daemon {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/daemon.v1.rs"));
    }
}

/// Private relay-initiated credential-broker transport. This service imports
/// the neutral material-free bridge frames but no daemon service authority.
pub mod broker {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/broker.v1.rs"));
    }
}

#[cfg(test)]
mod tests {
    /// Each unpublished port has a refusal that names it and the way in, its
    /// neighbours have none, and forwarding still reaches both: neither is a
    /// platform listener.
    #[test]
    fn the_unpublished_ports_are_refused_by_name_and_stay_reachable_by_a_forward() {
        for port in super::UNPUBLISHED_WORKLOAD_PORTS {
            let refusal = super::unpublished_port_refusal(port).expect("refused");
            assert!(refusal.contains(&port.to_string()), "{refusal}");
            assert!(refusal.contains("SSH local forward"), "{refusal}");
            assert!(super::unpublished_port_refusal(port - 1).is_none());
            assert!(super::unpublished_port_refusal(port + 1).is_none());
            assert!(!super::platform_listeners(Some(7777)).contains_key(&port));
        }
        assert_eq!(
            super::UNPUBLISHED_WORKLOAD_PORTS,
            [super::DESKTOP_VNC_PORT, super::BROWSER_DEBUG_PORT]
        );
    }

    use super::*;

    #[test]
    fn a_sandbox_server_is_an_https_origin_and_nothing_else() {
        for (value, origin) in [
            ("https://codewire.sh", "https://codewire.sh"),
            ("https://codewire.sh/", "https://codewire.sh"),
            (
                "https://codewire-dev.sh:8443",
                "https://codewire-dev.sh:8443",
            ),
        ] {
            assert_eq!(sandbox_server_origin(value), Some(origin), "{value}");
        }
        for value in [
            "",
            "codewire.sh",
            "http://codewire.sh",
            "https://",
            "https://user@codewire.sh",
            "https://user:secret@codewire.sh",
            "https://codewire.sh/api",
            "https://codewire.sh//",
            "https://codewire.sh?next=1",
            "https://codewire.sh#top",
            "https://Codewire.sh",
            "https://codewire.sh:0",
            "https://codewire.sh:+443",
            "https://codewire.sh:65536",
            "https://.codewire.sh",
            " https://codewire.sh",
            "https://codewire.sh\n",
        ] {
            assert_eq!(sandbox_server_origin(value), None, "{value:?}");
        }
    }

    #[test]
    fn mesh_connect_requests_name_one_valid_node_and_port() {
        let request = mesh_connect_request("app-2", 8080).unwrap();
        assert_eq!(request, "CWMESHCONNECT1 app-2 8080\n");
        assert_eq!(
            parse_mesh_connect_request(request.trim_end()),
            Some(("app-2", 8080))
        );
        assert!(request.len() <= MESH_CONNECT_MAX_LINE);
        assert!(
            mesh_connect_request(&"n".repeat(63), 65535).unwrap().len() <= MESH_CONNECT_MAX_LINE
        );
        for (node, port) in [("", 1), ("-app", 1), ("a b", 1), ("app", 0)] {
            assert!(mesh_connect_request(node, port).is_none(), "{node} {port}");
        }
        for line in [
            "",
            "CWMESHCONNECT1 app-2",
            "CWMESHCONNECT1 app-2 0",
            "CWMESHCONNECT1 app-2 65536",
            "CWMESHCONNECT1 app/2 80",
            "CWMESHCONNECT1 app-2 80 extra",
            "OTHER app-2 80",
        ] {
            assert!(parse_mesh_connect_request(line).is_none(), "{line}");
        }
    }
    use prost::Message;

    #[test]
    fn platform_listeners_name_the_bridge_ssh_and_daemon_ports() {
        let listeners = platform_listeners(Some(7777));
        assert_eq!(
            listeners.into_iter().collect::<Vec<_>>(),
            [
                (WORKSPACE_SSH_PORT, "the workspace SSH server"),
                (7777, "the workspace daemon"),
                (CREDENTIAL_BRIDGE_LOOPBACK_PORT, "the credential bridge"),
            ]
        );
        assert_eq!(
            platform_listeners(None).into_keys().collect::<Vec<_>>(),
            [WORKSPACE_SSH_PORT, CREDENTIAL_BRIDGE_LOOPBACK_PORT]
        );
    }

    #[test]
    fn projected_token_audiences_are_pairwise_distinct_and_mounts_do_not_overlap() {
        let audiences = [
            CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            CREDENTIAL_RELAY_TOKEN_AUDIENCE,
            WORKSPACE_BINDING_TOKEN_AUDIENCE,
            EGRESS_TOKEN_AUDIENCE,
            EGRESS_NODE_TOKEN_AUDIENCE,
        ];
        for (index, audience) in audiences.iter().enumerate() {
            assert!(audience.starts_with("codewire.internal.") && audience.ends_with(".v1"));
            for other in &audiences[index + 1..] {
                assert_ne!(audience, other);
            }
        }
        assert_eq!(
            WORKSPACE_BINDING_TOKEN_PATH,
            format!("{WORKSPACE_BINDING_TOKEN_MOUNT_PATH}/token")
        );
        assert_eq!(
            CREDENTIAL_RELAY_TOKEN_PATH,
            format!("{CREDENTIAL_RELAY_TOKEN_MOUNT_PATH}/token")
        );
        assert_ne!(CREDENTIAL_RELAY_SERVICE_ACCOUNT, SANDBOX_SERVICE_ACCOUNT);
        assert_eq!(
            EGRESS_TOKEN_PATH,
            format!("{EGRESS_TOKEN_MOUNT_PATH}/token")
        );
        for account in [CREDENTIAL_RELAY_SERVICE_ACCOUNT, SANDBOX_SERVICE_ACCOUNT] {
            assert_ne!(EGRESS_NODE_SERVICE_ACCOUNT, account);
        }
        assert_eq!(
            CREDENTIAL_RELAY_TOKEN_EXPIRATION_SECONDS,
            WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS
        );
        assert_eq!(WORKSPACE_BINDING_PORT, 8087);
        assert_eq!(ORCHESTRATION_INTERNAL_TLS_PORT, 8088);
    }

    #[test]
    fn hosted_daemon_binding_state_lives_in_one_owner_directory() {
        assert_eq!(WORKSPACE_BINDING_URL_ENV, "CODEWIRE_WORKSPACE_BINDING_URL");
        assert_eq!(
            WORKSPACE_BINDING_TLS_ROOTS_FILE,
            format!("{WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH}/ca.crt")
        );
        assert_eq!(
            COORDINATOR_EXTRA_ROOTS_FILE,
            format!("{COORDINATOR_EXTRA_ROOTS_MOUNT_PATH}/ca.crt")
        );
        assert_eq!(WORKSPACE_POD_UID_ENV, "CODEWIRE_POD_UID");
        assert_eq!(EGRESS_STREAM_ADDR_ENV, "CODEWIRE_EGRESS_STREAM_ADDR");
        assert_eq!(CLUSTER_DNS_IP_ENV, "CODEWIRE_CLUSTER_DNS_IP");
        assert_eq!(
            WORKSPACE_BINDING_ADDR_ENV,
            "CODEWIRE_WORKSPACE_BINDING_ADDR"
        );
        assert_eq!(API_ADDR_ENV, "CODEWIRE_API_ADDR");
        assert_eq!(COORDINATOR_ADDR_ENV, "CODEWIRE_COORDINATOR_ADDR");
        assert_eq!(MESH_ADDR_ENV, "CODEWIRE_MESH_ADDR");
        assert_eq!(DERP_ADDR_ENV, "CODEWIRE_DERP_ADDR");
        assert_eq!(
            HOSTED_EGRESS_TRUST_CA_PATH,
            "/codewire/run/egress-trust/ca.pem"
        );
        assert_eq!(HOSTED_DAEMON_STATE_DIRECTORY, "/codewire/run/daemon");
        assert_eq!(
            HOSTED_DAEMON_MESH_SOCKET,
            format!("{HOSTED_DAEMON_STATE_DIRECTORY}/mesh.sock")
        );
        for file in [HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_CREDENTIAL_FILE] {
            let (directory, name) = file.rsplit_once('/').unwrap();
            assert_eq!(directory, HOSTED_DAEMON_STATE_DIRECTORY);
            assert!(!name.is_empty());
        }
        assert_ne!(HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_CREDENTIAL_FILE);
        // The measured anchors never reuse a name the binding mode refuses.
        assert_eq!(
            WORKSPACE_MEASURED_BINDING_ROOTS_ENV,
            "CODEWIRE_MEASURED_BINDING_ROOTS"
        );
        assert_eq!(
            WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV,
            "CODEWIRE_MEASURED_ENVIRONMENT_ID"
        );
        // The wait stays well inside the listener's 35s connection deadline.
        assert!((1..=20).contains(&WORKSPACE_BINDING_WAIT_SECONDS));
    }

    #[test]
    fn credential_bridge_capabilities_are_bounded_canonical_names() {
        for capability in [
            CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN,
            CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN,
            CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
        ] {
            assert!(valid_credential_bridge_capability(capability));
            assert!(CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.contains(&capability));
        }
        for known in CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES {
            assert!(valid_credential_bridge_capability(known));
        }
        assert!(CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITIES);
        // A full window of the largest chunks is the 1 MiB in-flight bound.
        assert_eq!(
            CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES as usize
                * CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES,
            1024 * 1024
        );
        let too_long = "a".repeat(CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES + 1);
        for invalid in [
            "",
            "Codex-Login",
            "codex login",
            "codex_login",
            "cödex",
            &too_long,
        ] {
            assert!(!valid_credential_bridge_capability(invalid), "{invalid:?}");
        }
        assert_eq!(
            CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
            CREDENTIAL_BRIDGE_CAPABILITIES_HEADER.to_ascii_lowercase()
        );
    }

    #[test]
    fn front_door_capabilities_are_canonical_and_never_known_to_daemon_sessions() {
        for capability in [
            CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
            CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET,
            CREDENTIAL_BRIDGE_CAPABILITY_ROUTED_ORIGIN,
        ] {
            assert!(valid_credential_bridge_capability(capability));
            assert!(CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES.contains(&capability));
        }
        assert!(
            CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITIES
        );
        for front_door in CREDENTIAL_BRIDGE_FRONT_DOOR_CAPABILITIES {
            assert!(valid_credential_bridge_capability(front_door));
            assert!(
                !CREDENTIAL_BRIDGE_KNOWN_CAPABILITIES.contains(front_door),
                "{front_door} must not reach a daemon session"
            );
        }
    }

    fn front_door_guest_payloads()
    -> Vec<codewire::bridge::v1::credential_bridge_guest_message::Payload> {
        use bridge_v1::credential_bridge_guest_message::Payload;
        use codewire::bridge::v1 as bridge_v1;
        vec![
            Payload::Upgrade(bridge_v1::CredentialBridgeUpgrade {
                request_id: "r".to_owned(),
                method: "GET".to_owned(),
                path: "/v1/responses".to_owned(),
                query: "a=1".to_owned(),
                headers: vec![bridge_v1::CredentialHttpHeader {
                    name: "upgrade".to_owned(),
                    value: b"websocket".to_vec(),
                }],
                capability_slot: "codex".to_owned(),
                route: "openai-api".to_owned(),
                intercepted_host: "chatgpt.com".to_owned(),
                initial_credit_bytes: 65_536,
                intercept_decision: Vec::new(),
            }),
            Payload::StreamData(bridge_v1::CredentialBridgeStreamData {
                request_id: "r".to_owned(),
                data: vec![0x81, 0x00],
            }),
            Payload::StreamCredit(bridge_v1::CredentialBridgeStreamCredit {
                request_id: "r".to_owned(),
                credit_bytes: 4096,
            }),
            Payload::StreamClose(bridge_v1::CredentialBridgeStreamClose {
                request_id: "r".to_owned(),
                kind: bridge_v1::CredentialBridgeStreamCloseKind::Reset as i32,
            }),
        ]
    }

    fn front_door_host_payloads()
    -> Vec<codewire::bridge::v1::credential_bridge_host_message::Payload> {
        use bridge_v1::credential_bridge_host_message::Payload;
        use codewire::bridge::v1 as bridge_v1;
        vec![
            Payload::UpgradeAccepted(bridge_v1::CredentialBridgeUpgradeAccepted {
                request_id: "r".to_owned(),
                headers: vec![bridge_v1::CredentialHttpHeader {
                    name: "sec-websocket-accept".to_owned(),
                    value: b"synthetic".to_vec(),
                }],
            }),
            Payload::StreamData(bridge_v1::CredentialBridgeStreamData {
                request_id: "r".to_owned(),
                data: vec![0x81, 0x00],
            }),
            Payload::StreamCredit(bridge_v1::CredentialBridgeStreamCredit {
                request_id: "r".to_owned(),
                credit_bytes: 4096,
            }),
            Payload::StreamClose(bridge_v1::CredentialBridgeStreamClose {
                request_id: "r".to_owned(),
                kind: bridge_v1::CredentialBridgeStreamCloseKind::HalfClose as i32,
            }),
            Payload::InterceptionHint(bridge_v1::CredentialBridgeInterceptionHint {
                request_id: "r".to_owned(),
                origin: "https://chatgpt.com".to_owned(),
            }),
        ]
    }

    /// The bridge frames as they were before the front-door variants: what
    /// an older peer decodes with.
    mod previous {
        use super::codewire::bridge::v1 as bridge_v1;

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct GuestMessage {
            #[prost(oneof = "Guest", tags = "1, 2, 3, 4, 5, 6, 7")]
            pub payload: Option<Guest>,
        }

        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Guest {
            #[prost(message, tag = "1")]
            Ready(bridge_v1::CredentialBridgeReady),
            #[prost(message, tag = "2")]
            Request(Request),
            #[prost(message, tag = "3")]
            Cancel(bridge_v1::CredentialBridgeCancel),
            #[prost(message, tag = "4")]
            EnvironmentProjection(bridge_v1::EnvironmentProjectionRequest),
            #[prost(message, tag = "5")]
            Ssh(bridge_v1::CredentialSshRequest),
            #[prost(message, tag = "6")]
            CodexLogin(bridge_v1::CodexLoginRequest),
            #[prost(message, tag = "7")]
            ClaudeLogin(bridge_v1::ClaudeLoginRequest),
        }

        /// CredentialBridgeRequest without `intercepted_host`.
        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Request {
            #[prost(string, tag = "1")]
            pub request_id: String,
            #[prost(string, tag = "2")]
            pub method: String,
            #[prost(string, tag = "3")]
            pub path: String,
            #[prost(string, tag = "4")]
            pub query: String,
            #[prost(message, repeated, tag = "5")]
            pub headers: Vec<bridge_v1::CredentialHttpHeader>,
            #[prost(bytes = "vec", tag = "6")]
            pub body: Vec<u8>,
            #[prost(string, tag = "7")]
            pub capability_slot: String,
            #[prost(string, tag = "8")]
            pub route: String,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct HostMessage {
            #[prost(oneof = "Host", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9")]
            pub payload: Option<Host>,
        }

        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Host {
            #[prost(message, tag = "1")]
            Open(bridge_v1::CredentialBridgeOpen),
            #[prost(message, tag = "2")]
            ResponseStart(bridge_v1::CredentialBridgeResponseStart),
            #[prost(message, tag = "3")]
            ResponseBody(bridge_v1::CredentialBridgeResponseBody),
            #[prost(message, tag = "4")]
            ResponseEnd(bridge_v1::CredentialBridgeResponseEnd),
            #[prost(message, tag = "5")]
            ResponseFailure(bridge_v1::CredentialBridgeResponseFailure),
            #[prost(message, tag = "6")]
            EnvironmentProjection(bridge_v1::EnvironmentProjectionResponse),
            #[prost(message, tag = "7")]
            Ssh(bridge_v1::CredentialSshResponse),
            #[prost(message, tag = "8")]
            CodexLogin(bridge_v1::CodexLoginResponse),
            #[prost(message, tag = "9")]
            ClaudeLogin(bridge_v1::ClaudeLoginResponse),
        }
    }

    #[test]
    fn front_door_frames_round_trip_and_an_older_peer_decodes_them_as_unknown() {
        use codewire::bridge::v1 as bridge_v1;

        let guest = front_door_guest_payloads();
        let host = front_door_host_payloads();
        assert_eq!((guest.len(), host.len()), (4, 5));
        for payload in guest {
            assert!(payload.is_front_door());
            let frame = bridge_v1::CredentialBridgeGuestMessage {
                payload: Some(payload),
            };
            let bytes = frame.encode_to_vec();
            assert_eq!(
                bridge_v1::CredentialBridgeGuestMessage::decode(bytes.as_slice()).unwrap(),
                frame
            );
            // An older peer decodes the frame without error and finds no
            // payload: its unknown-frame path.
            let previous = previous::GuestMessage::decode(bytes.as_slice()).unwrap();
            assert_eq!(previous.payload, None);
        }
        for payload in host {
            assert!(payload.is_front_door());
            let frame = bridge_v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            };
            let bytes = frame.encode_to_vec();
            assert_eq!(
                bridge_v1::CredentialBridgeHostMessage::decode(bytes.as_slice()).unwrap(),
                frame
            );
            let previous = previous::HostMessage::decode(bytes.as_slice()).unwrap();
            assert_eq!(previous.payload, None);
        }
    }

    #[test]
    fn existing_frames_are_not_front_door_frames_and_keep_their_bytes() {
        use bridge_v1::credential_bridge_guest_message::Payload as Guest;
        use bridge_v1::credential_bridge_host_message::Payload as Host;
        use codewire::bridge::v1 as bridge_v1;

        for payload in [
            Guest::Ready(Default::default()),
            Guest::Request(Default::default()),
            Guest::Cancel(Default::default()),
            Guest::EnvironmentProjection(Default::default()),
            Guest::Ssh(Default::default()),
            Guest::CodexLogin(Default::default()),
            Guest::ClaudeLogin(Default::default()),
        ] {
            assert!(!payload.is_front_door(), "{payload:?}");
        }
        for payload in [
            Host::Open(Default::default()),
            Host::ResponseStart(Default::default()),
            Host::ResponseBody(Default::default()),
            Host::ResponseEnd(Default::default()),
            Host::ResponseFailure(Default::default()),
            Host::EnvironmentProjection(Default::default()),
            Host::Ssh(Default::default()),
            Host::CodexLogin(Default::default()),
            Host::ClaudeLogin(Default::default()),
        ] {
            assert!(!payload.is_front_door(), "{payload:?}");
        }

        // A request that leaves `intercepted_host` empty encodes exactly as
        // before, and an older peer reads one that sets it as the same
        // request without it.
        let request = bridge_v1::CredentialBridgeRequest {
            request_id: "r".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/responses".to_owned(),
            query: String::new(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
            capability_slot: "codex".to_owned(),
            route: "openai-api".to_owned(),
            intercepted_host: String::new(),
            destination_ip: String::new(),
            streamed_body: false,
            intercept_decision: Vec::new(),
        };
        let previous_request = previous::Request {
            request_id: request.request_id.clone(),
            method: request.method.clone(),
            path: request.path.clone(),
            query: String::new(),
            headers: Vec::new(),
            body: request.body.clone(),
            capability_slot: request.capability_slot.clone(),
            route: request.route.clone(),
        };
        assert_eq!(request.encode_to_vec(), previous_request.encode_to_vec());
        let intercepted = bridge_v1::CredentialBridgeGuestMessage {
            payload: Some(Guest::Request(bridge_v1::CredentialBridgeRequest {
                intercepted_host: "api.openai.com".to_owned(),
                // An older peer skips the admitted address too (#3999).
                destination_ip: "192.0.2.7".to_owned(),
                ..request
            })),
        };
        assert_eq!(
            previous::GuestMessage::decode(intercepted.encode_to_vec().as_slice())
                .unwrap()
                .payload,
            Some(previous::Guest::Request(previous_request))
        );
    }

    #[test]
    fn daemon_auth_token_is_mandatory_canonical_and_redacted() {
        for invalid in ["", " ", " token", "token ", "line\nbreak", "tökén"] {
            assert_eq!(
                DaemonAuthToken::new(invalid),
                Err(InvalidDaemonAuthToken),
                "accepted {invalid:?}"
            );
        }

        let marker = "daemon-auth-token-marker";
        let token = DaemonAuthToken::new(marker).expect("valid token");
        assert_eq!(token.expose_secret(), marker);
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
    }

    #[test]
    fn neutral_bridge_frames_preserve_pre_extraction_wire_bytes() {
        use codewire::bridge::v1 as bridge_v1;

        // Captured from the former daemon.v1 messages before their package-only
        // extraction. Protobuf package names do not participate in these bytes.
        let previous_open = [0x0a, 0x07, 0x08, 0x03, 0x12, 0x01, b'e', 0x18, 0x07];
        let open = bridge_v1::CredentialBridgeHostMessage {
            payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                bridge_v1::CredentialBridgeOpen {
                    protocol_version: 3,
                    environment_id: "e".to_owned(),
                    environment_generation: 7,
                    capabilities: Vec::new(),
                },
            )),
        };
        assert_eq!(open.encode_to_vec(), previous_open);
        assert_eq!(
            bridge_v1::CredentialBridgeHostMessage::decode(previous_open.as_slice()).unwrap(),
            open
        );

        let previous_ssh = [
            0x2a, 0x0d, 0x0a, 0x01, b'r', 0x10, 0x01, 0x22, 0x06, 0x0a, 0x01, 0x01, 0x12, 0x01,
            0x02,
        ];
        let ssh = bridge_v1::CredentialBridgeGuestMessage {
            payload: Some(bridge_v1::credential_bridge_guest_message::Payload::Ssh(
                bridge_v1::CredentialSshRequest {
                    request_id: "r".to_owned(),
                    deadline_unix_ms: 1,
                    operation: Some(bridge_v1::credential_ssh_request::Operation::Sign(
                        bridge_v1::CredentialSshSignRequest {
                            public_key_blob: vec![1],
                            data: vec![2],
                            flags: 0,
                        },
                    )),
                },
            )),
        };
        assert_eq!(ssh.encode_to_vec(), previous_ssh);
        assert_eq!(
            bridge_v1::CredentialBridgeGuestMessage::decode(previous_ssh.as_slice()).unwrap(),
            ssh
        );

        let previous_projection_failure = [0x32, 0x05, 0x0a, 0x01, b'r', 0x18, 0x01];
        let projection_failure = bridge_v1::CredentialBridgeHostMessage {
            payload: Some(
                bridge_v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                    bridge_v1::EnvironmentProjectionResponse {
                        request_id: "r".to_owned(),
                        result: Some(bridge_v1::environment_projection_response::Result::Failure(
                            bridge_v1::CredentialBridgeFailureReason::Denied as i32,
                        )),
                    },
                ),
            ),
        };
        assert_eq!(
            projection_failure.encode_to_vec(),
            previous_projection_failure
        );
        assert_eq!(
            bridge_v1::CredentialBridgeHostMessage::decode(previous_projection_failure.as_slice())
                .unwrap(),
            projection_failure
        );
    }
}

/// Closed private platform managed-agent framing; authority remains with the caller.
pub mod platform_managed;
