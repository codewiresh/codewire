//! The hosted control channel between a `standard` Pod's runtime and its
//! guest (#5602).
//!
//! The runtime hands the guest the hosted daemon's settings once at boot, and
//! its rotating tokens at boot and again whenever the kubelet replaces one.
//! It is one direction: the host sends, and the guest only acknowledges;
//! nothing the guest writes is acted on by the host beyond the acknowledgement
//! (cw-security's conditions, `designs/vm-runtime-in-the-pod.md` section 2).
//!
//! Each connection is one exchange, as the checkpoint hook's is. The guest
//! sends a fresh challenge, the host sends one message MACed over it, and the
//! guest answers with one reply MACed over it too. The key is derived from the
//! boot's daemon token, VM id and generation, so a message made for one boot
//! is refused by any other.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

/// The guest's hosted control listener, for the host CID only.
pub const HOSTED_CONTROL_VSOCK_PORT: u32 = 7_780;

/// A standard Pod's ports in (#5602, cw-security's conditions): the guest
/// listens on these from the host CID only, in a guest-carried boot only, and
/// joins each connection to one fixed target in the workspace's network
/// namespace. The Pod's 7777 reaches the first, its 2222 the second.
pub const HOSTED_DAEMON_INGRESS_VSOCK_PORT: u32 = 7_781;
pub const HOSTED_SSH_INGRESS_VSOCK_PORT: u32 = 7_782;
/// The hosted daemon's gRPC port inside the guest's workspace namespace.
/// Guest port 7777 is the local daemon's, which no forwarder reaches.
pub const HOSTED_DAEMON_GUEST_PORT: u16 = 17_777;
/// At most this many joins at once per ingress port; a connection over the
/// cap is refused, not queued.
pub const HOSTED_INGRESS_MAX_JOINS: usize = 64;
/// The variable that tells a guest-carried daemon it inherited its gRPC
/// listener, and the descriptor that holds it. The guest sets it on the
/// workload alone, never from the Pod's settings.
pub const HOSTED_DAEMON_LISTENER_FD_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_LISTEN_FD";
pub const HOSTED_DAEMON_LISTENER_FD: i32 = 9;
/// A join with no bytes either way for this long is closed.
pub const HOSTED_INGRESS_IDLE: std::time::Duration = std::time::Duration::from_secs(600);
/// How long a join waits to connect to its target.
pub const HOSTED_INGRESS_CONNECT: std::time::Duration = std::time::Duration::from_secs(5);
/// The hosted workload's output out (#5602): in a guest-carried boot the
/// guest connects to this host port and only writes; the Pod's runtime only
/// reads, and writes what it accepts to its own log as untrusted text.
pub const HOSTED_LOG_VSOCK_PORT: u32 = 7_783;
/// The longest line, in bytes, either side keeps; the rest of a longer line
/// is dropped and the line marked truncated.
pub const HOSTED_LOG_MAX_LINE: usize = 4_096;
/// A suspend asked for by the guest (#5529, `docs/dev/IDLE-STOP.md`,
/// "Suspend"): the guest connects to this host port and writes
/// [`HOSTED_SUSPEND_REQUEST`]; the Pod's runtime answers
/// [`HOSTED_SUSPEND_ACCEPTED`] or [`HOSTED_SUSPEND_REFUSED`] and, having
/// accepted, freezes the workload and pauses the VM. The guest can only ask
/// to be paused: nothing it sends resumes it.
pub const HOSTED_SUSPEND_VSOCK_PORT: u32 = 7_784;
pub const HOSTED_SUSPEND_REQUEST: &[u8; 8] = b"suspend\n";
pub const HOSTED_SUSPEND_ACCEPTED: &[u8; 3] = b"ok\n";
pub const HOSTED_SUSPEND_REFUSED: &[u8; 3] = b"no\n";
/// Container-side Unix socket where guest init relays fixed sleep-control
/// requests to the host's [`HOSTED_SUSPEND_VSOCK_PORT`], so nothing inside the
/// workspace container needs `AF_VSOCK` (#5638).
pub const HOSTED_SLEEP_CONTROL_SOCKET_PATH: &str = "/run/codewire-hosted/sleep/control.sock";
/// How long either side waits for the other's part of a suspend request.
pub const HOSTED_SUSPEND_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(5);

/// The guest's side of a suspend: asks the Pod's runtime (through guest init's
/// Unix-socket relay at [`HOSTED_SLEEP_CONTROL_SOCKET_PATH`]) to pause this
/// VM, and returns whether it accepted. On `true` the VM pauses straight after
/// the answer; the caller has already closed the connections whose far end
/// sends periodic traffic, so that traffic can't wake it.
///
/// If the relay socket does not exist (`NotFound`), falls back to dialing
/// [`HOSTED_SUSPEND_VSOCK_PORT`] directly so an updated `cw` runtime asset
/// continues to work inside an older `pod-runtime` VM during rollout; on any
/// `pod-runtime` with the relay, `AF_VSOCK` is blocked by container seccomp.
#[cfg(target_os = "linux")]
pub async fn request_suspend() -> std::io::Result<bool> {
    match request_suspend_at(std::path::Path::new(HOSTED_SLEEP_CONTROL_SOCKET_PATH)).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => request_suspend_vsock().await,
        other => other,
    }
}

#[cfg(target_os = "linux")]
async fn request_suspend_at(socket_path: &std::path::Path) -> std::io::Result<bool> {
    let exchange = async {
        let relay = tokio::net::UnixStream::connect(socket_path).await?;
        exchange_suspend(relay).await
    };
    tokio::time::timeout(HOSTED_SUSPEND_EXCHANGE, exchange)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

#[cfg(target_os = "linux")]
async fn request_suspend_vsock() -> std::io::Result<bool> {
    let exchange = async {
        let host = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_HOST,
            HOSTED_SUSPEND_VSOCK_PORT,
        ))
        .await?;
        exchange_suspend(host).await
    };
    tokio::time::timeout(HOSTED_SUSPEND_EXCHANGE, exchange)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

#[cfg(target_os = "linux")]
async fn exchange_suspend<S>(mut stream: S) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    stream.write_all(HOSTED_SUSPEND_REQUEST).await?;
    stream.flush().await?;
    let mut answer = [0_u8; 3];
    stream.read_exact(&mut answer).await?;
    Ok(&answer == HOSTED_SUSPEND_ACCEPTED)
}

/// Joins two streams byte for byte until both directions have ended, or
/// until neither has carried a byte for `idle`. The ingress on both sides of
/// a standard Pod's ports uses it, the guest's and the Pod's.
#[cfg(target_os = "linux")]
pub async fn join_until_idle<A, B>(a: A, b: B, idle: std::time::Duration) -> std::io::Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let activity = std::sync::Mutex::new(tokio::time::Instant::now());
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let both = async {
        tokio::try_join!(
            copy_noting_activity(&mut a_read, &mut b_write, &activity),
            copy_noting_activity(&mut b_read, &mut a_write, &activity),
        )
    };
    let idle_out = async {
        loop {
            tokio::time::sleep(idle / 8).await;
            // A poisoned clock can only come from a panicked copy: end the join.
            if activity.lock().map_or(true, |last| last.elapsed() >= idle) {
                return;
            }
        }
    };
    tokio::select! {
        ended = both => ended.map(|_| ()),
        () = idle_out => Ok(()),
    }
}

#[cfg(target_os = "linux")]
async fn copy_noting_activity<R, W>(
    from: &mut R,
    to: &mut W,
    activity: &std::sync::Mutex<tokio::time::Instant>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            return to.shutdown().await;
        }
        to.write_all(&buffer[..read]).await?;
        if let Ok(mut last) = activity.lock() {
            *last = tokio::time::Instant::now();
        }
    }
}

/// The kernel command-line parameter a standard Pod's VMM boots its guest
/// with, and nothing else sets: the hosted daemon in that guest is
/// guest-carried, its platform dials leaving through the VM's own network
/// session and its workload's egress closed at the host end (#5602,
/// cw-security's conditions). Only the runtime's fixed VMM configuration
/// writes a kernel command line; no Pod spec, workload or setting reaches it.
pub const GUEST_CARRIED_PARAMETER: &str = "codewire.guest_carried=1";

/// Whether a kernel command line names [`GUEST_CARRIED_PARAMETER`] as one
/// whole parameter.
pub fn guest_carried(command_line: &str) -> bool {
    names(command_line, GUEST_CARRIED_PARAMETER)
}

/// The kernel command-line parameter a standard Pod's VMM boots a
/// broker-mode guest with, never beside [`GUEST_CARRIED_PARAMETER`] (#5602,
/// design: comment 130891). The hosted daemon in that guest runs hosted
/// broker mode unchanged: its workload's default route is the egress TUN the
/// guest's init makes, carried to `cw-egress` over a stream the daemon opens
/// with the Pod's own egress token. As with the other parameter, only the
/// runtime's fixed VMM configuration writes it.
pub const HOSTED_BROKER_PARAMETER: &str = "codewire.hosted_broker=1";

/// How a standard Pod's guest carries its workload's egress. The Pod's
/// `CODEWIRE_VM_EGRESS_MODE` chooses it on the host, and the kernel command
/// line carries it into the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedEgressMode {
    /// The workload has no egress; the daemon reaches only the platform
    /// peers, through the VM's own network session.
    GuestCarried,
    /// Hosted broker mode inside the VM.
    Broker,
}

impl HostedEgressMode {
    /// The one kernel command-line parameter that names this mode.
    pub fn parameter(self) -> &'static str {
        match self {
            Self::GuestCarried => GUEST_CARRIED_PARAMETER,
            Self::Broker => HOSTED_BROKER_PARAMETER,
        }
    }

    /// The mode a kernel command line names: none for a local VM's, and an
    /// error for one naming both, which no runtime writes.
    pub fn from_command_line(command_line: &str) -> Result<Option<Self>, HostedControlError> {
        match (
            guest_carried(command_line),
            names(command_line, HOSTED_BROKER_PARAMETER),
        ) {
            (false, false) => Ok(None),
            (true, false) => Ok(Some(Self::GuestCarried)),
            (false, true) => Ok(Some(Self::Broker)),
            (true, true) => Err(HostedControlError::InvalidContent),
        }
    }
}

/// Whether a standard Pod's VMM booted this kernel, in either mode.
pub fn hosted_guest(command_line: &str) -> bool {
    !matches!(HostedEgressMode::from_command_line(command_line), Ok(None))
}

/// The kernel command-line parameters naming the workspace container's first
/// process in a standard Pod (`docs/dev/SYSTEMD-WORKSPACE.md`, "On the
/// `standard` profile", #5638).
pub const HOSTED_WORKSPACE_INIT_IMAGE_PARAMETER: &str = "codewire.workspace_init=image";
pub const HOSTED_WORKSPACE_INIT_SYSTEMD_PARAMETER: &str = "codewire.workspace_init=systemd";

/// How a standard Pod's guest runs the workspace container's first process.
/// The Pod's `CODEWIRE_WORKSPACE_INIT` chooses it on the host, and the kernel
/// command line carries it into the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedWorkspaceInit {
    /// Codewire's workspace init stays container PID 1 and runs the hosted
    /// daemon as a child.
    Image,
    /// The workspace container hands PID 1 over to `/sbin/init` (`systemd`) in
    /// a delegated cgroup v2 subtree, with `codewire-daemon.service` and
    /// `docker.service` masked and the hosted daemon run by guest init.
    Systemd,
}

impl HostedWorkspaceInit {
    /// The one kernel command-line parameter that names this workspace init.
    pub fn parameter(self) -> &'static str {
        match self {
            Self::Image => HOSTED_WORKSPACE_INIT_IMAGE_PARAMETER,
            Self::Systemd => HOSTED_WORKSPACE_INIT_SYSTEMD_PARAMETER,
        }
    }

    /// The workspace init a kernel command line names: none for a local VM's,
    /// and an error for one naming both, which no runtime writes.
    pub fn from_command_line(command_line: &str) -> Result<Option<Self>, HostedControlError> {
        match (
            names(command_line, HOSTED_WORKSPACE_INIT_IMAGE_PARAMETER),
            names(command_line, HOSTED_WORKSPACE_INIT_SYSTEMD_PARAMETER),
        ) {
            (false, false) => Ok(None),
            (true, false) => Ok(Some(Self::Image)),
            (false, true) => Ok(Some(Self::Systemd)),
            (true, true) => Err(HostedControlError::InvalidContent),
        }
    }
}

fn names(command_line: &str, parameter: &str) -> bool {
    command_line
        .split_ascii_whitespace()
        .any(|named| named == parameter)
}
pub const HOSTED_CHALLENGE_LEN: usize = 32;
pub const HOSTED_HELLO_LEN: usize = 40;
pub const HOSTED_REPLY_LEN: usize = 48;
/// A message's header before its payload: magic, kind, reserved, length.
pub const HOSTED_REQUEST_HEADER_LEN: usize = 16;
/// The largest payload: the settings with two roots bundles, or three tokens.
pub const HOSTED_MAX_PAYLOAD: usize = 256 * 1024;
const TAG_LEN: usize = 32;

/// The hosted daemon's environment, by the Kata template's names and no
/// other (cw-security's condition): the binding, the shim, the user, the Pod
/// and, with hosted egress, the platform peers' addresses. Kind's test
/// deployment alone sets the Codex sign-in check period.
pub const HOSTED_ENVIRONMENT_NAMES: [&str; 12] = [
    "CODEWIRE_API_ADDR",
    "CODEWIRE_CLUSTER_DNS_IP",
    "CODEWIRE_CODEX_LOGIN_CHECK_PERIOD_SECONDS",
    "CODEWIRE_DERP_ADDR",
    "CODEWIRE_EGRESS_STREAM_ADDR",
    "CODEWIRE_MESH_ADDR",
    "CODEWIRE_POD_UID",
    "CODEWIRE_WORKSPACE_BINDING_ADDR",
    "CODEWIRE_WORKSPACE_BINDING_URL",
    "CODEWIRE_WORKSPACE_SHIM_ADDR",
    "HOME",
    "USER",
];
const MAX_VALUE_BYTES: usize = 4096;
const MAX_FILES_PER_DIRECTORY: usize = 8;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

const HELLO_MAGIC: &[u8; 8] = b"CWHCH1\0\0";
const REQUEST_MAGIC: &[u8; 8] = b"CWHCQ1\0\0";
const REPLY_MAGIC: &[u8; 8] = b"CWHCR1\0\0";
const KEY_DOMAIN: &[u8] = b"codewire-hosted-control-v1\0";
const REQUEST_DOMAIN: &[u8] = b"codewire-hosted-control-request-v1\0";
const REPLY_DOMAIN: &[u8] = b"codewire-hosted-control-reply-v1\0";
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostedControlError {
    #[error("the boot's daemon token is not a valid key source")]
    InvalidToken,
    #[error("the boot identity is not valid")]
    InvalidIdentity,
    #[error("a hosted control frame has the wrong length")]
    InvalidLength,
    #[error("a hosted control frame has the wrong magic")]
    InvalidMagic,
    #[error("a hosted control frame is malformed")]
    InvalidFraming,
    #[error("a hosted control frame is not authentic")]
    InvalidTag,
    #[error("a hosted control message names a setting, file or token it may not carry")]
    InvalidContent,
}

/// One boot's channel key: `HMAC-SHA256(token, domain ‖ vm_id ‖ generation)`.
#[derive(Clone)]
pub struct HostedControlKey([u8; 32]);

impl HostedControlKey {
    pub fn derive(token: &str, vm_id: Uuid, generation: u64) -> Result<Self, HostedControlError> {
        if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(HostedControlError::InvalidToken);
        }
        if vm_id.is_nil() || generation == 0 {
            return Err(HostedControlError::InvalidIdentity);
        }
        let mut mac = HmacSha256::new_from_slice(token.as_bytes())
            .map_err(|_| HostedControlError::InvalidToken)?;
        mac.update(KEY_DOMAIN);
        mac.update(vm_id.as_bytes());
        mac.update(&generation.to_le_bytes());
        Ok(Self(mac.finalize().into_bytes().into()))
    }

    fn mac(&self, domain: &[u8], challenge: &[u8; HOSTED_CHALLENGE_LEN]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(domain);
        mac.update(challenge);
        mac
    }
}

impl Drop for HostedControlKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The guest's first frame on a connection: a fresh, non-zero challenge.
pub fn encode_hello(challenge: &[u8; HOSTED_CHALLENGE_LEN]) -> [u8; HOSTED_HELLO_LEN] {
    let mut bytes = [0_u8; HOSTED_HELLO_LEN];
    bytes[..8].copy_from_slice(HELLO_MAGIC);
    bytes[8..].copy_from_slice(challenge);
    bytes
}

pub fn decode_hello(bytes: &[u8]) -> Result<[u8; HOSTED_CHALLENGE_LEN], HostedControlError> {
    if bytes.len() != HOSTED_HELLO_LEN {
        return Err(HostedControlError::InvalidLength);
    }
    if &bytes[..8] != HELLO_MAGIC {
        return Err(HostedControlError::InvalidMagic);
    }
    let challenge: [u8; HOSTED_CHALLENGE_LEN] = bytes[8..].try_into().expect("fixed challenge");
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(HostedControlError::InvalidFraming);
    }
    Ok(challenge)
}

/// The two things the host sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostedMessage {
    /// Once per boot, before the workload starts.
    Settings(HostedSettings),
    /// At boot after the settings, and again after each rotation.
    Tokens(HostedTokens),
}

/// The hosted daemon's settings, read afresh from the Pod at every boot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSettings {
    /// Only [`HOSTED_ENVIRONMENT_NAMES`].
    pub environment: BTreeMap<String, String>,
    /// The orchestration roots ConfigMap's files, mounted where the Kata Pod
    /// mounts them.
    pub binding_tls_roots: BTreeMap<String, String>,
    /// On local clusters only, the coordinator's extra roots.
    pub coordinator_extra_roots: BTreeMap<String, String>,
}

/// The tokens that cross into a standard guest, each Pod-bound and each
/// checked by the service it opens, never by anything the guest says
/// (cw-security, #5602 comments 130894 and 130903):
///
/// | Token | Audience | Mode | Checked by |
/// |---|---|---|---|
/// | `binding` | the workspace binding | both | orchestration's binding, by TokenReview and the live Pod |
/// | `credential` | the credential workspace | both, when set up | the credential service, by reviewed Pod UID |
/// | `egress` | `cw-egress` | broker only | `cw-egress`'s admission: this Pod's UID and address, on this node |
///
/// A guest-carried guest gets no egress token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedTokens {
    /// The Pod-bound token the daemon presents to the binding.
    pub binding: String,
    /// The credential workspace token, when the credential runtime is set up.
    pub credential: Option<String>,
    /// The Pod-bound `cw-egress` token a broker-mode daemon opens its egress
    /// stream with; absent in guest-carried mode.
    #[serde(default)]
    pub egress: Option<String>,
}

impl HostedSettings {
    pub fn validate(&self) -> Result<(), HostedControlError> {
        let bad = || HostedControlError::InvalidContent;
        for (name, value) in &self.environment {
            if !HOSTED_ENVIRONMENT_NAMES.contains(&name.as_str())
                || value.len() > MAX_VALUE_BYTES
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(bad());
            }
        }
        for files in [&self.binding_tls_roots, &self.coordinator_extra_roots] {
            if files.len() > MAX_FILES_PER_DIRECTORY {
                return Err(bad());
            }
            for (name, contents) in files {
                if !valid_file_name(name) || contents.len() > MAX_FILE_BYTES {
                    return Err(bad());
                }
            }
        }
        Ok(())
    }
}

impl HostedTokens {
    pub fn validate(&self) -> Result<(), HostedControlError> {
        let valid = |token: &str| {
            !token.is_empty()
                && token.len() <= MAX_TOKEN_BYTES
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        };
        if !valid(&self.binding)
            || [&self.credential, &self.egress]
                .into_iter()
                .any(|token| token.as_deref().is_some_and(|token| !valid(token)))
        {
            return Err(HostedControlError::InvalidContent);
        }
        Ok(())
    }
}

/// A ConfigMap key: what the kubelet would write as a file name.
fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

impl HostedMessage {
    fn kind(&self) -> u16 {
        match self {
            Self::Settings(_) => 1,
            Self::Tokens(_) => 2,
        }
    }

    /// The whole frame: header, payload and the tag over both.
    pub fn encode(
        &self,
        key: &HostedControlKey,
        challenge: &[u8; HOSTED_CHALLENGE_LEN],
    ) -> Result<Vec<u8>, HostedControlError> {
        let payload = match self {
            Self::Settings(settings) => {
                settings.validate()?;
                serde_json::to_vec(settings)
            }
            Self::Tokens(tokens) => {
                tokens.validate()?;
                serde_json::to_vec(tokens)
            }
        }
        .map_err(|_| HostedControlError::InvalidContent)?;
        if payload.len() > HOSTED_MAX_PAYLOAD {
            return Err(HostedControlError::InvalidContent);
        }
        let length =
            u32::try_from(payload.len()).map_err(|_| HostedControlError::InvalidContent)?;
        let mut bytes = Vec::with_capacity(HOSTED_REQUEST_HEADER_LEN + payload.len() + TAG_LEN);
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&self.kind().to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let mut mac = key.mac(REQUEST_DOMAIN, challenge);
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }

    /// The payload's length from a frame's header, bounded, so a reader
    /// knows how much more to read before [`Self::decode`].
    pub fn payload_len(header: &[u8]) -> Result<usize, HostedControlError> {
        if header.len() != HOSTED_REQUEST_HEADER_LEN {
            return Err(HostedControlError::InvalidLength);
        }
        if &header[..8] != REQUEST_MAGIC {
            return Err(HostedControlError::InvalidMagic);
        }
        if header[10..12] != [0, 0] {
            return Err(HostedControlError::InvalidFraming);
        }
        let length = usize::try_from(u32::from_le_bytes(
            header[12..16].try_into().expect("fixed length"),
        ))
        .map_err(|_| HostedControlError::InvalidFraming)?;
        if length > HOSTED_MAX_PAYLOAD {
            return Err(HostedControlError::InvalidLength);
        }
        Ok(length)
    }

    /// Checks the tag before it parses anything, then the content.
    pub fn decode(
        bytes: &[u8],
        key: &HostedControlKey,
        challenge: &[u8; HOSTED_CHALLENGE_LEN],
    ) -> Result<Self, HostedControlError> {
        if bytes.len() < HOSTED_REQUEST_HEADER_LEN + TAG_LEN {
            return Err(HostedControlError::InvalidLength);
        }
        let length = Self::payload_len(&bytes[..HOSTED_REQUEST_HEADER_LEN])?;
        if bytes.len() != HOSTED_REQUEST_HEADER_LEN + length + TAG_LEN {
            return Err(HostedControlError::InvalidLength);
        }
        let (authenticated, tag) = bytes.split_at(bytes.len() - TAG_LEN);
        let mut mac = key.mac(REQUEST_DOMAIN, challenge);
        mac.update(authenticated);
        mac.verify_slice(tag)
            .map_err(|_| HostedControlError::InvalidTag)?;
        let payload = &authenticated[HOSTED_REQUEST_HEADER_LEN..];
        let kind = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed kind"));
        let message = match kind {
            1 => Self::Settings(
                serde_json::from_slice(payload).map_err(|_| HostedControlError::InvalidContent)?,
            ),
            2 => Self::Tokens(
                serde_json::from_slice(payload).map_err(|_| HostedControlError::InvalidContent)?,
            ),
            _ => return Err(HostedControlError::InvalidFraming),
        };
        match &message {
            Self::Settings(settings) => settings.validate()?,
            Self::Tokens(tokens) => tokens.validate()?,
        }
        Ok(message)
    }
}

/// The guest's answer: whether it applied the message, MACed over the same
/// challenge, so the host knows the guest it set up is the one that answered.
pub fn encode_reply(
    key: &HostedControlKey,
    challenge: &[u8; HOSTED_CHALLENGE_LEN],
    applied: bool,
) -> [u8; HOSTED_REPLY_LEN] {
    let mut bytes = [0_u8; HOSTED_REPLY_LEN];
    bytes[..8].copy_from_slice(REPLY_MAGIC);
    bytes[8..10].copy_from_slice(&u16::from(applied).to_le_bytes());
    let mut mac = key.mac(REPLY_DOMAIN, challenge);
    mac.update(&bytes[..16]);
    bytes[16..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

/// Whether the guest applied the message; an unauthentic reply is an error.
pub fn decode_reply(
    bytes: &[u8],
    key: &HostedControlKey,
    challenge: &[u8; HOSTED_CHALLENGE_LEN],
) -> Result<bool, HostedControlError> {
    if bytes.len() != HOSTED_REPLY_LEN {
        return Err(HostedControlError::InvalidLength);
    }
    if &bytes[..8] != REPLY_MAGIC {
        return Err(HostedControlError::InvalidMagic);
    }
    if bytes[10..16].iter().any(|byte| *byte != 0) {
        return Err(HostedControlError::InvalidFraming);
    }
    let mut mac = key.mac(REPLY_DOMAIN, challenge);
    mac.update(&bytes[..16]);
    mac.verify_slice(&bytes[16..])
        .map_err(|_| HostedControlError::InvalidTag)?;
    match u16::from_le_bytes(bytes[8..10].try_into().expect("fixed status")) {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(HostedControlError::InvalidFraming),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(generation: u64) -> HostedControlKey {
        HostedControlKey::derive(&"t".repeat(64), Uuid::from_u128(7), generation).unwrap()
    }

    fn settings() -> HostedSettings {
        HostedSettings {
            environment: [
                ("CODEWIRE_POD_UID", "5f0c6a1e-0000-4000-8000-000000000001"),
                ("CODEWIRE_WORKSPACE_SHIM_ADDR", "0.0.0.0:7777"),
                ("HOME", "/home/codewire"),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
            binding_tls_roots: [(
                "ca.crt".to_owned(),
                "-----BEGIN CERTIFICATE-----\n".to_owned(),
            )]
            .into_iter()
            .collect(),
            coordinator_extra_roots: BTreeMap::new(),
        }
    }

    fn tokens() -> HostedTokens {
        HostedTokens {
            binding: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln".to_owned(),
            credential: None,
            egress: Some("eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJlZ3Jlc3MifQ.c2ln".to_owned()),
        }
    }

    #[test]
    fn a_kernel_command_line_names_one_hosted_mode_or_none() {
        let base = "console=ttyS0 rdinit=/init panic=-1";
        assert_eq!(HostedEgressMode::from_command_line(base), Ok(None));
        assert!(!hosted_guest(base));
        for mode in [HostedEgressMode::GuestCarried, HostedEgressMode::Broker] {
            let line = format!("{base} {}", mode.parameter());
            assert_eq!(HostedEgressMode::from_command_line(&line), Ok(Some(mode)));
            assert!(hosted_guest(&line));
        }
        // Only whole parameters count, and the two never stand together.
        for near in ["codewire.hosted_broker=10", "xcodewire.hosted_broker=1"] {
            assert_eq!(
                HostedEgressMode::from_command_line(&format!("{base} {near}")),
                Ok(None)
            );
        }
        let both = format!("{base} {GUEST_CARRIED_PARAMETER} {HOSTED_BROKER_PARAMETER}");
        assert_eq!(
            HostedEgressMode::from_command_line(&both),
            Err(HostedControlError::InvalidContent)
        );
        assert!(!guest_carried(&format!("{base} {HOSTED_BROKER_PARAMETER}")));
    }

    #[test]
    fn a_kernel_command_line_names_one_workspace_init_or_none() {
        let base = "console=ttyS0 rdinit=/init panic=-1";
        assert_eq!(HostedWorkspaceInit::from_command_line(base), Ok(None));
        for init in [HostedWorkspaceInit::Image, HostedWorkspaceInit::Systemd] {
            let line = format!("{base} {}", init.parameter());
            assert_eq!(
                HostedWorkspaceInit::from_command_line(&line),
                Ok(Some(init))
            );
        }
        for near in [
            "codewire.workspace_init=systemd2",
            "xcodewire.workspace_init=systemd",
            "codewire.workspace_init=Systemd",
        ] {
            assert_eq!(
                HostedWorkspaceInit::from_command_line(&format!("{base} {near}")),
                Ok(None)
            );
        }
        let both = format!(
            "{base} {HOSTED_WORKSPACE_INIT_IMAGE_PARAMETER} {HOSTED_WORKSPACE_INIT_SYSTEMD_PARAMETER}"
        );
        assert_eq!(
            HostedWorkspaceInit::from_command_line(&both),
            Err(HostedControlError::InvalidContent)
        );
    }

    #[test]
    fn a_message_reaches_only_the_boot_and_challenge_it_was_made_for() {
        let challenge = [3_u8; HOSTED_CHALLENGE_LEN];
        for message in [
            HostedMessage::Settings(settings()),
            HostedMessage::Tokens(tokens()),
        ] {
            let frame = message.encode(&key(1), &challenge).unwrap();
            assert_eq!(
                HostedMessage::decode(&frame, &key(1), &challenge).unwrap(),
                message
            );
            // Another boot, or a replay against a new challenge, is refused.
            assert_eq!(
                HostedMessage::decode(&frame, &key(2), &challenge),
                Err(HostedControlError::InvalidTag)
            );
            assert_eq!(
                HostedMessage::decode(&frame, &key(1), &[4_u8; HOSTED_CHALLENGE_LEN]),
                Err(HostedControlError::InvalidTag)
            );
            // Any flipped byte is refused before anything is parsed.
            for index in [8, HOSTED_REQUEST_HEADER_LEN + 1, frame.len() - 1] {
                let mut tampered = frame.clone();
                tampered[index] ^= 1;
                assert!(HostedMessage::decode(&tampered, &key(1), &challenge).is_err());
            }
        }
    }

    #[test]
    fn only_the_fixed_names_files_and_tokens_cross() {
        let challenge = [3_u8; HOSTED_CHALLENGE_LEN];
        let mut unknown = settings();
        unknown
            .environment
            .insert("CODEWIRE_ENVIRONMENT_ID".to_owned(), "x".to_owned());
        let mut control = settings();
        control
            .environment
            .insert("HOME".to_owned(), "/home\n/x".to_owned());
        let mut path = settings();
        path.binding_tls_roots
            .insert("../ca.crt".to_owned(), String::new());
        let mut hidden = settings();
        hidden
            .binding_tls_roots
            .insert(".hidden".to_owned(), String::new());
        for refused in [unknown, control, path, hidden] {
            assert_eq!(
                HostedMessage::Settings(refused).encode(&key(1), &challenge),
                Err(HostedControlError::InvalidContent)
            );
        }
        for token in ["", "has space", &"a".repeat(MAX_TOKEN_BYTES + 1)] {
            for refused in [
                HostedTokens {
                    binding: token.to_owned(),
                    ..tokens()
                },
                HostedTokens {
                    egress: Some(token.to_owned()),
                    ..tokens()
                },
            ] {
                assert_eq!(
                    HostedMessage::Tokens(refused).encode(&key(1), &challenge),
                    Err(HostedControlError::InvalidContent)
                );
            }
        }
    }

    #[test]
    fn an_oversized_frame_is_refused_from_its_header() {
        let mut header = [0_u8; HOSTED_REQUEST_HEADER_LEN];
        header[..8].copy_from_slice(REQUEST_MAGIC);
        header[12..16]
            .copy_from_slice(&u32::try_from(HOSTED_MAX_PAYLOAD + 1).unwrap().to_le_bytes());
        assert_eq!(
            HostedMessage::payload_len(&header),
            Err(HostedControlError::InvalidLength)
        );
    }

    #[test]
    fn the_reply_and_hello_are_bound_and_exact() {
        let challenge = [9_u8; HOSTED_CHALLENGE_LEN];
        assert_eq!(decode_hello(&encode_hello(&challenge)).unwrap(), challenge);
        assert_eq!(
            decode_hello(&encode_hello(&[0_u8; HOSTED_CHALLENGE_LEN])),
            Err(HostedControlError::InvalidFraming)
        );
        for applied in [true, false] {
            let reply = encode_reply(&key(1), &challenge, applied);
            assert_eq!(decode_reply(&reply, &key(1), &challenge).unwrap(), applied);
            assert_eq!(
                decode_reply(&reply, &key(2), &challenge),
                Err(HostedControlError::InvalidTag)
            );
        }
    }

    #[test]
    fn the_key_needs_a_real_token_and_identity() {
        assert!(HostedControlKey::derive("short", Uuid::from_u128(7), 1).is_err());
        assert!(HostedControlKey::derive(&"t".repeat(64), Uuid::nil(), 1).is_err());
        assert!(HostedControlKey::derive(&"t".repeat(64), Uuid::from_u128(7), 0).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn request_suspend_uses_unix_socket_relay() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("control.sock");
        for (reply, expected) in [
            (HOSTED_SUSPEND_ACCEPTED, true),
            (HOSTED_SUSPEND_REFUSED, false),
        ] {
            let _ = std::fs::remove_file(&socket_path);
            let path = socket_path.clone();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::bind(&path).unwrap();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = [0_u8; HOSTED_SUSPEND_REQUEST.len()];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request, HOSTED_SUSPEND_REQUEST);
                    stream.write_all(reply).await.unwrap();
                    stream.flush().await.unwrap();
                });
                let accepted = request_suspend_at(&path).await.unwrap();
                assert_eq!(accepted, expected);
                server.await.unwrap();
            });
        }
    }
}
