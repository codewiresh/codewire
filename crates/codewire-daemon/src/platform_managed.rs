//! Fixed platform managed-agent target and original-channel ownership.
//!
//! Origin is material-free correlation from the original authenticated Pod
//! channel. Config does not retain PodUID: the control-plane capture, current
//! actor/grant check and durable Issued journal remain required authority.
//! This module provides no Host/Mesh grants, arbitrary Exec, Store selection,
//! ordinary-session adoption or replay mechanism.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Config, CredentialBridgeTransport, execution::ProcessExecution};

pub(crate) const IMAGE: &str = "/codewire/bin/cw";
pub(crate) const HOME: &str = "/home/codewire";
pub(crate) const STATE: &str = "/home/codewire/.local/state/codewire/platform-managed-agents-v1";
const MAX_IMAGE: u64 = 256 * 1024 * 1024;
const MAX_REQUEST: usize = 512 * 1024;
mod files;
pub(crate) use files::{Tree, leaf_refusal, publish_session, tree_refusal};
mod payload;
pub use payload::{PinRefusal, ProviderIdentity, ProviderPin, shell_client, shell_client_on};
mod service;
pub(crate) use service::{CleanupLink, Owner, RestartAdvance, Service};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agent {
    Codex,
    Claude,
}
impl TryFrom<i32> for Agent {
    type Error = Error;
    fn try_from(value: i32) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Codex),
            2 => Ok(Self::Claude),
            _ => Err(Error::Refused),
        }
    }
}
impl Agent {
    pub(crate) fn wire(self) -> i32 {
        match self {
            Self::Codex => 1,
            Self::Claude => 2,
        }
    }

    /// The command the workspace user's shell runs for this agent.
    pub fn command(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }

    /// The route this agent's private home uses with the binding's `selected`
    /// slots, or `None` when no selected slot serves it, by the rule every
    /// placement shares ([`ManagedCredentialClients::managed_agent_client`]).
    pub(crate) fn route(self, selected: ManagedCredentialClients) -> Option<Route> {
        let agent = match self {
            Self::Codex => codewire_access::ManagedAgent::Codex,
            Self::Claude => codewire_access::ManagedAgent::Claude,
        };
        match selected.managed_agent_client(agent)? {
            ManagedCredentialClient::Codex => Some(Route::Codex),
            ManagedCredentialClient::OpenAi => Some(Route::OpenAi),
            ManagedCredentialClient::Anthropic => Some(Route::Anthropic),
            ManagedCredentialClient::Ssh | ManagedCredentialClient::GitHub => None,
        }
    }
}

/// The broker route of one managed agent, fixed when the agent is prepared.
/// Every route is credential-free: the private home names only a loopback
/// endpoint, and the broker adds the selected slot's credential outside the
/// Sandbox. None of them reads Codex's delivered `~/.codex/auth.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    /// Codex through the Codex slot's `/v1` route: the owner's ChatGPT
    /// sign-in, or an API key held in that slot.
    #[serde(rename = "codex")]
    Codex,
    /// Codex through the OpenAI API-key slot's `/_codewire/openai/v1` route.
    #[serde(rename = "openai")]
    OpenAi,
    /// Claude through the Anthropic slot.
    #[serde(rename = "anthropic")]
    Anthropic,
}

impl Route {
    pub fn agent(self) -> Agent {
        match self {
            Self::Codex | Self::OpenAi => Agent::Codex,
            Self::Anthropic => Agent::Claude,
        }
    }
}

/// Bound by the next controlled-Start admission before process effects. Never
/// read a token, infer a category from environment names, or recover a scope
/// from whichever Pod/binding happens to be current later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Origin {
    pub version: u32,
    pub environment_id: String,
    pub org_id: String,
    pub pod_uid: String,
    pub binding_generation: u64,
    pub projection_selection_sha256: [u8; 32],
    pub driver_id: String,
    pub agent: Agent,
    pub support_image_sha256: [u8; 32],
    pub support_image_size: u64,
    pub provider: ProviderIdentity,
    pub parent_generation: Option<u64>,
}

impl Origin {
    /// What a record must satisfy to launch, load, list, be read, stopped or
    /// restarted. It names no value that changes between releases, so a
    /// record an earlier daemon wrote keeps loading after an upgrade, and any
    /// version its client named is admitted.
    pub(crate) fn validate(&self, session: &str) -> Result<(), Error> {
        match self.shape_fault(session) {
            Some(_) => Err(Error::Refused),
            None => Ok(()),
        }
    }

    /// The first shape check this origin fails, named without any of its
    /// values, for the store's refusal reason.
    pub(crate) fn shape_fault(&self, session: &str) -> Option<&'static str> {
        if [&self.environment_id, &self.pod_uid, &self.driver_id]
            .into_iter()
            .any(|value| canonical_uuid(value).is_err())
        {
            return Some("an origin identity is not a canonical UUID");
        }
        let version = &self.provider.version;
        [
            (self.version != 1, "the origin version is not 1"),
            (
                self.org_id.is_empty()
                    || self.org_id.len() > 256
                    || self.org_id.trim() != self.org_id
                    || self.org_id.chars().any(char::is_control),
                "the origin organization is malformed",
            ),
            (
                self.binding_generation == 0,
                "the origin binding generation is zero",
            ),
            (
                self.projection_selection_sha256 == [0; 32],
                "the origin projection selection is empty",
            ),
            (
                self.support_image_sha256 == [0; 32]
                    || !(4..=MAX_IMAGE).contains(&self.support_image_size),
                "the origin support image is malformed",
            ),
            (
                self.provider.sha256 == [0; 32]
                    || !(4..=512 * 1024 * 1024).contains(&self.provider.size),
                "the origin provider identity is malformed",
            ),
            (
                version.is_empty()
                    || version.len() > 64
                    || !version.starts_with(|c: char| c.is_ascii_digit())
                    || !version
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b)),
                "the origin provider version is malformed",
            ),
            (
                self.parent_generation == Some(0),
                "the origin parent generation is zero",
            ),
            (
                session != format!("session-{}", self.driver_id),
                "the origin driver does not name its session",
            ),
        ]
        .into_iter()
        .find_map(|(failed, check)| failed.then_some(check))
    }

    pub(crate) fn command(&self) -> Vec<String> {
        vec![
            IMAGE.into(),
            "__platform-agent-driver".into(),
            "--environment".into(),
            self.environment_id.clone(),
            "--driver-id".into(),
            self.driver_id.clone(),
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("platform managed incarnation refused")]
    Refused,
    #[error("platform managed outcome is unknown; observe the original request")]
    Unknown,
    /// An issued launch whose environment projection was refused before the
    /// agent's program ran, with the launcher's cleanup confirmed: nothing
    /// started and nothing remains, so the request is refused, not unknown.
    #[error("the environment launch was denied before the managed agent started")]
    DeniedBeforeRun,
    /// A Resume refused before issue for one of the closed plain reasons in
    /// [`codewire_daemon_proto::platform_managed::RESUME_REFUSALS`] (#2705).
    #[error("platform managed resume refused: {0}")]
    ResumeRefused(&'static str),
}

/// A Resume's plain refusals the daemon itself finds (#2705); the helper's
/// `adopt` check names the others. Members of `RESUME_REFUSALS`.
pub(crate) const DRIVER_ALIVE: &str = "resume-driver-alive";
pub(crate) const PROVIDER_NOT_ADMITTED: &str = "resume-provider-not-admitted";

/// The closed plain reason the helper's `adopt` check names, if any (#2705).
/// Anything else in its place is refused, never passed on.
pub(crate) fn adopt_refusal(value: &Value) -> Result<Option<&'static str>, Error> {
    match value.get("refused") {
        None => Ok(None),
        Some(Value::String(reason)) => codewire_daemon_proto::platform_managed::RESUME_REFUSALS
            .iter()
            .find(|known| **known == reason.as_str())
            .map(|known| Some(*known))
            .ok_or(Error::Refused),
        Some(_) => Err(Error::Refused),
    }
}

fn canonical_uuid(value: &str) -> Result<(), Error> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| Error::Refused)?;
    if id.is_nil() || id.to_string() != value {
        return Err(Error::Refused);
    }
    Ok(())
}

pub(crate) fn peer_packet(origin: &Origin, session: &str) -> Value {
    json!({"op":"peer_status", "driver_id":origin.driver_id,"session_id":session})
}

/// Keep original running bytes, not the mutable default or a PATH sibling.
/// Incoming release-musl/full-record admission belongs to the producer and
/// next Start seam. Here the independently admitted original support hash is
/// compared against this fixed running image, with all reads held and bounded.
pub(crate) struct ImagePin {
    file: File,
    stamp: Stamp,
}

type Stamp = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn stamp(m: &std::fs::Metadata) -> Stamp {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn safe_image(m: &std::fs::Metadata) -> bool {
    m.is_file()
        && m.uid() == 0
        && m.nlink() == 1
        && m.mode() & 0o6022 == 0
        && m.mode() & 0o111 != 0
        && (4..=MAX_IMAGE).contains(&m.len())
}

pub(crate) fn validate_selection(config: &Config, origin: &Origin) -> Result<(), Error> {
    let bridge = config.credential_bridge.as_ref().ok_or(Error::Refused)?;
    let projection = config.launch_projection.as_ref().ok_or(Error::Refused)?;
    if config.host.is_some()
        || config.process_execution != ProcessExecution::Native
        || config.home_root != Path::new(HOME)
        || bridge.transport != CredentialBridgeTransport::Hosted
        || bridge.environment_id.to_string() != origin.environment_id
        // This is immutable binding generation, not the current DB env generation.
        || bridge.environment_generation != origin.binding_generation
        || bridge.ingress_uid != 1000 || bridge.ingress_gid != 1000
        || projection.selection_sha256 != origin.projection_selection_sha256
        // The driver is started through the launch projection's launcher, so
        // that launcher must be the very image this origin pins and hashes,
        // never merely a configured path that happens to equal it today.
        || projection
            .native
            .as_ref()
            .is_none_or(|native| native.helper_path != Path::new(IMAGE))
        || origin
            .agent
            .route(config.managed_credential_clients)
            .is_none()
    {
        return Err(Error::Refused);
    }
    Ok(())
}

impl ImagePin {
    pub(crate) fn identity() -> Result<([u8; 32], u64), Error> {
        for path in ["/", "/codewire", "/codewire/bin"] {
            let m = std::fs::symlink_metadata(path).map_err(|_| Error::Refused)?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(Error::Refused);
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(IMAGE)
            .map_err(|_| Error::Refused)?;
        let before = file.metadata().map_err(|_| Error::Refused)?;
        if !safe_image(&before)
            || stamp(&before)
                != stamp(&std::fs::metadata("/proc/self/exe").map_err(|_| Error::Refused)?)
        {
            return Err(Error::Refused);
        }
        let mut hash = Sha256::new();
        let mut bytes = [0; 64 * 1024];
        let mut count = 0;
        loop {
            let n = file.read(&mut bytes).map_err(|_| Error::Refused)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > MAX_IMAGE {
                return Err(Error::Refused);
            }
            hash.update(&bytes[..n]);
        }
        let pin = Self {
            file,
            stamp: stamp(&before),
        };
        pin.check()?;
        if count != before.len() {
            return Err(Error::Refused);
        }
        Ok((hash.finalize().into(), count))
    }
    pub(crate) fn admit(config: &Config, origin: &Origin) -> Result<Self, Error> {
        validate_selection(config, origin)?;
        if unsafe { libc::geteuid() } != 1000 || unsafe { libc::getegid() } != 1000 {
            return Err(Error::Refused);
        }
        // The fixed image ancestry cannot be replaced by a workload owner.
        for path in ["/", "/codewire", "/codewire/bin"] {
            let meta = std::fs::symlink_metadata(path).map_err(|_| Error::Refused)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(Error::Refused);
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(IMAGE)
            .map_err(|_| Error::Refused)?;
        let meta = file.metadata().map_err(|_| Error::Refused)?;
        let running = std::fs::metadata("/proc/self/exe").map_err(|_| Error::Refused)?;
        if !safe_image(&meta)
            || stamp(&meta) != stamp(&running)
            || meta.len() != origin.support_image_size
        {
            return Err(Error::Refused);
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let count = file.read(&mut buffer).map_err(|_| Error::Refused)?;
            if count == 0 {
                break;
            }
            total = total.checked_add(count as u64).ok_or(Error::Refused)?;
            if total > MAX_IMAGE {
                return Err(Error::Refused);
            }
            hash.update(&buffer[..count]);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if total != origin.support_image_size || actual != origin.support_image_sha256 {
            return Err(Error::Refused);
        }
        let pin = Self {
            file,
            stamp: stamp(&meta),
        };
        pin.check()?;
        Ok(pin)
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        for meta in [
            self.file.metadata().map_err(|_| Error::Unknown)?,
            std::fs::symlink_metadata(IMAGE).map_err(|_| Error::Unknown)?,
            std::fs::metadata("/proc/self/exe").map_err(|_| Error::Unknown)?,
        ] {
            if !safe_image(&meta) || stamp(&meta) != self.stamp {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }

    pub(crate) async fn helper(
        &self,
        origin: &Origin,
        session: &str,
        generation: u64,
        packet: Value,
    ) -> Result<Value, Error> {
        self.check()?;
        let bytes = serde_json::to_vec(&json!({
            "version": 1, "origin": origin, "session_id": session,
            "launch_generation": generation, "request": packet,
        }))
        .map_err(|_| Error::Refused)?;
        if bytes.len() > MAX_REQUEST {
            return Err(Error::Refused);
        }
        let parent = unsafe { libc::getpid() };
        let mut command = tokio::process::Command::new("/proc/self/exe");
        command
            .args([
                "__platform-agent-control",
                "--environment",
                &origin.environment_id,
            ])
            .env_clear()
            .env("HOME", HOME)
            .env("USER", "codewire")
            .env("LOGNAME", "codewire")
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        // Fixed lifetime confinement of this owned helper only. No target PID
        // or signal argument is exposed, and no UID/capability elevation occurs.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| Error::Unknown)?;
        // Reuse only the existing bounded write/EOF/read/exit/kill/wait exchange,
        // never its Host executable selection, scope, grants, journal or owner.
        let result = crate::host_control::managed::exchange_record_pipe(&mut child, &bytes)
            .await
            .map_err(|_| Error::Unknown)?;
        self.check()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn platform_adopt_refusal_passes_on_only_a_closed_reason() {
        assert!(matches!(
            adopt_refusal(&json!({"launch_generation": 3})),
            Ok(None)
        ));
        for reason in codewire_daemon_proto::platform_managed::RESUME_REFUSALS {
            assert!(matches!(
                adopt_refusal(&json!({ "refused": reason })),
                Ok(Some(known)) if known == reason
            ));
        }
        for value in [
            json!({"refused": "resume-anything"}),
            json!({"refused": "/workspace/private path"}),
            json!({"refused": ""}),
            json!({"refused": 1}),
            json!({"refused": null}),
        ] {
            assert!(
                matches!(adopt_refusal(&value), Err(Error::Refused)),
                "{value}"
            );
        }
        assert_eq!(DRIVER_ALIVE, "resume-driver-alive");
        assert_eq!(PROVIDER_NOT_ADMITTED, "resume-provider-not-admitted");
        for reason in [DRIVER_ALIVE, PROVIDER_NOT_ADMITTED] {
            assert!(codewire_daemon_proto::platform_managed::resume_refusal(
                reason
            ));
        }
    }
    #[test]
    fn platform_managed_selection_requires_typed_proxy_slot_before_image_io() {
        let environment = uuid::Uuid::new_v4();
        let mut config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: "/workspace".into(),
            home_root: HOME.into(),
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("synthetic-platform-selection").unwrap(),
            process_execution: ProcessExecution::Native,
            host: None,
            launch_projection: Some(crate::LaunchProjectionConfig {
                selection_sha256: [7; 32],
                native: Some(crate::NativeLaunchProjectionConfig {
                    helper_path: IMAGE.into(),
                    process_directory: crate::config::HOSTED_PROCESS_DIRECTORY.into(),
                }),
            }),
            credential_bridge: Some(crate::CredentialBridgeConfig {
                transport: CredentialBridgeTransport::Hosted,
                environment_id: environment,
                environment_generation: u64::MAX,
                ingress_socket: "/run/codewire/fixture-only.sock".into(),
                ingress_uid: 1000,
                ingress_gid: 1000,
            }),
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
            session_working_dir: None,
        };
        let mut origin = Origin {
            version: 1,
            environment_id: environment.to_string(),
            org_id: "fixture".into(),
            pod_uid: uuid::Uuid::new_v4().to_string(),
            binding_generation: u64::MAX,
            projection_selection_sha256: [7; 32],
            driver_id: uuid::Uuid::new_v4().to_string(),
            agent: Agent::Codex,
            support_image_sha256: [8; 32],
            support_image_size: 1024,
            provider: ProviderIdentity {
                sha256: [9; 32],
                size: 1024,
                version: "0.160.0".into(),
            },
            parent_generation: None,
        };
        // Codex qualifies with the Codex slot, the OpenAI API-key slot or
        // both, and never with neither.
        for slots in [&["codex"][..], &["openai"], &["codex", "openai"]] {
            config.managed_credential_clients =
                codewire_access::ManagedCredentialClients::from_profile_slots(
                    slots.iter().copied(),
                )
                .unwrap();
            assert!(validate_selection(&config, &origin).is_ok(), "{slots:?}");
        }
        for slots in [&["anthropic"][..], &[], &["anthropic", "github", "ssh"]] {
            config.managed_credential_clients =
                codewire_access::ManagedCredentialClients::from_profile_slots(
                    slots.iter().copied(),
                )
                .unwrap();
            assert!(
                matches!(validate_selection(&config, &origin), Err(Error::Refused)),
                "{slots:?}"
            );
        }
        config.managed_credential_clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(["codex", "openai"])
                .unwrap();
        origin.agent = Agent::Claude;
        assert!(validate_selection(&config, &origin).is_err());
        config.managed_credential_clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap();
        assert!(validate_selection(&config, &origin).is_ok());
        config
            .credential_bridge
            .as_mut()
            .unwrap()
            .environment_generation -= 1;
        assert!(validate_selection(&config, &origin).is_err());
    }

    /// The managed driver is started through the launch projection's
    /// launcher. Only the pinned, hashed image may be that launcher: a
    /// different path, or no launcher at all, refuses the selection before
    /// any image I/O.
    #[test]
    fn platform_managed_selection_requires_the_pinned_image_as_the_projection_launcher() {
        let environment = uuid::Uuid::new_v4();
        let native = |helper: &str| {
            Some(crate::NativeLaunchProjectionConfig {
                helper_path: helper.into(),
                process_directory: crate::config::HOSTED_PROCESS_DIRECTORY.into(),
            })
        };
        let mut config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: "/workspace".into(),
            home_root: HOME.into(),
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("synthetic-platform-launcher").unwrap(),
            process_execution: ProcessExecution::Native,
            host: None,
            launch_projection: Some(crate::LaunchProjectionConfig {
                selection_sha256: [7; 32],
                native: native(IMAGE),
            }),
            credential_bridge: Some(crate::CredentialBridgeConfig {
                transport: CredentialBridgeTransport::Hosted,
                environment_id: environment,
                environment_generation: 3,
                ingress_socket: "/run/codewire/fixture-only.sock".into(),
                ingress_uid: 1000,
                ingress_gid: 1000,
            }),
            managed_credential_clients:
                codewire_access::ManagedCredentialClients::from_profile_slots(["anthropic"])
                    .unwrap(),
            session_working_dir: None,
        };
        let origin = Origin {
            version: 1,
            environment_id: environment.to_string(),
            org_id: "fixture".into(),
            pod_uid: uuid::Uuid::new_v4().to_string(),
            binding_generation: 3,
            projection_selection_sha256: [7; 32],
            driver_id: uuid::Uuid::new_v4().to_string(),
            agent: Agent::Claude,
            support_image_sha256: [8; 32],
            support_image_size: 1024,
            provider: ProviderIdentity {
                sha256: [9; 32],
                size: 1024,
                version: "2.1.288".into(),
            },
            parent_generation: None,
        };
        assert!(validate_selection(&config, &origin).is_ok());
        // The hosted daemon's own configuration names exactly the pinned
        // image, so a real managed selection passes.
        let mut hosted = config.clone();
        hosted.apply_hosted_projection(environment, 3, [7; 32], config.managed_credential_clients);
        assert!(validate_selection(&hosted, &origin).is_ok());
        assert_eq!(
            hosted
                .launch_projection
                .as_ref()
                .and_then(|projection| projection.native.as_ref())
                .map(|native| native.helper_path.as_path()),
            Some(Path::new(IMAGE))
        );
        for refused in [
            native("/codewire/bin/cw2"),
            native("/usr/local/bin/cw"),
            native("/codewire/bin/../bin/cw"),
            native("codewire/bin/cw"),
            None,
        ] {
            config.launch_projection.as_mut().unwrap().native = refused.clone();
            assert!(
                matches!(validate_selection(&config, &origin), Err(Error::Refused)),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn platform_managed_route_prefers_the_codex_slot_and_names_its_agent() {
        let route = |agent: Agent, slots: &[&str]| {
            agent.route(
                codewire_access::ManagedCredentialClients::from_profile_slots(
                    slots.iter().copied(),
                )
                .unwrap(),
            )
        };
        assert_eq!(route(Agent::Codex, &["codex"]), Some(Route::Codex));
        assert_eq!(route(Agent::Codex, &["openai"]), Some(Route::OpenAi));
        // Codex's own `~/.codex` configuration uses the Codex slot when both
        // are selected; the OpenAI slot is for API clients.
        assert_eq!(
            route(Agent::Codex, &["openai", "codex"]),
            Some(Route::Codex)
        );
        assert_eq!(route(Agent::Codex, &[]), None);
        assert_eq!(route(Agent::Codex, &["anthropic", "github", "ssh"]), None);
        assert_eq!(route(Agent::Claude, &["anthropic"]), Some(Route::Anthropic));
        assert_eq!(route(Agent::Claude, &["codex", "openai"]), None);
        for (route, agent, wire) in [
            (Route::Codex, Agent::Codex, "\"codex\""),
            (Route::OpenAi, Agent::Codex, "\"openai\""),
            (Route::Anthropic, Agent::Claude, "\"anthropic\""),
        ] {
            assert_eq!(route.agent(), agent);
            assert_eq!(serde_json::to_string(&route).unwrap(), wire);
            assert_eq!(serde_json::from_str::<Route>(wire).unwrap(), route);
        }
        assert!(serde_json::from_str::<Route>("\"open_ai\"").is_err());
    }
}
