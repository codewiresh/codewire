//! `cw host` and `cw hosts` (#3609, slice 1): computers that provide VMs.
//!
//! A host here is a VM provider, not a trusted host environment
//! (`--type host`, `cw member`). Enrolling registers this computer and keeps
//! its Ed25519 key in the OS keyring; it installs and starts nothing. `cw
//! host run` is the host agent, in the foreground. `cw host service install`
//! is the opt-in that keeps it running (design rev 4).
//!
//! The key is read from the keyring only to sign, held in memory that is
//! wiped when dropped, and never written anywhere else.

use std::path::Path;
use std::sync::Arc;

use codewire_client::hosts::{
    EnrollHostRequest, GetHostRequest, GrantHostRequest, Host, HostAgentClient, HostClient,
    HostEvent, HostLimits, HostPlatform, HostState, LeaveHostRequest, ListHostsRequest,
    RevokeHostGrantRequest, RevokeHostRequest, UpdateHostProvideRequest, enrollment_statement,
    grant_host_request, revoke_host_grant_request,
};
use codewire_client::{ClientError, ErrorCode};
use codewire_protected_store::{
    OsProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedValue,
};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use super::*;

/// The host capability this `cw` offers. Slice 1 carries liveness only.
pub(crate) const HOST_CAPABILITY_VERSION: u32 = 1;
/// The keyring entries holding host keys: one per enrollment, so two
/// configurations on one computer (say Dev and Production) never share one.
const HOST_KEY_ENTRY_PREFIX: &str = "host/ed25519/";
/// This computer's enrollment, beside the platform config.
const ENROLLMENT_FILE: &str = "host.json";
/// What the running agent last reported, for `cw host status`.
const AGENT_STATUS_FILE: &str = "host-agent.json";
/// How long the agent waits before retrying a locked keyring.
const KEY_RETRY: Duration = Duration::from_secs(30);
/// The longest wait between reconnects.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub(crate) const HOST_LONG_ABOUT: &str =
    "Let this computer provide VMs for your organization's environments.

A host here is a computer that runs Codewire VMs. It is not a trusted host
environment (`--type host`, `cw member`).

  cw host enroll [--name NAME]   register this computer; installs and starts nothing
  cw host run                    the host agent, in the foreground; Ctrl-C stops it
  cw host service install        opt in to keeping the agent running (systemd --user
                                 on Linux, a LaunchAgent on macOS)
  cw host provide --max-vms N    offer VMs, with limits; --off stops offering
  cw host status                 enrollment, agent, service and what Codewire sees
  cw host grant HOST --user ID   let a member place environments here
  cw host revoke HOST            revoke a host for good (owner or organization admin)
  cw host leave                  remove this computer's host
  cw hosts                       list your organization's hosts

Enrolling grants nothing: only you may use the host until you provide and
grant it. The host key stays in the OS keyring (Secret Service, Keychain). If
the keyring is locked, for example after a reboot with nobody logged in, the
agent waits and `cw host status` says so.";

#[derive(Debug, Subcommand)]
pub(crate) enum HostCommand {
    #[command(about = "Register this computer as a host; installs and starts nothing")]
    Enroll(HostEnrollArgs),
    #[command(about = "Run the host agent in the foreground")]
    Run,
    #[command(about = "Show this computer's host: enrollment, agent, service and state")]
    Status(HostOutputArgs),
    #[command(about = "Offer VMs from this host, with limits; --off stops offering")]
    Provide(HostProvideArgs),
    #[command(about = "Let a member, or the whole organization, place environments on a host")]
    Grant(HostGrantArgs),
    #[command(about = "Take back a grant")]
    Ungrant(HostGrantArgs),
    #[command(about = "Revoke a host for good (its owner or an organization admin)")]
    Revoke(HostRevokeArgs),
    #[command(about = "Remove this computer's host, its key and its service")]
    Leave(HostLeaveArgs),
    #[command(about = "Install, remove or show the service that keeps the agent running")]
    Service {
        #[command(subcommand)]
        command: HostServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum HostServiceCommand {
    #[command(about = "Keep `cw host run` running, under systemd --user or launchd")]
    Install,
    #[command(about = "Stop the service and remove what `install` wrote")]
    Uninstall,
    #[command(about = "Show whether the service is installed and running")]
    Status,
}

#[derive(Debug, Args)]
pub(crate) struct HostOutputArgs {
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct HostEnrollArgs {
    #[arg(
        long,
        help = "The host's name in the organization (default: this computer's name)"
    )]
    name: Option<String>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct HostProvideArgs {
    #[arg(long, value_name = "N", help = "The most VMs at once (1 to 1024)")]
    max_vms: Option<u32>,
    #[arg(long, value_name = "N", help = "The most vCPUs across them")]
    max_vcpus: Option<u32>,
    #[arg(
        long,
        value_name = "SIZE",
        help = "The most memory across them, e.g. 8G or 512M"
    )]
    max_memory: Option<String>,
    #[arg(
        long,
        value_name = "SIZE",
        help = "The most disk across them, e.g. 200G or 1T"
    )]
    max_disk: Option<String>,
    #[arg(long, conflicts_with_all = ["max_vms", "max_vcpus", "max_memory", "max_disk"], help = "Stop offering VMs; the limits are kept")]
    off: bool,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct HostGrantArgs {
    #[arg(
        value_name = "HOST",
        help = "The host's name or ID (default: this computer's host)"
    )]
    host: Option<String>,
    #[arg(
        long,
        value_name = "ID",
        conflicts_with = "organization",
        required_unless_present = "organization",
        help = "The member's user ID"
    )]
    user: Option<String>,
    #[arg(long, help = "Every member of the organization")]
    organization: bool,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct HostRevokeArgs {
    #[arg(value_name = "HOST", help = "The host's name or ID")]
    host: String,
    #[arg(short, long, help = "Revoke without asking for confirmation")]
    yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct HostLeaveArgs {
    #[arg(short, long, help = "Leave without asking for confirmation")]
    yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct HostsArgs {
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

/// This computer's enrollment. It holds no secret: the key is in the
/// keyring.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Enrollment {
    pub host_id: String,
    pub org_id: String,
    pub name: String,
    pub server_url: String,
    /// The keyring entry holding this host's key: a name, not a secret.
    pub key_entry: String,
    /// The CA `cw login --ca-file` pinned, copied beside this file (#4121).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_ca: Option<config::PinnedCa>,
}

/// What the running agent last reported.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentStatus {
    pub pid: u32,
    /// `attaching`, `attached`, `waiting_for_key`, `reconnecting`,
    /// `unrecognised`, `revoked` or `stopped`.
    pub state: String,
    pub detail: String,
    pub since: String,
}

// ── Pure helpers ──────────────────────────────────────────────────────────

/// The same rule as the server: a DNS label.
pub(crate) fn valid_host_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A host name from a computer name: lowercase, other characters as '-',
/// trimmed to a DNS label. None when nothing usable is left.
pub(crate) fn host_name_from(computer: &str) -> Option<String> {
    let first = computer.split('.').next().unwrap_or_default();
    let mut name: String = first
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9') => c,
            _ => '-',
        })
        .collect();
    while name.contains("--") {
        name = name.replace("--", "-");
    }
    let name: String = name.trim_matches('-').chars().take(63).collect();
    let name = name.trim_end_matches('-').to_owned();
    valid_host_name(&name).then_some(name)
}

/// This computer's name, as the operating system reports it.
fn computer_name() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for writes of its full length, which is the
    // length passed; gethostname writes at most that many bytes.
    let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if status != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&buffer[..end]).ok().map(str::to_owned)
}

/// The platform this computer provides, if it can provide VMs at all.
pub(crate) fn this_platform() -> anyhow::Result<HostPlatform> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => {
            anyhow::ensure!(
                Path::new("/dev/kvm").exists(),
                "this computer has no KVM (/dev/kvm), so it cannot provide VMs"
            );
            Ok(HostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM)
        }
        ("macos", "aarch64") => Ok(HostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ),
        (os, arch) => anyhow::bail!(
            "a host must be Linux on x86_64 with KVM, or macOS on Apple silicon; this is {os} on {arch}"
        ),
    }
}

/// Parses a size into `unit`s: a bare number is in `unit`, and the suffixes
/// M/MiB, G/GiB and T/TiB are binary.
pub(crate) fn parse_size(text: &str, unit_mib: u64) -> anyhow::Result<u64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, suffix) = text.split_at(split);
    let number: u64 = number
        .parse()
        .with_context(|| format!("`{text}` is not a size such as 8G or 512M"))?;
    let mib = match suffix.trim().to_ascii_lowercase().as_str() {
        "" => return Ok(number),
        "m" | "mb" | "mib" => number,
        "g" | "gb" | "gib" => number.saturating_mul(1024),
        "t" | "tb" | "tib" => number.saturating_mul(1024 * 1024),
        other => anyhow::bail!("`{other}` is not a size unit; use M, G or T"),
    };
    anyhow::ensure!(
        mib % unit_mib == 0,
        "`{text}` is not a whole number of {}",
        if unit_mib == 1024 { "GiB" } else { "MiB" }
    );
    Ok(mib / unit_mib)
}

fn state_name(state: HostState) -> &'static str {
    match state {
        HostState::HOST_STATE_ONLINE => "online",
        HostState::HOST_STATE_OFFLINE => "offline",
        HostState::HOST_STATE_REVOKED => "revoked",
        HostState::HOST_STATE_UNSPECIFIED => "unknown",
    }
}

fn platform_name(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM => "linux-x86_64-kvm",
        HostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ => "darwin-arm64-vz",
        HostPlatform::HOST_PLATFORM_UNSPECIFIED => "unknown",
    }
}

fn timestamp(value: Option<&buffa_types::Timestamp>) -> Option<String> {
    let value = value?;
    chrono::DateTime::from_timestamp(value.seconds, value.nanos.max(0) as u32)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn limits_text(host: &Host) -> String {
    let Some(limits) = host.limits.as_option() else {
        return "-".into();
    };
    let mut parts = vec![format!("{} VMs", limits.max_vms)];
    if let Some(vcpus) = limits.max_vcpus {
        parts.push(format!("{vcpus} vCPU"));
    }
    if let Some(memory) = limits.max_memory_mib {
        parts.push(format!("{} GiB memory", memory as f64 / 1024.0));
    }
    if let Some(disk) = limits.max_disk_gib {
        parts.push(format!("{disk} GiB disk"));
    }
    parts.join(", ")
}

fn host_json(host: &Host) -> serde_json::Value {
    serde_json::json!({
        "id": host.id,
        "name": host.name,
        "org_id": host.org_id,
        "owner_user_id": host.owner_user_id,
        "platform": platform_name(host.platform.as_known().unwrap_or_default()),
        "capability_version": host.capability_version,
        "state": state_name(host.state.as_known().unwrap_or_default()),
        "provide": host.provide,
        "limits": host.limits.as_option().map(|limits| serde_json::json!({
            "max_vms": limits.max_vms,
            "max_vcpus": limits.max_vcpus,
            "max_memory_mib": limits.max_memory_mib,
            "max_disk_gib": limits.max_disk_gib,
        })),
        "organization_grant": host.organization_grant,
        "granted_user_ids": host.granted_user_ids,
        "created_at": timestamp(host.created_at.as_option()),
        "last_seen_at": timestamp(host.last_seen_at.as_option()),
        "revoked_at": timestamp(host.revoked_at.as_option()),
    })
}

// ── Local state ───────────────────────────────────────────────────────────

fn config_dir() -> anyhow::Result<PathBuf> {
    Ok(ResolvePaths::from_env(&OsEnv)?.platform_config_dir)
}

fn read_enrollment(dir: &Path) -> anyhow::Result<Option<Enrollment>> {
    match fs::read(dir.join(ENROLLMENT_FILE)) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("read this computer's host enrollment")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read this computer's host enrollment"),
    }
}

fn enrolled(dir: &Path) -> anyhow::Result<Enrollment> {
    read_enrollment(dir)?
        .context("this computer is not enrolled as a host; run `cw host enroll` first")
}

fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(())
}

fn write_agent_status(dir: &Path, state: &str, detail: impl Into<String>) {
    let status = AgentStatus {
        pid: std::process::id(),
        state: state.into(),
        detail: detail.into(),
        since: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    // The status file is a convenience for `cw host status`; failing to
    // write it never stops the agent.
    let _ = super::host::write_private_json(&dir.join(AGENT_STATUS_FILE), &status);
}

fn read_agent_status(dir: &Path) -> Option<AgentStatus> {
    serde_json::from_slice(&fs::read(dir.join(AGENT_STATUS_FILE)).ok()?).ok()
}

fn process_alive(pid: u32) -> bool {
    // Signal 0 checks existence without sending anything.
    rustix::process::Pid::from_raw(pid as i32)
        .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
}

// ── The key ───────────────────────────────────────────────────────────────

/// A fresh keyring entry name for a new enrollment.
fn new_key_entry() -> String {
    format!("{HOST_KEY_ENTRY_PREFIX}{}", uuid::Uuid::new_v4())
}

fn key_entry(name: &str) -> Result<ProtectedEntryId, ProtectedStoreError> {
    if !name.starts_with(HOST_KEY_ENTRY_PREFIX) {
        return Err(ProtectedStoreError::InvalidEntryId);
    }
    ProtectedEntryId::parse(name)
}

fn keyring_error(error: ProtectedStoreError) -> anyhow::Error {
    match error {
        ProtectedStoreError::AccessDenied => anyhow::anyhow!(
            "the OS keyring is locked or inaccessible; unlock it (log in to this computer) and retry"
        ),
        other => anyhow::anyhow!("the OS keyring could not be used: {other}"),
    }
}

/// Reads the host key, off the async runtime: the keyring calls block.
async fn read_key(entry: &str) -> Result<Option<SigningKey>, ProtectedStoreError> {
    let entry = key_entry(entry)?;
    tokio::task::spawn_blocking(move || {
        let Some(value) = OsProtectedStore.get(&entry)? else {
            return Ok(None);
        };
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(value.expose_secret())
                .map_err(|_| ProtectedStoreError::CorruptEntry)?,
        );
        Ok(Some(SigningKey::from_bytes(&seed)))
    })
    .await
    .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

async fn store_key(entry: &str, key: &SigningKey) -> Result<(), ProtectedStoreError> {
    let entry = key_entry(entry)?;
    let value = ProtectedValue::from_slice(key.as_bytes())?;
    tokio::task::spawn_blocking(move || OsProtectedStore.put(&entry, &value))
        .await
        .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

async fn delete_key(entry: &str) -> Result<(), ProtectedStoreError> {
    let entry = key_entry(entry)?;
    tokio::task::spawn_blocking(move || OsProtectedStore.delete(&entry))
        .await
        .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

fn new_key() -> SigningKey {
    use rand::RngCore as _;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    SigningKey::from_bytes(&seed)
}

// ── Clients ───────────────────────────────────────────────────────────────

struct Signed {
    platform: config::ResolvedPlatformConfig,
    hosts: HostClient,
    org_id: String,
}

async fn signed_in(globals: &Globals) -> anyhow::Result<Signed> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list organizations")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let hosts = HostClient::new(platform.client_config()?, platform.token_provider()?)?;
    Ok(Signed {
        platform,
        hosts,
        org_id,
    })
}

fn client_error(error: ClientError) -> anyhow::Error {
    display_client_error(error)
}

/// A host of the organization by name or ID; the enrolled host when none is
/// named.
async fn resolve_host(signed: &Signed, named: Option<&str>) -> anyhow::Result<Host> {
    let named = match named {
        Some(named) => named.to_owned(),
        None => enrolled(&config_dir()?)?.host_id,
    };
    let hosts = signed
        .hosts
        .list_hosts(ListHostsRequest {
            org_id: signed.org_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(client_error)?
        .hosts;
    if let Some(host) = hosts.iter().find(|host| host.id == named) {
        return Ok(host.clone());
    }
    // A revoked host's name may be reused, so prefer the live one.
    let mut matching: Vec<&Host> = hosts.iter().filter(|host| host.name == named).collect();
    matching.sort_by_key(|host| host.state.as_known() == Some(HostState::HOST_STATE_REVOKED));
    match matching.as_slice() {
        [] => anyhow::bail!("no host named `{named}` in this organization; see `cw hosts`"),
        [host, ..] => Ok((*host).clone()),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────

pub(crate) async fn handle_hosts_command(globals: &Globals, args: HostsArgs) -> anyhow::Result<()> {
    let signed = signed_in(globals).await?;
    let hosts = signed
        .hosts
        .list_hosts(ListHostsRequest {
            org_id: signed.org_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(client_error)?
        .hosts;
    let this = read_enrollment(&config_dir()?)?.map(|enrollment| enrollment.host_id);
    if matches!(args.output, OutputFormat::Json) {
        println!(
            "{}",
            serde_json::to_string_pretty(&hosts.iter().map(host_json).collect::<Vec<_>>())?
        );
        return Ok(());
    }
    if hosts.is_empty() {
        println!("No hosts in this organization. Run `cw host enroll` on a computer to add one.");
        return Ok(());
    }
    println!(
        "{:<24} {:<18} {:<9} {:<34} LAST SEEN",
        "NAME", "PLATFORM", "STATE", "PROVIDES"
    );
    for host in &hosts {
        let mut name = host.name.clone();
        if this.as_deref() == Some(host.id.as_str()) {
            name.push_str(" (this)");
        }
        let provides = if host.provide {
            limits_text(host)
        } else {
            "not providing".into()
        };
        println!(
            "{:<24} {:<18} {:<9} {:<34} {}",
            name,
            platform_name(host.platform.as_known().unwrap_or_default()),
            state_name(host.state.as_known().unwrap_or_default()),
            provides,
            timestamp(host.last_seen_at.as_option()).unwrap_or_else(|| "never".into()),
        );
    }
    Ok(())
}

pub(crate) async fn handle_host_command(
    globals: &Globals,
    command: HostCommand,
) -> anyhow::Result<()> {
    match command {
        HostCommand::Enroll(args) => enroll(globals, args).await,
        HostCommand::Run => run(globals).await,
        HostCommand::Status(args) => status(globals, args).await,
        HostCommand::Provide(args) => provide(globals, args).await,
        HostCommand::Grant(args) => grant(globals, args, true).await,
        HostCommand::Ungrant(args) => grant(globals, args, false).await,
        HostCommand::Revoke(args) => revoke(globals, args).await,
        HostCommand::Leave(args) => leave(globals, args).await,
        HostCommand::Service { command } => service::handle(command),
    }
}

async fn enroll(globals: &Globals, args: HostEnrollArgs) -> anyhow::Result<()> {
    let dir = config_dir()?;
    if let Some(enrollment) = read_enrollment(&dir)? {
        anyhow::bail!(
            "this computer is already enrolled as host `{}` ({}); run `cw host leave` first",
            enrollment.name,
            enrollment.host_id
        );
    }
    let platform = this_platform()?;
    let name = match args.name {
        Some(name) => {
            anyhow::ensure!(
                valid_host_name(&name),
                "`{name}` is not a host name: use 1 to 63 lowercase letters, digits and '-'"
            );
            name
        }
        None => computer_name()
            .as_deref()
            .and_then(host_name_from)
            .context("this computer's name is not usable as a host name; pass --name")?,
    };
    let signed = signed_in(globals).await?;
    let user = current_platform_user(
        &codewire_client(&signed.platform)?,
        &signed.platform.oauth_client()?,
    )
    .await?;

    // The key goes into the keyring first, so a failure there leaves no host
    // record behind.
    let key = new_key();
    let entry = new_key_entry();
    store_key(&entry, &key).await.map_err(keyring_error)?;
    let public_key = key.verifying_key().to_bytes().to_vec();
    let signature = key
        .sign(&enrollment_statement(&signed.org_id, &user.id, &public_key))
        .to_bytes()
        .to_vec();
    let enrolled = signed
        .hosts
        .enroll_host(EnrollHostRequest {
            org_id: signed.org_id.clone(),
            name: name.clone(),
            platform: platform.into(),
            capability_version: HOST_CAPABILITY_VERSION,
            public_key,
            enrollment_signature: signature,
            ..Default::default()
        })
        .await;
    let host = match enrolled {
        Ok(response) => response
            .host
            .into_option()
            .context("the server returned no host")?,
        Err(error) => {
            let _ = delete_key(&entry).await;
            return Err(client_error(error));
        }
    };
    let enrollment = Enrollment {
        host_id: host.id.clone(),
        org_id: host.org_id.clone(),
        name: host.name.clone(),
        server_url: signed.platform.server_url.clone(),
        key_entry: entry,
        deployment_ca: config::pin_for_host(
            &signed.platform,
            &ResolvePaths::from_env(&OsEnv)?.platform_config_dir,
            &dir,
        )?,
    };
    let written = ensure_private_dir(&dir)
        .and_then(|()| super::host::write_private_json(&dir.join(ENROLLMENT_FILE), &enrollment));
    if let Err(error) = written {
        // Without the local record nothing could use or remove this host, so
        // undo it rather than leave an orphan the next enroll duplicates.
        let left = signed
            .hosts
            .leave_host(LeaveHostRequest {
                org_id: enrollment.org_id.clone(),
                host_id: enrollment.host_id.clone(),
                ..Default::default()
            })
            .await;
        let _ = delete_key(&enrollment.key_entry).await;
        let outcome = match left {
            Ok(_) => "the enrollment was undone".to_owned(),
            Err(_) => format!(
                "host `{}` ({}) remains on the server; revoke it with `cw host revoke {}`",
                enrollment.name, enrollment.host_id, enrollment.host_id
            ),
        };
        return Err(error.context(format!("save this computer's host enrollment; {outcome}")));
    }
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&host_json(&host))?);
        return Ok(());
    }
    println!(
        "Enrolled this computer as host `{}` ({}).",
        host.name, host.id
    );
    println!("Its key is in the OS keyring. Nothing is running yet, and nothing is offered.");
    println!("Next:");
    println!("  cw host run                  run the agent now, in this terminal");
    println!("  cw host service install      or keep it running in the background");
    println!("  cw host provide --max-vms 2  offer VMs, with limits");
    Ok(())
}

async fn status(globals: &Globals, args: HostOutputArgs) -> anyhow::Result<()> {
    let dir = config_dir()?;
    let enrollment = enrolled(&dir)?;
    let agent = read_agent_status(&dir).filter(|status| process_alive(status.pid));
    let service = service::state();
    let signed = signed_in(globals).await?;
    let host = signed
        .hosts
        .get_host(GetHostRequest {
            org_id: enrollment.org_id.clone(),
            host_id: enrollment.host_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(client_error)?
        .host
        .into_option()
        .context("the server returned no host")?;
    if matches!(args.output, OutputFormat::Json) {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "enrollment": enrollment,
                "host": host_json(&host),
                "agent": agent,
                "service": service.to_string(),
                "cw_version": CLI_VERSION,
            }))?
        );
        return Ok(());
    }
    println!("Host:      {} ({})", host.name, host.id);
    println!("Server:    {}", enrollment.server_url);
    println!(
        "State:     {}{}",
        state_name(host.state.as_known().unwrap_or_default()),
        timestamp(host.last_seen_at.as_option())
            .map(|seen| format!(", last seen {seen}"))
            .unwrap_or_else(|| ", never seen".into())
    );
    println!(
        "Provides:  {}",
        if host.provide {
            limits_text(&host)
        } else {
            "nothing (`cw host provide` to offer VMs)".into()
        }
    );
    let grants = match (host.organization_grant, host.granted_user_ids.len()) {
        (true, _) => "the whole organization".to_owned(),
        (false, 0) => "only you".to_owned(),
        (false, count) => format!("you and {count} member(s)"),
    };
    println!("Used by:   {grants}");
    match &agent {
        Some(agent) => println!(
            "Agent:     {} since {} (pid {}){}",
            agent.state.replace('_', " "),
            agent.since,
            agent.pid,
            if agent.detail.is_empty() {
                String::new()
            } else {
                format!(": {}", agent.detail)
            }
        ),
        None => println!("Agent:     not running (`cw host run`, or `cw host service install`)"),
    }
    println!("Service:   {service}");
    println!("cw:        {}", CLI_VERSION);
    Ok(())
}

async fn provide(globals: &Globals, args: HostProvideArgs) -> anyhow::Result<()> {
    let signed = signed_in(globals).await?;
    let host = resolve_host(&signed, None).await?;
    let limits = if args.off {
        None
    } else {
        let max_vms = args
            .max_vms
            .context("--max-vms is required to provide VMs (or --off to stop)")?;
        Some(HostLimits {
            max_vms,
            max_vcpus: args.max_vcpus,
            max_memory_mib: args
                .max_memory
                .as_deref()
                .map(|size| parse_size(size, 1))
                .transpose()?,
            max_disk_gib: args
                .max_disk
                .as_deref()
                .map(|size| parse_size(size, 1024))
                .transpose()?,
            ..Default::default()
        })
    };
    let host = signed
        .hosts
        .update_host_provide(UpdateHostProvideRequest {
            org_id: signed.org_id.clone(),
            host_id: host.id,
            provide: !args.off,
            limits: limits.into(),
            ..Default::default()
        })
        .await
        .map_err(client_error)?
        .host
        .into_option()
        .context("the server returned no host")?;
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&host_json(&host))?);
    } else if host.provide {
        println!("Host `{}` provides VMs: {}.", host.name, limits_text(&host));
    } else {
        println!("Host `{}` no longer offers VMs.", host.name);
    }
    Ok(())
}

async fn grant(globals: &Globals, args: HostGrantArgs, give: bool) -> anyhow::Result<()> {
    let signed = signed_in(globals).await?;
    let host = resolve_host(&signed, args.host.as_deref()).await?;
    let response = if give {
        let grantee = match &args.user {
            Some(user) => grant_host_request::Grantee::UserId(user.clone()),
            None => grant_host_request::Grantee::Organization(true),
        };
        signed
            .hosts
            .grant_host(GrantHostRequest {
                org_id: signed.org_id.clone(),
                host_id: host.id,
                grantee: Some(grantee),
                ..Default::default()
            })
            .await
            .map(|response| response.host)
    } else {
        let grantee = match &args.user {
            Some(user) => revoke_host_grant_request::Grantee::UserId(user.clone()),
            None => revoke_host_grant_request::Grantee::Organization(true),
        };
        signed
            .hosts
            .revoke_host_grant(RevokeHostGrantRequest {
                org_id: signed.org_id.clone(),
                host_id: host.id,
                grantee: Some(grantee),
                ..Default::default()
            })
            .await
            .map(|response| response.host)
    };
    let host = response
        .map_err(client_error)?
        .into_option()
        .context("the server returned no host")?;
    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&host_json(&host))?);
        return Ok(());
    }
    let who = args
        .user
        .as_deref()
        .map_or("the whole organization".to_owned(), |user| {
            format!("member {user}")
        });
    if give {
        println!("Host `{}` may now be used by {who}.", host.name);
    } else {
        println!("Host `{}` may no longer be used by {who}.", host.name);
    }
    Ok(())
}

fn confirm(question: &str) -> anyhow::Result<()> {
    use std::io::{IsTerminal as _, Write as _};
    anyhow::ensure!(
        std::io::stdin().is_terminal(),
        "{question} Pass --yes to confirm outside a terminal."
    );
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    anyhow::ensure!(
        matches!(answer.trim(), "y" | "Y" | "yes"),
        "cancelled; nothing changed"
    );
    Ok(())
}

async fn revoke(globals: &Globals, args: HostRevokeArgs) -> anyhow::Result<()> {
    let signed = signed_in(globals).await?;
    let host = resolve_host(&signed, Some(&args.host)).await?;
    if !args.yes {
        confirm(&format!(
            "Revoke host `{}` ({}) for good? It can never attach again.",
            host.name, host.id
        ))?;
    }
    let host = signed
        .hosts
        .revoke_host(RevokeHostRequest {
            org_id: signed.org_id.clone(),
            host_id: host.id,
            ..Default::default()
        })
        .await
        .map_err(client_error)?
        .host
        .into_option()
        .context("the server returned no host")?;
    println!("Host `{}` is revoked.", host.name);
    Ok(())
}

async fn leave(globals: &Globals, args: HostLeaveArgs) -> anyhow::Result<()> {
    let dir = config_dir()?;
    let enrollment = enrolled(&dir)?;
    if !args.yes {
        confirm(&format!(
            "Remove host `{}` ({}) and this computer's host key?",
            enrollment.name, enrollment.host_id
        ))?;
    }
    let signed = signed_in(globals).await?;
    let left = signed
        .hosts
        .leave_host(LeaveHostRequest {
            org_id: enrollment.org_id.clone(),
            host_id: enrollment.host_id.clone(),
            ..Default::default()
        })
        .await;
    match left {
        Ok(_) => println!("Removed host `{}`.", enrollment.name),
        // A revoked host's record stays for good; this computer is let go
        // all the same.
        Err(error) if error.code() == ErrorCode::FailedPrecondition => println!(
            "Host `{}` was revoked, so its record stays; this computer is no longer enrolled.",
            enrollment.name
        ),
        Err(error) if error.code() == ErrorCode::NotFound => println!(
            "Host `{}` no longer exists; this computer is no longer enrolled.",
            enrollment.name
        ),
        Err(error) => return Err(client_error(error)),
    }
    if service::state() != service::ServiceState::NotInstalled {
        service::uninstall()?;
    }
    delete_key(&enrollment.key_entry)
        .await
        .map_err(keyring_error)?;
    for file in [
        ENROLLMENT_FILE,
        AGENT_STATUS_FILE,
        config::DEPLOYMENT_CA_FILE,
    ] {
        match fs::remove_file(dir.join(file)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("remove {file}"));
            }
            _ => {}
        }
    }
    Ok(())
}

// ── The agent ─────────────────────────────────────────────────────────────

/// How long the agent waits before trying again when Codewire does not
/// recognise the host: long, because it rarely heals, but not forever,
/// because a server-side fault would otherwise strand every host.
const UNRECOGNISED_RETRY: Duration = Duration::from_secs(300);

/// Why one session ended.
enum SessionEnd {
    /// The host was revoked: stop for good.
    Final(String),
    /// Try again after a pause. `attached` says the session had attached,
    /// so the pause starts short again.
    Retry { reason: String, attached: bool },
    /// Codewire does not recognise the host or its key: try again, rarely.
    Unrecognised(String),
    /// Ctrl-C or SIGTERM.
    Stopped,
}

/// Resolves when the agent is asked to stop: Ctrl-C at a terminal, or
/// SIGTERM from a service manager (`systemctl stop`, `launchctl bootout`).
struct StopSignal(tokio::sync::watch::Receiver<bool>);

impl StopSignal {
    fn listen() -> anyhow::Result<Self> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("listen for SIGTERM")?;
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            let _ = stop.send(true);
        });
        Ok(Self(stopped))
    }

    async fn requested(&mut self) {
        let _ = self.0.wait_for(|stop| *stop).await;
    }
}

async fn run(_globals: &Globals) -> anyhow::Result<()> {
    let dir = config_dir()?;
    let enrollment = enrolled(&dir)?;
    let platform = this_platform()?;
    let agent = HostAgentClient::new(config::host_client_config(
        &enrollment.server_url,
        &dir,
        enrollment.deployment_ca.as_ref(),
    )?)?;
    eprintln!(
        "Host agent for `{}` ({}) on {}. Ctrl-C stops it.",
        enrollment.name, enrollment.host_id, enrollment.server_url
    );
    let mut stop = StopSignal::listen()?;
    let mut backoff = Duration::from_secs(1);
    loop {
        // The key is read for each session, so unlocking the keyring is
        // noticed without a restart.
        let key = match read_key(&enrollment.key_entry).await {
            Ok(Some(key)) => Arc::new(key),
            Ok(None) => {
                write_agent_status(&dir, "stopped", "the host key is missing");
                anyhow::bail!(
                    "this computer's host key is missing from the OS keyring; run `cw host leave` and `cw host enroll` again"
                );
            }
            Err(error) => {
                let detail = match error {
                    ProtectedStoreError::AccessDenied => {
                        "waiting for a login to unlock the OS keyring that holds the host key"
                            .to_owned()
                    }
                    other => format!("the OS keyring is unavailable: {other}"),
                };
                write_agent_status(&dir, "waiting_for_key", &detail);
                eprintln!("{detail}; retrying in {}s", KEY_RETRY.as_secs());
                if wait_or_stop(KEY_RETRY, &mut stop).await {
                    break;
                }
                continue;
            }
        };
        write_agent_status(&dir, "attaching", "");
        match session(&agent, &enrollment, platform, &key, &dir, &mut stop).await {
            SessionEnd::Stopped => break,
            SessionEnd::Final(reason) => {
                write_agent_status(&dir, "revoked", &reason);
                eprintln!("{reason}");
                return Ok(());
            }
            SessionEnd::Unrecognised(reason) => {
                write_agent_status(&dir, "unrecognised", &reason);
                eprintln!(
                    "{reason}; trying again in {}s",
                    UNRECOGNISED_RETRY.as_secs()
                );
                if wait_or_stop(UNRECOGNISED_RETRY, &mut stop).await {
                    break;
                }
            }
            SessionEnd::Retry { reason, attached } => {
                // A session that attached starts the pause short again.
                if attached {
                    backoff = Duration::from_secs(1);
                }
                write_agent_status(&dir, "reconnecting", &reason);
                eprintln!("{reason}; reconnecting in {}s", backoff.as_secs());
                if wait_or_stop(backoff, &mut stop).await {
                    break;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
    write_agent_status(&dir, "stopped", "");
    Ok(())
}

/// Waits, or returns true when asked to stop.
async fn wait_or_stop(duration: Duration, stop: &mut StopSignal) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        () = stop.requested() => true,
    }
}

fn ended(error: ClientError) -> SessionEnd {
    match error.code() {
        ErrorCode::PermissionDenied => SessionEnd::Final(
            "this host is revoked; it cannot attach again (`cw host leave` to clean up)".into(),
        ),
        ErrorCode::Unauthenticated => SessionEnd::Unrecognised(
            "Codewire does not recognise this host or its key; if it was removed, run `cw host leave` and `cw host enroll` again"
                .into(),
        ),
        _ => SessionEnd::Retry {
            reason: format!("the session ended: {}", error.message()),
            attached: false,
        },
    }
}

async fn session(
    agent: &HostAgentClient,
    enrollment: &Enrollment,
    platform: HostPlatform,
    key: &Arc<SigningKey>,
    dir: &Path,
    stop: &mut StopSignal,
) -> SessionEnd {
    let sign = |statement: &[u8]| key.sign(statement).to_bytes().to_vec();
    let attached = tokio::select! {
        attached = agent.attach(&enrollment.host_id, platform, HOST_CAPABILITY_VERSION, sign) => attached,
        () = stop.requested() => return SessionEnd::Stopped,
    };
    let mut host = match attached {
        Ok(host) => host,
        Err(error) => return ended(error),
    };
    write_agent_status(dir, "attached", "");
    eprintln!("Attached: this host is online.");
    let ping_every = Duration::from_secs(u64::from(host.attached.ping_interval_seconds.max(1)));
    let mut pings = tokio::time::interval_at(tokio::time::Instant::now() + ping_every, ping_every);
    loop {
        tokio::select! {
            _ = pings.tick() => {
                if let Err(error) = host.ping().await {
                    return attached_end(ended(error));
                }
            }
            event = host.next_event() => match event {
                Ok(HostEvent::Pong) => {}
                Ok(HostEvent::Challenge(nonce)) => {
                    if let Err(error) = host.prove(&nonce, sign).await {
                        return attached_end(ended(error));
                    }
                }
                Ok(HostEvent::Revoked) => {
                    return SessionEnd::Final("this host was revoked; the agent stops".into());
                }
                Ok(HostEvent::Superseded) => {
                    return attached_end(SessionEnd::Retry {
                        reason: "another agent for this host attached".into(),
                        attached: false,
                    });
                }
                Ok(HostEvent::Ended) => {
                    return attached_end(SessionEnd::Retry {
                        reason: "the session ended".into(),
                        attached: false,
                    });
                }
                Err(error) => return attached_end(ended(error)),
            },
            () = stop.requested() => return SessionEnd::Stopped,
        }
    }
}

/// Marks a retry after an attached session, so the pause starts short again.
fn attached_end(end: SessionEnd) -> SessionEnd {
    match end {
        SessionEnd::Retry { reason, .. } => SessionEnd::Retry {
            reason,
            attached: true,
        },
        other => other,
    }
}

// ── The service ───────────────────────────────────────────────────────────

pub(crate) mod service;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computer_names_become_host_names() {
        assert_eq!(
            host_name_from("Noel-MacBook-Pro.local").as_deref(),
            Some("noel-macbook-pro")
        );
        assert_eq!(host_name_from("build_box").as_deref(), Some("build-box"));
        assert_eq!(host_name_from("--x--y--").as_deref(), Some("x-y"));
        assert_eq!(
            host_name_from(&"a".repeat(80)).map(|name| name.len()),
            Some(63)
        );
        assert_eq!(host_name_from("***"), None);
        assert_eq!(host_name_from(""), None);
    }

    #[test]
    fn host_names_are_the_servers_dns_labels() {
        for name in ["a", "build-box", &"a".repeat(63)] {
            assert!(valid_host_name(name), "{name}");
        }
        for name in ["", "-a", "a-", "Build", "a_b", &"a".repeat(64)] {
            assert!(!valid_host_name(name), "{name}");
        }
    }

    #[test]
    fn each_enrollment_has_its_own_host_key_entry() {
        let (first, second) = (new_key_entry(), new_key_entry());
        assert_ne!(first, second);
        assert!(key_entry(&first).is_ok());
        // Only host key entries, never another credential's.
        assert_eq!(
            key_entry("local/credentials/x/material-v1").unwrap_err(),
            ProtectedStoreError::InvalidEntryId
        );
    }

    #[test]
    fn sizes_parse_in_binary_units() {
        assert_eq!(parse_size("8G", 1).unwrap(), 8192);
        assert_eq!(parse_size("512M", 1).unwrap(), 512);
        assert_eq!(parse_size("8192", 1).unwrap(), 8192);
        assert_eq!(parse_size("200G", 1024).unwrap(), 200);
        assert_eq!(parse_size("1T", 1024).unwrap(), 1024);
        assert_eq!(parse_size("200", 1024).unwrap(), 200);
        assert!(parse_size("1500M", 1024).is_err());
        assert!(parse_size("8X", 1).is_err());
        assert!(parse_size("lots", 1).is_err());
    }

    #[test]
    fn the_systemd_unit_runs_the_agent_and_is_marked() {
        let unit = service::systemd_unit(Path::new("/home/u/.local/bin/cw"), None);
        assert!(unit.starts_with(&format!("# {}", service::MARKER)));
        assert!(unit.contains("\nExecStart=/home/u/.local/bin/cw host run\n"));
        assert!(unit.contains("\nRestart=on-failure\n"));
        assert!(!unit.contains("Environment="));
        let unit = service::systemd_unit(Path::new("/cw"), Some("/home/u/cfg"));
        assert!(unit.contains("\nEnvironment=CW_CONFIG_DIR=/home/u/cfg\n"));
    }

    #[test]
    fn service_files_refuse_values_they_cannot_carry() {
        service::service_value("/home/u/.config/codewire", "CW_CONFIG_DIR").unwrap();
        for (class, value) in [
            ("whitespace", "/home/u/my cfg"),
            ("a tab", "/home/u/a\tb"),
            ("a newline", "/home/u/cfg\nExecStartPre=/bin/sh"),
            ("a control character", "/home/u/\u{1b}cfg"),
            ("a systemd specifier", "/home/%u/cfg"),
            ("a double quote", "/home/u/\"cfg"),
            ("a single quote", "/home/u/'cfg"),
            ("a backslash", "/home/u/\\cfg"),
            ("a dollar", "/home/$USER/cfg"),
            ("a plist tag", "/home/u/<cfg>"),
            ("a plist entity", "/home/u/a&b"),
        ] {
            assert!(
                service::service_value(value, "CW_CONFIG_DIR").is_err(),
                "{class}"
            );
        }
    }

    #[test]
    fn the_launch_agent_runs_the_agent_and_is_marked() {
        let plist = service::launch_agent(
            "sh.codewire.host",
            Path::new("/usr/local/bin/cw"),
            None,
            Path::new("/Users/u/Library/Logs/codewire-host.log"),
        );
        assert!(plist.contains(service::MARKER));
        assert!(plist.contains("<string>/usr/local/bin/cw</string>\n    <string>host</string>\n    <string>run</string>"));
        assert!(plist.contains("<key>SuccessfulExit</key>\n    <false/>"));
        assert!(!plist.contains("CW_CONFIG_DIR"));
    }

    #[test]
    fn the_enrollment_file_round_trips_and_refuses_unknown_fields() {
        let enrollment = Enrollment {
            host_id: "00000000-0000-4000-8000-000000000001".into(),
            org_id: "org".into(),
            name: "build-box".into(),
            server_url: "https://codewire.sh".into(),
            key_entry: "host/ed25519/00000000-0000-4000-8000-000000000002".into(),
            deployment_ca: None,
        };
        let text = serde_json::to_string(&enrollment).unwrap();
        assert_eq!(
            serde_json::from_str::<Enrollment>(&text).unwrap(),
            enrollment
        );
        assert!(serde_json::from_str::<Enrollment>(&text.replace('}', ",\"key\":\"x\"}")).is_err());
    }
}
