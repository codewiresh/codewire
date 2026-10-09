//! Fixed platform Guest records and original-generation intake. No registry,
//! provider resolution, user configuration, daemon startup or network authority.
//! The helper borrows only strict directory/record IO from Host's helper, never
//! its network/grant/book authority or member-origin marker.
use super::*;
use anyhow::ensure;
use host_control::{DirectoryPin, private_record};
use std::os::unix::fs::DirBuilderExt;

const STATE: &str = "/home/codewire/.local/state/codewire/platform-managed-agents-v1";
const ORIGIN: &str = "platform-origin.json";
const GENERATION: &str = "platform-generation.json";
mod proxy;
const REQUEST_BYTES: u64 = 512 * 1024;
const RESPONSE_BYTES: usize = 5 * 1024 * 1024;

// Intentionally private wire, atomically identical to daemon::platform_managed.
// Pod/org correlation is authenticated by the ORIGINAL captured Pod channel;
// this helper cannot discover/prove a live Kubernetes Pod incarnation itself.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Origin {
    version: u32,
    environment_id: String,
    org_id: String,
    pod_uid: String,
    binding_generation: u64,
    projection_selection_sha256: [u8; 32],
    driver_id: String,
    agent: AgentKind,
    support_image_sha256: [u8; 32],
    support_image_size: u64,
    provider: codewire_daemon::platform_managed::ProviderIdentity,
    parent_generation: Option<u64>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    version: u32,
    driver_id: String,
    session_id: String,
    generation: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    origin: Origin,
    session_id: String,
    launch_generation: u64,
    request: Request,
}
#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Prepare {
        model: String,
        effort: Option<String>,
        working_dir: String,
        name: String,
        prompt: Option<String>,
        parent_session_id: String,
        initial_message_id: Option<String>,
    },
    Queue {
        driver_id: String,
        session_id: String,
        message_id: String,
        action: MessageAction,
        text: String,
        reply_to: Option<String>,
        expected_turn_id: Option<String>,
        expected_active_message_id: Option<String>,
    },
    MarkDelivery {
        driver_id: String,
        session_id: String,
        message_id: String,
        outcome: native::DeliveryOutcome,
    },
    AdvanceGeneration {
        expected_generation: u64,
        expected_peer: guest_peer::PeerIdentity,
    },
    GenerationStatus {
        driver_id: String,
        session_id: String,
    },
    ConfirmCleanGeneration {
        expected_peer: guest_peer::PeerIdentity,
    },
    Status {
        driver_id: String,
        session_id: String,
        limit: usize,
    },
    GetMessage {
        driver_id: String,
        message_id: String,
    },
    PeerStatus {
        driver_id: String,
        session_id: String,
    },
    Shutdown {
        driver_id: String,
        session_id: String,
        operation_id: String,
        peer: guest_peer::PeerIdentity,
    },
}
fn id(value: &str) -> anyhow::Result<()> {
    canonical_uuid(value)?;
    ensure!(
        !uuid::Uuid::parse_str(value)?.is_nil(),
        "nil platform identity"
    );
    Ok(())
}
fn validate_envelope(environment: &str, request: &Envelope) -> anyhow::Result<()> {
    let origin = &request.origin;
    for value in [&origin.environment_id, &origin.driver_id, &origin.pod_uid] {
        id(value)?;
    }
    ensure!(
        request.version == 1
            && origin.version == 1
            && origin.environment_id == environment
            && request.session_id == format!("session-{}", origin.driver_id)
            && request.launch_generation > 0
            && origin.binding_generation > 0
            && !origin.org_id.is_empty()
            && origin.org_id.len() <= 256
            && origin.org_id.trim() == origin.org_id
            && !origin.org_id.chars().any(char::is_control)
            && origin.projection_selection_sha256 != [0; 32]
            && origin.support_image_sha256 != [0; 32]
            && (4..=256 * 1024 * 1024).contains(&origin.support_image_size)
            && origin.provider.sha256 != [0; 32]
            && (4..=512 * 1024 * 1024).contains(&origin.provider.size)
            && origin.provider.version
                == match origin.agent {
                    AgentKind::Codex => "0.157.0",
                    AgentKind::Claude => "2.1.238",
                }
            && origin.parent_generation.is_none_or(|g| g > 0),
        "platform incarnation differs"
    );
    Ok(())
}
fn check_markers(dir: &Path, request: &Envelope) -> anyhow::Result<()> {
    // Do not adopt legacy/Host/Mesh records, including corrupt/symlink markers.
    match fs::symlink_metadata(dir.join("member-origin.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => anyhow::bail!("mixed managed origin refused"),
    }
    let saved: Origin = private_record(&dir.join(ORIGIN))?;
    let generation: Generation = private_record(&dir.join(GENERATION))?;
    ensure!(
        saved == request.origin
            && generation.version == 1
            && generation.driver_id == request.origin.driver_id
            && generation.session_id == request.session_id
            && generation.generation >= request.launch_generation
            && (matches!(
                request.request,
                Request::Status { .. }
                    | Request::GetMessage { .. }
                    | Request::GenerationStatus { .. }
            ) || generation.generation == request.launch_generation),
        "platform generation or origin differs"
    );
    Ok(())
}
fn optional_private(path: &Path) -> anyhow::Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => private_record(path).map(Some),
    }
}
fn strict_peer_files(dir: &Path) -> anyhow::Result<()> {
    if let Some(value) = optional_private(&dir.join("peer-current.json"))? {
        let instance = value["instance_id"]
            .as_str()
            .context("invalid peer pointer")?;
        id(instance)?;
        private_record::<Value>(&dir.join(format!("peer-{instance}.json")))?;
        optional_private(&dir.join(format!("shutdown-{instance}.json")))?;
    }
    Ok(())
}
pub(super) fn refuse_native_bypass(
    environment: &DriverEnvironment,
    request: &native::ControlRequest,
) -> anyhow::Result<()> {
    use native::ControlRequest as R;
    let driver = match request {
        R::Prepare { config } => Some(config.driver_id.as_str()),
        R::Bind { driver_id, .. }
        | R::Queue { driver_id, .. }
        | R::MarkDelivery { driver_id, .. }
        | R::Status { driver_id, .. }
        | R::GetMessage { driver_id, .. }
        | R::Shutdown { driver_id, .. }
        | R::GetShutdown { driver_id, .. }
        | R::PeerStatus { driver_id, .. } => Some(driver_id.as_str()),
        _ => None,
    };
    ensure!(
        !environment.root().starts_with(STATE),
        "platform control requires the original scoped helper"
    );
    if let Some(driver) = driver {
        ensure!(
            marker(environment, driver)?.is_none(),
            "platform control requires its original generation"
        );
    }
    Ok(())
}
fn agent(agent: AgentKind) -> codewire_daemon::platform_managed::Agent {
    match agent {
        AgentKind::Codex => codewire_daemon::platform_managed::Agent::Codex,
        AgentKind::Claude => codewire_daemon::platform_managed::Agent::Claude,
    }
}
pub(super) fn marker(
    environment: &DriverEnvironment,
    driver: &str,
) -> anyhow::Result<Option<Origin>> {
    id(driver)?;
    let dir = agents_root(environment).join(driver);
    let Some(value) = optional_private(&dir.join(ORIGIN))? else {
        return Ok(None);
    };
    let origin: Origin =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid platform origin"))?;
    validate_envelope(
        environment.id(),
        &Envelope {
            version: 1,
            origin: origin.clone(),
            session_id: format!("session-{driver}"),
            launch_generation: 1,
            request: Request::PeerStatus {
                driver_id: driver.into(),
                session_id: format!("session-{driver}"),
            },
        },
    )?;
    ensure!(origin.driver_id == driver, "platform marker driver differs");
    Ok(Some(origin))
}
pub(super) fn generation(
    environment: &DriverEnvironment,
    driver: &str,
) -> anyhow::Result<Option<u64>> {
    if marker(environment, driver)?.is_none() {
        return Ok(None);
    }
    let g: Generation = private_record(&agents_root(environment).join(driver).join(GENERATION))?;
    ensure!(
        g.version == 1
            && g.driver_id == driver
            && g.session_id == format!("session-{driver}")
            && g.generation > 0,
        "invalid platform generation"
    );
    Ok(Some(g.generation))
}
fn same_scope(a: &Origin, b: &Origin) -> bool {
    a.environment_id == b.environment_id
        && a.org_id == b.org_id
        && a.pod_uid == b.pod_uid
        && a.binding_generation == b.binding_generation
        && a.projection_selection_sha256 == b.projection_selection_sha256
        && a.support_image_sha256 == b.support_image_sha256
        && a.support_image_size == b.support_image_size
}
pub(super) fn parent_generation(
    environment: &DriverEnvironment,
    child: &str,
    parent: &str,
) -> anyhow::Result<Option<u64>> {
    let Some(child) = marker(environment, child)? else {
        ensure!(
            marker(environment, parent)?.is_none(),
            "ordinary child cannot adopt a platform parent"
        );
        return Ok(None);
    };
    let parent = marker(environment, parent)?.context("platform parent origin missing")?;
    let expected = child
        .parent_generation
        .context("platform parent generation missing")?;
    ensure!(
        same_scope(&child, &parent)
            && generation(environment, &parent.driver_id)? == Some(expected),
        "platform parent incarnation changed"
    );
    Ok(Some(expected))
}
/// A directory made below a setgid volume root (the Pod's fsGroup home)
/// inherits setgid, which owner-private admission refuses. Set the directory
/// this call just made exactly 0700 through its own nofollow descriptor.
fn set_created_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let made = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = made.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == euid() && m.mode() & 0o5777 == 0o700,
        "created platform directory changed"
    );
    made.set_permissions(fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn make_directory(path: &Path) -> anyhow::Result<DirectoryPin> {
    use std::os::unix::fs::DirBuilderExt;
    ensure!(
        path.is_absolute() && path.components().count() <= 64,
        "invalid private platform root"
    );
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        ensure!(
            matches!(part, std::path::Component::Normal(_)),
            "invalid private platform ancestor"
        );
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&current)?;
                set_created_private(&current)?;
                fs::File::open(current.parent().context("platform parent")?)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        let m = fs::symlink_metadata(&current)?;
        ensure!(
            host_control::admitted_ancestor(&current, &m, Path::new(host_control::PLATFORM_HOME)),
            "unsafe platform ancestor"
        );
    }
    DirectoryPin::open(path)
}
fn prepare(environment: &DriverEnvironment, request: Envelope) -> anyhow::Result<Value> {
    let Request::Prepare {
        model,
        effort,
        working_dir,
        name,
        prompt,
        parent_session_id,
        initial_message_id,
    } = request.request
    else {
        unreachable!()
    };
    ensure!(
        request.launch_generation == 1,
        "platform preparation requires first generation"
    );
    let provider = codewire_daemon::platform_managed::ProviderPin::admit(
        agent(request.origin.agent),
        &request.origin.provider,
    )?;
    let parent = if parent_session_id.is_empty() {
        ensure!(
            request.origin.parent_generation.is_none(),
            "unexpected platform parent generation"
        );
        None
    } else {
        let parent_driver = parent_session_id
            .strip_prefix("session-")
            .context("invalid platform parent")?;
        id(parent_driver)?;
        let saved = marker(environment, parent_driver)?.context("platform parent missing")?;
        ensure!(
            same_scope(&request.origin, &saved)
                && generation(environment, parent_driver)? == request.origin.parent_generation,
            "platform parent generation changed"
        );
        let parent_driver = parent_driver.to_owned();
        Some(ParentLink {
            session_id: parent_session_id,
            driver_id: parent_driver,
        })
    };
    let mut config = AgentConfig {
        version: 1,
        driver_id: request.origin.driver_id.clone(),
        environment_id: environment.id().into(),
        agent: request.origin.agent,
        program: PathBuf::new(),
        model,
        effort,
        working_dir,
        name,
        parent,
        initial_message_id,
        created_at: now(),
    };
    native::validate_launch(&config)?;
    ensure!(
        prompt.is_some() == config.initial_message_id.is_some(),
        "platform initial prompt identity differs"
    );
    if let Some(text) = &prompt {
        validate_text(text)?;
    }
    config.program = provider.path().to_owned();
    let _root = make_directory(&environment.root())?;
    let agents = agents_root(environment);
    let root = make_directory(&agents)?;
    let destination = agents.join(&request.origin.driver_id);
    ensure!(
        matches!(fs::symlink_metadata(&destination),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "platform driver already exists; observe original request"
    );
    let stage = agents.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    set_created_private(&stage)?;
    make_directory(&stage.join("messages"))?;
    write_private_json(&stage.join("config.json"), &config)?;
    write_private_json(&stage.join(ORIGIN), &request.origin)?;
    write_private_json(
        &stage.join(GENERATION),
        &Generation {
            version: 1,
            driver_id: config.driver_id.clone(),
            session_id: request.session_id.clone(),
            generation: 1,
        },
    )?;
    proxy::prepare(&stage, &config)?;
    if let (Some(message), Some(text)) = (&config.initial_message_id, prompt) {
        let mut record = MessageRecord::new(
            &config.driver_id,
            &request.session_id,
            MessageAction::Prompt,
            text,
        );
        record.id = message.clone();
        record.platform_launch_generation = Some(1);
        write_private_json(&message_path(&stage, message), &record)?;
    }
    write_private_json(
        &stage.join("binding.json"),
        &AgentBinding {
            driver_id: config.driver_id.clone(),
            session_id: request.session_id.clone(),
            bound_at: now(),
        },
    )?;
    provider.check()?;
    root.check()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &stage,
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    fs::File::open(&agents)?.sync_all()?;
    root.check()?;
    Ok(
        json!({"driver_id":config.driver_id,"message_id":config.initial_message_id.unwrap_or_default()}),
    )
}
pub(super) struct DriverContext {
    origin: Origin,
    pub(super) generation: u64,
    provider: codewire_daemon::platform_managed::ProviderPin,
}
impl DriverContext {
    pub(super) fn admit(environment: &DriverEnvironment, driver: &str) -> anyhow::Result<Self> {
        ensure!(
            environment.host().is_none(),
            "platform driver cannot adopt a Host"
        );
        let origin = marker(environment, driver)?.context("platform origin missing")?;
        let generation = generation(environment, driver)?.context("platform generation missing")?;
        let dir = driver_dir(environment, driver)?;
        let pin = DirectoryPin::open(&dir)?;
        let config: AgentConfig = private_record(&dir.join("config.json"))?;
        config.validate(environment.id(), driver)?;
        let provider = codewire_daemon::platform_managed::ProviderPin::admit(
            agent(origin.agent),
            &origin.provider,
        )?;
        let context = Self {
            origin,
            generation,
            provider,
        };
        context.check(environment, &config)?;
        pin.check()?;
        Ok(context)
    }
    pub(super) fn check(
        &self,
        environment: &DriverEnvironment,
        config: &AgentConfig,
    ) -> anyhow::Result<()> {
        ensure!(
            marker(environment, &config.driver_id)?.as_ref() == Some(&self.origin)
                && generation(environment, &config.driver_id)? == Some(self.generation)
                && config.agent == self.origin.agent
                && config.program == self.provider.path(),
            "platform original driver changed"
        );
        self.provider.check()?;
        proxy::check(&driver_dir(environment, &config.driver_id)?, config)
    }
    pub(super) fn environment(&self, dir: &Path) -> anyhow::Result<Vec<(String, String)>> {
        let config: AgentConfig = private_record(&dir.join("config.json"))?;
        ensure!(
            config.agent == self.origin.agent && config.program == self.provider.path(),
            "platform provider changed"
        );
        self.provider.check()?;
        proxy::environment(dir, &config)
    }
    pub(super) fn arguments(&self, args: &[&str]) -> Vec<String> {
        let mut fixed = proxy::arguments(self.origin.agent);
        fixed.extend(args.iter().map(|s| (*s).to_owned()));
        fixed
    }
}
pub(crate) async fn run_platform_agent_driver(
    environment: String,
    driver_id: String,
) -> anyhow::Result<()> {
    ensure!(
        euid() == 1000 && unsafe { libc::getegid() } == 1000,
        "platform ordinary owner required"
    );
    id(&environment)?;
    id(&driver_id)?;
    run_agent_driver_inner(
        AgentDriverArgs {
            environment: environment.clone(),
            driver_id,
            registry_root: None,
            guest_root: Some(Path::new(STATE).join(environment)),
        },
        true,
    )
    .await
    .map_err(|_| anyhow::anyhow!("platform agent driver refused"))
}
pub(crate) async fn run_platform_agent_peer(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Args {
        #[command(flatten)]
        peer: guest_peer::AgentPeerArgs,
    }
    let args = Args::try_parse_from(
        std::iter::once(std::ffi::OsString::from("__platform-agent-peer")).chain(arguments),
    )
    .map_err(|_| anyhow::anyhow!("invalid platform peer arguments"))?
    .peer;
    ensure!(
        euid() == 1000
            && unsafe { libc::getegid() } == 1000
            && !args.host_member_custody
            && args.guest_root == Path::new(STATE).join(&args.environment),
        "platform peer root differs"
    );
    let environment = DriverEnvironment::Guest {
        id: args.environment.clone(),
        root: args.guest_root.clone(),
    };
    let context = DriverContext::admit(&environment, &args.driver_id)?;
    let dir = driver_dir(&environment, &args.driver_id)?;
    let config: AgentConfig = private_record(&dir.join("config.json"))?;
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    ensure!(
        binding.session_id == args.session_id && args.program == context.provider.path(),
        "platform peer binding differs"
    );
    let prefix = proxy::arguments(config.agent);
    ensure!(
        args.arguments.starts_with(&prefix),
        "platform API-only peer arguments differ"
    );
    let native = &args.arguments[prefix.len()..];
    match config.agent {
        AgentKind::Codex => ensure!(native == ["app-server"], "platform Codex peer differs"),
        AgentKind::Claude => {
            let state: DriverState = private_record(&dir.join("state.json"))?;
            let session = state
                .native_thread_id
                .as_deref()
                .context("platform Claude native thread missing")?;
            id(session)?;
            let mut expected = vec![
                "-p",
                "--input-format",
                "stream-json",
                "--output-format",
                "stream-json",
                "--verbose",
                "--replay-user-messages",
                "--model",
                config.model.as_str(),
                if state.native_thread_established {
                    "--resume"
                } else {
                    "--session-id"
                },
                session,
            ];
            if let Some(effort) = &config.effort {
                expected.extend(["--effort", effort]);
            }
            ensure!(
                native.iter().map(String::as_str).eq(expected),
                "platform Claude peer differs"
            );
        }
    }
    let projection = context.environment(&dir)?;
    guest_peer::run_platform_peer(args, projection)
        .await
        .map_err(|_| anyhow::anyhow!("platform peer refused"))
}
fn handle_fixed(environment: &DriverEnvironment, request: Envelope) -> anyhow::Result<Value> {
    validate_envelope(environment.id(), &request)?;
    if matches!(request.request, Request::Prepare { .. }) {
        return prepare(environment, request);
    }
    let dir = driver_dir(environment, &request.origin.driver_id)?;
    let pin = DirectoryPin::open(&dir)?;
    check_markers(&dir, &request)?;
    let config: AgentConfig = private_record(&dir.join("config.json"))?;
    config.validate(environment.id(), &request.origin.driver_id)?;
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    ensure!(
        config.agent == request.origin.agent
            && binding.driver_id == request.origin.driver_id
            && binding.session_id == request.session_id,
        "platform driver differs"
    );
    optional_private(&dir.join("state.json"))?;
    strict_peer_files(&dir)?;
    let expected_driver = &request.origin.driver_id;
    let expected_session = &request.session_id;
    let native = match &request.request {
        Request::Prepare { .. } => unreachable!(),
        Request::Queue {
            driver_id,
            session_id,
            message_id,
            action,
            text,
            reply_to,
            expected_turn_id,
            expected_active_message_id,
        } => {
            ensure!(
                driver_id == expected_driver && session_id == expected_session,
                "platform driver differs"
            );
            id(message_id)?;
            if !matches!(action, MessageAction::Message) {
                let state: DriverState = private_record(&dir.join("state.json"))?;
                ensure!(
                    state.active_message_id == *expected_active_message_id
                        && state.active_message_id.is_some()
                        && state.current_turn_id == *expected_turn_id,
                    "platform active turn changed"
                );
            }
            native::ControlRequest::Queue {
                driver_id: driver_id.clone(),
                session_id: session_id.clone(),
                message_id: message_id.clone(),
                action: *action,
                text: text.clone(),
                reply_to: reply_to.clone(),
                turn_id: expected_turn_id.clone(),
            }
        }
        Request::MarkDelivery {
            driver_id,
            session_id,
            message_id,
            outcome,
        } => {
            ensure!(
                driver_id == expected_driver && session_id == expected_session,
                "platform driver differs"
            );
            id(message_id)?;
            let record: MessageRecord = private_record(&message_path(&dir, message_id))?;
            ensure!(
                record.platform_launch_generation == Some(request.launch_generation)
                    && record.member_launch_generation.is_none(),
                "platform message generation differs"
            );
            native::ControlRequest::MarkDelivery {
                driver_id: driver_id.clone(),
                session_id: session_id.clone(),
                message_id: message_id.clone(),
                outcome: *outcome,
                error: (!matches!(outcome, native::DeliveryOutcome::Written))
                    .then(|| "platform pipe acknowledgement uncertain".into()),
            }
        }
        Request::AdvanceGeneration {
            expected_generation,
            expected_peer,
        } => {
            ensure!(
                *expected_generation == request.launch_generation,
                "platform generation differs"
            );
            return generation_control(
                &dir,
                environment.id(),
                expected_driver,
                expected_session,
                request.launch_generation,
                expected_peer,
                true,
            );
        }
        Request::ConfirmCleanGeneration { expected_peer } => {
            return generation_control(
                &dir,
                environment.id(),
                expected_driver,
                expected_session,
                request.launch_generation,
                expected_peer,
                false,
            );
        }
        Request::Status {
            driver_id,
            session_id,
            limit,
        } => {
            ensure!(
                driver_id == expected_driver
                    && session_id == expected_session
                    && *limit <= INBOX_LIMIT,
                "invalid platform read"
            );
            native::ControlRequest::Status {
                driver_id: driver_id.clone(),
                session_id: session_id.clone(),
                limit: *limit,
            }
        }
        Request::GetMessage {
            driver_id,
            message_id,
        } => {
            ensure!(driver_id == expected_driver, "platform driver differs");
            id(message_id)?;
            let record: MessageRecord = private_record(&message_path(&dir, message_id))?;
            ensure!(
                record.target_session_id == request.session_id,
                "platform message belongs to another session"
            );
            ensure!(
                record.platform_launch_generation == Some(request.launch_generation)
                    && record.member_launch_generation.is_none(),
                "platform message generation differs"
            );
            native::ControlRequest::GetMessage {
                driver_id: driver_id.clone(),
                message_id: message_id.clone(),
            }
        }
        Request::PeerStatus {
            driver_id,
            session_id,
        }
        | Request::GenerationStatus {
            driver_id,
            session_id,
        } => {
            ensure!(
                driver_id == expected_driver && session_id == expected_session,
                "platform driver differs"
            );
            native::ControlRequest::PeerStatus {
                driver_id: driver_id.clone(),
                session_id: session_id.clone(),
            }
        }
        Request::Shutdown {
            driver_id,
            session_id,
            operation_id,
            peer,
        } => {
            id(operation_id)?;
            ensure!(
                driver_id == expected_driver && session_id == expected_session,
                "platform driver differs"
            );
            native::ControlRequest::Shutdown {
                driver_id: driver_id.clone(),
                session_id: session_id.clone(),
                operation_id: operation_id.clone(),
                peer: peer.clone(),
            }
        }
    };
    // All native launch/delivery/lookup operations are absent from this enum.
    // A resolution call would be a programming error; never PATH-fallback here.
    let mut value = native::handle_platform(environment, native, &|_| {
        anyhow::bail!("platform record helper cannot resolve a provider")
    })?;
    if matches!(request.request, Request::GenerationStatus { .. }) {
        let g: Generation = private_record(&dir.join(GENERATION))?;
        value["launch_generation"] = json!(g.generation);
    }
    if let Request::Queue {
        message_id,
        expected_active_message_id,
        ..
    } = &request.request
    {
        let saved = update_message(&dir, message_id, |r| {
            r.platform_launch_generation = Some(request.launch_generation);
            if expected_active_message_id.is_some() {
                r.expected_active_message_id = expected_active_message_id.clone();
            }
        })?;
        value["record"] = json!(saved);
    }
    // Validate all emitted message custody before returning bytes. A running
    // driver's later update is legal; compare immutable markers/generation,
    // not a mutable driver's timestamp snapshot.
    if let Some(records) = value["messages"].as_array() {
        ensure!(
            records.len() <= INBOX_LIMIT,
            "platform inbox bound exceeded"
        );
        let mut admitted = Vec::new();
        for record in records {
            let message = record["id"].as_str().context("invalid message identity")?;
            id(message)?;
            let saved: MessageRecord = private_record(&message_path(&dir, message))?;
            ensure!(
                saved.target_session_id == request.session_id,
                "platform message belongs to another session"
            );
            ensure!(
                saved.platform_launch_generation.is_some_and(|g| g > 0)
                    && saved.member_launch_generation.is_none(),
                "missing platform message generation"
            );
            if saved.platform_launch_generation == Some(request.launch_generation) {
                admitted.push(record.clone());
            }
        }
        value["messages"] = json!(admitted);
    }
    strict_peer_files(&dir)?;
    check_markers(&dir, &request)?;
    pin.check()?;
    Ok(value)
}
fn generation_control(
    dir: &Path,
    environment: &str,
    driver: &str,
    session: &str,
    generation: u64,
    expected_peer: &guest_peer::PeerIdentity,
    advance: bool,
) -> anyhow::Result<Value> {
    let pin = DirectoryPin::open(dir)?;
    let _control = StateLock::acquire(&dir.join("control.lock"))?;
    let _driver = StateLock::try_acquire(&dir.join("driver.lock"))?
        .context("old platform driver is still alive")?;
    let old: Generation = private_record(&dir.join(GENERATION))?;
    ensure!(
        old.version == 1
            && old.driver_id == driver
            && old.session_id == session
            && old.generation == generation,
        "platform generation CAS refused"
    );
    let peer = guest_peer::require_clean_previous(dir, environment, driver, session)?
        .context("original platform guardian cleanup unknown")?;
    let state: DriverState = private_record(&dir.join("state.json"))?;
    ensure!(
        peer.identity == *expected_peer
            && state.phase == DriverPhase::Stopped
            && state.started_at == expected_peer.driver_started_at
            && state.active_message_id.is_none()
            && state.current_turn_id.is_none(),
        "original platform peer or active turn changed"
    );
    let selected = if advance {
        generation
            .checked_add(1)
            .context("platform generation exhausted")?
    } else {
        generation
    };
    if advance {
        write_private_json(
            &dir.join(GENERATION),
            &Generation {
                generation: selected,
                ..old
            },
        )?;
    }
    pin.check()?;
    Ok(json!({"launch_generation":selected,"peer":peer}))
}
fn parse_envelope(input: impl std::io::Read) -> anyhow::Result<Envelope> {
    let mut bytes = Vec::new();
    input.take(REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= REQUEST_BYTES,
        "platform request too large"
    );
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid platform request"))
}
pub(crate) async fn run_platform_agent_control(environment: String) -> anyhow::Result<()> {
    let outcome = (|| {
        ensure!(
            euid() == 1000 && unsafe { libc::getegid() } == 1000,
            "platform ordinary owner required"
        );
        id(&environment)?;
        let root = Path::new(STATE).join(&environment);
        let environment = DriverEnvironment::Guest {
            id: environment,
            root,
        };
        let request = parse_envelope(std::io::stdin().lock())?;
        let value = handle_fixed(&environment, request)?;
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        ensure!(bytes.len() <= RESPONSE_BYTES, "platform response too large");
        let mut out = std::io::stdout().lock();
        out.write_all(&bytes)?;
        out.flush()?;
        Ok(())
    })();
    // An outer CLI must not format request values, paths or provider outputs.
    outcome.map_err(|_: anyhow::Error| anyhow::anyhow!("platform record helper refused"))
}

#[cfg(test)]
#[path = "platform_control_tests.rs"]
mod tests;
