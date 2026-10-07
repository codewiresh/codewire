//! Explicit authenticated Linux host members. Selection never starts a node,
//! daemon or coordinator; only `member up` launches the retained member helper.
use super::*;
use anyhow::ensure;
use codewire_daemon_proto::daemon::v1;
use codewire_tailnet::wg::PublicKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

mod custody;
pub(super) mod managed;
mod store;
pub(super) mod terminal;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

#[derive(Debug, Args)]
pub(crate) struct MemberArgs {
    #[command(subcommand)]
    command: MemberCommand,
}
#[derive(Debug, Subcommand)]
enum MemberCommand {
    /// Create or print this machine's separate member control public identity.
    Identity(MemberOutput),
    /// Save an explicit immutable full-key target alias. Names confer no trust.
    Add(MemberAdd),
    /// Expose one already-running host through a one-use Mesh enrollment.
    Up(MemberUp),
    /// Observe the retained member helper without starting or repairing it.
    Status(MemberOutput),
    /// Stop only the exact retained helper; delegated target requests survive.
    Down(MemberOutput),
    /// Inspect an explicitly pinned target without starting an owner.
    Info(MemberRemote),
    /// Observe the same retained request, including after grant revocation.
    Observe(MemberObserve),
}
#[derive(Debug, Args)]
struct MemberOutput {
    #[arg(long,value_enum,default_value_t=OutputFormat::Text)]
    output: OutputFormat,
}
#[derive(Debug, Args)]
struct MemberRemote {
    name: String,
    #[arg(long,value_parser=["direct_udp","derp"],help="Require this observed path before and after the typed request")]
    expect_transport: Option<String>,
    #[arg(long, default_value = "15s")]
    path_timeout: String,
    #[command(flatten)]
    presentation: MemberOutput,
}
#[derive(Debug, Args)]
struct MemberObserve {
    name: String,
    request_id: String,
    #[command(flatten)]
    presentation: MemberOutput,
}
#[derive(Debug, Args)]
struct MemberAdd {
    name: String,
    #[arg(long)]
    mesh_url: String,
    #[arg(long)]
    org: String,
    #[arg(long)]
    network: String,
    #[arg(long)]
    environment: String,
    #[arg(long)]
    node: String,
    #[arg(long)]
    target_key: String,
    #[arg(long)]
    target_wg_key: String,
    #[arg(long)]
    grant_id: String,
    #[arg(long)]
    grant_revision: u64,
    #[arg(long)]
    derp_only: bool,
    #[arg(
        long,
        value_enum,
        help = "Require and report the observed transport for each typed request; use --derp-only for derp"
    )]
    require_transport: Option<store::MemberPath>,
}
#[derive(Debug, Args)]
struct MemberUp {
    environment: String,
    #[arg(long)]
    mesh_url: String,
    #[arg(long)]
    org: String,
    #[arg(long)]
    network: String,
    #[arg(
        long,
        required = true,
        help = "Read one-use node enrollment from stdin; never save it"
    )]
    enrollment_stdin: bool,
    #[arg(long)]
    derp_only: bool,
    #[command(flatten)]
    presentation: MemberOutput,
}
#[derive(clap::Parser)]
struct HelperArgs {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    environment: String,
    #[arg(long)]
    host_root: PathBuf,
    #[arg(long)]
    origin: String,
    #[arg(long)]
    org: String,
    #[arg(long)]
    network: String,
    #[arg(long)]
    control_key: String,
    #[arg(long)]
    wg_key: String,
    #[arg(long,action=clap::ArgAction::Set)]
    derp_only: bool,
}

pub(super) fn name(value: &str) -> anyhow::Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "member name must be 1–64 letters, numbers, '-' or '_'"
    );
    Ok(())
}
fn key(value: &str) -> anyhow::Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "member public key must be 64 lowercase hexadecimal digits"
    );
    let mut result = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        result[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    ensure!(result != [0; 32], "member public key must be nonzero");
    Ok(result)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("String write");
    }
    text
}
fn directory(create: bool) -> anyhow::Result<store::Directory> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    store::Directory::open(&paths.mesh_data_dir.join("members"), create)
}
fn select_host(requested: &str) -> anyhow::Result<HostEnvironment> {
    select_host_from(host_environments()?, requested)
}
fn select_host_from(
    hosts: Vec<HostEnvironment>,
    requested: &str,
) -> anyhow::Result<HostEnvironment> {
    let selected = if uuid::Uuid::parse_str(requested).is_ok() {
        wire::canonical_uuid(requested)?;
        hosts.into_iter().find(|host| host.id == requested)
    } else {
        hosts.into_iter().find(|host| host.name == requested)
    };
    selected.context("registered host environment was not found")
}
fn value(value: serde_json::Value, output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Text => println!("{value}"),
    };
    Ok(())
}
fn receipt_value(value: &v1::HostControlReceipt) -> serde_json::Value {
    serde_json::json!({"request_id":value.request_id,"session_id":value.session_id,"launch_generation":value.launch_generation,
        "driver_id":value.driver_id,"message_id":value.message_id,
        "phase":v1::HostControlRequestPhase::try_from(value.phase).map(|x|x.as_str_name()).unwrap_or("UNKNOWN"),
        "cleanup_unknown":value.cleanup_unknown,"input_acknowledged":value.input_acknowledged,"reason":value.reason})
}
fn complete(receipt: &v1::HostControlReceipt) -> anyhow::Result<()> {
    ensure!(
        receipt.phase == v1::HostControlRequestPhase::Completed as i32 && !receipt.cleanup_unknown,
        "member request is not confirmed; observe the original request UUID, never reissue"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    nonce: String,
    environment_id: String,
    control_key: String,
    wg_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Starting {
    schema: u32,
    configuration: mesh_commands::retained::HelperConfiguration,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    schema: u32,
    custody: mesh_commands::retained::ProcessCustody,
}

async fn down(dir: &store::Directory) -> anyhow::Result<u32> {
    let _lock = dir.lock().await?;
    let (runtime, runtime_record) = dir
        .read_held::<Runtime>("member-runtime.json")?
        .context("member helper is not retained; unknown startup must be retained")?;
    ensure!(runtime.schema == 1, "member runtime schema unavailable");
    let ready = dir.read_held::<Ready>("member-ready.json")?;
    let starting = dir.read_held::<Starting>("member-starting.json")?;
    if let Some((ready, _)) = &ready {
        ensure!(
            ready.nonce == runtime.custody.member_nonce(),
            "member ready record was replaced"
        );
        if let mesh_commands::retained::HelperConfiguration::HostMember {
            environment_id,
            control_key,
            wg_key,
            ..
        } = runtime.custody.member_configuration()?
        {
            ensure!(
                ready.environment_id == *environment_id
                    && ready.control_key == *control_key
                    && ready.wg_key == *wg_key,
                "member ready binding changed"
            );
        }
    }
    if let Some((starting, _)) = &starting {
        ensure!(
            starting.schema == 1
                && &starting.configuration == runtime.custody.member_configuration()?,
            "member startup record was replaced"
        );
    }
    let records = std::iter::once(&runtime_record)
        .chain(ready.as_ref().map(|(_, record)| record))
        .chain(starting.as_ref().map(|(_, record)| record))
        .collect::<Vec<_>>();
    for record in &records {
        dir.validate_held(record)?;
    }
    if !runtime.custody.member_terminal()? {
        runtime.custody.pin_member()?.terminate().await?;
    }
    ensure!(
        runtime.custody.member_terminal()?,
        "member incarnation terminal state unknown"
    );
    // Recheck the entire captured set before the first unlink. A partial
    // cleanup keeps the authoritative runtime record until the final unlink.
    for record in &records {
        dir.validate_held(record)?;
    }
    if let Some((_, record)) = &ready {
        dir.remove_held(record)?;
    }
    if let Some((_, record)) = &starting {
        dir.remove_held(record)?;
    }
    dir.remove_held(&runtime_record)?;
    Ok(runtime.custody.member_pid())
}

pub(crate) async fn handle_member_command(
    globals: &Globals,
    args: MemberArgs,
) -> anyhow::Result<()> {
    ensure!(
        globals.member.is_none(),
        "member administration does not accept --member"
    );
    match args.command {
        MemberCommand::Identity(args) => {
            let dir = directory(true)?;
            let identity = store::Identity::load(&dir, true).await?;
            value(
                serde_json::json!({"control_key":hex(identity.secret().public().as_bytes()),"wg_key":hex(&PublicKey::from(&identity.wg()).to_bytes())}),
                args.output,
            )
        }
        MemberCommand::Add(args) => {
            name(&args.name)?;
            wire::canonical_uuid(&args.environment)?;
            wire::canonical_uuid(&args.grant_id)?;
            let target = key(&args.target_key)?;
            let target_wg = key(&args.target_wg_key)?;
            let dir = directory(false)?;
            let identity = store::Identity::load(&dir, false).await?;
            identity
                .secret()
                .require_contributory(&codewire_tailnet::derp::NodePublic::from_raw(target))?;
            identity
                .secret()
                .require_contributory(&codewire_tailnet::derp::NodePublic::from_raw(target_wg))?;
            let alias = store::Alias {
                schema: 1,
                name: args.name,
                origin: args.mesh_url,
                route_name: args.node,
                binding: wire::Binding {
                    environment_id: args.environment,
                    org: args.org,
                    network: args.network,
                    target_wg,
                    caller: *identity.secret().public().as_bytes(),
                    target,
                    grant_id: args.grant_id,
                    grant_revision: args.grant_revision,
                },
                derp_only: args.derp_only,
                required_transport: args.require_transport,
            };
            alias.save(&dir).await?;
            println!(
                "Member {} pinned to {}",
                alias.name, alias.binding.environment_id
            );
            Ok(())
        }
        MemberCommand::Up(args) => up(args).await,
        MemberCommand::Status(args) => {
            let dir = directory(false)?;
            let runtime: Runtime = dir
                .read("member-runtime.json")?
                .context("member helper is not retained")?;
            ensure!(runtime.schema == 1, "member runtime schema unavailable");
            runtime.custody.pin_member()?;
            value(
                serde_json::json!({"running":true,"pid":runtime.custody.member_pid(),"configuration":runtime.custody.member_configuration()?}),
                args.output,
            )
        }
        MemberCommand::Down(args) => {
            let dir = directory(false)?;
            let pid = down(&dir).await?;
            value(serde_json::json!({"stopped":true,"pid":pid}), args.output)
        }
        MemberCommand::Info(args) => {
            let dir = directory(false)?;
            let alias = store::Alias::load(&dir, &args.name)?;
            let mut remote = transport::Remote::connect(&dir, alias, globals).await?;
            let timeout = tailnet_ssh::parse_duration(&args.path_timeout)
                .map_err(|_| anyhow::anyhow!("invalid member path timeout"))?;
            ensure!(
                !timeout.is_zero() && timeout <= Duration::from_secs(60),
                "member path timeout must be 1ms..60s"
            );
            let before = remote
                .observe_path(args.expect_transport.as_deref(), timeout)
                .await?;
            let info = remote.info().await?;
            let after = remote
                .observe_path(args.expect_transport.as_deref(), timeout)
                .await?;
            value(
                serde_json::json!({"environment_id":info.environment_id,"protocol_version":info.protocol_version,"verbs":info.verbs,"path_before":before,"path_after":after}),
                args.presentation.output,
            )
        }
        MemberCommand::Observe(args) => {
            wire::canonical_uuid(&args.request_id)?;
            let dir = directory(false)?;
            let alias = store::Alias::load(&dir, &args.name)?;
            let mut record = store::RequestRecord::load(&dir, &args.request_id)?;
            ensure!(
                record.binding == alias.binding,
                "member request belongs to a different pinned principal"
            );
            let mut remote = transport::Remote::connect(&dir, alias, globals).await?;
            let receipt = remote.observe_record(&dir, &mut record).await?;
            value(receipt_value(&receipt), args.presentation.output)
        }
    }
}

async fn up(args: MemberUp) -> anyhow::Result<()> {
    let environment = select_host(&args.environment)?;
    let pin = custody::OwnerPin::admit(&environment).await?;
    pin.client(&environment).await?;
    let dir = directory(true)?;
    let _lock = dir.lock().await?;
    if let Some(runtime) = dir.read::<Runtime>("member-runtime.json")? {
        runtime.custody.pin_member()?;
        if let mesh_commands::retained::HelperConfiguration::HostMember {
            environment_id,
            origin,
            org,
            network,
            derp_only,
            ..
        } = runtime.custody.member_configuration()?
        {
            ensure!(
                environment_id == &environment.id
                    && origin == &args.mesh_url
                    && org == &args.org
                    && network == &args.network
                    && *derp_only == args.derp_only,
                "retained member configuration differs; stop it explicitly"
            );
        } else {
            anyhow::bail!("retained member role invalid");
        }
        return value(
            serde_json::json!({"running":true,"reused":true,"pid":runtime.custody.member_pid()}),
            args.presentation.output,
        );
    }
    ensure!(
        dir.read::<Starting>("member-starting.json")?.is_none(),
        "member startup outcome unknown; retain its state and do not re-enroll"
    );
    drop(_lock);
    let identity = store::Identity::load(&dir, true).await?;
    let _lock = dir.lock().await?;
    ensure!(
        dir.read::<Starting>("member-starting.json")?.is_none()
            && dir.read::<Runtime>("member-runtime.json")?.is_none(),
        "member startup changed concurrently"
    );
    let target = *identity.secret().public().as_bytes();
    let wg = PublicKey::from(&identity.wg()).to_bytes();
    // Validate the same public origin/scope contract as aliases before reading
    // enrollment or publishing a startup intent.
    store::Alias {
        schema: 1,
        name: "validation".into(),
        route_name: "validation".into(),
        origin: args.mesh_url.clone(),
        derp_only: args.derp_only,
        required_transport: None,
        binding: wire::Binding {
            environment_id: environment.id.clone(),
            org: args.org.clone(),
            network: args.network.clone(),
            target_wg: wg,
            caller: target,
            target,
            grant_id: environment.id.clone(),
            grant_revision: 1,
        },
    }
    .validate()?;
    let configuration = mesh_commands::retained::HelperConfiguration::HostMember {
        directory: dir.path.clone(),
        environment_id: environment.id.clone(),
        host_root: environment.root(),
        origin: args.mesh_url,
        org: args.org,
        network: args.network,
        control_key: hex(&target),
        wg_key: hex(&wg),
        derp_only: args.derp_only,
    };
    let mut enrollment = zeroize::Zeroizing::new(Vec::new());
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::io::stdin().take(8193).read_to_end(&mut enrollment),
    )
    .await??;
    ensure!(
        !enrollment.is_empty() && enrollment.len() <= 8192,
        "member enrollment stdin exceeds its closed bound"
    );
    let executable = mesh_commands::retained::ExecutableIdentity::admit(&env::current_exe()?)?;
    dir.write(
        "member-starting.json",
        &Starting {
            schema: 1,
            configuration: configuration.clone(),
        },
    )?;
    let helper = mesh_commands::retained::spawn_member(
        dir.retained(),
        executable,
        configuration,
        &enrollment,
    )?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            helper.live()?;
            pin.validate()?;
            if let Some(ready) = dir.read::<Ready>("member-ready.json")?
                && ready.nonce == helper.custody.member_nonce()
            {
                ensure!(
                    ready.environment_id == environment.id
                        && ready.control_key == hex(&target)
                        && ready.wg_key == hex(&wg),
                    "member ready identity changed"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("member startup not confirmed; retain its intent")??;
    dir.write(
        "member-runtime.json",
        &Runtime {
            schema: 1,
            custody: helper.custody.clone(),
        },
    )?;
    let custody = helper.retain();
    dir.remove("member-starting.json")?;
    value(
        serde_json::json!({"running":true,"pid":custody.member_pid(),"environment_id":environment.id,"control_key":hex(&target),"wg_key":hex(&wg)}),
        args.presentation.output,
    )
}

pub(crate) async fn run_host_member_helper(
    arguments: Vec<std::ffi::OsString>,
) -> anyhow::Result<()> {
    let args = HelperArgs::try_parse_from(
        std::iter::once(std::ffi::OsString::from("__host-member")).chain(arguments),
    )?;
    wire::canonical_uuid(&args.environment)?;
    let dir = store::Directory::open(&args.directory, false)?;
    let identity = store::Identity::load(&dir, false).await?;
    ensure!(
        hex(identity.secret().public().as_bytes()) == args.control_key
            && hex(&PublicKey::from(&identity.wg()).to_bytes()) == args.wg_key,
        "member helper key projection changed"
    );
    let environment: HostEnvironment = store::Directory::open(&args.host_root, false)?
        .read("host.json")?
        .context("member host metadata absent")?;
    ensure!(
        environment.id == args.environment
            && args.host_root.file_name().and_then(|x| x.to_str())
                == Some(args.environment.as_str()),
        "member helper environment identity changed"
    );
    let environment = HostEnvironment {
        runtime_root: Some(args.host_root),
        ..environment
    };
    let pin = custody::OwnerPin::admit(&environment).await?;
    let client = pin.client(&environment).await?;
    let mut enrollment = zeroize::Zeroizing::new(Vec::new());
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::stdin().take(8193).read_to_end(&mut enrollment),
    )
    .await??;
    ensure!(
        !enrollment.is_empty() && enrollment.len() <= 8192,
        "member enrollment unavailable"
    );
    let enrollment_text = std::str::from_utf8(&enrollment)?.trim();
    let tailnet = codewire_client::member_tailnet::MemberTailnet::peer(
        &args.origin,
        enrollment_text,
        &args.org,
        &args.network,
        wire::canonical_uuid(&args.environment)?,
        identity.wg(),
        codewire_client::member_tailnet::MemberTransportOptions {
            derp_only: args.derp_only,
        },
    )
    .await?;
    drop(enrollment);
    let mut listener = tailnet.listen_member().await?;
    let binding = wire::Binding {
        environment_id: args.environment.clone(),
        org: args.org,
        network: args.network,
        target_wg: key(&args.wg_key)?,
        caller: *identity.secret().public().as_bytes(),
        target: key(&args.control_key)?,
        grant_id: args.environment.clone(),
        grant_revision: 1,
    };
    let nonce = env::var("CW_LOCAL_HELPER_NONCE").context("member launch nonce unavailable")?;
    wire::canonical_uuid(&nonce)?;
    dir.write(
        "member-ready.json",
        &Ready {
            nonce,
            environment_id: args.environment,
            control_key: args.control_key,
            wg_key: args.wg_key,
        },
    )?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut tasks = tokio::task::JoinSet::new();
    let mut owner_check = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _=terminate.recv()=>break, _=interrupt.recv()=>break,
            _=owner_check.tick()=>{pin.validate()?;ensure!(tailnet.is_ready(),"member coordinate owner ended");},
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            connection=listener.accept(),if tasks.len()<16=>{
                let stream=connection.context("member listener closed")?;let secret=identity.secret();let binding=binding.clone();let pin=Arc::clone(&pin);let client=client.clone();
                tasks.spawn(async move { let _=transport::serve_connection(stream,secret,binding,pin,client).await; });
            },
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
