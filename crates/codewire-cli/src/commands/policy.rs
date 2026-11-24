//! `cw policy`: network policies, the destinations an environment may reach
//! (#2537). Not Mesh networks, which `cw network` manages.
//!
//! A policy is named and every edit makes a new revision. `open`, `web` and
//! `locked` are built-ins. Policies live in this host's store (`--local`) or in the
//! organization's platform store (`--cloud`, #4000), which a deployment
//! enforces where its hosted egress is on.

use std::collections::BTreeMap;
use std::net::IpAddr;

use clap::{Args, Subcommand};
use codewire_egress_policy::check::{CheckDestination, PolicyCheck};
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::reference::{PolicyReference, PolicyStore};
use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy};
use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy, is_reserved_policy_name};

use super::*;

mod platform;
mod refusal_log;

/// The one refusal for a server with network policies turned off, from
/// `cw policy`, `create --policy` and `update --policy` alike
/// (docs/dev/CLI-PARITY.md, P4), or `None` for any other error. It keeps the
/// id of the trace the answer named.
pub(crate) fn policies_disabled(error: &codewire_client::ClientError) -> Option<anyhow::Error> {
    (error.reason() == Some("NETWORK_POLICIES_DISABLED")).then(|| {
        crate::error_report::with_next_step(
            crate::reworded::reworded(
                "network policies are turned off on this Codewire server; a local VM can still use one",
                error.trace_id(),
            ),
            "cw --local policy",
        )
    })
}

/// `cw --cloud policy log`'s answer until hosted Sandboxes keep a log (#4000).
const NO_HOSTED_REFUSAL_LOG: &str =
    "hosted Sandboxes have no refusal log yet; `cw --local policy log ENV` shows a local VM's";

/// The ports a target gets when it names none: those `web` allows, so an
/// allowed Git host also works over SSH.
const DEFAULT_PORTS: [u16; 3] = [22, 80, 443];
const DEFAULT_CHECK_PORT: u16 = 443;

/// The network policy `--policy` names on a create or an update. An empty
/// name is refused when the command line is parsed, so it can never read as
/// "no policy given" and fall back to the default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyName(String);

impl std::str::FromStr for PolicyName {
    type Err = &'static str;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() {
            return Err("name a network policy: open, web, locked, or a policy from `cw policy`");
        }
        Ok(Self(name.to_owned()))
    }
}

impl std::ops::Deref for PolicyName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<PolicyName> for String {
    fn from(name: PolicyName) -> Self {
        name.0
    }
}

impl PolicyName {
    /// Ask for the policy in the guided create, offering `current` or `open`.
    /// Only a reference that parses is accepted.
    pub(super) fn ask(current: Option<&str>) -> anyhow::Result<Self> {
        guided::text("Network policy", current.or(Some("open")), |name| {
            PolicyReference::parse(name)
                .map(drop)
                .map_err(|error| error.to_string())
        })
        .map(Self)
    }
}

#[derive(Debug, Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    #[command(
        about = "Create a network policy from `locked` or another policy",
        after_help = "Examples:\n  cw policy --local create work --allow github.com,'*.npmjs.org'\n  cw policy --local create work-plus --from work --allow extra.example.org:443\n\nA target is a DNS name, a `*.` pattern for every name under a domain, or a public CIDR, with an optional :PORT (repeat the target for more ports). Without a port it allows 22, 80 and 443."
    )]
    Create(PolicyCreateArgs),
    #[command(visible_alias = "ls", about = "List network policies and their rules")]
    List(PolicyListArgs),
    #[command(about = "Allow more destinations: makes a new revision")]
    Allow(PolicyEditArgs),
    #[command(about = "Remove destinations' rules: makes a new revision")]
    Rm(PolicyEditArgs),
    #[command(about = "Show whether a policy allows a destination, and why")]
    Check(PolicyCheckArgs),
    #[command(about = "Delete a network policy no environment selects")]
    Delete(PolicyDeleteArgs),
    #[command(about = "Show what a running local VM's network policy refused, and why")]
    Log(refusal_log::PolicyLogArgs),
}

#[derive(Debug, Args)]
pub(crate) struct PolicyCreateArgs {
    #[arg(help = "The new policy's name; omit for an interactive walkthrough")]
    pub(crate) name: Option<String>,
    #[arg(
        long,
        value_name = "POLICY",
        help = "Start from this policy's current rules (`locked`, the default, or a policy of yours)"
    )]
    pub(crate) from: Option<String>,
    #[arg(
        long,
        value_name = "TARGET[:PORT]",
        value_delimiter = ',',
        help = "Destinations to allow, comma-separated or repeated"
    )]
    pub(crate) allow: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyEditArgs {
    #[arg(help = "The policy to change")]
    pub(crate) name: String,
    #[arg(required = true, value_name = "TARGET[:PORT]", help = "Destinations")]
    pub(crate) targets: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyCheckArgs {
    #[arg(help = "The policy: `open`, `locked` or a policy of yours")]
    pub(crate) name: String,
    #[arg(
        value_name = "DESTINATION[:PORT]",
        help = "A DNS name or IP address; the port defaults to 443"
    )]
    pub(crate) destination: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyDeleteArgs {
    #[arg(help = "The policy to delete")]
    pub(crate) name: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

impl PolicyCommand {
    fn json(&self) -> bool {
        let output = match self {
            Self::Create(args) => args.output,
            Self::List(args) => args.output,
            Self::Allow(args) | Self::Rm(args) => args.output,
            Self::Check(args) => args.output,
            Self::Delete(args) => args.output,
            Self::Log(args) => args.output,
        };
        matches!(output, OutputFormat::Json)
    }
}

/// Whether a policy command uses the organization's store: only when its
/// location says `--cloud`. With no location it uses this computer's store,
/// as before organization policies existed, so a scripted `cw policy allow …`
/// keeps its meaning (#4594, #4000).
fn uses_platform(placement: Option<EnvironmentPlacement>) -> bool {
    matches!(placement, Some(EnvironmentPlacement::Platform))
}

pub(crate) async fn handle_policy_command(
    globals: &Globals,
    mut args: PolicyArgs,
) -> anyhow::Result<()> {
    // `check` against a built-in needs no store.
    if let PolicyCommand::Check(check) = &args.command
        && let Some(builtin) = BuiltinPolicy::from_name(&check.name)
    {
        return print_check(check, &builtin.to_string(), None, &builtin.compile(), None);
    }
    let guided_create = matches!(&args.command, PolicyCommand::Create(args) if args.name.is_none());
    if let PolicyCommand::Create(args) = &mut args.command {
        let hint = match globals.placement {
            Some(EnvironmentPlacement::Platform) => {
                "name the policy: `cw --cloud policy create NAME`"
            }
            _ => "name the policy: `cw --local policy create NAME`",
        };
        args.name = Some(super::additions::required(
            args.name.take(),
            "Policy name",
            args.output,
            hint,
        )?);
    }
    let platform = uses_platform(globals.placement);
    // A list says which store it read, and never asks (#4594).
    if globals.placement.is_none()
        && matches!(args.command, PolicyCommand::List(_))
        && !args.command.json()
    {
        eprintln!("Policies on this computer; your organization's are in `cw --cloud policy ls`:");
    }
    if let PolicyCommand::Log(log) = args.command {
        anyhow::ensure!(!platform, NO_HOSTED_REFUSAL_LOG);
        return refusal_log::handle(log).await;
    }
    if platform {
        return platform::handle(globals, args.command).await;
    }
    handle_local_policy_command(args.command, guided_create).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_local_policy_command(
    command: PolicyCommand,
    guided_create: bool,
) -> anyhow::Result<()> {
    use codewire_local_vmm::control::v1;

    if let PolicyCommand::List(args) = &command {
        return list_local_policies(args.output).await;
    }
    let mut client = native_client().await?;
    let status = |action: &'static str| {
        move |status: tonic::Status| anyhow::anyhow!("couldn't {action}: {}", status.message())
    };
    match command {
        PolicyCommand::Create(mut args) => {
            if guided_create {
                if args.from.is_none() {
                    let policies = client
                        .list_network_policies()
                        .await
                        .map_err(status("list base policies"))?;
                    let mut choices =
                        vec![super::guided::Choice::new("Locked", "No outbound access")];
                    choices.extend(policies.iter().map(|policy| {
                        super::guided::Choice::new(&policy.name, rules_text(policy))
                    }));
                    let index = super::guided::choose("Start with which rules?", &choices)?;
                    args.from = Some(if index == 0 {
                        "locked".to_owned()
                    } else {
                        policies[index - 1].name.clone()
                    });
                }
                if args.allow.is_empty() {
                    let targets = super::guided::text(
                        "Destinations to allow (comma separated; Enter for none)",
                        Some(""),
                        |value| {
                            let targets = value
                                .split(',')
                                .map(str::trim)
                                .filter(|v| !v.is_empty())
                                .map(str::to_owned)
                                .collect::<Vec<_>>();
                            rules_from(&targets)
                                .map(|_| ())
                                .map_err(|error| error.to_string())
                        },
                    )?;
                    args.allow = targets
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                super::additions::review(
                    "Create network policy?",
                    &[
                        ("Storage", "This computer".to_owned()),
                        ("Name", args.name.clone().unwrap_or_default()),
                        (
                            "Base",
                            args.from.clone().unwrap_or_else(|| "locked".to_owned()),
                        ),
                        (
                            "Allow",
                            if args.allow.is_empty() {
                                "No additional destinations".to_owned()
                            } else {
                                format!(
                                    "{} (unspecified ports: 22, 80, 443)",
                                    args.allow.join(", ")
                                )
                            },
                        ),
                    ],
                )?;
            }
            let from = args
                .from
                .as_deref()
                .map(base_selector)
                .transpose()?
                .flatten();
            let allow = rules_from(&args.allow)?;
            let created = client
                .create_network_policy(v1::CreateNetworkPolicyRequest {
                    name: args.name.context("policy name is required")?,
                    from,
                    allow: allow.into_iter().map(rule_proto).collect(),
                })
                .await
                .map_err(status("create the network policy"))?;
            print_policy("Created", &created, args.output)
        }
        PolicyCommand::List(_) => unreachable!("a list returned above, before connecting"),
        PolicyCommand::Allow(args) => {
            let allow = rules_from(&args.targets)?;
            let updated = client
                .update_network_policy(v1::UpdateNetworkPolicyRequest {
                    policy: Some(stored_selector(&args.name)?),
                    allow: allow.into_iter().map(rule_proto).collect(),
                    remove: Vec::new(),
                })
                .await
                .map_err(status("change the network policy"))?;
            print_policy("Changed", &updated, args.output)
        }
        PolicyCommand::Rm(args) => {
            let remove = args
                .targets
                .iter()
                .map(|target| removal_target(target))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let updated = client
                .update_network_policy(v1::UpdateNetworkPolicyRequest {
                    policy: Some(stored_selector(&args.name)?),
                    allow: Vec::new(),
                    remove,
                })
                .await
                .map_err(status("change the network policy"))?;
            print_policy("Changed", &updated, args.output)
        }
        PolicyCommand::Check(args) => {
            let stored = client
                .get_network_policy(v1::GetNetworkPolicyRequest {
                    policy: Some(stored_selector(&args.name)?),
                    revision: 0,
                })
                .await
                .map_err(status("read the network policy"))?;
            let compiled = typed_from(&stored, "the supervisor")?.compile();
            print_check(&args, &stored.name, Some(stored.revision), &compiled, None)
        }
        PolicyCommand::Log(args) => refusal_log::handle(args).await,
        PolicyCommand::Delete(args) => {
            let deleted = client
                .delete_network_policy(stored_selector(&args.name)?)
                .await
                .map_err(status("delete the network policy"))?;
            print_deleted(&deleted, args.output)
        }
    }
}

/// `cw policy ls` on this computer. A read starts nothing (CLI-PARITY.md,
/// P3): the store is read without the supervisor, and none stored lists the
/// built-ins. Only a store this cw cannot read on its own (one the
/// supervisor must first upgrade, or one being replaced) is asked of the
/// supervisor, as before.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn list_local_policies(output: OutputFormat) -> anyhow::Result<()> {
    let root = native_runtime_config()?.root;
    let policies =
        match codewire_local_vmm::supervisor::network_policies::read_network_policies(&root) {
            Ok(policies) => policies.unwrap_or_default(),
            Err(_) => native_client()
                .await?
                .list_network_policies()
                .await
                .map_err(|status| anyhow::anyhow!("list network policies: {}", status.message()))?,
        };
    // A local VM's broker always enforces its policy.
    print_policies(&policies, output, true)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn handle_local_policy_command(
    _command: PolicyCommand,
    _guided_create: bool,
) -> anyhow::Result<()> {
    anyhow::bail!("local network policies need a Linux or macOS host")
}

/// A stored policy named in a command: a bare name, `local:NAME` or
/// `local:id:UUID`. Built-ins are not stored and cannot be edited.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stored_selector(
    value: &str,
) -> anyhow::Result<codewire_local_vmm::control::v1::NetworkPolicySelector> {
    use codewire_local_vmm::control::v1::network_policy_selector::Selector;
    let selector = match PolicyReference::parse(value)
        .map_err(|error| anyhow::anyhow!("the policy {value}: {error}"))?
    {
        PolicyReference::Builtin(builtin) => anyhow::bail!(
            "the built-in policy {builtin} cannot be changed; create your own with `cw policy create NAME --allow TARGET`, which starts from `locked`"
        ),
        PolicyReference::Name { store, name } => {
            require_local(store)?;
            Selector::Name(name.to_string())
        }
        PolicyReference::Id { store, id } => {
            require_local(Some(store))?;
            Selector::Id(id.to_string())
        }
    };
    Ok(codewire_local_vmm::control::v1::NetworkPolicySelector {
        selector: Some(selector),
    })
}

/// `--from`: `locked` (no selector) or a stored policy. `open` and `web`
/// allow every public destination and are outside the rule subset, so nothing
/// starts from them.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn base_selector(
    value: &str,
) -> anyhow::Result<Option<codewire_local_vmm::control::v1::NetworkPolicySelector>> {
    match BuiltinPolicy::from_name(value) {
        Some(BuiltinPolicy::Locked) => Ok(None),
        Some(builtin @ (BuiltinPolicy::Open | BuiltinPolicy::Web)) => anyhow::bail!(
            "a policy cannot start from `{builtin}`, which allows every public destination; start from `locked` and allow what you need"
        ),
        None => stored_selector(value).map(Some),
    }
}

fn require_local(store: Option<PolicyStore>) -> anyhow::Result<()> {
    anyhow::ensure!(
        store != Some(PolicyStore::Platform),
        "platform network policies are not available yet; name a policy on this host"
    );
    Ok(())
}

/// `TARGET[:PORT]`. An IPv6 range with a port is written `[RANGE]:PORT`.
fn split_port(value: &str) -> anyhow::Result<(&str, Option<u16>)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (target, tail) = rest.split_once(']').ok_or_else(|| {
            anyhow::anyhow!("the destination {value}: a `[` needs its closing `]`")
        })?;
        return match tail {
            "" => Ok((target, None)),
            _ => {
                let port = tail.strip_prefix(':').ok_or_else(|| {
                    anyhow::anyhow!("the destination {value}: write `[RANGE]:PORT`")
                })?;
                Ok((target, Some(parse_port(value, port)?)))
            }
        };
    }
    match value.rsplit_once(':') {
        // A bare IPv6 address or range has colons of its own.
        Some((target, port)) if !target.contains(':') => {
            Ok((target, Some(parse_port(value, port)?)))
        }
        _ => Ok((value, None)),
    }
}

fn parse_port(value: &str, port: &str) -> anyhow::Result<u16> {
    match port.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => anyhow::bail!("the destination {value}: {port} is not a TCP port from 1 to 65535"),
    }
}

/// Group `TARGET[:PORT]` items into one rule per target. A target given
/// without any port gets the default ports.
fn rules_from(items: &[String]) -> anyhow::Result<Vec<AllowRule>> {
    let mut ports: BTreeMap<AllowTarget, Vec<u16>> = BTreeMap::new();
    for item in items.iter().filter(|item| !item.trim().is_empty()) {
        let (target, port) = split_port(item)?;
        let target = AllowTarget::parse(target).map_err(|error| anyhow::anyhow!("{error}"))?;
        let entry = ports.entry(target).or_default();
        match port {
            Some(port) => entry.push(port),
            None => entry.extend(DEFAULT_PORTS),
        }
    }
    ports
        .into_iter()
        .map(|(target, mut ports)| {
            ports.sort_unstable();
            ports.dedup();
            AllowRule::new(target, ports).map_err(|error| anyhow::anyhow!("{error}"))
        })
        .collect()
}

/// `rm` drops a target's whole rule, so it takes no port.
fn removal_target(value: &str) -> anyhow::Result<String> {
    let (target, port) = split_port(value)?;
    anyhow::ensure!(
        port.is_none(),
        "the destination {value}: `rm` removes a destination's whole rule; name it without a port"
    );
    Ok(AllowTarget::parse(target)
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rule_proto(rule: AllowRule) -> codewire_local_vmm::control::v1::NetworkPolicyRule {
    codewire_local_vmm::control::v1::NetworkPolicyRule {
        target: rule.target().to_string(),
        ports: rule.ports().iter().map(|port| u32::from(*port)).collect(),
    }
}

/// What the renderers need from a stored policy, on this host or on the
/// platform.
trait ShownPolicy {
    fn name(&self) -> &str;
    /// Its exact reference, `local:id:UUID` or `platform:id:UUID`.
    fn reference(&self) -> String;
    fn revision(&self) -> u32;
    fn digest(&self) -> &str;
    fn rules(&self) -> Vec<(&str, &[u32])>;
    fn json(&self) -> serde_json::Value;
    /// Where an edit took effect at once, and where it waits for a restart.
    fn applied(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ShownPolicy for codewire_local_vmm::control::v1::NetworkPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn reference(&self) -> String {
        format!("local:id:{}", self.id)
    }

    fn revision(&self) -> u32 {
        self.revision
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn rules(&self) -> Vec<(&str, &[u32])> {
        self.rules
            .iter()
            .map(|rule| (rule.target.as_str(), rule.ports.as_slice()))
            .collect()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "reference": self.reference(),
            "revision": self.revision,
            "current_revision": self.current_revision,
            "digest": self.digest,
            "rules": rules_json(self),
            "created_unix_ms": self.created_unix_ms,
            "enforced_in": self.enforced_in,
            "restart_required_in": self.restart_required_in,
        })
    }

    fn applied(&self) -> Vec<String> {
        applied_text(self)
    }
}

/// The policy's rules, checked against its digest. `source` names who
/// returned it, for the error.
fn typed_from(policy: &impl ShownPolicy, source: &str) -> anyhow::Result<TypedPolicy> {
    let rules = policy
        .rules()
        .into_iter()
        .map(|(target, ports)| {
            let ports = ports
                .iter()
                .map(|port| u16::try_from(*port))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AllowRule::new(AllowTarget::parse(target)?, ports)?)
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .with_context(|| format!("the network policy from {source} is invalid"))?;
    let typed = TypedPolicy::new(rules)?;
    anyhow::ensure!(
        typed.compile().digest().to_hex() == policy.digest(),
        "the network policy from {source} has rules that do not match its digest"
    );
    Ok(typed)
}

fn rules_json(policy: &impl ShownPolicy) -> Vec<serde_json::Value> {
    policy
        .rules()
        .into_iter()
        .map(|(target, ports)| serde_json::json!({ "target": target, "ports": ports }))
        .collect()
}

fn rules_text(policy: &impl ShownPolicy) -> String {
    let rules = policy.rules();
    if rules.is_empty() {
        return "nothing (like `locked`)".to_owned();
    }
    rules
        .into_iter()
        .map(|(target, ports)| {
            let ports = ports
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{target} ({ports})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_policy(verb: &str, policy: &impl ShownPolicy, output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&policy.json())?),
        OutputFormat::Text => {
            println!(
                "{verb} network policy {} · rev {}\n  Allows: {}",
                policy.name(),
                policy.revision(),
                rules_text(policy)
            );
            for line in policy.applied() {
                println!("  {line}");
            }
        }
    }
    Ok(())
}

/// Where an edit took effect at once, and where it waits for a restart.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn applied_text(policy: &codewire_local_vmm::control::v1::NetworkPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    if !policy.enforced_in.is_empty() {
        lines.push(format!(
            "Enforced now in: {}",
            policy.enforced_in.join(", ")
        ));
    }
    if !policy.restart_required_in.is_empty() {
        lines.push(format!(
            "Applies after a restart in: {} (their broker could not take it)",
            policy.restart_required_in.join(", ")
        ));
    }
    lines
}

/// The built-ins, then each stored policy. `locked` names what it leaves
/// open: a selected model credential still reaches its own provider (SPEC,
/// the interception paragraph; #5215). A stored policy named before its name
/// became a built-in's is marked and asked for a new name. `udp_blocked`:
/// a broker enforces the policies, which never allow UDP other than DNS
/// (#3997).
fn policies_text(policies: &[impl ShownPolicy], udp_blocked: bool) -> String {
    let mut text = String::from(
        "open    built-in, the default · every public destination on any TCP port\n\
         web     built-in · every public destination on TCP 22, 80 and 443\n\
         locked  built-in · nothing, except the model providers of credentials you selected\n",
    );
    for policy in policies {
        text.push_str(&format!(
            "{}  rev {} · {}\n",
            policy.name(),
            policy.revision(),
            rules_text(policy)
        ));
        if is_reserved_policy_name(policy.name()) {
            text.push_str(&format!(
                "  Its name is now a built-in's, so give it a new one: `cw --local policy create NAME --from {}`.\n",
                policy.reference()
            ));
        }
    }
    if udp_blocked {
        text.push_str("UDP other than DNS is blocked under every policy.\n");
    }
    text
}

fn print_deleted(policy: &impl ShownPolicy, output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&policy.json())?),
        OutputFormat::Text => println!("Deleted network policy {}", policy.name()),
    }
    Ok(())
}

fn print_policies(
    policies: &[impl ShownPolicy],
    output: OutputFormat,
    udp_blocked: bool,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(
                &policies.iter().map(ShownPolicy::json).collect::<Vec<_>>()
            )?
        ),
        OutputFormat::Text => print!("{}", policies_text(policies, udp_blocked)),
    }
    Ok(())
}

/// `hosted_enforced` is `Some` for an organization's policy only: whether
/// hosted Sandboxes enforce it, which its JSON reports. A local or built-in
/// policy's JSON is unchanged.
fn print_check(
    args: &PolicyCheckArgs,
    name: &str,
    revision: Option<u32>,
    policy: &CompiledPolicy,
    hosted_enforced: Option<bool>,
) -> anyhow::Result<()> {
    let (destination, port) = split_port(&args.destination)?;
    let port = port.unwrap_or(DEFAULT_CHECK_PORT);
    let parsed = CheckDestination::parse(destination).map_err(|_| {
        anyhow::anyhow!("the destination {destination} is not a DNS name or IP address")
    })?;
    let check: PolicyCheck = policy.check(&parsed, port)?;
    let named = matches!(parsed, CheckDestination::Name(_));
    let shown = match &parsed {
        CheckDestination::Name(name) => format!("{name}:{port}"),
        CheckDestination::Address(IpAddr::V6(address)) => format!("[{address}]:{port}"),
        CheckDestination::Address(address) => format!("{address}:{port}"),
    };
    let revision_text = revision
        .map(|revision| format!(" rev {revision}"))
        .unwrap_or_default();
    match args.output {
        OutputFormat::Json => {
            let mut json = serde_json::json!({
                "policy": name,
                "revision": revision,
                "destination": shown,
                "allowed": check.is_allowed(),
                "reason": check.refusal.map(RefusalReason::code),
                "allowed_within": check.allowed_within,
                "refused_within": check.refusal.is_none().then_some(&check.refused_within),
            });
            if let Some(enforced) = hosted_enforced {
                json["enforced"] = enforced.into();
                json["enforcement"] = if enforced {
                    "available"
                } else {
                    "not_available"
                }
                .into();
            }
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text => {
            match check.refusal {
                None if named => println!(
                    "Allowed: {shown} by {name}{revision_text}, when the name answers public addresses"
                ),
                None => println!("Allowed: {shown} by {name}{revision_text}"),
                Some(reason) => println!(
                    "Refused: {shown} by {name}{revision_text} ({})",
                    reason.description()
                ),
            }
            if let Some(within) = check_networks_text(&check) {
                println!("  {within}");
            }
        }
    }
    Ok(())
}

/// For a name, the networks its answer would change the decision for.
fn check_networks_text(check: &PolicyCheck) -> Option<String> {
    let (verb, networks) = if check.is_allowed() {
        ("refused", &check.refused_within)
    } else {
        ("allowed", &check.allowed_within)
    };
    (!networks.is_empty()).then(|| {
        format!(
            "Also {verb} if the name resolves within {}",
            networks.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `locked` names the one thing it leaves open, a selected model
    /// credential's provider (#5215).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_list_says_what_each_built_in_allows() {
        let none: &[codewire_local_vmm::control::v1::NetworkPolicy] = &[];
        assert_eq!(
            policies_text(none, false),
            "open    built-in, the default · every public destination on any TCP port\n\
             web     built-in · every public destination on TCP 22, 80 and 443\n\
             locked  built-in · nothing, except the model providers of credentials you selected\n"
        );
    }

    /// Where a broker enforces, the list says UDP other than DNS is blocked;
    /// a policy named `web` before it was a built-in is marked and asked for
    /// a new name, by its exact reference (#3997).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_list_says_udp_is_blocked_and_marks_a_policy_with_a_built_ins_name() {
        let policy = |name: &str| codewire_local_vmm::control::v1::NetworkPolicy {
            id: "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01".into(),
            name: name.into(),
            revision: 2,
            ..Default::default()
        };
        let text = policies_text(&[policy("web"), policy("team")], true);
        assert!(
            text.ends_with(
                "web  rev 2 · nothing (like `locked`)\n\
                 \x20 Its name is now a built-in's, so give it a new one: `cw --local policy create NAME --from local:id:0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01`.\n\
                 team  rev 2 · nothing (like `locked`)\n\
                 UDP other than DNS is blocked under every policy.\n"
            ),
            "{text}"
        );
        assert!(!policies_text(&[policy("team")], false).contains("UDP"));
    }

    #[test]
    fn with_no_location_every_policy_command_uses_this_computers_store() {
        assert!(!uses_platform(None));
        assert!(!uses_platform(Some(EnvironmentPlacement::Local)));
        assert!(uses_platform(Some(EnvironmentPlacement::Platform)));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_edit_names_where_it_took_effect() {
        let policy = codewire_local_vmm::control::v1::NetworkPolicy {
            enforced_in: vec!["j-a".into(), "j-b".into()],
            restart_required_in: vec!["j-c".into()],
            ..Default::default()
        };
        assert_eq!(
            applied_text(&policy),
            [
                "Enforced now in: j-a, j-b",
                "Applies after a restart in: j-c (their broker could not take it)"
            ]
        );
        assert!(applied_text(&Default::default()).is_empty());
    }

    #[test]
    fn a_check_names_the_networks_that_would_change_its_answer() {
        let refused = PolicyCheck {
            refusal: Some(RefusalReason::PortNotAllowed),
            rule_id: None,
            allowed_within: vec!["8.0.0.0/8".into()],
            refused_within: Vec::new(),
        };
        assert_eq!(
            check_networks_text(&refused).as_deref(),
            Some("Also allowed if the name resolves within 8.0.0.0/8")
        );
        let plain = PolicyCheck {
            allowed_within: Vec::new(),
            ..refused
        };
        assert_eq!(check_networks_text(&plain), None);
    }

    #[test]
    fn targets_take_an_optional_port_and_default_to_22_80_and_443() {
        let rules = rules_from(&[
            "github.com".to_owned(),
            "*.npmjs.org:443".to_owned(),
            "185.199.108.0/22:8443".to_owned(),
            "[2001:db8::/32]:443".to_owned(),
            "pypi.org:443".to_owned(),
            "pypi.org:8443".to_owned(),
        ]);
        // 2001:db8::/32 is documentation space, which is protected.
        assert!(rules.is_err());
        let rules = rules_from(&[
            "GitHub.com".to_owned(),
            "*.npmjs.org:443".to_owned(),
            "185.199.108.0/22:8443".to_owned(),
            "pypi.org:443".to_owned(),
            "pypi.org:8443".to_owned(),
        ])
        .unwrap();
        let mut shown: Vec<_> = rules
            .iter()
            .map(|rule| (rule.target().to_string(), rule.ports().to_vec()))
            .collect();
        shown.sort();
        assert_eq!(
            shown,
            [
                ("*.npmjs.org".to_owned(), vec![443]),
                ("185.199.108.0/22".to_owned(), vec![8443]),
                ("github.com".to_owned(), vec![22, 80, 443]),
                ("pypi.org".to_owned(), vec![443, 8443]),
            ]
        );
        assert_eq!(
            split_port("2606:4700::/32").unwrap(),
            ("2606:4700::/32", None)
        );
        assert_eq!(
            split_port("[2606:4700::/32]:443").unwrap(),
            ("2606:4700::/32", Some(443))
        );
        for bad in [
            "github.com:0",
            "github.com:70000",
            "github.com:ssh",
            "[2606::/32",
        ] {
            assert!(split_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rm_names_whole_rules_without_ports() {
        assert_eq!(removal_target("GitHub.com").unwrap(), "github.com");
        assert!(
            removal_target("github.com:22")
                .unwrap_err()
                .to_string()
                .contains("without a port")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn built_ins_are_never_edited_and_nothing_starts_from_open() {
        assert!(base_selector("locked").unwrap().is_none());
        for name in ["open", "web"] {
            assert!(
                base_selector(name)
                    .unwrap_err()
                    .to_string()
                    .contains("start from `locked`")
            );
        }
        for name in ["open", "web", "locked"] {
            let error = stored_selector(name).unwrap_err().to_string();
            assert!(error.contains("built-in"), "{error}");
            // The hint must be one `create` accepts: never `--from open`.
            assert!(!error.contains("--from"), "{error}");
        }
        assert!(
            stored_selector("platform:work")
                .unwrap_err()
                .to_string()
                .contains("not available yet")
        );
        assert!(stored_selector("local:work").is_ok());
        assert!(stored_selector("work").is_ok());
    }
}
