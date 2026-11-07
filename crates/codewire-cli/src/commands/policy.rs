//! `cw policy`: network policies, the destinations an environment may reach
//! (#2537). Not Mesh networks, which `cw network` manages.
//!
//! A policy is named and every edit makes a new revision. `open` and `locked`
//! are built-ins. Policies live in this host's store (`--local`); platform
//! policies come later.

use std::collections::BTreeMap;
use std::net::IpAddr;

use clap::{Args, Subcommand};
use codewire_egress_policy::check::{CheckDestination, PolicyCheck};
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::reference::{PolicyReference, PolicyStore};
use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy};
use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy};

use super::*;

/// The ports a target gets when it names none: those `open` allows, so an
/// allowed Git host also works over SSH.
const DEFAULT_PORTS: [u16; 3] = [22, 80, 443];
const DEFAULT_CHECK_PORT: u16 = 443;

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
}

#[derive(Debug, Args)]
pub(crate) struct PolicyCreateArgs {
    #[arg(help = "The new policy's name")]
    pub(crate) name: String,
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
        };
        matches!(output, OutputFormat::Json)
    }
}

pub(crate) async fn handle_policy_command(
    globals: &Globals,
    args: PolicyArgs,
) -> anyhow::Result<()> {
    // `check` against a built-in needs no store.
    if let PolicyCommand::Check(check) = &args.command
        && let Some(builtin) = BuiltinPolicy::from_name(&check.name)
    {
        return print_check(check, &builtin.to_string(), None, &builtin.compile());
    }
    match globals.placement {
        Some(EnvironmentPlacement::Platform) => anyhow::bail!(
            "platform network policies are not available yet; keep this policy on this host with --local"
        ),
        Some(EnvironmentPlacement::Local) => {}
        None => {
            guided::require_available(
                if args.command.json() {
                    OutputFormat::Json
                } else {
                    OutputFormat::Text
                },
                "select the policy store: `cw --local policy ...`",
            )?;
            guided::choose(
                "Where should Codewire store this policy?",
                &[guided::Choice::new(
                    "On this computer",
                    "Local policy store; cloud policy storage is not available yet",
                )],
            )?;
        }
    }
    handle_local_policy_command(args.command).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_local_policy_command(command: PolicyCommand) -> anyhow::Result<()> {
    use codewire_local_vmm::control::v1;

    let mut client = native_client().await?;
    let status = |action: &'static str| {
        move |status: tonic::Status| anyhow::anyhow!("{action}: {}", status.message())
    };
    match command {
        PolicyCommand::Create(args) => {
            let from = args
                .from
                .as_deref()
                .map(base_selector)
                .transpose()?
                .flatten();
            let allow = rules_from(&args.allow)?;
            let created = client
                .create_network_policy(v1::CreateNetworkPolicyRequest {
                    name: args.name,
                    from,
                    allow: allow.into_iter().map(rule_proto).collect(),
                })
                .await
                .map_err(status("create the network policy"))?;
            print_policy("Created", &created, args.output)
        }
        PolicyCommand::List(args) => {
            let policies = client
                .list_network_policies()
                .await
                .map_err(status("list network policies"))?;
            print_policies(&policies, args.output)
        }
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
            let compiled = typed_from(&stored)?.compile();
            print_check(&args, &stored.name, Some(stored.revision), &compiled)
        }
        PolicyCommand::Delete(args) => {
            let deleted = client
                .delete_network_policy(stored_selector(&args.name)?)
                .await
                .map_err(status("delete the network policy"))?;
            match args.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&policy_json(&deleted))?)
                }
                OutputFormat::Text => println!("Deleted network policy {}", deleted.name),
            }
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn handle_local_policy_command(_command: PolicyCommand) -> anyhow::Result<()> {
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
        .map_err(|error| anyhow::anyhow!("{value}: {error}"))?
    {
        PolicyReference::Builtin(builtin) => anyhow::bail!(
            "{builtin} is a built-in policy and cannot be changed; create your own with `cw policy create NAME --allow TARGET`, which starts from `locked`"
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

/// `--from`: `locked` (no selector) or a stored policy. `open` allows every
/// public destination and is outside the rule subset, so nothing starts from it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn base_selector(
    value: &str,
) -> anyhow::Result<Option<codewire_local_vmm::control::v1::NetworkPolicySelector>> {
    match BuiltinPolicy::from_name(value) {
        Some(BuiltinPolicy::Locked) => Ok(None),
        Some(BuiltinPolicy::Open) => anyhow::bail!(
            "a policy cannot start from `open`, which allows every public destination; start from `locked` and allow what you need"
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
        let (target, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("{value}: a `[` needs its closing `]`"))?;
        return match tail {
            "" => Ok((target, None)),
            _ => {
                let port = tail
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow::anyhow!("{value}: write `[RANGE]:PORT`"))?;
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
        _ => anyhow::bail!("{value}: {port} is not a TCP port from 1 to 65535"),
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
        "{value}: `rm` removes a destination's whole rule; name it without a port"
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn typed_from(
    policy: &codewire_local_vmm::control::v1::NetworkPolicy,
) -> anyhow::Result<TypedPolicy> {
    let rules = policy
        .rules
        .iter()
        .map(|rule| {
            let ports = rule
                .ports
                .iter()
                .map(|port| u16::try_from(*port))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AllowRule::new(AllowTarget::parse(&rule.target)?, ports)?)
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .context("the supervisor returned an invalid network policy")?;
    let typed = TypedPolicy::new(rules)?;
    anyhow::ensure!(
        typed.compile().digest().to_hex() == policy.digest,
        "the supervisor returned a network policy whose rules do not match its digest"
    );
    Ok(typed)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn policy_json(policy: &codewire_local_vmm::control::v1::NetworkPolicy) -> serde_json::Value {
    serde_json::json!({
        "id": policy.id,
        "name": policy.name,
        "reference": format!("local:id:{}", policy.id),
        "revision": policy.revision,
        "current_revision": policy.current_revision,
        "digest": policy.digest,
        "rules": policy.rules.iter().map(|rule| serde_json::json!({
            "target": rule.target,
            "ports": rule.ports,
        })).collect::<Vec<_>>(),
        "created_unix_ms": policy.created_unix_ms,
        "enforced_in": policy.enforced_in,
        "restart_required_in": policy.restart_required_in,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rules_text(policy: &codewire_local_vmm::control::v1::NetworkPolicy) -> String {
    if policy.rules.is_empty() {
        return "nothing (like `locked`)".to_owned();
    }
    policy
        .rules
        .iter()
        .map(|rule| {
            let ports = rule
                .ports
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} ({ports})", rule.target)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_policy(
    verb: &str,
    policy: &codewire_local_vmm::control::v1::NetworkPolicy,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&policy_json(policy))?),
        OutputFormat::Text => {
            println!(
                "{verb} network policy {} · rev {}\n  Allows: {}",
                policy.name,
                policy.revision,
                rules_text(policy)
            );
            for line in applied_text(policy) {
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_policies(
    policies: &[codewire_local_vmm::control::v1::NetworkPolicy],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&policies.iter().map(policy_json).collect::<Vec<_>>())?
        ),
        OutputFormat::Text => {
            println!("open    built-in · every public destination on TCP 22, 80 and 443");
            println!("locked  built-in · nothing");
            for policy in policies {
                println!(
                    "{}  rev {} · {}",
                    policy.name,
                    policy.revision,
                    rules_text(policy)
                );
            }
        }
    }
    Ok(())
}

fn print_check(
    args: &PolicyCheckArgs,
    name: &str,
    revision: Option<u32>,
    policy: &CompiledPolicy,
) -> anyhow::Result<()> {
    let (destination, port) = split_port(&args.destination)?;
    let port = port.unwrap_or(DEFAULT_CHECK_PORT);
    let parsed = CheckDestination::parse(destination)
        .map_err(|_| anyhow::anyhow!("{destination} is not a DNS name or IP address"))?;
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
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policy": name,
                "revision": revision,
                "destination": shown,
                "allowed": check.is_allowed(),
                "reason": check.refusal.map(RefusalReason::code),
                "allowed_within": check.allowed_within,
                "refused_within": check.refusal.is_none().then_some(&check.refused_within),
            }))?
        ),
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
        assert!(
            base_selector("open")
                .unwrap_err()
                .to_string()
                .contains("start from `locked`")
        );
        for name in ["open", "locked"] {
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
