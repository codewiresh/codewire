//! `cw --cloud policy`: the organization's network policies (#4000). The
//! same subcommands, rules and output as the local store; the platform keeps
//! the revisions and digests. Nothing enforces a stored policy until
//! cw-egress does, and the commands that select one say so.

use codewire_client::{
    ClientError, CodewireClient, CreateNetworkPolicyRequest, DeleteNetworkPolicyRequest,
    GetNetworkPolicyRequest, ListNetworkPoliciesRequest, NetworkPolicy, NetworkPolicyRule,
    UpdateNetworkPolicyRequest,
};
use codewire_egress_policy::reference::{PolicyReference, PolicyStore};
use codewire_egress_policy::typed::AllowRule;
use codewire_proto::codewire::v1::__buffa::oneof::network_policy_selector::Selector;
use codewire_proto::codewire::v1::NetworkPolicySelector;

use super::*;

/// Whether hosted Sandboxes enforce an organization's network policies
/// (#4000). They don't yet: enforcement is per environment, and no
/// deployment-level state exists to read. Every platform policy command's
/// text and `check`'s JSON read this one constant, so nothing else claims
/// either way; when cw-egress enforces, the server's state replaces it
/// (#4000's done-when).
const HOSTED_ENFORCEMENT: bool = false;

/// Whether a platform policy command wrote the policy or only read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touched {
    /// create, allow and rm: a new revision was stored.
    Stored,
    /// ls and check.
    Read,
}

/// The one line every platform policy command's text ends with while hosted
/// Sandboxes don't enforce, on stderr and never in JSON.
fn say_hosted_enforcement(output: OutputFormat, touched: Touched) {
    if let Some(line) = hosted_enforcement_line(output, touched) {
        let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
            .stderr_style();
        eprintln!("{} {line}", style.status(crate::output::Status::Attention));
    }
}

/// The line, without the status glyph, or nothing: for JSON, or once hosted
/// Sandboxes enforce.
fn hosted_enforcement_line(output: OutputFormat, touched: Touched) -> Option<&'static str> {
    if HOSTED_ENFORCEMENT || !matches!(output, OutputFormat::Text) {
        return None;
    }
    Some(match touched {
        Touched::Stored => {
            "Stored. Hosted sandboxes don't enforce network policies yet, so this changes nothing a sandbox can reach."
        }
        Touched::Read => {
            "Hosted sandboxes don't enforce network policies yet: whatever their policy, they can reach any public destination."
        }
    })
}

impl ShownPolicy for NetworkPolicy {
    fn name(&self) -> &str {
        &self.name
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
            "reference": format!("platform:id:{}", self.id),
            "revision": self.revision,
            "current_revision": self.current_revision,
            "digest": self.digest,
            "rules": rules_json(self),
            "org_id": self.org_id,
        })
    }
}

pub(super) async fn handle(globals: &Globals, command: PolicyCommand) -> anyhow::Result<()> {
    let (org_id, _, _) = super::super::core::resolve_platform_context(globals).await?;
    let client = super::super::guided_credentials::platform_client(globals)?;
    match command {
        PolicyCommand::Log(_) => anyhow::bail!(NO_HOSTED_REFUSAL_LOG),
        PolicyCommand::Create(args) => {
            let from = args
                .from
                .as_deref()
                .map(base_selector)
                .transpose()?
                .flatten();
            let created = client
                .create_network_policy(CreateNetworkPolicyRequest {
                    org_id,
                    name: args.name.context("policy name is required")?,
                    from: from.into(),
                    allow: rules_proto(rules_from(&args.allow)?),
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("create the network policy", error))?;
            print_policy(
                "Created",
                &returned(created.policy.into_option())?,
                args.output,
            )?;
            say_hosted_enforcement(args.output, Touched::Stored);
            Ok(())
        }
        PolicyCommand::List(args) => {
            let listed = client
                .list_network_policies(ListNetworkPoliciesRequest {
                    org_id,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("list network policies", error))?;
            print_policies(&listed.policies, args.output)?;
            say_hosted_enforcement(args.output, Touched::Read);
            Ok(())
        }
        PolicyCommand::Allow(args) => {
            let changed = update(
                &client,
                UpdateNetworkPolicyRequest {
                    org_id,
                    policy: Some(stored_selector(&args.name)?).into(),
                    allow: rules_proto(rules_from(&args.targets)?),
                    ..Default::default()
                },
            )
            .await?;
            print_policy("Changed", &changed, args.output)?;
            say_hosted_enforcement(args.output, Touched::Stored);
            Ok(())
        }
        PolicyCommand::Rm(args) => {
            let remove = args
                .targets
                .iter()
                .map(|target| removal_target(target))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let changed = update(
                &client,
                UpdateNetworkPolicyRequest {
                    org_id,
                    policy: Some(stored_selector(&args.name)?).into(),
                    remove,
                    ..Default::default()
                },
            )
            .await?;
            print_policy("Changed", &changed, args.output)?;
            say_hosted_enforcement(args.output, Touched::Stored);
            Ok(())
        }
        PolicyCommand::Check(args) => {
            let stored = returned(
                client
                    .get_network_policy(GetNetworkPolicyRequest {
                        org_id,
                        policy: Some(stored_selector(&args.name)?).into(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| failed("read the network policy", error))?
                    .policy
                    .into_option(),
            )?;
            let compiled = typed_from(&stored, "the platform")?.compile();
            print_check(
                &args,
                &stored.name,
                Some(stored.revision),
                &compiled,
                Some(HOSTED_ENFORCEMENT),
            )?;
            say_hosted_enforcement(args.output, Touched::Read);
            Ok(())
        }
        PolicyCommand::Delete(args) => {
            let deleted = returned(
                client
                    .delete_network_policy(DeleteNetworkPolicyRequest {
                        org_id,
                        policy: Some(stored_selector(&args.name)?).into(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| failed("delete the network policy", error))?
                    .policy
                    .into_option(),
            )?;
            match args.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&deleted.json())?)
                }
                OutputFormat::Text => println!("Deleted network policy {}", deleted.name),
            }
            Ok(())
        }
    }
}

async fn update(
    client: &CodewireClient,
    request: UpdateNetworkPolicyRequest,
) -> anyhow::Result<NetworkPolicy> {
    returned(
        client
            .update_network_policy(request)
            .await
            .map_err(|error| failed("change the network policy", error))?
            .policy
            .into_option(),
    )
}

fn returned(policy: Option<NetworkPolicy>) -> anyhow::Result<NetworkPolicy> {
    policy.context("the platform returned no network policy")
}

/// The server's message, in the user's terms where the server says why. It
/// keeps the id of the trace the answer named.
fn failed(action: &str, error: ClientError) -> anyhow::Error {
    let text = match error.reason() {
        Some("NETWORK_POLICIES_DISABLED") => "organization network policies are not enabled on this deployment; keep the policy on this host with `cw --local policy`".to_owned(),
        _ => format!("couldn't {action}: {}", error.message()),
    };
    crate::reworded::reworded(text, error.trace_id())
}

fn rules_proto(rules: Vec<AllowRule>) -> Vec<NetworkPolicyRule> {
    rules
        .into_iter()
        .map(|rule| NetworkPolicyRule {
            target: rule.target().to_string(),
            ports: rule.ports().iter().map(|port| u32::from(*port)).collect(),
            ..Default::default()
        })
        .collect()
}

/// A stored platform policy named in a command: a bare name,
/// `platform:NAME` or `platform:id:UUID`. Built-ins are not stored and
/// cannot be edited, and a `local:` policy lives on a host.
fn stored_selector(value: &str) -> anyhow::Result<NetworkPolicySelector> {
    let selector = match PolicyReference::parse(value)
        .map_err(|error| anyhow::anyhow!("{value}: {error}"))?
    {
        PolicyReference::Builtin(builtin) => anyhow::bail!(
            "{builtin} is a built-in policy and cannot be changed; create your own with `cw --cloud policy create NAME --allow TARGET`, which starts from `locked`"
        ),
        PolicyReference::Name { store, name } => {
            require_platform(store)?;
            Selector::Name(name.to_string())
        }
        PolicyReference::Id { store, id } => {
            require_platform(Some(store))?;
            Selector::Id(id.to_string())
        }
    };
    Ok(NetworkPolicySelector {
        selector: Some(selector),
        ..Default::default()
    })
}

/// `--from`: `locked` (no selector) or a stored policy of the organization.
fn base_selector(value: &str) -> anyhow::Result<Option<NetworkPolicySelector>> {
    match BuiltinPolicy::from_name(value) {
        Some(BuiltinPolicy::Locked) => Ok(None),
        Some(BuiltinPolicy::Open) => anyhow::bail!(
            "a policy cannot start from `open`, which allows every public destination; start from `locked` and allow what you need"
        ),
        None => stored_selector(value).map(Some),
    }
}

fn require_platform(store: Option<PolicyStore>) -> anyhow::Result<()> {
    anyhow::ensure!(
        store != Some(PolicyStore::Local),
        "a `local:` policy lives on a host; use `cw --local policy`"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_platform_command_names_only_platform_policies() {
        assert!(matches!(
            stored_selector("web").unwrap().selector,
            Some(Selector::Name(name)) if name == "web"
        ));
        assert!(matches!(
            stored_selector("platform:web").unwrap().selector,
            Some(Selector::Name(name)) if name == "web"
        ));
        let id = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
        assert!(matches!(
            stored_selector(&format!("platform:id:{id}")).unwrap().selector,
            Some(Selector::Id(found)) if found == id
        ));
        let local = stored_selector("local:web").unwrap_err().to_string();
        assert!(local.contains("cw --local policy"), "{local}");
        for builtin in ["open", "locked"] {
            let error = stored_selector(builtin).unwrap_err().to_string();
            assert!(error.contains("built-in"), "{error}");
        }
    }

    #[test]
    fn a_platform_policy_renders_as_a_platform_reference() {
        let policy = NetworkPolicy {
            id: "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01".into(),
            org_id: "org".into(),
            name: "web".into(),
            revision: 2,
            current_revision: 2,
            rules: vec![NetworkPolicyRule {
                target: "github.com".into(),
                ports: vec![22, 443],
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = policy.json();
        assert_eq!(
            json["reference"],
            "platform:id:0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01"
        );
        assert_eq!(json["rules"][0]["ports"], serde_json::json!([22, 443]));
        assert_eq!(rules_text(&policy), "github.com (22, 443)");
    }

    #[test]
    fn a_platform_policy_starts_from_locked_or_one_of_the_organizations() {
        assert!(base_selector("locked").unwrap().is_none());
        assert!(base_selector("open").is_err());
        assert!(base_selector("web").unwrap().is_some());
    }

    #[test]
    fn a_disabled_store_answers_in_the_users_terms_from_the_servers_reason() {
        let error = connectrpc::ConnectError::new(
            connectrpc::ErrorCode::FailedPrecondition,
            "network policies are disabled",
        )
        .with_detail(connectrpc::ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &codewire_proto::google::rpc::ErrorInfo {
                reason: "NETWORK_POLICIES_DISABLED".into(),
                domain: "codewire.sh".into(),
                ..Default::default()
            },
        ));
        assert_eq!(
            failed("list network policies", ClientError::from(error)).to_string(),
            "organization network policies are not enabled on this deployment; keep the policy on this host with `cw --local policy`"
        );
    }

    #[test]
    fn the_not_enforced_line_is_said_in_text_and_never_in_json() {
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Text, Touched::Stored),
            Some(
                "Stored. Hosted sandboxes don't enforce network policies yet, so this changes nothing a sandbox can reach."
            )
        );
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Text, Touched::Read),
            Some(
                "Hosted sandboxes don't enforce network policies yet: whatever their policy, they can reach any public destination."
            )
        );
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Json, Touched::Stored),
            None
        );
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Json, Touched::Read),
            None
        );
    }

    #[test]
    fn a_disabled_deployment_says_so_in_the_users_terms() {
        let error = ClientError::new(
            codewire_client::ErrorCode::Unavailable,
            "platform network policies are not enabled on this deployment",
        );
        // Without the server's reason the action and message show.
        assert_eq!(
            failed("list network policies", error).to_string(),
            "couldn't list network policies: platform network policies are not enabled on this deployment"
        );
    }

    #[test]
    fn a_refusal_in_cws_words_keeps_its_trace_id() {
        use crate::error_report::trace_id;
        use crate::reworded::{TRACE_FOR_TESTS, answered_for_tests};
        let disabled = failed(
            "list network policies",
            answered_for_tests(
                connectrpc::ConnectError::failed_precondition("disabled"),
                "NETWORK_POLICIES_DISABLED",
            ),
        );
        assert_eq!(
            disabled.to_string(),
            "organization network policies are not enabled on this deployment; keep the policy on this host with `cw --local policy`"
        );
        assert_eq!(trace_id(&disabled), Some(TRACE_FOR_TESTS));
        let other = failed(
            "change the network policy",
            answered_for_tests(
                connectrpc::ConnectError::not_found("no such policy"),
                "OTHER",
            ),
        );
        assert_eq!(
            other.to_string(),
            "couldn't change the network policy: no such policy"
        );
        assert_eq!(trace_id(&other), Some(TRACE_FOR_TESTS));
    }
}
