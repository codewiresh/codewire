//! `cw --cloud policy`: the organization's network policies (#4000). The
//! same subcommands, rules and output as the local store; the platform keeps
//! the revisions and digests. A deployment enforces them where its hosted
//! egress is on, and the server says which (#3997).

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

/// Whether a platform policy command wrote the policy or only read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touched {
    /// create, allow and rm: a new revision was stored.
    Stored,
    /// ls and check.
    Read,
}

/// The one line every platform policy command's text ends with where the
/// deployment doesn't enforce hosted policies, on stderr and never in JSON.
/// `enforced` is the server's `hosted_policies_enforced`; `None` when it
/// could not be read, which claims nothing.
fn say_hosted_enforcement(output: OutputFormat, touched: Touched, enforced: Option<bool>) {
    if let Some(line) = hosted_enforcement_line(output, touched, enforced) {
        let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
            .stderr_style();
        eprintln!("{} {line}", style.status(crate::output::Status::Attention));
    }
}

/// The line, without the status glyph, or nothing: for JSON, or where the
/// deployment enforces or it isn't known.
fn hosted_enforcement_line(
    output: OutputFormat,
    touched: Touched,
    enforced: Option<bool>,
) -> Option<&'static str> {
    if enforced != Some(false) || !matches!(output, OutputFormat::Text) {
        return None;
    }
    Some(match touched {
        Touched::Stored => {
            "Stored. Network policies aren't enforced on this deployment, so this changes nothing a Sandbox can reach."
        }
        Touched::Read => {
            "Network policies aren't enforced on this deployment: whatever their policy, Sandboxes can reach any public destination."
        }
    })
}

/// After a write, whether the deployment enforces hosted policies, read
/// with the policy just written; only text says it, so JSON asks nothing.
async fn enforced_after_write(
    client: &CodewireClient,
    org_id: &str,
    policy: &NetworkPolicy,
    output: OutputFormat,
) -> Option<bool> {
    if !matches!(output, OutputFormat::Text) {
        return None;
    }
    client
        .get_network_policy(GetNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            policy: Some(NetworkPolicySelector {
                selector: Some(Selector::Id(policy.id.clone())),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .await
        .ok()
        .map(|response| response.hosted_policies_enforced)
}

impl ShownPolicy for NetworkPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn reference(&self) -> String {
        format!("platform:id:{}", self.id)
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
                    org_id: org_id.clone(),
                    name: args.name.context("policy name is required")?,
                    from: from.into(),
                    allow: rules_proto(rules_from(&args.allow)?),
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("create the network policy", error))?;
            let created = returned(created.policy.into_option())?;
            print_policy("Created", &created, args.output)?;
            let enforced = enforced_after_write(&client, &org_id, &created, args.output).await;
            say_hosted_enforcement(args.output, Touched::Stored, enforced);
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
            let enforced = listed.hosted_policies_enforced;
            print_policies(&listed.policies, args.output, enforced)?;
            say_hosted_enforcement(args.output, Touched::Read, Some(enforced));
            Ok(())
        }
        PolicyCommand::Allow(args) => {
            let changed = update(
                &client,
                UpdateNetworkPolicyRequest {
                    org_id: org_id.clone(),
                    policy: Some(stored_selector(&args.name)?).into(),
                    allow: rules_proto(rules_from(&args.targets)?),
                    ..Default::default()
                },
            )
            .await?;
            print_policy("Changed", &changed, args.output)?;
            let enforced = enforced_after_write(&client, &org_id, &changed, args.output).await;
            say_hosted_enforcement(args.output, Touched::Stored, enforced);
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
                    org_id: org_id.clone(),
                    policy: Some(stored_selector(&args.name)?).into(),
                    remove,
                    ..Default::default()
                },
            )
            .await?;
            print_policy("Changed", &changed, args.output)?;
            let enforced = enforced_after_write(&client, &org_id, &changed, args.output).await;
            say_hosted_enforcement(args.output, Touched::Stored, enforced);
            Ok(())
        }
        PolicyCommand::Check(args) => {
            let response = client
                .get_network_policy(GetNetworkPolicyRequest {
                    org_id,
                    policy: Some(stored_selector(&args.name)?).into(),
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("read the network policy", error))?;
            let enforced = response.hosted_policies_enforced;
            let stored = returned(response.policy.into_option())?;
            let compiled = typed_from(&stored, "the platform")?.compile();
            print_check(
                &args,
                &stored.name,
                Some(stored.revision),
                &compiled,
                Some(enforced),
            )?;
            say_hosted_enforcement(args.output, Touched::Read, Some(enforced));
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
    super::policies_disabled(&error).unwrap_or_else(|| {
        crate::reworded::reworded(
            format!("couldn't {action}: {}", error.message()),
            error.trace_id(),
        )
    })
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
        .map_err(|error| anyhow::anyhow!("the policy {value}: {error}"))?
    {
        PolicyReference::Builtin(builtin) => anyhow::bail!(
            "the built-in policy {builtin} cannot be changed; create your own with `cw --cloud policy create NAME --allow TARGET`, which starts from `locked`"
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
        Some(builtin @ (BuiltinPolicy::Open | BuiltinPolicy::Web)) => anyhow::bail!(
            "a policy cannot start from `{builtin}`, which allows every public destination; start from `locked` and allow what you need"
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

    /// The sentence and the `→` step an error carries.
    fn said(error: &anyhow::Error) -> (String, Option<String>) {
        (
            crate::error_report::sentence(error),
            crate::error_report::next_step(error),
        )
    }

    fn turned_off() -> (String, Option<String>) {
        (
            "network policies are turned off on this Codewire server; a local VM can still use one"
                .to_owned(),
            Some("cw --local policy".to_owned()),
        )
    }

    #[test]
    fn a_platform_command_names_only_platform_policies() {
        assert!(matches!(
            stored_selector("team-web").unwrap().selector,
            Some(Selector::Name(name)) if name == "team-web"
        ));
        assert!(matches!(
            stored_selector("platform:team-web").unwrap().selector,
            Some(Selector::Name(name)) if name == "team-web"
        ));
        let id = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
        assert!(matches!(
            stored_selector(&format!("platform:id:{id}")).unwrap().selector,
            Some(Selector::Id(found)) if found == id
        ));
        let local = stored_selector("local:team-web").unwrap_err().to_string();
        assert!(local.contains("cw --local policy"), "{local}");
        for builtin in ["open", "web", "locked"] {
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
        assert!(base_selector("web").is_err());
        assert!(base_selector("team-web").unwrap().is_some());
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
            said(&failed("list network policies", ClientError::from(error))),
            turned_off()
        );
    }

    /// Said in text only, and only where the server says the deployment
    /// doesn't enforce: never where it does, or where it isn't known (#3997).
    #[test]
    fn the_not_enforced_line_is_said_only_where_the_deployment_does_not_enforce() {
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Text, Touched::Stored, Some(false)),
            Some(
                "Stored. Network policies aren't enforced on this deployment, so this changes nothing a Sandbox can reach."
            )
        );
        assert_eq!(
            hosted_enforcement_line(OutputFormat::Text, Touched::Read, Some(false)),
            Some(
                "Network policies aren't enforced on this deployment: whatever their policy, Sandboxes can reach any public destination."
            )
        );
        for touched in [Touched::Stored, Touched::Read] {
            for enforced in [Some(true), None] {
                assert_eq!(
                    hosted_enforcement_line(OutputFormat::Text, touched, enforced),
                    None
                );
            }
            assert_eq!(
                hosted_enforcement_line(OutputFormat::Json, touched, Some(false)),
                None
            );
        }
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
        assert_eq!(said(&disabled), turned_off());
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
