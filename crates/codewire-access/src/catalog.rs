use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot, CredentialAuthKind,
    GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
};

/// Operation of the dedicated Codex login permission. It names the one listed
/// direct delivery exception (docs/dev/SECRETS-AND-CREDENTIALS.md): the
/// Sandbox creator's own personal Codex ChatGPT access and ID tokens, sealed to
/// the workspace daemon. No HTTP route or other operation implies it.
pub const CODEX_LOGIN_OPERATION: &str = "codex-login";
/// Route of the dedicated Codex login permission. It is not an HTTP route.
pub const CODEX_LOGIN_ROUTE: &str = "codex-login";

/// The Codex slot's dedicated permission for sealed login delivery. Holding it
/// is necessary, never sufficient: the broker also requires a hosted Sandbox,
/// an Active OAuth credential, and the creator as credential owner, profile
/// owner and confirming user.
pub fn codex_login_permission() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse(CODEX_LOGIN_OPERATION)
            .expect("built-in Codex login operation ID"),
        route: BrokerRouteId::parse(CODEX_LOGIN_ROUTE).expect("built-in Codex login route ID"),
    }
}

/// Return the provider credential forms and capabilities admitted by the
/// current Codewire credential stack.
///
/// The catalog is deliberately narrower than the type system. Storable
/// provider credentials and runnable capability adapters are both explicit:
/// enrollment may land before execution without making a half-working grant
/// selectable. An absent combination is unsupported rather than inferred from
/// ambient host configuration.
pub fn builtin_provider_catalog() -> ProviderCatalog {
    ProviderCatalog::from_definitions([
        ProviderDefinition {
            id: ProviderId::parse("ssh").expect("built-in SSH provider ID"),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::parse("ssh").expect("canonical SSH capability slot"),
                policy(
                    &[CredentialAuthKind::SshKey],
                    &[("ssh-identities", "ssh-agent"), ("ssh-sign", "ssh-agent")],
                ),
            )]),
        },
        ProviderDefinition {
            id: ProviderId::parse("openai").expect("built-in OpenAI provider ID"),
            authentication_kinds: BTreeSet::from([
                CredentialAuthKind::OAuth,
                CredentialAuthKind::ApiKey,
            ]),
            capabilities: BTreeMap::from([
                (
                    CapabilitySlot::codex(),
                    CapabilityPolicy {
                        authentication_kinds: BTreeSet::from([
                            CredentialAuthKind::OAuth,
                            CredentialAuthKind::ApiKey,
                        ]),
                        permissions: BTreeSet::from([
                            GrantPermission {
                                operation: BrokerOperationId::parse("responses")
                                    .expect("built-in Responses operation ID"),
                                route: BrokerRouteId::parse("openai-api")
                                    .expect("built-in OpenAI route ID"),
                            },
                            codex_login_permission(),
                        ]),
                    },
                ),
                (
                    CapabilitySlot::openai(),
                    policy(
                        &[CredentialAuthKind::ApiKey],
                        &[("responses", "openai-api")],
                    ),
                ),
            ]),
        },
        // One Anthropic slot holds either an API key or a Claude subscription
        // token (`claude setup-token`), its OAuth form. Both reach only the
        // same two Messages routes through the broker; neither is delivered.
        ProviderDefinition {
            id: ProviderId::parse("anthropic").expect("built-in Anthropic provider ID"),
            authentication_kinds: BTreeSet::from([
                CredentialAuthKind::OAuth,
                CredentialAuthKind::ApiKey,
            ]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::anthropic(),
                policy(
                    &[CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey],
                    &[
                        ("messages", "anthropic-api"),
                        ("count-tokens", "anthropic-api"),
                    ],
                ),
            )]),
        },
        ProviderDefinition {
            id: ProviderId::parse("github").expect("built-in GitHub provider ID"),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::github(),
                policy(
                    &[CredentialAuthKind::OAuth],
                    &[
                        ("git-fetch", "github-https"),
                        ("git-push", "github-https"),
                        ("rest", "github-api"),
                        ("graphql", "github-api"),
                    ],
                ),
            )]),
        },
    ])
    .expect("built-in provider catalog")
}

fn policy(kinds: &[CredentialAuthKind], permissions: &[(&str, &str)]) -> CapabilityPolicy {
    CapabilityPolicy {
        authentication_kinds: kinds.iter().copied().collect(),
        permissions: permissions
            .iter()
            .map(|(operation, route)| GrantPermission {
                operation: BrokerOperationId::parse(*operation).expect("built-in operation"),
                route: BrokerRouteId::parse(*route).expect("built-in route"),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_destination_families_require_exact_named_slot_provider_and_form() {
        use crate::{
            CredentialId, CredentialMetadata, CredentialStatus, HttpProvider, Owner, OwnerId,
            Placement,
        };
        let mut credential = CredentialMetadata {
            id: CredentialId::parse("synthetic-credential").unwrap(),
            placement: Placement::Local,
            owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
            provider: ProviderId::parse("openai").unwrap(),
            authentication_kind: CredentialAuthKind::ApiKey,
            display_name: "synthetic-only".into(),
            account_hint: None,
            ssh_public_key: None,
            status: CredentialStatus::Active,
            expires_at_unix: None,
            revocation_generation: 1,
        };
        for (slot, provider, kind, expected) in [
            (
                "codex",
                "openai",
                CredentialAuthKind::ApiKey,
                Some(HttpProvider::OpenAiApiKey),
            ),
            (
                "openai",
                "openai",
                CredentialAuthKind::ApiKey,
                Some(HttpProvider::OpenAiApiKey),
            ),
            (
                "codex",
                "openai",
                CredentialAuthKind::OAuth,
                Some(HttpProvider::CodexOAuth),
            ),
            ("openai", "openai", CredentialAuthKind::OAuth, None),
            (
                "anthropic",
                "anthropic",
                CredentialAuthKind::ApiKey,
                Some(HttpProvider::AnthropicApiKey),
            ),
            (
                "anthropic",
                "anthropic",
                CredentialAuthKind::OAuth,
                Some(HttpProvider::AnthropicSubscriptionToken),
            ),
            ("codex", "anthropic", CredentialAuthKind::OAuth, None),
            ("anthropic", "openai", CredentialAuthKind::OAuth, None),
            (
                "github",
                "github",
                CredentialAuthKind::OAuth,
                Some(HttpProvider::GitHubOAuth),
            ),
            ("github", "github", CredentialAuthKind::ApiKey, None),
            ("codex", "github", CredentialAuthKind::OAuth, None),
            ("other", "openai", CredentialAuthKind::ApiKey, None),
        ] {
            credential.provider = ProviderId::parse(provider).unwrap();
            credential.authentication_kind = kind;
            assert_eq!(
                HttpProvider::for_credential(&CapabilitySlot::parse(slot).unwrap(), &credential),
                expected
            );
        }
        assert!(serde_json::from_str::<HttpProvider>("\"unknown\"").is_err());
        assert!(HttpProvider::parse("github-app-authorization").is_none());
        for provider in [
            HttpProvider::AnthropicApiKey,
            HttpProvider::AnthropicSubscriptionToken,
        ] {
            assert_eq!(HttpProvider::parse(provider.as_str()), Some(provider));
            // Both Anthropic forms own the same stock-client names.
            assert_eq!(
                provider.reserved_environment_keys(),
                [
                    "ANTHROPIC_BASE_URL",
                    "ANTHROPIC_API_KEY",
                    "ANTHROPIC_AUTH_TOKEN",
                    "CLAUDE_CODE_OAUTH_TOKEN",
                ]
            );
        }
        assert_eq!(
            HttpProvider::AnthropicSubscriptionToken.as_str(),
            "anthropic-subscription-token"
        );
    }

    #[test]
    fn builtins_admit_only_typed_provider_capabilities() {
        let catalog = builtin_provider_catalog();
        let ssh = catalog.get(&ProviderId::parse("ssh").unwrap()).unwrap();
        assert_eq!(
            ssh.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::SshKey])
        );
        assert_eq!(
            ssh.capabilities,
            BTreeMap::from([(
                CapabilitySlot::parse("ssh").unwrap(),
                policy(
                    &[CredentialAuthKind::SshKey],
                    &[("ssh-identities", "ssh-agent"), ("ssh-sign", "ssh-agent")]
                ),
            )])
        );
        let provider = catalog
            .get(&ProviderId::parse("openai").unwrap())
            .expect("OpenAI provider");
        let codex = provider
            .capabilities
            .get(&CapabilitySlot::codex())
            .expect("Codex capability");

        assert_eq!(
            codex.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey,])
        );
        assert_eq!(provider.authentication_kinds, codex.authentication_kinds);
        assert_eq!(
            codex.permissions,
            BTreeSet::from([
                GrantPermission {
                    operation: BrokerOperationId::parse("responses").unwrap(),
                    route: BrokerRouteId::parse("openai-api").unwrap(),
                },
                GrantPermission {
                    operation: BrokerOperationId::parse("codex-login").unwrap(),
                    route: BrokerRouteId::parse("codex-login").unwrap(),
                },
            ])
        );
        // The dedicated login permission belongs to the Codex slot alone.
        for (id, provider) in [
            ("openai", provider),
            (
                "github",
                catalog.get(&ProviderId::parse("github").unwrap()).unwrap(),
            ),
            (
                "anthropic",
                catalog
                    .get(&ProviderId::parse("anthropic").unwrap())
                    .unwrap(),
            ),
            ("ssh", ssh),
        ] {
            for (slot, policy) in &provider.capabilities {
                assert_eq!(
                    policy.permissions.contains(&codex_login_permission()),
                    id == "openai" && *slot == CapabilitySlot::codex(),
                    "{id}/{slot}"
                );
            }
        }

        let github = catalog
            .get(&ProviderId::parse("github").unwrap())
            .expect("GitHub provider");
        assert_eq!(
            github.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::OAuth])
        );
        assert_eq!(
            github.capabilities[&CapabilitySlot::github()],
            policy(
                &[CredentialAuthKind::OAuth],
                &[
                    ("git-fetch", "github-https"),
                    ("git-push", "github-https"),
                    ("rest", "github-api"),
                    ("graphql", "github-api"),
                ]
            )
        );
        assert_eq!(
            provider.capabilities[&CapabilitySlot::openai()],
            policy(
                &[CredentialAuthKind::ApiKey],
                &[("responses", "openai-api")]
            )
        );
        let anthropic = catalog
            .get(&ProviderId::parse("anthropic").unwrap())
            .unwrap();
        assert_eq!(
            anthropic.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey])
        );
        assert_eq!(
            anthropic.capabilities[&CapabilitySlot::anthropic()],
            policy(
                &[CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey],
                &[
                    ("messages", "anthropic-api"),
                    ("count-tokens", "anthropic-api")
                ]
            )
        );
    }
}
