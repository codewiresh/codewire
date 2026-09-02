use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot, CredentialAuthKind,
    GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
};

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
            id: ProviderId::parse("openai").expect("built-in OpenAI provider ID"),
            authentication_kinds: BTreeSet::from([
                CredentialAuthKind::OAuth,
                CredentialAuthKind::ApiKey,
            ]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([
                        CredentialAuthKind::OAuth,
                        CredentialAuthKind::ApiKey,
                    ]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("responses")
                            .expect("built-in Responses operation ID"),
                        route: BrokerRouteId::parse("openai-api")
                            .expect("built-in OpenAI route ID"),
                    }]),
                },
            )]),
        },
        ProviderDefinition {
            id: ProviderId::parse("github").expect("built-in GitHub provider ID"),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::github(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("git-fetch")
                            .expect("built-in Git fetch operation ID"),
                        route: BrokerRouteId::parse("github-https")
                            .expect("built-in GitHub HTTPS route ID"),
                    }]),
                },
            )]),
        },
    ])
    .expect("built-in provider catalog")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_separate_storable_credentials_from_runnable_capabilities() {
        let catalog = builtin_provider_catalog();
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
            BTreeSet::from([GrantPermission {
                operation: BrokerOperationId::parse("responses").unwrap(),
                route: BrokerRouteId::parse("openai-api").unwrap(),
            }])
        );

        let github = catalog
            .get(&ProviderId::parse("github").unwrap())
            .expect("GitHub provider");
        assert_eq!(
            github.authentication_kinds,
            BTreeSet::from([CredentialAuthKind::OAuth])
        );
        assert_eq!(
            github.capabilities[&CapabilitySlot::github()],
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                permissions: BTreeSet::from([GrantPermission {
                    operation: BrokerOperationId::parse("git-fetch").unwrap(),
                    route: BrokerRouteId::parse("github-https").unwrap(),
                }]),
            }
        );
    }
}
