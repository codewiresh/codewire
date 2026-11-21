//! Whether a front-door request that carries none of this environment's
//! placeholders may be forwarded untouched (#5555; `SPEC.md`, "On an
//! intercepted host…"; interception design, section 3a).
//!
//! The broker never sees the network policy. Locally the supervisor, which
//! holds it, says at launch which bound hosts a rule allows; a host it does
//! not name is refused. Hosted, nobody says: the broker runs in the platform,
//! where a forward would leave past the Sandbox's own policy and `cw-egress`,
//! so it refuses every such request by its own rule. Each forward branch asks
//! here with the URL it would dial, never a name the request gives, and a
//! refused request is answered the same whatever it carried.

use std::collections::BTreeSet;

use url::Url;

use super::{BrokerRequestError, OpenAiBroker};

/// Where an untouched forward may go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UntouchedForwards {
    /// To the hosts the policy's holder named as allowed by rule on 443,
    /// lowercase. A broker started without an answer has none.
    AllowedHosts(BTreeSet<String>),
    /// Nowhere: this broker runs in the platform.
    Refused,
}

impl Default for UntouchedForwards {
    fn default() -> Self {
        Self::AllowedHosts(BTreeSet::new())
    }
}

/// The only port an intercepted host is bound on.
const INTERCEPT_PORT: u16 = 443;

impl UntouchedForwards {
    /// `routed` is a forward to a routed origin, already admitted at the
    /// origin its session recorded, on Codex's model path and at the address
    /// the egress broker dialled; only such a forward may be allowed by a
    /// `*.` entry, and only one for a routed suffix, whatever the supervisor
    /// sent. A denied routed name never gets this far: the egress broker
    /// refuses its connection before any hand-off (`deny_beats_interception`).
    pub(crate) fn check(&self, target: &Url, routed: bool) -> Result<(), BrokerRequestError> {
        match self {
            Self::Refused => Err(BrokerRequestError::SelectedCredentialOnly),
            Self::AllowedHosts(hosts) => {
                let allowed = target.scheme() == "https"
                    && target.port_or_known_default() == Some(INTERCEPT_PORT)
                    && target.host_str().is_some_and(|host| {
                        let host = host.to_ascii_lowercase();
                        hosts.contains(&host)
                            || (routed
                                && codewire_access::routed_suffix(&host)
                                    .is_some_and(|suffix| hosts.contains(&format!("*.{suffix}"))))
                    });
                if allowed {
                    Ok(())
                } else {
                    Err(BrokerRequestError::NameNotAllowed)
                }
            }
        }
    }
}

impl<P, U> OpenAiBroker<P, U> {
    /// The bound hosts the environment's network policy allows by rule, as
    /// the local supervisor computed them from the same selection the egress
    /// broker enforces. An untouched forward to any other host is refused.
    pub fn with_network_policy_allowing_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.untouched_forwards = UntouchedForwards::AllowedHosts(
            hosts
                .into_iter()
                .map(|host| host.as_ref().to_ascii_lowercase())
                .collect(),
        );
        self
    }

    /// A hosted broker: no untouched forward, whatever the policy.
    pub fn with_untouched_forwards_refused(mut self) -> Self {
        self.untouched_forwards = UntouchedForwards::Refused;
        self
    }

    /// Before any untouched forward is dialled; `routed` as for
    /// [`UntouchedForwards::check`].
    pub(super) fn untouched_forward_allowed(
        &self,
        target: &Url,
        routed: bool,
    ) -> Result<(), BrokerRequestError> {
        self.untouched_forwards.check(target, routed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    #[test]
    fn a_broker_started_without_an_answer_refuses_every_untouched_forward() {
        assert_eq!(
            UntouchedForwards::default()
                .check(&url("https://api.anthropic.com/v1/messages"), false),
            Err(BrokerRequestError::NameNotAllowed)
        );
    }

    #[test]
    fn only_a_named_host_on_443_is_forwarded() {
        let rule = UntouchedForwards::AllowedHosts(["api.anthropic.com".to_owned()].into());
        assert_eq!(
            rule.check(&url("https://api.anthropic.com/v1/messages"), false),
            Ok(())
        );
        assert_eq!(
            rule.check(&url("https://API.Anthropic.com/v1/messages"), false),
            Ok(())
        );
        for refused in [
            "https://chatgpt.com/backend-api/codex",
            "https://api.anthropic.com:8443/v1/messages",
            "http://api.anthropic.com/v1/messages",
        ] {
            assert_eq!(
                rule.check(&url(refused), false),
                Err(BrokerRequestError::NameNotAllowed),
                "{refused}"
            );
        }
    }

    /// A `*.` entry lets through only a routed forward to a name exactly one
    /// label under a routed suffix; it never stands in for an exact host, and
    /// one for any other suffix counts for nothing.
    #[test]
    fn a_routed_suffix_entry_allows_only_a_routed_forward_one_label_under_it() {
        let rule = UntouchedForwards::AllowedHosts(
            ["*.chatgpt.com".to_owned(), "*.example.com".to_owned()].into(),
        );
        assert_eq!(
            rule.check(
                &url("https://a.chatgpt.com/backend-api/codex/responses"),
                true
            ),
            Ok(())
        );
        for (target, routed) in [
            ("https://a.chatgpt.com/backend-api/codex/responses", false),
            ("https://a.b.chatgpt.com/backend-api/codex/responses", true),
            ("https://chatgpt.com/backend-api/codex/responses", true),
            ("https://a.example.com/", true),
            (
                "https://a.chatgpt.com:8443/backend-api/codex/responses",
                true,
            ),
        ] {
            assert_eq!(
                rule.check(&url(target), routed),
                Err(BrokerRequestError::NameNotAllowed),
                "{target} {routed}"
            );
        }
    }

    #[test]
    fn a_hosted_broker_refuses_whatever_is_allowed() {
        assert_eq!(
            UntouchedForwards::Refused.check(&url("https://api.anthropic.com/v1/messages"), false),
            Err(BrokerRequestError::SelectedCredentialOnly)
        );
    }
}
