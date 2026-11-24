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
//!
//! One exception, hosted only: where the binding selects the `github` slot,
//! a Git smart-HTTP request to `github.com` that carries no placeholder gets
//! GitHub's own challenge instead of the refusal, so Git asks its credential
//! helper, which answers with the placeholder (#4001; docs/dev/
//! SECRETS-AND-CREDENTIALS.md, "GitHub, hosted"). Nothing is leased for it
//! and nothing is sent upstream.

use std::collections::BTreeSet;

use http::Method;
use url::Url;

use super::{BrokerRequestError, OpenAiBroker};
use crate::network::RouteHost;

/// Where an untouched forward may go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UntouchedForwards {
    /// To the hosts the policy's holder named as allowed by rule on 443,
    /// lowercase. A broker started without an answer has none.
    AllowedHosts(BTreeSet<String>),
    /// Nowhere: this broker runs in the platform. With `git_challenge`, the
    /// binding selects the `github` slot, so Git's smart-HTTP requests to
    /// `github.com` are challenged rather than refused
    /// ([`Self::challenges_git`]).
    Refused { git_challenge: bool },
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
            Self::Refused { .. } => Err(BrokerRequestError::SelectedCredentialOnly),
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

    /// Whether a request that carries no placeholder-shaped value gets
    /// GitHub's challenge (401, `WWW-Authenticate: Basic realm="GitHub"`)
    /// instead of [`Self::check`]'s answer. Only when all hold: this broker
    /// refuses untouched forwards and its binding selects the `github` slot;
    /// the host is `github.com`, never `api.github.com`; and the request is
    /// on Git's smart-HTTP grammar exactly ([`git_smart_http`]).
    pub(crate) fn challenges_git(
        &self,
        host: RouteHost,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> bool {
        matches!(
            self,
            Self::Refused {
                git_challenge: true
            }
        ) && host == RouteHost::GitHub
            && git_smart_http(method, path, query)
    }
}

/// The services Git's smart HTTP names: fetch and push.
const GIT_SERVICES: [&str; 2] = ["git-upload-pack", "git-receive-pack"];

/// Git's smart-HTTP grammar, exactly: `GET <repository>/info/refs` whose
/// whole query is `service=` and one of [`GIT_SERVICES`], or
/// `POST <repository>/<service>` with no query. Any other method, path
/// suffix or query is not Git's.
fn git_smart_http(method: &Method, path: &str, query: Option<&str>) -> bool {
    let under_repository = |suffix: &str| {
        path.strip_suffix(suffix)
            .is_some_and(|repository| repository.len() > 1)
    };
    if *method == Method::GET {
        under_repository("/info/refs")
            && query
                .and_then(|query| query.strip_prefix("service="))
                .is_some_and(|service| GIT_SERVICES.contains(&service))
    } else if *method == Method::POST {
        query.is_none()
            && GIT_SERVICES
                .iter()
                .any(|service| under_repository(&format!("/{service}")))
    } else {
        false
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
        self.untouched_forwards = UntouchedForwards::Refused {
            git_challenge: false,
        };
        self
    }

    /// A hosted broker whose binding selects the `github` slot: Git's
    /// smart-HTTP requests to `github.com` that carry no placeholder get
    /// GitHub's challenge rather than the refusal (#4001). Every other
    /// untouched forward stays refused.
    pub fn with_untouched_forwards_refused_challenging_git(mut self) -> Self {
        self.untouched_forwards = UntouchedForwards::Refused {
            git_challenge: true,
        };
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
        for git_challenge in [false, true] {
            for target in [
                "https://api.anthropic.com/v1/messages",
                "https://github.com/owner/repo.git/info/refs?service=git-upload-pack",
            ] {
                assert_eq!(
                    UntouchedForwards::Refused { git_challenge }.check(&url(target), false),
                    Err(BrokerRequestError::SelectedCredentialOnly)
                );
            }
        }
    }

    /// GitHub's challenge needs every condition: a hosted broker whose
    /// binding selects the `github` slot, `github.com`, and Git's smart-HTTP
    /// grammar exactly. Each request here fails exactly one of them.
    #[test]
    fn only_gits_smart_http_to_github_com_is_challenged_and_only_when_github_is_selected() {
        let selected = UntouchedForwards::Refused {
            git_challenge: true,
        };
        let challenged = |forwards: &UntouchedForwards, host, method, path, query| {
            forwards.challenges_git(host, &method, path, query)
        };
        let grammar = [
            (
                Method::GET,
                "/owner/repo.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                Method::GET,
                "/owner/repo/info/refs",
                Some("service=git-receive-pack"),
            ),
            (Method::POST, "/owner/repo.git/git-upload-pack", None),
            (Method::POST, "/owner/repo.git/git-receive-pack", None),
        ];
        for (method, path, query) in grammar.clone() {
            assert!(
                challenged(&selected, RouteHost::GitHub, method.clone(), path, query),
                "{method} {path}"
            );
            // Never on the API's host.
            assert!(!challenged(
                &selected,
                RouteHost::GitHubApi,
                method.clone(),
                path,
                query
            ));
            // Never unless the binding selects the github slot, and never on
            // a broker that may forward.
            for other in [
                UntouchedForwards::Refused {
                    git_challenge: false,
                },
                UntouchedForwards::AllowedHosts(["github.com".to_owned()].into()),
                UntouchedForwards::default(),
            ] {
                assert!(!challenged(
                    &other,
                    RouteHost::GitHub,
                    method.clone(),
                    path,
                    query
                ));
            }
        }
        for (method, path, query) in [
            // A service Git does not fetch or push with, or none.
            (
                Method::GET,
                "/owner/repo.git/info/refs",
                Some("service=git-upload-archive"),
            ),
            (
                Method::GET,
                "/owner/repo.git/info/refs",
                Some("service=git-upload-pack&x=1"),
            ),
            (
                Method::GET,
                "/owner/repo.git/info/refs",
                Some("x=1&service=git-upload-pack"),
            ),
            (Method::GET, "/owner/repo.git/info/refs", Some("service=")),
            (Method::GET, "/owner/repo.git/info/refs", Some("")),
            (Method::GET, "/owner/repo.git/info/refs", None),
            // An extra path suffix, or none before the suffix.
            (
                Method::GET,
                "/owner/repo.git/info/refs/x",
                Some("service=git-upload-pack"),
            ),
            (
                Method::GET,
                "/owner/repo.git/info/refsx",
                Some("service=git-upload-pack"),
            ),
            (Method::GET, "/info/refs", Some("service=git-upload-pack")),
            (Method::POST, "/owner/repo.git/git-upload-pack/x", None),
            (Method::POST, "/git-receive-pack", None),
            (Method::POST, "/owner/repo.git/info/lfs/objects/batch", None),
            // A query on a POST, or the other method for a path.
            (
                Method::POST,
                "/owner/repo.git/git-upload-pack",
                Some("service=git-upload-pack"),
            ),
            (
                Method::POST,
                "/owner/repo.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (Method::GET, "/owner/repo.git/git-upload-pack", None),
            (Method::PUT, "/owner/repo.git/git-receive-pack", None),
            (
                Method::HEAD,
                "/owner/repo.git/info/refs",
                Some("service=git-upload-pack"),
            ),
        ] {
            assert!(
                !challenged(&selected, RouteHost::GitHub, method.clone(), path, query),
                "{method} {path} {query:?}"
            );
        }
    }
}
