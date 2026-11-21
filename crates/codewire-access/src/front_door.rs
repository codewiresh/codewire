//! The hosts a TLS front door outside the environment serves (#3999, #4001).
//! [`front_door_hosts`] is the one selection both placements read: a local
//! boot's bindings and route table, and hosted interception's bindings, so
//! the two never serve different hosts for the same clients (#4001 step P).

use crate::{ManagedCredentialClient, ManagedCredentialClients};

/// The only port interception binds: the front door serves TLS.
pub const INTERCEPT_PORT: u16 = 443;

/// The Anthropic API.
pub const ANTHROPIC_API_HOST: &str = "api.anthropic.com";
/// The OpenAI API.
pub const OPENAI_API_HOST: &str = "api.openai.com";
/// Codex on a ChatGPT sign-in.
pub const CHATGPT_HOST: &str = "chatgpt.com";
/// The fixed suffixes under which Codex's account routing may name its model
/// origin (#3999): the egress broker intercepts every name under each on
/// 443, and a front-door request is served there only on Codex's model path,
/// at the origin this session recorded, dialled at the admitted address.
pub const ROUTED_SUFFIXES: [&str; 1] = [CHATGPT_HOST];

/// The routed suffix `host` is exactly one label under, if any.
pub fn routed_suffix(host: &str) -> Option<&'static str> {
    ROUTED_SUFFIXES.into_iter().find(|suffix| {
        host.strip_suffix(suffix)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    })
}
/// Claude's token host, on every path: the pinned Claude Code refreshes its
/// sign-in at `/v1/oauth/token`. Served only for a Claude sign-in.
pub const CLAUDE_TOKEN_HOST: &str = "platform.claude.com";
/// GitHub over Git and the GitHub API. Served only for a GitHub connection,
/// and only once [`GITHUB_INTERCEPTED`] is on.
pub const GITHUB_HOSTS: [&str; 2] = ["github.com", "api.github.com"];
/// Whether GitHub's hosts are served at all. They stay off until a
/// placeholder sent outside GitHub's route is refused on that route (#5087;
/// cw-security's condition on #5149), so GitHub stays on its loopback route
/// on both placements until then.
pub const GITHUB_INTERCEPTED: bool = false;

/// One host the front door serves on [`INTERCEPT_PORT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontDoorHost {
    pub host: &'static str,
    /// Every name strictly under `host` that no exact entry names, never
    /// `host` itself. A host served both ways is listed once each way.
    pub suffix: bool,
}

/// The hosts the front door routes for every environment.
pub const FRONT_DOOR_HOSTS: [FrontDoorHost; 3] = [
    FrontDoorHost {
        host: ANTHROPIC_API_HOST,
        suffix: false,
    },
    FrontDoorHost {
        host: OPENAI_API_HOST,
        suffix: false,
    },
    FrontDoorHost {
        host: CHATGPT_HOST,
        suffix: false,
    },
];

/// The hosts the front door serves for an environment whose stock clients are
/// `clients`, each exact: [`FRONT_DOOR_HOSTS`], Claude's token host for a
/// Claude sign-in, and GitHub's two hosts for a GitHub connection once
/// [`GITHUB_INTERCEPTED`]. With an API key, a subscription token or no
/// Anthropic client the token host is never served, and without a GitHub
/// connection neither GitHub host is, so the environment reaches them as it
/// would without a front door.
pub fn front_door_hosts(clients: ManagedCredentialClients) -> Vec<FrontDoorHost> {
    let exact = |host| FrontDoorHost {
        host,
        suffix: false,
    };
    let mut hosts = FRONT_DOOR_HOSTS.to_vec();
    if clients.anthropic_sign_in() {
        hosts.push(exact(CLAUDE_TOKEN_HOST));
    }
    if GITHUB_INTERCEPTED && clients.contains(ManagedCredentialClient::GitHub) {
        hosts.extend(GITHUB_HOSTS.map(exact));
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    fn names(clients: ManagedCredentialClients) -> Vec<&'static str> {
        front_door_hosts(clients)
            .iter()
            .map(|host| host.host)
            .collect()
    }

    #[test]
    fn the_fixed_hosts_are_served_for_every_selection() {
        let fixed = [ANTHROPIC_API_HOST, OPENAI_API_HOST, CHATGPT_HOST];
        assert_eq!(names(clients(&[])), fixed);
        assert_eq!(names(clients(&["openai", "codex", "ssh"])), fixed);
        assert_eq!(names(clients(&["anthropic"])), fixed);
        let token = clients(&["anthropic"])
            .with_anthropic_subscription_token()
            .unwrap();
        assert_eq!(names(token), fixed);
    }

    #[test]
    fn claude_token_host_is_served_for_a_claude_sign_in_only() {
        let sign_in = clients(&["anthropic"]).with_anthropic_sign_in().unwrap();
        assert_eq!(
            names(sign_in),
            [
                ANTHROPIC_API_HOST,
                OPENAI_API_HOST,
                CHATGPT_HOST,
                CLAUDE_TOKEN_HOST
            ]
        );
    }

    #[test]
    fn github_hosts_wait_for_the_refusal_on_their_route() {
        let github = clients(&["github", "ssh"]);
        assert_eq!(
            names(github)
                .iter()
                .filter(|host| GITHUB_HOSTS.contains(host))
                .count(),
            if GITHUB_INTERCEPTED { 2 } else { 0 }
        );
        assert!(
            !names(clients(&["ssh"]))
                .iter()
                .any(|host| GITHUB_HOSTS.contains(host))
        );
    }
}
