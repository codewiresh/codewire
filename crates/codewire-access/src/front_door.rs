//! The hosts a TLS front door outside the environment serves (#3999, #4001).
//! [`front_door_hosts`] is the one selection both placements read: a local
//! boot's bindings and route table, and hosted interception's bindings, so
//! the two never serve different hosts for the same clients (#4001 step P).
//! A host is served exactly when a selected credential names it (#5215;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "A host is proxied when something
//! selected names it").

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

/// The name a leaf carries for the `chatgpt.com` suffix: as TLS clients match
/// a wildcard, it covers exactly one label under it.
pub const CHATGPT_WILDCARD: &str = "*.chatgpt.com";

/// The routed suffix `host` is exactly one label under, if any.
pub fn routed_suffix(host: &str) -> Option<&'static str> {
    ROUTED_SUFFIXES
        .into_iter()
        .find(|suffix| one_label_under(host, suffix))
}

/// Whether `host` is exactly one non-empty label under `suffix`, compared byte
/// for byte: `a.chatgpt.com` is, and `a.b.chatgpt.com`, `.chatgpt.com`,
/// `xchatgpt.com` and `a.chatgpt.com.` are not. A caller that takes a name a
/// client chose checks it is canonical first, since case is not folded here.
pub fn one_label_under(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix)
        .and_then(|label| label.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}
/// Claude's token host, on every path: the pinned Claude Code refreshes its
/// sign-in at `/v1/oauth/token`. Served only for a Claude sign-in.
pub const CLAUDE_TOKEN_HOST: &str = "platform.claude.com";
/// Codex's token host, on every path: the pinned Codex refreshes its ChatGPT
/// sign-in at `/oauth/token` (#6197). Served only for the Codex slot.
pub const CODEX_TOKEN_HOST: &str = "auth.openai.com";
/// GitHub over Git and the GitHub API. Served only for a GitHub connection,
/// and only once [`GITHUB_INTERCEPTED`] is on.
pub const GITHUB_HOSTS: [&str; 2] = ["github.com", "api.github.com"];
/// The Gemini API (`generativelanguage.googleapis.com`). Front-door-only:
/// served only when the `gemini` slot is selected (#6555).
pub const GEMINI_API_HOST: &str = "generativelanguage.googleapis.com";
/// Antigravity Cloud Code daily endpoint (`daily-cloudcode-pa.googleapis.com`).
/// Front-door-only: served only when the `antigravity` slot is selected (#6555).
pub const ANTIGRAVITY_DAILY_HOST: &str = "daily-cloudcode-pa.googleapis.com";
/// Antigravity Cloud Code production endpoint (`cloudcode-pa.googleapis.com`).
/// Front-door-only: served only when the `antigravity` slot is selected (#6555).
pub const ANTIGRAVITY_PROD_HOST: &str = "cloudcode-pa.googleapis.com";
/// Google OAuth token endpoint (`oauth2.googleapis.com`), served for managed
/// refresh when the `antigravity` slot is selected (#6555).
pub const ANTIGRAVITY_OAUTH_HOST: &str = "oauth2.googleapis.com";
/// The Antigravity API hosts where pinned `POST /v1internal:` calls swap the
/// environment's placeholder for the leased Google access token (#6555).
pub const ANTIGRAVITY_API_HOSTS: [&str; 2] = [ANTIGRAVITY_DAILY_HOST, ANTIGRAVITY_PROD_HOST];
/// Every front-door host served for an Antigravity sign-in (#6555).
/// `www.googleapis.com` is permanently excluded.
pub const ANTIGRAVITY_HOSTS: [&str; 3] = [
    ANTIGRAVITY_DAILY_HOST,
    ANTIGRAVITY_PROD_HOST,
    ANTIGRAVITY_OAUTH_HOST,
];
/// Whether GitHub's hosts are served at all. On: a placeholder sent outside
/// GitHub's route is refused on that route (#5087, #5149), and both
/// placements deliver the `github` slot's placeholder and trust (#4001). A
/// boot or epoch without that placeholder still leaves GitHub on its
/// loopback route.
pub const GITHUB_INTERCEPTED: bool = true;

/// One host the front door serves on [`INTERCEPT_PORT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontDoorHost {
    pub host: &'static str,
    /// Every name exactly one label under `host` that no exact entry names,
    /// never `host` itself. A host served both ways is listed once each way.
    pub suffix: bool,
}

impl FrontDoorHost {
    /// The name an interception leaf carries for this entry: the host, or
    /// for a suffix its one-label wildcard. `None` for a suffix this table
    /// has no wildcard for, which no entry is.
    pub fn leaf_name(self) -> Option<&'static str> {
        match (self.host, self.suffix) {
            (host, false) => Some(host),
            (CHATGPT_HOST, true) => Some(CHATGPT_WILDCARD),
            _ => None,
        }
    }
}

/// Every provider host a selected credential may name for the front door:
/// the table [`front_door_hosts`] selects from. Its one suffix is
/// `chatgpt.com`, for Codex's routed workspace origin, and only the Codex
/// slot selects it (#6195).
pub const FRONT_DOOR_HOSTS: [FrontDoorHost; 5] = [
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
    FrontDoorHost {
        host: CHATGPT_HOST,
        suffix: true,
    },
    FrontDoorHost {
        host: CODEX_TOKEN_HOST,
        suffix: false,
    },
];

/// The hosts the front door serves for an environment whose stock clients are
/// `clients`, and only those its selected credentials name: the Anthropic API
/// for an Anthropic client, and Claude's token host as well for a Claude
/// sign-in; the OpenAI API for an OpenAI API key; `chatgpt.com`, every name
/// one label under it and Codex's token host for Codex; and GitHub's two
/// hosts for a GitHub connection once [`GITHUB_INTERCEPTED`]. Each is exact
/// but Codex's suffix. Every other host, an unselected provider's included,
/// is reached as it would be without a front door.
pub fn front_door_hosts(clients: ManagedCredentialClients) -> Vec<FrontDoorHost> {
    let exact = |host| FrontDoorHost {
        host,
        suffix: false,
    };
    let mut hosts = Vec::new();
    if clients.contains(ManagedCredentialClient::Anthropic) {
        hosts.push(exact(ANTHROPIC_API_HOST));
    }
    if clients.contains(ManagedCredentialClient::OpenAi) {
        hosts.push(exact(OPENAI_API_HOST));
    }
    if clients.contains(ManagedCredentialClient::Codex) {
        hosts.push(exact(CHATGPT_HOST));
        hosts.push(FrontDoorHost {
            host: CHATGPT_HOST,
            suffix: true,
        });
        hosts.push(exact(CODEX_TOKEN_HOST));
    }
    if clients.anthropic_sign_in() {
        hosts.push(exact(CLAUDE_TOKEN_HOST));
    }
    if GITHUB_INTERCEPTED && clients.contains(ManagedCredentialClient::GitHub) {
        hosts.extend(GITHUB_HOSTS.map(exact));
    }
    if clients.contains(ManagedCredentialClient::Gemini) {
        hosts.push(exact(GEMINI_API_HOST));
    }
    if clients.contains(ManagedCredentialClient::Antigravity) {
        hosts.extend(ANTIGRAVITY_HOSTS.map(exact));
    }
    hosts
}

/// Whether the front door serves GitHub's two hosts for `clients`: a GitHub
/// connection, once [`GITHUB_INTERCEPTED`] is on. Both placements bind them
/// from [`front_door_hosts`], so each reads this from the same selection.
pub fn binds_github(clients: ManagedCredentialClients) -> bool {
    front_door_hosts(clients)
        .iter()
        .any(|host| GITHUB_HOSTS.contains(&host.host))
}

/// Whether the front door serves the Gemini API host for `clients` (#6555).
pub fn binds_gemini(clients: ManagedCredentialClients) -> bool {
    front_door_hosts(clients)
        .iter()
        .any(|host| host.host == GEMINI_API_HOST)
}

/// Whether the front door serves Antigravity's hosts for `clients` (#6555).
pub fn binds_antigravity(clients: ManagedCredentialClients) -> bool {
    front_door_hosts(clients)
        .iter()
        .any(|host| ANTIGRAVITY_HOSTS.contains(&host.host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    /// The exact hosts served for `clients`.
    fn names(clients: ManagedCredentialClients) -> Vec<&'static str> {
        front_door_hosts(clients)
            .iter()
            .filter(|host| !host.suffix)
            .map(|host| host.host)
            .collect()
    }

    /// Every selection of the slots, in each Anthropic form it can take.
    fn every_selection() -> Vec<(Vec<&'static str>, ManagedCredentialClients)> {
        let slots = [
            "anthropic",
            "openai",
            "codex",
            "ssh",
            "github",
            "gemini",
            "antigravity",
        ];
        let mut selections = Vec::new();
        for bits in 0..(1_u16 << slots.len()) {
            let chosen: Vec<&str> = (0..slots.len())
                .filter(|bit| bits & (1 << bit) != 0)
                .map(|bit| slots[bit])
                .collect();
            let base = clients(&chosen);
            let forms = [
                Some(base),
                base.with_anthropic_subscription_token().ok(),
                base.with_anthropic_sign_in().ok(),
            ];
            for selection in forms.into_iter().flatten() {
                selections.push((chosen.clone(), selection));
            }
        }
        selections
    }

    #[test]
    fn a_providers_host_is_served_only_when_its_credential_is_selected() {
        assert!(names(clients(&[])).is_empty());
        assert!(names(clients(&["ssh"])).is_empty());
        assert_eq!(names(clients(&["anthropic"])), [ANTHROPIC_API_HOST]);
        assert_eq!(names(clients(&["openai"])), [OPENAI_API_HOST]);
        assert_eq!(names(clients(&["codex"])), [CHATGPT_HOST, CODEX_TOKEN_HOST]);
        assert_eq!(
            names(clients(&["openai", "codex", "ssh"])),
            [OPENAI_API_HOST, CHATGPT_HOST, CODEX_TOKEN_HOST]
        );
        let token = clients(&["anthropic"])
            .with_anthropic_subscription_token()
            .unwrap();
        assert_eq!(names(token), [ANTHROPIC_API_HOST]);
        // Every host served is one of the table's.
        let every = clients(&["anthropic", "openai", "codex"]);
        assert_eq!(front_door_hosts(every), FRONT_DOOR_HOSTS);
    }

    /// The checked-in list of every name any selection serves, which a Dev
    /// delivery compares between orchestration's source and the pinned
    /// cw-egress image's (egress-image-pin.py verify, infra#1534), is the
    /// derived set itself, so a host change anywhere moves the list.
    #[test]
    fn the_checked_in_front_door_host_list_is_the_derived_set() {
        let mut served: Vec<&str> = every_selection()
            .into_iter()
            .flat_map(|(_, selection)| front_door_hosts(selection))
            .map(|host| host.leaf_name().expect("every entry has a leaf name"))
            .collect();
        served.sort_unstable();
        served.dedup();
        let listed: Vec<&str> = include_str!("../front-door-hosts.txt").lines().collect();
        assert_eq!(
            listed, served,
            "crates/codewire-access/front-door-hosts.txt must list the derived set, one name a line"
        );
    }

    /// The `chatgpt.com` suffix is served for the Codex slot and no other
    /// selection, beside its exact host, and it is the only suffix any
    /// selection is served (#6195).
    #[test]
    fn the_chatgpt_suffix_is_served_for_the_codex_slot_only() {
        let suffix = FrontDoorHost {
            host: CHATGPT_HOST,
            suffix: true,
        };
        for (chosen, selection) in every_selection() {
            let served = front_door_hosts(selection);
            let codex = chosen.contains(&"codex");
            assert_eq!(served.contains(&suffix), codex, "{chosen:?}");
            assert_eq!(
                served.iter().filter(|host| host.suffix).count(),
                usize::from(codex),
                "{chosen:?}"
            );
            if codex {
                assert!(names(selection).contains(&CHATGPT_HOST), "{chosen:?}");
            }
        }
    }

    /// Each suffix the table serves is a routed suffix, and the name its leaf
    /// carries is its one-label wildcard.
    #[test]
    fn each_table_entry_has_its_leaf_name() {
        for host in FRONT_DOOR_HOSTS {
            let name = host.leaf_name().expect("every entry has a leaf name");
            if host.suffix {
                assert!(ROUTED_SUFFIXES.contains(&host.host), "{host:?}");
                assert_eq!(name, format!("*.{}", host.host));
            } else {
                assert_eq!(name, host.host);
            }
        }
        assert_eq!(
            FrontDoorHost {
                host: OPENAI_API_HOST,
                suffix: true,
            }
            .leaf_name(),
            None
        );
    }

    /// A routed name is exactly one label under its suffix, byte for byte
    /// (#6195): the forms cw-security named fail closed.
    #[test]
    fn a_routed_name_is_exactly_one_label_under_its_suffix() {
        for routed in ["x.chatgpt.com", "chatgpt-us.chatgpt.com"] {
            assert_eq!(routed_suffix(routed), Some(CHATGPT_HOST), "{routed}");
        }
        for refused in [
            "a.b.chatgpt.com",
            "chatgpt.com.example",
            "x.chatgpt.com.example",
            "xchatgpt.com",
            ".chatgpt.com",
            "..chatgpt.com",
            "chatgpt.com",
            "x.chatgpt.com.",
            "X.ChatGPT.com",
            "x.CHATGPT.COM",
            // Look-alikes of the suffix: Cyrillic letters, in Unicode and as
            // punycode, and a full-width dot.
            "x.chatg\u{0440}t.com",
            "x.xn--chatgt-frf.com",
            "x.xn--hatgpt-hrf.com",
            "x\u{ff0e}chatgpt.com",
            "",
        ] {
            assert_eq!(routed_suffix(refused), None, "{refused:?}");
        }
        assert!(one_label_under("routed.example.com", "example.com"));
        assert!(!one_label_under("example.com", "example.com"));
    }

    #[test]
    fn claude_token_host_is_served_for_a_claude_sign_in_only() {
        let sign_in = clients(&["anthropic"]).with_anthropic_sign_in().unwrap();
        assert_eq!(names(sign_in), [ANTHROPIC_API_HOST, CLAUDE_TOKEN_HOST]);
    }

    /// Codex's token host is one of the Codex slot's exact names, and no
    /// other selection's, whatever else it holds (#6197).
    #[test]
    fn codex_token_host_is_served_for_the_codex_slot_only() {
        let slots = ["anthropic", "openai", "codex", "ssh", "github"];
        for bits in 0..(1_u8 << slots.len()) {
            let chosen: Vec<&str> = (0..slots.len())
                .filter(|bit| bits & (1 << bit) != 0)
                .map(|bit| slots[bit])
                .collect();
            let base = clients(&chosen);
            let forms = [
                Some(base),
                base.with_anthropic_subscription_token().ok(),
                base.with_anthropic_sign_in().ok(),
            ];
            for selection in forms.into_iter().flatten() {
                let served = front_door_hosts(selection);
                assert_eq!(
                    served.contains(&FrontDoorHost {
                        host: CODEX_TOKEN_HOST,
                        suffix: false,
                    }),
                    chosen.contains(&"codex"),
                    "{chosen:?}"
                );
                assert!(
                    served
                        .iter()
                        .all(|host| host.host != CODEX_TOKEN_HOST || !host.suffix)
                );
            }
        }
    }

    /// GitHub's two hosts are served for a GitHub connection, and only then
    /// (#4001).
    #[test]
    fn github_hosts_are_served_for_a_github_connection() {
        let github = clients(&["github", "ssh"]);
        assert_eq!(
            names(github)
                .iter()
                .filter(|host| GITHUB_HOSTS.contains(host))
                .count(),
            2
        );
        assert!(
            !names(clients(&["ssh"]))
                .iter()
                .any(|host| GITHUB_HOSTS.contains(host))
        );
        assert!(binds_github(github));
        assert!(!binds_github(clients(&["anthropic", "ssh"])));
    }
}
