//! The fixed hosts a TLS front door outside the environment serves (#3999,
//! #4001), which the front door's route table and hosted interception's
//! bindings both read. The hosts the front door adds for some environments'
//! clients (Claude's token host, GitHub) are not here yet: one selection for
//! both sides is #4001 step P.

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
