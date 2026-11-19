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
