//! The curated coding-agent contract for workspace images.
//!
//! This registry describes *availability*, not installation. Workspace setup
//! must never turn a selected agent into an arbitrary curl, npm, or pip
//! download. The canonical workspace image supplies these commands instead.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentDefinition {
    pub id: &'static str,
    pub command: &'static str,
}

const AGENTS: &[AgentDefinition] = &[
    AgentDefinition {
        id: "claude-code",
        command: "claude",
    },
    AgentDefinition {
        id: "codex",
        command: "codex",
    },
    AgentDefinition {
        id: "gemini-cli",
        command: "gemini",
    },
    AgentDefinition {
        id: "kimi-code",
        command: "kimi",
    },
    AgentDefinition {
        id: "pi",
        command: "pi",
    },
    AgentDefinition {
        id: "aider",
        command: "aider",
    },
];

pub fn agent_definition(id: &str) -> Option<AgentDefinition> {
    AGENTS.iter().copied().find(|agent| agent.id == id)
}

pub fn is_supported_agent(id: &str) -> bool {
    agent_definition(id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_agents_have_stable_ids_and_commands() {
        assert_eq!(agent_definition("claude-code").unwrap().command, "claude");
        assert_eq!(agent_definition("codex").unwrap().command, "codex");
        assert_eq!(agent_definition("gemini-cli").unwrap().command, "gemini");
        assert_eq!(agent_definition("kimi-code").unwrap().command, "kimi");
        assert_eq!(agent_definition("pi").unwrap().command, "pi");
        assert_eq!(agent_definition("aider").unwrap().command, "aider");
        assert!(!is_supported_agent("unknown"));
    }
}
