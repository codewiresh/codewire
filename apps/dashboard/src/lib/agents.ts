export type AgentEnvVar = {
  key: string;
  label: string;
  placeholder?: string;
  required?: boolean;
};

export type AgentCatalogEntry = {
  id: string;
  label: string;
  envVars: AgentEnvVar[];
};

export const AGENT_CATALOG: AgentCatalogEntry[] = [
  {
    id: "claude-code",
    label: "Claude Code",
    envVars: [
      { key: "ANTHROPIC_API_KEY", label: "Anthropic API Key", placeholder: "sk-ant-...", required: false },
      { key: "CLAUDE_CODE_OAUTH_TOKEN", label: "Claude Code OAuth Token", placeholder: "claude auth token", required: false },
    ],
  },
  {
    id: "codex",
    label: "OpenAI Codex",
    envVars: [
      { key: "OPENAI_API_KEY", label: "OpenAI API Key", placeholder: "sk-...", required: true },
    ],
  },
  {
    id: "gemini-cli",
    label: "Gemini CLI",
    envVars: [
      { key: "GEMINI_API_KEY", label: "Gemini API Key", placeholder: "AIza...", required: true },
    ],
  },
  {
    id: "aider",
    label: "Aider",
    envVars: [
      { key: "OPENAI_API_KEY", label: "OpenAI API Key", placeholder: "sk-...", required: true },
    ],
  },
];

export const AGENT_CATALOG_BY_ID = Object.fromEntries(
  AGENT_CATALOG.map((agent) => [agent.id, agent]),
) as Record<string, AgentCatalogEntry>;
