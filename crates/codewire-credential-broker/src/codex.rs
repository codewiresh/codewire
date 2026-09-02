use crate::CredentialBrokerError;

const CODEX_PROVIDER_ID: &str = "codewire_openai";
const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Relative path for the generated credential-free Codex provider config.
pub const CODEX_CONFIG_FILE_NAME: &str = "config.toml";

/// Deterministic machine-owned Codex configuration for the guest loopback
/// endpoint.
///
/// The projection contains no provider credential, environment-key lookup,
/// token command, or reusable authorization value. The loopback HTTP leg is
/// credential-free; the isolated host broker terminates provider TLS and
/// injects authorization only after authenticating the environment operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexProviderProjection {
    config_toml: String,
}

impl CodexProviderProjection {
    /// Create a Responses-only provider projection for one unprivileged IPv4
    /// loopback port owned by the guest-side Codewire listener.
    pub fn for_loopback_port(port: u16) -> Result<Self, CredentialBrokerError> {
        if port < MIN_UNPRIVILEGED_PORT {
            return Err(CredentialBrokerError::InvalidGuestEndpoint);
        }
        Ok(Self {
            config_toml: format!(
                concat!(
                    "model_provider = \"{provider}\"\n",
                    "\n",
                    "[model_providers.{provider}]\n",
                    "name = \"Codewire OpenAI\"\n",
                    "base_url = \"http://127.0.0.1:{port}/v1\"\n",
                    "wire_api = \"responses\"\n",
                    "requires_openai_auth = false\n",
                    "supports_websockets = false\n",
                ),
                provider = CODEX_PROVIDER_ID,
                port = port,
            ),
        })
    }

    /// Return the complete UTF-8 contents to install as
    /// [`CODEX_CONFIG_FILE_NAME`] inside an isolated guest `CODEX_HOME`.
    pub fn config_toml(&self) -> &str {
        &self.config_toml
    }

    /// Consume the projection and return its complete UTF-8 contents.
    pub fn into_config_toml(self) -> String {
        self.config_toml
    }
}

#[cfg(test)]
mod tests {
    use toml::Value;

    use super::*;

    #[test]
    fn projects_one_credential_free_responses_provider() {
        let projection =
            CodexProviderProjection::for_loopback_port(38_081).expect("Codex projection");
        let config = projection.config_toml();
        assert_eq!(
            config,
            concat!(
                "model_provider = \"codewire_openai\"\n",
                "\n",
                "[model_providers.codewire_openai]\n",
                "name = \"Codewire OpenAI\"\n",
                "base_url = \"http://127.0.0.1:38081/v1\"\n",
                "wire_api = \"responses\"\n",
                "requires_openai_auth = false\n",
                "supports_websockets = false\n",
            )
        );
        let parsed = toml::from_str::<Value>(config).expect("valid TOML projection");

        assert_eq!(
            parsed.get("model_provider").and_then(Value::as_str),
            Some(CODEX_PROVIDER_ID)
        );
        let provider = parsed
            .get("model_providers")
            .and_then(Value::as_table)
            .and_then(|providers| providers.get(CODEX_PROVIDER_ID))
            .and_then(Value::as_table)
            .expect("Codewire provider");
        assert_eq!(provider.len(), 5);
        assert_eq!(
            provider.get("name").and_then(Value::as_str),
            Some("Codewire OpenAI")
        );
        assert_eq!(
            provider.get("base_url").and_then(Value::as_str),
            Some("http://127.0.0.1:38081/v1")
        );
        assert_eq!(
            provider.get("wire_api").and_then(Value::as_str),
            Some("responses")
        );
        assert_eq!(
            provider
                .get("requires_openai_auth")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            provider.get("supports_websockets").and_then(Value::as_bool),
            Some(false)
        );
        for forbidden in [
            "env_key",
            "experimental_bearer_token",
            "auth.command",
            "OPENAI_API_KEY",
            "Bearer ",
        ] {
            assert!(!config.contains(forbidden));
        }
        assert_eq!(CODEX_CONFIG_FILE_NAME, "config.toml");
        assert_eq!(projection.clone().into_config_toml(), config);
    }

    #[test]
    fn rejects_privileged_or_missing_loopback_ports() {
        for port in [0, 1, MIN_UNPRIVILEGED_PORT - 1] {
            assert_eq!(
                CodexProviderProjection::for_loopback_port(port),
                Err(CredentialBrokerError::InvalidGuestEndpoint)
            );
        }
        for port in [MIN_UNPRIVILEGED_PORT, u16::MAX] {
            assert!(CodexProviderProjection::for_loopback_port(port).is_ok());
        }
    }
}
