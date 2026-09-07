use thiserror::Error;

const CODEX_PROVIDER_ID: &str = "codewire_openai";
const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Relative path for the generated credential-free Codex provider config.
pub const CODEX_CONFIG_FILE_NAME: &str = "config.toml";

/// Projected, purpose-bound workspace capability, never provider material.
pub const CODEX_PLATFORM_TOKEN_FILE: &str = "/run/codewire-credentials/workspace/token";
/// Public gateway CA bundle mounted only as trust, not a private identity.
pub const CODEX_PLATFORM_ROOTS_FILE: &str = "/run/codewire-credentials/gateway-roots/ca.crt";
/// Writable per-Pod Codex state, separate from the persisted user workspace.
pub const CODEX_PLATFORM_HOME: &str = "/run/codewire-codex/home";

/// Deterministic machine-owned Codex configuration for a protected provider
/// route.
///
/// The projection contains no provider credential or environment-key lookup.
/// Local delivery uses its guest loopback listener. Platform delivery uses a
/// fixed command to read a short-lived, purpose-bound Pod capability; it never
/// reads provider credentials. Both keep material in their broker boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexProviderProjection {
    config_toml: String,
}

impl CodexProviderProjection {
    /// Project an exact per-environment Kubernetes gateway on HTTPS port443.
    /// Codex 0.149.0's supported command-backed bearer mechanism re-reads the
    /// dedicated projected Pod capability on demand and after one401 retry.
    /// The caller also mounts public roots and sets CODEX_CA_CERTIFICATE to
    /// [`CODEX_PLATFORM_ROOTS_FILE`]. This is environment-level capability
    /// access, not a promise to hide the Pod token from its own workload.
    pub fn for_platform_gateway(dns_name: &str) -> Result<Self, ProjectionError> {
        if dns_name.len() > 253
            || !dns_name.ends_with(".svc.cluster.local")
            || dns_name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(ProjectionError::InvalidGuestEndpoint);
        }
        Ok(Self {
            config_toml: format!(
                concat!(
                    "model_provider = \"{provider}\"\n",
                    "\n",
                    "[model_providers.{provider}]\n",
                    "name = \"Codewire OpenAI\"\n",
                    "base_url = \"https://{dns_name}/v1\"\n",
                    "wire_api = \"responses\"\n",
                    "requires_openai_auth = false\n",
                    "supports_websockets = false\n",
                    "\n",
                    "[model_providers.{provider}.auth]\n",
                    "command = \"/bin/cat\"\n",
                    "args = [\"{token}\"]\n",
                    "cwd = \"/\"\n",
                    "timeout_ms = 2000\n",
                    "refresh_interval_ms = 30000\n",
                    "\n",
                    "[features]\n",
                    "enable_request_compression = false\n",
                ),
                provider = CODEX_PROVIDER_ID,
                token = CODEX_PLATFORM_TOKEN_FILE,
                dns_name = dns_name,
            ),
        })
    }

    /// Create a Responses-only provider projection for one unprivileged IPv4
    /// loopback port owned by the guest-side Codewire listener.
    pub fn for_loopback_port(port: u16) -> Result<Self, ProjectionError> {
        if port < MIN_UNPRIVILEGED_PORT {
            return Err(ProjectionError::InvalidGuestEndpoint);
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
                    "\n",
                    "[features]\n",
                    "enable_request_compression = false\n",
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

/// Stable material-free projection validation errors.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProjectionError {
    #[error("credential broker guest endpoint is invalid")]
    InvalidGuestEndpoint,
}

#[cfg(test)]
mod tests {
    use toml::Value;

    use super::*;

    #[test]
    fn platform_projection_reads_only_fixed_pod_capability_over_exact_https() {
        let host = "cw-gateway-svc-123.dev-sandboxes.svc.cluster.local";
        let projection = CodexProviderProjection::for_platform_gateway(host).unwrap();
        let parsed: Value = toml::from_str(projection.config_toml()).unwrap();
        let provider = &parsed["model_providers"][CODEX_PROVIDER_ID];
        assert_eq!(
            provider["base_url"].as_str(),
            Some(format!("https://{host}/v1").as_str())
        );
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(false));
        assert_eq!(provider["supports_websockets"].as_bool(), Some(false));
        let auth = &provider["auth"];
        assert_eq!(auth["command"].as_str(), Some("/bin/cat"));
        assert_eq!(
            auth["args"].as_array().unwrap(),
            &[Value::String(CODEX_PLATFORM_TOKEN_FILE.to_owned())]
        );
        assert_eq!(auth["cwd"].as_str(), Some("/"));
        assert_eq!(auth["timeout_ms"].as_integer(), Some(2000));
        assert_eq!(auth["refresh_interval_ms"].as_integer(), Some(30000));
        for forbidden in [
            "env_key",
            "experimental_bearer_token",
            "OPENAI_API_KEY",
            "auth.json",
            "sh -c",
            "Bearer ",
        ] {
            assert!(!projection.config_toml().contains(forbidden));
        }
    }

    #[test]
    fn platform_projection_rejects_authority_or_toml_injection() {
        for host in [
            "",
            "localhost",
            "127.0.0.1",
            "https://gateway.dev.svc.cluster.local",
            "gateway.dev.svc.cluster.local:8443",
            "gateway.dev.svc.cluster.local/elsewhere",
            "gateway.dev.svc.cluster.local\"\n",
            "Gateway.dev.svc.cluster.local",
            "gateway..svc.cluster.local",
            "-gateway.dev.svc.cluster.local",
            "gateway-.dev.svc.cluster.local",
            "gateway.dev.svc.cluster.local.",
        ] {
            assert_eq!(
                CodexProviderProjection::for_platform_gateway(host),
                Err(ProjectionError::InvalidGuestEndpoint)
            );
        }
    }

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
                "\n",
                "[features]\n",
                "enable_request_compression = false\n",
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
        assert_eq!(
            parsed
                .get("features")
                .and_then(Value::as_table)
                .and_then(|features| features.get("enable_request_compression"))
                .and_then(Value::as_bool),
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
                Err(ProjectionError::InvalidGuestEndpoint)
            );
        }
        for port in [MIN_UNPRIVILEGED_PORT, u16::MAX] {
            assert!(CodexProviderProjection::for_loopback_port(port).is_ok());
        }
    }
}
