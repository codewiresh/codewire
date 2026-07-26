use std::env;
use std::time::Duration;

use connectrpc::{ErrorCode, Protocol};
use http::{HeaderMap, HeaderValue, header};
use url::Url;

use crate::ClientError;

pub const CODEWIRE_API_URL_ENV: &str = "CODEWIRE_API_URL";
pub const CODEWIRE_URL_ENV: &str = "CODEWIRE_URL";
pub const DEFAULT_CODEWIRE_URL: &str = "https://codewire.sh";
pub const DEFAULT_UNARY_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection settings shared by every generated Connect service client.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    server_url: Url,
    unary_timeout: Duration,
    user_agent: Option<HeaderValue>,
}

impl ClientConfig {
    /// Accept an explicit normalized CLI URL or any equivalent HTTP(S) base.
    pub fn new(server_url: impl AsRef<str>) -> Result<Self, ClientError> {
        let server_url = server_url.as_ref().trim().trim_end_matches('/');
        let parsed = Url::parse(server_url).map_err(|_| {
            ClientError::new(ErrorCode::InvalidArgument, "invalid Codewire server URL")
        })?;
        match parsed.scheme() {
            "http" | "https" => {}
            _ => {
                return Err(ClientError::new(
                    ErrorCode::InvalidArgument,
                    "Codewire server URL must use http or https",
                ));
            }
        }
        if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                "Codewire server URL must be an absolute HTTP URL",
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                "Codewire server URL must not contain a query or fragment",
            ));
        }

        Ok(Self {
            server_url: parsed,
            unary_timeout: DEFAULT_UNARY_TIMEOUT,
            user_agent: None,
        })
    }

    /// Preserve the legacy desktop's `CODEWIRE_API_URL` → `CODEWIRE_URL` →
    /// production-default resolution without coupling the wrapper to that app.
    pub fn from_env() -> Result<Self, ClientError> {
        Self::from_env_values(
            env::var(CODEWIRE_API_URL_ENV).ok(),
            env::var(CODEWIRE_URL_ENV).ok(),
        )
    }

    pub fn with_unary_timeout(mut self, timeout: Duration) -> Self {
        self.unary_timeout = timeout;
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl AsRef<str>) -> Result<Self, ClientError> {
        let user_agent = HeaderValue::try_from(user_agent.as_ref()).map_err(|_| {
            ClientError::new(
                ErrorCode::InvalidArgument,
                "Codewire client user-agent contains invalid header characters",
            )
        })?;
        self.user_agent = Some(user_agent);
        Ok(self)
    }

    pub fn server_url(&self) -> &Url {
        &self.server_url
    }

    pub fn unary_timeout(&self) -> Duration {
        self.unary_timeout
    }

    pub(crate) fn connect_config(&self) -> Result<connectrpc::client::ClientConfig, ClientError> {
        Ok(self
            .base_connect_config()?
            .with_default_timeout(self.unary_timeout))
    }

    fn base_connect_config(&self) -> Result<connectrpc::client::ClientConfig, ClientError> {
        let base_uri = self
            .server_url
            .as_str()
            .trim_end_matches('/')
            .parse()
            .map_err(|_| {
                ClientError::new(
                    ErrorCode::InvalidArgument,
                    "Codewire server URL is not a valid Connect URI",
                )
            })?;
        let mut headers = HeaderMap::new();
        if let Some(user_agent) = &self.user_agent {
            headers.insert(header::USER_AGENT, user_agent.clone());
        }
        Ok(connectrpc::client::ClientConfig::new(base_uri).with_default_headers(headers))
    }

    /// Environment sessions are bidirectional. The public TLS edge uses native
    /// gRPC to preserve request-stream progress through Cloudflare and
    /// ingress-nginx; direct/local cleartext endpoints retain Connect. The
    /// generated service has no default whole-call deadline because durable
    /// attachments are intentionally long-lived. Facade unary calls apply the
    /// configured unary timeout explicitly.
    pub(crate) fn environment_session_connect_config(
        &self,
    ) -> Result<connectrpc::client::ClientConfig, ClientError> {
        Ok(self
            .base_connect_config()?
            .with_protocol(self.environment_session_protocol()))
    }

    fn environment_session_protocol(&self) -> Protocol {
        match self.server_url.scheme() {
            "https" => Protocol::Grpc,
            "http" => Protocol::Connect,
            _ => unreachable!("ClientConfig validates the server URL scheme"),
        }
    }

    fn from_env_values(
        api_url: Option<String>,
        codewire_url: Option<String>,
    ) -> Result<Self, ClientError> {
        let server_url = api_url
            .filter(|value| !value.trim().is_empty())
            .or_else(|| codewire_url.filter(|value| !value.trim().is_empty()))
            .unwrap_or_else(|| DEFAULT_CODEWIRE_URL.to_owned());
        Self::new(server_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_url_is_normalized_and_validated() {
        let config = ClientConfig::new("  https://example.test/base/  ").expect("valid URL");
        assert_eq!(config.server_url().as_str(), "https://example.test/base");
        assert_eq!(config.unary_timeout(), DEFAULT_UNARY_TIMEOUT);

        assert!(ClientConfig::new("file:///tmp/codewire").is_err());
        assert!(ClientConfig::new("https://example.test/?token=nope").is_err());
    }

    #[test]
    fn desktop_environment_precedence_and_default_are_preserved() {
        let direct = ClientConfig::from_env_values(
            Some("https://api.example.test".into()),
            Some("https://edge.example.test".into()),
        )
        .expect("direct URL");
        assert_eq!(direct.server_url().host_str(), Some("api.example.test"));

        let edge = ClientConfig::from_env_values(
            Some("  ".into()),
            Some("https://edge.example.test".into()),
        )
        .expect("edge URL");
        assert_eq!(edge.server_url().host_str(), Some("edge.example.test"));

        let default = ClientConfig::from_env_values(None, None).expect("default URL");
        assert_eq!(default.server_url().as_str(), "https://codewire.sh/");
    }

    #[test]
    fn environment_sessions_use_grpc_only_for_secure_public_urls() {
        let direct = ClientConfig::new("http://127.0.0.1:8084").expect("direct URL");
        assert_eq!(direct.environment_session_protocol(), Protocol::Connect);
        assert_eq!(
            direct
                .environment_session_connect_config()
                .expect("direct session config")
                .default_timeout(),
            None,
            "durable attachments must not inherit the unary whole-call deadline"
        );

        let public = ClientConfig::new("https://codewire-dev.sh").expect("public URL");
        assert_eq!(public.environment_session_protocol(), Protocol::Grpc);
        assert_eq!(
            public
                .environment_session_connect_config()
                .expect("public session config")
                .default_timeout(),
            None
        );
    }
}
