//! Transactional Codewire email delivery through Amazon SES.
//!
//! Mail is disabled until the workload-specific SES projection explicitly
//! enables it and supplies both `CODEWIRE_SES_FROM` and
//! `CODEWIRE_SES_REGION`. The sender uses only the exact standard AWS access
//! key pair projected for that workload; it never falls through to profiles,
//! instance metadata, or another Codewire configuration value.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aws_config::{BehaviorVersion, Region, retry::RetryConfig, timeout::TimeoutConfig};
use aws_credential_types::Credentials;
use aws_sdk_sesv2::Client;
use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

/// Environment variable holding the exact SES From address approved for this
/// workload. It must be a single mailbox, without a display name.
pub const FROM_ENV: &str = "CODEWIRE_SES_FROM";

/// Environment variable holding the AWS region for the Codewire SES identity.
pub const REGION_ENV: &str = "CODEWIRE_SES_REGION";

/// A marker delivered only with the workload-specific SES credential
/// projection. It prevents a deployment with public sender configuration but
/// no mail credentials from accepting access requests it cannot verify.
pub const ENABLED_ENV: &str = "CODEWIRE_SES_ENABLED";

/// Standard AWS credential field projected from the dedicated SES Secret.
pub const ACCESS_KEY_ID_ENV: &str = "AWS_ACCESS_KEY_ID";

/// Standard AWS credential field projected from the dedicated SES Secret.
pub const SECRET_ACCESS_KEY_ENV: &str = "AWS_SECRET_ACCESS_KEY";

const SESSION_TOKEN_ENV: &str = "AWS_SESSION_TOKEN";
const DISABLE_IMDS_ENV: &str = "AWS_EC2_METADATA_DISABLED";
const IGNORE_ENDPOINTS_ENV: &str = "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS";
const ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL";
const SES_ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL_SES";
const SES_V2_ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL_SESV2";

// SendEmail has no client idempotency key. One bounded SDK attempt avoids
// turning an uncertain transport outcome into an SDK-originated duplicate.
const SES_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const SES_READ_TIMEOUT: Duration = Duration::from_secs(4);
const SES_OPERATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const SES_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone)]
pub struct EmailClient {
    delivery: Arc<Delivery>,
}

enum Delivery {
    Disabled,
    Ses { from: String, client: Client },
}

impl fmt::Debug for EmailClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailClient")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl EmailClient {
    /// Builds a client from public mail configuration and the dedicated AWS
    /// credential projection. The separate marker deliberately keeps mail
    /// disabled for local development and during an environment's cutover
    /// until that narrowly scoped projection is present.
    pub async fn from_env() -> Result<Self> {
        let Some(config) = EmailConfig::from_env()? else {
            return Ok(Self::disabled());
        };
        let credentials = EmailCredentials::from_env()?;
        assert_sdk_transport_boundary()?;

        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region))
            .credentials_provider(Credentials::new(
                credentials.access_key_id,
                credentials.secret_access_key,
                None,
                None,
                "codewire-ses-projection",
            ))
            .retry_config(ses_retry_config())
            .timeout_config(ses_timeout_config())
            .load()
            .await;
        Ok(Self {
            delivery: Arc::new(Delivery::Ses {
                from: config.from,
                client: Client::new(&sdk_config),
            }),
        })
    }

    /// Returns a client that cannot send mail. This is intentionally explicit
    /// in tests and local development rather than silently accepting a legacy
    /// mail-provider credential.
    pub fn disabled() -> Self {
        Self {
            delivery: Arc::new(Delivery::Disabled),
        }
    }

    /// Whether this workload received a complete SES delivery projection.
    pub fn is_configured(&self) -> bool {
        matches!(self.delivery.as_ref(), Delivery::Ses { .. })
    }

    /// Delivers one UTF-8 HTML email through the SES v2 `SendEmail` API.
    pub async fn send_html(&self, to: &str, subject: &str, html: &str) -> Result<()> {
        let Delivery::Ses { from, client } = self.delivery.as_ref() else {
            bail!("SES email delivery is not configured");
        };
        validate_mailbox(to, "recipient")?;
        validate_subject(subject)?;

        let subject = Content::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .context("build SES email subject")?;
        let html = Content::builder()
            .data(html)
            .charset("UTF-8")
            .build()
            .context("build SES HTML body")?;
        let message = Message::builder()
            .subject(subject)
            .body(Body::builder().html(html).build())
            .build();
        let destination = Destination::builder().to_addresses(to).build();
        let content = EmailContent::builder().simple(message).build();

        client
            .send_email()
            .from_email_address(from)
            .destination(destination)
            .content(content)
            .send()
            .await
            .context("send SES email")?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct EmailConfig {
    from: String,
    region: String,
}

/// Credentials are intentionally not `Debug` or `Clone`: after they have
/// entered the AWS SDK they are no longer retained in Codewire configuration.
struct EmailCredentials {
    access_key_id: String,
    secret_access_key: String,
}

impl EmailCredentials {
    fn from_env() -> Result<Self> {
        let access_key_id = read_optional_env(ACCESS_KEY_ID_ENV)?;
        let secret_access_key = read_optional_env(SECRET_ACCESS_KEY_ENV)?;
        let session_token = read_optional_env(SESSION_TOKEN_ENV)?;
        Self::parse(
            access_key_id.as_deref(),
            secret_access_key.as_deref(),
            session_token.as_deref(),
        )
    }

    fn parse(
        access_key_id: Option<&str>,
        secret_access_key: Option<&str>,
        session_token: Option<&str>,
    ) -> Result<Self> {
        if session_token.is_some_and(|value| !value.is_empty()) {
            bail!("{SESSION_TOKEN_ENV} is not permitted for Codewire SES delivery");
        }
        Ok(Self {
            access_key_id: validate_credential_value(ACCESS_KEY_ID_ENV, access_key_id)?,
            secret_access_key: validate_credential_value(SECRET_ACCESS_KEY_ENV, secret_access_key)?,
        })
    }
}

impl EmailConfig {
    fn from_env() -> Result<Option<Self>> {
        let enabled = read_optional_env(ENABLED_ENV)?;
        let from = read_optional_env(FROM_ENV)?;
        let region = read_optional_env(REGION_ENV)?;
        Self::parse(enabled.as_deref(), from.as_deref(), region.as_deref())
    }

    fn parse(
        enabled: Option<&str>,
        from: Option<&str>,
        region: Option<&str>,
    ) -> Result<Option<Self>> {
        match enabled.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some("false") => return Ok(None),
            Some("true") => {}
            Some(_) => bail!("{ENABLED_ENV} must be true or false"),
        }
        let Some(from) = from.map(str::trim).filter(|value| !value.is_empty()) else {
            bail!("{FROM_ENV} is required when {ENABLED_ENV}=true");
        };
        validate_mailbox(from, "sender")?;
        let region = region
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("{REGION_ENV} is required when {FROM_ENV} is configured")
            })?;
        if !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            bail!("{REGION_ENV} must be an AWS region identifier");
        }
        Ok(Some(Self {
            from: from.to_owned(),
            region: region.to_owned(),
        }))
    }
}

fn read_optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

fn validate_credential_value(name: &str, value: Option<&str>) -> Result<String> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        bail!("{name} is required when {ENABLED_ENV}=true");
    };
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("{name} must not contain whitespace or control characters");
    }
    Ok(value.to_owned())
}

fn assert_sdk_transport_boundary() -> Result<()> {
    let disable_imds = read_optional_env(DISABLE_IMDS_ENV)?;
    let ignore_endpoints = read_optional_env(IGNORE_ENDPOINTS_ENV)?;
    let endpoint_url = read_optional_env(ENDPOINT_URL_ENV)?;
    let ses_endpoint_url = read_optional_env(SES_ENDPOINT_URL_ENV)?;
    let ses_v2_endpoint_url = read_optional_env(SES_V2_ENDPOINT_URL_ENV)?;
    validate_sdk_transport_boundary(
        disable_imds.as_deref(),
        ignore_endpoints.as_deref(),
        [
            (ENDPOINT_URL_ENV, endpoint_url.as_deref()),
            (SES_ENDPOINT_URL_ENV, ses_endpoint_url.as_deref()),
            (SES_V2_ENDPOINT_URL_ENV, ses_v2_endpoint_url.as_deref()),
        ],
    )
}

fn validate_sdk_transport_boundary(
    disable_imds: Option<&str>,
    ignore_endpoints: Option<&str>,
    endpoint_urls: [(&str, Option<&str>); 3],
) -> Result<()> {
    for (name, value) in [
        (DISABLE_IMDS_ENV, disable_imds),
        (IGNORE_ENDPOINTS_ENV, ignore_endpoints),
    ] {
        if value != Some("true") {
            bail!("{name}=true is required for Codewire SES delivery");
        }
    }
    for (name, value) in endpoint_urls {
        if value.is_some_and(|value| !value.is_empty()) {
            bail!("{name} is not permitted for Codewire SES delivery");
        }
    }
    Ok(())
}

fn ses_retry_config() -> RetryConfig {
    RetryConfig::disabled()
}

fn ses_timeout_config() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(SES_CONNECT_TIMEOUT)
        .read_timeout(SES_READ_TIMEOUT)
        .operation_attempt_timeout(SES_OPERATION_ATTEMPT_TIMEOUT)
        .operation_timeout(SES_OPERATION_TIMEOUT)
        .build()
}

fn validate_mailbox(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 320
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['<', '>', ',', ';'])
    {
        bail!("SES {label} must be one plain email address");
    }
    let Some((local, domain)) = value.split_once('@') else {
        bail!("SES {label} must be one plain email address");
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        bail!("SES {label} must be one plain email address");
    }
    Ok(())
}

fn validate_subject(subject: &str) -> Result<()> {
    if subject.is_empty()
        || subject.len() > 998
        || subject.chars().any(|character| character.is_control())
    {
        bail!("SES email subject is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_marker_disables_delivery_even_with_public_sender_configuration() {
        assert_eq!(
            EmailConfig::parse(None, Some("hello@codewire.sh"), Some("eu-west-1")).unwrap(),
            None
        );
    }

    #[test]
    fn enabled_sender_requires_an_explicit_region() {
        let error = EmailConfig::parse(Some("true"), Some("hello@codewire.sh"), None).unwrap_err();
        assert!(error.to_string().contains(REGION_ENV));
    }

    #[test]
    fn sender_configuration_accepts_the_reviewed_shape() {
        assert_eq!(
            EmailConfig::parse(
                Some("true"),
                Some("hello@codewire-dev.sh"),
                Some("eu-west-1"),
            )
            .unwrap(),
            Some(EmailConfig {
                from: "hello@codewire-dev.sh".to_owned(),
                region: "eu-west-1".to_owned(),
            })
        );
    }

    #[test]
    fn sender_configuration_rejects_display_names_and_invalid_regions() {
        assert!(
            EmailConfig::parse(
                Some("true"),
                Some("Codewire <hello@codewire.sh>"),
                Some("eu-west-1"),
            )
            .is_err()
        );
        assert!(
            EmailConfig::parse(Some("true"), Some("hello@codewire.sh"), Some("eu-west_1")).is_err()
        );
    }

    #[test]
    fn marker_is_strict_and_requires_a_sender() {
        assert!(EmailConfig::parse(Some("yes"), None, None).is_err());
        let error = EmailConfig::parse(Some("true"), None, Some("eu-west-1")).unwrap_err();
        assert!(error.to_string().contains(FROM_ENV));
    }

    #[test]
    fn enabled_delivery_requires_the_exact_static_credential_pair() {
        assert!(EmailCredentials::parse(None, Some("secret"), None).is_err());
        assert!(EmailCredentials::parse(Some("access"), None, None).is_err());
        assert!(EmailCredentials::parse(Some("access"), Some("secret"), Some("token")).is_err());
        assert!(EmailCredentials::parse(Some("access"), Some("secret"), None).is_ok());
    }

    #[test]
    fn transactional_delivery_uses_one_bounded_sdk_attempt() {
        assert_eq!(ses_retry_config().max_attempts(), 1);
        let timeout = ses_timeout_config();
        assert_eq!(timeout.connect_timeout(), Some(SES_CONNECT_TIMEOUT));
        assert_eq!(timeout.read_timeout(), Some(SES_READ_TIMEOUT));
        assert_eq!(
            timeout.operation_attempt_timeout(),
            Some(SES_OPERATION_ATTEMPT_TIMEOUT)
        );
        assert_eq!(timeout.operation_timeout(), Some(SES_OPERATION_TIMEOUT));
    }

    #[test]
    fn transport_boundary_rejects_metadata_and_endpoint_fallthrough() {
        let no_endpoint_overrides = [
            (ENDPOINT_URL_ENV, None),
            (SES_ENDPOINT_URL_ENV, None),
            (SES_V2_ENDPOINT_URL_ENV, None),
        ];
        assert!(
            validate_sdk_transport_boundary(Some("true"), Some("true"), no_endpoint_overrides,)
                .is_ok()
        );
        assert!(
            validate_sdk_transport_boundary(Some("false"), Some("true"), no_endpoint_overrides,)
                .is_err()
        );
        assert!(
            validate_sdk_transport_boundary(
                Some("true"),
                Some("true"),
                [
                    (ENDPOINT_URL_ENV, Some("https://example.test")),
                    (SES_ENDPOINT_URL_ENV, None),
                    (SES_V2_ENDPOINT_URL_ENV, None),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn disabled_client_reports_that_delivery_is_unavailable() {
        let client = EmailClient::disabled();
        assert!(!client.is_configured());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(client.send_html("owner@example.com", "Subject", "<p>body</p>"))
            .unwrap_err();
        assert_eq!(error.to_string(), "SES email delivery is not configured");
    }
}
