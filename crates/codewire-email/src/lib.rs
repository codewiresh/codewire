//! Transactional Codewire email delivery.
//!
//! During the SES migration, an explicit workload-specific marker selects SES
//! and requires its complete, narrow AWS credential projection. Without that
//! marker, the client uses the existing Codewire Resend credential as a
//! rollback provider. An active SES sender never falls back to Resend after a
//! configuration or delivery error.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    SignableBody, SignableRequest, SigningParams, SigningSettings, sign,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};

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

/// Legacy Resend credential retained only until SES delivery and the access
/// signup flow are proved in an environment. Remove it immediately afterward
/// through a separately qualified environment transaction.
pub const RESEND_API_KEY_ENV: &str = "RESEND_API_KEY";

const SESSION_TOKEN_ENV: &str = "AWS_SESSION_TOKEN";
const DISABLE_IMDS_ENV: &str = "AWS_EC2_METADATA_DISABLED";
const IGNORE_ENDPOINTS_ENV: &str = "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS";
const ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL";
const SES_ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL_SES";
const SES_V2_ENDPOINT_URL_ENV: &str = "AWS_ENDPOINT_URL_SESV2";
const PROFILE_ENV: &str = "AWS_PROFILE";
const DEFAULT_PROFILE_ENV: &str = "AWS_DEFAULT_PROFILE";
const CONFIG_FILE_ENV: &str = "AWS_CONFIG_FILE";
const SHARED_CREDENTIALS_FILE_ENV: &str = "AWS_SHARED_CREDENTIALS_FILE";
const WEB_IDENTITY_TOKEN_FILE_ENV: &str = "AWS_WEB_IDENTITY_TOKEN_FILE";
const ROLE_ARN_ENV: &str = "AWS_ROLE_ARN";
const ROLE_SESSION_NAME_ENV: &str = "AWS_ROLE_SESSION_NAME";
const ECS_CREDENTIALS_RELATIVE_URI_ENV: &str = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const ECS_CREDENTIALS_FULL_URI_ENV: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const ECS_AUTHORIZATION_TOKEN_ENV: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
const ECS_AUTHORIZATION_TOKEN_FILE_ENV: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
const RESEND_EMAIL_ENDPOINT: &str = "https://api.resend.com/emails";
const RESEND_FROM: &str = "Codewire <ops@example.invalid>";

// SendEmail has no client idempotency key. One bounded HTTP attempt avoids
// turning an uncertain transport outcome into an automatic duplicate.
const EMAIL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const EMAIL_READ_TIMEOUT: Duration = Duration::from_secs(4);
const EMAIL_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone)]
pub struct EmailClient {
    delivery: Arc<Delivery>,
}

enum Delivery {
    Disabled,
    Resend(ResendDelivery),
    Ses(SesDelivery),
}

/// The active transactional-email transport. This is intentionally safe to
/// expose for diagnostics; it contains no delivery configuration or secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailProvider {
    Disabled,
    Resend,
    Ses,
}

/// The legacy credential stays within the dedicated delivery client. It is
/// deliberately neither `Clone` nor `Debug`.
struct ResendDelivery {
    api_key: String,
    client: reqwest::Client,
}

/// The material required to sign a request stays within the narrowly scoped
/// delivery client. It is deliberately neither `Clone` nor `Debug`.
struct SesDelivery {
    from: String,
    region: String,
    credentials: Credentials,
    client: reqwest::Client,
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
    /// Builds a client from the migration configuration. An explicit SES
    /// marker chooses SES exclusively; otherwise the legacy Resend credential
    /// remains available as the bounded rollback provider.
    pub async fn from_env() -> Result<Self> {
        if let Some(config) = EmailConfig::from_env()? {
            let credentials = EmailCredentials::from_env()?;
            assert_ses_transport_boundary()?;

            // The sender has one credential source and synthesizes its SES
            // HTTPS endpoint from the reviewed region. It does not load AWS
            // profiles, instance metadata, endpoint overrides, or a provider
            // chain.
            let credentials = Credentials::new(
                credentials.access_key_id,
                credentials.secret_access_key,
                None,
                None,
                "codewire-ses-projection",
            );
            return Ok(Self {
                delivery: Arc::new(Delivery::Ses(SesDelivery {
                    from: config.from,
                    region: config.region,
                    credentials,
                    client: ses_http_client()?,
                })),
            });
        }

        let Some(credentials) = ResendCredentials::from_env()? else {
            return Ok(Self::disabled());
        };
        Ok(Self {
            delivery: Arc::new(Delivery::Resend(ResendDelivery {
                api_key: credentials.api_key,
                client: resend_http_client()?,
            })),
        })
    }

    /// Returns a client that cannot send mail. This is intentionally explicit
    /// in tests and local development.
    pub fn disabled() -> Self {
        Self {
            delivery: Arc::new(Delivery::Disabled),
        }
    }

    /// Returns the selected transactional-email transport without exposing
    /// configuration or credentials.
    pub fn provider(&self) -> EmailProvider {
        match self.delivery.as_ref() {
            Delivery::Disabled => EmailProvider::Disabled,
            Delivery::Resend(..) => EmailProvider::Resend,
            Delivery::Ses(..) => EmailProvider::Ses,
        }
    }

    /// Whether this workload received a complete delivery configuration.
    pub fn is_configured(&self) -> bool {
        self.provider() != EmailProvider::Disabled
    }

    /// Delivers one UTF-8 HTML email through the selected transport.
    pub async fn send_html(&self, to: &str, subject: &str, html: &str) -> Result<()> {
        match self.delivery.as_ref() {
            Delivery::Disabled => bail!("transactional email delivery is not configured"),
            Delivery::Resend(delivery) => {
                validate_mailbox(to, "recipient")?;
                validate_subject(subject)?;
                let request =
                    resend_email_request(&delivery.client, &delivery.api_key, to, subject, html)?;
                let response = delivery
                    .client
                    .execute(request)
                    .await
                    .context("send Resend email")?;
                ensure_resend_success(response.status())
            }
            Delivery::Ses(delivery) => {
                validate_mailbox(to, "recipient")?;
                validate_subject(subject)?;
                let body = ses_email_payload(&delivery.from, to, subject, html)?;
                let request = signed_ses_request(
                    &delivery.client,
                    &delivery.credentials,
                    &delivery.region,
                    body,
                    SystemTime::now(),
                )?;
                let response = delivery
                    .client
                    .execute(request)
                    .await
                    .context("send SES email")?;
                ensure_ses_success(response.status())
            }
        }
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

/// Legacy Resend credentials are accepted only while SES is inactive. This
/// keeps the rollback path explicit and prevents malformed credentials from
/// being silently treated as an unavailable sender.
struct ResendCredentials {
    api_key: String,
}

impl ResendCredentials {
    fn from_env() -> Result<Option<Self>> {
        let api_key = read_optional_env(RESEND_API_KEY_ENV)?;
        Self::parse(api_key.as_deref())
    }

    fn parse(api_key: Option<&str>) -> Result<Option<Self>> {
        let Some(api_key) = api_key.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        if api_key
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            bail!("{RESEND_API_KEY_ENV} must not contain whitespace or control characters");
        }
        Ok(Some(Self {
            api_key: api_key.to_owned(),
        }))
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
            .ok_or_else(|| anyhow::anyhow!("{REGION_ENV} is required when {ENABLED_ENV}=true"))?;
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

fn assert_ses_transport_boundary() -> Result<()> {
    let disable_imds = read_optional_env(DISABLE_IMDS_ENV)?;
    let ignore_endpoints = read_optional_env(IGNORE_ENDPOINTS_ENV)?;
    let endpoint_url = read_optional_env(ENDPOINT_URL_ENV)?;
    let ses_endpoint_url = read_optional_env(SES_ENDPOINT_URL_ENV)?;
    let ses_v2_endpoint_url = read_optional_env(SES_V2_ENDPOINT_URL_ENV)?;
    let session_token = read_optional_env(SESSION_TOKEN_ENV)?;
    let profile = read_optional_env(PROFILE_ENV)?;
    let default_profile = read_optional_env(DEFAULT_PROFILE_ENV)?;
    let config_file = read_optional_env(CONFIG_FILE_ENV)?;
    let shared_credentials_file = read_optional_env(SHARED_CREDENTIALS_FILE_ENV)?;
    let web_identity_token_file = read_optional_env(WEB_IDENTITY_TOKEN_FILE_ENV)?;
    let role_arn = read_optional_env(ROLE_ARN_ENV)?;
    let role_session_name = read_optional_env(ROLE_SESSION_NAME_ENV)?;
    let ecs_credentials_relative_uri = read_optional_env(ECS_CREDENTIALS_RELATIVE_URI_ENV)?;
    let ecs_credentials_full_uri = read_optional_env(ECS_CREDENTIALS_FULL_URI_ENV)?;
    let ecs_authorization_token = read_optional_env(ECS_AUTHORIZATION_TOKEN_ENV)?;
    let ecs_authorization_token_file = read_optional_env(ECS_AUTHORIZATION_TOKEN_FILE_ENV)?;
    validate_ses_transport_boundary(
        disable_imds.as_deref(),
        ignore_endpoints.as_deref(),
        [
            (ENDPOINT_URL_ENV, endpoint_url.as_deref()),
            (SES_ENDPOINT_URL_ENV, ses_endpoint_url.as_deref()),
            (SES_V2_ENDPOINT_URL_ENV, ses_v2_endpoint_url.as_deref()),
        ],
        &[
            (SESSION_TOKEN_ENV, session_token.as_deref()),
            (PROFILE_ENV, profile.as_deref()),
            (DEFAULT_PROFILE_ENV, default_profile.as_deref()),
            (CONFIG_FILE_ENV, config_file.as_deref()),
            (
                SHARED_CREDENTIALS_FILE_ENV,
                shared_credentials_file.as_deref(),
            ),
            (
                WEB_IDENTITY_TOKEN_FILE_ENV,
                web_identity_token_file.as_deref(),
            ),
            (ROLE_ARN_ENV, role_arn.as_deref()),
            (ROLE_SESSION_NAME_ENV, role_session_name.as_deref()),
            (
                ECS_CREDENTIALS_RELATIVE_URI_ENV,
                ecs_credentials_relative_uri.as_deref(),
            ),
            (
                ECS_CREDENTIALS_FULL_URI_ENV,
                ecs_credentials_full_uri.as_deref(),
            ),
            (
                ECS_AUTHORIZATION_TOKEN_ENV,
                ecs_authorization_token.as_deref(),
            ),
            (
                ECS_AUTHORIZATION_TOKEN_FILE_ENV,
                ecs_authorization_token_file.as_deref(),
            ),
        ],
    )
}

fn validate_ses_transport_boundary(
    disable_imds: Option<&str>,
    ignore_endpoints: Option<&str>,
    endpoint_urls: [(&str, Option<&str>); 3],
    ambient_credential_source_inputs: &[(&str, Option<&str>)],
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
    // The signer never reads these values, but an enabled sender still fails
    // closed if its projection contains any ambient AWS credential-chain input.
    for (name, value) in ambient_credential_source_inputs {
        if value.is_some_and(|value| !value.is_empty()) {
            bail!("{name} is not permitted for Codewire SES delivery");
        }
    }
    Ok(())
}

fn ses_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(EMAIL_CONNECT_TIMEOUT)
        .read_timeout(EMAIL_READ_TIMEOUT)
        .timeout(EMAIL_OPERATION_TIMEOUT)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .context("construct SES HTTP client")
}

fn resend_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(EMAIL_CONNECT_TIMEOUT)
        .read_timeout(EMAIL_READ_TIMEOUT)
        .timeout(EMAIL_OPERATION_TIMEOUT)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .context("construct Resend HTTP client")
}

fn ses_email_payload(from: &str, to: &str, subject: &str, html: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "FromEmailAddress": from,
        "Destination": {
            "ToAddresses": [to],
        },
        "Content": {
            "Simple": {
                "Subject": {
                    "Data": subject,
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Html": {
                        "Data": html,
                        "Charset": "UTF-8",
                    },
                },
            },
        },
    }))
    .context("serialize SES email")
}

fn resend_email_payload(to: &str, subject: &str, html: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "from": RESEND_FROM,
        "to": [to],
        "subject": subject,
        "html": html,
    }))
    .context("serialize Resend email")
}

fn resend_email_request(
    client: &reqwest::Client,
    api_key: &str,
    to: &str,
    subject: &str,
    html: &str,
) -> Result<reqwest::Request> {
    let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
        .context("encode Resend authorization header")?;
    authorization.set_sensitive(true);
    client
        .post(RESEND_EMAIL_ENDPOINT)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, authorization)
        .body(resend_email_payload(to, subject, html)?)
        .build()
        .context("build Resend email request")
}

fn signed_ses_request(
    client: &reqwest::Client,
    credentials: &Credentials,
    region: &str,
    body: Vec<u8>,
    time: SystemTime,
) -> Result<reqwest::Request> {
    let endpoint = format!("https://email.{region}.amazonaws.com/v2/email/outbound-emails");
    let mut request = client
        .post(&endpoint)
        .header(CONTENT_TYPE, "application/json")
        .build()
        .context("build SES email request")?;
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str(),
                value.to_str().context("read SES email request header")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let signable_request = SignableRequest::new(
        "POST",
        request.url().as_str(),
        headers.iter().copied(),
        SignableBody::Bytes(&body),
    )
    .context("construct SES signable request")?;
    let identity: Identity = credentials.clone().into();
    let signing_params: SigningParams<'_> = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("ses")
        .time(time)
        .settings(SigningSettings::default())
        .build()
        .context("build SES signing parameters")?
        .into();
    let (instructions, _) = sign(signable_request, &signing_params)
        .context("sign SES email request")?
        .into_parts();
    let (headers, params) = instructions.into_parts();
    if !params.is_empty() {
        bail!("SES signing unexpectedly produced query parameters");
    }
    for header in headers {
        let mut value =
            HeaderValue::from_str(header.value()).context("encode SES signing header")?;
        value.set_sensitive(
            header.sensitive() || matches!(header.name(), "authorization" | "x-amz-security-token"),
        );
        request
            .headers_mut()
            .insert(HeaderName::from_static(header.name()), value);
    }
    *request.body_mut() = Some(body.into());
    Ok(request)
}

fn ensure_ses_success(status: reqwest::StatusCode) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        bail!("SES email request failed with HTTP {}", status.as_u16())
    }
}

fn ensure_resend_success(status: reqwest::StatusCode) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        bail!("Resend email request failed with HTTP {}", status.as_u16())
    }
}

fn validate_mailbox(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 320
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['<', '>', ',', ';'])
    {
        bail!("email {label} must be one plain email address");
    }
    let Some((local, domain)) = value.split_once('@') else {
        bail!("email {label} must be one plain email address");
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        bail!("email {label} must be one plain email address");
    }
    Ok(())
}

fn validate_subject(subject: &str) -> Result<()> {
    if subject.is_empty()
        || subject.len() > 998
        || subject.chars().any(|character| character.is_control())
    {
        bail!("email subject is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_ses_marker_leaves_the_legacy_provider_available() {
        assert_eq!(
            EmailConfig::parse(None, Some("hello@codewire.sh"), Some("eu-west-1")).unwrap(),
            None
        );
        assert!(
            ResendCredentials::parse(Some("re_legacy_credential"))
                .unwrap()
                .is_some()
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
    fn legacy_delivery_requires_a_well_formed_resend_credential() {
        assert!(ResendCredentials::parse(None).unwrap().is_none());
        assert!(ResendCredentials::parse(Some("")).unwrap().is_none());
        assert!(
            ResendCredentials::parse(Some("re_good_credential"))
                .unwrap()
                .is_some()
        );
        assert!(ResendCredentials::parse(Some("re credential")).is_err());
        assert!(ResendCredentials::parse(Some("re_credential\n")).is_err());
    }

    #[test]
    fn transactional_delivery_uses_one_bounded_http_attempt() {
        assert!(ses_http_client().is_ok());
        assert!(resend_http_client().is_ok());
        assert_eq!(EMAIL_CONNECT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(EMAIL_READ_TIMEOUT, Duration::from_secs(4));
        assert_eq!(EMAIL_OPERATION_TIMEOUT, Duration::from_secs(8));
    }

    #[test]
    fn ses_request_uses_the_reviewed_endpoint_and_a_sensitive_signature() {
        let client = ses_http_client().unwrap();
        let credentials =
            Credentials::new("test-access-key", "test-secret-key", None, None, "test");
        let request = signed_ses_request(
            &client,
            &credentials,
            "eu-west-1",
            b"{}".to_vec(),
            std::time::UNIX_EPOCH + Duration::from_secs(1_726_000_000),
        )
        .unwrap();

        assert_eq!(
            request.url().as_str(),
            "https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails"
        );
        assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
        let authorization = request.headers().get("authorization").unwrap();
        assert!(authorization.is_sensitive());
        assert!(
            authorization
                .to_str()
                .unwrap()
                .starts_with("AWS4-HMAC-SHA256 Credential=test-access-key/")
        );
        assert!(request.headers().contains_key("x-amz-date"));
    }

    #[test]
    fn ses_payload_uses_the_send_email_v2_shape() {
        let payload = ses_email_payload(
            "hello@codewire-dev.sh",
            "owner@example.com",
            "Review your Codewire request",
            "<p>review</p>",
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(value["FromEmailAddress"], "hello@codewire-dev.sh");
        assert_eq!(
            value["Destination"]["ToAddresses"],
            serde_json::json!(["owner@example.com"])
        );
        assert_eq!(
            value["Content"]["Simple"]["Subject"],
            serde_json::json!({"Data": "Review your Codewire request", "Charset": "UTF-8"})
        );
        assert_eq!(
            value["Content"]["Simple"]["Body"]["Html"],
            serde_json::json!({"Data": "<p>review</p>", "Charset": "UTF-8"})
        );
    }

    #[test]
    fn legacy_resend_request_preserves_the_reviewed_sender_and_secret_boundary() {
        let client = resend_http_client().unwrap();
        let request = resend_email_request(
            &client,
            "re_test_credential",
            "owner@example.com",
            "Review your Codewire request",
            "<p>review</p>",
        )
        .unwrap();

        assert_eq!(request.url().as_str(), RESEND_EMAIL_ENDPOINT);
        assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
        let authorization = request.headers().get(AUTHORIZATION).unwrap();
        assert!(authorization.is_sensitive());
        assert_eq!(authorization, "Bearer re_test_credential");
        let body = request.body().unwrap().as_bytes().unwrap();
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(value["from"], RESEND_FROM);
        assert_eq!(value["to"], serde_json::json!(["owner@example.com"]));
        assert_eq!(value["subject"], "Review your Codewire request");
        assert_eq!(value["html"], "<p>review</p>");
    }

    #[test]
    fn ses_response_status_must_indicate_delivery_success() {
        assert!(ensure_ses_success(reqwest::StatusCode::OK).is_ok());
        let error = ensure_ses_success(reqwest::StatusCode::FORBIDDEN).unwrap_err();
        assert_eq!(error.to_string(), "SES email request failed with HTTP 403");
    }

    #[test]
    fn legacy_resend_response_status_must_indicate_delivery_success() {
        assert!(ensure_resend_success(reqwest::StatusCode::ACCEPTED).is_ok());
        let error = ensure_resend_success(reqwest::StatusCode::TOO_MANY_REQUESTS).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Resend email request failed with HTTP 429"
        );
    }

    #[test]
    fn transport_boundary_rejects_metadata_and_endpoint_fallthrough() {
        let no_endpoint_overrides = [
            (ENDPOINT_URL_ENV, None),
            (SES_ENDPOINT_URL_ENV, None),
            (SES_V2_ENDPOINT_URL_ENV, None),
        ];
        assert!(
            validate_ses_transport_boundary(
                Some("true"),
                Some("true"),
                no_endpoint_overrides,
                &[],
            )
            .is_ok()
        );
        assert!(
            validate_ses_transport_boundary(
                Some("false"),
                Some("true"),
                no_endpoint_overrides,
                &[],
            )
            .is_err()
        );
        assert!(
            validate_ses_transport_boundary(
                Some("true"),
                Some("true"),
                [
                    (ENDPOINT_URL_ENV, Some("https://example.test")),
                    (SES_ENDPOINT_URL_ENV, None),
                    (SES_V2_ENDPOINT_URL_ENV, None),
                ],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn transport_boundary_rejects_every_ambient_credential_source() {
        let endpoint_urls = [
            (ENDPOINT_URL_ENV, None),
            (SES_ENDPOINT_URL_ENV, None),
            (SES_V2_ENDPOINT_URL_ENV, None),
        ];
        for name in [
            SESSION_TOKEN_ENV,
            PROFILE_ENV,
            DEFAULT_PROFILE_ENV,
            CONFIG_FILE_ENV,
            SHARED_CREDENTIALS_FILE_ENV,
            WEB_IDENTITY_TOKEN_FILE_ENV,
            ROLE_ARN_ENV,
            ROLE_SESSION_NAME_ENV,
            ECS_CREDENTIALS_RELATIVE_URI_ENV,
            ECS_CREDENTIALS_FULL_URI_ENV,
            ECS_AUTHORIZATION_TOKEN_ENV,
            ECS_AUTHORIZATION_TOKEN_FILE_ENV,
        ] {
            let error = validate_ses_transport_boundary(
                Some("true"),
                Some("true"),
                endpoint_urls,
                &[(name, Some("ambient-input"))],
            )
            .unwrap_err();
            assert!(error.to_string().contains(name));
        }
    }

    #[test]
    fn disabled_client_reports_that_delivery_is_unavailable() {
        let client = EmailClient::disabled();
        assert_eq!(client.provider(), EmailProvider::Disabled);
        assert!(!client.is_configured());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(client.send_html("owner@example.com", "Subject", "<p>body</p>"))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "transactional email delivery is not configured"
        );
    }
}
