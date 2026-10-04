//! Material-free personal credential and profile adapters for the dashboard.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderValue;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileEntry, AccessProfileServiceClient, AddApiKeyCredentialRequest,
    AddClaudeSubscriptionTokenCredentialRequest, AddSshCredentialRequest,
    CompleteGithubAppAuthorizationRequest, CreateAccessProfileRequest, Credential,
    CredentialAuthenticationKind, CredentialMutationServiceClient, CredentialServiceClient,
    CredentialStatus, DeleteAccessProfileRequest, DeleteCredentialRequest, EnrollCodexRequest,
    EnrollCodexResponse, GenerateSshCredentialRequest, GetAccessProfileRequest,
    GetCredentialRequest, ListAccessProfilesRequest, ListCredentialsRequest,
    RenameAccessProfileRequest, RenameCredentialRequest, RevokeCredentialRequest,
    RotateApiKeyCredentialRequest, UpdateAccessProfileRequest, enroll_codex_response,
    get_access_profile_request, get_credential_request,
};
use connectrpc::{
    ConnectError, ErrorCode,
    client::{CallOptions, ClientConfig},
};

use crate::environment_source_forms::exact_id;
use crate::state::AppState;
use crate::time_display::calendar_date;
use crate::transport::BrowserTransport;
use crate::view::{
    CredentialChoiceView, CredentialChoicesView, CredentialProfileEntryView,
    CredentialProfileRowView, CredentialRowView,
};

const PAGE_SIZE: i32 = 100;
const MAX_PAGES: usize = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Sandbox notices are advisory: a slow read never holds the list or page.
const ATTENTION_TIMEOUT: Duration = Duration::from_secs(3);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(45);
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(16 * 60);
const MAX_MUTATION_RESPONSE_BYTES: usize = 16 * 1024;
/// The credential service records a pasted Claude subscription token's hard
/// expiry one year after it is added; `claude setup-token` names no issue time.
const CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS: u64 = 365 * 24 * 60 * 60;
/// Acknowledged expiry may differ from this page's clock by request time and
/// ordinary clock skew, never by a different lifetime.
const CLAUDE_SUBSCRIPTION_TOKEN_EXPIRY_TOLERANCE_SECONDS: u64 = 24 * 60 * 60;
/// A subscription token this close to its recorded expiry reads Expires soon.
const EXPIRES_SOON_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy)]
pub(crate) enum OAuthProvider {
    Codex,
}

pub(crate) struct OAuthEnrollmentRequest {
    pub(crate) provider: OAuthProvider,
    pub(crate) name: String,
    pub(crate) credential_id: Option<String>,
    pub(crate) expected_generation: Option<u64>,
}

// Deliberately not Debug: the challenge code is short-lived user-facing
// authorization material and must not enter routine diagnostics.
pub(crate) enum OAuthEnrollmentEvent {
    Challenge {
        provider: &'static str,
        verification_url: String,
        user_code: String,
        expires_utc: String,
    },
    Committed,
    Failed {
        reason: OAuthEnrollmentFailure,
        uncertain: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OAuthEnrollmentFailure {
    SignInRequired,
    Unavailable,
    AlreadyExists,
    Changed,
    Unsupported,
    Invalid,
    NotCompleted,
    Expired,
    Cancelled,
    UnexpectedResponse,
}

fn failed(uncertain: bool) -> OAuthEnrollmentEvent {
    OAuthEnrollmentEvent::Failed {
        reason: OAuthEnrollmentFailure::UnexpectedResponse,
        uncertain,
    }
}

fn failed_error(error: &ConnectError, uncertain: bool) -> OAuthEnrollmentEvent {
    use OAuthEnrollmentFailure as Failure;
    // Do not render or retain an upstream message, detail metadata, provider
    // output or challenge. Only these closed reasons cross into the view.
    let trusted_reason = match enrollment_error_reason(error) {
        Ok(reason) => reason,
        Err(()) => return failed(uncertain),
    };
    let reason = match (trusted_reason.as_deref(), error.code) {
        (Some("CREDENTIAL_REVISION_CHANGED"), ErrorCode::FailedPrecondition) => Failure::Changed,
        (Some("CREDENTIAL_ENROLLMENT_FAILED"), ErrorCode::FailedPrecondition) => {
            Failure::NotCompleted
        }
        (Some("CREDENTIAL_ENROLLMENT_UNSUPPORTED"), ErrorCode::FailedPrecondition) => {
            Failure::Unsupported
        }
        (Some("CREDENTIAL_ENROLLMENT_CLEANUP_FAILED"), ErrorCode::Unavailable)
        | (Some("CREDENTIAL_MUTATION_UNCERTAIN"), ErrorCode::Unknown) => {
            return failed(true);
        }
        (Some(_), _) => return failed(uncertain),
        (None, _) => match error.code {
            ErrorCode::Unauthenticated | ErrorCode::PermissionDenied => Failure::SignInRequired,
            ErrorCode::Unavailable | ErrorCode::ResourceExhausted => Failure::Unavailable,
            ErrorCode::AlreadyExists => Failure::AlreadyExists,
            ErrorCode::Aborted | ErrorCode::NotFound => Failure::Changed,
            ErrorCode::InvalidArgument => Failure::Invalid,
            ErrorCode::DeadlineExceeded => Failure::Expired,
            ErrorCode::Canceled => Failure::Cancelled,
            _ => Failure::UnexpectedResponse,
        },
    };
    // These failures are proven before publication. Other failures after a
    // challenge can leave publication uncertain, so preserve reconciliation.
    let uncertain = uncertain
        && !matches!(
            reason,
            Failure::AlreadyExists
                | Failure::Changed
                | Failure::Unsupported
                | Failure::NotCompleted
        );
    OAuthEnrollmentEvent::Failed { reason, uncertain }
}

fn enrollment_error_reason(error: &ConnectError) -> Result<Option<String>, ()> {
    let mut details = error.details.iter().filter(|detail| {
        matches!(
            detail.type_url.as_str(),
            "google.rpc.ErrorInfo" | "type.googleapis.com/google.rpc.ErrorInfo"
        )
    });
    let Some(detail) = details.next() else {
        return Ok(None);
    };
    if details.next().is_some() {
        return Err(());
    }
    let encoded = detail.value.as_deref().ok_or(())?;
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| STANDARD.decode(encoded))
        .map_err(|_| ())?;
    let info = codewire_proto::google::rpc::ErrorInfo::decode_from_slice(&bytes).map_err(|_| ())?;
    if info.domain != "codewire.sh" || info.reason.is_empty() {
        return Err(());
    }
    Ok(Some(info.reason))
}

pub(crate) fn github_authorization_feedback(error: &ConnectError) -> Option<&'static str> {
    if error.code != ErrorCode::FailedPrecondition {
        return None;
    }
    match enrollment_error_reason(error).ok()?.as_deref()? {
        "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED" => Some("github-app-unavailable"),
        "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED" => Some("github-installation-required"),
        "CREDENTIAL_ENROLLMENT_FAILED" => Some("github-app-failed"),
        "CREDENTIAL_ENROLLMENT_UNSUPPORTED" => Some("github-app-response-invalid"),
        _ => None,
    }
}

pub(crate) struct CredentialSettingsData {
    pub(crate) credentials: Vec<CredentialRowView>,
    pub(crate) profiles: Vec<CredentialProfileRowView>,
    pub(crate) choices: CredentialChoicesView,
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone()).with_default_timeout(REQUEST_TIMEOUT)
}

fn credential_client(
    state: &AppState,
    cookie: HeaderValue,
) -> CredentialServiceClient<BrowserTransport> {
    CredentialServiceClient::new(transport(state, cookie), config(state))
}

fn profile_client(
    state: &AppState,
    cookie: HeaderValue,
) -> AccessProfileServiceClient<BrowserTransport> {
    AccessProfileServiceClient::new(transport(state, cookie), config(state))
}

fn mutation_client(
    state: &AppState,
    cookie: HeaderValue,
) -> CredentialMutationServiceClient<BrowserTransport> {
    let origin = HeaderValue::from_str(&state.public_origin)
        .expect("validated dashboard public origin is a valid header value");
    CredentialMutationServiceClient::new(
        BrowserTransport {
            http: state.credential_http.clone(),
            cookie: Some(cookie),
            origin: Some(origin),
        },
        ClientConfig::new(state.credential_origin.clone())
            .with_default_timeout(MUTATION_TIMEOUT)
            .with_default_max_message_size(MAX_MUTATION_RESPONSE_BYTES),
    )
}

pub(crate) async fn run_oauth_enrollment(
    state: AppState,
    cookie: HeaderValue,
    request: OAuthEnrollmentRequest,
    events: tokio::sync::mpsc::Sender<OAuthEnrollmentEvent>,
) {
    let expected = match enrollment_expected(&state, cookie.clone(), &request).await {
        Ok(expected) => expected,
        Err(error) => {
            let _ = events.send(failed_error(&error, false)).await;
            return;
        }
    };
    let expected_name = request.name.clone();
    let client = mutation_client(&state, cookie);
    let options = CallOptions::default()
        .with_timeout(ENROLLMENT_TIMEOUT)
        .with_max_message_size(MAX_MUTATION_RESPONSE_BYTES);
    match request.provider {
        OAuthProvider::Codex => {
            let rpc = EnrollCodexRequest {
                name: request.name,
                credential_id: request.credential_id,
                expected_revocation_generation: request.expected_generation,
                ..Default::default()
            };
            let stream = tokio::select! {
                _ = events.closed() => return,
                result = client.enroll_codex_with_options(rpc, options) => result,
            };
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = events.send(failed_error(&error, false)).await;
                    return;
                }
            };
            let mut challenged = false;
            loop {
                let message = tokio::select! {
                    _ = events.closed() => return,
                    result = stream.message::<EnrollCodexResponse>() => result,
                };
                match message {
                    Ok(Some(message)) => match message.to_owned_message().event {
                        Some(enroll_codex_response::Event::Challenge(challenge))
                            if !challenged && valid_codex_challenge(&challenge) =>
                        {
                            challenged = true;
                            if events
                                .send(OAuthEnrollmentEvent::Challenge {
                                    provider: "OpenAI Codex",
                                    verification_url: challenge.verification_url,
                                    user_code: challenge.user_code,
                                    expires_utc: challenge_expiry(challenge.expires_at_unix),
                                })
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Some(enroll_codex_response::Event::Credential(credential))
                            if challenged
                                && validate_oauth_ack(
                                    &credential,
                                    "openai",
                                    &expected_name,
                                    &expected,
                                )
                                .is_ok() =>
                        {
                            let terminal = tokio::select! {
                                _ = events.closed() => return,
                                result = stream.message::<EnrollCodexResponse>() => result,
                            };
                            let event = if matches!(terminal, Ok(None)) {
                                OAuthEnrollmentEvent::Committed
                            } else {
                                failed(true)
                            };
                            let _ = events.send(event).await;
                            return;
                        }
                        Some(enroll_codex_response::Event::Credential(_)) => {
                            let _ = events.send(failed(true)).await;
                            return;
                        }
                        _ => {
                            let _ = events.send(failed(challenged)).await;
                            return;
                        }
                    },
                    Ok(None) => {
                        let _ = events.send(failed(challenged)).await;
                        return;
                    }
                    Err(error) => {
                        let _ = events.send(failed_error(&error, challenged)).await;
                        return;
                    }
                }
            }
        }
    }
}

async fn enrollment_expected(
    state: &AppState,
    cookie: HeaderValue,
    request: &OAuthEnrollmentRequest,
) -> Result<Option<Credential>, ConnectError> {
    match (&request.credential_id, request.expected_generation) {
        (None, None) => Ok(None),
        (Some(id), Some(generation)) => {
            let current = get_exact_credential(state, cookie, id).await?;
            let expected_slot = match request.provider {
                OAuthProvider::Codex => "codex",
            };
            if current.name != request.name
                || current.revocation_generation != generation
                || credential_slot(&current)? != expected_slot
            {
                return Err(ConnectError::aborted("credential metadata changed"));
            }
            Ok(Some(current))
        }
        _ => Err(invalid_metadata()),
    }
}

fn validate_oauth_ack(
    credential: &Credential,
    provider: &str,
    expected_name: &str,
    expected: &Option<Credential>,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    if credential.provider != provider
        || credential.authentication_kind != CredentialAuthenticationKind::Oauth
        || credential.status != CredentialStatus::Active
        || credential.name != expected_name
    {
        return Err(invalid_metadata());
    }
    if let Some(current) = expected {
        if credential.id != current.id
            || credential.name != current.name
            || credential.expires_at_unix != current.expires_at_unix
            || credential.revocation_generation != current.revocation_generation + 1
        {
            return Err(invalid_metadata());
        }
    } else if credential.revocation_generation != 1 || credential.expires_at_unix.is_some() {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn valid_codex_challenge(challenge: &codewire_proto::codewire::v1::CodexDeviceChallenge) -> bool {
    challenge.verification_url == "https://auth.openai.com/codex/device"
        && !challenge.user_code.is_empty()
        && challenge.user_code.len() <= 64
        && challenge
            .user_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && challenge.expires_at_unix > 0
        && challenge.expires_at_unix <= i64::MAX as u64
}

fn challenge_expiry(expires_at_unix: u64) -> String {
    chrono::DateTime::from_timestamp(expires_at_unix as i64, 0)
        .expect("validated enrollment challenge timestamp")
        .format("%Y-%m-%d %H:%M UTC")
        .to_string()
}

pub(crate) async fn add_api_key(
    state: &AppState,
    cookie: HeaderValue,
    provider: String,
    name: String,
    value: Vec<u8>,
    expires_at_unix: Option<u64>,
) -> Result<(), ConnectError> {
    let response = mutation_client(state, cookie)
        .add_api_key_credential(AddApiKeyCredentialRequest {
            provider: provider.clone(),
            name: name.clone(),
            value,
            expires_at_unix,
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_created_ack(
        &credential,
        &name,
        &provider,
        CredentialAuthenticationKind::ApiKey,
        expires_at_unix,
    )
}

/// Store a pasted Claude subscription token (`claude setup-token`), or
/// replace the exact named one the dialog observed. The token is sent only to
/// the isolated credential authority; the acknowledgement is metadata only.
pub(crate) async fn add_claude_subscription_token(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    token: Vec<u8>,
    replacement: Option<(String, u64)>,
) -> Result<(), ConnectError> {
    let current = match &replacement {
        None => None,
        Some((credential_id, generation)) => {
            let current = get_exact_credential(state, cookie.clone(), credential_id).await?;
            if current.revocation_generation != *generation
                || current.name != name
                || credential_form(&current)? != "claude"
            {
                return Err(ConnectError::aborted("credential metadata changed"));
            }
            Some(current)
        }
    };
    let (credential_id, expected_revocation_generation) = replacement.unzip();
    let response = mutation_client(state, cookie)
        .add_claude_subscription_token_credential(AddClaudeSubscriptionTokenCredentialRequest {
            name: name.clone(),
            token,
            credential_id,
            expected_revocation_generation,
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_subscription_token_ack(&credential, &name, current.as_ref(), unix_now()?)
}

/// A created token is a new Active personal Anthropic OAuth identity; a
/// replaced one keeps its identity and name at the next generation. Either way
/// its expiry restarts one year from now.
fn validate_subscription_token_ack(
    credential: &Credential,
    expected_name: &str,
    current: Option<&Credential>,
    now: u64,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    let expected_expiry = now + CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS;
    if credential_form(credential)? != "claude"
        || credential.name != expected_name
        || credential.account_hint.is_some()
        || credential.status != CredentialStatus::Active
        || credential.expires_at_unix.is_none_or(|expiry| {
            expiry.abs_diff(expected_expiry) > CLAUDE_SUBSCRIPTION_TOKEN_EXPIRY_TOLERANCE_SECONDS
        })
    {
        return Err(invalid_metadata());
    }
    let expected_generation = match current {
        None => 1,
        Some(current) => {
            if credential.id != current.id {
                return Err(invalid_metadata());
            }
            current
                .revocation_generation
                .checked_add(1)
                .filter(|generation| *generation <= i64::MAX as u64)
                .ok_or_else(invalid_metadata)?
        }
    };
    if credential.revocation_generation != expected_generation {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn unix_now() -> Result<u64, ConnectError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| invalid_metadata())
}

/// Complete the server-side GitHub App callback. The callback code is sent
/// only to credential-service over the authenticated mutation connection; the
/// browser receives no token, provider response, or installation metadata.
pub(crate) async fn complete_github_app_authorization(
    state: &AppState,
    cookie: HeaderValue,
    code: Vec<u8>,
    credential_id: Option<String>,
    expected_generation: Option<u64>,
) -> Result<(), ConnectError> {
    let current = match (&credential_id, expected_generation) {
        (None, None) => None,
        (Some(id), Some(generation)) => {
            let current = get_exact_credential(state, cookie.clone(), id).await?;
            if current.provider != "github"
                || current.authentication_kind != CredentialAuthenticationKind::Oauth
                || current.revocation_generation != generation
            {
                return Err(ConnectError::aborted("credential metadata changed"));
            }
            Some(current)
        }
        _ => return Err(invalid_metadata()),
    };
    let response = mutation_client(state, cookie)
        .complete_github_app_authorization(CompleteGithubAppAuthorizationRequest {
            code,
            credential_id,
            expected_revocation_generation: expected_generation,
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_github_app_authorization_ack(&credential, current.as_ref())
}

pub(crate) async fn validate_github_app_reconnect(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: &str,
    expected_generation: u64,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie, credential_id).await?;
    if current.provider != "github"
        || current.authentication_kind != CredentialAuthenticationKind::Oauth
        || current.revocation_generation != expected_generation
    {
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    Ok(())
}

pub(crate) async fn generate_ssh(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    expires_at_unix: Option<u64>,
) -> Result<(), ConnectError> {
    let response = mutation_client(state, cookie)
        .generate_ssh_credential(GenerateSshCredentialRequest {
            name: name.clone(),
            expires_at_unix,
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_created_ack(
        &credential,
        &name,
        "ssh",
        CredentialAuthenticationKind::SshKey,
        expires_at_unix,
    )
}

pub(crate) async fn import_ssh(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    private_key: Vec<u8>,
    passphrase: Option<Vec<u8>>,
    expires_at_unix: Option<u64>,
) -> Result<(), ConnectError> {
    let response = mutation_client(state, cookie)
        .add_ssh_credential(AddSshCredentialRequest {
            name: name.clone(),
            private_key,
            passphrase,
            expires_at_unix,
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_created_ack(
        &credential,
        &name,
        "ssh",
        CredentialAuthenticationKind::SshKey,
        expires_at_unix,
    )
}

pub(crate) async fn rename_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
    expected_name: String,
    name: String,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    if current.revocation_generation != expected_generation || current.name != expected_name {
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    let mut expected = current.clone();
    expected.name = name.clone();
    let response = mutation_client(state, cookie)
        .rename_credential(RenameCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            expected_name,
            name,
            ..Default::default()
        })
        .await?
        .into_owned();
    validate_exact_credential_ack(response.credential.into_option(), &expected)
}

pub(crate) async fn rotate_api_key(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
    value: Vec<u8>,
    expires_at_unix: Option<u64>,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    // A Claude subscription token shares the Anthropic slot but is replaced
    // with a new token, never rotated as an API key.
    if current.revocation_generation != expected_generation
        || !matches!(credential_form(&current)?, "openai" | "anthropic")
    {
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    let mut expected = current;
    expected.status = CredentialStatus::Active.into();
    expected.expires_at_unix = expires_at_unix;
    expected.revocation_generation = expected_generation
        .checked_add(1)
        .filter(|generation| *generation <= i64::MAX as u64)
        .ok_or_else(invalid_metadata)?;
    let response = mutation_client(state, cookie)
        .rotate_api_key_credential(RotateApiKeyCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            value,
            expires_at_unix,
            ..Default::default()
        })
        .await?
        .into_owned();
    validate_exact_credential_ack(response.credential.into_option(), &expected)
}

pub(crate) async fn revoke_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    if current.revocation_generation != expected_generation || is_github_connection(&current) {
        // GitHub has no user-visible revoke step; Delete replaces it.
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    let mut expected = current;
    expected.status = CredentialStatus::Revoked.into();
    expected.revocation_generation = expected_generation
        .checked_add(1)
        .filter(|generation| *generation <= i64::MAX as u64)
        .ok_or_else(invalid_metadata)?;
    let response = mutation_client(state, cookie)
        .revoke_credential(RevokeCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            ..Default::default()
        })
        .await?
        .into_owned();
    validate_exact_credential_ack(response.credential.into_option(), &expected)
}

pub(crate) async fn delete_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    // GitHub is the account's one connection and is deleted directly; the
    // service revokes and forgets it in one fenced mutation.
    if current.revocation_generation != expected_generation
        || current.status != CredentialStatus::Revoked && !is_github_connection(&current)
    {
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    mutation_client(state, cookie)
        .delete_credential(DeleteCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn is_github_connection(credential: &Credential) -> bool {
    credential.provider == "github"
        && credential.authentication_kind == CredentialAuthenticationKind::Oauth
}

async fn get_exact_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: &str,
) -> Result<Credential, ConnectError> {
    let response = credential_client(state, cookie)
        .get_credential(GetCredentialRequest {
            selector: Some(get_credential_request::Selector::CredentialId(
                credential_id.into(),
            )),
            ..Default::default()
        })
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    if credential.id != credential_id {
        return Err(invalid_metadata());
    }
    validate_credential_metadata(&credential)?;
    Ok(credential)
}

pub(crate) async fn settings_data(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<CredentialSettingsData, ConnectError> {
    let (credentials, profiles) = tokio::time::timeout(REQUEST_TIMEOUT, async {
        tokio::try_join!(
            list_credentials(state, cookie.clone()),
            list_profiles(state, cookie)
        )
    })
    .await
    .map_err(|_| ConnectError::deadline_exceeded("credential metadata request timed out"))??;
    build_settings_data(credentials, profiles)
}

/// The settings inventory as of now: a Claude subscription token's recorded
/// expiry is a wall-clock fact the service does not restate as a status.
fn build_settings_data(
    credentials: Vec<Credential>,
    profiles: Vec<AccessProfile>,
) -> Result<CredentialSettingsData, ConnectError> {
    build_settings_data_at(credentials, profiles, unix_now()?)
}

/// The viewer's own profiles at their current revisions, each with the
/// capabilities its credentials withhold now. This is the Credentials page's
/// one read. Any failure yields no profiles, so Sandboxes render as they would
/// without notices; nothing about the failure is shown or logged.
pub(crate) async fn current_profile_attention(
    state: &AppState,
    cookie: HeaderValue,
) -> Vec<CredentialProfileRowView> {
    match tokio::time::timeout(ATTENTION_TIMEOUT, settings_data(state, cookie)).await {
        Ok(Ok(data)) => data.profiles,
        _ => Vec::new(),
    }
}

/// One exact revision of the viewer's own profile, with the capabilities its
/// credentials withhold now. Another account's profile is not readable, so
/// it yields nothing, as does any other failure.
pub(crate) async fn bound_profile_attention(
    state: &AppState,
    cookie: HeaderValue,
    profile_id: &str,
    revision: u64,
) -> Vec<CredentialProfileRowView> {
    let read = async {
        let (credentials, profile) = tokio::try_join!(
            list_credentials(state, cookie.clone()),
            get_profile_revision(state, cookie, profile_id, revision),
        )?;
        build_settings_data(credentials, vec![profile])
    };
    match tokio::time::timeout(ATTENTION_TIMEOUT, read).await {
        Ok(Ok(data)) => data.profiles,
        _ => Vec::new(),
    }
}

async fn get_profile_revision(
    state: &AppState,
    cookie: HeaderValue,
    profile_id: &str,
    revision: u64,
) -> Result<AccessProfile, ConnectError> {
    let profile = profile_client(state, cookie)
        .get_access_profile(GetAccessProfileRequest {
            selector: Some(get_access_profile_request::Selector::AccessProfileId(
                profile_id.into(),
            )),
            revision: Some(revision),
            ..Default::default()
        })
        .await?
        .into_owned()
        .access_profile
        .into_option()
        .ok_or_else(invalid_metadata)?;
    if profile.id != profile_id || profile.revision != revision {
        return Err(invalid_metadata());
    }
    Ok(profile)
}

pub(crate) async fn list_credentials(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<Credential>, ConnectError> {
    let client = credential_client(state, cookie);
    let mut credentials = Vec::new();
    let mut page_token = String::new();
    let mut cursors = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let response = client
            .list_credentials(ListCredentialsRequest {
                page_size: PAGE_SIZE,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if response.credentials.len() > PAGE_SIZE as usize {
            return Err(invalid_metadata());
        }
        credentials.extend(response.credentials);
        if response.next_page_token.is_empty() {
            return Ok(credentials);
        }
        if !cursors.insert(response.next_page_token.clone()) {
            return Err(invalid_metadata());
        }
        page_token = response.next_page_token;
    }
    Err(invalid_metadata())
}

async fn list_profiles(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<AccessProfile>, ConnectError> {
    let client = profile_client(state, cookie);
    let mut profiles = Vec::new();
    let mut page_token = String::new();
    let mut cursors = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let response = client
            .list_access_profiles(ListAccessProfilesRequest {
                page_size: PAGE_SIZE,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if response.access_profiles.len() > PAGE_SIZE as usize {
            return Err(invalid_metadata());
        }
        profiles.extend(response.access_profiles);
        if response.next_page_token.is_empty() {
            return Ok(profiles);
        }
        if !cursors.insert(response.next_page_token.clone()) {
            return Err(invalid_metadata());
        }
        page_token = response.next_page_token;
    }
    Err(invalid_metadata())
}

pub(crate) async fn create_profile(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    entries: Vec<AccessProfileEntry>,
) -> Result<(), ConnectError> {
    let expected_entries = canonical_entries(&entries)?;
    let response = profile_client(state, cookie)
        .create_access_profile(CreateAccessProfileRequest {
            name: name.clone(),
            entries,
            ..Default::default()
        })
        .await?
        .into_owned();
    let profile = response
        .access_profile
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_profile_ack(&profile, None, Some(&name), 1, &expected_entries)?;
    Ok(())
}

pub(crate) async fn update_profile(
    state: &AppState,
    cookie: HeaderValue,
    profile_id: String,
    expected_revision: u64,
    entries: Vec<AccessProfileEntry>,
) -> Result<(), ConnectError> {
    let expected_entries = canonical_entries(&entries)?;
    if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
        return Err(invalid_metadata());
    }
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or_else(invalid_metadata)?;
    let response = profile_client(state, cookie)
        .update_access_profile(UpdateAccessProfileRequest {
            access_profile_id: profile_id.clone(),
            expected_revision,
            entries,
            ..Default::default()
        })
        .await?
        .into_owned();
    let profile = response
        .access_profile
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_profile_ack(
        &profile,
        Some(&profile_id),
        None,
        next_revision,
        &expected_entries,
    )?;
    Ok(())
}

/// A rename is a label change fenced on the revision and name the dialog
/// observed: the acknowledged profile must keep its identity and revision.
pub(crate) async fn rename_profile(
    state: &AppState,
    cookie: HeaderValue,
    profile_id: String,
    expected_revision: u64,
    expected_name: String,
    name: String,
) -> Result<(), ConnectError> {
    if expected_revision == 0 || expected_revision > i64::MAX as u64 {
        return Err(invalid_metadata());
    }
    let response = profile_client(state, cookie)
        .rename_access_profile(RenameAccessProfileRequest {
            access_profile_id: profile_id.clone(),
            expected_revision,
            expected_name,
            name: name.clone(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let profile = response
        .access_profile
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_profile_rename_ack(&profile, &profile_id, &name, expected_revision)
}

pub(crate) async fn delete_profile(
    state: &AppState,
    cookie: HeaderValue,
    profile_id: String,
    expected_revision: u64,
) -> Result<(), ConnectError> {
    profile_client(state, cookie)
        .delete_access_profile(DeleteAccessProfileRequest {
            access_profile_id: profile_id,
            expected_revision,
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn build_settings_data_at(
    mut credentials: Vec<Credential>,
    mut profiles: Vec<AccessProfile>,
    now: u64,
) -> Result<CredentialSettingsData, ConnectError> {
    credentials.sort_by(|a, b| {
        credential_display_name(a)
            .cmp(credential_display_name(b))
            .then(a.id.cmp(&b.id))
    });
    profiles.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));

    let mut seen_credentials = BTreeSet::new();
    let mut credential_index = BTreeMap::new();
    let mut choices = CredentialChoicesView::default();
    let mut rows = Vec::with_capacity(credentials.len());
    for (index, credential) in credentials.into_iter().enumerate() {
        let form = credential_form(&credential)?;
        let slot = form_slot(form);
        if !seen_credentials.insert(credential.id.clone()) {
            return Err(invalid_metadata());
        }
        validate_credential_metadata(&credential)?;
        let (status, status_tone) = credential_status_at(&credential, form, now)?;
        let withheld = capability_withheld_at(&credential, form, now);
        let expires = credential
            .expires_at_unix
            .map(|expiry| calendar_date(expiry as i64))
            .unwrap_or_default();
        let (ssh_public_key, ssh_fingerprint) = if slot == "ssh" {
            if credential.account_hint.is_some() {
                return Err(invalid_metadata());
            }
            let key = credential
                .ssh_public_key
                .as_option()
                .ok_or_else(invalid_metadata)?;
            if key.openssh.is_empty()
                || key.openssh.len() > 4096
                || key.fingerprint.is_empty()
                || key.fingerprint.len() > 128
                || key.openssh.bytes().any(|byte| byte.is_ascii_control())
                || key.fingerprint.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(invalid_metadata());
            }
            (key.openssh.clone(), key.fingerprint.clone())
        } else {
            if credential.ssh_public_key.is_set() {
                return Err(invalid_metadata());
            }
            (String::new(), String::new())
        };
        let choice = CredentialChoiceView {
            id: credential.id.clone(),
            name: credential_display_name(&credential).to_owned(),
            status,
        };
        match slot {
            "codex" => choices.codex.push(choice),
            "openai" => choices.openai.push(choice),
            "github" => {}
            "anthropic" => choices.anthropic.push(choice),
            "ssh" => choices.ssh.push(choice),
            _ => unreachable!("credential_slot returns a closed slot"),
        }
        credential_index.insert(
            credential.id.clone(),
            (
                credential_display_name(&credential).to_owned(),
                slot,
                form,
                status,
                status_tone,
                withheld,
            ),
        );
        let revoked = credential.status == CredentialStatus::Revoked;
        rows.push(CredentialRowView {
            id: credential.id,
            name: credential.name,
            provider: provider_label(form),
            oauth_provider: match form {
                "codex" => "codex",
                "github" => "github",
                "openai" | "anthropic" | "claude" | "ssh" => "",
                _ => unreachable!("credential_form returns a closed form"),
            },
            authentication: authentication_label(form),
            account_hint: credential.account_hint.unwrap_or_default(),
            status,
            status_tone,
            api_key: matches!(form, "openai" | "anthropic"),
            oauth: matches!(form, "codex" | "github"),
            subscription_token: form == "claude",
            // A subscription token has no refresh: only a new token from its
            // owner restores one the provider refused or that has expired.
            reconnect_needed: (matches!(form, "codex" | "github")
                && credential.status == CredentialStatus::RefreshFailed)
                || (form == "claude" && withheld && !revoked),
            revoked,
            expires,
            generation: credential.revocation_generation,
            ssh_public_key,
            ssh_fingerprint,
            public_key_id: format!("credential-public-key-{index}"),
        });
    }

    let mut seen_profiles = BTreeSet::new();
    let github_connection = credential_index
        .values()
        .find(|(_, slot, _, _, _, _)| *slot == "github")
        .map(|(name, _, _, status, tone, withheld)| (name.clone(), *status, *tone, *withheld));
    let mut profile_rows = Vec::with_capacity(profiles.len());
    for profile in profiles {
        if exact_id(&profile.id).is_err()
            || !seen_profiles.insert(profile.id.clone())
            || codewire_access::AccessProfileName::parse(&profile.name).is_err()
            || profile.revision == 0
            || profile.revision > i64::MAX as u64
            || profile.entries.len() > 4
        {
            return Err(invalid_metadata());
        }
        let mut selected = BTreeMap::new();
        let mut entries = Vec::with_capacity(profile.entries.len());
        let mut attention = Vec::new();
        for entry in profile.entries {
            let Some((credential_name, credential_slot, form, status, status_tone, withheld)) =
                credential_index.get(&entry.credential_id)
            else {
                return Err(invalid_metadata());
            };
            if entry.capability_slot != *credential_slot
                || selected
                    .insert(entry.capability_slot.clone(), entry.credential_id.clone())
                    .is_some()
            {
                return Err(invalid_metadata());
            }
            entries.push(CredentialProfileEntryView {
                slot: slot_label(&entry.capability_slot).ok_or_else(invalid_metadata)?,
                credential: credential_name.clone(),
                status,
                status_tone,
            });
            if *withheld {
                attention.push(attention_notice(form));
            }
        }
        // Every profile includes the account's one GitHub connection. Show it,
        // or show it as missing until the account connects GitHub. A missing
        // connection grants nothing, so only an unusable one needs Reconnect.
        let (credential, status, status_tone) = github_connection.as_ref().map_or_else(
            || ("missing".to_owned(), "Connect GitHub", "warning"),
            |(account, status, status_tone, withheld)| {
                if *withheld {
                    attention.push(attention_notice("github"));
                }
                (format!("@{account}"), *status, *status_tone)
            },
        );
        entries.push(CredentialProfileEntryView {
            slot: "GitHub",
            credential,
            status,
            status_tone,
        });
        entries.sort_by(|a, b| a.slot.cmp(b.slot));
        // Each notice starts with its capability, so this is the entry order.
        attention.sort_unstable();
        profile_rows.push(CredentialProfileRowView {
            id: profile.id,
            name: profile.name,
            revision: profile.revision,
            entries,
            attention,
            codex: selected.remove("codex").unwrap_or_default(),
            openai: selected.remove("openai").unwrap_or_default(),
            anthropic: selected.remove("anthropic").unwrap_or_default(),
            ssh: selected.remove("ssh").unwrap_or_default(),
        });
    }

    Ok(CredentialSettingsData {
        credentials: rows,
        profiles: profile_rows,
        choices,
    })
}

fn credential_display_name(credential: &Credential) -> &str {
    if credential.provider == "github" {
        credential
            .account_hint
            .as_deref()
            .filter(|hint| !hint.is_empty())
            .unwrap_or(&credential.name)
    } else {
        &credential.name
    }
}

pub(crate) fn validate_credential_metadata(credential: &Credential) -> Result<(), ConnectError> {
    let slot = credential_slot(credential)?;
    if exact_id(&credential.id).is_err()
        || credential.name.is_empty()
        || credential.name.len() > 256
        || credential.name.bytes().any(|byte| byte.is_ascii_control())
        || credential.revocation_generation == 0
        || credential.revocation_generation > i64::MAX as u64
        || credential
            .expires_at_unix
            .is_some_and(|expiry| expiry == 0 || expiry > i64::MAX as u64)
        || credential.account_hint.as_ref().is_some_and(|hint| {
            hint.len() > 320 || hint.bytes().any(|byte| byte.is_ascii_control())
        })
        || credential_status(credential).is_err()
    {
        return Err(invalid_metadata());
    }
    if slot == "ssh" {
        if credential.account_hint.is_some() {
            return Err(invalid_metadata());
        }
        let key = credential
            .ssh_public_key
            .as_option()
            .ok_or_else(invalid_metadata)?;
        if key.openssh.is_empty()
            || key.openssh.len() > 4096
            || key.fingerprint.is_empty()
            || key.fingerprint.len() > 128
            || key.openssh.bytes().any(|byte| byte.is_ascii_control())
            || key.fingerprint.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_metadata());
        }
    } else if credential.ssh_public_key.is_set() {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn validate_created_ack(
    credential: &Credential,
    expected_name: &str,
    expected_provider: &str,
    expected_kind: CredentialAuthenticationKind,
    expected_expiry: Option<u64>,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    if credential.name != expected_name
        || credential.provider != expected_provider
        || credential.authentication_kind != expected_kind
        || credential.account_hint.is_some()
        || credential.status != CredentialStatus::Active
        || credential.expires_at_unix != expected_expiry
        || credential.revocation_generation != 1
    {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn validate_github_app_authorization_ack(
    credential: &Credential,
    current: Option<&Credential>,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    if credential.provider != "github"
        || credential.authentication_kind != CredentialAuthenticationKind::Oauth
        || credential.status != CredentialStatus::Active
    {
        return Err(invalid_metadata());
    }
    match current {
        None if credential.account_hint.as_deref() == Some(credential.name.as_str())
            && credential.revocation_generation == 1
            && credential.expires_at_unix.is_none() =>
        {
            Ok(())
        }
        Some(current)
            if credential.id == current.id
                && credential.name == current.name
                && credential.account_hint.is_some()
                && current
                    .account_hint
                    .as_ref()
                    .is_none_or(|expected| credential.account_hint.as_ref() == Some(expected))
                && credential.expires_at_unix == current.expires_at_unix
                && credential.revocation_generation
                    == current
                        .revocation_generation
                        .checked_add(1)
                        .filter(|generation| *generation <= i64::MAX as u64)
                        .ok_or_else(invalid_metadata)? =>
        {
            Ok(())
        }
        _ => Err(invalid_metadata()),
    }
}

fn validate_exact_credential_ack(
    credential: Option<Credential>,
    expected: &Credential,
) -> Result<(), ConnectError> {
    let credential = credential.ok_or_else(invalid_metadata)?;
    validate_credential_metadata(&credential)?;
    if credential != *expected {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn canonical_entries(
    entries: &[AccessProfileEntry],
) -> Result<BTreeMap<String, String>, ConnectError> {
    let mut canonical = BTreeMap::new();
    for entry in entries {
        if slot_label(&entry.capability_slot).is_none()
            || exact_id(&entry.credential_id).is_err()
            || canonical
                .insert(entry.capability_slot.clone(), entry.credential_id.clone())
                .is_some()
        {
            return Err(invalid_metadata());
        }
    }
    Ok(canonical)
}

fn validate_profile_ack(
    profile: &AccessProfile,
    expected_id: Option<&str>,
    expected_name: Option<&str>,
    expected_revision: u64,
    expected_entries: &BTreeMap<String, String>,
) -> Result<(), ConnectError> {
    if exact_id(&profile.id).is_err()
        || expected_id.is_some_and(|id| profile.id != id)
        || expected_name.is_some_and(|name| profile.name != name)
        || codewire_access::AccessProfileName::parse(&profile.name).is_err()
        || profile.revision != expected_revision
        || canonical_entries(&profile.entries)? != *expected_entries
    {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn validate_profile_rename_ack(
    profile: &AccessProfile,
    expected_id: &str,
    expected_name: &str,
    expected_revision: u64,
) -> Result<(), ConnectError> {
    let entries = canonical_entries(&profile.entries)?;
    validate_profile_ack(
        profile,
        Some(expected_id),
        Some(expected_name),
        expected_revision,
        &entries,
    )
}

/// The profile slot a credential can fill. The Anthropic slot holds either an
/// API key or a Claude subscription token.
pub(crate) fn credential_slot(credential: &Credential) -> Result<&'static str, ConnectError> {
    credential_form(credential).map(form_slot)
}

/// The closed provider/authentication form a credential takes, which names
/// its labels and actions: `claude` is a Claude subscription token, the
/// anthropic provider's OAuth kind, pasted from `claude setup-token`.
pub(crate) fn credential_form(credential: &Credential) -> Result<&'static str, ConnectError> {
    match (credential.provider.as_str(), credential.authentication_kind) {
        ("openai", kind) if kind == CredentialAuthenticationKind::Oauth => Ok("codex"),
        ("openai", kind) if kind == CredentialAuthenticationKind::ApiKey => Ok("openai"),
        ("github", kind) if kind == CredentialAuthenticationKind::Oauth => Ok("github"),
        ("anthropic", kind) if kind == CredentialAuthenticationKind::ApiKey => Ok("anthropic"),
        ("anthropic", kind) if kind == CredentialAuthenticationKind::Oauth => Ok("claude"),
        ("ssh", kind) if kind == CredentialAuthenticationKind::SshKey => Ok("ssh"),
        _ => Err(invalid_metadata()),
    }
}

fn form_slot(form: &'static str) -> &'static str {
    match form {
        "claude" => "anthropic",
        form => form,
    }
}

/// The status a row and its profiles read. A Claude subscription token's
/// recorded expiry is shown as Expired once it passes and as Expires soon in
/// its last thirty days; every other form reads its service status alone.
fn credential_status_at(
    credential: &Credential,
    form: &str,
    now: u64,
) -> Result<(&'static str, &'static str), ConnectError> {
    let status = credential_status(credential)?;
    if form != "claude" || credential.status != CredentialStatus::Active {
        return Ok(status);
    }
    Ok(match credential.expires_at_unix {
        Some(expiry) if expiry <= now => ("Expired", "warning"),
        Some(expiry) if expiry - now <= EXPIRES_SOON_SECONDS => ("Expires soon", "warning"),
        _ => status,
    })
}

fn credential_status(
    credential: &Credential,
) -> Result<(&'static str, &'static str), ConnectError> {
    if credential.status == CredentialStatus::Active {
        Ok(("Active", "success"))
    } else if credential.status == CredentialStatus::Revoked {
        Ok(("Revoked", "danger"))
    } else if credential.status == CredentialStatus::Expired {
        Ok(("Expired", "warning"))
    } else if credential.status == CredentialStatus::RefreshFailed {
        // The provider refused or lost the stored refresh token; only the
        // owner can restore it. Say what to do, not what failed.
        Ok(("Reconnect needed", "warning"))
    } else {
        Err(invalid_metadata())
    }
}

/// The broker withholds a capability whose credential reads as anything but
/// Active in [`credential_status`]: its refresh failed, or it was revoked or
/// expired. Sessions and the other capabilities keep working.
fn capability_withheld(credential: &Credential) -> bool {
    credential.status != CredentialStatus::Active
}

/// As [`capability_withheld`]; a Claude subscription token past its recorded
/// expiry is withheld too, as the broker withholds any expired credential.
fn capability_withheld_at(credential: &Credential, form: &str, now: u64) -> bool {
    capability_withheld(credential)
        || (form == "claude"
            && credential
                .expires_at_unix
                .is_some_and(|expiry| expiry <= now))
}

/// What a withheld capability needs, in the words of the broker's 403 for the
/// same slot: an OAuth identity is reconnected, a key is replaced.
fn attention_notice(form: &str) -> &'static str {
    match form {
        "codex" => "Codex needs Reconnect",
        "github" => "GitHub needs Reconnect",
        "openai" => "OpenAI API key needs replacing",
        "anthropic" => "Anthropic API key needs replacing",
        "claude" => "Claude subscription token needs replacing",
        "ssh" => "SSH key needs replacing",
        _ => unreachable!("closed form"),
    }
}

fn provider_label(form: &str) -> &'static str {
    match form {
        "codex" => "OpenAI Codex",
        "openai" => "OpenAI API",
        "github" => "GitHub",
        "anthropic" | "claude" => "Anthropic",
        "ssh" => "SSH",
        _ => unreachable!("closed form"),
    }
}

fn authentication_label(form: &str) -> &'static str {
    match form {
        "codex" | "github" => "OAuth",
        "openai" | "anthropic" => "API key",
        "claude" => "Claude subscription token",
        "ssh" => "SSH key",
        _ => unreachable!("closed form"),
    }
}

fn slot_label(slot: &str) -> Option<&'static str> {
    match slot {
        "codex" => Some("Codex"),
        "openai" => Some("OpenAI API"),
        "github" => Some("GitHub"),
        "anthropic" => Some("Anthropic"),
        "ssh" => Some("SSH"),
        _ => None,
    }
}

fn invalid_metadata() -> ConnectError {
    ConnectError::unavailable("complete credential metadata is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(
        id: &str,
        name: &str,
        provider: &str,
        kind: CredentialAuthenticationKind,
    ) -> Credential {
        Credential {
            id: id.into(),
            name: name.into(),
            provider: provider.into(),
            authentication_kind: kind.into(),
            status: CredentialStatus::Active.into(),
            revocation_generation: 1,
            ..Default::default()
        }
    }

    #[test]
    fn material_free_inventory_joins_profiles_by_exact_identity_and_slot() {
        let codex_id = "00000000-0000-4000-8000-000000000001";
        let ssh_id = "00000000-0000-4000-8000-000000000002";
        let profile_id = "00000000-0000-4000-8000-000000000003";
        let mut ssh = credential(
            ssh_id,
            "Work SSH",
            "ssh",
            CredentialAuthenticationKind::SshKey,
        );
        ssh.ssh_public_key = Some(codewire_proto::codewire::v1::SshPublicKey {
            openssh: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKey".into(),
            fingerprint: "SHA256:fixture".into(),
            ..Default::default()
        })
        .into();
        let data = build_settings_data(
            vec![
                credential(
                    codex_id,
                    "Work Codex",
                    "openai",
                    CredentialAuthenticationKind::Oauth,
                ),
                ssh,
            ],
            vec![AccessProfile {
                id: profile_id.into(),
                name: "work".into(),
                revision: 7,
                entries: vec![
                    AccessProfileEntry {
                        capability_slot: "codex".into(),
                        credential_id: codex_id.into(),
                        ..Default::default()
                    },
                    AccessProfileEntry {
                        capability_slot: "ssh".into(),
                        credential_id: ssh_id.into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        )
        .unwrap();
        assert_eq!(data.credentials.len(), 2);
        assert_eq!(data.choices.codex.len(), 1);
        assert_eq!(data.choices.ssh.len(), 1);
        assert_eq!(data.profiles[0].revision, 7);
        assert_eq!(data.profiles[0].codex, codex_id);
        assert_eq!(data.profiles[0].ssh, ssh_id);
        // Codex, SSH, and the account GitHub connection every profile includes.
        assert_eq!(data.profiles[0].entries.len(), 3);
        assert!(
            data.profiles[0]
                .entries
                .iter()
                .any(|entry| entry.slot == "GitHub")
        );
    }

    #[test]
    fn github_display_uses_verified_account_without_changing_canonical_reconnect_name() {
        let id = "00000000-0000-4000-8000-000000000001";
        let mut github = credential(
            id,
            "legacy-reference",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        github.account_hint = Some("verified-user".into());
        let data = build_settings_data(
            vec![github],
            vec![AccessProfile {
                id: "00000000-0000-4000-8000-000000000002".into(),
                name: "work".into(),
                revision: 1,
                entries: Vec::new(),
                ..Default::default()
            }],
        )
        .unwrap();
        assert_eq!(data.credentials[0].display_name(), "verified-user");
        assert_eq!(data.credentials[0].name, "legacy-reference");
        // Every profile shows the account's one GitHub connection.
        assert_eq!(data.profiles[0].entries[0].slot, "GitHub");
        assert_eq!(data.profiles[0].entries[0].credential, "@verified-user");
        assert_eq!(
            data.profiles[0].entries[0].status,
            data.credentials[0].status
        );
        assert_eq!(
            data.profiles[0].entries[0].status_tone,
            data.credentials[0].status_tone
        );
    }

    #[test]
    fn failed_refresh_reads_reconnect_needed_on_the_row_and_its_profiles() {
        let failed_id = "00000000-0000-4000-8000-000000000001";
        let active_id = "00000000-0000-4000-8000-000000000002";
        let mut failed = credential(
            failed_id,
            "Work Codex",
            "openai",
            CredentialAuthenticationKind::Oauth,
        );
        failed.status = CredentialStatus::RefreshFailed.into();
        let data = build_settings_data(
            vec![
                failed,
                credential(
                    active_id,
                    "Other Codex",
                    "openai",
                    CredentialAuthenticationKind::Oauth,
                ),
            ],
            vec![AccessProfile {
                id: "00000000-0000-4000-8000-000000000003".into(),
                name: "work".into(),
                revision: 1,
                entries: vec![AccessProfileEntry {
                    capability_slot: "codex".into(),
                    credential_id: failed_id.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        )
        .unwrap();
        let row = |id: &str| {
            data.credentials
                .iter()
                .find(|row| row.id == id)
                .expect("credential row")
        };
        assert_eq!(row(failed_id).status, "Reconnect needed");
        assert_eq!(row(failed_id).status_tone, "warning");
        assert!(row(failed_id).reconnect_needed);
        assert_eq!(row(active_id).status, "Active");
        assert!(!row(active_id).reconnect_needed);
        let entry = data.profiles[0]
            .entries
            .iter()
            .find(|entry| entry.slot == "Codex")
            .unwrap();
        assert_eq!(
            (entry.status, entry.status_tone),
            ("Reconnect needed", "warning")
        );
    }

    /// #2361: a Sandbox names the capabilities its bound revision withholds,
    /// in the broker's words, from the status the Credentials page shows.
    #[test]
    fn withheld_capabilities_read_in_the_broker_words_per_profile_revision() {
        let id = |n: u8| format!("00000000-0000-4000-8000-0000000000{n:02}");
        let mut codex = credential(
            &id(1),
            "Work Codex",
            "openai",
            CredentialAuthenticationKind::Oauth,
        );
        codex.status = CredentialStatus::RefreshFailed.into();
        let anthropic = credential(
            &id(2),
            "Work Anthropic",
            "anthropic",
            CredentialAuthenticationKind::ApiKey,
        );
        let mut openai = credential(
            &id(3),
            "Old OpenAI",
            "openai",
            CredentialAuthenticationKind::ApiKey,
        );
        openai.status = CredentialStatus::Revoked.into();
        let mut expired = credential(
            &id(4),
            "Old Anthropic",
            "anthropic",
            CredentialAuthenticationKind::ApiKey,
        );
        expired.status = CredentialStatus::Expired.into();
        let profile = |n: u8, entries: &[(&str, String)]| AccessProfile {
            id: id(n),
            name: format!("profile-{n}"),
            revision: 7,
            entries: entries
                .iter()
                .map(|(slot, credential_id)| AccessProfileEntry {
                    capability_slot: (*slot).into(),
                    credential_id: credential_id.clone(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let profiles = vec![
            profile(10, &[("codex", id(1)), ("anthropic", id(2))]),
            profile(11, &[("anthropic", id(2))]),
            profile(12, &[("openai", id(3)), ("anthropic", id(4))]),
            profile(13, &[]),
        ];
        let attention = |data: &CredentialSettingsData, n: u8| {
            data.profiles
                .iter()
                .find(|profile| profile.id == id(n))
                .unwrap()
                .attention
                .clone()
        };
        let data = build_settings_data(
            vec![
                codex.clone(),
                anthropic.clone(),
                openai.clone(),
                expired.clone(),
            ],
            profiles.clone(),
        )
        .unwrap();
        assert_eq!(attention(&data, 10), ["Codex needs Reconnect"]);
        assert!(attention(&data, 11).is_empty());
        assert_eq!(
            attention(&data, 12),
            [
                "Anthropic API key needs replacing",
                "OpenAI API key needs replacing"
            ]
        );
        // No GitHub connection grants nothing, so it needs no Reconnect.
        assert!(attention(&data, 13).is_empty());

        // The account's one GitHub connection belongs to every profile.
        let mut github = credential(
            &id(5),
            "synthetic",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        github.account_hint = Some("synthetic-user".into());
        github.status = CredentialStatus::RefreshFailed.into();
        let data =
            build_settings_data(vec![codex, anthropic, openai, expired, github], profiles).unwrap();
        assert_eq!(
            attention(&data, 10),
            ["Codex needs Reconnect", "GitHub needs Reconnect"]
        );
        assert_eq!(attention(&data, 13), ["GitHub needs Reconnect"]);
    }

    /// A Claude subscription token fills the Anthropic slot like an API key,
    /// with its own labels, a replace action and its recorded expiry read
    /// against now, since it has no refresh.
    #[test]
    fn claude_subscription_tokens_share_the_anthropic_slot_with_their_own_states() {
        const NOW: u64 = 1_800_000_000;
        const DAY: u64 = 24 * 60 * 60;
        let id = |n: u8| format!("00000000-0000-4000-8000-0000000000{n:02}");
        let token = |n: u8, name: &str| {
            let mut token = credential(
                &id(n),
                name,
                "anthropic",
                CredentialAuthenticationKind::Oauth,
            );
            token.expires_at_unix = Some(NOW + 200 * DAY);
            token
        };
        let active = token(1, "Claude active");
        let mut soon = token(2, "Claude soon");
        soon.expires_at_unix = Some(NOW + 10 * DAY);
        let mut expired = token(3, "Claude expired");
        expired.expires_at_unix = Some(NOW - 1);
        let mut refused = token(4, "Claude refused");
        refused.status = CredentialStatus::RefreshFailed.into();
        let mut revoked = token(5, "Claude revoked");
        revoked.status = CredentialStatus::Revoked.into();
        let key = credential(
            &id(6),
            "Work Anthropic",
            "anthropic",
            CredentialAuthenticationKind::ApiKey,
        );
        assert_eq!(credential_form(&active).unwrap(), "claude");
        assert_eq!(credential_slot(&active).unwrap(), "anthropic");
        assert_eq!(credential_form(&key).unwrap(), "anthropic");
        let profile = |n: u8, credential: u8| AccessProfile {
            id: id(n),
            name: format!("profile-{n}"),
            revision: 3,
            entries: vec![AccessProfileEntry {
                capability_slot: "anthropic".into(),
                credential_id: id(credential),
                ..Default::default()
            }],
            ..Default::default()
        };
        let data = build_settings_data_at(
            vec![active.clone(), soon, expired, refused, revoked, key.clone()],
            (1..=6).map(|n| profile(10 + n, n)).collect(),
            NOW,
        )
        .unwrap();
        let row = |n: u8| {
            data.credentials
                .iter()
                .find(|row| row.id == id(n))
                .expect("credential row")
        };
        for n in 1..=5 {
            let row = row(n);
            assert_eq!(row.provider, "Anthropic");
            assert_eq!(row.authentication, "Claude subscription token");
            assert!(row.subscription_token && !row.api_key && !row.oauth);
            assert_eq!(row.oauth_provider, "");
        }
        let key_row = row(6);
        assert_eq!(
            (key_row.authentication, key_row.subscription_token),
            ("API key", false)
        );
        assert!(key_row.api_key);
        for (n, status, tone, reconnect) in [
            (1, "Active", "success", false),
            (2, "Expires soon", "warning", false),
            (3, "Expired", "warning", true),
            (4, "Reconnect needed", "warning", true),
            (5, "Revoked", "danger", false),
        ] {
            assert_eq!((row(n).status, row(n).status_tone), (status, tone), "{n}");
            assert_eq!(row(n).reconnect_needed, reconnect, "{n}");
        }
        assert!(row(1).expires.contains("2027"));
        // Tokens are Anthropic choices beside the API key; none is offered
        // for another slot.
        assert_eq!(data.choices.anthropic.len(), 6);
        assert!(data.choices.codex.is_empty() && data.choices.openai.is_empty());
        let attention = |n: u8| {
            data.profiles
                .iter()
                .find(|profile| profile.id == id(10 + n))
                .unwrap()
                .attention
                .clone()
        };
        let notice = ["Claude subscription token needs replacing"];
        assert!(attention(1).is_empty());
        // Expiring soon still works; expired, refused and revoked do not.
        assert!(attention(2).is_empty());
        assert_eq!(attention(3), notice);
        assert_eq!(attention(4), notice);
        assert_eq!(attention(5), notice);
        assert!(attention(6).is_empty());
        let entry = data
            .profiles
            .iter()
            .find(|profile| profile.id == id(13))
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.slot == "Anthropic")
            .unwrap();
        assert_eq!((entry.status, entry.status_tone), ("Expired", "warning"));
        // An API key past a hard expiry keeps its existing reading.
        let mut old_key = key.clone();
        old_key.expires_at_unix = Some(NOW - 1);
        let data = build_settings_data_at(vec![old_key], Vec::new(), NOW).unwrap();
        assert_eq!(data.credentials[0].status, "Active");
        assert!(!data.credentials[0].reconnect_needed);
        // A token never fills the Codex slot.
        let mut cross = profile(20, 1);
        cross.entries[0].capability_slot = "codex".into();
        assert!(build_settings_data_at(vec![active], vec![cross], NOW).is_err());
    }

    #[test]
    fn subscription_token_acknowledgements_are_exact_and_restart_the_year() {
        const NOW: u64 = 1_800_000_000;
        let id = "00000000-0000-4000-8000-000000000001";
        let mut created = credential(
            id,
            "Claude",
            "anthropic",
            CredentialAuthenticationKind::Oauth,
        );
        created.expires_at_unix = Some(NOW + CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS + 5);
        validate_subscription_token_ack(&created, "Claude", None, NOW).unwrap();
        let invalid = |change: &dyn Fn(&mut Credential)| {
            let mut changed = created.clone();
            change(&mut changed);
            validate_subscription_token_ack(&changed, "Claude", None, NOW).is_err()
        };
        assert!(invalid(&|c| c.provider = "openai".into()));
        assert!(invalid(
            &|c| c.authentication_kind = CredentialAuthenticationKind::ApiKey.into()
        ));
        assert!(invalid(&|c| c.name = "Other".into()));
        assert!(invalid(&|c| c.account_hint = Some("account".into())));
        assert!(invalid(
            &|c| c.status = CredentialStatus::RefreshFailed.into()
        ));
        assert!(invalid(&|c| c.revocation_generation = 2));
        assert!(invalid(&|c| c.expires_at_unix = None));
        assert!(invalid(
            &|c| c.expires_at_unix = Some(NOW + 30 * 24 * 60 * 60)
        ));

        let mut current = created.clone();
        current.status = CredentialStatus::RefreshFailed.into();
        current.revocation_generation = 4;
        current.expires_at_unix = Some(NOW - 1);
        let mut replaced = created.clone();
        replaced.revocation_generation = 5;
        validate_subscription_token_ack(&replaced, "Claude", Some(&current), NOW).unwrap();
        let mut moved = replaced.clone();
        moved.id = "00000000-0000-4000-8000-000000000002".into();
        assert!(validate_subscription_token_ack(&moved, "Claude", Some(&current), NOW).is_err());
        replaced.revocation_generation = 4;
        assert!(validate_subscription_token_ack(&replaced, "Claude", Some(&current), NOW).is_err());
    }

    #[test]
    fn profile_without_github_connection_shows_it_as_missing() {
        let data = build_settings_data(
            Vec::new(),
            vec![AccessProfile {
                id: "00000000-0000-4000-8000-000000000002".into(),
                name: "work".into(),
                revision: 1,
                ..Default::default()
            }],
        )
        .unwrap();
        let entry = &data.profiles[0].entries[0];
        assert_eq!(entry.slot, "GitHub");
        assert_eq!(entry.credential, "missing");
        assert_eq!(entry.status, "Connect GitHub");
        assert_eq!(entry.status_tone, "warning");
    }

    #[test]
    fn inventory_rejects_cross_slot_profiles_and_private_shape_drift() {
        let credential_id = "00000000-0000-4000-8000-000000000001";
        let profile_id = "00000000-0000-4000-8000-000000000002";
        let codex = credential(
            credential_id,
            "Work Codex",
            "openai",
            CredentialAuthenticationKind::Oauth,
        );
        let invalid = AccessProfile {
            id: profile_id.into(),
            name: "work".into(),
            revision: 1,
            entries: vec![AccessProfileEntry {
                capability_slot: "ssh".into(),
                credential_id: credential_id.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(build_settings_data(vec![codex.clone()], vec![invalid]).is_err());
        let mut unexpected_key = codex;
        unexpected_key.ssh_public_key = Some(codewire_proto::codewire::v1::SshPublicKey {
            openssh: "public".into(),
            fingerprint: "fingerprint".into(),
            ..Default::default()
        })
        .into();
        assert!(build_settings_data(vec![unexpected_key], Vec::new()).is_err());
    }

    #[test]
    fn github_recovery_requires_one_closed_domain_bound_reason() {
        for (reason, feedback) in [
            (
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
                "github-installation-required",
            ),
            (
                "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED",
                "github-app-unavailable",
            ),
        ] {
            for (domain, code, duplicate, expected) in [
                ("codewire.sh", ErrorCode::FailedPrecondition, false, true),
                (
                    "foreign.example",
                    ErrorCode::FailedPrecondition,
                    false,
                    false,
                ),
                ("codewire.sh", ErrorCode::Unavailable, false, false),
                ("codewire.sh", ErrorCode::FailedPrecondition, true, false),
            ] {
                let info = codewire_proto::google::rpc::ErrorInfo {
                    domain: domain.into(),
                    reason: reason.into(),
                    ..Default::default()
                };
                let mut error = ConnectError::new(code, "ignored-upstream-private-marker");
                error.details.push(connectrpc::ErrorDetail::from_message(
                    "google.rpc.ErrorInfo",
                    &info,
                ));
                if duplicate {
                    error.details.push(error.details[0].clone());
                }
                assert_eq!(github_authorization_feedback(&error).is_some(), expected);
                if expected {
                    assert_eq!(github_authorization_feedback(&error), Some(feedback));
                    error.details[0].value = Some("malformed-base64".into());
                    assert_eq!(github_authorization_feedback(&error), None);
                }
            }
        }
        assert!(
            github_authorization_feedback(&ConnectError::new(
                ErrorCode::FailedPrecondition,
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED"
            ))
            .is_none()
        );
        for (reason, feedback) in [
            (
                "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED",
                Some("github-app-unavailable"),
            ),
            ("CREDENTIAL_ENROLLMENT_FAILED", Some("github-app-failed")),
            (
                "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
                Some("github-app-response-invalid"),
            ),
            ("CREDENTIAL_REVISION_CHANGED", None),
            ("unknown", None),
        ] {
            let info = codewire_proto::google::rpc::ErrorInfo {
                domain: "codewire.sh".into(),
                reason: reason.into(),
                ..Default::default()
            };
            let mut error = ConnectError::new(ErrorCode::FailedPrecondition, "ignored");
            error.details.push(connectrpc::ErrorDetail::from_message(
                "google.rpc.ErrorInfo",
                &info,
            ));
            assert_eq!(github_authorization_feedback(&error), feedback);
        }
    }

    #[test]
    fn profile_acknowledgements_are_exact_and_complete() {
        let profile_id = "00000000-0000-4000-8000-000000000001";
        let credential_id = "00000000-0000-4000-8000-000000000002";
        let entries = vec![AccessProfileEntry {
            capability_slot: "ssh".into(),
            credential_id: credential_id.into(),
            ..Default::default()
        }];
        let expected = canonical_entries(&entries).unwrap();
        let profile = AccessProfile {
            id: profile_id.into(),
            name: "work".into(),
            revision: 2,
            entries,
            ..Default::default()
        };
        validate_profile_ack(&profile, Some(profile_id), None, 2, &expected).unwrap();

        let mut wrong_revision = profile.clone();
        wrong_revision.revision = 3;
        assert!(
            validate_profile_ack(&wrong_revision, Some(profile_id), None, 2, &expected).is_err()
        );
        let mut incomplete = profile;
        incomplete.entries.clear();
        assert!(validate_profile_ack(&incomplete, Some(profile_id), None, 2, &expected).is_err());

        let create_ack = AccessProfile {
            id: profile_id.into(),
            name: "work".into(),
            revision: 1,
            entries: vec![AccessProfileEntry {
                capability_slot: "ssh".into(),
                credential_id: credential_id.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        validate_profile_ack(&create_ack, None, Some("work"), 1, &expected).unwrap();
        assert!(validate_profile_ack(&create_ack, None, Some("other"), 1, &expected).is_err());

        let mut invalid_name = create_ack.clone();
        invalid_name.name = "GitHub repository browser".into();
        assert!(validate_profile_ack(&invalid_name, None, None, 1, &expected).is_err());
        invalid_name.entries.clear();
        assert!(build_settings_data(Vec::new(), vec![invalid_name]).is_err());

        let mut malformed = create_ack;
        malformed.id = "not-an-id".into();
        assert!(validate_profile_ack(&malformed, None, Some("work"), 1, &expected).is_err());
    }

    #[test]
    fn credential_acknowledgements_are_exact_and_material_free() {
        let id = "00000000-0000-4000-8000-000000000001";
        let api_key = credential(
            id,
            "Work API",
            "openai",
            CredentialAuthenticationKind::ApiKey,
        );
        validate_created_ack(
            &api_key,
            "Work API",
            "openai",
            CredentialAuthenticationKind::ApiKey,
            None,
        )
        .unwrap();
        let mut wrong_generation = api_key.clone();
        wrong_generation.revocation_generation = 2;
        assert!(
            validate_created_ack(
                &wrong_generation,
                "Work API",
                "openai",
                CredentialAuthenticationKind::ApiKey,
                None,
            )
            .is_err()
        );

        let mut renamed = api_key.clone();
        renamed.name = "Renamed API".into();
        validate_exact_credential_ack(Some(renamed.clone()), &renamed).unwrap();
        let mut drifted = renamed.clone();
        drifted.account_hint = Some("unexpected".into());
        assert!(validate_exact_credential_ack(Some(drifted), &renamed).is_err());
    }

    #[test]
    fn codex_challenges_and_github_app_reconnect_acknowledgements_are_closed() {
        let codex = codewire_proto::codewire::v1::CodexDeviceChallenge {
            verification_url: "https://auth.openai.com/codex/device".into(),
            user_code: "ABCD-1234".into(),
            expires_at_unix: 4_102_444_800,
            ..Default::default()
        };
        assert!(valid_codex_challenge(&codex));
        let mut wrong_url = codex;
        wrong_url.verification_url = "https://attacker.test/device".into();
        assert!(!valid_codex_challenge(&wrong_url));

        let mut automatic = credential(
            "00000000-0000-4000-8000-000000000002",
            "verified-account",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        automatic.account_hint = Some("verified-account".into());
        validate_github_app_authorization_ack(&automatic, None).unwrap();
        automatic.account_hint = Some("different-account".into());
        assert!(validate_github_app_authorization_ack(&automatic, None).is_err());
        automatic.account_hint = None;
        assert!(validate_github_app_authorization_ack(&automatic, None).is_err());
        automatic.provider = "openai".into();
        assert!(validate_github_app_authorization_ack(&automatic, None).is_err());

        let mut current = credential(
            "00000000-0000-4000-8000-000000000001",
            "old-account",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        current.status = CredentialStatus::Active.into();
        current.account_hint = Some("old-account".into());
        assert_eq!(credential_display_name(&current), "old-account");
        let mut replacement = current.clone();
        replacement.revocation_generation = 2;
        validate_github_app_authorization_ack(&replacement, Some(&current)).unwrap();
        replacement.account_hint = Some("different-account".into());
        assert!(validate_github_app_authorization_ack(&replacement, Some(&current)).is_err());

        let mut legacy = current.clone();
        legacy.name = "legacy-reference".into();
        legacy.account_hint = Some("old-account".into());
        let mut legacy_replacement = legacy.clone();
        legacy_replacement.revocation_generation = 2;
        validate_github_app_authorization_ack(&legacy_replacement, Some(&legacy)).unwrap();

        let mut unknown_legacy = legacy.clone();
        unknown_legacy.account_hint = None;
        let mut discovered_identity = unknown_legacy.clone();
        discovered_identity.account_hint = Some("old-account".into());
        discovered_identity.revocation_generation = 2;
        validate_github_app_authorization_ack(&discovered_identity, Some(&unknown_legacy)).unwrap();
    }

    #[test]
    fn oauth_failure_reasons_are_closed_and_keep_uncertain_publication_distinct() {
        use OAuthEnrollmentFailure as Failure;
        let cases = [
            (
                ErrorCode::Unauthenticated,
                "",
                Failure::SignInRequired,
                true,
            ),
            (ErrorCode::Unavailable, "", Failure::Unavailable, true),
            (ErrorCode::AlreadyExists, "", Failure::AlreadyExists, false),
            (
                ErrorCode::FailedPrecondition,
                "CREDENTIAL_REVISION_CHANGED",
                Failure::Changed,
                false,
            ),
            (
                ErrorCode::FailedPrecondition,
                "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
                Failure::Unsupported,
                false,
            ),
            (
                ErrorCode::FailedPrecondition,
                "CREDENTIAL_ENROLLMENT_FAILED",
                Failure::NotCompleted,
                false,
            ),
            (ErrorCode::DeadlineExceeded, "", Failure::Expired, true),
            (ErrorCode::Canceled, "", Failure::Cancelled, true),
            (
                ErrorCode::Unknown,
                "CREDENTIAL_MUTATION_UNCERTAIN",
                Failure::UnexpectedResponse,
                true,
            ),
            (
                ErrorCode::Unavailable,
                "CREDENTIAL_ENROLLMENT_CLEANUP_FAILED",
                Failure::UnexpectedResponse,
                true,
            ),
            (
                ErrorCode::FailedPrecondition,
                "synthetic-private-marker",
                Failure::UnexpectedResponse,
                true,
            ),
        ];
        for (code, reason, expected, expected_uncertain) in cases {
            let detail = codewire_proto::google::rpc::ErrorInfo {
                domain: "codewire.sh".into(),
                reason: reason.into(),
                ..Default::default()
            };
            let mut error = ConnectError::new(code, "synthetic-private-marker");
            if !reason.is_empty() {
                error.details.push(connectrpc::ErrorDetail::from_message(
                    "google.rpc.ErrorInfo",
                    &detail,
                ));
            }
            let OAuthEnrollmentEvent::Failed { reason, uncertain } = failed_error(&error, true)
            else {
                panic!("expected a closed failure");
            };
            assert_eq!(reason, expected);
            assert_eq!(uncertain, expected_uncertain);
            assert!(!format!("{reason:?}").contains("synthetic-private-marker"));
        }
        for (domain, code, duplicate) in [
            ("foreign.example", ErrorCode::FailedPrecondition, false),
            ("codewire.sh", ErrorCode::Unavailable, false),
            ("codewire.sh", ErrorCode::FailedPrecondition, true),
        ] {
            let detail = codewire_proto::google::rpc::ErrorInfo {
                domain: domain.into(),
                reason: "CREDENTIAL_ENROLLMENT_UNSUPPORTED".into(),
                ..Default::default()
            };
            let mut error = ConnectError::new(code, "synthetic-private-marker");
            error.details.push(connectrpc::ErrorDetail::from_message(
                "google.rpc.ErrorInfo",
                &detail,
            ));
            if duplicate {
                error.details.push(error.details[0].clone());
            }
            assert!(matches!(
                failed_error(&error, true),
                OAuthEnrollmentEvent::Failed {
                    reason: Failure::UnexpectedResponse,
                    uncertain: true
                }
            ));
        }
    }
}
