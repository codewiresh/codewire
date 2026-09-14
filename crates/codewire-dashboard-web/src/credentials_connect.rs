//! Material-free personal credential and profile adapters for the dashboard.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use axum::http::HeaderValue;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileEntry, AccessProfileServiceClient, AddApiKeyCredentialRequest,
    AddSshCredentialRequest, CreateAccessProfileRequest, Credential, CredentialAuthenticationKind,
    CredentialMutationServiceClient, CredentialServiceClient, CredentialStatus,
    DeleteAccessProfileRequest, DeleteCredentialRequest, EnrollCodexRequest, EnrollCodexResponse,
    EnrollGithubRequest, EnrollGithubResponse, GenerateSshCredentialRequest, GetCredentialRequest,
    ListAccessProfilesRequest, ListCredentialsRequest, RenameCredentialRequest,
    RevokeCredentialRequest, RotateApiKeyCredentialRequest, UpdateAccessProfileRequest,
    enroll_codex_response, enroll_github_response, get_credential_request,
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
const MUTATION_TIMEOUT: Duration = Duration::from_secs(45);
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(16 * 60);
const MAX_MUTATION_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum OAuthProvider {
    Codex,
    Github,
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
        OAuthProvider::Github => {
            let rpc = EnrollGithubRequest {
                name: request.name,
                credential_id: request.credential_id,
                expected_revocation_generation: request.expected_generation,
                ..Default::default()
            };
            let stream = tokio::select! {
                _ = events.closed() => return,
                result = client.enroll_github_with_options(rpc, options) => result,
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
                    result = stream.message::<EnrollGithubResponse>() => result,
                };
                match message {
                    Ok(Some(message)) => match message.to_owned_message().event {
                        Some(enroll_github_response::Event::Challenge(challenge))
                            if !challenged && valid_github_challenge(&challenge) =>
                        {
                            challenged = true;
                            if events
                                .send(OAuthEnrollmentEvent::Challenge {
                                    provider: "GitHub",
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
                        Some(enroll_github_response::Event::Credential(credential))
                            if challenged
                                && validate_oauth_ack(
                                    &credential,
                                    "github",
                                    &expected_name,
                                    &expected,
                                )
                                .is_ok() =>
                        {
                            let terminal = tokio::select! {
                                _ = events.closed() => return,
                                result = stream.message::<EnrollGithubResponse>() => result,
                            };
                            let event = if matches!(terminal, Ok(None)) {
                                OAuthEnrollmentEvent::Committed
                            } else {
                                failed(true)
                            };
                            let _ = events.send(event).await;
                            return;
                        }
                        Some(enroll_github_response::Event::Credential(_)) => {
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
                OAuthProvider::Github => "github",
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
        || if provider == "github" && expected.is_none() && expected_name.is_empty() {
            credential.account_hint.as_deref() != Some(credential.name.as_str())
        } else {
            credential.name != expected_name
        }
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

fn valid_github_challenge(challenge: &codewire_proto::codewire::v1::GithubDeviceChallenge) -> bool {
    challenge.verification_url == "https://github.com/login/device"
        && challenge.user_code.len() == 9
        && challenge
            .user_code
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                if index == 4 {
                    byte == b'-'
                } else {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit()
                }
            })
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
    if current.revocation_generation != expected_generation
        || !matches!(credential_slot(&current)?, "openai" | "anthropic")
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
    if current.revocation_generation != expected_generation {
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
    if current.revocation_generation != expected_generation
        || current.status != CredentialStatus::Revoked
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

async fn list_credentials(
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

fn build_settings_data(
    mut credentials: Vec<Credential>,
    mut profiles: Vec<AccessProfile>,
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
        let slot = credential_slot(&credential)?;
        if !seen_credentials.insert(credential.id.clone()) {
            return Err(invalid_metadata());
        }
        validate_credential_metadata(&credential)?;
        let (status, status_tone) = credential_status(&credential)?;
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
            "github" => choices.github.push(choice),
            "anthropic" => choices.anthropic.push(choice),
            "ssh" => choices.ssh.push(choice),
            _ => unreachable!("credential_slot returns a closed slot"),
        }
        credential_index.insert(
            credential.id.clone(),
            (credential_display_name(&credential).to_owned(), slot),
        );
        rows.push(CredentialRowView {
            id: credential.id,
            name: credential.name,
            provider: provider_label(slot),
            oauth_provider: match slot {
                "codex" => "codex",
                "github" => "github",
                "openai" | "anthropic" | "ssh" => "",
                _ => unreachable!("credential_slot returns a closed slot"),
            },
            authentication: authentication_label(slot),
            account_hint: credential.account_hint.unwrap_or_default(),
            status,
            status_tone,
            api_key: matches!(slot, "openai" | "anthropic"),
            oauth: matches!(slot, "codex" | "github"),
            revoked: credential.status == CredentialStatus::Revoked,
            expires,
            generation: credential.revocation_generation,
            ssh_public_key,
            ssh_fingerprint,
            public_key_id: format!("credential-public-key-{index}"),
        });
    }

    let mut seen_profiles = BTreeSet::new();
    let mut profile_rows = Vec::with_capacity(profiles.len());
    for profile in profiles {
        if exact_id(&profile.id).is_err()
            || !seen_profiles.insert(profile.id.clone())
            || profile.name.is_empty()
            || profile.name.len() > 128
            || profile.name.bytes().any(|byte| byte.is_ascii_control())
            || profile.revision == 0
            || profile.revision > i64::MAX as u64
            || profile.entries.len() > 5
        {
            return Err(invalid_metadata());
        }
        let mut selected = BTreeMap::new();
        let mut entries = Vec::with_capacity(profile.entries.len());
        for entry in profile.entries {
            let Some((credential_name, credential_slot)) =
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
            });
        }
        entries.sort_by(|a, b| a.slot.cmp(b.slot));
        profile_rows.push(CredentialProfileRowView {
            id: profile.id,
            name: profile.name,
            revision: profile.revision,
            entries,
            codex: selected.remove("codex").unwrap_or_default(),
            openai: selected.remove("openai").unwrap_or_default(),
            github: selected.remove("github").unwrap_or_default(),
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

fn validate_credential_metadata(credential: &Credential) -> Result<(), ConnectError> {
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
        || profile.name.is_empty()
        || profile.name.len() > 128
        || profile.name.bytes().any(|byte| byte.is_ascii_control())
        || profile.revision != expected_revision
        || canonical_entries(&profile.entries)? != *expected_entries
    {
        return Err(invalid_metadata());
    }
    Ok(())
}

fn credential_slot(credential: &Credential) -> Result<&'static str, ConnectError> {
    match (credential.provider.as_str(), credential.authentication_kind) {
        ("openai", kind) if kind == CredentialAuthenticationKind::Oauth => Ok("codex"),
        ("openai", kind) if kind == CredentialAuthenticationKind::ApiKey => Ok("openai"),
        ("github", kind) if kind == CredentialAuthenticationKind::Oauth => Ok("github"),
        ("anthropic", kind) if kind == CredentialAuthenticationKind::ApiKey => Ok("anthropic"),
        ("ssh", kind) if kind == CredentialAuthenticationKind::SshKey => Ok("ssh"),
        _ => Err(invalid_metadata()),
    }
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
        Ok(("Refresh failed", "warning"))
    } else {
        Err(invalid_metadata())
    }
}

fn provider_label(slot: &str) -> &'static str {
    match slot {
        "codex" => "OpenAI Codex",
        "openai" => "OpenAI API",
        "github" => "GitHub",
        "anthropic" => "Anthropic",
        "ssh" => "SSH",
        _ => unreachable!("closed slot"),
    }
}

fn authentication_label(slot: &str) -> &'static str {
    match slot {
        "codex" | "github" => "OAuth",
        "openai" | "anthropic" => "API key",
        "ssh" => "SSH key",
        _ => unreachable!("closed slot"),
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
        assert_eq!(data.profiles[0].entries.len(), 2);
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
                entries: vec![AccessProfileEntry {
                    capability_slot: "github".into(),
                    credential_id: id.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        )
        .unwrap();
        assert_eq!(data.credentials[0].display_name(), "verified-user");
        assert_eq!(data.credentials[0].name, "legacy-reference");
        assert_eq!(data.choices.github[0].name, "verified-user");
        assert_eq!(data.profiles[0].entries[0].credential, "verified-user");
        assert_eq!(data.profiles[0].github, id);
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
    fn oauth_challenges_and_reconnect_acknowledgements_are_closed() {
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

        let github = codewire_proto::codewire::v1::GithubDeviceChallenge {
            verification_url: "https://github.com/login/device".into(),
            user_code: "ABCD-1234".into(),
            expires_at_unix: 4_102_444_800,
            ..Default::default()
        };
        assert!(valid_github_challenge(&github));

        let mut automatic = credential(
            "00000000-0000-4000-8000-000000000002",
            "verified-account",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        automatic.account_hint = Some("verified-account".into());
        validate_oauth_ack(&automatic, "github", "", &None).unwrap();
        automatic.account_hint = Some("different-account".into());
        assert!(validate_oauth_ack(&automatic, "github", "", &None).is_err());
        automatic.account_hint = None;
        assert!(validate_oauth_ack(&automatic, "github", "", &None).is_err());
        assert!(validate_oauth_ack(&automatic, "openai", "", &None).is_err());

        let mut current = credential(
            "00000000-0000-4000-8000-000000000001",
            "Work GitHub",
            "github",
            CredentialAuthenticationKind::Oauth,
        );
        current.status = CredentialStatus::Revoked.into();
        current.expires_at_unix = Some(4_102_444_800);
        current.account_hint = Some("old-account".into());
        assert_eq!(credential_display_name(&current), "old-account");
        let mut replacement = current.clone();
        replacement.status = CredentialStatus::Active.into();
        replacement.revocation_generation = 2;
        replacement.account_hint = Some("verified-account".into());
        validate_oauth_ack(
            &replacement,
            "github",
            "Work GitHub",
            &Some(current.clone()),
        )
        .unwrap();
        replacement.expires_at_unix = None;
        assert!(validate_oauth_ack(&replacement, "github", "Work GitHub", &Some(current)).is_err());
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
