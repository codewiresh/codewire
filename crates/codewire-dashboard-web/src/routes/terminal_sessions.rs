//! Browser presentation of the existing durable session service. Commands,
//! environment, retained output, and daemon authority never enter this DTO.
use std::{collections::BTreeSet, time::Duration};

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::v1::{
    EnvironmentSession, EnvironmentSessionServiceClient, EnvironmentSessionState,
    LaunchSessionRequest, ListSessionsRequest, StopSessionRequest,
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    security::{canonical_cookie, request_has_same_origin, valid_csrf_token},
    state::AppState,
    transport::BrowserTransport,
};

const MAX_SESSIONS: usize = 256;
const SHELL: &str = "if [ -x /bin/bash ]; then exec /bin/bash -i; else exec /bin/sh -i; fi";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionView {
    session_id: String,
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Inventory {
    account_id: String,
    sessions: Vec<SessionView>,
}

// No Debug: CSRF is request authority, not diagnostic data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StopForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    session_id: String,
}

struct Context {
    account_id: String,
    org_id: String,
    cookie: HeaderValue,
}

fn json(status: StatusCode, value: impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

fn failure(status: StatusCode, code: &'static str) -> Response {
    #[derive(Serialize)]
    struct Failure {
        error: &'static str,
    }
    json(status, Failure { error: code })
}

fn web_failure(error: WebError) -> Response {
    match error {
        WebError::Unauthorized => failure(StatusCode::UNAUTHORIZED, "sign-in-required"),
        WebError::TwoFactorRequired => failure(StatusCode::FORBIDDEN, "two-factor-required"),
        WebError::NotFound => failure(StatusCode::NOT_FOUND, "not-found"),
        WebError::Connect(error) => connect_failure(error, false),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "sessions-unavailable"),
    }
}

fn connect_failure(error: ConnectError, mutation: bool) -> Response {
    match error.code {
        ErrorCode::Unauthenticated => failure(StatusCode::UNAUTHORIZED, "sign-in-required"),
        ErrorCode::PermissionDenied => failure(StatusCode::FORBIDDEN, "not-authorized"),
        ErrorCode::NotFound => failure(StatusCode::NOT_FOUND, "not-found"),
        ErrorCode::InvalidArgument => failure(StatusCode::BAD_REQUEST, "invalid-request"),
        // The daemon refuses a launch at its session limit before creating one.
        ErrorCode::ResourceExhausted if mutation => failure(StatusCode::CONFLICT, "session-limit"),
        // A timed-out/lost reply is not proof that launch/stop did not happen.
        // Do not forward raw messages or automatic retry advice.
        _ if mutation => failure(StatusCode::CONFLICT, "session-outcome-unknown"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "sessions-unavailable"),
    }
}

/// A session list the Sandbox itself refused: orchestration answers
/// FailedPrecondition when the Sandbox is not running or its daemon is
/// starting, out of date, unhealthy or refuses its session store. The reason
/// stays in orchestration and the daemon status; the browser gets one closed
/// code it can explain. Mutations never use it: there FailedPrecondition can
/// also mean an unknown outcome.
fn list_failure(error: ConnectError) -> Response {
    match error.code {
        ErrorCode::FailedPrecondition => failure(StatusCode::CONFLICT, "sessions-refused"),
        _ => connect_failure(error, false),
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn context(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    environment_id: &str,
) -> Result<Context, Response> {
    if !codewire_server_core::organization_slug::valid_organization_slug(slug)
        || !super::terminal::canonical_environment_id(environment_id)
    {
        return Err(failure(StatusCode::NOT_FOUND, "not-found"));
    }
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(web_failure)?;
    enforce_two_factor(&identity).map_err(web_failure)?;
    if !valid_account_id(&identity.id) {
        return Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "sessions-unavailable",
        ));
    }
    let cookie = canonical_cookie(headers)
        .map_err(|()| failure(StatusCode::UNAUTHORIZED, "sign-in-required"))?;
    let dashboard = super::dashboard::dashboard_shell_view_from_identity(
        state,
        headers,
        &identity,
        cookie.clone(),
    )
    .await
    .map_err(web_failure)?;
    let org_id = dashboard
        .organizations
        .iter()
        .find(|organization| organization.slug == slug)
        .map(|organization| organization.id.clone())
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not-found"))?;
    // EnvironmentSessionService remains the authority for operator/runtime,
    // confidential policy and daemon-target readiness; metadata is not permission.
    Ok(Context {
        account_id: identity.id,
        org_id,
        cookie,
    })
}

fn client(
    state: &AppState,
    cookie: HeaderValue,
) -> EnvironmentSessionServiceClient<BrowserTransport> {
    EnvironmentSessionServiceClient::new(
        BrowserTransport {
            http: state.session_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone())
            .with_default_timeout(Duration::from_secs(80))
            .with_default_max_message_size(1024 * 1024),
    )
}

fn valid_session_id(value: &str) -> bool {
    value
        .strip_prefix("session-")
        .is_some_and(super::terminal::canonical_environment_id)
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn presentation(session: EnvironmentSession) -> Result<SessionView, ()> {
    if !session.pty || !valid_session_id(&session.session_id) {
        return Err(());
    }
    let state = match session.state.to_i32() {
        value if value == EnvironmentSessionState::Starting as i32 => "starting",
        value if value == EnvironmentSessionState::Running as i32 => "running",
        value if value == EnvironmentSessionState::Stopping as i32 => "stopping",
        value if value == EnvironmentSessionState::Stopped as i32 => "stopped",
        value if value == EnvironmentSessionState::Exited as i32 => "exited",
        value if value == EnvironmentSessionState::Failed as i32 => "failed",
        value if value == EnvironmentSessionState::Interrupted as i32 => "interrupted",
        _ => return Err(()),
    };
    Ok(SessionView {
        session_id: session.session_id,
        state,
    })
}

fn inventory(account_id: String, sessions: Vec<EnvironmentSession>) -> Result<Inventory, ()> {
    if sessions.len() > MAX_SESSIONS {
        return Err(());
    }
    let mut seen = BTreeSet::new();
    let sessions = sessions
        .into_iter()
        .filter(|session| session.pty)
        .map(|session| {
            let session = presentation(session)?;
            if !seen.insert(session.session_id.clone()) {
                return Err(());
            }
            Ok(session)
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok(Inventory {
        account_id,
        sessions,
    })
}

pub(super) async fn list(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let context = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = client(&state, context.cookie)
        .list_sessions(ListSessionsRequest {
            org_id: context.org_id,
            environment_id,
            ..Default::default()
        })
        .await;
    match result {
        Ok(response) => match inventory(context.account_id, response.into_owned().sessions) {
            Ok(inventory) => json(StatusCode::OK, inventory),
            Err(()) => failure(StatusCode::BAD_GATEWAY, "sessions-unavailable"),
        },
        Err(error) => list_failure(error),
    }
}

fn valid_action(public_origin: &str, headers: &HeaderMap, csrf: &str) -> bool {
    headers.get_all(header::ORIGIN).iter().count() == 1
        && request_has_same_origin(headers, public_origin)
        && valid_csrf_token(headers, csrf)
}

fn launch_request(org_id: String, environment_id: String) -> LaunchSessionRequest {
    LaunchSessionRequest {
        org_id,
        environment_id,
        command: vec!["/bin/sh".into(), "-c".into(), SHELL.into()],
        pty: true,
        term: "xterm-256color".into(),
        columns: 80,
        rows: 24,
        ..Default::default()
    }
}

pub(super) async fn launch(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<LaunchForm>,
) -> Response {
    if !valid_action(&state.public_origin, &headers, &form.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    let context = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if context.account_id != form.account_id {
        return failure(StatusCode::CONFLICT, "account-changed");
    }
    match client(&state, context.cookie)
        .launch_session(launch_request(context.org_id, environment_id))
        .await
    {
        Ok(response) => match response
            .into_owned()
            .session
            .into_option()
            .and_then(|s| presentation(s).ok())
        {
            Some(session) if matches!(session.state, "running" | "failed") => {
                json(StatusCode::OK, session)
            }
            _ => failure(StatusCode::CONFLICT, "session-outcome-unknown"),
        },
        Err(error) => connect_failure(error, true),
    }
}

pub(super) async fn stop(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<StopForm>,
) -> Response {
    if !valid_action(&state.public_origin, &headers, &form.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    if !valid_session_id(&form.session_id) {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let context = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if context.account_id != form.account_id {
        return failure(StatusCode::CONFLICT, "account-changed");
    }
    let expected = form.session_id.clone();
    match client(&state, context.cookie)
        .stop_session(StopSessionRequest {
            org_id: context.org_id,
            environment_id,
            session_id: form.session_id,
            ..Default::default()
        })
        .await
    {
        Ok(response) => match response
            .into_owned()
            .session
            .into_option()
            .and_then(|s| presentation(s).ok())
        {
            Some(session)
                if session.session_id == expected
                    && matches!(session.state, "stopped" | "exited") =>
            {
                json(StatusCode::OK, session)
            }
            _ => failure(StatusCode::CONFLICT, "session-outcome-unknown"),
        },
        Err(error) => connect_failure(error, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> EnvironmentSession {
        EnvironmentSession {
            session_id: "session-5d1db799-4300-4ab3-b957-efb980760542".into(),
            state: EnvironmentSessionState::Running.into(),
            pty: true,
            command: vec!["private-command-canary".into()],
            working_dir: "private-directory-canary".into(),
            status_message: "private-status-canary".into(),
            ..Default::default()
        }
    }

    #[test]
    fn inventory_is_bounded_metadata_only_and_rejects_duplicates() {
        let value = inventory("account-id".into(), vec![session()]).unwrap();
        let value = serde_json::to_value(value).unwrap();
        assert_eq!(value["accountId"], "account-id");
        assert_eq!(value["sessions"][0].as_object().unwrap().len(), 2);
        assert!(!value.to_string().contains("canary"));
        assert!(inventory("account".into(), vec![session(), session()]).is_err());
        assert!(inventory("account".into(), vec![session(); MAX_SESSIONS + 1]).is_err());
        let mut command_session = session();
        command_session.pty = false;
        assert!(
            inventory("account".into(), vec![command_session])
                .unwrap()
                .sessions
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_launch_refused_at_the_session_limit_is_named_but_reads_stay_unavailable() {
        let body = |response: Response| async move {
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        };
        let limit = ConnectError::new(ErrorCode::ResourceExhausted, "private-limit-canary");
        let (status, text) = body(connect_failure(limit.clone(), true)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(text.contains("session-limit") && !text.contains("canary"));
        let (status, text) = body(connect_failure(limit, false)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(text.contains("sessions-unavailable"));
    }

    #[tokio::test]
    async fn a_list_the_sandbox_refused_is_named_without_its_reason() {
        use http_body_util::BodyExt;
        let body = |response: Response| async move {
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        };
        let refused = ConnectError::new(
            ErrorCode::FailedPrecondition,
            "environment session store is refused; private-reason-canary",
        );
        let (status, value) = body(list_failure(refused.clone())).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value, serde_json::json!({"error": "sessions-refused"}));
        // A refused mutation may still have run; it stays an unknown outcome.
        let (status, value) = body(connect_failure(refused, true)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            value,
            serde_json::json!({"error": "session-outcome-unknown"})
        );
        // Other list failures keep their codes; an internal one stays generic.
        let (status, value) = body(list_failure(ConnectError::new(
            ErrorCode::Internal,
            "environment session request failed",
        )))
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(value, serde_json::json!({"error": "sessions-unavailable"}));
        let (status, _) = body(list_failure(ConnectError::new(
            ErrorCode::PermissionDenied,
            "denied",
        )))
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn launches_use_only_the_fixed_interactive_shell_and_no_environment() {
        let request = launch_request("org".into(), "environment".into());
        assert_eq!(request.command, ["/bin/sh", "-c", SHELL]);
        assert!(request.env.is_empty());
        assert!(request.working_dir.is_empty());
        assert!(request.pty);
        assert_eq!(request.term, "xterm-256color");
    }

    #[test]
    fn mutations_do_not_accept_browser_commands_or_foreign_fields() {
        assert!(
            serde_json::from_value::<LaunchForm>(serde_json::json!({
                "_csrf": "csrf", "account_id": "account", "command": "not-allowed"
            }))
            .is_err()
        );
        assert!(valid_session_id(&session().session_id));
        assert!(!valid_session_id(
            "session-5D1DB799-4300-4AB3-B957-EFB980760542"
        ));
        assert!(!valid_session_id("5d1db799-4300-4ab3-b957-efb980760542"));
    }

    #[test]
    fn browser_actions_require_one_exact_origin_and_current_csrf() {
        let token = crate::security::new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("codewire_ssr_csrf={token}")).unwrap(),
        );
        assert!(!valid_action(
            "https://dashboard.example.test",
            &headers,
            &token
        ));
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://dashboard.example.test/"),
        );
        assert!(!valid_action(
            "https://dashboard.example.test",
            &headers,
            &token
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://dashboard.example.test"),
        );
        assert!(valid_action(
            "https://dashboard.example.test",
            &headers,
            &token
        ));
        assert!(!valid_action(
            "https://dashboard.example.test",
            &headers,
            &crate::security::new_csrf_token()
        ));
        assert!(!valid_action(
            "https://foreign.example.test",
            &headers,
            &token
        ));
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://dashboard.example.test"),
        );
        assert!(!valid_action(
            "https://dashboard.example.test",
            &headers,
            &token
        ));
    }

    #[test]
    fn presentation_does_not_guess_unknown_state_or_session_identity() {
        let mut invalid = session();
        invalid.state = EnvironmentSessionState::Unspecified.into();
        assert!(presentation(invalid).is_err());
        let mut invalid = session();
        invalid.session_id = "session-other".into();
        assert!(presentation(invalid).is_err());
        assert!(valid_account_id("account-0123456789_ABC"));
        for invalid in ["", "name@example.test", "account:other", "line\nbreak"] {
            assert!(!valid_account_id(invalid));
        }
        assert!(!valid_account_id(&"a".repeat(129)));
    }

    #[tokio::test]
    async fn unknown_mutation_outcome_is_closed_no_store_and_has_no_retry_advice() {
        use http_body_util::BodyExt;
        let response = connect_failure(ConnectError::unavailable("private-upstream-canary"), true);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::RETRY_AFTER));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error": "session-outcome-unknown"})
        );
    }
}
