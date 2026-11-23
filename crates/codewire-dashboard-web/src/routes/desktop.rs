//! The Desktop panel's state, Start and Stop (`docs/dev/SANDBOX-DESKTOP.md`,
//! "The dashboard viewer"), through the environment desktop service with the
//! browser's own session. Start and Stop pass the checks the terminal's New
//! and Close pass. The viewer password reaches the page only in the answer
//! to the panel's own request, never cached, and nothing else of the
//! environment's answer does.
use std::time::Duration;

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use codewire_proto::codewire::v1::{
    EnvironmentDesktop, EnvironmentDesktopServiceClient, EnvironmentDesktopState,
    GetDesktopRequest, StartDesktopRequest, StopDesktopRequest,
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};
use serde::{Deserialize, Serialize};

use super::terminal_sessions::{context, failure, json, valid_action};
use crate::{state::AppState, transport::BrowserTransport};

/// What the panel shows. No Debug: it can carry the viewer password.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopView {
    account_id: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

// No Debug: CSRF is request authority, not diagnostic data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DesktopForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
}

fn client(
    state: &AppState,
    cookie: HeaderValue,
) -> EnvironmentDesktopServiceClient<BrowserTransport> {
    EnvironmentDesktopServiceClient::new(
        BrowserTransport {
            http: state.session_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        // A start answers once the desktop accepts a viewer.
        ClientConfig::new(state.api_origin.clone())
            .with_default_timeout(Duration::from_secs(80))
            .with_default_max_message_size(64 * 1024),
    )
}

/// The password the daemon makes at each start: eight lowercase letters or
/// digits. Orchestration vets it too; anything else is not handed to a page.
fn viewer_password(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn view(account_id: String, desktop: EnvironmentDesktop) -> Result<DesktopView, ()> {
    let state = match desktop.state.to_i32() {
        value if value == EnvironmentDesktopState::Unavailable as i32 => "unavailable",
        value if value == EnvironmentDesktopState::Stopped as i32 => "stopped",
        value if value == EnvironmentDesktopState::Starting as i32 => "starting",
        value if value == EnvironmentDesktopState::Running as i32 => "running",
        _ => return Err(()),
    };
    let password = match (state, desktop.running.into_option()) {
        ("running", Some(running)) if viewer_password(&running.viewer_password) => {
            Some(running.viewer_password)
        }
        ("running", _) => return Err(()),
        _ => None,
    };
    Ok(DesktopView {
        account_id,
        state,
        password,
    })
}

/// A refusal the page can explain. The service's own words stay on the
/// server.
fn desktop_failure(error: ConnectError, mutation: bool) -> Response {
    match error.code {
        ErrorCode::Unauthenticated => failure(StatusCode::UNAUTHORIZED, "sign-in-required"),
        ErrorCode::PermissionDenied => failure(StatusCode::FORBIDDEN, "not-authorized"),
        ErrorCode::NotFound => failure(StatusCode::NOT_FOUND, "not-found"),
        // The Sandbox is not running, or its runtime predates the desktop.
        ErrorCode::FailedPrecondition => failure(StatusCode::CONFLICT, "desktop-refused"),
        // A start or stop whose answer was lost may still have happened.
        _ if mutation => failure(StatusCode::CONFLICT, "desktop-outcome-unknown"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "desktop-unavailable"),
    }
}

fn answer(account_id: String, desktop: Option<EnvironmentDesktop>, expected: &[&str]) -> Response {
    match desktop.map(|desktop| view(account_id, desktop)) {
        Some(Ok(view)) if expected.contains(&view.state) => json(StatusCode::OK, view),
        _ => failure(StatusCode::BAD_GATEWAY, "desktop-unavailable"),
    }
}

pub(super) async fn get(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let context = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match client(&state, context.cookie)
        .get_desktop(GetDesktopRequest {
            org_id: context.org_id,
            environment_id,
            ..Default::default()
        })
        .await
    {
        Ok(response) => answer(
            context.account_id,
            response.into_owned().desktop.into_option(),
            &["unavailable", "stopped", "starting", "running"],
        ),
        Err(error) => desktop_failure(error, false),
    }
}

pub(super) async fn start(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<DesktopForm>,
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
        .start_desktop(StartDesktopRequest {
            org_id: context.org_id,
            environment_id,
            ..Default::default()
        })
        .await
    {
        // A start answers once the desktop accepts a viewer, or that the
        // image has none.
        Ok(response) => answer(
            context.account_id,
            response.into_owned().desktop.into_option(),
            &["running", "unavailable"],
        ),
        Err(error) => desktop_failure(error, true),
    }
}

pub(super) async fn stop(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<DesktopForm>,
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
        .stop_desktop(StopDesktopRequest {
            org_id: context.org_id,
            environment_id,
            ..Default::default()
        })
        .await
    {
        Ok(response) => answer(
            context.account_id,
            response.into_owned().desktop.into_option(),
            &["stopped", "unavailable"],
        ),
        Err(error) => desktop_failure(error, true),
    }
}

#[cfg(test)]
mod tests {
    use codewire_proto::codewire::v1::EnvironmentDesktopRunning;
    use http_body_util::BodyExt;

    use super::*;

    fn desktop(state: EnvironmentDesktopState, password: Option<&str>) -> EnvironmentDesktop {
        EnvironmentDesktop {
            state: state.into(),
            unavailable_reason: "private-reason-canary".into(),
            running: password
                .map(|password| EnvironmentDesktopRunning {
                    display: ":1".into(),
                    port: 5901,
                    viewer_password: password.into(),
                    ..Default::default()
                })
                .map(::buffa::MessageField::some)
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    #[test]
    fn the_page_gets_the_state_and_only_a_running_desktops_password() {
        let running = view(
            "account-id".into(),
            desktop(EnvironmentDesktopState::Running, Some("a1b2c3d4")),
        )
        .unwrap();
        let running = serde_json::to_value(running).unwrap();
        assert_eq!(running["accountId"], "account-id");
        assert_eq!(running["state"], "running");
        assert_eq!(running["password"], "a1b2c3d4");
        assert_eq!(running.as_object().unwrap().len(), 3);

        for (state, name) in [
            (EnvironmentDesktopState::Unavailable, "unavailable"),
            (EnvironmentDesktopState::Stopped, "stopped"),
            (EnvironmentDesktopState::Starting, "starting"),
        ] {
            // A password left over from a running answer is never passed on.
            let value = serde_json::to_value(
                view("account".into(), desktop(state, Some("a1b2c3d4"))).unwrap(),
            )
            .unwrap();
            assert_eq!(value["state"], name);
            assert!(value.get("password").is_none(), "{name}");
            assert!(!value.to_string().contains("canary"));
        }
    }

    #[test]
    fn an_answer_the_page_cannot_use_is_refused() {
        assert!(
            view(
                "account".into(),
                desktop(EnvironmentDesktopState::Unspecified, None)
            )
            .is_err()
        );
        assert!(
            view(
                "account".into(),
                desktop(EnvironmentDesktopState::Running, None)
            )
            .is_err()
        );
        for password in [
            "",
            "a1b2c3d",
            "a1b2c3d4e",
            "A1B2C3D4",
            "a1b2c3d\"",
            "a1b2</sc",
            "a1b2 c3d",
            "a1b2c3d\u{e9}",
        ] {
            assert!(
                view(
                    "account".into(),
                    desktop(EnvironmentDesktopState::Running, Some(password))
                )
                .is_err(),
                "{password:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_refusal_is_named_without_the_services_words() {
        let body = |response: Response| async move {
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        };
        let refused = ConnectError::new(ErrorCode::FailedPrecondition, "private-canary");
        let (status, text) = body(desktop_failure(refused, true)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(text.contains("desktop-refused") && !text.contains("canary"));
        let lost = ConnectError::new(ErrorCode::DeadlineExceeded, "private-canary");
        let (status, text) = body(desktop_failure(lost.clone(), true)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(text.contains("desktop-outcome-unknown"));
        let (status, text) = body(desktop_failure(lost, false)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(text.contains("desktop-unavailable") && !text.contains("canary"));
    }
}
