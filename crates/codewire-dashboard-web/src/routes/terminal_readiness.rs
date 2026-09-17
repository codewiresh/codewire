//! Fresh authenticated readiness for terminal presentation, never an authority
//! to launch. The session service independently checks setup before dispatch.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use connectrpc::ErrorCode;
use serde::Serialize;

use crate::{environment_connect, state::AppState, view::EnvironmentRow};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Readiness {
    environment_id: String,
    running: bool,
    setup_complete: bool,
}

impl Readiness {
    fn new(row: EnvironmentRow, setup_complete: bool) -> Self {
        Self {
            environment_id: row.id,
            running: row.state == "running" && row.confidential_actions_allowed,
            setup_complete,
        }
    }
}

fn json(status: StatusCode, body: impl Serialize) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

fn unavailable(status: StatusCode) -> Response {
    #[derive(Serialize)]
    struct Failure {
        error: &'static str,
    }
    json(
        status,
        Failure {
            error: "terminal-readiness-unavailable",
        },
    )
}

pub(super) async fn get(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug)
        || !super::terminal::canonical_environment_id(&environment_id)
    {
        return unavailable(StatusCode::NOT_FOUND);
    }
    let continuation = super::terminal::terminal_path(&slug, &environment_id);
    let (dashboard, organization, cookie) =
        match super::organization_governance::get_context(&state, &headers, &slug, &continuation)
            .await
        {
            Ok(context) => context,
            // Background reads must not follow redirects, return HTML, or
            // rotate the page's current CSRF cookie.
            Err(response) => {
                return unavailable(if response.status().is_redirection() {
                    StatusCode::UNAUTHORIZED
                } else {
                    response.status()
                });
            }
        };
    let source = match environment_connect::environment_data(
        &state,
        cookie,
        &organization.id,
        &environment_id,
    )
    .await
    {
        Ok(source) if source.id == environment_id => source,
        Ok(_) => return unavailable(StatusCode::BAD_GATEWAY),
        Err(error) => {
            return unavailable(match error.code {
                ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
                ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
                ErrorCode::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            });
        }
    };
    let setup_complete = source.setup_complete;
    let mut row = environment_connect::environment_row(source);
    super::environments::apply_confidential_visibility(&state, dashboard.is_admin, &mut row);
    json(StatusCode::OK, Readiness::new(row, setup_complete))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::v1::{Environment, EnvironmentState};

    #[test]
    fn running_does_not_imply_setup_complete_or_interactive_permission() {
        let source = Environment {
            id: "00000000-0000-4000-8000-000000000001".into(),
            name: "private-name-canary".into(),
            state: EnvironmentState::Running.into(),
            setup_complete: false,
            ..Default::default()
        };
        let mut row = environment_connect::environment_row(source);
        row.confidential_actions_allowed = false;
        let value = serde_json::to_value(Readiness::new(row, false)).unwrap();
        assert_eq!(value["running"], false);
        assert_eq!(value["setupComplete"], false);
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert!(!value.to_string().contains("canary"));
    }

    #[test]
    fn failure_does_not_navigate_or_rotate_authority() {
        let response = unavailable(StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        for name in [header::LOCATION, header::SET_COOKIE, header::RETRY_AFTER] {
            assert!(!response.headers().contains_key(name));
        }
    }
}
