//! Fresh authenticated readiness for terminal presentation, never an authority
//! to launch. The session service independently checks setup before dispatch.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::v1::DesiredState;
use connectrpc::ErrorCode;
use serde::Serialize;

use crate::{environment_connect, state::AppState, view::EnvironmentRow};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Readiness {
    environment_id: String,
    running: bool,
    setup_complete: bool,
    detail: Detail,
}

/// Lifecycle eligibility is presentation, never mutation authorization. Each
/// submitted action still independently enforces its backend actor/policy gate.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Detail {
    state: &'static str,
    desired_state: &'static str,
    tone: &'static str,
    last_event: String,
    resources: String,
    deletion_state: &'static str,
    shutdown_at: Option<String>,
    cpu_millicores: i32,
    memory_mib: i32,
    disk_gib: i32,
    start_eligible: bool,
    stop_eligible: bool,
    delete_eligible: bool,
    actions_allowed: bool,
    pending: bool,
}

fn desired_state_name(value: i32) -> &'static str {
    match value {
        value if value == DesiredState::Started as i32 => "started",
        value if value == DesiredState::Stopped as i32 => "stopped",
        value if value == DesiredState::Destroyed as i32 => "destroyed",
        value if value == DesiredState::Archived as i32 => "archived",
        value if value == DesiredState::Resized as i32 => "resized",
        _ => "unknown",
    }
}

fn lifecycle_pending(state: &str, desired: &str) -> bool {
    match state {
        "running" => !matches!(desired, "started" | "resized"),
        "stopped" => desired != "stopped",
        "destroyed" => desired != "destroyed",
        "archived" => desired != "archived",
        "error" | "build failed" => false,
        _ => true,
    }
}

/// A create or start that has not converged stays deletable. Destroy already
/// supersedes the `started` intent in any state but destroying/destroyed, and
/// a retry that cannot converge must not leave the Sandbox with no action
/// (#2328). Pending stop, resize, and destroy intents keep their own guard.
fn start_intent_unconverged(state: &str, desired: &str) -> bool {
    desired == "started" && matches!(state, "pending" | "creating" | "starting")
}

impl Readiness {
    fn new(row: EnvironmentRow, setup_complete: bool, desired_state: i32) -> Self {
        let desired_state = desired_state_name(desired_state);
        let pending = lifecycle_pending(row.state, desired_state);
        let allowed = row.confidential_actions_allowed;
        Self {
            environment_id: row.id,
            running: row.state == "running" && row.confidential_actions_allowed,
            setup_complete,
            detail: Detail {
                state: row.state,
                desired_state,
                tone: row.state_tone,
                last_event: row.last_event,
                resources: row.resources,
                deletion_state: row.deletion_state,
                shutdown_at: row.shutdown_at,
                cpu_millicores: row.cpu_millicores,
                memory_mib: row.memory_mb,
                disk_gib: row.disk_gb,
                start_eligible: allowed && !pending && row.can_start,
                stop_eligible: allowed && !pending && row.can_stop,
                delete_eligible: row.can_destroy
                    && (!pending || start_intent_unconverged(row.state, desired_state)),
                actions_allowed: allowed,
                pending,
            },
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
    let desired_state = source.desired_state.to_i32();
    let mut row = environment_connect::environment_row(source);
    super::environments::apply_confidential_visibility(&state, dashboard.is_admin, &mut row);
    json(
        StatusCode::OK,
        Readiness::new(row, setup_complete, desired_state),
    )
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
        let value =
            serde_json::to_value(Readiness::new(row, false, DesiredState::Started as i32)).unwrap();
        assert_eq!(value["running"], false);
        assert_eq!(value["setupComplete"], false);
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["detail"].as_object().unwrap().len(), 15);
        assert_eq!(value["detail"]["deletionState"], "unscheduled");
        assert_eq!(value["detail"]["shutdownAt"], serde_json::Value::Null);
        assert!(!value.to_string().contains("canary"));
    }

    #[test]
    fn deletion_metadata_never_changes_observed_lifecycle_or_authority() {
        use codewire_proto::codewire::v1::{Environment, EnvironmentState};
        for protected in [false, true] {
            let mut source = Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                state: EnvironmentState::Running.into(),
                cpu_millicores: 750,
                memory_mb: 1536,
                disk_gb: 10,
                protected,
                ..Default::default()
            };
            let mut timestamp = source.shutdown_at.into_option().unwrap_or_default();
            timestamp.seconds = 0;
            timestamp.nanos = 123_456_789;
            source.shutdown_at = Some(timestamp).into();
            let value = serde_json::to_value(Readiness::new(
                environment_connect::environment_row(source),
                true,
                DesiredState::Started as i32,
            ))
            .unwrap();
            assert_eq!(value["running"], true);
            assert_eq!(value["setupComplete"], true);
            assert_eq!(value["detail"]["stopEligible"], true);
            assert_eq!(value["detail"]["pending"], false);
            if protected {
                assert_eq!(value["detail"]["deletionState"], "protected");
                assert!(value["detail"]["shutdownAt"].is_null());
            } else {
                assert_eq!(value["detail"]["deletionState"], "scheduled");
                assert_eq!(
                    value["detail"]["shutdownAt"],
                    "1970-01-01T00:00:00.123456789Z"
                );
            }
            assert!(serde_json::to_vec(&value).unwrap().len() <= 2048);
        }
    }

    #[test]
    fn accepted_desired_transition_stays_pending_before_observed_state_changes() {
        assert!(lifecycle_pending("running", "stopped"));
        assert!(lifecycle_pending("stopped", "started"));
        assert!(lifecycle_pending("running", "destroyed"));
        assert!(lifecycle_pending("running", "unknown"));
        assert!(!lifecycle_pending("running", "started"));
        assert!(!lifecycle_pending("running", "resized"));
        assert!(!lifecycle_pending("stopped", "stopped"));
        assert!(!lifecycle_pending("error", "started"));
        for state in [
            "pending",
            "creating",
            "starting",
            "stopping",
            "resizing",
            "destroying",
            "unknown",
        ] {
            assert!(lifecycle_pending(state, "started"));
        }
    }

    #[test]
    fn unconverged_create_or_start_stays_deletable_but_other_pending_intents_do_not() {
        use codewire_proto::codewire::v1::{Environment, EnvironmentState};
        let readiness = |state: EnvironmentState, desired: DesiredState| {
            let row = environment_connect::environment_row(Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                state: state.into(),
                ..Default::default()
            });
            serde_json::to_value(Readiness::new(row, false, desired as i32)).unwrap()
        };
        // #2328: a pending-create retry waiting on a suspended Sandbox hid
        // Delete together with every other action.
        for state in [
            EnvironmentState::Pending,
            EnvironmentState::Creating,
            EnvironmentState::Starting,
        ] {
            let value = readiness(state, DesiredState::Started);
            assert_eq!(value["detail"]["pending"], true, "{state:?}");
            assert_eq!(value["detail"]["deleteEligible"], true, "{state:?}");
            assert_eq!(value["detail"]["startEligible"], false, "{state:?}");
            assert_eq!(value["detail"]["stopEligible"], false, "{state:?}");
        }
        for (state, desired) in [
            (EnvironmentState::Running, DesiredState::Stopped),
            (EnvironmentState::Stopping, DesiredState::Stopped),
            (EnvironmentState::Resizing, DesiredState::Resized),
            (EnvironmentState::Running, DesiredState::Destroyed),
            (EnvironmentState::Destroying, DesiredState::Destroyed),
        ] {
            let value = readiness(state, desired);
            assert_eq!(value["detail"]["pending"], true, "{state:?}");
            assert_eq!(value["detail"]["deleteEligible"], false, "{state:?}");
        }
        assert_eq!(
            readiness(EnvironmentState::Running, DesiredState::Started)["detail"]["deleteEligible"],
            true
        );
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
