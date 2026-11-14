//! Fresh authenticated readiness for terminal presentation, never an authority
//! to launch. The session service independently checks setup before dispatch.
use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use connectrpc::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::{environment_connect, state::AppState, view::EnvironmentRow};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Readiness {
    environment_id: String,
    running: bool,
    setup_complete: bool,
    /// Setup still owns the running Sandbox, so Resize waits and says why.
    /// Sent only on request: pages loaded before it existed reject unknown
    /// fields, and must keep their terminals across a deploy.
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_running: Option<bool>,
    /// The one thing the page says about the Sandbox's state, and the action
    /// it offers (#3772). Sent only on request, for the same reason as
    /// `setupRunning`.
    #[serde(skip_serializing_if = "Option::is_none")]
    notice: Option<environment_connect::SandboxNotice>,
    detail: Detail,
}

/// The fixed, enumerated fields a page can opt into. Anything else, including
/// a repeated or unknown parameter, is refused like other private queries.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadinessQuery {
    fields: Option<ReadinessFields>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ReadinessFields {
    /// `fields=setup` adds `setupRunning` (#2333).
    Setup,
    /// `fields=status` adds `setupRunning` and `notice` (#3772).
    Status,
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

impl Readiness {
    fn new(
        mut row: EnvironmentRow,
        setup_complete: bool,
        desired_state: i32,
        fields: Option<ReadinessFields>,
    ) -> Self {
        row.desired_state = environment_connect::desired_state_name(desired_state);
        let actions = environment_connect::lifecycle_actions(&row);
        let allowed = row.confidential_actions_allowed;
        let status = fields == Some(ReadinessFields::Status);
        Self {
            environment_id: row.id.clone(),
            running: row.state == "running" && row.confidential_actions_allowed,
            setup_complete,
            setup_running: fields.is_some().then_some(row.setup_running),
            notice: status.then(|| row.notice()),
            detail: Detail {
                state: row.state,
                desired_state: row.desired_state,
                tone: row.state_tone,
                last_event: row.last_event,
                resources: row.resources,
                deletion_state: row.deletion_state,
                shutdown_at: row.shutdown_at,
                cpu_millicores: row.cpu_millicores,
                memory_mib: row.memory_mb,
                disk_gib: row.disk_gb,
                start_eligible: actions.start,
                stop_eligible: actions.stop,
                delete_eligible: actions.delete,
                actions_allowed: allowed,
                pending: actions.pending,
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
    query: Result<Query<ReadinessQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug)
        || !super::terminal::canonical_environment_id(&environment_id)
    {
        return unavailable(StatusCode::NOT_FOUND);
    }
    let Ok(Query(query)) = query else {
        return unavailable(StatusCode::BAD_REQUEST);
    };
    let continuation = super::terminal::terminal_path(&slug, &environment_id);
    let (_, organization, cookie) =
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
    super::environments::apply_confidential_visibility(&state, &mut row);
    json(
        StatusCode::OK,
        Readiness::new(row, setup_complete, desired_state, query.fields),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment_connect::lifecycle_pending;
    use codewire_proto::codewire::v1::DesiredState;
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
        let value = serde_json::to_value(Readiness::new(
            row,
            false,
            DesiredState::Started as i32,
            None,
        ))
        .unwrap();
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
                None,
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
            serde_json::to_value(Readiness::new(row, false, desired as i32, None)).unwrap()
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

    /// #2333: Resize waits while setup owns a running Sandbox, as orchestration
    /// does, and is offered again once setup completes or records a failure.
    #[test]
    fn setup_running_only_while_setup_owns_a_running_sandbox() {
        use codewire_proto::codewire::v1::{Environment, EnvironmentState};
        let setup_running = |state: EnvironmentState, complete: bool, error: &str| {
            let row = environment_connect::environment_row(Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                state: state.into(),
                setup_complete: complete,
                setup_error: error.into(),
                ..Default::default()
            });
            let value = serde_json::to_value(Readiness::new(
                row,
                complete,
                DesiredState::Started as i32,
                Some(ReadinessFields::Setup),
            ))
            .unwrap();
            assert!(!value.to_string().contains("private setup failure"));
            value["setupRunning"].as_bool().unwrap()
        };
        assert!(setup_running(EnvironmentState::Running, false, ""));
        assert!(setup_running(EnvironmentState::Running, false, " "));
        assert!(!setup_running(EnvironmentState::Running, true, ""));
        assert!(!setup_running(
            EnvironmentState::Running,
            false,
            "private setup failure"
        ));
        // Resize of a stopped Sandbox applies on its next start.
        assert!(!setup_running(EnvironmentState::Stopped, false, ""));
        assert!(!setup_running(EnvironmentState::Starting, false, ""));
    }

    /// Pages loaded before `setupRunning` existed reject unknown fields. Only a
    /// page that asks for it receives it, so open terminals survive a deploy.
    #[test]
    fn setup_running_is_sent_only_to_a_page_that_asks_for_it() {
        use axum::http::Uri;
        let fields = |uri: &str| {
            Query::<ReadinessQuery>::try_from_uri(&uri.parse::<Uri>().unwrap())
                .map(|Query(query)| query.fields)
        };
        let base = "https://dashboard.invalid/org/id/_fragments/terminal-readiness";
        assert!(fields(base).unwrap().is_none());
        assert!(fields(&format!("{base}?fields=setup")).unwrap() == Some(ReadinessFields::Setup));
        for query in [
            "fields=",
            "fields=other",
            "fields=SETUP",
            "fields=setup&fields=setup",
            "fields=setup&extra=1",
            "extra=1",
        ] {
            assert!(fields(&format!("{base}?{query}")).is_err(), "{query}");
        }

        let render = |fields: Option<ReadinessFields>| {
            let row = environment_connect::environment_row(Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                state: EnvironmentState::Running.into(),
                ..Default::default()
            });
            serde_json::to_string(&Readiness::new(
                row,
                false,
                DesiredState::Started as i32,
                fields,
            ))
            .unwrap()
        };
        let id = "\"environmentId\":\"00000000-0000-4000-8000-000000000001\"";
        // Without the opt-in: the earlier shape, field for field and in order.
        let earlier = render(None);
        let earlier_detail = earlier
            .strip_prefix(&format!(
                "{{{id},\"running\":true,\"setupComplete\":false,\"detail\":"
            ))
            .expect("earlier readiness shape");
        assert!(!earlier.contains("setupRunning"));
        // With it: the same bytes plus setupRunning before detail.
        let opted_in = render(Some(ReadinessFields::Setup));
        let opted_in_detail = opted_in
            .strip_prefix(&format!(
                "{{{id},\"running\":true,\"setupComplete\":false,\"setupRunning\":true,\"detail\":"
            ))
            .expect("opted-in readiness shape");
        assert_eq!(earlier_detail, opted_in_detail);
    }

    /// #3772: a page that asks for the status receives the notice beside
    /// `setupRunning`; a page that asks only for setup gets exactly the shape
    /// it knows.
    #[test]
    fn the_status_is_sent_only_to_a_page_that_asks_for_it() {
        use axum::http::Uri;
        let base = "https://dashboard.invalid/org/id/_fragments/terminal-readiness";
        let query = Query::<ReadinessQuery>::try_from_uri(
            &format!("{base}?fields=status").parse::<Uri>().unwrap(),
        )
        .map(|Query(query)| query.fields);
        assert!(query.unwrap() == Some(ReadinessFields::Status));

        let render = |fields: Option<ReadinessFields>| {
            let row = environment_connect::environment_row(Environment {
                id: "00000000-0000-4000-8000-000000000001".into(),
                state: EnvironmentState::Starting.into(),
                error_code: "sandbox_replacing".into(),
                error_reason: "This sandbox's runtime is being replaced.".into(),
                ..Default::default()
            });
            serde_json::to_string(&Readiness::new(
                row,
                false,
                DesiredState::Started as i32,
                fields,
            ))
            .unwrap()
        };
        let setup = render(Some(ReadinessFields::Setup));
        assert!(!setup.contains("notice"));
        let status = render(Some(ReadinessFields::Status));
        let (head, detail) = status.split_once(",\"detail\":").unwrap();
        assert!(
            head.ends_with(
                "\"setupRunning\":false,\"notice\":{\"kind\":\"banner\",\"text\":\"This sandbox's runtime is being replaced.\",\"tone\":\"info\",\"action\":\"\",\"label\":\"\",\"dismissible\":false,\"graphic\":\"\"}"
            ),
            "{head}"
        );
        assert_eq!(
            Some(detail),
            setup.split_once(",\"detail\":").map(|(_, d)| d)
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
