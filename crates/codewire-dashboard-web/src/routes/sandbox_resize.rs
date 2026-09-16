//! Private, bounded presentation of Resize. The backend still recomputes the
//! plan, enforces ownership/consent and binds its immutable request tuple.
use axum::{
    Form, Json,
    extract::{
        Path, Query, State,
        rejection::{FormRejection, PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::v1::{
    EnvironmentResizeDisruptionPolicy, EnvironmentResizeExecutionMode, EnvironmentResizeOperation,
    EnvironmentResizeOperationState, EnvironmentResizePlan, EnvironmentResources,
    ResizeEnvironmentRequest,
};
use connectrpc::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    environment_connect,
    error::WebError,
    security::{canonical_cookie, request_has_same_origin, valid_csrf_token},
    state::AppState,
};

// No Debug: these inputs contain request authority, not diagnostic data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    request_id: String,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
    allow_restart: bool,
    force: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationQuery {
    account_id: String,
    operation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Resources {
    cpu_millicores: i32,
    memory_mib: i32,
    disk_gib: i32,
}

impl Resources {
    fn new(cpu_millicores: i32, memory_mib: i32, disk_gib: i32) -> Option<Self> {
        if !(100..=128_000).contains(&cpu_millicores)
            || !(128..=1_048_576).contains(&memory_mib)
            || !(1..=16_384).contains(&disk_gib)
        {
            return None;
        }
        Some(Self {
            cpu_millicores,
            memory_mib,
            disk_gib,
        })
    }

    fn from_proto(value: Option<&EnvironmentResources>) -> Option<Self> {
        let value = value?;
        Self::new(value.cpu_millicores, value.memory_mb, value.disk_gb)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    account_id: String,
    environment_id: String,
    request_id: String,
    previous_resources: Resources,
    desired_resources: Resources,
    mode: &'static str,
    restart_required: bool,
    sessions_will_terminate: bool,
    active_session_count: i32,
}

impl Plan {
    fn new(
        account_id: String,
        environment_id: String,
        source: &EnvironmentResizePlan,
    ) -> Option<Self> {
        let mode = match source.execution_mode.as_known()? {
            EnvironmentResizeExecutionMode::Noop => "noop",
            EnvironmentResizeExecutionMode::ApplyOnStart => "apply-on-start",
            EnvironmentResizeExecutionMode::InPlace => "in-place",
            EnvironmentResizeExecutionMode::Restart => "restart",
            EnvironmentResizeExecutionMode::Unspecified => return None,
        };
        let restart_required = mode == "restart";
        if !(0..=1_000_000).contains(&source.active_session_count)
            || source.active_sessions_will_be_terminated
                != (restart_required && source.active_session_count > 0)
        {
            return None;
        }
        Some(Self {
            account_id,
            environment_id,
            request_id: uuid::Uuid::new_v4().simple().to_string(),
            previous_resources: Resources::from_proto(source.previous_resources.as_option())?,
            desired_resources: Resources::from_proto(source.desired_resources.as_option())?,
            mode,
            restart_required,
            sessions_will_terminate: source.active_sessions_will_be_terminated,
            active_session_count: source.active_session_count,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    account_id: String,
    environment_id: String,
    operation_id: String,
    request_id: String,
    desired_resources: Resources,
    policy: &'static str,
    state: &'static str,
}

impl Operation {
    fn new(account_id: String, source: &EnvironmentResizeOperation) -> Option<Self> {
        let state = match source.state.as_known()? {
            EnvironmentResizeOperationState::Pending => "pending",
            EnvironmentResizeOperationState::Applying => "applying",
            EnvironmentResizeOperationState::Restarting => "restarting",
            EnvironmentResizeOperationState::Completed => "completed",
            EnvironmentResizeOperationState::Failed => "failed",
            EnvironmentResizeOperationState::Unspecified => return None,
        };
        let policy = match source.disruption_policy.as_known()? {
            EnvironmentResizeDisruptionPolicy::LiveOnly => "live-only",
            EnvironmentResizeDisruptionPolicy::AllowRestart => "allow-restart",
            EnvironmentResizeDisruptionPolicy::Unspecified => return None,
        };
        if !canonical_operation_id(&source.id) || !canonical_operation_id(&source.request_id) {
            return None;
        }
        Some(Self {
            account_id,
            environment_id: source.environment_id.clone(),
            operation_id: source.id.clone(),
            request_id: source.request_id.clone(),
            desired_resources: Resources::from_proto(source.desired_resources.as_option())?,
            policy,
            state,
        })
    }
}

fn canonical_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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

fn failure(status: StatusCode, error: &'static str) -> Response {
    #[derive(Serialize)]
    struct Failure {
        error: &'static str,
    }
    json(status, Failure { error })
}

fn web_failure(error: WebError) -> Response {
    let (status, code) = match error {
        WebError::Unauthorized => (StatusCode::UNAUTHORIZED, "sign-in-required"),
        WebError::TwoFactorRequired => (StatusCode::FORBIDDEN, "two-factor-required"),
        WebError::NotFound => (StatusCode::NOT_FOUND, "not-found"),
        WebError::Forbidden => (StatusCode::FORBIDDEN, "not-authorized"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "resize-unavailable"),
    };
    failure(status, code)
}

struct Context {
    account_id: String,
    org_id: String,
    cookie: HeaderValue,
}

async fn context(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    environment_id: &str,
    account_id: &str,
) -> Result<Context, Response> {
    if !codewire_server_core::organization_slug::valid_organization_slug(slug)
        || !super::terminal::canonical_environment_id(environment_id)
        || !valid_account_id(account_id)
    {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid-request"));
    }
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(web_failure)?;
    enforce_two_factor(&identity).map_err(web_failure)?;
    if identity.id != account_id {
        return Err(failure(StatusCode::CONFLICT, "account-changed"));
    }
    let cookie = canonical_cookie(headers)
        .map_err(|()| failure(StatusCode::UNAUTHORIZED, "sign-in-required"))?;
    let dashboard =
        super::dashboard::dashboard_shell_view_from_identity(state, &identity, cookie.clone())
            .await
            .map_err(web_failure)?;
    let org_id = dashboard
        .organizations
        .iter()
        .find(|org| org.slug == slug)
        .map(|org| org.id.clone())
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not-found"))?;
    Ok(Context {
        account_id: identity.id,
        org_id,
        cookie,
    })
}

fn valid_action(state: &AppState, headers: &HeaderMap, csrf: &str) -> bool {
    request_has_same_origin(headers, &state.public_origin) && valid_csrf_token(headers, csrf)
}

pub(super) async fn plan(
    State(state): State<AppState>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
    form: Result<Form<PlanForm>, FormRejection>,
) -> Response {
    let Ok(Path((slug, environment_id))) = path else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    let Ok(Form(form)) = form else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    if !valid_action(&state, &headers, &form.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    if Resources::new(form.cpu_millicores, form.memory_mb, form.disk_gb).is_none() {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let context = match context(&state, &headers, &slug, &environment_id, &form.account_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match environment_connect::plan_environment_resize(
        &state,
        context.cookie,
        context.org_id,
        environment_id.clone(),
        form.cpu_millicores,
        form.memory_mb,
        form.disk_gb,
    )
    .await
    {
        Ok((source, _)) => match Plan::new(context.account_id, environment_id, &source) {
            Some(value) => json(StatusCode::OK, value),
            None => failure(StatusCode::BAD_GATEWAY, "resize-plan-unavailable"),
        },
        Err(error) => failure(
            match error.code {
                ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
                ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
                ErrorCode::NotFound => StatusCode::NOT_FOUND,
                ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            },
            "resize-plan-unavailable",
        ),
    }
}

pub(super) async fn apply(
    State(state): State<AppState>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
    form: Result<Form<ApplyForm>, FormRejection>,
) -> Response {
    let Ok(Path((slug, environment_id))) = path else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    let Ok(Form(form)) = form else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    if !valid_action(&state, &headers, &form.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    if !canonical_operation_id(&form.request_id)
        || Resources::new(form.cpu_millicores, form.memory_mb, form.disk_gb).is_none()
    {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let context = match context(&state, &headers, &slug, &environment_id, &form.account_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request = ResizeEnvironmentRequest {
        org_id: context.org_id,
        environment_id,
        request_id: form.request_id,
        cpu_millicores: form.cpu_millicores,
        memory_mb: form.memory_mb,
        disk_gb: form.disk_gb,
        force: form.force,
        disruption_policy: if form.allow_restart {
            EnvironmentResizeDisruptionPolicy::AllowRestart
        } else {
            EnvironmentResizeDisruptionPolicy::LiveOnly
        }
        .into(),
        ..Default::default()
    };
    // After dispatch, even a missing/mismatched response cannot prove rejection.
    match environment_connect::resize_environment(&state, context.cookie, request).await {
        Ok(source) => match Operation::new(context.account_id, &source) {
            Some(value) => json(StatusCode::OK, value),
            None => failure(StatusCode::CONFLICT, "resize-outcome-unknown"),
        },
        Err(_) => failure(StatusCode::CONFLICT, "resize-outcome-unknown"),
    }
}

pub(super) async fn operation(
    State(state): State<AppState>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
    query: Result<Query<OperationQuery>, QueryRejection>,
) -> Response {
    let Ok(Path((slug, environment_id))) = path else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    let Ok(Query(query)) = query else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    if !canonical_operation_id(&query.operation_id) {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let context = match context(&state, &headers, &slug, &environment_id, &query.account_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match environment_connect::environment_resize_operation(
        &state,
        context.cookie,
        context.org_id,
        environment_id,
        query.operation_id,
    )
    .await
    {
        Ok((source, _)) => match Operation::new(context.account_id, &source) {
            Some(value) => json(StatusCode::OK, value),
            None => failure(StatusCode::BAD_GATEWAY, "resize-observation-unavailable"),
        },
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "resize-observation-unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::FromRequest, http::Request};

    fn resources() -> EnvironmentResources {
        EnvironmentResources {
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 20,
            ..Default::default()
        }
    }

    fn source_plan() -> EnvironmentResizePlan {
        EnvironmentResizePlan {
            previous_resources: Some(resources()).into(),
            desired_resources: Some(resources()).into(),
            execution_mode: EnvironmentResizeExecutionMode::InPlace.into(),
            reason: "must not forward private backend text".into(),
            warnings: vec!["must not forward raw warning".into()],
            ..Default::default()
        }
    }

    #[test]
    fn plan_is_closed_bounded_metadata_and_requires_consistent_consent_flags() {
        let source = source_plan();
        let value =
            serde_json::to_value(Plan::new("actor".into(), "sandbox".into(), &source).unwrap())
                .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 9);
        assert_eq!(value["mode"], "in-place");
        assert_eq!(value["accountId"], "actor");
        assert_eq!(
            value["desiredResources"],
            serde_json::json!({ "cpuMillicores": 2000, "memoryMib": 4096, "diskGib": 20 })
        );
        assert!(canonical_operation_id(value["requestId"].as_str().unwrap()));
        assert!(!value.to_string().contains("must not forward"));
        for invalid in [
            EnvironmentResizePlan {
                execution_mode: EnvironmentResizeExecutionMode::Unspecified.into(),
                ..source.clone()
            },
            EnvironmentResizePlan {
                active_session_count: -1,
                ..source.clone()
            },
            EnvironmentResizePlan {
                active_session_count: 1_000_001,
                ..source.clone()
            },
            EnvironmentResizePlan {
                active_sessions_will_be_terminated: true,
                ..source.clone()
            },
            EnvironmentResizePlan {
                previous_resources: None.into(),
                ..source.clone()
            },
            EnvironmentResizePlan {
                desired_resources: None.into(),
                ..source.clone()
            },
        ] {
            assert!(Plan::new("actor".into(), "sandbox".into(), &invalid).is_none());
        }
        let mut restart = EnvironmentResizePlan {
            execution_mode: EnvironmentResizeExecutionMode::Restart.into(),
            active_session_count: 2,
            ..source
        };
        assert!(Plan::new("actor".into(), "sandbox".into(), &restart).is_none());
        restart.active_sessions_will_be_terminated = true;
        let value = Plan::new("actor".into(), "sandbox".into(), &restart).unwrap();
        assert!(value.restart_required && value.sessions_will_terminate);
    }

    #[test]
    fn operation_reports_desired_not_applied_and_never_forwards_failure_material() {
        let mut source = EnvironmentResizeOperation {
            id: "0123456789abcdef0123456789abcdef".into(),
            request_id: "fedcba9876543210fedcba9876543210".into(),
            environment_id: "sandbox".into(),
            desired_resources: Some(resources()).into(),
            last_applied_resources: Some(EnvironmentResources {
                cpu_millicores: 1000,
                ..resources()
            })
            .into(),
            disruption_policy: EnvironmentResizeDisruptionPolicy::LiveOnly.into(),
            state: EnvironmentResizeOperationState::Failed.into(),
            failure: Some(codewire_proto::codewire::v1::EnvironmentResizeFailure {
                code: "private code".into(),
                message: "private backend material".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let value = serde_json::to_value(Operation::new("actor".into(), &source).unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(value["state"], "failed");
        assert_eq!(value["desiredResources"]["cpuMillicores"], 2000);
        assert!(!value.to_string().contains("private"));
        source.state = EnvironmentResizeOperationState::Unspecified.into();
        assert!(Operation::new("actor".into(), &source).is_none());
        source.state = EnvironmentResizeOperationState::Pending.into();
        source.request_id = " noncanonical request ".into();
        assert!(Operation::new("actor".into(), &source).is_none());
    }

    #[tokio::test]
    async fn private_forms_reject_unknown_duplicate_and_missing_authority_fields() {
        let valid =
            "_csrf=synthetic&account_id=actor&cpu_millicores=2000&memory_mb=4096&disk_gb=20";
        for (body, accepted) in [
            (valid.to_owned(), true),
            (format!("{valid}&account_id=other"), false),
            (format!("{valid}&environment_id=foreign"), false),
            (format!("{valid}&command=arbitrary"), false),
            (valid.replace("account_id=actor&", ""), false),
        ] {
            let request = Request::builder()
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                Form::<PlanForm>::from_request(request, &()).await.is_ok(),
                accepted
            );
        }
        let valid = format!(
            "{valid}&request_id=0123456789abcdef0123456789abcdef&allow_restart=false&force=false"
        );
        for (body, accepted) in [
            (valid.clone(), true),
            (format!("{valid}&force=true"), false),
            (
                valid.replace("allow_restart=false", "allow_restart=unknown"),
                false,
            ),
            (valid.replace("&force=false", ""), false),
        ] {
            let request = Request::builder()
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                Form::<ApplyForm>::from_request(request, &()).await.is_ok(),
                accepted
            );
        }
    }

    #[tokio::test]
    async fn failure_responses_are_closed_private_and_never_redirect_or_rotate_csrf() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let response = failure(status, "resize-outcome-unknown");
            assert_eq!(response.status(), status);
            let headers = response.headers();
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers[header::VARY], "Cookie");
            for header in ["location", "set-cookie", "hx-redirect", "hx-refresh"] {
                assert!(!headers.contains_key(header));
            }
            let bytes = axum::body::to_bytes(response.into_body(), 2048)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"error": "resize-outcome-unknown"})
            );
        }
    }

    #[test]
    fn identifiers_and_resources_are_canonical_before_dispatch() {
        assert!(canonical_operation_id("0123456789abcdef0123456789abcdef"));
        for id in [
            "",
            "request",
            "0123456789ABCDEF0123456789ABCDEF",
            " 0123456789abcdef0123456789abcdef",
        ] {
            assert!(!canonical_operation_id(id));
        }
        assert!(valid_account_id("actor-1_2"));
        assert!(!valid_account_id("actor changed"));
        for tuple in [
            (99, 4096, 20),
            (128001, 4096, 20),
            (2000, 127, 20),
            (2000, 1048577, 20),
            (2000, 4096, 0),
            (2000, 4096, 16385),
        ] {
            assert!(Resources::new(tuple.0, tuple.1, tuple.2).is_none());
        }
    }
}
