//! The organization's Network policies pages (#5114): its stored policies,
//! the built-ins, and one policy's destinations, check and delete. The store
//! and its rules are `NetworkPolicyService`'s; these pages show and change
//! the same policies `cw --cloud policy` does.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    network_policies_connect::{self, CheckError, PolicyList, PolicyRow, RuleInput},
    response::render_page,
    routes::organization_governance::{
        action_context, connect_page_error, get_context, mutation_redirect,
    },
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::{NetworkPoliciesTemplate, NetworkPolicyTemplate},
    view::{DashboardView, OrganizationContext, connect_error_reason},
};

/// What a page says above its content, after a redirect.
#[derive(Debug, Default, Deserialize)]
pub(super) struct PolicyQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    /// A destination to check, from the policy page's check form.
    #[serde(default)]
    check: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    /// Empty for `locked`, or one of the organization's policies.
    #[serde(default)]
    from: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    ports: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChangeSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    /// The revision the page showed; a change made against an older one is
    /// refused rather than lost.
    revision: u32,
    target: String,
    #[serde(default)]
    ports: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// The create dialog's fields, kept when the store refuses them.
#[derive(Clone, Debug, Default)]
pub(crate) struct CreateForm {
    pub(crate) open: bool,
    pub(crate) name: String,
    pub(crate) from: String,
    pub(crate) target: String,
    pub(crate) ports: String,
    pub(crate) error: String,
}

/// The policy page's "Allow a destination" fields, kept on a refusal.
#[derive(Clone, Debug, Default)]
pub(crate) struct AllowForm {
    pub(crate) target: String,
    pub(crate) ports: String,
    pub(crate) error: String,
}

/// Whether the page has policies to show, and why not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreState {
    Ready,
    /// The deployment has organization network policies switched off.
    SwitchedOff,
    /// The store did not answer.
    Unavailable,
}

pub(crate) struct ListPageView {
    pub(crate) store: StoreState,
    pub(crate) list: PolicyList,
    pub(crate) csrf_token: String,
    pub(crate) message: &'static str,
    pub(crate) error: &'static str,
    pub(crate) create: CreateForm,
}

/// Said on every page while hosted Sandboxes don't enforce network
/// policies (#4000), in the words `cw --cloud policy` uses.
const NOT_ENFORCED: &str = "Hosted Sandboxes don't enforce network policies yet, so a policy here changes nothing a Sandbox can reach.";

impl ListPageView {
    pub(crate) fn ready(&self) -> bool {
        self.store == StoreState::Ready
    }

    pub(crate) fn switched_off(&self) -> bool {
        self.store == StoreState::SwitchedOff
    }

    pub(crate) fn unavailable(&self) -> bool {
        self.store == StoreState::Unavailable
    }

    pub(crate) fn not_enforced(&self) -> &'static str {
        NOT_ENFORCED
    }
}

impl PolicyPageView {
    pub(crate) fn not_enforced(&self) -> &'static str {
        NOT_ENFORCED
    }
}

pub(crate) struct PolicyPageView {
    pub(crate) policy: PolicyRow,
    pub(crate) csrf_token: String,
    pub(crate) message: &'static str,
    /// The store's own words, such as delete's refusal naming Sandboxes.
    pub(crate) error: String,
    pub(crate) allow: AllowForm,
    pub(crate) check_input: String,
    pub(crate) check: Option<network_policies_connect::CheckAnswer>,
    pub(crate) check_error: &'static str,
}

fn list_path(slug: &str) -> String {
    format!("/{slug}/network-policies/")
}

fn policy_path(slug: &str, name: &str) -> String {
    format!("/{slug}/network-policies/{name}/")
}

/// A policy name as the store accepts it; anything else is not a policy.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn message_text(code: &str) -> &'static str {
    match code {
        "created" => "Policy created at revision 1.",
        "saved" => "Saved as a new revision.",
        "deleted" => "Policy deleted.",
        _ => "",
    }
}

fn error_text(code: &str) -> &'static str {
    match code {
        "not-authorized" => "Only an organization owner or admin can change network policies.",
        "unavailable" => "Network policies could not be changed. Try again.",
        _ => "",
    }
}

/// "22, 80, 443" as ports, or an error; empty is the default ports.
fn parse_ports(text: &str) -> Result<Vec<u32>, &'static str> {
    text.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .map(u32::from)
                .ok_or("Ports are numbers from 1 to 65535, separated by commas.")
        })
        .collect()
}

/// The store's refusal in its own words, or a general one.
fn refusal(error: &ConnectError) -> String {
    match error.code {
        ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition | ErrorCode::AlreadyExists => {
            error.message.clone().unwrap_or_default()
        }
        ErrorCode::PermissionDenied => error_text("not-authorized").to_owned(),
        _ => error_text("unavailable").to_owned(),
    }
}

fn store_state(error: &ConnectError) -> StoreState {
    if connect_error_reason(error).as_deref() == Some("NETWORK_POLICIES_DISABLED") {
        StoreState::SwitchedOff
    } else {
        StoreState::Unavailable
    }
}

fn is_page_error(error: &ConnectError) -> bool {
    matches!(
        error.code,
        ErrorCode::Unauthenticated | ErrorCode::NotFound | ErrorCode::PermissionDenied
    )
}

async fn render_list(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: &DashboardView,
    organization: &OrganizationContext,
    cookie: axum::http::HeaderValue,
    feedback: (&str, &str),
    create: CreateForm,
) -> Response {
    let continuation = list_path(&organization.slug);
    let (store, list) = match network_policies_connect::list(state, cookie, &organization.id).await
    {
        Ok(list) => (StoreState::Ready, list),
        Err(error) if is_page_error(&error) => {
            return connect_page_error(error, &continuation, headers);
        }
        Err(error) => (store_state(&error), PolicyList::default()),
    };
    let token = page_csrf_token(headers);
    let status = if create.error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = ListPageView {
        store,
        list,
        csrf_token: token.clone(),
        message: message_text(feedback.0),
        error: error_text(feedback.1),
        create,
    };
    let response = render_page(NetworkPoliciesTemplate {
        view: dashboard,
        organization,
        page: &page,
        active_tab: "network-policies",
    });
    with_csrf_cookie(
        (status, response).into_response(),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn list_page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<PolicyQuery>,
    headers: HeaderMap,
) -> Response {
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &list_path(&slug)).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    render_list(
        &state,
        &headers,
        &dashboard,
        &organization,
        cookie,
        (&query.message, &query.error),
        CreateForm::default(),
    )
    .await
}

pub(super) async fn create(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<CreateSubmission>,
) -> Response {
    let continuation = list_path(&slug);
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin {
        return mutation_redirect(continuation, "", "not-authorized", &headers);
    }
    let mut form = CreateForm {
        open: true,
        name: submission.name.trim().to_owned(),
        from: submission.from.trim().to_owned(),
        target: submission.target.trim().to_owned(),
        ports: submission.ports.trim().to_owned(),
        error: String::new(),
    };
    let ports = match parse_ports(&form.ports) {
        Ok(ports) => ports,
        Err(message) => {
            form.error = message.to_owned();
            return render_list(
                &state,
                &headers,
                &dashboard,
                &organization,
                cookie,
                ("", ""),
                form,
            )
            .await;
        }
    };
    let allow: Vec<RuleInput> = if form.target.is_empty() {
        Vec::new()
    } else {
        vec![RuleInput {
            target: form.target.clone(),
            ports,
        }]
    };
    let from = (!form.from.is_empty()).then_some(form.from.as_str());
    match network_policies_connect::create(
        &state,
        cookie.clone(),
        &organization.id,
        &form.name,
        from,
        &allow,
    )
    .await
    {
        Ok(()) => mutation_redirect(policy_path(&slug, &form.name), "created", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            connect_page_error(error, &continuation, &headers)
        }
        Err(error) => {
            form.error = refusal(&error);
            render_list(
                &state,
                &headers,
                &dashboard,
                &organization,
                cookie,
                ("", ""),
                form,
            )
            .await
        }
    }
}

/// What one rendering of a policy page carries besides the policy.
#[derive(Default)]
struct PolicyFeedback<'a> {
    message: &'static str,
    error: String,
    allow: AllowForm,
    check_input: &'a str,
}

async fn render_policy(
    state: &AppState,
    headers: &HeaderMap,
    context: (
        &DashboardView,
        &OrganizationContext,
        axum::http::HeaderValue,
    ),
    name: &str,
    feedback: PolicyFeedback<'_>,
) -> Response {
    let (dashboard, organization, cookie) = context;
    let PolicyFeedback {
        message,
        error,
        allow,
        check_input,
    } = feedback;
    let continuation = policy_path(&organization.slug, name);
    let policy = match network_policies_connect::get(state, cookie, &organization.id, name).await {
        Ok(policy) => policy,
        Err(error) => return connect_page_error(error, &continuation, headers),
    };
    let (check, check_error) = if check_input.trim().is_empty() {
        (None, "")
    } else {
        match network_policies_connect::check(&policy, check_input) {
            Ok(answer) => (Some(answer), ""),
            Err(CheckError::Destination) => (
                None,
                "Enter a DNS name or IP address, with a port from 1 to 65535 if not 443.",
            ),
            Err(CheckError::Policy) => (None, "This revision could not be checked."),
        }
    };
    let token = page_csrf_token(headers);
    let status = if error.is_empty() && allow.error.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let page = PolicyPageView {
        policy,
        csrf_token: token.clone(),
        message,
        error,
        allow,
        check_input: check_input.trim().to_owned(),
        check,
        check_error,
    };
    let response = render_page(NetworkPolicyTemplate {
        view: dashboard,
        organization,
        page: &page,
        active_tab: "network-policies",
    });
    with_csrf_cookie(
        (status, response).into_response(),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn policy_page(
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    Query(query): Query<PolicyQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = policy_path(&slug, &name);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !valid_name(&name) {
        return mutation_redirect(list_path(&slug), "", "", &headers);
    }
    render_policy(
        &state,
        &headers,
        (&dashboard, &organization, cookie),
        &name,
        PolicyFeedback {
            message: message_text(&query.message),
            error: error_text(&query.error).to_owned(),
            check_input: &query.check,
            ..Default::default()
        },
    )
    .await
}

/// Adds or removes one destination in a new revision.
async fn change(
    state: AppState,
    slug: String,
    name: String,
    headers: HeaderMap,
    submission: ChangeSubmission,
    adding: bool,
) -> Response {
    let continuation = policy_path(&slug, &name);
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_name(&name) {
        return mutation_redirect(continuation, "", "not-authorized", &headers);
    }
    let target = submission.target.trim().to_owned();
    let mut form = AllowForm {
        target: if adding {
            target.clone()
        } else {
            String::new()
        },
        ports: submission.ports.trim().to_owned(),
        error: String::new(),
    };
    let ports = match parse_ports(&form.ports) {
        Ok(ports) => ports,
        Err(message) => {
            form.error = message.to_owned();
            return render_policy(
                &state,
                &headers,
                (&dashboard, &organization, cookie),
                &name,
                PolicyFeedback {
                    allow: form,
                    ..Default::default()
                },
            )
            .await;
        }
    };
    let (allow, remove) = if adding {
        (vec![RuleInput { target, ports }], Vec::new())
    } else {
        (Vec::new(), vec![target])
    };
    let result = network_policies_connect::update(
        &state,
        cookie.clone(),
        &organization.id,
        &name,
        &allow,
        &remove,
        submission.revision,
    )
    .await;
    let error = match result {
        Ok(()) => return mutation_redirect(continuation, "saved", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return connect_page_error(error, &continuation, &headers);
        }
        Err(error) => error,
    };
    // A refused change against an older revision is a concurrent save: say
    // so, show the current revision, and keep what the user typed.
    let current = network_policies_connect::get(&state, cookie.clone(), &organization.id, &name)
        .await
        .map(|policy| policy.revision)
        .unwrap_or(submission.revision);
    let message = if current != submission.revision {
        format!(
            "Revision {current} was saved while you were editing, so your change is not saved yet. Review revision {current} and try again."
        )
    } else {
        refusal(&error)
    };
    if adding {
        form.error = message;
        render_policy(
            &state,
            &headers,
            (&dashboard, &organization, cookie),
            &name,
            PolicyFeedback {
                allow: form,
                ..Default::default()
            },
        )
        .await
    } else {
        render_policy(
            &state,
            &headers,
            (&dashboard, &organization, cookie),
            &name,
            PolicyFeedback {
                error: message,
                ..Default::default()
            },
        )
        .await
    }
}

pub(super) async fn allow(
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<ChangeSubmission>,
) -> Response {
    change(state, slug, name, headers, submission, true).await
}

pub(super) async fn remove(
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<ChangeSubmission>,
) -> Response {
    change(state, slug, name, headers, submission, false).await
}

pub(super) async fn delete(
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
    headers: HeaderMap,
    Form(submission): Form<DeleteSubmission>,
) -> Response {
    let continuation = policy_path(&slug, &name);
    let (dashboard, organization, cookie) = match action_context(
        &state,
        &headers,
        &slug,
        &submission.csrf,
        continuation.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !organization.can_admin || !valid_name(&name) {
        return mutation_redirect(continuation, "", "not-authorized", &headers);
    }
    match network_policies_connect::delete(&state, cookie.clone(), &organization.id, &name).await {
        Ok(()) => mutation_redirect(list_path(&slug), "deleted", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            connect_page_error(error, &continuation, &headers)
        }
        // The store's refusal names the Sandboxes that still select it.
        Err(error) => {
            render_policy(
                &state,
                &headers,
                (&dashboard, &organization, cookie),
                &name,
                PolicyFeedback {
                    error: refusal(&error),
                    ..Default::default()
                },
            )
            .await
        }
    }
}

#[cfg(test)]
#[path = "network_policies_tests.rs"]
mod tests;
