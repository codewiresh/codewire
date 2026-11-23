//! One row of the Sandboxes list (#4762; private-docs
//! `designs/live-updates.md` §3a). When the live stream says a Sandbox
//! changed, the page re-fetches only its row from here, under the same
//! filters and visibility as the list, and replaces that row alone.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};

use super::environments::{
    EnvironmentsQuery, allowlisted_state, apply_confidential_visibility, bounded_query,
    default_create_form, environments_path, filtered_environments,
};
use crate::{
    environment_connect,
    response::render_template,
    routes::organization_governance::{connect_page_error, get_context_without_rail},
    security::csrf_cookie_value,
    state::AppState,
    templates::EnvironmentRowTemplate,
    view::{EnvironmentRow, EnvironmentsPageView, SandboxStartView},
};

/// The list's page view for `environments` under `query`.
pub(super) fn list_page(
    environments: Vec<EnvironmentRow>,
    query: &EnvironmentsQuery,
    headers: &HeaderMap,
    start: Option<SandboxStartView>,
) -> EnvironmentsPageView {
    let token = csrf_cookie_value(headers).unwrap_or_default().to_owned();
    EnvironmentsPageView {
        environments,
        environments_loading: false,
        create_form: default_create_form(token, false),
        source_editor: None,
        port_panel: None,
        trust_summary: None,
        resize_confirmation: None,
        resize_operation: None,
        search: bounded_query(&query.search),
        state: allowlisted_state(&query.state).to_owned(),
        message: String::new(),
        error: String::new(),
        start,
    }
}

/// `GET /{slug}/_fragments/sandboxes/{id}`: the Sandbox's row as the list
/// renders it, or 204 when the list under these filters has no such row (it
/// was created, removed, or left the view), and the page re-fetches the list.
pub(super) async fn row_fragment(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    Query(query): Query<EnvironmentsQuery>,
    headers: HeaderMap,
) -> Response {
    if !super::terminal::canonical_environment_id(&environment_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let continuation = environments_path(&slug);
    let (_, organization, cookie) =
        match get_context_without_rail(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    // The list's own query, so the row and the list never disagree about
    // filters or about what this viewer may see.
    let environments =
        match filtered_environments(&state, cookie.clone(), &organization.id, &query).await {
            Ok(environments) => environments,
            Err(error) => return connect_page_error(error, &continuation, &headers),
        };
    let Some(mut row) = environments
        .into_iter()
        .find(|environment| environment.id == environment_id)
    else {
        return StatusCode::NO_CONTENT.into_response();
    };
    apply_confidential_visibility(&state, &mut row);
    let mut rows = vec![row];
    environment_connect::mark_credential_attention(&state, cookie, &mut rows).await;
    let page = list_page(rows, &query, &headers, None);
    render_template(
        StatusCode::OK,
        EnvironmentRowTemplate {
            organization: &organization,
            page: &page,
            sandbox: &page.environments[0],
        },
    )
}
