use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    response::render_page, routes::organization_governance::get_context, state::AppState,
    templates::SnapshotsTemplate,
};

pub(super) async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let continuation = format!("/{slug}/snapshots/");
    let (dashboard, organization, _) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    render_page(SnapshotsTemplate {
        view: &dashboard,
        organization: &organization,
    })
}
