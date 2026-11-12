//! The organization's Hosts page (#3609): the computers its members enrolled
//! to provide VMs, with their state.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};

use connectrpc::ErrorCode;

use crate::{
    hosts_connect, organization_connect,
    response::render_page,
    routes::organization_governance::{connect_page_error, get_context},
    state::AppState,
    templates::HostsTemplate,
};

pub(super) async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let continuation = format!("/{slug}/hosts/");
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    // Owners are shown by name; a member list that can't be read only costs
    // the names, never the page.
    let names: HashMap<String, String> =
        organization_connect::members(&state, cookie.clone(), &organization.id, false)
            .await
            .map(|(members, _)| {
                members
                    .into_iter()
                    .map(|member| (member.user_id, member.display_name))
                    .collect()
            })
            .unwrap_or_default();
    let (hosts, error) = match hosts_connect::hosts(&state, cookie, &organization.id, |id| {
        names.get(id).cloned()
    })
    .await
    {
        Ok(hosts) => (hosts, String::new()),
        // Signed out, not a member or not allowed: the shared answers.
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unauthenticated | ErrorCode::NotFound | ErrorCode::PermissionDenied
            ) =>
        {
            return connect_page_error(error, &continuation, &headers);
        }
        // Anything else is shown on the page, which still renders.
        Err(_) => (
            Vec::new(),
            "Hosts could not be loaded. Reload the page to try again.".to_owned(),
        ),
    };
    render_page(HostsTemplate {
        view: &dashboard,
        organization: &organization,
        hosts,
        error,
    })
}

#[cfg(test)]
mod tests {
    use askama::Template as _;

    use crate::hosts_connect::HostRow;
    use crate::templates::HostsTemplate;
    use crate::view::{DashboardView, OrganizationContext, OrganizationRow};

    fn organization() -> OrganizationContext {
        OrganizationContext::from_row(&OrganizationRow {
            id: "org-test".into(),
            name: "Test organization".into(),
            slug: "test".into(),
            billing_plan: "none".into(),
            role: "Owner",
            can_admin: true,
            url: "/test/".into(),
        })
    }

    fn render(hosts: Vec<HostRow>, error: &str) -> String {
        HostsTemplate {
            view: &DashboardView::default(),
            organization: &organization(),
            hosts,
            error: error.to_owned(),
        }
        .render()
        .expect("render hosts")
    }

    fn host(name: &str, state: &'static str, tone: &'static str) -> HostRow {
        HostRow {
            id: format!("id-{name}"),
            name: name.into(),
            owner: "Ada Lovelace".into(),
            platform: "Linux x86-64",
            state,
            tone,
            last_seen: "just now".into(),
            provides: "Up to 2 VMs · 8 GiB memory".into(),
        }
    }

    #[test]
    fn hosts_are_listed_with_their_state_badge() {
        let html = render(
            vec![
                host("build-box", "Online", "success"),
                host("old", "Revoked", ""),
            ],
            "",
        );
        assert!(html.contains("<title>Hosts · Test organization · Codewire</title>"));
        assert!(html.contains(r#"<h2 id="hosts-title" class="cw-card-title">Hosts (2)</h2>"#));
        assert!(html.contains("<strong>build-box</strong>"));
        assert!(html.contains("Linux x86-64 · Owned by Ada Lovelace"));
        assert!(html.contains("Up to 2 VMs · 8 GiB memory"));
        assert!(html.contains(r#"<span class="cw-badge" data-tone="success">Online</span>"#));
        // A neutral state carries no tone at all.
        assert!(html.contains(r#"<span class="cw-badge">Revoked</span>"#));
        assert!(html.contains("Last seen just now"));
        assert!(!html.contains("No hosts yet"));
    }

    #[test]
    fn no_hosts_shows_how_to_enroll_one() {
        let html = render(Vec::new(), "");
        assert!(html.contains("No hosts yet"));
        assert!(html.contains("<code>cw host enroll</code>"));
        assert!(!html.contains("hosts-title"));
    }

    #[test]
    fn a_failed_read_says_so_instead_of_an_empty_list() {
        let html = render(
            Vec::new(),
            "Hosts could not be loaded. Reload the page to try again.",
        );
        assert!(html.contains(r#"role="alert">Hosts could not be loaded."#));
        assert!(!html.contains("No hosts yet"));
    }
}
