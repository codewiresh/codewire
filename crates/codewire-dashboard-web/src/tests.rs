use askama::Template as _;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use codewire_proto::google::rpc::BadRequest;
use connectrpc::ConnectError;

use crate::{
    admin_connect::{
        AdminApiKeyRow, AdminMemberRow, AdminOrganizationRow, AdminOrganizationView,
        AdminOrganizations, AdminSubscriptionRow, AuditLogRow, FeedbackFilter, FeedbackRow,
        FeedbackSenderView, QuotaLimitView, QuotaView,
    },
    admin_sandbox_counts::{OrganizationSandboxes, SandboxCountsView},
    response::{HTMX_REQUEST, login_redirect, safe_auth_continuation, two_factor_redirect},
    templates::{
        AdminAccountsTemplate, AdminAuditTemplate, AdminFeedbackTemplate,
        AdminOrganizationTemplate, AdminOrganizationsTemplate, OrganizationFormTemplate,
        OrganizationListTemplate, SetupTwoFactorTemplate, TwoFactorRecoveryTemplate,
    },
    transport::browser_headers,
    view::{
        AccountAccessView, DashboardView, OrganizationFormView, OrganizationRow,
        SetupTwoFactorView, TwoFactorRecoveryView, apply_organization_error,
        valid_organization_slug, validate_organization_form,
    },
};

#[test]
fn two_factor_template_exposes_an_escaped_manual_setup_key() {
    let view = SetupTwoFactorView {
        csrf_token: "csrf-token".into(),
        return_to: "/dashboard".into(),
        qr_svg: "<svg aria-hidden=\"true\"></svg>".into(),
        secret: "<unsafe-secret>".into(),
        error: String::new(),
    };
    let body = SetupTwoFactorTemplate { view: &view }
        .render()
        .expect("render two-factor setup page");

    assert!(body.contains("data-testid=\"totp-secret\""));
    assert!(!body.contains("<unsafe-secret>"));
    assert!(body.contains("&lt;unsafe-secret&gt;") || body.contains("&#60;unsafe-secret&#62;"));
    assert!(!body.contains("recovery-code"));
}

#[test]
fn two_factor_recovery_template_reveals_codes_only_after_verification() {
    let view = TwoFactorRecoveryView {
        return_to: "/dashboard".into(),
        backup_codes: vec!["<unsafe-recovery>".into()],
    };
    let body = TwoFactorRecoveryTemplate { view: &view }
        .render()
        .expect("render two-factor recovery page");

    assert!(body.contains("Two-factor authentication enabled"));
    assert!(body.contains("data-testid=\"recovery-code\""));
    assert!(!body.contains("<unsafe-recovery>"));
    assert!(body.contains("&lt;unsafe-recovery&gt;") || body.contains("&#60;unsafe-recovery&#62;"));
}

#[test]
fn admin_audit_template_escapes_sensitive_upstream_fields() {
    let view = DashboardView {
        account_id: "synthetic-account".to_owned(),
        user_name: "<unsafe admin>".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: false,
        support_mailto: String::new(),
        updates_enabled: false,
    };
    let logs = vec![AuditLogRow {
        occurred: "Just now".into(),
        action: "<script>alert('action')</script>".into(),
        user: "<unsafe@example.test>".into(),
        ip_address: "127.0.0.1".into(),
        severity: "error".into(),
        severity_tone: "danger",
        metadata: "</pre><script>alert('metadata')</script>".into(),
        has_metadata: true,
    }];
    let body = AdminAuditTemplate {
        view: &view,
        logs: &logs,
        action: "<unsafe filter>",
        info_selected: false,
        warn_selected: false,
        error_selected: true,
        has_previous: false,
        has_next: false,
        previous_url: "/admin/audit",
        next_url: "/admin/audit?offset=50",
    }
    .render()
    .expect("render admin audit page");

    assert!(!body.contains("<script>"));
    assert!(!body.contains("<unsafe admin>"));
    assert!(!body.contains("</pre><script>"));
    assert!(body.contains("&lt;script&gt;") || body.contains("&#60;script&#62;"));
}

#[test]
fn admin_feedback_shows_each_sender_and_escapes_what_they_sent() {
    let view = DashboardView::default();
    let rows = vec![
        FeedbackRow {
            received: "November 14, 2026, 17:02 UTC".into(),
            received_at: "2026-11-14T17:02:09Z".into(),
            sender: FeedbackSenderView::SignedIn {
                label: "<owner@example.test>".into(),
                mailto: Some(
                    "mailto:%3Cowner@example.test%3E?subject=Re%3A%20your%20Codewire%20feedback"
                        .into(),
                ),
                account_url: "/admin/accounts/?account=user-1".into(),
                organization: Some("Acme <Labs>".into()),
            },
            message: "first line\n</p><script>alert('feedback')</script>".into(),
            cli_version: "0.9.1".into(),
            platform: "linux x86_64".into(),
            placement: "Cloud",
            environment_id: Some("env-123".into()),
        },
        FeedbackRow {
            received: "November 14, 2026, 16:40 UTC".into(),
            received_at: "2026-11-14T16:40:00Z".into(),
            sender: FeedbackSenderView::Anonymous,
            message: "anonymous note".into(),
            cli_version: "0.9.0".into(),
            platform: "macos aarch64".into(),
            placement: "",
            environment_id: None,
        },
    ];
    let body = AdminFeedbackTemplate {
        view: &view,
        rows: &rows,
        filter: FeedbackFilter::Anonymous,
        later_page: true,
        first_page_url: "/admin/feedback/?sender=anonymous",
        next_page_url: "/admin/feedback/?sender=anonymous&page=1.a",
    }
    .render()
    .expect("render admin feedback page");

    assert!(!body.contains("<script>alert"));
    assert!(!body.contains("<owner@example.test>"));
    assert!(!body.contains("Acme <Labs>"));
    assert_eq!(body.matches("<article class=\"cw-feedback\"").count(), 2);
    assert!(body.contains(">Anonymous</h3>"));
    assert!(body.contains(
        "<a href=\"mailto:%3Cowner@example.test%3E?subject=Re%3A%20your%20Codewire%20feedback\">&#60;owner@example.test&#62;</a></h3>"
    ) || body.contains(
        "<a href=\"mailto:%3Cowner@example.test%3E?subject=Re%3A%20your%20Codewire%20feedback\">&lt;owner@example.test&gt;</a></h3>"
    ));
    assert_eq!(body.matches("View account").count(), 1);
    assert!(body.contains("href=\"/admin/accounts/?account=user-1\">View account"));
    assert_eq!(body.matches("mailto:").count(), 1);
    assert!(
        body.contains(
            "<time datetime=\"2026-11-14T17:02:09Z\">November 14, 2026, 17:02 UTC</time>"
        )
    );
    assert!(body.contains("<dt>Placement</dt><dd>Cloud</dd>"));
    assert_eq!(body.matches("<dt>Placement</dt>").count(), 1);
    assert_eq!(body.matches("<dt>Sandbox</dt>").count(), 1);
    assert!(body.contains("<option value=\"anonymous\" selected>"));
    assert!(body.contains(">Newest</a>"));
    assert!(
        body.contains("href=\"/admin/feedback/?sender=anonymous&amp;page=1.a\">Older</a>")
            || body.contains("href=\"/admin/feedback/?sender=anonymous&#38;page=1.a\">Older</a>")
    );

    for (filter, later_page, empty) in [
        (FeedbackFilter::All, false, "No feedback yet."),
        (
            FeedbackFilter::SignedIn,
            false,
            "No signed-in feedback yet.",
        ),
        (
            FeedbackFilter::Anonymous,
            false,
            "No anonymous feedback yet.",
        ),
        (FeedbackFilter::All, true, "No older feedback."),
    ] {
        let body = AdminFeedbackTemplate {
            view: &view,
            rows: &[],
            filter,
            later_page,
            first_page_url: "",
            next_page_url: "",
        }
        .render()
        .expect("render empty admin feedback page");
        assert!(body.contains(empty), "{empty}");
        assert!(!body.contains("cw-pagination"));
    }
}

/// The header's Support button writes to the configured support address
/// with a "[Support]" subject, in this tab; without an address it is gone.
#[test]
fn the_support_button_follows_the_configured_address() {
    for (support_mailto, shown) in [
        ("mailto:support@codewire.sh?subject=%5BSupport%5D", true),
        ("", false),
    ] {
        let view = DashboardView {
            support_mailto: support_mailto.to_owned(),
            ..Default::default()
        };
        let body = AdminFeedbackTemplate {
            view: &view,
            rows: &[],
            filter: FeedbackFilter::All,
            later_page: false,
            first_page_url: "",
            next_page_url: "",
        }
        .render()
        .expect("render a page with the console header");
        assert_eq!(
            body.contains(
                "<a class=\"cw-button cw-button--outline cw-button--small\" href=\"mailto:support@codewire.sh?subject=%5BSupport%5D\">Support</a>"
            ),
            shown
        );
        assert_eq!(body.contains(">Support</a>"), shown);
        assert!(!body.contains("target=\"_blank\" rel=\"noopener\"><span>Support"));
    }
}

/// The sidebar links Updates, above Documentation, only where the deployment
/// serves the page.
#[test]
fn the_sidebar_links_updates_only_where_the_page_is_served() {
    for updates_enabled in [true, false] {
        let view = DashboardView {
            updates_enabled,
            ..Default::default()
        };
        let body = AdminFeedbackTemplate {
            view: &view,
            rows: &[],
            filter: FeedbackFilter::All,
            later_page: false,
            first_page_url: "",
            next_page_url: "",
        }
        .render()
        .unwrap();
        let updates = body.find(r#"href="/updates""#);
        assert_eq!(updates.is_some(), updates_enabled);
        if let Some(updates) = updates {
            assert!(updates < body.find(r#"href="/docs">"#).unwrap());
        }
    }
}

/// Both copies of the Sandbox rail (desktop sidebar and mobile drawer) wait
/// for dashboard.js to refresh the one on screen; htmx itself never loads or
/// polls either, so a page makes one rail request, not two (#3395).
#[test]
fn both_rail_copies_refresh_only_when_the_dashboard_script_asks() {
    for loading in [false, true] {
        let view = DashboardView {
            has_selected_organization: true,
            selected_organization_slug: "acme".to_owned(),
            selected_organization_url: "/acme/".to_owned(),
            sandbox_rail_loading: loading,
            ..Default::default()
        };
        let body = AdminAuditTemplate {
            view: &view,
            logs: &Vec::new(),
            action: "",
            info_selected: false,
            warn_selected: false,
            error_selected: false,
            has_previous: false,
            has_next: false,
            previous_url: "/admin/audit",
            next_url: "/admin/audit",
        }
        .render()
        .expect("render admin audit page");
        let rail = format!(
            "hx-get=\"/acme/_fragments/sandbox-rail\" hx-trigger=\"sandbox-rail-refresh\" hx-swap=\"innerHTML\" data-sandbox-rail data-rail-loading=\"{loading}\""
        );
        assert_eq!(body.matches(&rail).count(), 2, "{loading}");
        assert_eq!(body.matches("_fragments/sandbox-rail").count(), 2);
        assert!(!body.contains("every 10s"));
    }
}

#[test]
fn the_shell_renders_the_collapsed_sidebar_and_both_sidebar_buttons() {
    for collapsed in [false, true] {
        let view = DashboardView {
            sidebar_collapsed: collapsed,
            support_mailto: String::new(),
            updates_enabled: false,
            ..Default::default()
        };
        let body = AdminAuditTemplate {
            view: &view,
            logs: &Vec::new(),
            action: "",
            info_selected: false,
            warn_selected: false,
            error_selected: false,
            has_previous: false,
            has_next: false,
            previous_url: "/admin/audit",
            next_url: "/admin/audit",
        }
        .render()
        .expect("render admin audit page");
        assert!(body.contains(&format!("data-sidebar-collapsed=\"{collapsed}\">")));
        assert!(body.contains("data-sidebar-close aria-label=\"Collapse navigation\""));
        assert!(body.contains("data-sidebar-expand aria-label=\"Expand navigation\""));
    }
}

#[test]
fn admin_accounts_template_escapes_access_request_fields() {
    let view = DashboardView {
        account_id: "synthetic-account".to_owned(),
        user_name: "Admin".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: false,
        support_mailto: String::new(),
        updates_enabled: false,
    };
    let accounts = vec![AccountAccessView {
        id: "user-safe".into(),
        email: "<unsafe@example.test>".into(),
        name: "<script>alert('name')</script>".into(),
        email_verified: true,
        enabled: false,
        suspended: false,
        mail_suppressed: "",
        own: false,
        reason: "</td><script>alert('reason')</script>".into(),
        has_reason: true,
        created_at: "2026-09-08T12:00:00".into(),
        identities: vec![crate::view::LinkedIdentityView {
            provider: "GitHub",
            subject: "583231".into(),
            account: "<script>alert('login')</script>".into(),
            linked_at: "2026-11-12T09:30:00".into(),
        }],
        deletion: crate::view::AccountDeletionOffer::Offered,
    }];
    let body = AdminAccountsTemplate {
        view: &view,
        accounts: &accounts,
        one_account: false,
        csrf_token: "csrf-safe",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin account access page");

    assert!(!body.contains("<script>"));
    assert!(!body.contains("<unsafe@example.test>"));
    assert!(!body.contains("</td><script>"));
    assert!(body.contains("&lt;script&gt;") || body.contains("&#60;script&#62;"));
    // Admins see each linked identity: provider, login, subject and when.
    assert!(body.contains("<th scope=\"col\">Sign-in providers</th>"));
    assert!(body.contains("<li><strong>GitHub</strong><span class=\"cw-access-email\">"));
    assert!(body.contains("<code>583231</code> · linked <time datetime=\"2026-11-12T09:30:00\">"));
}

#[test]
fn only_an_unverified_account_offers_to_resend_its_verification_email() {
    let view = DashboardView {
        account_id: "synthetic-account".to_owned(),
        user_name: "Admin".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: false,
        support_mailto: String::new(),
        updates_enabled: false,
    };
    let account = |id: &str, email_verified: bool| AccountAccessView {
        id: id.into(),
        email: format!("{id}@example.test"),
        name: id.into(),
        email_verified,
        enabled: false,
        suspended: false,
        mail_suppressed: "",
        own: false,
        reason: "Build agents".into(),
        has_reason: true,
        created_at: "2026-11-12T12:00:00".into(),
        identities: Vec::new(),
        deletion: crate::view::AccountDeletionOffer::Offered,
    };
    // An address SES suppressed is marked beside its verification (#4548).
    let bounced = AccountAccessView {
        mail_suppressed: "Bounced",
        ..account("user-bounced", false)
    };
    let accounts = vec![
        account("user-waiting", false),
        account("user-verified", true),
        bounced,
    ];
    let body = AdminAccountsTemplate {
        view: &view,
        accounts: &accounts,
        one_account: false,
        csrf_token: "csrf-marker",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin account access page");
    assert_eq!(
        body.matches("action=\"/admin/accounts/_actions/resend-verification\"")
            .count(),
        2
    );
    assert_eq!(
        body.matches("data-tone=\"danger\">Bounced</span>").count(),
        1
    );
    assert!(body.contains(
        "<span class=\"cw-status cw-status--quiet\" data-tone=\"warning\">Unverified</span> <span class=\"cw-status cw-status--quiet\" data-tone=\"danger\">Bounced</span><form"
    ));
    assert!(body.contains(
        "<span class=\"cw-status cw-status--quiet\" data-tone=\"warning\">Unverified</span><form class=\"cw-access-resend\" method=\"post\" action=\"/admin/accounts/_actions/resend-verification\"><input type=\"hidden\" name=\"_csrf\" value=\"csrf-marker\"><input type=\"hidden\" name=\"user_id\" value=\"user-waiting\"><button class=\"cw-text-action\" type=\"submit\">Resend verification email</button></form>"
    ));
}

/// Suspend is offered on every account but the administrator's own, behind a
/// confirmation that asks why; a suspended account offers only Unsuspend,
/// never Enable (#3297, #4579).
#[test]
fn account_access_offers_suspend_and_unsuspend_behind_a_confirmation() {
    let view = DashboardView {
        account_id: "user-admin".to_owned(),
        user_name: "Admin".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: false,
        support_mailto: String::new(),
        updates_enabled: false,
    };
    let account = |id: &str, suspended: bool, own: bool| AccountAccessView {
        id: id.into(),
        email: format!("{id}@example.test"),
        name: id.into(),
        email_verified: true,
        enabled: !suspended,
        suspended,
        mail_suppressed: "",
        own,
        reason: "Build agents".into(),
        has_reason: true,
        created_at: "2026-11-12T12:00:00".into(),
        identities: Vec::new(),
        deletion: crate::view::AccountDeletionOffer::Offered,
    };
    let accounts = vec![
        account("user-active", false, false),
        account("user-suspended", true, false),
        account("user-admin", false, true),
    ];
    let body = AdminAccountsTemplate {
        view: &view,
        accounts: &accounts,
        one_account: false,
        csrf_token: "csrf-marker",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin account access page");

    // Only the active account that isn't the administrator's can be suspended.
    assert_eq!(
        body.matches("data-dialog-open=\"account-1-suspend\"")
            .count(),
        1
    );
    assert!(!body.contains("account-3-suspend"));
    assert_eq!(
        body.matches("action=\"/admin/accounts/_actions/suspend\"")
            .count(),
        1
    );
    assert!(body.contains(
        "<p>Suspending signs this account out everywhere and disables its API keys. Unsuspending does not bring them back.</p>"
    ));
    assert!(body.contains(
        "<input type=\"hidden\" name=\"user_id\" value=\"user-active\"><div class=\"cw-field\"><label class=\"cw-label\" for=\"account-1-suspend-reason\">Reason</label><textarea class=\"cw-textarea\" id=\"account-1-suspend-reason\" name=\"reason\" rows=\"3\" maxlength=\"2000\" required"
    ));
    assert!(body.contains(
        "<button class=\"cw-button cw-danger-button\" type=\"submit\" form=\"account-1-suspend-form\">Suspend account</button>"
    ));

    // The suspended account says so and offers Unsuspend, not Enable.
    assert!(body.contains(
        "<span class=\"cw-status cw-status--quiet\" data-tone=\"danger\">Suspended</span><button class=\"cw-text-action\" type=\"button\" data-dialog-open=\"account-2-unsuspend\""
    ));
    assert_eq!(
        body.matches("action=\"/admin/accounts/_actions/unsuspend\"")
            .count(),
        1
    );
    assert!(
        body.contains("<input type=\"hidden\" name=\"user_id\" value=\"user-suspended\"></form>")
    );
    assert_eq!(
        body.matches("action=\"/admin/accounts/_actions/enabled\"")
            .count(),
        2
    );
    assert!(body.contains(
        "Nothing the suspension stopped comes back: its Sandboxes stay stopped, its API keys stay disabled and its ports stay creator-only."
    ));
}

#[test]
fn organization_template_escapes_upstream_data() {
    let organizations = vec![OrganizationRow {
        id: "org-safe".into(),
        name: "<unsafe>".into(),
        slug: "safe".into(),
        role: "Owner",
        can_admin: true,
        billing_plan: "trial".into(),
        url: "/safe/".into(),
        joined: String::new(),
        only_owner: false,
    }];
    let body = OrganizationListTemplate {
        organizations: &organizations,
        has_organizations: true,
    }
    .render()
    .expect("render organization fragment");
    assert!(body.contains("&lt;unsafe&gt;") || body.contains("&#60;unsafe&#62;"));
    assert!(!body.contains("<unsafe>"));
}

#[test]
fn organization_form_escapes_preserved_values_and_csrf_token() {
    let form = OrganizationFormView {
        name: "<script>alert('name')</script>".into(),
        slug: "safe-slug".into(),
        slug_error: "<unsafe error>".into(),
        ..Default::default()
    };
    let body = OrganizationFormTemplate {
        form: &form,
        csrf_token: "csrf-token",
    }
    .render()
    .expect("render organization form");

    assert!(body.contains("name=\"_csrf\" value=\"csrf-token\""));
    assert!(body.contains("safe-slug"));
    assert!(!body.contains("<script>"));
    assert!(!body.contains("<unsafe error>"));
}

#[test]
fn organization_form_validation_matches_the_public_contract() {
    for slug in ["acme", "acme-2", "a2b", "123"] {
        assert!(valid_organization_slug(slug), "expected {slug} to be valid");
    }
    for slug in [
        "Acme",
        "-acme",
        "acme-",
        "acme--corp",
        "acme_corp",
        "admin",
        "settings",
        "",
    ] {
        assert!(
            !valid_organization_slug(slug),
            "expected {slug:?} to be invalid"
        );
    }

    let mut form = OrganizationFormView {
        name: String::new(),
        slug: "ab".into(),
        ..Default::default()
    };
    validate_organization_form(&mut form);
    assert_eq!(form.name_error, "Name is required");
    assert_eq!(form.slug_error, "Slug must be between 3 and 48 characters");
}

#[test]
fn typed_bad_request_details_are_mapped_to_form_fields() {
    let detail = BadRequest {
        field_violations: vec![
            codewire_proto::google::rpc::bad_request::FieldViolation {
                field: "/name".into(),
                description: "Choose a name".into(),
                ..Default::default()
            },
            codewire_proto::google::rpc::bad_request::FieldViolation {
                field: "/slug".into(),
                description: "Choose another slug".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let error = ConnectError::invalid_argument("validation failed").with_detail(
        connectrpc::ErrorDetail::from_message("google.rpc.BadRequest", &detail),
    );
    let mut form = OrganizationFormView::default();
    apply_organization_error(&mut form, &error);
    assert_eq!(form.name_error, "Choose a name");
    assert_eq!(form.slug_error, "Choose another slug");
    assert!(form.form_error.is_empty());
}

#[test]
fn organization_conflicts_are_attached_to_the_slug() {
    let error = ConnectError::aborted("organization slug already exists");
    let mut form = OrganizationFormView::default();
    apply_organization_error(&mut form, &error);
    assert_eq!(
        form.slug_error,
        "An organization with this slug already exists"
    );
    assert!(form.form_error.is_empty());
}

#[test]
fn transport_forwards_only_the_canonical_session_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer never-forward"),
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("unrelated=discard"),
    );
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://attacker.test"),
    );
    let headers = browser_headers(
        headers,
        Some(HeaderValue::from_static("codewire.session_token=expected")),
        None,
    );
    assert!(!headers.contains_key(header::AUTHORIZATION));
    assert!(!headers.contains_key(header::ORIGIN));
    assert_eq!(
        headers.get(header::COOKIE).unwrap(),
        "codewire.session_token=expected"
    );
}

#[test]
fn mutation_transport_replaces_origin_and_forwards_only_the_canonical_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://attacker.test"),
    );
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer never-forward"),
    );
    let headers = browser_headers(
        headers,
        Some(HeaderValue::from_static("codewire.session_token=expected")),
        Some(HeaderValue::from_static("https://codewire.test")),
    );
    assert!(!headers.contains_key(header::AUTHORIZATION));
    assert_eq!(
        headers.get(header::ORIGIN).unwrap(),
        "https://codewire.test"
    );
    assert_eq!(
        headers.get(header::COOKIE).unwrap(),
        "codewire.session_token=expected"
    );
}

#[test]
fn auth_continuations_remain_application_relative() {
    for safe in [
        "/dashboard",
        "/organizations/new/",
        "/device?user_code=ABCD-1234#approval",
    ] {
        assert_eq!(safe_auth_continuation(safe), Some(safe));
    }
    for unsafe_target in [
        "https://evil.example/device",
        "//evil.example/device",
        "/\\evil.example/device",
        "/dashboard\nLocation: https://evil.example",
        "device",
    ] {
        assert_eq!(safe_auth_continuation(unsafe_target), None);
    }
}

#[test]
fn auth_redirects_preserve_the_originating_rust_route() {
    let mut headers = HeaderMap::new();
    headers.insert(HTMX_REQUEST, HeaderValue::from_static("true"));
    let response = login_redirect("/organizations/new/", &headers);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("hx-redirect").unwrap(),
        "/login?return_to=%2Forganizations%2Fnew%2F"
    );

    let response = two_factor_redirect("/organizations/new/", &HeaderMap::new());
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/setup-2fa?return_to=%2Forganizations%2Fnew%2F"
    );
}

fn admin_view() -> DashboardView {
    DashboardView {
        user_name: "<unsafe admin>".into(),
        is_admin: true,
        ..Default::default()
    }
}

fn unsafe_organization(has_explicit_quota: bool) -> AdminOrganizationView {
    let limit = |value: i32, display: &str| QuotaLimitView {
        value,
        display: display.into(),
    };
    AdminOrganizationView {
        id: "org_safe-1".into(),
        name: "<script>alert('org')</script>".into(),
        slug: "safe-org".into(),
        created: "2026-10-28".into(),
        members: vec![AdminMemberRow {
            email: "<unsafe@example.test>".into(),
            role: "owner".into(),
            joined: "2026-10-28".into(),
        }],
        billing_plan: "<plan>".into(),
        billing_status: "active".into(),
        billing_exempt: true,
        effective_plan: "unlimited".into(),
        subscriptions: vec![AdminSubscriptionRow {
            kind: "environment".into(),
            plan: "unlimited".into(),
            status: "active".into(),
            updated: "2026-10-28".into(),
        }],
        dedicated_cpu: false,
        rate_card: "Discounted".into(),
        rate_cards: crate::admin_connect::RATE_CARDS
            .iter()
            .map(|(value, label)| crate::admin_connect::RateCardOption {
                value,
                label,
                selected: *value == "discounted",
            })
            .collect(),
        credit_balance: "-$0.003385".into(),
        credit_negative: true,
        credit_balance_nano_eur: -3_385_000,
        auto_top_up_enabled: true,
        auto_top_up_cents: 2000,
        credit_entries: vec![crate::admin_connect::AdminCreditRow {
            kind: "Adjustment".into(),
            amount: "$25.00".into(),
            when: "2026-10-28".into(),
            note: "<script>alert('reason')</script>".into(),
        }],
        has_explicit_quota,
        confidential_environments: Some(false),
        systemd_environments: Some(false),
        standard_runtime: Some(false),
        effective_quota: QuotaView {
            environments: limit(-1, "Unlimited"),
            sandboxes: limit(200, "200"),
            cpu_millicores: limit(400_000, "400 vCPU"),
            memory_mb: limit(1_600_000, "1562.5 GiB"),
        },
        active_environments: 3,
        active_sandboxes: 3,
        used_cpu: "6 vCPU".into(),
        used_memory: "24 GiB".into(),
        api_keys: vec![AdminApiKeyRow {
            name: "</td><script>alert('key')</script>".into(),
            created: "2026-10-28".into(),
            last_used: "Never".into(),
            expires: "Never".into(),
            disabled: false,
        }],
    }
}

#[test]
fn admin_organizations_template_links_each_row_and_escapes_names() {
    let view = admin_view();
    let organizations = AdminOrganizations {
        rows: vec![AdminOrganizationRow {
            name: "<script>alert('org')</script>".into(),
            slug: "safe-org".into(),
            billing_plan: "unlimited".into(),
            billing_status: "active".into(),
            created: "2026-10-28".into(),
            url: "/admin/organizations/org_safe-1/".into(),
            confidential_environments: Some(true),
            sandboxes: Some(OrganizationSandboxes {
                counts: SandboxCountsView {
                    created: 18,
                    running: 9,
                    stopped: 4,
                    failed: 3,
                    deleted: 2,
                },
                last_created: "Nov 20, 2026, 09:30 UTC".into(),
            }),
        }],
        sandbox_totals: Some(SandboxCountsView {
            created: 19,
            running: 9,
            stopped: 4,
            failed: 3,
            deleted: 3,
        }),
    };
    let defaults = unsafe_organization(false).effective_quota;
    let body = AdminOrganizationsTemplate {
        view: &view,
        organizations: &organizations,
        defaults: &defaults,
        csrf_token: "csrf-safe",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin organizations page");
    assert!(!body.contains("<script>"));
    // Each organization is a row group (#6086): its name and slug on one row,
    // the details under the column headings on the next. Both rows open it
    // through its one stretched link.
    assert!(body.contains(r#"<table class="cw-table cw-table--row-groups">"#));
    assert!(body.contains(
        r#"<th scope="rowgroup" colspan="10"><a class="cw-row-link" href="/admin/organizations/org_safe-1/">"#
    ));
    assert_eq!(body.matches(r#"class="cw-row-link""#).count(), 1);
    // The confidential opt-in is a column of state, not a control in the row.
    assert!(body.contains(r#"<th scope="col">Confidential environments</th>"#));
    assert!(body.contains(
        r#"<td><span class="cw-status cw-status--quiet" data-tone="success">Opted in</span></td>"#
    ));
    assert!(!body.contains("_actions/confidential"));
    // The defaults form: labelled, starting at the stored defaults, and
    // saying that the Unlimited rate card has no limits.
    assert!(body.contains(r#"action="/admin/organizations/_actions/defaults/set""#));
    assert!(body.contains(r#"<input type="hidden" name="_csrf" value="csrf-safe">"#));
    assert!(body.contains("Defaults for organizations without their own quota"));
    assert!(body.contains("An organization on the Unlimited rate card has no limits."));
    for (label, name, value) in [
        ("Concurrent environments", "environments", "-1"),
        ("Concurrent sandboxes", "sandboxes", "200"),
        ("CPU (millicores)", "cpu_millicores", "400000"),
        ("Memory (MiB)", "memory_mb", "1600000"),
    ] {
        assert!(
            body.contains(&format!(
                r#"<label class="cw-field"><span>{label}</span><input class="cw-input" type="number" name="{name}" min="-1" step="1" value="{value}" required></label>"#
            )),
            "{name}"
        );
    }
    assert!(body.contains(r#"<th scope="col">Plan</th>"#));
    assert!(body.contains("</a> <code>safe-org</code></th></tr>"));
    assert_eq!(
        body.matches("<th scope=\"col\">").count(),
        10,
        "the headings label the details row only"
    );
    assert!(body.contains(r#"href="/admin/organizations/">Organizations</a>"#));
    // The Sandbox totals across every organization, then each one's (#6086).
    for (label, value) in [
        ("Sandboxes created", 19),
        ("Sandboxes running", 9),
        ("Sandboxes stopped", 4),
        ("Sandboxes failed", 3),
        ("Sandboxes deleted", 3),
    ] {
        assert!(
            body.contains(&format!(
                r#"<article class="cw-admin-stat"><span>{label}</span><strong>{value}</strong></article>"#
            )),
            "{label}"
        );
    }
    assert!(body.contains(
        r#"<th scope="col">Sandboxes created</th><th scope="col">Running</th><th scope="col">Stopped</th><th scope="col">Failed</th><th scope="col">Deleted</th><th scope="col">Last Sandbox</th>"#
    ));
    assert!(body.contains(
        "<td>18</td><td>9</td><td>4</td><td>3</td><td>2</td><td>Nov 20, 2026, 09:30 UTC</td>"
    ));
}

#[test]
fn admin_organizations_template_says_when_the_sandbox_counts_are_unavailable() {
    let view = admin_view();
    let organizations = AdminOrganizations {
        rows: vec![AdminOrganizationRow {
            name: "Example".into(),
            slug: "example".into(),
            billing_plan: "none".into(),
            billing_status: "none".into(),
            created: "2026-10-28".into(),
            url: "/admin/organizations/org_example/".into(),
            confidential_environments: None,
            sandboxes: None,
        }],
        sandbox_totals: None,
    };
    let defaults = unsafe_organization(false).effective_quota;
    let body = AdminOrganizationsTemplate {
        view: &view,
        organizations: &organizations,
        defaults: &defaults,
        csrf_token: "csrf-safe",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin organizations page");
    assert!(body.contains(
        r#"<article class="cw-admin-stat"><span>Sandboxes</span><strong>Unavailable</strong></article>"#
    ));
    assert!(!body.contains("Sandboxes running"));
    assert!(body.contains(r#"<td colspan="6">Unavailable</td>"#));
}

#[test]
fn admin_organization_template_shows_billing_quota_usage_and_escapes_upstream_data() {
    let view = admin_view();
    for has_explicit_quota in [false, true] {
        let organization = unsafe_organization(has_explicit_quota);
        let body = AdminOrganizationTemplate {
            view: &view,
            organization: &organization,
            csrf_token: "csrf-safe",
            credit_key: "credit-key-1",
            credit_confirmation: None,
            message: "",
            error: "",
        }
        .render()
        .expect("render admin organization page");
        assert!(!body.contains("<script>"));
        assert!(!body.contains("<unsafe@example.test>"));
        assert!(!body.contains("<plan>"));
        // Usage against the effective limits, as a description list.
        assert!(body.contains("<dt>Sandboxes</dt><dd>3 <small>of 200</small></dd>"));
        assert!(body.contains("<dt>Environments</dt><dd>3 <small>of Unlimited</small></dd>"));
        assert!(body.contains("<dt>Effective plan</dt><dd>unlimited</dd>"));
        assert!(body.contains("<dt>Billing exempt</dt><dd>Yes</dd>"));
        // Every quota control is labelled and starts at the effective value.
        for (label, name, value) in [
            ("Concurrent environments", "environments", "-1"),
            ("Concurrent sandboxes", "sandboxes", "200"),
            ("CPU (millicores)", "cpu_millicores", "400000"),
            ("Memory (MiB)", "memory_mb", "1600000"),
        ] {
            assert!(
                body.contains(&format!(
                    r#"<label class="cw-field"><span>{label}</span><input class="cw-input" type="number" name="{name}" min="-1" step="1" value="{value}" required></label>"#
                )),
                "{name}"
            );
        }
        assert!(body.contains(r#"action="/admin/organizations/_actions/quota/set""#));
        assert!(
            body.contains(r#"<input type="hidden" name="organization_id" value="org_safe-1">"#)
        );
        // The rate card, starting at the organization's, and the balance.
        assert!(body.contains("<dt>Rate card</dt><dd>Discounted</dd>"));
        assert!(body.contains(
            r#"<dt>Credit balance</dt><dd><span class="cw-badge" data-tone="warning">-$0.003385</span></dd>"#
        ));
        assert!(body.contains(r#"action="/admin/organizations/_actions/rate-card/set""#));
        assert!(body.contains(r#"action="/admin/organizations/_actions/features/set""#));
        assert!(body.contains(
            r#"<select class="cw-select" name="rate_card"><option value="regular">Regular</option><option value="discounted" selected>Discounted</option><option value="unlimited">Unlimited</option></select>"#
        ));
        // The credit form carries its one-time key; the ledger is a table.
        assert!(body.contains(r#"action="/admin/organizations/_actions/credit/adjust""#));
        assert!(
            body.contains(r#"<input type="hidden" name="idempotency_key" value="credit-key-1">"#)
        );
        assert!(body.contains(r#"<label class="cw-field"><span>Reason</span><input class="cw-input" type="text" name="reason" maxlength="500" required></label>"#));
        assert!(body.contains("<tr><th scope=\"row\">Adjustment</th><td>$25.00</td>"));
        assert!(body.contains(r#"<input type="hidden" name="_csrf" value="csrf-safe">"#));
        assert_eq!(
            body.contains(r#"action="/admin/organizations/_actions/quota/clear""#),
            has_explicit_quota
        );
        assert_eq!(
            body.contains("No quota of its own: the defaults apply."),
            !has_explicit_quota
        );
    }
}

/// The organization's switches are one list of checkboxes saved together
/// (#5602): each box starts at its setting and carries the value the page
/// showed, the standard runtime says what it does, and a switch whose state
/// can't be read shows that and posts nothing.
#[test]
fn admin_organization_switches_are_one_checkbox_list_that_follows_each_setting() {
    let view = admin_view();
    let render = |organization: AdminOrganizationView| {
        AdminOrganizationTemplate {
            view: &view,
            organization: &organization,
            csrf_token: "csrf-safe",
            credit_key: "credit-key-1",
            credit_confirmation: None,
            message: "",
            error: "",
        }
        .render()
        .expect("render admin organization page")
    };
    let action = r#"action="/admin/organizations/_actions/features/set""#;
    let form = |html: &str| -> String {
        let start = html.find(action).expect("the settings form");
        html[start..start + html[start..].find("</form>").unwrap()].to_owned()
    };
    let checkbox = |name: &str, label: &str, checked: bool| {
        format!(
            r#"<label class="cw-choice"><input class="cw-checkbox" type="checkbox" name="{name}" value="on"{}> {label}</label>"#,
            if checked { " checked" } else { "" }
        )
    };
    let was = |name: &str, value: bool| {
        format!(r#"<input type="hidden" name="{name}_was" value="{value}">"#)
    };

    for on in [false, true] {
        let html = form(&render(AdminOrganizationView {
            confidential_environments: Some(on),
            systemd_environments: Some(!on),
            standard_runtime: Some(on),
            dedicated_cpu: !on,
            ..unsafe_organization(false)
        }));
        assert!(
            html.contains(r#"<input type="hidden" name="organization_id" value="org_safe-1">"#)
        );
        assert!(
            html.contains(r#"<input type="hidden" name="organization_slug" value="safe-org">"#)
        );
        assert!(html.contains(r#"<input type="hidden" name="_csrf" value="csrf-safe">"#));
        for (name, label, value) in [
            ("confidential", "Confidential environments", on),
            ("systemd", "Systemd workspaces", !on),
            ("standard", "Standard runtime", on),
            ("dedicated_cpu", "Dedicated CPU", !on),
        ] {
            assert!(
                html.contains(&checkbox(name, label, value)),
                "{name} {value}"
            );
            assert!(html.contains(&was(name, value)), "{name} was {value}");
        }
        assert!(html.contains(
            "<p class=\"cw-muted\">New sandboxes run on Codewire's own VM runtime instead of Kata.</p>"
        ));
        assert!(html.contains(r#"<button class="cw-button" type="submit">Save settings</button>"#));
    }

    // A switch whose service can't be read says so, with no box and no
    // value to post; the others are still offered.
    let html = form(&render(AdminOrganizationView {
        confidential_environments: None,
        systemd_environments: None,
        standard_runtime: None,
        ..unsafe_organization(false)
    }));
    for (name, label) in [
        ("confidential", "Confidential environments"),
        ("systemd", "Systemd workspaces"),
        ("standard", "Standard runtime"),
    ] {
        assert!(html.contains(&format!(
            r#"<p>{label} <span class="cw-muted">cannot be read right now</span></p>"#
        )));
        assert!(!html.contains(&format!(r#"name="{name}""#)), "{name}");
        assert!(!html.contains(&format!(r#"name="{name}_was""#)), "{name}");
    }
    assert!(html.contains(r#"name="dedicated_cpu_was""#));
}

/// An adjustment below zero asks first (#4754): the page shows what it sets
/// off and a Confirm that sends the same adjustment with the balance it
/// showed, and no second Adjust form.
#[test]
fn admin_organization_asks_before_a_negative_balance() {
    let view = admin_view();
    let organization = unsafe_organization(false);
    let confirmation = crate::admin_connect::CreditConfirmationView {
        amount: "-6".into(),
        reason: "billing test".into(),
        idempotency_key: "credit-key-1".into(),
        confirmed_balance_nano_eur: -1_140_000_000,
        question: crate::admin_connect::negative_balance_question(
            -1_140_000_000,
            false,
            true,
            2000,
            Some(Some("Visa •••• 4242")),
        ),
    };
    let body = AdminOrganizationTemplate {
        view: &view,
        organization: &organization,
        csrf_token: "csrf-safe",
        credit_key: "credit-key-1",
        credit_confirmation: Some(&confirmation),
        message: "",
        error: "",
    }
    .render()
    .expect("render admin organization page");
    assert!(body.contains(r#"<p class="cw-alert cw-alert--warning" role="alert">This leaves the balance at -$1.14. Automatic top-up is on, so Visa •••• 4242 is charged $20.00 within seconds.</p>"#), "{body}");
    for field in [
        r#"<input type="hidden" name="amount" value="-6">"#,
        r#"<input type="hidden" name="reason" value="billing test">"#,
        r#"<input type="hidden" name="idempotency_key" value="credit-key-1">"#,
        r#"<input type="hidden" name="confirmed_balance" value="-1140000000">"#,
    ] {
        assert!(body.contains(field), "{field}");
    }
    assert!(body.contains(r#"<button class="cw-button" type="submit">Confirm</button>"#));
    assert!(body.contains(&format!(
        r#"href="/admin/organizations/{}/">Go back</a>"#,
        organization.id
    )));
    assert!(!body.contains(">Adjust credit</button>"));
}

/// The question names the card top-up charges, refused work when nothing
/// will be charged, and both outcomes when billing can't say (#5094).
#[test]
fn a_negative_balance_question_says_what_top_up_sets_off() {
    use crate::admin_connect::negative_balance_question;
    let refused = "This leaves the balance at -$1.14. New Sandboxes and starts are refused, and running Sandboxes stop after 24 hours; their storage is kept.";
    assert_eq!(
        negative_balance_question(
            -1_140_000_000,
            false,
            true,
            2000,
            Some(Some("Visa •••• 4242"))
        ),
        "This leaves the balance at -$1.14. Automatic top-up is on, so Visa •••• 4242 is charged $20.00 within seconds."
    );
    // No card, or top-up off: nothing is charged, so work is refused.
    assert_eq!(
        negative_balance_question(-1_140_000_000, false, true, 2000, Some(None)),
        refused
    );
    for card in [Some(Some("Visa •••• 4242")), Some(None), None] {
        assert_eq!(
            negative_balance_question(-1_140_000_000, false, false, 2000, card),
            refused
        );
    }
    // Billing can't say: both outcomes.
    assert!(negative_balance_question(-1, false, true, 5000, None).ends_with(
        "Automatic top-up is on at $50.00, so a saved card is charged within seconds; without one, new Sandboxes and starts are refused."
    ));
    // Unlimited is never charged or refused, whatever top-up and the card say (#6503).
    for (top_up, card) in [
        (true, Some(Some("Visa •••• 0341"))),
        (true, None),
        (false, Some(None)),
    ] {
        assert_eq!(
            negative_balance_question(-11_000_000_000, true, top_up, 2000, card),
            "This leaves the balance at -$11.00. The organization is on Unlimited, so nothing is charged or refused."
        );
    }
}

#[test]
fn admin_overview_shows_the_month_s_cost_in_euros_from_compute_credit() {
    // #5318: the old dollar field is ignored, whatever it holds.
    let stats = crate::admin_connect::stats_view(
        &codewire_admin_proto::codewire::admin::v1::GetStatsResponse {
            active_environments: 2,
            monthly_cpu_hours: 4.0,
            monthly_memory_gb_hours: 8.0,
            monthly_cost_cents: 1_234,
            monthly_usage_nano_eur: 40_000_000,
            ..Default::default()
        },
    );
    let body = crate::templates::AdminOverviewTemplate {
        view: &admin_view(),
        stats: &stats,
    }
    .render()
    .expect("render admin overview page");
    assert!(body.contains("<span>Monthly Cost</span><strong>$0.04</strong>"));
    assert!(body.contains("<span>CPU Hours</span><strong>4.0</strong>"));
    assert!(!body.contains('€'), "a euro sign on Admin → Overview");
}
