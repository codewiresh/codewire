use askama::Template as _;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use codewire_proto::google::rpc::BadRequest;
use connectrpc::ConnectError;

use crate::{
    admin_connect::{
        AdminApiKeyRow, AdminMemberRow, AdminOrganizationRow, AdminOrganizationView,
        AdminSubscriptionRow, AuditLogRow, QuotaLimitView, QuotaView,
    },
    response::{HTMX_REQUEST, login_redirect, safe_auth_continuation, two_factor_redirect},
    templates::{
        AdminAccountsTemplate, AdminAuditTemplate, AdminOrganizationTemplate,
        AdminOrganizationsTemplate, OrganizationFormTemplate, OrganizationListTemplate,
        SetupTwoFactorTemplate, TwoFactorRecoveryTemplate,
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
    };
    let accounts = vec![AccountAccessView {
        id: "user-safe".into(),
        email: "<unsafe@example.test>".into(),
        name: "<script>alert('name')</script>".into(),
        email_verified: true,
        enabled: false,
        reason: "</td><script>alert('reason')</script>".into(),
        has_reason: true,
        created_at: "2026-09-08T12:00:00".into(),
        identities: vec![crate::view::LinkedIdentityView {
            provider: "GitHub",
            subject: "583231".into(),
            account: "<script>alert('login')</script>".into(),
            linked_at: "2026-11-12T09:30:00".into(),
        }],
    }];
    let body = AdminAccountsTemplate {
        view: &view,
        accounts: &accounts,
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
    };
    let account = |id: &str, email_verified: bool| AccountAccessView {
        id: id.into(),
        email: format!("{id}@example.test"),
        name: id.into(),
        email_verified,
        enabled: false,
        reason: "Build agents".into(),
        has_reason: true,
        created_at: "2026-11-12T12:00:00".into(),
        identities: Vec::new(),
    };
    let accounts = vec![
        account("user-waiting", false),
        account("user-verified", true),
    ];
    let body = AdminAccountsTemplate {
        view: &view,
        accounts: &accounts,
        csrf_token: "csrf-marker",
        message: "",
        error: "",
    }
    .render()
    .expect("render admin account access page");
    assert_eq!(
        body.matches("action=\"/admin/accounts/_actions/resend-verification\"")
            .count(),
        1
    );
    assert!(body.contains(
        "<span class=\"cw-badge\" data-tone=\"warning\">Unverified</span><form class=\"cw-access-resend\" method=\"post\" action=\"/admin/accounts/_actions/resend-verification\"><input type=\"hidden\" name=\"_csrf\" value=\"csrf-marker\"><input type=\"hidden\" name=\"user_id\" value=\"user-waiting\"><button class=\"cw-button cw-button--outline cw-button--pill cw-button--small\" type=\"submit\">Resend verification email</button></form>"
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
        credit_balance: "-€0.003385".into(),
        credit_negative: true,
        credit_entries: vec![crate::admin_connect::AdminCreditRow {
            kind: "Adjustment".into(),
            amount: "€25.00".into(),
            when: "2026-10-28".into(),
            note: "<script>alert('reason')</script>".into(),
        }],
        has_explicit_quota,
        confidential_environments: Some(false),
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
    let organizations = vec![AdminOrganizationRow {
        name: "<script>alert('org')</script>".into(),
        slug: "safe-org".into(),
        billing_plan: "unlimited".into(),
        billing_status: "active".into(),
        created: "2026-10-28".into(),
        url: "/admin/organizations/org_safe-1/".into(),
        confidential_environments: Some(true),
    }];
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
    // The whole row opens the organization through its one stretched link.
    assert!(body.contains(r#"<table class="cw-table cw-table--row-links">"#));
    assert!(body.contains(
        r#"<th scope="row"><a class="cw-row-link" href="/admin/organizations/org_safe-1/">"#
    ));
    assert_eq!(body.matches(r#"class="cw-row-link""#).count(), 1);
    // The confidential opt-in is a column of state, not a control in the row.
    assert!(body.contains(r#"<th scope="col">Confidential environments</th>"#));
    assert!(
        body.contains(r#"<td><span class="cw-badge" data-tone="success">Opted in</span></td>"#)
    );
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
    assert!(body.contains(r#"<th scope="row">"#));
    assert!(body.contains(r#"href="/admin/organizations/">Organizations</a>"#));
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
            r#"<dt>Credit balance</dt><dd><span class="cw-badge" data-tone="warning">-€0.003385</span></dd>"#
        ));
        assert!(body.contains(r#"action="/admin/organizations/_actions/rate-card/set""#));
        assert!(body.contains(r#"action="/admin/organizations/_actions/dedicated-cpu/set""#));
        assert!(body.contains(
            r#"<select class="cw-select" name="rate_card"><option value="regular">Regular</option><option value="discounted" selected>Discounted</option><option value="unlimited">Unlimited</option></select>"#
        ));
        // The credit form carries its one-time key; the ledger is a table.
        assert!(body.contains(r#"action="/admin/organizations/_actions/credit/adjust""#));
        assert!(
            body.contains(r#"<input type="hidden" name="idempotency_key" value="credit-key-1">"#)
        );
        assert!(body.contains(r#"<label class="cw-field"><span>Reason</span><input class="cw-input" type="text" name="reason" maxlength="500" required></label>"#));
        assert!(body.contains("<tr><th scope=\"row\">Adjustment</th><td>€25.00</td>"));
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

/// Dedicated CPU is one button whose verb follows the state, posting the
/// opposite state (#3635).
#[test]
fn admin_organization_dedicated_cpu_toggle_follows_the_setting() {
    let view = admin_view();
    let render = |dedicated_cpu: bool| {
        let organization = AdminOrganizationView {
            dedicated_cpu,
            ..unsafe_organization(false)
        };
        AdminOrganizationTemplate {
            view: &view,
            organization: &organization,
            csrf_token: "csrf-safe",
            credit_key: "credit-key-1",
            message: "",
            error: "",
        }
        .render()
        .expect("render admin organization page")
    };
    let shared = render(false);
    assert!(shared.contains(r#"<p>CPU reservation <span class="cw-badge">Shared</span></p>"#));
    assert!(shared.contains(r#"<input type="hidden" name="dedicated_cpu" value="true">"#));
    assert!(shared.contains(">Give dedicated CPU</button>"));
    assert!(!shared.contains(">Return to shared CPU</button>"));
    let dedicated = render(true);
    assert!(dedicated.contains(
        r#"<p>CPU reservation <span class="cw-badge" data-tone="info">Dedicated</span></p>"#
    ));
    assert!(dedicated.contains(r#"<input type="hidden" name="dedicated_cpu" value="false">"#));
    assert!(dedicated.contains(">Return to shared CPU</button>"));
    assert!(!dedicated.contains(">Give dedicated CPU</button>"));
}

/// The confidential opt-in is one button whose verb follows the state, posting
/// the opposite state with the organization's id and slug; while billing
/// cannot say, the page says so and offers no button (#2497).
#[test]
fn admin_organization_confidential_toggle_follows_the_opt_in() {
    let view = admin_view();
    let render = |confidential_environments: Option<bool>| {
        let organization = AdminOrganizationView {
            confidential_environments,
            ..unsafe_organization(false)
        };
        AdminOrganizationTemplate {
            view: &view,
            organization: &organization,
            csrf_token: "csrf-safe",
            credit_key: "credit-key-1",
            message: "",
            error: "",
        }
        .render()
        .expect("render admin organization page")
    };
    let action = r#"action="/admin/organizations/_actions/confidential/set""#;
    let ids = r#"<input type="hidden" name="organization_id" value="org_safe-1">
                <input type="hidden" name="organization_slug" value="safe-org">"#;

    let off = render(Some(false));
    assert!(
        off.contains(r#"<ul class="cw-organization-settings" aria-label="Organization settings">"#)
    );
    assert!(!off.contains("confidential-heading"));
    assert!(off.contains(action) && off.contains(ids));
    assert!(off.contains(r#"<input type="hidden" name="enabled" value="true">"#));
    assert!(off.contains(
        r#"<p>Confidential environments <span class="cw-badge">Not opted in</span></p>"#
    ));
    assert!(off.contains(
        r#"<button class="cw-button cw-button--outline" type="submit"><span>Opt in</span><span class="cw-sr-only"> to confidential environments</span></button>"#
    ));

    let on = render(Some(true));
    assert!(on.contains(action) && on.contains(ids));
    assert!(on.contains(r#"<input type="hidden" name="enabled" value="false">"#));
    assert!(on.contains(r#"<p>Confidential environments <span class="cw-badge" data-tone="success">Opted in</span></p>"#));
    assert!(on.contains(
        r#"<button class="cw-button cw-button--outline" type="submit"><span>Remove opt-in</span><span class="cw-sr-only"> for confidential environments</span></button>"#
    ));

    let unknown = render(None);
    assert!(!unknown.contains(action));
    assert!(unknown.contains(
        r#"<p>Confidential environments <span class="cw-muted">cannot be read right now</span></p>"#
    ));
}
