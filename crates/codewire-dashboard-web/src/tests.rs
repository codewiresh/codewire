use askama::Template as _;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use codewire_proto::google::rpc::BadRequest;
use connectrpc::ConnectError;

use crate::{
    admin_connect::AuditLogRow,
    response::{HTMX_REQUEST, login_redirect, safe_auth_continuation, two_factor_redirect},
    templates::{
        AdminAccountsTemplate, AdminAuditTemplate, OrganizationFormTemplate,
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
        user_name: "<unsafe admin>".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        show_checklist: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        global_context_query: String::new(),
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
fn admin_accounts_template_escapes_access_request_fields() {
    let view = DashboardView {
        user_name: "Admin".into(),
        csrf_token: Default::default(),
        is_admin: true,
        organizations: Vec::new(),
        has_organizations: false,
        organization_navigation_unavailable: false,
        show_checklist: false,
        new_organization_url: "/organizations/new/".into(),
        settings_url: "/settings/".into(),
        global_context_query: String::new(),
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
