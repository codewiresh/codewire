//! Black-box Connect contract for the billing service.
//!
//! The selected service and Kind gates start the real `codewire-billing`
//! binary, load the deterministic fixture, and drive its retained public
//! surface through generated Connect clients. REST parity is intentionally not
//! retained: the two representative former REST paths below must be absent.

use std::env;
use std::time::Duration;

use codewire_admin_proto::codewire::admin::v1::{
    BillingCatalogServiceClient, GetCatalogRequest, ListConfidentialOrganizationsRequest,
    ListSubscriptionMigrationsRequest, SetOrganizationConfidentialEnvironmentsRequest,
};
use codewire_proto::codewire::console::v1::{
    BillingServiceClient, GetBillingOverviewRequest, GetEnvironmentUsageRequest,
    ListBillingEventsRequest, ListInvoicesRequest, ListOrgPlansRequest, ListResourcePlansRequest,
    UpdateAutoTopUpRequest,
};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{CodecFormat, ErrorCode};
use reqwest::header::COOKIE;
use reqwest::{Client, StatusCode};

const SESSION_COOKIE: &str = "codewire.session_token";
const FIXTURE_ORG: &str = "org_contract_1";
const FIXTURE_ORG_SLUG: &str = "contract-org";

struct Harness {
    base_url: String,
    admin_token: String,
    user_token: String,
    skip_health: bool,
    http: Client,
}

impl Harness {
    fn from_env() -> Self {
        assert_eq!(
            required_env("BILLING_SEEDED"),
            "1",
            "BILLING_SEEDED must declare the deterministic fixture"
        );
        Self {
            base_url: trim_url(&required_env("BILLING_BASE_URL")),
            admin_token: required_env("BILLING_ADMIN_SESSION_TOKEN"),
            user_token: required_env("BILLING_USER_SESSION_TOKEN"),
            skip_health: env::var("BILLING_SKIP_HEALTH").as_deref() == Ok("1"),
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("build billing contract HTTP client"),
        }
    }

    fn client_config(&self, token: Option<&str>, codec: CodecFormat) -> ClientConfig {
        let mut config = ClientConfig::new(self.base_url.parse().expect("Connect base URI"))
            .with_codec_format(codec)
            .with_default_timeout(Duration::from_secs(10));
        if let Some(token) = token {
            config = config.with_default_header(COOKIE, format!("{SESSION_COOKIE}={token}"));
        }
        config
    }

    async fn assert_health_and_retired_rest_absent(&self) {
        if !self.skip_health {
            for path in ["/healthz", "/readyz"] {
                let response = self
                    .http
                    .get(format!("{}{path}", self.base_url))
                    .send()
                    .await
                    .unwrap_or_else(|error| panic!("GET {path}: {error}"));
                assert_eq!(response.status(), StatusCode::OK, "GET {path}");
            }
        }

        for path in ["/api/v1/billing/plans/org", "/api/v1/admin/billing/catalog"] {
            let response = self
                .http
                .get(format!("{}{path}", self.base_url))
                .header(COOKIE, format!("{SESSION_COOKIE}={}", self.admin_token))
                .send()
                .await
                .unwrap_or_else(|error| panic!("GET {path}: {error}"));
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "retired {path}");
        }
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required by the selected billing contract"))
}

fn trim_url(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

#[tokio::test]
#[ignore = "requires the selected billing service fixture"]
async fn configured_billing_wire_contract() {
    let harness = Harness::from_env();
    harness.assert_health_and_retired_rest_absent().await;

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let anonymous =
            BillingServiceClient::new(HttpClient::plaintext(), harness.client_config(None, codec));
        let error = anonymous
            .list_org_plans(ListOrgPlansRequest::default())
            .await
            .expect_err("anonymous billing list must be unauthenticated");
        assert_eq!(error.code, ErrorCode::Unauthenticated);

        let billing = BillingServiceClient::new(
            HttpClient::plaintext(),
            harness.client_config(Some(&harness.user_token), codec),
        );
        let org_plans = billing
            .list_org_plans(ListOrgPlansRequest::default())
            .await
            .expect("ListOrgPlans Connect round trip")
            .into_owned();
        assert_eq!(
            org_plans
                .plans
                .get("starter")
                .expect("seeded starter organization plan")
                .display_name,
            "Starter"
        );

        let resource_plans = billing
            .list_resource_plans(ListResourcePlansRequest {
                resource_type: "sandbox".into(),
                ..Default::default()
            })
            .await
            .expect("ListResourcePlans Connect round trip")
            .into_owned();
        assert!(resource_plans.plans.contains_key("standard"));
        assert!(!resource_plans.plans.contains_key("legacy"));

        let overview = billing
            .get_billing_overview(GetBillingOverviewRequest {
                org_id: FIXTURE_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("GetBillingOverview Connect round trip")
            .into_owned();
        assert_eq!(overview.plan, "starter");
        // The fixture organization is on the Regular card, with no credit yet.
        assert!(!overview.unmetered);
        assert_eq!(overview.credit_balance_nano_eur, 0);
        assert_eq!(
            overview
                .rates
                .as_option()
                .expect("rates")
                .cpu_nano_eur_per_vcpu_hour,
            43_800_000
        );

        // Automatic top-up: a member may not change it; the owner may, within
        // EUR 5 to EUR 1,000.
        let top_up = |enabled: bool, amount_cents: i32| UpdateAutoTopUpRequest {
            org_id: FIXTURE_ORG.into(),
            enabled,
            amount_cents,
            ..Default::default()
        };
        let error = billing
            .update_auto_top_up(top_up(false, 1000))
            .await
            .expect_err("a member cannot change automatic top-up");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        let owner = BillingServiceClient::new(
            HttpClient::plaintext(),
            harness.client_config(Some(&harness.admin_token), codec),
        );
        let error = owner
            .update_auto_top_up(top_up(true, 499))
            .await
            .expect_err("a top-up below EUR 5 is invalid");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        for (enabled, amount_cents) in [(false, 1000), (true, 2000)] {
            let updated = owner
                .update_auto_top_up(top_up(enabled, amount_cents))
                .await
                .expect("UpdateAutoTopUp Connect round trip")
                .into_owned();
            assert_eq!(
                (updated.enabled, updated.amount_cents),
                (enabled, amount_cents)
            );
            let overview = owner
                .get_billing_overview(GetBillingOverviewRequest {
                    org_id: FIXTURE_ORG.into(),
                    ..Default::default()
                })
                .await
                .expect("GetBillingOverview Connect round trip")
                .into_owned();
            assert_eq!(
                (overview.auto_top_up_enabled, overview.auto_top_up_cents),
                (enabled, amount_cents)
            );
        }

        let invoices = billing
            .list_invoices(ListInvoicesRequest {
                org_id: FIXTURE_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("ListInvoices Connect round trip")
            .into_owned();
        assert_eq!(invoices.invoices.len(), 2);

        let events = billing
            .list_billing_events(ListBillingEventsRequest {
                org_id: FIXTURE_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("ListBillingEvents Connect round trip")
            .into_owned();
        assert_eq!(events.events.len(), 2);

        let usage = billing
            .get_environment_usage(GetEnvironmentUsageRequest {
                org_id: FIXTURE_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("GetEnvironmentUsage Connect round trip")
            .into_owned();
        assert_eq!(usage.per_environment.len(), 1);

        let catalog_as_user = BillingCatalogServiceClient::new(
            HttpClient::plaintext(),
            harness.client_config(Some(&harness.user_token), codec),
        );
        let error = catalog_as_user
            .get_catalog(GetCatalogRequest::default())
            .await
            .expect_err("non-admin catalog read must be denied");
        assert_eq!(error.code, ErrorCode::PermissionDenied);

        let catalog = BillingCatalogServiceClient::new(
            HttpClient::plaintext(),
            harness.client_config(Some(&harness.admin_token), codec),
        );
        let catalog_response = catalog
            .get_catalog(GetCatalogRequest::default())
            .await
            .expect("GetCatalog Connect round trip")
            .into_owned();
        assert!(
            catalog_response
                .plans
                .iter()
                .any(|plan| plan.resource_type == "org" && plan.plan_key == "starter")
        );

        let error = catalog
            .list_subscription_migrations(ListSubscriptionMigrationsRequest {
                limit: 101,
                ..Default::default()
            })
            .await
            .expect_err("oversized migration page must be invalid_argument");
        assert_eq!(error.code, ErrorCode::InvalidArgument);

        // Confidential environments opt-in (#2497): global-admin only, by
        // slug, and the list shows exactly the opted-in organizations.
        let error = catalog_as_user
            .set_organization_confidential_environments(
                SetOrganizationConfidentialEnvironmentsRequest {
                    organization_slug: FIXTURE_ORG_SLUG.into(),
                    enabled: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("a non-admin cannot opt an organization in");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        let error = catalog
            .set_organization_confidential_environments(
                SetOrganizationConfidentialEnvironmentsRequest {
                    organization_slug: "no-such-organization".into(),
                    enabled: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("an unknown organization is not found");
        assert_eq!(error.code, ErrorCode::NotFound);
        let listed = |enabled: bool| {
            let catalog = &catalog;
            async move {
                let organizations =
                    catalog
                        .list_confidential_organizations(
                            ListConfidentialOrganizationsRequest::default(),
                        )
                        .await
                        .expect("ListConfidentialOrganizations Connect round trip")
                        .into_owned()
                        .organizations;
                assert_eq!(
                    organizations.iter().any(|organization| {
                        organization.organization_id == FIXTURE_ORG
                            && organization.slug == FIXTURE_ORG_SLUG
                    }),
                    enabled
                );
            }
        };
        listed(false).await;
        for enabled in [true, false] {
            let response = catalog
                .set_organization_confidential_environments(
                    SetOrganizationConfidentialEnvironmentsRequest {
                        organization_slug: FIXTURE_ORG_SLUG.into(),
                        enabled,
                        ..Default::default()
                    },
                )
                .await
                .expect("SetOrganizationConfidentialEnvironments Connect round trip")
                .into_owned();
            assert_eq!(response.enabled, enabled);
            assert_eq!(
                response
                    .organization
                    .as_option()
                    .map(|organization| organization.organization_id.as_str()),
                Some(FIXTURE_ORG)
            );
            listed(enabled).await;
        }
    }
}
