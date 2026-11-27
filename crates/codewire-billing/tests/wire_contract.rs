//! Black-box Connect contract for the billing service.
//!
//! The selected service and Kind gates start the real `codewire-billing`
//! binary, load the deterministic fixture, and drive its retained public
//! surface through generated Connect clients. REST parity is intentionally not
//! retained: the two representative former REST paths below must be absent.
//!
//! The no-credential test builds billing's mounts in process, as the binary
//! does, and needs no fixture; with `DATABASE_URL` it also reads the rates.

use std::collections::BTreeSet;
use std::env;
use std::time::Duration;

use codewire_admin_proto::codewire::admin::v1::{
    BillingCatalogServiceClient, GetCatalogRequest, GetOrganizationDefaultCardRequest,
    ListConfidentialOrganizationsRequest, ListRateCardsRequest, ListSubscriptionMigrationsRequest,
    ListSystemdOrganizationsRequest, SetOrganizationConfidentialEnvironmentsRequest,
    SetOrganizationSystemdEnvironmentsRequest, UpdateRateCardRequest,
};
use codewire_billing::cards::CardSetupAddressKey;
use codewire_billing::checkout_sessions::FrontendOrigin;
use codewire_billing::email::EmailClient;
use codewire_billing::routes::BillingState;
use codewire_billing::stripe_client::StripeHandle;
use codewire_proto::codewire::console::v1::{
    BillingServiceClient, GetBillingOverviewRequest, GetEnvironmentUsageRequest,
    GetPublicRatesRequest, ListBillingEventsRequest, ListInvoicesRequest, ListOrgPlansRequest,
    ListResourcePlansRequest, UpdateAutoTopUpRequest,
};
use codewire_server_core::auth::AuthState;
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::{CodecFormat, ErrorCode};
use prost::Message as _;
use prost_types::FileDescriptorSet;
use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE};
use reqwest::{Client, StatusCode};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// How long these tests wait for the service under test: a hang guard, not a
/// speed expectation (docs/dev/AGENT-WORKFLOW.md "Failure convergence"). The
/// rejections they check are immediate server checks; on a loaded service lane
/// a 10-15 s client deadline fired first (#4315).
const SERVICE_HANG_GUARD: Duration = Duration::from_secs(120);
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
                .timeout(SERVICE_HANG_GUARD)
                .build()
                .expect("build billing contract HTTP client"),
        }
    }

    fn client_config(&self, token: Option<&str>, codec: CodecFormat) -> ClientConfig {
        let mut config = ClientConfig::new(self.base_url.parse().expect("Connect base URI"))
            .with_codec_format(codec)
            .with_default_timeout(SERVICE_HANG_GUARD);
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
            50_000_000
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

        assert_organization_opt_ins(&catalog, &catalog_as_user).await;

        // An organization's default card, for the admin credit question
        // (#5094): global-admin only, and none for the fixture, which has no
        // card in Stripe.
        let card_request = || GetOrganizationDefaultCardRequest {
            organization_id: FIXTURE_ORG.into(),
            ..Default::default()
        };
        let error = catalog_as_user
            .get_organization_default_card(card_request())
            .await
            .expect_err("a non-admin cannot read an organization's card");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        let card = catalog
            .get_organization_default_card(card_request())
            .await
            .expect("GetOrganizationDefaultCard Connect round trip")
            .into_owned();
        assert!(card.card.as_option().is_none());

        // Rate cards (#5782): only a global admin reads or changes a price.
        let error = catalog_as_user
            .list_rate_cards(ListRateCardsRequest::default())
            .await
            .expect_err("a non-admin cannot list the rate cards");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        let error = catalog_as_user
            .update_rate_card(UpdateRateCardRequest {
                rate_card: "regular".into(),
                ..Default::default()
            })
            .await
            .expect_err("a non-admin cannot change a rate card");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }
}

/// The confidential (#2497) and systemd (#5638) environment opt-ins, through
/// the global admin `catalog` and the member `catalog_as_user`.
async fn assert_organization_opt_ins(
    catalog: &BillingCatalogServiceClient<HttpClient>,
    catalog_as_user: &BillingCatalogServiceClient<HttpClient>,
) {
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
            let organizations = catalog
                .list_confidential_organizations(ListConfidentialOrganizationsRequest::default())
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

    // Systemd environments opt-in (#5638): global-admin only for both
    // calls, by slug, and the list shows exactly the opted-in
    // organizations.
    let error = catalog_as_user
        .set_organization_systemd_environments(SetOrganizationSystemdEnvironmentsRequest {
            organization_slug: FIXTURE_ORG_SLUG.into(),
            enabled: true,
            ..Default::default()
        })
        .await
        .expect_err("a non-admin cannot opt an organization in");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let error = catalog_as_user
        .list_systemd_organizations(ListSystemdOrganizationsRequest::default())
        .await
        .expect_err("a non-admin cannot list the opted-in organizations");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let error = catalog
        .set_organization_systemd_environments(SetOrganizationSystemdEnvironmentsRequest {
            organization_slug: "no-such-organization".into(),
            enabled: true,
            ..Default::default()
        })
        .await
        .expect_err("an unknown organization is not found");
    assert_eq!(error.code, ErrorCode::NotFound);
    let listed_systemd = |enabled: bool| {
        let catalog = &catalog;
        async move {
            let organizations = catalog
                .list_systemd_organizations(ListSystemdOrganizationsRequest::default())
                .await
                .expect("ListSystemdOrganizations Connect round trip")
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
    listed_systemd(false).await;
    for enabled in [true, false] {
        let response = catalog
            .set_organization_systemd_environments(SetOrganizationSystemdEnvironmentsRequest {
                organization_slug: FIXTURE_ORG_SLUG.into(),
                enabled,
                ..Default::default()
            })
            .await
            .expect("SetOrganizationSystemdEnvironments Connect round trip")
            .into_owned();
        assert_eq!(response.enabled, enabled);
        assert_eq!(
            response
                .organization
                .as_option()
                .map(|organization| organization.organization_id.as_str()),
            Some(FIXTURE_ORG)
        );
        listed_systemd(enabled).await;
    }
}

/// The only methods billing answers without a credential: the signed-out
/// pricing page reads both. Any other is refused.
const ANSWERED_WITHOUT_A_CREDENTIAL: [&str; 2] = [
    "/codewire.console.v1.BillingService/GetSignupCredit",
    "/codewire.console.v1.BillingService/GetPublicRates",
];

/// Every Connect service billing serves.
const BILLING_SERVICES: [&str; 2] = [
    "codewire.admin.v1.BillingCatalogService",
    "codewire.console.v1.BillingService",
];

/// Each method of `BILLING_SERVICES` as its Connect path, read from the
/// generated descriptor sets, so a method added later is covered too.
fn billing_methods() -> BTreeSet<String> {
    let mut methods = BTreeSet::new();
    let mut found = BTreeSet::new();
    for encoded in [
        codewire_proto::FILE_DESCRIPTOR_SET,
        codewire_admin_proto::FILE_DESCRIPTOR_SET,
    ] {
        let set = FileDescriptorSet::decode(encoded).expect("decode a descriptor set");
        for file in &set.file {
            for service in &file.service {
                let name = format!("{}.{}", file.package(), service.name());
                if BILLING_SERVICES.contains(&name.as_str()) {
                    methods.extend(
                        service
                            .method
                            .iter()
                            .map(|method| format!("/{name}/{}", method.name())),
                    );
                    found.insert(name);
                }
            }
        }
    }
    assert_eq!(
        found,
        BILLING_SERVICES.map(String::from).into(),
        "every billing service is described"
    );
    methods
}

/// Serves billing's Connect mounts and raw routes as the binary builds them,
/// on a local port, and returns its base URL.
async fn serve_billing(pool: PgPool) -> String {
    let state = BillingState {
        pool: pool.clone(),
        stripe: StripeHandle::default(),
        email: EmailClient::disabled(),
        credit_enforcement: Default::default(),
        receipts: Default::default(),
        frontend_origin: FrontendOrigin::parse("https://app.codewire.test")
            .expect("the test frontend origin"),
        operator_email: None,
        card_setup_address_key: CardSetupAddressKey::for_test("wire-contract"),
    };
    let app = codewire_billing::connect::mount(
        codewire_billing::routes::api_builder(),
        state.clone(),
        AuthState { pool },
    )
    .with_routes(codewire_billing::router(state))
    .into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a local port");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("the local address")
    );
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    base_url
}

/// Without a credential billing answers `GetPublicRates` with Regular's rates
/// and refuses every method of its Connect services but its two public reads,
/// so its public allowlist makes nothing else public (#5782).
#[tokio::test]
async fn without_a_credential_billing_answers_only_its_public_reads() {
    let database_url = env::var("DATABASE_URL").ok().filter(|url| !url.is_empty());
    let pool = match &database_url {
        Some(url) => PgPoolOptions::new()
            .max_connections(2)
            .connect(url)
            .await
            .expect("connect the billing test database"),
        // Never connected: a refusal needs no database, and a method that
        // reached its handler fails rather than answers.
        None => PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://codewire@127.0.0.1:1/codewire")
            .expect("a lazy pool"),
    };
    let base_url = serve_billing(pool.clone()).await;
    let http = Client::builder()
        .timeout(SERVICE_HANG_GUARD)
        .build()
        .expect("build billing mount HTTP client");

    let methods = billing_methods();
    for path in ANSWERED_WITHOUT_A_CREDENTIAL {
        assert!(methods.contains(path), "{path} is a billing method");
    }
    for path in methods
        .iter()
        .filter(|path| !ANSWERED_WITHOUT_A_CREDENTIAL.contains(&path.as_str()))
    {
        let response = http
            .post(format!("{base_url}{path}"))
            .header(CONTENT_TYPE, "application/proto")
            .send()
            .await
            .unwrap_or_else(|error| panic!("POST {path}: {error}"));
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_else(|error| {
            panic!("{path} answered {status} without a Connect error: {error}")
        });
        assert!(
            matches!(
                body["code"].as_str(),
                Some("unauthenticated" | "permission_denied" | "not_found")
            ),
            "{path} without a credential: {status} {body}"
        );
    }

    if database_url.is_none() {
        eprintln!("DATABASE_URL unset; skipping GetPublicRates' answer");
        return;
    }
    let (cpu, memory, disk, parked): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT cpu_nano_eur_per_vcpu_hour, memory_nano_eur_per_gib_hour, \
                disk_nano_eur_per_gib_hour, parked_storage_nano_eur_per_gib_hour \
           FROM billing_rate_cards WHERE rate_card = 'regular'",
    )
    .fetch_one(&pool)
    .await
    .expect("read Regular's rates");
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let config = ClientConfig::new(base_url.parse().expect("Connect base URI"))
            .with_codec_format(codec)
            .with_default_timeout(SERVICE_HANG_GUARD);
        let rates = BillingServiceClient::new(HttpClient::plaintext(), config)
            .get_public_rates(GetPublicRatesRequest::default())
            .await
            .expect("GetPublicRates without a credential")
            .into_owned();
        assert_eq!(
            (
                rates.cpu_nano_eur_per_vcpu_hour,
                rates.memory_nano_eur_per_gib_hour,
                rates.disk_nano_eur_per_gib_hour,
                rates.parked_storage_nano_eur_per_gib_hour,
            ),
            (cpu, memory, disk, parked)
        );
    }
    let response = http
        .post(format!(
            "{base_url}/codewire.console.v1.BillingService/GetPublicRates"
        ))
        .header(CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .expect("POST GetPublicRates");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
}
