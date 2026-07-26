//! Rust-owned OpenAPI preview for billing routes.
//!
//! This service-local preview records the billing service's Rust DTOs and route
//! metadata for the merged canonical contract without changing runtime
//! handlers.

use std::collections::BTreeMap;

use codewire_api_contract::{Method, OpenApiBuilder, Operation, with_standard_health_routes};
use schemars::JsonSchema;
use serde::Serialize;

use crate::catalog::CatalogResponse;
use crate::catalog_admin::{
    ArchivePlanBody, ArchivePriceBody, CreatePlanBody, CreatePriceBody, MigrationPreviewResponse,
    MigrationRunResponse, PlanWriteBody, PreviewMigrationBody, RunMigrationBody, SuccessResponse,
    UpdatePriceBody, UpdateSettingBody,
};
use crate::checkout_sessions::{
    CheckoutRequest, CheckoutUrlResponse, PortalRequest, PortalUrlResponse, SetupRequest,
};
use crate::org_billing::{BillingEventResponse, InvoiceResponse};
use crate::overview::{BillingOverviewResponse, EnvironmentUsageResponse};
use crate::plans::{OrgPlan, ResourcePlan};

#[derive(Debug, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum PlansResponse {
    Org(BTreeMap<String, OrgPlan>),
    Resource(BTreeMap<String, ResourcePlan>),
}

pub fn rust_openapi_preview() -> serde_json::Value {
    with_standard_health_routes(OpenApiBuilder::new(
        "Codewire Billing Rust API Preview",
        "0.1.0",
    ))
    .operation(
        "/api/v1/admin/billing/catalog",
        Method::Get,
        Operation::new("getAdminBillingCatalog")
            .tag("admin")
            .tag("billing")
            .summary("Get billing catalog")
            .json_response::<CatalogResponse>(200, "OK", "AdminBillingCatalogResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/plans",
        Method::Post,
        Operation::new("createAdminBillingCatalogPlan")
            .tag("admin")
            .tag("billing")
            .summary("Create billing catalog plan")
            .json_request::<CreatePlanBody>("CreateAdminBillingCatalogPlanInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/plans/{resourceType}/{planKey}",
        Method::Put,
        Operation::new("updateAdminBillingCatalogPlan")
            .tag("admin")
            .tag("billing")
            .summary("Update billing catalog plan")
            .path_param("resourceType")
            .path_param("planKey")
            .json_request::<PlanWriteBody>("UpdateAdminBillingCatalogPlanInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/plans/{resourceType}/{planKey}/archive",
        Method::Put,
        Operation::new("setAdminBillingCatalogPlanArchive")
            .tag("admin")
            .tag("billing")
            .summary("Archive or unarchive billing catalog plan")
            .path_param("resourceType")
            .path_param("planKey")
            .json_request::<ArchivePlanBody>("SetAdminBillingCatalogPlanArchiveInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/prices",
        Method::Post,
        Operation::new("createAdminBillingCatalogPrice")
            .tag("admin")
            .tag("billing")
            .summary("Create billing catalog price")
            .json_request::<CreatePriceBody>("CreateAdminBillingCatalogPriceInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/prices/{resourceType}/{planKey}/{stripeMode}/{priceKind}",
        Method::Put,
        Operation::new("updateAdminBillingCatalogPrice")
            .tag("admin")
            .tag("billing")
            .summary("Update billing catalog price")
            .path_param("resourceType")
            .path_param("planKey")
            .path_param("stripeMode")
            .path_param("priceKind")
            .json_request::<UpdatePriceBody>("UpdateAdminBillingCatalogPriceInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/prices/{resourceType}/{planKey}/{stripeMode}/{priceKind}/archive",
        Method::Put,
        Operation::new("setAdminBillingCatalogPriceArchive")
            .tag("admin")
            .tag("billing")
            .summary("Archive or unarchive billing catalog price")
            .path_param("resourceType")
            .path_param("planKey")
            .path_param("stripeMode")
            .path_param("priceKind")
            .json_request::<ArchivePriceBody>("SetAdminBillingCatalogPriceArchiveInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/settings/{settingKey}",
        Method::Put,
        Operation::new("updateAdminBillingCatalogSetting")
            .tag("admin")
            .tag("billing")
            .summary("Update billing catalog setting")
            .path_param("settingKey")
            .json_request::<UpdateSettingBody>("UpdateAdminBillingCatalogSettingInputBody")
            .json_response::<SuccessResponse>(200, "OK", "SuccessResponse"),
    )
    .operation(
        "/api/v1/admin/billing/catalog/subscription-migrations",
        Method::Get,
        Operation::new("listAdminBillingCatalogMigrations")
            .tag("admin")
            .tag("billing")
            .summary("List billing subscription migrations")
            .query_param(
                "limit",
                serde_json::json!({
                    "type": "integer",
                    "format": "int64",
                    "default": 25,
                    "maximum": 100,
                }),
            )
            .json_array_response::<MigrationRunResponse>(
                200,
                "OK",
                "AdminBillingCatalogMigrationRun",
            ),
    )
    .operation(
        "/api/v1/admin/billing/catalog/subscription-migrations",
        Method::Post,
        Operation::new("runAdminBillingCatalogMigration")
            .tag("admin")
            .tag("billing")
            .summary("Run billing subscription migration")
            .json_request::<RunMigrationBody>("RunAdminBillingCatalogMigrationInputBody")
            .json_response::<MigrationRunResponse>(
                200,
                "OK",
                "AdminBillingCatalogMigrationRun",
            ),
    )
    .operation(
        "/api/v1/admin/billing/catalog/subscription-migrations/preview",
        Method::Post,
        Operation::new("previewAdminBillingCatalogMigration")
            .tag("admin")
            .tag("billing")
            .summary("Preview billing subscription migration")
            .json_request::<PreviewMigrationBody>("PreviewAdminBillingCatalogMigrationInputBody")
            .json_response::<MigrationPreviewResponse>(
                200,
                "OK",
                "AdminBillingCatalogMigrationPreview",
            ),
    )
    .operation(
        "/api/v1/billing/plans/{resourceType}",
        Method::Get,
        Operation::new("listPlansForType")
            .tag("billing")
            .summary("List available plans for resource type")
            .path_param("resourceType")
            .json_response::<PlansResponse>(200, "OK", "PlansResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing",
        Method::Get,
        Operation::new("getBillingOverview")
            .tag("billing")
            .summary("Get billing overview for organization")
            .path_param("orgId")
            .json_response::<BillingOverviewResponse>(200, "OK", "BillingOverviewResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing/invoices",
        Method::Get,
        Operation::new("listBillingInvoices")
            .tag("billing")
            .summary("List billing invoices")
            .path_param("orgId")
            .json_array_response::<InvoiceResponse>(200, "OK", "InvoiceResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing/events",
        Method::Get,
        Operation::new("listOrgBillingEvents")
            .tag("billing")
            .summary("List billing activity for organization")
            .path_param("orgId")
            .json_array_response::<BillingEventResponse>(200, "OK", "BillingEventResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/environments/usage",
        Method::Get,
        Operation::new("getEnvironmentUsage")
            .tag("billing")
            .summary("Get environment usage for organization")
            .path_param("orgId")
            .json_response::<EnvironmentUsageResponse>(200, "OK", "EnvironmentUsageResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing/checkout",
        Method::Post,
        Operation::new("createOrgCheckoutSession")
            .tag("billing")
            .summary("Create org checkout session")
            .path_param("orgId")
            .json_request::<CheckoutRequest>("OrgCheckoutRequest")
            .json_response::<CheckoutUrlResponse>(200, "OK", "CheckoutURLResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing/portal",
        Method::Post,
        Operation::new("createPortalSession")
            .tag("billing")
            .summary("Create billing portal session")
            .path_param("orgId")
            .json_request::<PortalRequest>("PortalRequest")
            .json_response::<PortalUrlResponse>(200, "OK", "PortalURLResponse"),
    )
    .operation(
        "/api/v1/organizations/{orgId}/billing/setup",
        Method::Post,
        Operation::new("createBillingSetup")
            .tag("billing")
            .summary("Create billing setup session to add payment method")
            .path_param("orgId")
            .json_request::<SetupRequest>("CreateBillingSetupInputBody")
            .json_response::<CheckoutUrlResponse>(200, "OK", "CheckoutURLResponse"),
    )
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_contains_billing_read_and_session_routes() {
        let doc = rust_openapi_preview();

        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(
            doc["paths"]["/healthz"]["get"]["responses"]["200"]["content"]["text/plain"]["schema"]
                ["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AdminBillingCatalogResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/plans"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/CreateAdminBillingCatalogPlanInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/plans/{resourceType}/{planKey}"]["put"]["parameters"]
                [1]["name"],
            "planKey"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/prices/{resourceType}/{planKey}/{stripeMode}/{priceKind}"]
                ["put"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/UpdateAdminBillingCatalogPriceInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/settings/{settingKey}"]["put"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/UpdateAdminBillingCatalogSettingInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/subscription-migrations"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/AdminBillingCatalogMigrationRun"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/billing/catalog/subscription-migrations/preview"]["post"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/AdminBillingCatalogMigrationPreview"
        );
        assert_eq!(
            doc["paths"]["/api/v1/billing/plans/{resourceType}"]["get"]["parameters"][0]["name"],
            "resourceType"
        );
        assert_eq!(
            doc["paths"]["/api/v1/billing/plans/{resourceType}"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/PlansResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/billing"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/BillingOverviewResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/billing/invoices"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/InvoiceResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/billing/events"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/BillingEventResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/usage"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EnvironmentUsageResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/billing/checkout"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/OrgCheckoutRequest"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/billing/setup"]["post"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/CheckoutURLResponse"
        );
    }

    #[test]
    fn plans_response_schema_replaces_go_empty_schema() {
        let doc = rust_openapi_preview();
        let schema = &doc["components"]["schemas"]["PlansResponse"];

        assert!(schema["anyOf"].is_array());
        assert_eq!(
            doc["components"]["schemas"]["OrgPlan"]["properties"]["display_name"]["type"],
            "string"
        );
        assert!(
            !doc["components"]["schemas"]["OrgPlan"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "archived")
        );
        assert_eq!(
            doc["components"]["schemas"]["ResourcePlan"]["properties"]["included_cpu_hours"]["type"],
            "integer"
        );
        assert!(
            !doc["components"]["schemas"]["ResourcePlan"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "is_admin_only" || field == "archived")
        );
        assert!(
            !doc["components"]["schemas"]["AdminBillingCatalogMigrationSample"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "current_stripe_price_id")
        );
        assert!(
            doc["components"]["schemas"]["AdminBillingCatalogMigrationSample"]["properties"]
                .as_object()
                .unwrap()
                .get("resource_id")
                .is_none()
        );
        assert!(
            doc["components"]["schemas"]["AdminBillingCatalogMigrationSample"]["properties"]
                .as_object()
                .unwrap()
                .get("resource_name")
                .is_none()
        );
    }
}
