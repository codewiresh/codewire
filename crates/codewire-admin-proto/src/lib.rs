//! Generated Connect-RPC contract types for Codewire global-administrator
//! APIs. This crate owns [`codewire::admin::v1`] and is deliberately separate
//! from the customer contract crate so customer clients do not transitively
//! compile or link administrator-only services.

connectrpc::include_generated!();

#[cfg(test)]
mod tests {
    use super::codewire::admin::v1::{
        ADMIN_SERVICE_SERVICE_NAME, BILLING_CATALOG_SERVICE_SERVICE_NAME, GetCatalogResponse,
        GetEnvironmentStartupSummaryRequest, GetStatsResponse, ListAuditLogsRequest, PlanSpec,
    };

    #[test]
    fn admin_proto_json_surface_and_typed_window_are_pinned() {
        assert_eq!(ADMIN_SERVICE_SERVICE_NAME, "codewire.admin.v1.AdminService");

        let stats = GetStatsResponse {
            monthly_cost_cents: 1_234,
            ..Default::default()
        };
        let json = serde_json::to_value(stats).expect("admin stats proto3 JSON");
        assert_eq!(json["monthlyCostCents"], "1234");
        assert!(json.get("monthly_cost_cents").is_none());

        let filters = ListAuditLogsRequest {
            limit: 50,
            action: "contract.audit.fixture".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(filters).expect("admin filters proto3 JSON");
        assert_eq!(json["limit"], 50);
        assert_eq!(json["action"], "contract.audit.fixture");

        let summary = GetEnvironmentStartupSummaryRequest {
            window: Some(buffa_types::Duration::from_secs(300)).into(),
            ..Default::default()
        };
        let json = serde_json::to_value(summary).expect("admin window proto3 JSON");
        assert_eq!(json["window"], "300s");
    }

    #[test]
    fn billing_catalog_proto_json_surface_and_fractional_rates_are_pinned() {
        assert_eq!(
            BILLING_CATALOG_SERVICE_SERVICE_NAME,
            "codewire.admin.v1.BillingCatalogService"
        );

        let plan = PlanSpec {
            display_name: "Standard".into(),
            cpu_overage_cents: 0.5,
            mem_overage_cents: 0.25,
            disk_overage_cents: 0.125,
            ..Default::default()
        };
        let json = serde_json::to_value(plan).expect("billing catalog proto3 JSON");
        assert_eq!(json["displayName"], "Standard");
        assert_eq!(json["cpuOverageCents"], 0.5);
        assert_eq!(json["memOverageCents"], 0.25);
        assert_eq!(json["diskOverageCents"], 0.125);
        assert!(
            json.get("cpu_overage_cents").is_none(),
            "unexpected JSON: {json}"
        );

        let catalog = serde_json::to_value(GetCatalogResponse::default())
            .expect("billing catalog repeated JSON serialization");
        for field in ["plans", "prices", "settings"] {
            assert_ne!(catalog.get(field), Some(&serde_json::Value::Null));
        }
    }
}
