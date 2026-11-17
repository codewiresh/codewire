//! Generated Connect-RPC contract types for Codewire global-administrator
//! APIs. This crate owns [`codewire::admin::v1`] and is deliberately separate
//! from the customer contract crate so customer clients do not transitively
//! compile or link administrator-only services.

connectrpc::include_generated!();

/// The descriptor set these contracts are generated from, as this build
/// compiled it from `proto/`. For tests that read the contract itself.
#[doc(hidden)]
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/codewire_admin_descriptor.bin"));

/// The proto files this crate generates from, comma-separated; the set also
/// holds what they import.
#[doc(hidden)]
pub const PROTO_FILES: &str = env!("CODEWIRE_PROTO_FILES");

#[cfg(test)]
mod tests {
    use super::codewire::admin::v1::{
        ADMIN_SERVICE_SERVICE_NAME, BILLING_CATALOG_SERVICE_SERVICE_NAME, GetCatalogResponse,
        GetEnvironmentStartupSummaryRequest, GetStatsResponse, ListAuditLogsRequest, PlanSpec,
    };

    #[test]
    fn the_administrator_descriptor_set_holds_both_administrator_services() {
        let pool = prost_reflect::DescriptorPool::decode(crate::FILE_DESCRIPTOR_SET)
            .expect("decode administrator descriptor");
        for service in [
            ADMIN_SERVICE_SERVICE_NAME,
            BILLING_CATALOG_SERVICE_SERVICE_NAME,
        ] {
            assert!(
                pool.get_service_by_name(service).is_some(),
                "the administrator descriptor omits {service}"
            );
        }
    }

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
