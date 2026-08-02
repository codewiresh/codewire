//! Transitional OpenAPI preview for the billing listener.
//!
//! Connect-RPC / Wave 5 / WS13 / WI-S1 removed the listener's
//! control-plane REST contract. Health remains in the transitional OpenAPI
//! document until WI-S2 removes the entire OpenAPI production line.

use codewire_api_contract::{OpenApiBuilder, with_standard_health_routes};

pub fn rust_openapi_preview() -> serde_json::Value {
    with_standard_health_routes(OpenApiBuilder::new(
        "Codewire Billing Rust API Preview",
        "0.1.0",
    ))
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_is_limited_to_standard_health_routes() {
        let doc = rust_openapi_preview();
        let paths = doc["paths"].as_object().expect("paths object");

        assert!(paths.contains_key("/healthz"));
        assert!(paths.contains_key("/readyz"));
        assert_eq!(paths.len(), 2);
    }
}
