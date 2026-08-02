//! Rust-owned black-box wire contract for `codewire-orchestration`.
//!
//! The service-integration and all-up diagnostic harnesses start the real
//! binary, load the deterministic fixture, and run this test over its network
//! listener. The complete scope owns the current Connect, authentication,
//! canonical-error, streaming, and retired-route contract. The runtime
//! scope repeats only the fake-Kubernetes boundary after the harness restarts
//! orchestration without a Kubernetes client.

#[path = "wire_contract/mod.rs"]
mod contract;

use contract::Harness;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the selected orchestration service harness"]
async fn configured_orchestration_wire_contract() {
    let harness = Harness::from_env();
    harness.run().await;
}
