use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let descriptor_set = manifest_dir.join("codewire_admin_descriptor.bin");

    // Global-administrator contracts intentionally compile in their own
    // descriptor boundary. Customer-facing clients (in particular `cw`) must
    // not build or link BillingCatalogService just to use EnvironmentService.
    let protos = [
        "codewire/admin/v1/admin.proto",
        "codewire/admin/v1/billing_catalog.proto",
    ];

    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(descriptor_set)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("compile Codewire administrator protobuf contracts");
}
