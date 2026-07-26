use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let descriptor_set = manifest_dir.join("codewire_descriptor.bin");

    // Every Rust Connect contract is compiled here; add new files to this
    // list as packages grow (docs/dev/PROTO-STYLE.md is the authoring guide).
    let protos = [
        "codewire/admin/v1/admin.proto",
        "codewire/admin/v1/billing_catalog.proto",
        "codewire/console/v1/account.proto",
        "codewire/console/v1/billing.proto",
        "codewire/console/v1/environment_setup.proto",
        "codewire/console/v1/github.proto",
        "codewire/internal/v1/coordinate.proto",
        "codewire/internal/v1/environment_credentials.proto",
        "codewire/internal/v1/gateway_binding.proto",
        "codewire/internal/v1/mesh_authorization.proto",
        "codewire/v1/api_key.proto",
        "codewire/v1/common.proto",
        "codewire/v1/environment.proto",
        "codewire/v1/environment_session.proto",
        "codewire/v1/exec.proto",
        "codewire/v1/file.proto",
        "codewire/v1/mesh_group.proto",
        "codewire/v1/mesh_invite.proto",
        "codewire/v1/mesh_kv.proto",
        "codewire/v1/mesh_network.proto",
        "codewire/v1/mesh_node.proto",
        "codewire/v1/organization.proto",
        "codewire/v1/port.proto",
        "codewire/v1/preset.proto",
        "codewire/v1/secret.proto",
        "codewire/testing/v1/ping.proto",
        "coordinator/v1/coordinator.proto",
        // Vendored google.rpc error-detail types (01 WI-1): typed carriers
        // for Connect error `details` (BadRequest, ErrorInfo, RetryInfo).
        "google/rpc/error_details.proto",
    ];

    // The checked-in descriptor set is generated and drift-checked with the
    // pinned contract toolchain. Rust and image builds consume that exact
    // artifact, so they neither depend on an ambient protoc version nor run
    // contract codegen with an unreviewed compiler.
    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(descriptor_set)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("compile codewire protobuf contracts");
}
