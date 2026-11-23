use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"));
    let descriptor_set = out_dir.join("codewire_descriptor.bin");

    // Customer, console, internal, and infrastructure Rust Connect contracts
    // compile here. Global-administrator contracts are intentionally emitted
    // by `codewire-admin-proto`, so command-line/customer consumers do not
    // build BillingCatalogService.
    let protos = [
        "codewire/bridge/v1/bridge.proto",
        "codewire/console/v1/account.proto",
        "codewire/console/v1/billing.proto",
        "codewire/console/v1/environment_setup.proto",
        "codewire/console/v1/live.proto",
        "codewire/internal/v1/coordinate.proto",
        "codewire/internal/v1/derp_admission.proto",
        "codewire/internal/v1/egress.proto",
        "codewire/internal/v1/environment_mesh.proto",
        "codewire/internal/v1/mesh_authorization.proto",
        "codewire/internal/v1/peer_relay_admission.proto",
        "codewire/internal/v1/workspace_binding.proto",
        "codewire/v1/access_profile.proto",
        "codewire/v1/api_key.proto",
        "codewire/v1/common.proto",
        "codewire/v1/credential.proto",
        "codewire/v1/credential_delegation.proto",
        "codewire/v1/environment.proto",
        "codewire/v1/environment_agent.proto",
        "codewire/v1/environment_cw_runtime.proto",
        "codewire/v1/environment_desktop.proto",
        "codewire/v1/environment_session.proto",
        "codewire/v1/exec.proto",
        "codewire/v1/feedback.proto",
        "codewire/v1/file.proto",
        "codewire/v1/host.proto",
        "codewire/v1/host_agent.proto",
        "codewire/v1/network_policy.proto",
        "codewire/v1/mesh_group.proto",
        "codewire/v1/mesh_invite.proto",
        "codewire/v1/mesh_kv.proto",
        "codewire/v1/mesh_network.proto",
        "codewire/v1/mesh_node.proto",
        "codewire/v1/organization.proto",
        "codewire/v1/port.proto",
        "codewire/v1/preset.proto",
        "codewire/v1/sandbox_identity.proto",
        "codewire/v1/secret.proto",
        "codewire/v1/snapshot.proto",
        "codewire/testing/v1/ping.proto",
        // Vendored google.rpc error-detail types (01 WI-1): typed carriers
        // for Connect error `details` (BadRequest, ErrorInfo, RetryInfo).
        "google/rpc/error_details.proto",
    ];

    // The descriptor set is compiled here, from `proto/`, by a compiler that
    // `Cargo.lock` pins, so no build depends on an ambient protoc or buf and
    // none reads a checked-in binary that every proto change rewrites
    // (#4950). CI holds its output to the pinned buf's.
    //
    // The encoder matters: the typed descriptor form drops options it does
    // not know, `debug_redact` among them, and the generated `Debug` would
    // then print the fields it marks.
    //
    // In the workspace the protos are the repository's `proto/`. A crate from
    // crates.io carries its own copy under `proto/` beside this file, which
    // packaging stages there (`stage-sdk-rust-source.sh`, #3511), so it
    // compiles the same sources. The repository keeps no link
    // here: Flux's checkout of an older commit and the cw runtime source
    // capsule both broke on one.
    let packaged = manifest_dir.join("proto");
    let proto_root = if packaged.is_dir() {
        packaged
    } else {
        manifest_dir.join("../../proto")
    };
    let mut compiler = protox::Compiler::new([proto_root]).expect("open the proto root");
    compiler.include_source_info(true).include_imports(true);
    compiler
        .open_files(protos)
        .expect("compile codewire protobuf contracts");
    // Customer clients must not compile the global-administrator surface,
    // not even through an import.
    assert!(
        compiler
            .files()
            .all(|file| !file.name().starts_with("codewire/admin/")),
        "a customer contract pulls in a global-administrator proto"
    );
    std::fs::write(&descriptor_set, compiler.encode_file_descriptor_set())
        .expect("write the descriptor set");
    let mut redact_marks = 0;
    for file in compiler.files() {
        if let Some(path) = file.path() {
            println!("cargo:rerun-if-changed={}", path.display());
            let source = std::fs::read_to_string(path).expect("read a proto file");
            redact_marks += source.matches("debug_redact = true").count();
        }
    }
    // For the redaction test: a compiler that stops reading the option must
    // not let it pass by finding no field to check.
    println!("cargo:rustc-env=CODEWIRE_PROTO_DEBUG_REDACT_MARKS={redact_marks}");
    println!("cargo:rustc-env=CODEWIRE_PROTO_FILES={}", protos.join(","));

    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(descriptor_set)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .emit_rerun_directives(false)
        .compile()
        .expect("generate codewire protobuf contracts");
}
