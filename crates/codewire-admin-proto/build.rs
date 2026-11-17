use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"));
    let descriptor_set = out_dir.join("codewire_admin_descriptor.bin");

    // Global-administrator contracts intentionally compile in their own
    // descriptor boundary. Customer-facing clients (in particular `cw`) must
    // not build or link BillingCatalogService just to use EnvironmentService.
    let protos = [
        "codewire/admin/v1/admin.proto",
        "codewire/admin/v1/billing_catalog.proto",
    ];

    // The descriptor set is compiled here, from `proto/`, by a compiler that
    // `Cargo.lock` pins, so no build depends on an ambient protoc or buf and
    // none reads a checked-in binary that every proto change rewrites
    // (#4950). CI holds its output to the pinned buf's.
    //
    // The encoder matters: the typed descriptor form drops options it does
    // not know, `debug_redact` among them, and the generated `Debug` would
    // then print the fields it marks.
    let mut compiler =
        protox::Compiler::new([manifest_dir.join("../../proto")]).expect("open the proto root");
    compiler.include_source_info(true).include_imports(true);
    compiler
        .open_files(protos)
        .expect("compile Codewire administrator protobuf contracts");
    std::fs::write(&descriptor_set, compiler.encode_file_descriptor_set())
        .expect("write the descriptor set");
    for file in compiler.files() {
        if let Some(path) = file.path() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rustc-env=CODEWIRE_PROTO_FILES={}", protos.join(","));

    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(descriptor_set)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .emit_rerun_directives(false)
        .compile()
        .expect("generate Codewire administrator protobuf contracts");
}
