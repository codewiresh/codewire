use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let proto_root = manifest_dir.join("proto");
    let authority_proto = proto_root.join("codewire/local/credentials/v1/authority.proto");
    let daemon_proto_root = manifest_dir.join("../../libs/daemon-proto/proto");
    let shared_proto_root = manifest_dir.join("../../proto");
    let bridge_proto = shared_proto_root.join("codewire/bridge/v1/bridge.proto");

    println!("cargo:rerun-if-changed={}", authority_proto.display());
    println!("cargo:rerun-if-changed={}", bridge_proto.display());

    let descriptor_set = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"))
        .join("local_credentials_descriptor.bin");
    let compiled = tonic_prost_build::configure()
        .extern_path(
            ".codewire.bridge.v1",
            "::codewire_daemon_proto::codewire::bridge::v1",
        )
        .file_descriptor_set_path(&descriptor_set)
        .skip_debug(SKIP_DEBUG)
        .compile_protos(
            &[authority_proto],
            &[proto_root, daemon_proto_root, shared_proto_root],
        );
    require_compiled(
        compiled,
        "compile private local credential-authority protobuf types",
    );
    codewire_prost_debug_redact::require_covered(
        &descriptor_set,
        &["codewire/local/credentials/v1/authority.proto"],
        SKIP_DEBUG,
    );
}

/// Messages prost derives no `Debug` for, because they carry credential or
/// secret material: each has a redacting one written by hand (src/control.rs)
/// or none. Every message with a field marked `debug_redact` must be here.
const SKIP_DEBUG: &[&str] = &[
    ".codewire.local.credentials.v1.AddCredentialRequest",
    ".codewire.local.credentials.v1.AddSshCredentialRequest",
    ".codewire.local.credentials.v1.RotateCredentialMaterialRequest",
    ".codewire.local.credentials.v1.SetUserWorkloadSecretRequest",
    ".codewire.local.credentials.v1.SetProjectWorkloadSecretRequest",
    ".codewire.local.credentials.v1.BrokerBootSecret",
    ".codewire.local.credentials.v1.BrokerCredentialRefreshCommitRequest",
    ".codewire.local.credentials.v1.RepositoryCredentialLeaseResponse",
    ".codewire.local.credentials.v1.RevocationCredentialLeaseResponse",
];

/// Reports a missing `protoc` in one line; any other failure keeps its detail.
fn require_compiled(result: std::io::Result<()>, what: &str) {
    let Err(error) = result else { return };
    if error.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
            "error: protoc (the Protocol Buffers compiler) was not found: install it, or set PROTOC to its path"
        );
        std::process::exit(1);
    }
    panic!("{what}: {error}");
}
