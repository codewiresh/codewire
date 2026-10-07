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

    tonic_prost_build::configure()
        .extern_path(
            ".codewire.bridge.v1",
            "::codewire_daemon_proto::codewire::bridge::v1",
        )
        .skip_debug([
            ".codewire.local.credentials.v1.AddCredentialRequest",
            ".codewire.local.credentials.v1.AddSshCredentialRequest",
            ".codewire.local.credentials.v1.RotateCredentialMaterialRequest",
            ".codewire.local.credentials.v1.SetUserWorkloadSecretRequest",
            ".codewire.local.credentials.v1.SetProjectWorkloadSecretRequest",
        ])
        .compile_protos(
            &[authority_proto],
            &[proto_root, daemon_proto_root, shared_proto_root],
        )
        .expect("compile private local credential-authority protobuf types");
}
