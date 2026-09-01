use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let proto_root = manifest_dir.join("proto");
    let authority_proto = proto_root.join("codewire/local/credentials/v1/authority.proto");

    println!("cargo:rerun-if-changed={}", authority_proto.display());

    tonic_prost_build::configure()
        .skip_debug([
            ".codewire.local.credentials.v1.AddCredentialRequest",
            ".codewire.local.credentials.v1.RotateCredentialMaterialRequest",
        ])
        .compile_protos(&[authority_proto], &[proto_root])
        .expect("compile private local credential-authority protobuf types");
}
