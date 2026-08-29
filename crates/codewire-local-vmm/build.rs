use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let proto_root = manifest_dir.join("proto");
    let control_proto = proto_root.join("codewire/local/v1/control.proto");

    println!("cargo:rerun-if-changed={}", control_proto.display());

    tonic_prost_build::configure()
        .compile_protos(&[control_proto], &[proto_root])
        .expect("compile private local runtime protobuf types");
}
