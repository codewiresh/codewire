use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let proto_root = manifest_dir.join("../../libs/gateway-proto/proto");
    let daemon_proto = proto_root.join("daemon/v1/daemon.proto");
    let broker_proto = proto_root.join("broker/v1/broker.proto");

    println!("cargo:rerun-if-changed={}", daemon_proto.display());
    println!("cargo:rerun-if-changed={}", broker_proto.display());

    tonic_prost_build::configure()
        .compile_protos(&[daemon_proto, broker_proto], &[proto_root])
        .expect("compile gateway protobuf types");
}
