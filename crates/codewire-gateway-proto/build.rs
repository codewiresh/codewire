use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let gateway_proto_root = manifest_dir.join("../../libs/gateway-proto/proto");
    let shared_proto_root = manifest_dir.join("../../proto");
    let bridge_proto = shared_proto_root.join("codewire/bridge/v1/bridge.proto");
    let daemon_proto = gateway_proto_root.join("daemon/v1/daemon.proto");
    let broker_proto = gateway_proto_root.join("broker/v1/broker.proto");

    println!("cargo:rerun-if-changed={}", bridge_proto.display());
    println!("cargo:rerun-if-changed={}", daemon_proto.display());
    println!("cargo:rerun-if-changed={}", broker_proto.display());

    tonic_prost_build::configure()
        .skip_debug([
            ".codewire.bridge.v1.CredentialSshSignRequest",
            ".codewire.bridge.v1.CredentialSshSignature",
        ])
        .compile_protos(
            &[bridge_proto, daemon_proto, broker_proto],
            &[gateway_proto_root, shared_proto_root],
        )
        .expect("compile gateway protobuf types");
}
