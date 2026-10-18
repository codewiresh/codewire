use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let daemon_proto_root = manifest_dir.join("../../libs/daemon-proto/proto");
    let shared_proto_root = manifest_dir.join("../../proto");
    let bridge_proto = shared_proto_root.join("codewire/bridge/v1/bridge.proto");
    let daemon_proto = daemon_proto_root.join("daemon/v1/daemon.proto");
    let broker_proto = daemon_proto_root.join("broker/v1/broker.proto");

    println!("cargo:rerun-if-changed={}", bridge_proto.display());
    println!("cargo:rerun-if-changed={}", daemon_proto.display());
    println!("cargo:rerun-if-changed={}", broker_proto.display());

    let compiled = tonic_prost_build::configure()
        .skip_debug([
            ".codewire.bridge.v1.CredentialSshSignRequest",
            ".codewire.bridge.v1.CredentialSshSignature",
        ])
        .compile_protos(
            &[bridge_proto, daemon_proto, broker_proto],
            &[daemon_proto_root, shared_proto_root],
        );
    require_compiled(compiled, "compile daemon protobuf types");
}

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
