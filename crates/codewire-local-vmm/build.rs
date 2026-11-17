use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let proto_root = manifest_dir.join("proto");
    let control_proto = proto_root.join("codewire/local/v1/control.proto");

    println!("cargo:rerun-if-changed={}", control_proto.display());

    let descriptor_set = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"))
        .join("local_runtime_descriptor.bin");
    require_compiled(
        tonic_prost_build::configure()
            .file_descriptor_set_path(&descriptor_set)
            .skip_debug(SKIP_DEBUG)
            .compile_protos(&[control_proto], &[proto_root]),
        "compile private local runtime protobuf types",
    );
    codewire_prost_debug_redact::require_covered(
        &descriptor_set,
        &["codewire/local/v1/control.proto"],
        SKIP_DEBUG,
    );
}

/// Messages prost derives no `Debug` for, because they hold a field marked
/// `debug_redact`; src/control.rs redacts them.
const SKIP_DEBUG: &[&str] = &[".codewire.local.v1.BootSecret"];

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
