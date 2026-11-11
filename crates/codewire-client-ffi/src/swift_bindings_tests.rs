//! The Swift bindings committed under `apps/ios` match this crate (#3825).
//! They are generated from this test binary, which carries the crate's UniFFI
//! metadata, so the check needs no iOS build and runs on any host.
//! `UPDATE_SWIFT_BINDINGS=1` rewrites them instead of failing
//! (`apps/ios/scripts/generate-bindings.sh`).

use std::path::Path;

/// The C module the generated Swift imports.
const FFI_MODULE: &str = "codewire_client_ffiFFI";

/// Each generated file and where it is committed: the Swift source the app
/// compiles, and the header and module map the xcframework carries.
const BINDINGS: [(&str, &str); 3] = [
    (
        "codewire_client_ffi.swift",
        "Sources/CodewireClientFFI/codewire_client_ffi.swift",
    ),
    (
        "codewire_client_ffiFFI.h",
        "FFI/include/codewire_client_ffiFFI.h",
    ),
    ("module.modulemap", "FFI/include/module.modulemap"),
];

#[test]
fn the_committed_swift_bindings_match_this_crate() {
    let generated = tempfile::tempdir().unwrap();
    let source = std::env::current_exe().unwrap();
    uniffi::generate_swift_bindings(uniffi::SwiftBindingsOptions {
        generate_swift_sources: true,
        generate_headers: true,
        generate_modulemap: true,
        source: source.to_str().unwrap().into(),
        out_dir: generated.path().to_str().unwrap().into(),
        xcframework: false,
        module_name: Some(FFI_MODULE.into()),
        modulemap_filename: Some("module.modulemap".into()),
        metadata_no_deps: true,
        link_frameworks: Vec::new(),
    })
    .unwrap();

    let mut written: Vec<_> = std::fs::read_dir(generated.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    let mut expected: Vec<_> = BINDINGS.iter().map(|(name, _)| name.to_string()).collect();
    expected.sort();
    assert_eq!(written, expected, "the generator wrote other files");

    let ios = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/ios");
    let update = std::env::var_os("UPDATE_SWIFT_BINDINGS").is_some();
    let mut stale = Vec::new();
    for (name, committed) in BINDINGS {
        let fresh = std::fs::read(generated.path().join(name)).unwrap();
        let committed = ios.join(committed);
        if update {
            std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
            std::fs::write(&committed, &fresh).unwrap();
        } else if std::fs::read(&committed).ok() != Some(fresh) {
            stale.push(committed);
        }
    }
    assert!(
        stale.is_empty(),
        "the Swift bindings are stale; run apps/ios/scripts/generate-bindings.sh: {stale:?}"
    );
}
