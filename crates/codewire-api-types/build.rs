use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let spec_path = manifest_dir.join("../../openapi.json");

    println!("cargo:rerun-if-changed={}", spec_path.display());

    let spec_file = File::open(&spec_path).expect("openapi.json");
    let reader = BufReader::new(spec_file);
    let mut spec: openapiv3::OpenAPI = serde_json::from_reader(reader).expect("parse OpenAPI spec");
    strip_unsupported_parameters(&mut spec);
    spec.paths.paths.clear();

    let mut generator = progenitor::Generator::default();
    let tokens = generator
        .generate_tokens(&spec)
        .expect("generate Rust bindings from OpenAPI");
    let syntax = syn::parse2(tokens).expect("parse generated tokens");
    let formatted = prettyplease::unparse(&syntax);
    let types_module = extract_types_module(&formatted);
    let generated = format!("{types_module}\n\npub use types::*;\n");

    let out_file = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("codegen.rs");
    std::fs::write(out_file, generated).expect("write generated bindings");
}

fn strip_unsupported_parameters(spec: &mut openapiv3::OpenAPI) {
    for item in spec.paths.paths.values_mut() {
        let openapiv3::ReferenceOr::Item(path_item) = item else {
            continue;
        };

        strip_cookie_parameters(&mut path_item.parameters);

        for operation in [
            path_item.get.as_mut(),
            path_item.put.as_mut(),
            path_item.post.as_mut(),
            path_item.delete.as_mut(),
            path_item.options.as_mut(),
            path_item.head.as_mut(),
            path_item.patch.as_mut(),
            path_item.trace.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            strip_cookie_parameters(&mut operation.parameters);
        }
    }
}

fn strip_cookie_parameters(params: &mut Vec<openapiv3::ReferenceOr<openapiv3::Parameter>>) {
    params.retain(|param| {
        !matches!(
            param,
            openapiv3::ReferenceOr::Item(openapiv3::Parameter::Cookie { .. })
        )
    });
}

fn extract_types_module(source: &str) -> String {
    let start = source
        .find("pub mod types {")
        .expect("generated code should contain a types module");
    let mut depth = 0usize;
    let mut end = None;

    for (offset, ch) in source[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    let end = end.expect("generated types module should be balanced");
    source[start..end].to_string()
}
