fn main() -> anyhow::Result<()> {
    let doc = codewire_orchestration::api::contract::rust_openapi_preview();
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}
