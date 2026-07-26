fn main() -> anyhow::Result<()> {
    let doc = codewire_billing::contract::rust_openapi_preview();
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}
