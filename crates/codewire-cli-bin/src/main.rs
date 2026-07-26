#[tokio::main]
async fn main() {
    if let Err(err) = codewire_cli::run().await {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
