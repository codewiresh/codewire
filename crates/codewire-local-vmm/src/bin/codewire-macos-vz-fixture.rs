//! Opt-in, synthetic developer proof, never a product local-runtime entrypoint.

#[cfg(unix)]
#[path = "vz_production_fixture/mod.rs"]
mod fixture;

fn main() {
    #[cfg(unix)]
    if fixture::entry().is_ok() {
        return;
    }
    // Never display guest responses, parser sources, paths or the synthetic
    // one-boot capability. The parent captures even this fixed diagnostic.
    eprintln!("macOS production-init verifier: rejected");
    std::process::exit(1);
}
