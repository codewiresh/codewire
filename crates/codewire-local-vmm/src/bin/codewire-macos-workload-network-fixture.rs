//! Opt-in fixed workload proof; never a production CLI or network decoder.

#[cfg(unix)]
#[path = "vz_workload_network_fixture/mod.rs"]
mod fixture;

fn main() {
    #[cfg(unix)]
    if fixture::entry().is_ok() {
        return;
    }
    // Even unexpected remote responses and capability-bearing parser errors
    // remain private. The parent captures this fixed diagnostic as well.
    eprintln!("macOS workload-network verifier: rejected");
    std::process::exit(1);
}
