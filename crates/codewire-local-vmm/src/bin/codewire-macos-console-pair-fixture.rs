//! Explicit developer fixture; never a product CLI entrypoint.

#[cfg(all(target_os = "linux", feature = "macos-console-pair-fixture"))]
fn main() {
    codewire_local_vmm::macos_console_pair_fixture::main();
}

#[cfg(not(all(target_os = "linux", feature = "macos-console-pair-fixture")))]
fn main() {
    eprintln!("console-pair fixture requires Linux and its explicit developer feature");
    std::process::exit(64);
}
