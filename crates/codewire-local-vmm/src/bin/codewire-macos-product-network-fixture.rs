//! Fixed production-network developer fixture; never a product CLI command.

#[cfg(all(target_os = "linux", feature = "macos-product-network-fixture"))]
fn main() {
    codewire_local_vmm::macos_console_pair_fixture::product_main();
}

#[cfg(not(all(target_os = "linux", feature = "macos-product-network-fixture")))]
fn main() {
    eprintln!("product-network fixture requires Linux and its explicit developer feature");
    std::process::exit(64);
}
