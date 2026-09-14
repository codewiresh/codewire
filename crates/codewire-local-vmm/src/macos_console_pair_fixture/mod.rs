//! Unreachable two-VM developer fixture. Production guest/vsock entrypoints
//! and the production worker's admission and confinement are unchanged.

mod binding;
mod descriptor;
mod packet;
mod process;
#[cfg(feature = "macos-product-network-fixture")]
mod product_network;
#[cfg(feature = "macos-product-network-fixture")]
mod product_runtime;
mod runtime;

use std::io;

type Result<T> = io::Result<T>;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid console-pair fixture input",
    )
}

/// The binary owns error presentation; never print a bootstrap or guest payload.
pub fn main() {
    let result = entrypoint();
    if result.is_err() {
        eprintln!("console-pair fixture failed");
    }
    if unsafe { libc::getpid() } == 1 {
        runtime::poweroff();
    }
    std::process::exit(if result.is_ok() { 0 } else { 70 });
}

pub fn entrypoint() -> io::Result<()> {
    runtime::entry(std::env::args().skip(1).collect())
}

/// Separate fixed-profile developer binary; never selected by product CLI.
#[cfg(feature = "macos-product-network-fixture")]
pub fn product_main() {
    let result = runtime::entry_for(
        std::env::args().skip(1).collect(),
        binding::Profile::ProductNetwork,
    );
    if result.is_err() {
        eprintln!("product-network fixture failed");
    }
    if unsafe { libc::getpid() } == 1 {
        runtime::poweroff();
    }
    std::process::exit(if result.is_ok() { 0 } else { 70 });
}

#[cfg(all(test, feature = "macos-product-network-fixture"))]
mod product_binding_tests;
#[cfg(test)]
mod tests;
