//! Host-loopback synthetic SSH repository for Linux initial checkout acceptance.
//! Never installed as a product binary; accepts a public client key only.

#[cfg(target_os = "linux")]
#[path = "initial_private_checkout_fixture/linux.rs"]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("initial-private-checkout fixture: Linux is required");
        std::process::exit(1);
    }
}
