//! Unreachable two-VM developer fixture. Production guest/vsock entrypoints
//! and the production worker's admission and confinement are unchanged.

mod binding;
mod descriptor;
mod packet;
mod process;
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

#[cfg(test)]
mod tests;
