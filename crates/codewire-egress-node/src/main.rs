//! cw-egress: the per-node egress supervisor for hosted sandboxes, and the
//! two confined children it starts from this same image.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    if let Some(status) = codewire_egress_node::children::run_child(std::env::args_os()) {
        return status;
    }
    codewire_egress_node::node::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("cw-egress runs only on Linux");
    ExitCode::FAILURE
}
