//! Test-only, synthetic host-agent broker. Never loads a login or live transport.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    use std::path::PathBuf;

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 || args[0] != "--root" || args[2] != "--environment" {
        eprintln!("usage: codewire-host-agent-smoke --root PRIVATE_ROOT --environment UUID");
        std::process::exit(2);
    }
    let Some(environment) = args[3].to_str() else {
        eprintln!("host-agent fixture arguments are invalid");
        std::process::exit(2);
    };
    if let Err(error) =
        codewire_credential_broker::host_agent_smoke::run(&PathBuf::from(&args[1]), environment)
            .await
    {
        // Every variant is a fixed label; never print parser/provider sources.
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the host-agent synthetic fixture requires Linux");
    std::process::exit(2);
}
