use clap::Subcommand;

/// `cw local-https`: the HTTPS URLs of local environments' labelled ports
/// (#4316).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Subcommand)]
pub(crate) enum LocalHttpsCommand {
    #[command(about = "Show whether labelled ports are served over HTTPS, and on which port")]
    Status,
    #[command(
        about = "Serve HTTPS URLs on another port, or turn them off",
        long_about = "Serve HTTPS URLs on another port, or turn them off:\n  cw local-https port 8443   (URLs then end in :8443)\n  cw local-https port 443\n  cw local-https port off\n\nThe choice is remembered for this user."
    )]
    Port {
        #[arg(value_name = "PORT", help = "A port number from 1 to 65535, or off")]
        port: String,
    },
    #[command(
        about = "Let HTTPS URLs use port 443 on Linux (run it with sudo, once)",
        long_about = "Linux lets only root listen on ports below 1024, and HTTPS uses 443. `sudo cw local-https setup` writes /etc/sysctl.d/60-codewire-local-https.conf and applies it: any program on this machine, not only root, may then listen on ports 443 and up. Nothing else changes. On macOS there is nothing to set up."
    )]
    Setup,
    #[command(
        about = "Trust the local HTTPS CA in your browsers",
        long_about = "Add the local HTTPS CA to your own browsers' trust: the NSS databases Firefox and, on Linux, Chromium-family browsers read. It is trusted for HTTPS servers only, and it can sign only names under cw.localhost. Nothing machine-wide is changed. This needs NSS's certutil. On macOS, Safari and Chromium-family browsers read the login keychain, which cw doesn't change yet."
    )]
    Trust,
    #[command(about = "Remove the local HTTPS CA from your browsers' trust")]
    Untrust,
    #[command(
        about = "Replace the local HTTPS CA with a new one",
        long_about = "Make a new CA, shredding the old one's key, then trust the new CA in every store that trusted the old one, which removes the old one there. Use it if the CA's key may have been read by someone else. If it stops part way, `cw local-https trust` finishes it."
    )]
    Rotate,
}
