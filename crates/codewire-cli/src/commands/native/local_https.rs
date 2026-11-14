//! HTTPS hostnames for local environments' labelled ports (#4316): the
//! `cw local-https` commands, and what `cw ports` and `cw create` say about
//! them. The supervisor serves the hostnames; this side reports its state in
//! plain words, names a program holding the port, and asks before choosing
//! another.

use std::io::BufRead as _;

use codewire_local_vmm::local_https::{ALTERNATIVE_PORT, DEFAULT_PORT, url};

use super::*;

/// Where `cw local-https setup` records its one setting.
#[cfg(target_os = "linux")]
const SYSCTL_FILE: &str = "/etc/sysctl.d/60-codewire-local-https.conf";
#[cfg(target_os = "linux")]
const UNPRIVILEGED_PORT_START: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";

/// One labelled port's HTTPS URL, as `cw ports --output json` lists it
/// beside the host ports.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(crate) struct NativeHttpsView {
    pub(crate) url: String,
    pub(crate) guest_port: u32,
    pub(crate) label: String,
}

/// What `cw ports` and `cw create` show for an environment: the URLs being
/// served, and notes about the router or ports that have none.
#[derive(Debug, Default)]
pub(crate) struct HttpsReport {
    pub(crate) urls: Vec<NativeHttpsView>,
    pub(crate) notes: Vec<String>,
}

/// The HTTPS report for `name`. With `ask`, a port another program holds is
/// named and the user is asked whether to serve on another one; without a
/// terminal, the note names the holder and says how to choose. Nothing is
/// said for an environment with no labelled port, or by an older supervisor.
pub(crate) async fn https_report(
    client: &mut NativeSupervisorClient,
    name: &str,
    ask: bool,
) -> anyhow::Result<HttpsReport> {
    let Some(mut status) = client.local_https(name).await.map_err(native_status)? else {
        return Ok(HttpsReport::default());
    };
    let mut report = HttpsReport::default();
    for host in &status.hosts {
        if host.hostname.is_empty() {
            report.notes.push(format!(
                "Port {} is labelled {:?}, which with {name} makes no valid hostname, so it has no HTTPS URL.",
                host.guest_port, host.label
            ));
        }
    }
    if status.hosts.iter().all(|host| host.hostname.is_empty()) {
        return Ok(report);
    }
    if status.state == v1::LocalHttpsState::InUse as i32
        && ask
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
    {
        status = ask_for_another_port(client, name, &status).await?;
    }
    let port = u16::try_from(status.port).unwrap_or(DEFAULT_PORT);
    match v1::LocalHttpsState::try_from(status.state) {
        Ok(v1::LocalHttpsState::Serving) => {
            report.urls = status
                .hosts
                .iter()
                .filter(|host| !host.hostname.is_empty())
                .map(|host| NativeHttpsView {
                    url: url(&host.hostname, port),
                    guest_port: host.guest_port,
                    label: host.label.clone(),
                })
                .collect();
        }
        Ok(v1::LocalHttpsState::NotPermitted) => report.notes.push(not_permitted(port)),
        Ok(v1::LocalHttpsState::InUse) => report.notes.push(format!(
            "HTTPS URLs are not served: port {port} is in use by {}. `cw local-https port {ALTERNATIVE_PORT}` serves them on port {ALTERNATIVE_PORT} instead.",
            holder(port)
        )),
        Ok(v1::LocalHttpsState::Off) => report.notes.push(format!(
            "HTTPS URLs are off. `cw local-https port {DEFAULT_PORT}` turns them on."
        )),
        Ok(v1::LocalHttpsState::Failed) => report.notes.push(format!(
            "HTTPS URLs are unavailable: {}.",
            status.failure
        )),
        Ok(v1::LocalHttpsState::Unused | v1::LocalHttpsState::Unspecified) | Err(_) => {}
    }
    Ok(report)
}

/// After a local `cw create`, in text output: the new environment's HTTPS
/// URLs and any note. A supervisor that cannot be asked leaves the create's
/// own result as it is.
pub(crate) async fn print_created_https(name: &str, output: OutputFormat) {
    if !matches!(output, OutputFormat::Text) {
        return;
    }
    let Ok(mut client) = native_client().await else {
        return;
    };
    let Ok(report) = https_report(&mut client, name, true).await else {
        return;
    };
    for view in &report.urls {
        println!("  {} -> {} ({})", view.url, view.guest_port, view.label);
    }
    for note in &report.notes {
        println!("{note}");
    }
}

/// The plain explanation of why port 443 needs a one-time setup, and what
/// that setup changes.
fn not_permitted(port: u16) -> String {
    if cfg!(target_os = "linux") && port == DEFAULT_PORT {
        format!(
            "HTTPS URLs are not served yet: Linux lets only root listen on ports below 1024, and HTTPS uses {port}.\n\
             Run `sudo cw local-https setup` once. It lets any program on this machine, not only root, listen on ports {port} and up, \
             so Codewire can serve these URLs without running as root."
        )
    } else {
        format!(
            "HTTPS URLs are not served: this user may not listen on port {port}. `cw local-https port {ALTERNATIVE_PORT}` serves them on port {ALTERNATIVE_PORT} instead."
        )
    }
}

/// Name the holder, then ask whether to serve on [`ALTERNATIVE_PORT`]. A
/// "no" turns local HTTPS off, so the question is not asked again.
async fn ask_for_another_port(
    client: &mut NativeSupervisorClient,
    name: &str,
    status: &v1::LocalHttps,
) -> anyhow::Result<v1::LocalHttps> {
    let port = u16::try_from(status.port).unwrap_or(DEFAULT_PORT);
    let example = status
        .hosts
        .iter()
        .find(|host| !host.hostname.is_empty())
        .map(|host| url(&host.hostname, ALTERNATIVE_PORT))
        .unwrap_or_else(|| format!("{name}'s URLs"));
    let mut stderr = std::io::stderr().lock();
    write!(
        stderr,
        "Port {port} is in use by {}, so Codewire can't serve HTTPS URLs there.\n\
         Serve them on port {ALTERNATIVE_PORT} instead, as {example}? [y/N]: ",
        holder(port)
    )?;
    stderr.flush()?;
    drop(stderr);
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    let chosen = if matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        ALTERNATIVE_PORT
    } else {
        0
    };
    client
        .set_local_https_port(chosen)
        .await
        .map_err(native_status)?;
    client
        .local_https(name)
        .await
        .map_err(native_status)?
        .ok_or_else(|| anyhow::anyhow!("the local supervisor changed while choosing a port"))
}

/// `cw local-https status|port|setup`.
pub(crate) async fn handle_local_https(command: LocalHttpsCommand) -> anyhow::Result<()> {
    match command {
        LocalHttpsCommand::Setup => setup(),
        LocalHttpsCommand::Status => {
            let mut client = native_client().await?;
            let status = client.local_https("").await.map_err(native_status)?;
            print_status(status.as_ref());
            Ok(())
        }
        LocalHttpsCommand::Port { port } => {
            let port = match port.as_str() {
                "off" => 0,
                port => port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| {
                        anyhow::anyhow!("PORT is a port number from 1 to 65535, or off")
                    })?,
            };
            let mut client = native_client().await?;
            let status = client
                .set_local_https_port(port)
                .await
                .map_err(native_status)?;
            print_status(Some(&status));
            Ok(())
        }
    }
}

fn print_status(status: Option<&v1::LocalHttps>) {
    let Some(status) = status else {
        println!(
            "Your local VMs run on an older cw's supervisor, which serves no HTTPS URLs; `cw upgrade --vms` moves them to this cw once they are idle."
        );
        return;
    };
    let port = u16::try_from(status.port).unwrap_or(DEFAULT_PORT);
    let line = match v1::LocalHttpsState::try_from(status.state) {
        Ok(v1::LocalHttpsState::Serving) => {
            format!(
                "Serving labelled ports at https://<label>-<env>.cw.localhost on 127.0.0.1:{port}."
            )
        }
        Ok(v1::LocalHttpsState::Unused) => format!(
            "No environment has a labelled port, so nothing listens. Labelled ports will be served on port {port}."
        ),
        Ok(v1::LocalHttpsState::NotPermitted) => not_permitted(port),
        Ok(v1::LocalHttpsState::InUse) => format!(
            "Port {port} is in use by {}, so HTTPS URLs are not served. `cw local-https port {ALTERNATIVE_PORT}` serves them on port {ALTERNATIVE_PORT} instead.",
            holder(port)
        ),
        Ok(v1::LocalHttpsState::Off) => {
            format!("HTTPS URLs are off. `cw local-https port {DEFAULT_PORT}` turns them on.")
        }
        Ok(v1::LocalHttpsState::Failed) => {
            format!("HTTPS URLs are unavailable: {}.", status.failure)
        }
        Ok(v1::LocalHttpsState::Unspecified) | Err(_) => "The local HTTPS state is unknown.".into(),
    };
    println!("{line}");
    println!("CA certificate: {}", status.ca_certificate_path);
}

/// `sudo cw local-https setup`: let programs that aren't root listen on
/// ports 443 and up, now and after every boot.
#[cfg(target_os = "linux")]
fn setup() -> anyhow::Result<()> {
    let current = std::fs::read_to_string(UNPRIVILEGED_PORT_START)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok());
    if current.is_some_and(|start| start <= DEFAULT_PORT) {
        println!(
            "Nothing to do: programs that aren't root may already listen on port {DEFAULT_PORT} here."
        );
        return Ok(());
    }
    anyhow::ensure!(
        rustix::process::geteuid().is_root(),
        "This changes a system setting, so it needs root: run `sudo cw local-https setup`."
    );
    std::fs::write(
        SYSCTL_FILE,
        format!(
            "# Written by `cw local-https setup`: lets programs that are not root\n\
             # listen on ports {DEFAULT_PORT} and up, so Codewire serves\n\
             # https://<label>-<env>.cw.localhost without root.\n\
             net.ipv4.ip_unprivileged_port_start={DEFAULT_PORT}\n"
        ),
    )
    .with_context(|| format!("writing {SYSCTL_FILE}"))?;
    std::fs::write(UNPRIVILEGED_PORT_START, format!("{DEFAULT_PORT}\n"))
        .with_context(|| format!("writing {UNPRIVILEGED_PORT_START}"))?;
    println!(
        "Done. Programs that aren't root may now listen on ports {DEFAULT_PORT} and up; Codewire serves HTTPS URLs within a few seconds.\n\
         The setting is in {SYSCTL_FILE}. To undo it, delete that file and run `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1024`."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn setup() -> anyhow::Result<()> {
    println!("Nothing to do: on this system any program may listen on port {DEFAULT_PORT}.");
    Ok(())
}

/// Who listens on `127.0.0.1:port`, in words: the program and its PID when
/// this user may see them, otherwise the user it runs as.
fn holder(port: u16) -> String {
    port_holder::describe(port).unwrap_or_else(|| "another program".to_owned())
}

#[cfg(target_os = "linux")]
mod port_holder {
    //! The listener of a TCP port, from `/proc`. Another user's process is
    //! named by its user only, since its file descriptors are not readable.

    use std::fs;

    /// `st` of a listening socket in `/proc/net/tcp`.
    const LISTEN: &str = "0A";

    pub(super) fn describe(port: u16) -> Option<String> {
        let (inode, uid) = listener(port)?;
        let user = user_name(uid);
        match process_with_socket(inode) {
            Some((pid, command)) => Some(format!("{command} (PID {pid}, user {user})")),
            None => Some(format!("a program run by {user}")),
        }
    }

    /// The socket inode and owner of a listener on `port`, IPv4 or IPv6.
    fn listener(port: u16) -> Option<(u64, u32)> {
        let wanted = format!("{port:04X}");
        ["/proc/net/tcp", "/proc/net/tcp6"]
            .into_iter()
            .filter_map(|table| fs::read_to_string(table).ok())
            .flat_map(|table| table.lines().skip(1).map(str::to_owned).collect::<Vec<_>>())
            .find_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let local = fields.get(1)?;
                let (_, local_port) = local.rsplit_once(':')?;
                (local_port == wanted && fields.get(3) == Some(&LISTEN)).then_some(())?;
                Some((fields.get(9)?.parse().ok()?, fields.get(7)?.parse().ok()?))
            })
    }

    /// A process holding socket `inode`, among those whose descriptors this
    /// user may read.
    fn process_with_socket(inode: u64) -> Option<(u32, String)> {
        let target = format!("socket:[{inode}]");
        fs::read_dir("/proc").ok()?.flatten().find_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let holds = fs::read_dir(entry.path().join("fd"))
                .ok()?
                .flatten()
                .any(|fd| {
                    fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
                });
            holds.then(|| {
                let command = fs::read_to_string(entry.path().join("comm"))
                    .map(|command| command.trim().to_owned())
                    .unwrap_or_else(|_| "a program".to_owned());
                (pid, command)
            })
        })
    }

    fn user_name(uid: u32) -> String {
        fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|passwd| {
                passwd.lines().find_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?;
                    (fields.nth(1)? == uid.to_string()).then(|| name.to_owned())
                })
            })
            .unwrap_or_else(|| format!("uid {uid}"))
    }
}

#[cfg(not(target_os = "linux"))]
mod port_holder {
    //! The listener of a TCP port, from `lsof`, which names only this user's
    //! processes without root.

    pub(super) fn describe(port: u16) -> Option<String> {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpc"])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let pid = text.lines().find_map(|line| line.strip_prefix('p'))?;
        let command = text.lines().find_map(|line| line.strip_prefix('c'))?;
        Some(format!("{command} (PID {pid})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_443_explanation_says_why_and_what_the_setup_changes() {
        let text = not_permitted(443);
        if cfg!(target_os = "linux") {
            assert!(
                text.contains("only root listen on ports below 1024"),
                "{text}"
            );
            assert!(text.contains("`sudo cw local-https setup`"), "{text}");
            assert!(text.contains("any program on this machine"), "{text}");
        }
        assert!(not_permitted(8443).contains("port 8443"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_this_user_holds_is_named_with_its_pid() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let named = holder(port);
        // While this listener is open, no other process can listen on the
        // port; once it closes, a test running alongside may take it.
        assert!(
            named.contains(&format!("PID {}", std::process::id())),
            "{named}"
        );
        drop(listener);
    }
}
