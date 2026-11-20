//! A Mesh replica that can't reach its shared registry says so (#5515): the
//! warning reaches stdout at the default level, and `/metrics` reads
//! `codewire_mesh_registry_shared 0`. A replica without NATS has no such
//! gauge, so an alert on 0 fires only where sharing is configured.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const LISTENING: &str = "codewire mesh service listening";
const UNSHARED: &str =
    "Mesh can't reach its shared registry yet; it serves its own sessions meanwhile";
const GAUGE: &str = "codewire_mesh_registry_shared";

struct Mesh(Child);

impl Drop for Mesh {
    fn drop(&mut self) {
        // Mesh may already have exited; either way it is reaped below.
        let _ = self.0.kill();
        // Reaping only: the exit status means nothing once the test killed it.
        let _ = self.0.wait();
    }
}

/// Starts Mesh with `nats_url`, if any, and returns it with its stdout lines.
fn start(nats_url: Option<&str>) -> (Mesh, mpsc::Receiver<String>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codewire-mesh"));
    command
        .env_clear()
        .env("CODEWIRE_MESH_URL", "http://mesh.test")
        .env("CODEWIRE_MESH_LISTEN_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(url) = nats_url {
        command.env("NATS_URL", url);
    }
    let mut mesh = Mesh(command.spawn().unwrap());
    let stdout = mesh.0.stdout.take().unwrap();
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    (mesh, lines)
}

/// The first stdout line carrying `message`, within 30 s.
fn line_with(lines: &mpsc::Receiver<String>, message: &str) -> serde_json::Value {
    let mut seen = Vec::new();
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("no {message:?} line within 30 s; saw {seen:#?}"));
        let value: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|err| panic!("not a JSON line ({err}): {line}"));
        if value["fields"]["message"] == message {
            return value;
        }
        seen.push(line);
    }
}

fn metrics(addr: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: mesh.test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
}

fn listen_addr(lines: &mpsc::Receiver<String>) -> String {
    line_with(lines, LISTENING)["fields"]["listen_addr"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn a_replica_that_cannot_reach_its_shared_registry_warns_and_reads_zero() {
    // Nothing listens on the discard port.
    let (_mesh, lines) = start(Some("nats://127.0.0.1:9"));
    let addr = listen_addr(&lines);
    let warning = line_with(&lines, UNSHARED);
    assert_eq!(warning["level"], "WARN", "{warning}");
    assert!(
        metrics(&addr)
            .lines()
            .any(|line| line == format!("{GAUGE} 0")),
        "{GAUGE} 0 missing"
    );
}

#[test]
fn a_replica_without_nats_has_no_sharing_gauge() {
    let (_mesh, lines) = start(None);
    let addr = listen_addr(&lines);
    let body = metrics(&addr);
    assert!(
        body.contains("codewire_control_plane_service_info"),
        "{body}"
    );
    assert!(!body.contains(GAUGE), "{body}");
}
