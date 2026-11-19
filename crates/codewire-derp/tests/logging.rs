//! The relay binary logs JSON lines on stdout, so the alert on its
//! public-certificate warning (#4000) has something to match, and those lines
//! never carry the certificate's files.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const PUBLIC: &str = "derp.example.test";
const LOADED: &str = "codewire derp tls public certificate loaded";
const NOT_LOADED: &str = "codewire derp tls public certificate not loaded; the previous one stays";

struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "codewire-derp-logging-{test}-{}",
            std::process::id()
        ));
        // Only a crashed earlier run leaves this; usually there is nothing to remove.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, cert: &str, key: &str) {
        std::fs::write(self.dir.join("tls.crt"), cert).unwrap();
        std::fs::write(self.dir.join("tls.key"), key).unwrap();
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        // Cleanup in Drop: a leftover temporary directory fails nothing.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        // The relay may already have exited; either way it is reaped below.
        let _ = self.0.kill();
        // Reaping only: the exit status means nothing once the test killed it.
        let _ = self.0.wait();
    }
}

fn issue() -> (String, String) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![PUBLIC.to_owned()]).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// The relay's stdout lines until one carries `message`, within 30 s.
fn lines_until(files: &Files, message: &str) -> Vec<String> {
    let mut relay = Relay(
        Command::new(env!("CARGO_BIN_EXE_codewire-derp"))
            .env_clear()
            .env("PORT", "-1")
            .env("STUN_PORT", "-1")
            .env("TLS_LISTEN_ADDR", "127.0.0.1:0")
            .env("TLS_HOSTS", "derp.in-cluster.test")
            .env("TLS_PUBLIC_HOSTNAME", PUBLIC)
            .env("TLS_PUBLIC_CERT_FILE", files.dir.join("tls.crt"))
            .env("TLS_PUBLIC_KEY_FILE", files.dir.join("tls.key"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = relay.0.stdout.take().unwrap();
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let mut seen = Vec::new();
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("no {message:?} line within 30 s; saw {seen:#?}"));
        let done = line.contains(message);
        seen.push(line);
        if done {
            return seen;
        }
    }
}

/// Every line is a JSON object, and none holds a line of either file's body.
fn assert_clean(lines: &[String], cert: &str, key: &str) {
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("not a JSON line ({err}): {line}"));
        assert!(value.is_object(), "{line}");
        assert!(!line.contains("PRIVATE KEY"), "{line}");
        for body in cert
            .lines()
            .chain(key.lines())
            .filter(|l| !l.starts_with("-----"))
        {
            assert!(!line.contains(body), "a file's contents in the log: {line}");
        }
    }
}

#[test]
fn a_loaded_public_certificate_is_logged_by_name_only() {
    let files = Files::new("loaded");
    let (cert, key) = issue();
    files.write(&cert, &key);

    let lines = lines_until(&files, LOADED);
    assert_clean(&lines, &cert, &key);
    let loaded = lines.last().unwrap();
    assert!(loaded.contains(PUBLIC), "{loaded}");
}

#[test]
fn a_public_certificate_that_does_not_load_logs_the_warning_the_alert_matches() {
    let files = Files::new("not-loaded");
    let (cert, _) = issue();
    let (_, other_key) = issue();
    files.write(&cert, &other_key);

    let lines = lines_until(&files, NOT_LOADED);
    assert_clean(&lines, &cert, &other_key);
    let warning: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(warning["level"], "WARN", "{warning}");
    assert_eq!(warning["fields"]["message"], NOT_LOADED, "{warning}");
}
